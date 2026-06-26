/**
 * `vaulytica compare <base> <revised>` — headless version comparison.
 *
 * The browser compares a base and a revised document and shows the finding
 * delta (resolved / introduced / unchanged) plus the clause-level redline.
 * This is that same comparison, headless, over the parity-proven Node engine
 * (`analyzeFile` → the SAME engine the tab runs) — so a CI pipeline can gate a
 * pull request on "did this revision introduce a finding at or above <sev>?"
 * and attach the redline as an artifact. The DKB ships with the tool; no socket.
 *
 *   tsx tools/cli/run.ts compare base.docx revised.docx \
 *       [--playbook <id>] [--format json|markdown] \
 *       [--fail-on critical|warning|info] [--confirm-pairing]
 *
 * `--fail-on <sev>` exits non-zero (code 2) when the *introduced* bucket holds
 * a finding at or above <sev> — the revision created new exposure. A
 * cross-family pairing (the two documents matched different playbooks) is
 * refused unless `--confirm-pairing` is passed, mirroring the UI.
 *
 * `--fail-on-regression` (spec-v11 Thrust C) exits non-zero (code 2) when the
 * posture movement holds any **regressed** dimension — a front that moved to a
 * strictly worse rung on the team's own ladder. It requires `--posture` (there
 * is no movement to gate without it). The gate is the well-ordered rung
 * worsening only; `now-unstated` (a term that dropped off the ladder) is
 * reported but does not trip it — per the §3 honesty contract a dropped front
 * is not conflated with a rung regression. A team that wants to gate on a
 * dropped term composes it from the JSON `posture_movement.counts`.
 *
 * Build/CI-only; never imported by `src/`.
 */

import { readFile } from "node:fs/promises";
import { analyzeFile, loadAccuracyDeps } from "./api.js";
import {
  compareRuns,
  buildComparisonJsonObject,
  type Comparison,
  type SeverityCounts,
} from "../../src/report/compare.js";
import { buildClauseDiff, type ClauseDiff } from "../../src/report/clause-diff.js";
import { comparePosture, type PostureMovement } from "../../src/report/posture-movement.js";
import { parseCustomPlaybookJson } from "../../src/playbooks/custom-playbook.js";
import type { Severity } from "../../src/engine/index.js";

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };

type CompareArgs = {
  base: string;
  revised: string;
  playbook?: string;
  /** spec-v11 — a custom playbook file whose positions drive `--posture`. */
  playbookFile?: string;
  /** spec-v11 — diff the negotiation posture between the two drafts. */
  posture: boolean;
  format: "json" | "markdown";
  failOn?: Severity;
  /** spec-v11 Thrust C — exit non-zero when any posture dimension regressed. */
  failOnRegression: boolean;
  confirmPairing: boolean;
};

export function parseCompareArgs(argv: string[]): CompareArgs {
  const positional: string[] = [];
  const args: Partial<CompareArgs> = {
    format: "markdown",
    confirmPairing: false,
    posture: false,
    failOnRegression: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i]!;
    switch (flag) {
      case "--playbook":
        args.playbook = argv[++i];
        break;
      case "--playbook-file":
        args.playbookFile = argv[++i];
        break;
      case "--posture":
        args.posture = true;
        break;
      case "--format": {
        const v = argv[++i];
        if (v !== "json" && v !== "markdown") throw new Error(`--format must be json|markdown`);
        args.format = v;
        break;
      }
      case "--fail-on": {
        const v = argv[++i];
        if (v !== "critical" && v !== "warning" && v !== "info") {
          throw new Error(`--fail-on must be critical|warning|info`);
        }
        args.failOn = v;
        break;
      }
      case "--fail-on-regression":
        args.failOnRegression = true;
        break;
      case "--confirm-pairing":
        args.confirmPairing = true;
        break;
      default:
        if (flag.startsWith("--")) throw new Error(`unknown flag "${flag}"`);
        positional.push(flag);
    }
  }
  if (positional.length !== 2) {
    throw new Error(
      "usage: compare <base> <revised> [--playbook <id>] [--playbook-file <path>] [--posture] [--format json|markdown] [--fail-on <sev>] [--fail-on-regression] [--confirm-pairing]",
    );
  }
  if (args.posture && !args.playbookFile) {
    throw new Error("--posture requires --playbook-file <path>");
  }
  if (args.failOnRegression && !args.posture) {
    throw new Error("--fail-on-regression requires --posture");
  }
  return {
    base: positional[0]!,
    revised: positional[1]!,
    ...(args.playbook ? { playbook: args.playbook } : {}),
    ...(args.playbookFile ? { playbookFile: args.playbookFile } : {}),
    posture: args.posture!,
    format: args.format!,
    ...(args.failOn ? { failOn: args.failOn } : {}),
    failOnRegression: args.failOnRegression!,
    confirmPairing: args.confirmPairing!,
  };
}

/** True when the introduced bucket holds a finding at or above `threshold`. */
export function introducedBreaches(counts: SeverityCounts, threshold: Severity): boolean {
  const rank = SEVERITY_RANK[threshold];
  if (rank >= SEVERITY_RANK.info && counts.info > 0) return true;
  if (rank >= SEVERITY_RANK.warning && counts.warning > 0) return true;
  return counts.critical > 0;
}

function countPhrase(c: SeverityCounts): string {
  return `${c.total} (${c.critical}C ${c.warning}W ${c.info}I)`;
}

/**
 * True when the posture movement holds a regressed dimension (spec-v11 Thrust
 * C). The gate is the well-ordered rung worsening only; `now-unstated` is
 * reported but never trips it (§3 honesty — a dropped front is not a rung
 * regression).
 */
export function postureRegressed(pm: PostureMovement): boolean {
  return pm.counts.regressed > 0;
}

/** Movement labels for the Markdown posture-movement section. */
const MOVEMENT_LABEL: Record<string, string> = {
  improved: "improved",
  regressed: "regressed",
  unchanged: "unchanged",
  "newly-stated": "newly stated",
  "now-unstated": "no longer stated",
  appeared: "added dimension",
  disappeared: "removed dimension",
};

function tierShort(tier: string | null): string {
  if (tier === null) return "—";
  return (
    {
      ideal: "ideal",
      acceptable: "acceptable",
      "below-acceptable": "below floor",
      unevaluable: "not stated",
    }[tier] ?? tier
  );
}

/** Render the negotiation-posture movement as a Markdown section (pure, spec-v11). */
export function formatPostureMovementMarkdown(pm: PostureMovement): string {
  const c = pm.counts;
  const lines: string[] = [];
  lines.push("## Negotiation posture movement");
  lines.push("");
  lines.push(`- Movement hash: \`${pm.movement_hash}\``);
  lines.push(
    `- ${c.improved} improved · ${c.regressed} regressed · ${c.unchanged} unchanged · ` +
      `${c["newly-stated"]} newly stated · ${c["now-unstated"]} no longer stated`,
  );
  lines.push("");
  lines.push("| Dimension | Movement | Base | Revised |");
  lines.push("|---|---|---|---|");
  for (const d of pm.dimensions) {
    lines.push(
      `| ${d.dimension} | ${MOVEMENT_LABEL[d.movement] ?? d.movement} | ${tierShort(d.base_tier)} | ${tierShort(d.revised_tier)} |`,
    );
  }
  lines.push("");
  return lines.join("\n");
}

/** Render the comparison + redline as a human-readable Markdown summary (pure). */
export function formatCompareMarkdown(
  cmp: Comparison,
  clauseDiff: ClauseDiff,
  postureMovement?: PostureMovement,
): string {
  const { resolved, introduced, unchanged } = cmp.delta.counts;
  const lines: string[] = [];
  lines.push(`# Comparison: ${cmp.base.name} → ${cmp.revised.name}`);
  lines.push("");
  lines.push(`- Comparison hash: \`${cmp.result_hash}\``);
  lines.push(`- Base: \`${cmp.base.result_hash}\` (${cmp.base.playbook_id})`);
  lines.push(`- Revised: \`${cmp.revised.result_hash}\` (${cmp.revised.playbook_id})`);
  if (cmp.dkb_mismatch) lines.push(`- ⚠ DKB version mismatch — not strictly apples-to-apples.`);
  if (cmp.family_mismatch) lines.push(`- ⚠ Cross-family pairing (confirmed).`);
  lines.push("");
  lines.push("## Finding delta");
  lines.push("");
  lines.push("| Bucket | Findings |");
  lines.push("|---|---|");
  lines.push(`| Resolved | ${countPhrase(resolved)} |`);
  lines.push(`| Introduced | ${countPhrase(introduced)} |`);
  lines.push(`| Unchanged | ${countPhrase(unchanged)} |`);
  lines.push(`| Carried clean | ${cmp.delta.carried_clean_count} |`);
  lines.push("");
  if (cmp.delta.introduced.length > 0) {
    lines.push("### Introduced findings");
    lines.push("");
    for (const f of cmp.delta.introduced) {
      lines.push(`- **[${f.severity.toUpperCase()}] ${f.rule_id}** — ${f.title}`);
    }
    lines.push("");
  }
  lines.push("## Document redline");
  lines.push("");
  lines.push(
    `${clauseDiff.changed.length} rewritten · ${clauseDiff.added.length} added · ` +
      `${clauseDiff.removed.length} removed · ${clauseDiff.unchanged_count} unchanged` +
      (clauseDiff.truncated ? " _(large documents — approximate)_" : ""),
  );
  lines.push("");
  for (const pair of clauseDiff.changed) {
    lines.push(`- **${pair.revised.heading || pair.revised.id}**: ${renderWordDiff(pair)}`);
  }
  lines.push("");
  if (postureMovement) {
    lines.push(formatPostureMovementMarkdown(postureMovement));
  }
  return lines.join("\n") + "\n";
}

/** Inline redline of a rewritten clause: ~~removed~~ / **added** Markdown. */
function renderWordDiff(pair: ClauseDiff["changed"][number]): string {
  if (!pair.word_diff) return `"${pair.base.text}" → "${pair.revised.text}"`;
  return pair.word_diff
    .map((s) => {
      const t = s.text;
      if (s.status === "removed") return `~~${t}~~`;
      if (s.status === "added") return `**${t}**`;
      return t;
    })
    .join("");
}

export async function runCompare(argv: string[]): Promise<void> {
  const args = parseCompareArgs(argv);

  // spec-v11 — load + validate the custom playbook whose positions drive the
  // posture movement. A malformed file is a hard error, never a silent no-op.
  let customPlaybook: import("../../src/playbooks/custom-playbook.js").CustomPlaybook | undefined;
  if (args.playbookFile) {
    const text = await readFile(args.playbookFile, "utf8").catch(() => null);
    if (text === null) {
      process.stderr.write(`cannot read playbook file: ${args.playbookFile}\n`);
      process.exitCode = 1;
      return;
    }
    const parsed = parseCustomPlaybookJson(text);
    if (!parsed.ok) {
      process.stderr.write(
        `invalid playbook ${args.playbookFile}:\n  ${parsed.errors.join("\n  ")}\n`,
      );
      process.exitCode = 1;
      return;
    }
    customPlaybook = parsed.playbook;
    if (args.posture && !customPlaybook.negotiation_positions?.length) {
      process.stderr.write(`--posture: ${args.playbookFile} defines no negotiation_positions.\n`);
    }
  }

  const deps = await loadAccuracyDeps();
  const analyzeOpts = { playbookId: args.playbook, deps, customPlaybook, posture: args.posture };
  const baseR = await analyzeFile(args.base, analyzeOpts);
  const revisedR = await analyzeFile(args.revised, analyzeOpts);

  const cmp = await compareRuns(baseR.run, revisedR.run, { confirmPairing: args.confirmPairing });
  const clauseDiff = buildClauseDiff(baseR.ingest.tree, revisedR.ingest.tree);
  // The posture movement is computed only when both drafts were classified
  // against the same positions (spec-v11). Outside the comparison result_hash.
  const postureMovement =
    args.posture && baseR.negotiation_posture && revisedR.negotiation_posture
      ? await comparePosture(baseR.negotiation_posture, revisedR.negotiation_posture)
      : undefined;

  if (args.format === "json") {
    process.stdout.write(
      JSON.stringify(buildComparisonJsonObject(cmp, clauseDiff, postureMovement), null, 2) + "\n",
    );
  } else {
    process.stdout.write(formatCompareMarkdown(cmp, clauseDiff, postureMovement));
  }

  if (args.failOn && introducedBreaches(cmp.delta.counts.introduced, args.failOn)) {
    process.stderr.write(
      `\n✗ this revision introduced a finding at or above --fail-on ${args.failOn}\n`,
    );
    process.exitCode = 2;
  }

  // spec-v11 Thrust C — gate on a posture regression. Reported alongside the
  // introduced-finding gate; either tripping sets exit code 2.
  if (args.failOnRegression && postureMovement && postureRegressed(postureMovement)) {
    const n = postureMovement.counts.regressed;
    process.stderr.write(
      `\n✗ this revision regressed ${n} posture dimension${n === 1 ? "" : "s"} (--fail-on-regression)\n`,
    );
    process.exitCode = 2;
  }
}
