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
 * Build/CI-only; never imported by `src/`.
 */

import { analyzeFile, loadAccuracyDeps } from "./api.js";
import {
  compareRuns,
  buildComparisonJsonObject,
  type Comparison,
  type SeverityCounts,
} from "../../src/report/compare.js";
import { buildClauseDiff, type ClauseDiff } from "../../src/report/clause-diff.js";
import type { Severity } from "../../src/engine/index.js";

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };

type CompareArgs = {
  base: string;
  revised: string;
  playbook?: string;
  format: "json" | "markdown";
  failOn?: Severity;
  confirmPairing: boolean;
};

export function parseCompareArgs(argv: string[]): CompareArgs {
  const positional: string[] = [];
  const args: Partial<CompareArgs> = { format: "markdown", confirmPairing: false };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i]!;
    switch (flag) {
      case "--playbook":
        args.playbook = argv[++i];
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
      case "--confirm-pairing":
        args.confirmPairing = true;
        break;
      default:
        if (flag.startsWith("--")) throw new Error(`unknown flag "${flag}"`);
        positional.push(flag);
    }
  }
  if (positional.length !== 2) {
    throw new Error("usage: compare <base> <revised> [--playbook <id>] [--format json|markdown] [--fail-on <sev>] [--confirm-pairing]");
  }
  return {
    base: positional[0]!,
    revised: positional[1]!,
    ...(args.playbook ? { playbook: args.playbook } : {}),
    format: args.format!,
    ...(args.failOn ? { failOn: args.failOn } : {}),
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

/** Render the comparison + redline as a human-readable Markdown summary (pure). */
export function formatCompareMarkdown(cmp: Comparison, clauseDiff: ClauseDiff): string {
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
  const deps = await loadAccuracyDeps();
  const baseR = await analyzeFile(args.base, { playbookId: args.playbook, deps });
  const revisedR = await analyzeFile(args.revised, { playbookId: args.playbook, deps });

  const cmp = await compareRuns(baseR.run, revisedR.run, { confirmPairing: args.confirmPairing });
  const clauseDiff = buildClauseDiff(baseR.ingest.tree, revisedR.ingest.tree);

  if (args.format === "json") {
    process.stdout.write(JSON.stringify(buildComparisonJsonObject(cmp, clauseDiff), null, 2) + "\n");
  } else {
    process.stdout.write(formatCompareMarkdown(cmp, clauseDiff));
  }

  if (args.failOn && introducedBreaches(cmp.delta.counts.introduced, args.failOn)) {
    process.stderr.write(`\n✗ this revision introduced a finding at or above --fail-on ${args.failOn}\n`);
    process.exitCode = 2;
  }
}
