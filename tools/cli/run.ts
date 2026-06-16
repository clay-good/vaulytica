/**
 * Vaulytica headless CLI (spec-v8 Thrust C, Steps 143–145).
 *
 *   tsx tools/cli/run.ts analyze <path|glob|dir> \
 *       [--playbook <id>] [--format json,sarif,html,md,csv] \
 *       [--out <dir>] [--fail-on critical|warning|info] \
 *       [--playbook-file <path> --posture [--fail-on-divergence]] \
 *       [--baseline <bundle> | --baseline-coherence <coherence.json>] \
 *       [--emit-coherence <path>] [--fail-on-coherence-regression]
 *
 * spec-v15: an emitted coherence artifact is pinned to the playbook ladder its
 * rungs were computed against; `--baseline-coherence` refuses to diff it against
 * a round computed on a different ladder (a cross-ladder compare is meaningless).
 *   tsx tools/cli/run.ts diff <a.json> <b.json> [--format markdown|json] [--exit-code]
 *   tsx tools/cli/run.ts compare <base> <revised> [--fail-on <sev>] [--fail-on-regression] [--format json|markdown]
 *   tsx tools/cli/run.ts compare-coherence <base.coherence.json> <revised.coherence.json> [--format markdown|json] [--fail-on-coherence-regression]
 *   tsx tools/cli/run.ts coherence-trend <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-coherence-regression]
 *   tsx tools/cli/run.ts coherence-shift-trend <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-fracture]
 *   tsx tools/cli/run.ts coherence-arc <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-regression-or-fracture]
 *   tsx tools/cli/run.ts coherence-exposure <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-exposure]
 *   tsx tools/cli/run.ts coherence-persistence <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-open-exposure]
 *   tsx tools/cli/run.ts coherence-breadth <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-widening-exposure]
 *   tsx tools/cli/run.ts coherence-recurrence <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-recurring-exposure]
 *   tsx tools/cli/run.ts coherence-volatility <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-volatile-exposure]
 *   tsx tools/cli/run.ts coherence-synchrony <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-synchronized-exposure]
 *   tsx tools/cli/run.ts coherence-settling <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-unsettled-exposure]
 *   tsx tools/cli/run.ts verify <report.json> <original> [--playbook <id>]
 *
 * One dispatcher over the reach commands: `analyze` runs the engine headless
 * (CI gate), `diff` compares two custom playbooks (Step 144), `compare`
 * version-compares two documents + emits the clause redline (a CI redline
 * gate), `compare-coherence` diffs two saved coherence artifacts with no
 * documents on either side (spec-v16), `coherence-trend` walks N ≥ 2 saved
 * coherence artifacts and reports the per-front binding-floor trajectory across
 * the whole negotiation (spec-v17), `coherence-shift-trend` walks the same N
 * artifacts and reports the per-front fracture/reconcile trajectory (spec-v18),
 * `coherence-arc` joins those two trajectories into the v13 per-front combined
 * view over N rounds with one combined gate (spec-v19), `coherence-exposure`
 * reads the same N artifacts on the orthogonal *level* axis — the worst binding
 * floor each front reached across the deal, gating on a front that ever fell
 * below the acceptable floor (spec-v20), `coherence-persistence` reads the same N
 * artifacts on the orthogonal *duration* axis — how long each front sat below the
 * floor and whether it is *still* below floor, gating only on a front open now
 * (spec-v21), `coherence-breadth` reads the same N artifacts on the transpose
 * *per-round* axis — how many fronts sat below the floor in each round, the deal's
 * worst round, and whether the package's exposure broadened first→latest, gating on
 * a widening deal (spec-v22), `coherence-recurrence` reads the same N artifacts on
 * the orthogonal *episode-count* axis — how many *separate* times each front fell
 * below the floor (one steady descent vs a recover-then-relapse), gating on a front
 * that recovered and relapsed (spec-v23), `coherence-volatility` reads the same N
 * artifacts on the orthogonal *crossing-count* axis — how many times each front's
 * standing flipped across the floor (falls and recoveries alike), gating on a front
 * whose standing reversed across the floor (spec-v24), `coherence-synchrony` reads
 * the same N artifacts on the per-round transpose of that crossing axis — how many
 * fronts crossed the floor *together* in each round-transition, the deal's peak step,
 * gating on a synchronized step where two or more fronts crossed at once
 * (spec-v25), `coherence-settling` reads the same N artifacts on the orthogonal
 * *time-of-last-movement* axis — the latest round-transition any front crossed the
 * floor, the quiet tail of steady rounds after it, and whether the final transition
 * still crossed, gating on a deal that never settled before the close (spec-v26),
 * `coherence-onset` reads the mirror *time-of-first-movement* axis — the earliest
 * round-transition any front crossed the floor, the clean lead-in of steady rounds
 * before it, and whether the first transition crossed, gating on a deal that
 * degraded from the opening (spec-v27), `coherence-latency` reads the same N
 * artifacts on the orthogonal *recovery-latency* axis — per front, how many rounds
 * its standing sat below the floor between a fall and the recovery that closes it, the
 * deal's slowest recovery, and whether any fall went unrecovered, gating on a front
 * that fell and never came back (spec-v28), `coherence-concurrency` reads the
 * direction-resolved split of v25's per-step crossing axis — per step, how many fronts
 * *fell* below the floor vs. *recovered*, the deal's peak fall step, gating on a
 * concerted fall where two or more fronts fell together (spec-v29), `coherence-relapse`
 * reads the mirror of v28's recovery-latency axis — per front, how many rounds its
 * standing held *above* the floor between a recovery and the next fall that undoes it,
 * the deal's quickest relapse, gating on a recovery undone at the very next round
 * (spec-v30) — and `verify` re-derives a saved report's `result_hash` (Step 145).
 * The DKB ships with the tool — it opens no socket. The engine is the SAME engine
 * the tab runs (parity-proven), so a number on a CI dashboard describes
 * shipped behavior. Build/CI-only; never imported by `src/`.
 */

import { mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { join, basename, extname, resolve } from "node:path";

import { analyzeFile, loadAccuracyDeps, type AnalyzeResult } from "./api.js";
import { runDiff } from "./diff.js";
import { runCompare } from "./compare.js";
import { runCompareCoherence } from "./compare-coherence.js";
import { runCoherenceTrend } from "./coherence-trend.js";
import { runCoherenceShiftTrend } from "./coherence-shift-trend.js";
import { runCoherenceArc } from "./coherence-arc.js";
import { runCoherenceExposure } from "./coherence-exposure.js";
import { runCoherencePersistence } from "./coherence-persistence.js";
import { runCoherenceBreadth } from "./coherence-breadth.js";
import { runCoherenceRecurrence } from "./coherence-recurrence.js";
import { runCoherenceVolatility } from "./coherence-volatility.js";
import { runCoherenceSynchrony } from "./coherence-synchrony.js";
import { runCoherenceSettling } from "./coherence-settling.js";
import { runCoherenceOnset } from "./coherence-onset.js";
import { runCoherenceLatency } from "./coherence-latency.js";
import { runCoherenceConcurrency } from "./coherence-concurrency.js";
import { runCoherenceRelapse } from "./coherence-relapse.js";
import { verifyReproducibility, explainReproResult, type SavedReport } from "./verify.js";
import type { Severity } from "../../src/engine/index.js";
import { buildJsonReport } from "../../src/report/json.js";
import { buildSarifJson } from "../../src/report/sarif.js";
import { buildHtmlReport } from "../../src/report/html.js";
import { buildFixListMarkdown, buildFixListCsv } from "../../src/report/exports.js";
import { parseCustomPlaybookJson } from "../../src/playbooks/custom-playbook.js";
import { ladderHash } from "../../src/playbooks/custom-interpreter.js";
import {
  bundlePostureCoherence,
  hasDivergence,
  buildPostureCoherenceJson,
  parsePostureCoherenceJson,
  type CoherenceInput,
  type PostureCoherence,
} from "../../src/report/posture-coherence.js";
import {
  compareCoherence,
  coherenceRegressed,
  renderCoherenceMovementSummary,
} from "../../src/report/coherence-movement.js";

const SUPPORTED_EXT = new Set([".txt", ".md", ".markdown", ".text", ".docx", ".pdf"]);
const SEVERITY_RANK: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };
type Format = "json" | "sarif" | "html" | "md" | "csv";
const FORMAT_EXT: Record<Format, string> = {
  json: ".json",
  sarif: ".sarif.json",
  html: ".html",
  md: ".fixlist.md",
  csv: ".fixlist.csv",
};

type Args = {
  target: string;
  playbook?: string;
  formats: Format[];
  out?: string;
  failOn?: Severity;
  /** spec-v9 Thrust A — run the pre-disclosure ("Clean to Send") scan. */
  delivery?: boolean;
  /** spec-v9 Thrust C — compute the critical-dates register. */
  criticalDates?: boolean;
  /** spec-v9 Thrust B — build the closing checklist. */
  checklist?: boolean;
  /** spec-v10 Thrust B — path to a custom playbook whose positions drive `--posture`. */
  playbookFile?: string;
  /** spec-v10 Thrust B — evaluate the custom playbook's negotiation posture. */
  posture?: boolean;
  /** spec-v12 Thrust A — exit non-zero when a posture front diverges across the bundle. */
  failOnDivergence?: boolean;
  /** spec-v13 Thrust A — a baseline bundle (path|glob|dir) to diff the coherence against. */
  baseline?: string;
  /** spec-v13 Thrust A — exit non-zero when the bundle's binding floor regressed vs. the baseline. */
  failOnCoherenceRegression?: boolean;
  /** spec-v14 Thrust B — write this round's cross-document coherence to a portable artifact. */
  emitCoherence?: string;
  /** spec-v14 Thrust B — diff against a saved coherence artifact instead of re-analyzing a baseline bundle. */
  baselineCoherence?: string;
};

function parseArgs(argv: string[]): Args {
  // argv: [target, ...flags] (the "analyze" command word is already stripped)
  const target = argv[0];
  if (!target || target.startsWith("--")) throw new Error("missing <path|glob|dir> argument");
  const args: Args = { target, formats: ["json"] };
  for (let i = 1; i < argv.length; i++) {
    const flag = argv[i];
    const val = argv[i + 1];
    switch (flag) {
      case "--playbook":
        args.playbook = val;
        i++;
        break;
      case "--format":
        args.formats = (val ?? "").split(",").map((f) => f.trim()).filter(Boolean) as Format[];
        i++;
        break;
      case "--out":
        args.out = val;
        i++;
        break;
      case "--fail-on":
        args.failOn = val as Severity;
        i++;
        break;
      case "--delivery":
        args.delivery = true;
        break;
      case "--critical-dates":
        args.criticalDates = true;
        break;
      case "--checklist":
        args.checklist = true;
        break;
      case "--playbook-file":
        args.playbookFile = val;
        i++;
        break;
      case "--posture":
        args.posture = true;
        break;
      case "--fail-on-divergence":
        args.failOnDivergence = true;
        break;
      case "--baseline":
        args.baseline = val;
        i++;
        break;
      case "--fail-on-coherence-regression":
        args.failOnCoherenceRegression = true;
        break;
      case "--emit-coherence":
        args.emitCoherence = val;
        i++;
        break;
      case "--baseline-coherence":
        args.baselineCoherence = val;
        i++;
        break;
      default:
        throw new Error(`unknown flag "${flag}"`);
    }
  }
  return args;
}

/** Recursively collect supported files under a directory. */
async function walkDir(dir: string): Promise<string[]> {
  const out: string[] = [];
  // Code-unit ordering (not `localeCompare`, which depends on the host
  // locale/ICU and would make a directory analysis non-reproducible across
  // machines) — and identical to the glob branch's bare `.sort()`, so
  // `analyze dir/` and `analyze 'dir/*.ext'` ingest files in the same order.
  for (const entry of (await readdir(dir, { withFileTypes: true })).sort((a, b) =>
    a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
  )) {
    if (entry.name.startsWith(".")) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await walkDir(full)));
    else if (SUPPORTED_EXT.has(extname(entry.name).toLowerCase())) out.push(full);
  }
  return out;
}

/**
 * Split a `dir/pattern` glob into its directory and basename pattern. A glob
 * with no slash (e.g. `*.docx`) resolves against the current directory — the
 * previous `slice(0, lastIndexOf("/"))` produced a bogus directory (`*.doc`)
 * for that case, so a bare glob silently matched nothing.
 */
export function splitGlob(target: string): { dir: string; pattern: string } {
  const slash = target.lastIndexOf("/");
  return slash >= 0
    ? { dir: target.slice(0, slash) || "/", pattern: target.slice(slash + 1) }
    : { dir: ".", pattern: target };
}

/** Compile a single-segment glob pattern (`*` wildcard) to an anchored RegExp. */
export function globToRegExp(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp("^" + escaped + "$");
}

/** Resolve the target into a deterministic, sorted list of input files. */
export async function resolveInputs(target: string): Promise<string[]> {
  const st = await stat(target).catch(() => null);
  if (st?.isDirectory()) return walkDir(target);
  if (st?.isFile()) return [target];
  // Treat as a simple `dir/*.ext` glob (one wildcard segment).
  if (target.includes("*")) {
    const { dir, pattern } = splitGlob(target);
    const re = globToRegExp(pattern);
    const names = await readdir(dir).catch(() => [] as string[]);
    return names
      .filter((n) => re.test(n))
      .sort()
      .map((n) => join(dir, n));
  }
  throw new Error(`no such file or directory: ${target}`);
}

async function renderFormat(fmt: Format, r: AnalyzeResult, dkb: Dkb): Promise<string> {
  // The v9 "Last Look" surfaces, populated only when the matching flag ran
  // (--delivery / --critical-dates / --checklist). Threaded into every format.
  const v9surfaces = {
    delivery: r.delivery,
    criticalDates: r.critical_dates,
    closingChecklist: r.closing_checklist,
  };
  switch (fmt) {
    case "json":
      return buildJsonReport(
        r.run,
        r.ingest,
        undefined,
        undefined,
        undefined,
        r.delivery,
        r.critical_dates,
        r.closing_checklist,
        r.negotiation_posture,
      ).text();
    case "sarif":
      return buildSarifJson(r.run, v9surfaces);
    case "html":
      return buildHtmlReport(r.run, r.ingest, dkb, undefined, v9surfaces);
    case "md":
      return buildFixListMarkdown(r.run);
    case "csv":
      return buildFixListCsv(r.run);
  }
}

type Dkb = Awaited<ReturnType<typeof loadAccuracyDeps>>["dkb"];

function worstSeverity(r: AnalyzeResult): Severity | null {
  let worst: Severity | null = null;
  for (const f of r.run.findings) {
    if (worst === null || SEVERITY_RANK[f.severity] < SEVERITY_RANK[worst]) worst = f.severity;
  }
  return worst;
}

async function runAnalyze(argv: string[]): Promise<void> {
  const args = parseArgs(argv);
  const deps = await loadAccuracyDeps();

  // spec-v10 Thrust B — load + validate a custom playbook file (its
  // `negotiation_positions` drive `--posture`). A malformed playbook is a hard
  // error with the validator's messages, never a silent no-op.
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
      process.stderr.write(`invalid playbook ${args.playbookFile}:\n  ${parsed.errors.join("\n  ")}\n`);
      process.exitCode = 1;
      return;
    }
    customPlaybook = parsed.playbook;
    if (args.posture && !(customPlaybook.negotiation_positions?.length)) {
      process.stderr.write(
        `--posture: ${args.playbookFile} defines no negotiation_positions.\n`,
      );
    }
  }
  if (args.posture && !args.playbookFile) {
    process.stderr.write("--posture requires --playbook-file <path>\n");
    process.exitCode = 1;
    return;
  }
  if (args.failOnDivergence && !args.posture) {
    process.stderr.write("--fail-on-divergence requires --posture\n");
    process.exitCode = 1;
    return;
  }
  if (args.baseline && !args.posture) {
    process.stderr.write("--baseline requires --posture\n");
    process.exitCode = 1;
    return;
  }
  // spec-v14 — a saved coherence baseline is an alternative source for the same
  // diff; it requires --posture (this round must produce a coherence) and is
  // mutually exclusive with re-analyzing a baseline bundle.
  if (args.baselineCoherence && !args.posture) {
    process.stderr.write("--baseline-coherence requires --posture\n");
    process.exitCode = 1;
    return;
  }
  if (args.baseline && args.baselineCoherence) {
    process.stderr.write("--baseline and --baseline-coherence are mutually exclusive\n");
    process.exitCode = 1;
    return;
  }
  if (args.failOnCoherenceRegression && !args.baseline && !args.baselineCoherence) {
    process.stderr.write(
      "--fail-on-coherence-regression requires --baseline or --baseline-coherence\n",
    );
    process.exitCode = 1;
    return;
  }
  if (args.emitCoherence && !args.posture) {
    process.stderr.write("--emit-coherence requires --posture\n");
    process.exitCode = 1;
    return;
  }

  const inputs = await resolveInputs(args.target);
  if (inputs.length === 0) {
    process.stderr.write(`no analyzable files matched: ${args.target}\n`);
    process.exitCode = 1;
    return;
  }

  let breached = false;
  // spec-v12 Thrust A — collect each document's posture so that, after the
  // bundle is analyzed, we can report how each negotiation front sits *across*
  // the documents (the cross-document axis of the v10 posture).
  const postures: CoherenceInput[] = [];
  for (const file of inputs) {
    const r = await analyzeFile(file, {
      playbookId: args.playbook,
      deps,
      delivery: args.delivery,
      criticalDates: args.criticalDates,
      checklist: args.checklist,
      customPlaybook,
      posture: args.posture,
    });

    const counts = { critical: 0, warning: 0, info: 0 };
    for (const f of r.run.findings) counts[f.severity]++;
    process.stdout.write(
      `${file}  [${r.playbook_id}]  ${counts.critical}C ${counts.warning}W ${counts.info}I\n`,
    );
    if (r.delivery) process.stdout.write(`  ${r.delivery.summary}\n`);
    if (r.critical_dates) {
      process.stdout.write(
        `  Critical dates: ${r.critical_dates.resolved_count} computed, ${r.critical_dates.unresolved_count} to verify manually.\n`,
      );
    }
    if (r.closing_checklist) {
      process.stdout.write(
        `  Closing checklist: ${r.closing_checklist.open_count} readiness item(s) to resolve.\n`,
      );
    }
    if (r.negotiation_posture) {
      const c = r.negotiation_posture.counts;
      process.stdout.write(
        `  Negotiation posture: ${c.ideal} ideal, ${c.acceptable} acceptable, ${c.below_acceptable} below floor, ${c.unevaluable} not stated.\n`,
      );
      postures.push({ document: file, posture: r.negotiation_posture });
    }

    for (const fmt of args.formats) {
      const content = await renderFormat(fmt, r, deps.dkb);
      if (args.out) {
        await mkdir(args.out, { recursive: true });
        const outName = basename(file, extname(file)) + FORMAT_EXT[fmt];
        await writeFile(join(args.out, outName), content);
      } else if (inputs.length === 1 && args.formats.length === 1) {
        process.stdout.write(content + "\n");
      }
    }

    if (args.failOn) {
      const worst = worstSeverity(r);
      if (worst !== null && SEVERITY_RANK[worst] <= SEVERITY_RANK[args.failOn]) breached = true;
    }
  }

  // spec-v12 Thrust A — cross-document posture coherence. Only meaningful for a
  // bundle (≥2 documents) classified against the same playbook ladder: it shows,
  // per front, whether the documents agree on the rung or one undercuts the
  // position, and surfaces the bundle's binding floor.
  let diverged = false;
  let coherence: PostureCoherence | null = null;
  if (args.posture && postures.length >= 2) {
    coherence = await bundlePostureCoherence(postures);
    process.stdout.write(renderCoherenceSummary(coherence));
    diverged = hasDivergence(coherence);
  }

  // spec-v14 Thrust B — emit this round's coherence as a portable, hash-verified
  // baseline artifact, so a later round can gate against it (--baseline-coherence)
  // without re-checking-out this round's documents. Off by default; additive.
  if (args.emitCoherence) {
    if (!coherence) {
      process.stderr.write(
        `\n--emit-coherence: no cross-document coherence to write (need ≥2 documents with a posture).\n`,
      );
    } else {
      // spec-v15 — pin the ladder the rungs were computed against so a consuming
      // round can refuse a cross-ladder diff. The ladder is always available here
      // (--emit-coherence requires --posture requires --playbook-file).
      const ladder = customPlaybook ? await ladderHash(customPlaybook) : null;
      await writeFile(args.emitCoherence, buildPostureCoherenceJson(coherence, ladder));
      process.stdout.write(`\nwrote coherence artifact → ${resolve(args.emitCoherence)}\n`);
    }
  }

  // spec-v13 Thrust A — cross-document posture movement. Given a baseline bundle
  // (a prior round of the same deal, classified against the SAME playbook), diff
  // the two coherences front-by-front: how did each binding floor move, and did
  // any front fracture or reconcile? Matched by dimension, so the baseline may
  // carry different filenames or a different document count. spec-v14 adds a
  // second baseline source: a saved coherence artifact, verified on load.
  let regressed = false;
  if (coherence && (args.baseline || args.baselineCoherence)) {
    let baselineCoherence: PostureCoherence | null;
    if (args.baselineCoherence) {
      const text = await readFile(args.baselineCoherence, "utf8").catch(() => null);
      if (text === null) {
        process.stderr.write(`\n--baseline-coherence: cannot read ${args.baselineCoherence}\n`);
        process.exitCode = 1;
        return;
      }
      const parsed = await parsePostureCoherenceJson(text);
      if (!parsed.ok) {
        process.stderr.write(
          `\n--baseline-coherence: invalid artifact ${args.baselineCoherence}:\n  ${parsed.errors.join("\n  ")}\n`,
        );
        process.exitCode = 1;
        return;
      }
      // spec-v15 — cross-ladder guard. A v2 artifact pins the ladder its rungs
      // sit on; refuse to diff it against a round computed on a different ladder
      // (comparing floors from two ladders is nonsense). A v1 artifact carries no
      // pin: fall back to v14's caller-owns-it contract with a clear note.
      if (parsed.ladderHash !== null) {
        const thisLadder = customPlaybook ? await ladderHash(customPlaybook) : null;
        if (thisLadder !== parsed.ladderHash) {
          process.stderr.write(
            `\n--baseline-coherence: ladder mismatch — the artifact was computed against a different playbook ladder ` +
              `(artifact ${parsed.ladderHash.slice(0, 12)}…, this round ${(thisLadder ?? "none").slice(0, 12)}…). ` +
              `Comparing binding floors across different ladders is meaningless; use the same --playbook-file for both rounds.\n`,
          );
          process.exitCode = 1;
          return;
        }
      } else {
        process.stderr.write(
          `\nnote: ${args.baselineCoherence} is an unpinned (v1) coherence artifact — cross-ladder verification unavailable; ` +
            `ensure both rounds used the same --playbook-file (spec-v15 pins this automatically for newly emitted artifacts).\n`,
        );
      }
      baselineCoherence = parsed.coherence;
    } else {
      baselineCoherence = await collectBaselineCoherence(args.baseline!, {
        deps,
        playbookId: args.playbook,
        customPlaybook,
      });
      if (!baselineCoherence) {
        process.stderr.write(
          `\n--baseline: ${args.baseline} yielded no cross-document coherence (need ≥2 documents with a posture).\n`,
        );
        process.exitCode = 1;
        return;
      }
    }
    const movement = await compareCoherence(baselineCoherence, coherence);
    process.stdout.write(renderCoherenceMovementSummary(movement));
    regressed = coherenceRegressed(movement);
  }

  if (args.out) process.stdout.write(`\nwrote ${args.formats.join(", ")} for ${inputs.length} file(s) → ${resolve(args.out)}\n`);
  if (breached) {
    process.stderr.write(`\n✗ findings breached --fail-on ${args.failOn}\n`);
    process.exitCode = 2;
  }
  if (args.failOnDivergence && diverged) {
    process.stderr.write("\n✗ posture diverges across the bundle (--fail-on-divergence)\n");
    process.exitCode = 2;
  }
  if (args.failOnCoherenceRegression && regressed) {
    process.stderr.write(
      "\n✗ the bundle's binding floor regressed vs. the baseline (--fail-on-coherence-regression)\n",
    );
    process.exitCode = 2;
  }
}

/**
 * Analyze a baseline bundle quietly (no per-file lines, no format output) and
 * return its cross-document coherence — the prior round to diff the current
 * bundle against (spec-v13). Returns `null` when fewer than two documents carry
 * a posture (nothing cross-document to compare). Every document is classified
 * against the SAME custom playbook the primary bundle used, so the two
 * coherences sit on one ladder.
 */
async function collectBaselineCoherence(
  target: string,
  opts: {
    deps: Awaited<ReturnType<typeof loadAccuracyDeps>>;
    playbookId?: string;
    customPlaybook?: import("../../src/playbooks/custom-playbook.js").CustomPlaybook;
  },
): Promise<PostureCoherence | null> {
  const inputs = await resolveInputs(target);
  const postures: CoherenceInput[] = [];
  for (const file of inputs) {
    const r = await analyzeFile(file, {
      playbookId: opts.playbookId,
      deps: opts.deps,
      customPlaybook: opts.customPlaybook,
      posture: true,
    });
    if (r.negotiation_posture) postures.push({ document: file, posture: r.negotiation_posture });
  }
  return postures.length >= 2 ? bundlePostureCoherence(postures) : null;
}

// `renderCoherenceMovementSummary` moved to `src/report/coherence-movement.ts`
// (beside its JSON sibling) in spec-v16 so both the `analyze --baseline*` path
// and the document-free `compare-coherence` command share one renderer; re-export
// it here so existing importers (and the test suite) keep their `./run.js` import.
export { renderCoherenceMovementSummary };

/**
 * Render the cross-document posture coherence (spec-v12) as human-readable
 * lines: the per-kind counts, then one line per divergent front naming the
 * binding floor and the document carrying it — the front a deal team most needs
 * to reconcile across a package.
 */
export function renderCoherenceSummary(coherence: PostureCoherence): string {
  const c = coherence.counts;
  const lines = [
    "\nCross-document posture coherence:",
    `  ${c.aligned} aligned, ${c.divergent} divergent, ${c.single} stated by one, ${c.unstated} unstated.`,
  ];
  for (const d of coherence.dimensions) {
    if (d.coherence !== "divergent") continue;
    const spread = d.tiers
      .filter((t) => t.tier !== "unevaluable")
      .map((t) => `${t.document}=${t.tier}`)
      .join(", ");
    lines.push(`  ⚠ ${d.dimension}: divergent (${spread}); binding floor ${d.weakest_tier} in ${d.weakest_documents.join(", ")}.`);
  }
  lines.push(`  coherence_hash: ${coherence.coherence_hash}`);
  return lines.join("\n") + "\n";
}

async function runVerify(argv: string[]): Promise<void> {
  // Sequential parse so a `--playbook <id>` placed *before* the positionals
  // does not leak its value into the positional list (a filter-by-prefix
  // approach would mis-assign the report path).
  const positional: string[] = [];
  let playbookId: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--playbook") {
      playbookId = argv[++i];
    } else if (argv[i]!.startsWith("--")) {
      throw new Error(`unknown flag "${argv[i]}"`);
    } else {
      positional.push(argv[i]!);
    }
  }
  const [reportPath, originalPath] = positional;
  if (!reportPath || !originalPath) {
    throw new Error("usage: verify <report.json> <original> [--playbook <id>]");
  }
  const saved = JSON.parse(await readFile(reportPath, "utf8")) as SavedReport;
  const original = await readFile(originalPath, "utf8");
  if (playbookId) saved.run.playbook_id = playbookId;
  const result = await verifyReproducibility(saved, original);
  process.stdout.write(explainReproResult(result) + "\n");
  if (!result.reproduced) process.exitCode = 3;
}

const USAGE = `vaulytica — deterministic legal-document linter (headless)

Commands:
  analyze <path|glob|dir> [--playbook <id>] [--format json,sarif,html,md,csv]
                          [--out <dir>] [--fail-on critical|warning|info]
                          [--delivery] [--critical-dates] [--checklist]
                          [--playbook-file <path>] [--posture]
                          [--fail-on-divergence]
                          [--baseline <path|glob|dir> | --baseline-coherence <coherence.json>]
                          [--emit-coherence <path>] [--fail-on-coherence-regression]
  diff    <a.json> <b.json> [--format markdown|json] [--exit-code]
  compare <base> <revised> [--playbook <id>] [--playbook-file <path>] [--posture]
                          [--format json|markdown]
                          [--fail-on critical|warning|info] [--fail-on-regression]
                          [--confirm-pairing]
  compare-coherence <base.coherence.json> <revised.coherence.json>
                          [--format markdown|json] [--fail-on-coherence-regression]
  coherence-trend <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-coherence-regression]
  coherence-shift-trend <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-fracture]
  coherence-arc <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-regression-or-fracture]
  coherence-exposure <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-exposure]
  coherence-persistence <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-open-exposure]
  coherence-breadth <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-widening-exposure]
  coherence-recurrence <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-recurring-exposure]
  coherence-volatility <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-volatile-exposure]
  coherence-synchrony <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-synchronized-exposure]
  coherence-settling <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-unsettled-exposure]
  coherence-onset <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-early-onset-exposure]
  coherence-latency <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-unrecovered-exposure]
  coherence-concurrency <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-concerted-fall]
  coherence-relapse <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-immediate-relapse]
  verify  <report.json> <original> [--playbook <id>]
`;

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);
  switch (command) {
    case "analyze":
      return runAnalyze(rest);
    case "diff":
      return runDiff(rest);
    case "compare":
      return runCompare(rest);
    case "compare-coherence":
      return runCompareCoherence(rest);
    case "coherence-trend":
      return runCoherenceTrend(rest);
    case "coherence-shift-trend":
      return runCoherenceShiftTrend(rest);
    case "coherence-arc":
      return runCoherenceArc(rest);
    case "coherence-exposure":
      return runCoherenceExposure(rest);
    case "coherence-persistence":
      return runCoherencePersistence(rest);
    case "coherence-breadth":
      return runCoherenceBreadth(rest);
    case "coherence-recurrence":
      return runCoherenceRecurrence(rest);
    case "coherence-volatility":
      return runCoherenceVolatility(rest);
    case "coherence-synchrony":
      return runCoherenceSynchrony(rest);
    case "coherence-settling":
      return runCoherenceSettling(rest);
    case "coherence-onset":
      return runCoherenceOnset(rest);
    case "coherence-latency":
      return runCoherenceLatency(rest);
    case "coherence-concurrency":
      return runCoherenceConcurrency(rest);
    case "coherence-relapse":
      return runCoherenceRelapse(rest);
    case "verify":
      return runVerify(rest);
    case undefined:
    case "--help":
    case "-h":
    case "help":
      process.stdout.write(USAGE);
      return;
    default:
      throw new Error(
        `unknown command "${command}" (expected: analyze | diff | compare | compare-coherence | coherence-trend | coherence-shift-trend | coherence-arc | coherence-exposure | coherence-persistence | coherence-breadth | coherence-recurrence | coherence-volatility | coherence-synchrony | coherence-settling | coherence-onset | coherence-latency | coherence-concurrency | coherence-relapse | verify)`,
      );
  }
}

// Run as a CLI only when invoked directly, not when imported by a test
// (importing for the unit tests must not trigger the dispatcher).
if (process.argv[1] && /run\.ts$/.test(process.argv[1])) {
  void main().catch((err) => {
    process.stderr.write(`vaulytica: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  });
}
