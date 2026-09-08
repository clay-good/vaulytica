/**
 * Running the OTHER families a document clearly contains.
 *
 * A composite document — an MSA with a data-processing exhibit, a services
 * agreement with a security addendum bolted on — matches one playbook and
 * contains several. `selectSecondaryFamilies` picks the others; this runs the
 * rules gated to each of them, so a present family is not skipped for want of
 * looking. Up to `MAX_SECONDARY_FAMILIES` of them — a cap 7 of the 312
 * specimens exceed, which the caller is responsible for stating.
 *
 * 🚨 **This lived inside `src/ui/pipeline.ts` as a private function, and the
 * headless path therefore did not have it at all.** Measured over the 312
 * specimens: **238 produce secondary-family findings — 2,629 of them, 1,333
 * CRITICAL — that `vaulytica analyze` never produced.** The browser tab and the
 * CI surface disagreed about what had been checked, and
 * `cross-surface-parity.test.ts` could not see it, because it compares
 * `EngineRun` and these findings deliberately live OUTSIDE the hashed run.
 * A parity test that compares only the hashed run is blind to every surface
 * that sits beside it.
 *
 * So the logic has one owner now and both callers pass their own rule catalog.
 *
 * ## What stays outside the run, and why
 *
 * Secondary findings are NOT merged into `run.findings`. The hashed run is the
 * matched family's verdict, and folding a second family's rules into it would
 * change `result_hash` for every composite document ever analyzed and silently
 * re-scope every `--fail-on` gate in every pipeline using this tool. They ride
 * alongside, exactly as they already do in the browser.
 */

import type { Finding, Rule } from "./finding.js";
import { runEngine } from "./runner.js";
import type { DKB } from "../dkb/types.js";
import type { Playbook } from "../playbooks/types.js";
import type { DocumentTree } from "../ingest/types.js";
import type { ExtractedData } from "../extract/types.js";

export type SecondaryFamilyRun = {
  playbook_id: string;
  playbook_name: string;
  findings: Finding[];
  counts: { critical: number; warning: number; info: number };
};

function countsOf(findings: readonly Finding[]): SecondaryFamilyRun["counts"] {
  let critical = 0;
  let warning = 0;
  let info = 0;
  for (const f of findings) {
    if (f.severity === "critical") critical++;
    else if (f.severity === "warning") warning++;
    else info++;
  }
  return { critical, warning, info };
}

/**
 * Run each secondary playbook against the document, using only the rules
 * **gated to that playbook** (`applies_to_playbooks`).
 *
 * That filter is the whole contract and it is easy to get wrong in the
 * generous direction: running the full catalog under a second playbook re-runs
 * every ungated rule and roughly doubles the finding count with duplicates of
 * what the primary run already reported. A playbook contributing no gated rule
 * is skipped entirely rather than emitting an empty family.
 *
 * `rules` is passed in rather than imported so the browser and the headless
 * path each supply the catalog they already hold, and neither can drift into
 * running a different one than it thinks it is.
 */
export async function runSecondaryFamilies(
  secondaryPlaybooks: ReadonlyArray<Playbook>,
  rules: readonly Rule[],
  ctx: {
    tree: DocumentTree;
    extracted: ExtractedData;
    dkb: DKB;
    source_file: { name: string; sha256: string; size_bytes: number };
  },
): Promise<SecondaryFamilyRun[]> {
  const out: SecondaryFamilyRun[] = [];
  for (const sp of secondaryPlaybooks) {
    const subset = rules.filter((r) => r.applies_to_playbooks?.includes(sp.id));
    if (subset.length === 0) continue;
    const run = await runEngine({
      rules: subset,
      ctx: { tree: ctx.tree, extracted: ctx.extracted, dkb: ctx.dkb, playbook: sp },
      source_file: ctx.source_file,
      executed_at: "",
    });
    out.push({
      playbook_id: sp.id,
      playbook_name: sp.name,
      findings: run.findings,
      counts: countsOf(run.findings),
    });
  }
  return out;
}
