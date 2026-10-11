/**
 * "Actionable" has one definition (spec-v51 §4): a finding that carries a
 * recommendation. Everything else is an observation about what the document
 * contains. An agent told to reach zero findings would delete the force
 * majeure clause to clear "Force majeure clause present"; the split is what
 * tells it, and a person, which findings are work.
 *
 * The compact report, the fix list (Markdown and CSV) and the comparison each
 * say it. Over every specimen, they must say the same thing.
 */
import { readdirSync } from "node:fs";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { isActionable } from "../../src/engine/finding.js";
import { compareRuns, buildComparisonJsonObject } from "../../src/report/compare.js";
import {
  OBSERVATION_NOTE,
  buildFixListCsv,
  buildFixListMarkdown,
} from "../../src/report/exports.js";
import {
  analyzeFile,
  buildBrief,
  loadAccuracyDeps,
  type AnalyzeResult,
} from "../../tools/cli/api.js";

const SPECIMENS = join(process.cwd(), "tests", "fixtures", "specimens");

/** The ten rules that reported a gap with no advice until 9.861.0. */
const GAP_RULES = [
  "RISK-011",
  "CHOICE-003",
  "TEMP-007",
  "STRUCT-009",
  "OBLI-003",
  "IPDATA-005",
  "STRUCT-004",
  "IPDATA-004",
  "TEMP-009",
  "TEMP-002",
];

let results: Array<{ name: string; r: AnalyzeResult }>;
beforeAll(async () => {
  const deps = await loadAccuracyDeps();
  results = [];
  for (const name of readdirSync(SPECIMENS)) {
    results.push({ name, r: await analyzeFile(join(SPECIMENS, name), { deps }) });
  }
}, 600_000);

describe("actionable", { timeout: 600_000 }, () => {
  it("is the same on the compact report, the fix list and the comparison", async () => {
    const wrong: string[] = [];
    for (const { name, r } of results) {
      const expected = r.run.findings.map(isActionable);
      const tasks = expected.filter(Boolean).length;

      const brief = buildBrief(r);
      if (JSON.stringify(brief.findings.map((f) => f.actionable)) !== JSON.stringify(expected)) {
        wrong.push(`${name}: brief findings`);
      }
      if (brief.actionable !== tasks) wrong.push(`${name}: brief count`);

      const md = buildFixListMarkdown(r.run);
      const [work, seen = ""] = md.split(/^## Observations \(\d+\)$/m);
      const boxes = (work!.match(/^- \[ \] \*\*[A-Z0-9-]+\*\* — /gm) ?? []).length;
      const observed = (seen.match(/^- \*\*[A-Z0-9-]+\*\* — /gm) ?? []).length;
      if (boxes !== tasks) wrong.push(`${name}: ${boxes} checkboxes for ${tasks} tasks`);
      if (observed !== expected.length - tasks) wrong.push(`${name}: observations`);
      // An observation never gets a checkbox, and the note is there to say why.
      if (/^- \[ \]/m.test(seen)) wrong.push(`${name}: a checkbox under Observations`);
      if (observed > 0 && !seen.includes(OBSERVATION_NOTE)) wrong.push(`${name}: no note`);

      const rows = buildFixListCsv(r.run).trimEnd().split("\r\n");
      if (!rows[0]!.endsWith(",actionable")) wrong.push(`${name}: csv header`);
      const yes = rows.slice(1).filter((row) => row.endsWith(",yes")).length;
      const no = rows.slice(1).filter((row) => row.endsWith(",no")).length;
      if (yes !== tasks || no !== expected.length - tasks) wrong.push(`${name}: csv column`);

      const cmp = buildComparisonJsonObject(await compareRuns(r.run, r.run));
      const flags = new Map(r.run.findings.map((f) => [f.rule_id, isActionable(f)]));
      if (cmp.unchanged.some((u) => u.actionable !== flags.get(u.rule_id))) {
        wrong.push(`${name}: comparison`);
      }
    }
    expect(wrong).toEqual([]);
  });

  it("splits the corpus as measured, and no warning or critical gap is left without advice", () => {
    const all = results.flatMap(({ r }) => r.run.findings);
    const tasks = all.filter(isActionable);
    // Measured on 9.881.0. A change here is a rule gaining or losing advice.
    expect(all).toHaveLength(1561);
    expect(tasks).toHaveLength(921);
    const silent = all.filter((f) => !isActionable(f) && f.severity !== "info");
    // The one non-info observation is a clause being present, not a gap.
    expect([...new Set(silent.map((f) => `${f.rule_id} ${f.title}`))]).toEqual([
      "PERS-002 Non-solicit clause present",
    ]);
  });

  it("the ten gap rules now say what to do", () => {
    const fired = results
      .flatMap(({ r }) => r.run.findings)
      .filter((f) => GAP_RULES.includes(f.rule_id));
    const seen = new Set(fired.map((f) => f.rule_id));
    // Anti-vacuity: most of the ten do fire on the corpus.
    expect(seen.size).toBeGreaterThanOrEqual(7);
    expect(fired.filter((f) => !isActionable(f)).map((f) => f.rule_id)).toEqual([]);
    for (const f of fired) expect(f.recommendation!.length).toBeGreaterThan(40);
  });

  it("an observation's advice is not to delete the clause", () => {
    const withObs = results.find(({ r }) => r.run.findings.some((f) => !isActionable(f)))!;
    const md = buildFixListMarkdown(withObs.r.run);
    expect(md).toContain("No change needed; do not remove the clause to clear this.");
    expect(md).toMatch(/^## Observations \(\d+\)$/m);
  });
});
