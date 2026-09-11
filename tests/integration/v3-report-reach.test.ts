/**
 * The v3 report sections must be reachable from BOTH surfaces — and the
 * compliance matrix must stay out of them.
 *
 * `src/report/v3/` shipped six conditional renderers with spec-v3, with tests
 * behind each, and `buildDocxReport` accepted them as an optional fifth
 * argument the whole time. **Nothing constructed that argument.** The type, its
 * re-exports and the `docx.ts` parameter were its only mentions in the tree, so
 * the cross-border transfers summary (§56), the subprocessor inventory (§57)
 * and the insurance schedule (§58) were code that shipped, was tested, was
 * specified, and could not be obtained from anywhere. `buildV3ReportInputs`
 * (9.674.0) is the producer they never had.
 *
 * This is the same reach question `export-reach.test.ts` asks of the report
 * builders, one layer up: a section wired into one surface and not the other is
 * a section a script cannot get. Both call sites go through the one producer so
 * the browser and the CLI render the same pages from the same document.
 *
 * 🚨 **The second half of this file is the more important one.** The §54
 * compliance matrix is deliberately NOT produced. A `MatrixCell` carries a
 * status of Pass / Partial / Fail / N/A per column, and nothing maps a column
 * to the rules that decide it: playbooks declare `compliance_matrix_columns` as
 * human-readable LABELS ("AM Best rating ≥ A-", "General liability ≥ $1M /
 * $2M") and a single-string `regulator_frame`. Deriving a status from a label
 * would make this tool render a **legal conclusion** — the one thing its
 * posture forbids, and the highest-consequence version of the confidently-wrong
 * failure the rest of the engine spends its suite preventing. Authoring a
 * `compliance_matrix_rules` mapping is a legal judgment and belongs beside the
 * attorney sign-offs. See BUILD_PROGRESS step 32.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = process.cwd();

/** Every surface that renders a per-document DOCX report. */
const DOCX_SURFACES: ReadonlyArray<[file: string, what: string]> = [
  ["tools/cli/run.ts", "the CLI's --format docx"],
  ["src/ui/pipeline.ts", "the in-tab pipeline"],
];

describe("the v3 report sections reach both surfaces", () => {
  it("each surface builds the inputs rather than passing undefined", () => {
    const missing: string[] = [];
    for (const [file, what] of DOCX_SURFACES) {
      const src = readFileSync(join(ROOT, file), "utf8");
      if (!src.includes("buildDocxReport")) {
        missing.push(`${what}: no longer renders a DOCX — update this list`);
        continue;
      }
      // Both the producer AND the gate that feeds its result to the report.
      // Mentioning the producer is not using it: a surface that builds the
      // inputs and then passes `undefined` is exactly the state this file
      // exists to end. (ESLint's no-unused-vars catches the crudest form of
      // that, since the built value would be dead — this catches the rest.)
      if (!src.includes("buildV3ReportInputs")) {
        missing.push(`${what}: renders a DOCX without building the v3 sections`);
      } else if (!src.includes("hasV3Sections(")) {
        missing.push(`${what}: builds the v3 sections but never passes them`);
      }
    }
    expect(missing).toEqual([]);
  });

  it("both go through the one producer, so the surfaces cannot diverge", () => {
    // Two hand-rolled constructions would drift the moment a section is added.
    for (const [file, what] of DOCX_SURFACES) {
      const src = readFileSync(join(ROOT, file), "utf8");
      expect(src, `${what} constructs V3ReportInputs by hand`).not.toMatch(
        /:\s*V3ReportInputs\s*=|\bas V3ReportInputs\b/,
      );
    }
  });

  it("the renderers it feeds are real, shipped and exported", () => {
    // Anti-vacuity: the reach assertions above mean nothing if the sections
    // they reach have been deleted.
    const index = readFileSync(join(ROOT, "src", "report", "v3", "index.ts"), "utf8");
    for (const fn of ["renderTransfersSummary", "renderSubprocessorPage", "renderInsurancePage"]) {
      expect(index, `${fn} is no longer exported`).toContain(fn);
    }
  });
});

describe("the compliance matrix stays underivable until someone qualified derives it", () => {
  it("the producer does not build a matrix", () => {
    const src = readFileSync(join(ROOT, "src", "report", "v3", "inputs.ts"), "utf8");
    // Comments explain WHY it does not; the code must not start doing it.
    const code = src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
    expect(
      /\bmatrix\s*:/.test(code),
      "the producer started building a compliance matrix — read BUILD_PROGRESS " +
        "step 32 (b) first: a cell reading Pass is a legal conclusion",
    ).toBe(false);
  });

  it("no playbook maps a matrix column to the rules that decide it", () => {
    const schema = readFileSync(join(ROOT, "src", "playbooks", "types.ts"), "utf8");
    expect(schema).toContain("compliance_matrix_columns");
    expect(
      /compliance_matrix_rules|matrix_rule_ids|column_rule_map/.test(schema),
      "a column → rule mapping appeared in the playbook schema — the compliance " +
        "matrix may now be derivable; re-read BUILD_PROGRESS step 32 (b)",
    ).toBe(false);
  });
});

describe("a bundle's conflicts reach BOTH human-readable surfaces", () => {
  // 🚨 `docx.ts` renders the §59 consistency appendix from
  // `V3ReportInputs.consistency` — and nothing ever set it. The CLI hands the
  // same `ConsistencyRun` straight to `buildHtmlReport`, so one run put a
  // "Cross-document consistency" section in the HTML report and NOTHING in the
  // DOCX. `html.ts`'s own comment describes that state for the mirror image of
  // it — "a bundle's conflicts reached one human-readable surface and not the
  // other" — and it was repaired in that direction only.
  it("the producer accepts a consistency run and a section counts as one", () => {
    const src = readFileSync(join(ROOT, "src", "report", "v3", "inputs.ts"), "utf8");
    expect(src, "buildV3ReportInputs cannot carry a ConsistencyRun").toMatch(
      /consistency\?:\s*ConsistencyRun/,
    );
    expect(src, "the producer never sets it").toMatch(/\{ consistency: options\.consistency \}/);
    // A run whose ONLY v3 content is the appendix must still reach the report.
    expect(src, "hasV3Sections ignores the appendix").toMatch(/inputs\.consistency/);
  });

  it("the CLI defers the DOCX until the cross-document run exists", () => {
    const cli = readFileSync(join(ROOT, "tools", "cli", "run.ts"), "utf8");
    // The deferral list is what decides: a format rendered inside the
    // per-document loop cannot see a run that does not exist yet.
    expect(cli, "the DOCX is not deferred, so it renders before the run").toMatch(
      /fmt:\s*"sarif"\s*\|\s*"html"\s*\|\s*"docx"/,
    );
    expect(cli).toMatch(/consistency:\s*consistency \?\? undefined/);
  });
});
