/**
 * The v3 report layer has no producer, and this file says so on purpose.
 *
 * `src/report/v3/` ships six conditional renderers — the §54 compliance
 * matrix, the §55 citation index, the §56 transfers summary, the §57
 * subprocessor page, the §58 insurance page, the §59 consistency appendix —
 * with 16 passing tests behind them. `buildDocxReport` accepts them as an
 * optional fifth argument. **Nothing constructs that argument.** Not the
 * browser pipeline, not the CLI, not the API: the type, its re-exports and
 * the parameter are the only mentions in the tree.
 *
 * So this is the inverse of `export-reach.test.ts`, which asserts that every
 * report artifact the browser can produce the CLI can produce too. Here
 * NEITHER surface can produce them, and the failure is silent because each
 * half is correct on its own terms — exactly the shape that left nine other
 * artifacts headless-unreachable until 9.532.0.
 *
 * The test is an EQUALITY, not a prohibition. It does not say the layer must
 * stay dormant; it says the tree currently knows it is, so that the day
 * someone wires it up this file fails and points at the two things that are
 * actually in the way (recorded in full in BUILD_PROGRESS step 32):
 *
 *   (a) the wiring itself — a session's work, no new judgment needed for the
 *       transfers, subprocessor and insurance pages;
 *   (b) the compliance matrix's CELLS, which cannot be derived from the data
 *       that exists. Playbooks declare column LABELS and a single-string
 *       `regulator_frame`; nothing maps a column to the rules that decide it.
 *       Authoring that mapping is a legal judgment about what "Pass" means for
 *       a coverage minimum, and the product's posture forbids the shortcut —
 *       it lints, references and positions, but never renders a legal
 *       conclusion, and a cell reading "Pass" is one.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { DOCUMENT_READING_ROOTS, sourceFiles } from "./_recognizer-sources.js";

const ROOT = process.cwd();

/** Every non-test source file that could plausibly build the inputs. */
function candidateFiles(): string[] {
  return [...sourceFiles(join(ROOT, "src")), ...sourceFiles(join(ROOT, "tools"))].filter(
    (f) => !f.includes("/report/v3/"),
  );
}

describe("the v3 report layer's producer", () => {
  it("still has none, and BUILD_PROGRESS says why", () => {
    // A file "produces" the inputs if it names the type in a value position or
    // passes a fifth argument to buildDocxReport. Type-only imports and
    // re-exports do not count — they are how the type reaches the renderer.
    const producers: string[] = [];
    for (const file of candidateFiles()) {
      const src = readFileSync(file, "utf8");
      if (!src.includes("V3ReportInputs")) continue;
      const valueUse = /:\s*V3ReportInputs\s*=|\bas V3ReportInputs\b|v3:\s*\{/.test(src);
      if (valueUse) producers.push(file.replace(ROOT + "/", ""));
    }
    expect(
      producers,
      "someone wired the v3 report layer up — good. Update BUILD_PROGRESS step 32, " +
        "and read its (b) before touching the compliance MATRIX: the cells are not derivable.",
    ).toEqual([]);
  });

  it("no playbook maps a matrix column to the rules that decide it", () => {
    // The load-bearing half of (b). If this ever finds a mapping, the matrix
    // became derivable and the diagnosis in BUILD_PROGRESS needs revisiting.
    const schema = readFileSync(join(ROOT, "src", "playbooks", "types.ts"), "utf8");
    expect(schema).toContain("compliance_matrix_columns");
    expect(
      /compliance_matrix_rules|matrix_rule_ids|column_rule_map/.test(schema),
      "a column → rule mapping appeared in the playbook schema — the compliance " +
        "matrix may now be derivable; re-read BUILD_PROGRESS step 32 (b)",
    ).toBe(false);
  });

  it("the renderers it would feed are real, shipped and tested", () => {
    // Anti-vacuity in the other direction: this file is only worth having
    // while there is something dormant to point at.
    const index = readFileSync(join(ROOT, "src", "report", "v3", "index.ts"), "utf8");
    for (const fn of [
      "renderComplianceMatrix",
      "renderTransfersSummary",
      "renderSubprocessorPage",
      "renderInsurancePage",
    ]) {
      expect(index, `${fn} is no longer exported`).toContain(fn);
    }
    void DOCUMENT_READING_ROOTS;
  });
});
