/**
 * A secondary family is DETECTED, not confirmed — and every surface that
 * reports one has to say so.
 *
 * `familyIsPresent` admits a family on its vocabulary: a title keyword, or
 * three signals from `distinguishing_phrases` and `required_clauses`. That is
 * evidence the document uses the family's words, not that it IS one — and the
 * rules then run are largely ABSENCE rules, which assume it is.
 *
 * The measured case this guard was written for: an **83(b) election**, a
 * one-page letter to the IRS, activates `rspa` and `secondary-stock-transfer`
 * on genuine collocations — "83(b)", "restricted stock", "right of first
 * refusal" — and was told at CRITICAL that it lacked a vesting schedule and a
 * restricted-securities legend. It has neither because it is not a stock
 * purchase agreement; the agreement it elects against is.
 *
 * The old wording made that worse in both directions. It asserted the document
 * "also contains content from the families below" as fact, and when a wrongly
 * activated family found nothing it printed **"this family's requirements
 * appear to be met"** — silent false reassurance that the document satisfies a
 * family it is not, which is harder for a reader to catch than a false
 * critical.
 *
 * This is deliberately NOT suppression. No finding is hidden and no threshold
 * moved; the reader is told what the detection actually is. Suppression needs
 * a signal that separates *contains* from *discusses*, and
 * `family-activation-evidence.test.ts` records that no such signal is
 * currently available.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const SRC = join(process.cwd(), "src", "report");

/** Every surface that renders a secondary family's findings. */
const SURFACES: ReadonlyArray<[file: string, what: string]> = [
  [join(SRC, "docx.ts"), "the DOCX report"],
  [join(SRC, "html.ts"), "the standalone HTML report"],
  [join(SRC, "bundle.ts"), "the bundle DOCX's per-document subsection"],
  [join(process.cwd(), "tools", "cli", "run.ts"), "the CLI's terminal output"],
];

describe("the secondary-family caveat", () => {
  it("every surface says the family was detected, not confirmed", () => {
    const missing: string[] = [];
    for (const [file, what] of SURFACES) {
      const src = readFileSync(file, "utf8");
      // "not confirmed" is the load-bearing phrase; each surface words the
      // rest to fit its space.
      if (!/not confirmed/i.test(src)) missing.push(`${file} — ${what}`);
    }
    expect(
      missing,
      "a surface reports another family's findings without saying the family was only detected from vocabulary",
    ).toEqual([]);
  });

  it("no surface tells a reader the requirements of an unconfirmed family are met", () => {
    // The regression that matters most: a family the document is not, finding
    // nothing, and the report calling that compliance.
    const offenders: string[] = [];
    for (const [file, what] of SURFACES) {
      const src = readFileSync(file, "utf8");
      if (/requirements appear to be met/i.test(src)) offenders.push(`${file} — ${what}`);
    }
    expect(
      offenders,
      "an empty secondary family must not be reported as its requirements being satisfied",
    ).toEqual([]);
  });

  it("no surface asserts the document CONTAINS the detected family", () => {
    const offenders: string[] = [];
    for (const [file, what] of SURFACES) {
      const src = readFileSync(file, "utf8");
      if (/also contains content from/i.test(src)) offenders.push(`${file} — ${what}`);
    }
    expect(offenders, "containment is the claim the detection does not support").toEqual([]);
  });
});
