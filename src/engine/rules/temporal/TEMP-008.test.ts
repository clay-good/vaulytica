import { describe, expect, it } from "vitest";
import { rule as TEMP_008 } from "./TEMP-008.js";
import { buildContext } from "../../_test-fixtures.js";

const doc = (...paras: string[]) => buildContext(["Term and Termination", ...paras]);

// 🥇 THE COMMONEST CURE CLAUSE IN ENGLISH PUTS THE BREACH IN THE OTHER CLAUSE
// (9.643.0). "…materially breaches this Agreement and FAILS TO CURE WITHIN
// THIRTY (30) DAYS" — the breach noun is before the conjunction and the count
// is after the verb, so neither the forward nor the count-first branch saw it.
// 24 of 322 corpus specimens state their cure period this way.
describe("TEMP-008 — the fails-to-cure form", () => {
  it.each([
    [
      "Either party may terminate this Agreement if the other materially breaches it and fails to cure within thirty (30) days after written notice.",
      30,
    ],
    [
      "Company may terminate if Vendor does not cure within ten (10) business days after notice.",
      10,
    ],
    ["If Supplier fails to cure within sixty (60) days, Buyer may terminate the order.", 60],
  ])("reads %s", (text, days) => {
    const f = TEMP_008.check(doc(text));
    expect(f?.title).toBe(`Cure period: ${days} days`);
  });

  // "CORRECT" IS AN ORDINARY WORD AND "CURE" IS A TERM OF ART. An
  // acceptance-testing correction window is not a material-breach cure period,
  // and a complete software licence reported 20 days on this sentence when its
  // cure period is the 30 days in its termination clause.
  it("does not read an acceptance-test correction window as a cure period", () => {
    expect(
      TEMP_008.check(
        doc(
          "Licensee shall notify Licensor in writing of any failure to meet the acceptance criteria. Licensor shall correct the failure within twenty (20) days and Licensee shall retest.",
        ),
      ),
    ).toBeNull();
  });

  // …but "cure the failure" still is one: the verb presupposes a breach.
  it("still reads 'cure the failure' as a cure period", () => {
    expect(
      TEMP_008.check(
        doc(
          "If Lessee fails to maintain the insurance required by this Lease, Lessor may declare a default unless Lessee shall cure the failure within thirty (30) days after written notice.",
        ),
      )?.title,
    ).toBe("Cure period: 30 days");
  });
});
