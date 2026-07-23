/**
 * TERM-002 wanted the literal phrase "for cause" or "material breach", but a
 * for-cause path is usually written as the mechanism — terminate on a breach
 * that is not cured within a notice period. Those clauses were reported as
 * having no for-cause termination path.
 */
import { describe, expect, it } from "vitest";
import { rule as TERM_002 } from "./TERM-002.js";
import { buildContext } from "../../_test-fixtures.js";

const doc = (...paras: string[]) => buildContext(["Termination", ...paras]);

describe("TERM-002 — termination for cause present", () => {
  it("reads a breach-and-fail-to-cure path", () => {
    expect(
      TERM_002.check(
        doc(
          "Licensor may terminate this EULA immediately upon written notice if End User breaches any term of this EULA and fails to cure such breach within thirty (30) days.",
        ),
      ),
    ).toBeNull();
  });

  it("reads an uncured-non-compliance path stated before the verb", () => {
    expect(
      TERM_002.check(
        doc(
          "If the data importer cannot comply with these Clauses, the data exporter may suspend the transfer and, if non-compliance is not cured within thirty (30) days, terminate the portion of the MSA concerning the processing.",
        ),
      ),
    ).toBeNull();
  });

  it("still reads the literal 'material breach' phrase", () => {
    expect(TERM_002.check(doc("Either party may terminate for material breach."))).toBeNull();
  });

  it("still fires on a convenience-only termination clause", () => {
    expect(
      TERM_002.check(
        doc(
          "Either party may terminate this Agreement for convenience upon sixty (60) days written notice.",
        ),
      ),
    ).not.toBeNull();
  });

  it("does not read a breach-notification duty as a for-cause path", () => {
    expect(
      TERM_002.check(
        doc(
          "Business Associate shall report any breach of PHI to Covered Entity within sixty (60) days of discovery.",
        ),
      ),
    ).not.toBeNull();
  });

  it("does not stitch a termination verb to an uncured breach in another sentence", () => {
    expect(
      TERM_002.check(
        doc(
          "Vendor may terminate on notice. Customer must cure any breach that is not cured within the applicable period, separately.",
        ),
      ),
    ).not.toBeNull();
  });

  it("does not treat an immaterial-breach disclaimer as a for-cause path", () => {
    expect(
      TERM_002.check(
        doc(
          "An immaterial breach shall not give rise to any right of termination under this Agreement.",
        ),
      ),
    ).not.toBeNull();
  });
});
