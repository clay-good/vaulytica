/**
 * Guards against the "only one party" overclaim in RISK-008 and TERM-003.
 *
 * Both rules recognized mutuality through exactly ONE phrasing — "neither
 * party will be liable" and "either party may terminate" — so a reciprocal
 * clause drafted as two symmetric grants was reported as one-sided.
 *
 * TERM-003 contradicted itself on the page: its `description` field prints the
 * matched text, so the finding read "Only one party may terminate for
 * convenience" directly above "Company may terminate … Customer may likewise
 * terminate …". RISK-008 claimed "Only one party is named as protected from
 * consequential damages" over an excerpt naming two.
 *
 * Both directions are pinned: a genuinely one-sided clause still fires.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../_test-fixtures.js";
import { rule as risk008 } from "./risk-allocation/RISK-008.js";
import { rule as term003 } from "./termination/TERM-003.js";

const doc = (heading: string, ...rest: string[]) => buildContext([heading, ...rest]);

describe("RISK-008 — consequential-damages waiver mutuality", () => {
  it("stays silent when the waiver is drafted as two symmetric grants", () => {
    expect(
      risk008.check(
        doc(
          "Limitation of Liability",
          "Company shall not be liable for any consequential, special, incidental, or punitive damages arising out of this Agreement, and Customer shall not be liable for any consequential, special, incidental, or punitive damages arising out of this Agreement.",
        ),
      ),
    ).toBeNull();
  });

  it("stays silent on the 'neither X nor Y' form", () => {
    expect(
      risk008.check(
        doc(
          "Limitation of Liability",
          "Neither Company nor Customer shall be liable for any consequential, special, incidental, or punitive damages.",
        ),
      ),
    ).toBeNull();
  });

  it("still honors the pre-existing 'neither party' form", () => {
    expect(
      risk008.check(
        doc(
          "Limitation of Liability",
          "Neither party shall be liable for any consequential, special, incidental, or punitive damages.",
        ),
      ),
    ).toBeNull();
  });

  it("still flags a genuinely one-sided waiver", () => {
    expect(
      risk008.check(
        doc(
          "Limitation of Liability",
          "Company shall not be liable for any consequential, special, incidental, or punitive damages arising out of this Agreement.",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("TERM-003 — termination-for-convenience mutuality", () => {
  it("stays silent when both parties are granted the right in separate sentences", () => {
    expect(
      term003.check(
        doc(
          "Termination",
          "Company may terminate this Agreement for convenience upon thirty (30) days prior written notice to Customer. Customer may likewise terminate this Agreement for convenience upon thirty (30) days prior written notice to Company.",
        ),
      ),
    ).toBeNull();
  });

  it("still honors the pre-existing 'either party' form", () => {
    expect(
      term003.check(
        doc(
          "Termination",
          "Either party may terminate this Agreement for convenience upon thirty (30) days prior written notice.",
        ),
      ),
    ).toBeNull();
  });

  it("still flags a genuinely asymmetric termination right", () => {
    expect(
      term003.check(
        doc(
          "Termination",
          "Company may terminate this Agreement for convenience upon thirty (30) days prior written notice to Customer.",
        ),
      ),
    ).not.toBeNull();
  });
});
