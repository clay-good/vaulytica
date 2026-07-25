/**
 * IPDATA-005 flags a data-heavy document that names personal data / PHI but
 * cites no governing regime. A HIPAA authorization uses HIPAA's own statutory
 * terms of art ("Covered Entity", "45 CFR 164") rather than the literal
 * "HIPAA", and reading only the acronym reported it as regime-less (v1.1.0).
 */
import { describe, expect, it } from "vitest";
import { rule as IPDATA005 } from "./IPDATA-005.js";
import { buildContext } from "../../_test-fixtures.js";

describe("IPDATA-005 — HIPAA terms of art count as a regime reference", () => {
  it("stays silent when PHI appears with 'Covered Entity' but no literal 'HIPAA'", () => {
    expect(
      IPDATA005.check(
        buildContext([
          "Authorization",
          'I authorize Cedar Point Medical Center (the "Covered Entity") to disclose my protected health information to the recipient named above.',
        ]),
      ),
    ).toBeNull();
  });

  it("still fires when personal data appears with no regime reference at all", () => {
    expect(
      IPDATA005.check(
        buildContext([
          "Data",
          "The vendor processes the personal data of end users for analytics and reporting.",
        ]),
      ),
    ).not.toBeNull();
  });
});
