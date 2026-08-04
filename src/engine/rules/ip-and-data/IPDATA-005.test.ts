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

  it("recognizes CPRA / LGPD / DPA / SCCs as regime references (v1.2.0)", () => {
    const base = "The Processor handles personal data on behalf of the Controller.";
    for (const regime of [
      "The parties comply with the CPRA.",
      "The parties comply with the LGPD.",
      "This Data Processing Agreement governs the processing.",
      "Cross-border transfers rely on the Standard Contractual Clauses.",
    ]) {
      expect(IPDATA005.check(buildContext(["Data", `${base} ${regime}`])), regime).toBeNull();
    }
  });

  it("does not treat a bare 'SCC' arbitration reference as a data regime", () => {
    // "SCC" also abbreviates the Stockholm Chamber of Commerce; only "SCCs" /
    // the spelled form counts, so an arbitration clause is not a false regime.
    expect(
      IPDATA005.check(
        buildContext([
          "Data",
          "The Processor handles personal data. Disputes are resolved by the SCC in Stockholm.",
        ]),
      ),
    ).not.toBeNull();
  });

  it("recognizes US sector / state regimes and transfer instruments (v1.3.0)", () => {
    // Absence detector: naming any of these regimes must SUPPRESS the finding
    // — flagging "regime missing" over a contract that cites GLBA / FERPA /
    // VCDPA / the Data Privacy Framework was a false positive.
    for (const regime of [
      "The parties shall comply with the Gramm-Leach-Bliley Act (GLBA).",
      "Student records are governed by FERPA.",
      "Services directed to children comply with COPPA.",
      "The parties shall comply with the Virginia Consumer Data Protection Act (VCDPA).",
      "The parties shall comply with the Colorado Privacy Act.",
      "Cross-border transfers rely on the EU-U.S. Data Privacy Framework.",
    ]) {
      expect(
        IPDATA005.check(
          buildContext(["Data", "The Company processes personal data of users.", "Compliance", regime]),
        ),
        regime,
      ).toBeNull();
    }
  });
});
