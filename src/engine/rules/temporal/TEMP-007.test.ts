/**
 * A survival clause that carries ANOTHER instrument's obligations past
 * termination states no survival list of its own, so auditing it for the
 * typical surviving categories demands a list it never purported to state.
 */
import { describe, expect, it } from "vitest";
import { rule as TEMP_007 } from "./TEMP-007.js";
import { buildContext } from "../../_test-fixtures.js";

describe("an incorporation-by-reference survival is not a survival list (v1.2.0)", () => {
  it("does not audit categories against another instrument's incorporated terms", () => {
    const ctx = buildContext([
      "Restrictive Covenants",
      "The Executive's obligations under the Restrictive Covenant Agreement dated January 5, 2027 are incorporated by reference and survive termination of this Agreement in accordance with their terms.",
    ]);
    expect(TEMP_007.check(ctx)).toBeNull();
  });

  it("still audits a document's own survival list", () => {
    const ctx = buildContext([
      "Indemnity",
      "Supplier shall indemnify Customer against all third-party claims arising from the Services.",
      "Survival",
      "The confidentiality obligations of Section 5 survive termination of this Agreement for five years.",
    ]);
    const f = TEMP_007.check(ctx);
    expect(f).not.toBeNull();
    expect(f?.title).toMatch(/indemnity/);
  });

  it("does not report a category the document does not have (v1.4.0)", () => {
    // A charitable grant agreement has no confidentiality clause and no
    // indemnity. Reporting them as missing from its survival list is a defect
    // with no answer short of adding two clauses the instrument does not want.
    const ctx = buildContext([
      "Grant Agreement",
      "The Grantee shall repay any unexpended funds within sixty days after the end of the Grant Period.",
      "Sections 4, 6, and 7.5 survive termination of this Agreement.",
    ]);
    expect(TEMP_007.check(ctx)).toBeNull();
  });
});

describe("TEMP-007 — a survival list naming sections by their headings", () => {
  it("incorporates a section whose number is in its HEADING (DOCX layout)", () => {
    const ctx = buildContext(
      [
        "8. CONFIDENTIALITY",
        "Each party shall keep the other's confidential information confidential.",
      ],
      ["9. TERM", "Sections 8 and 10 survive termination."],
      ["10. INDEMNIFICATION", "Each party shall indemnify the other against third-party claims."],
    );
    expect(TEMP_007.check(ctx)).toBeNull();
  });

  it("incorporates the body under a bare numbered heading line (pasted layout)", () => {
    const ctx = buildContext([
      "Agreement",
      "8. RESTRICTIONS",
      "Each party shall keep the other's confidential information confidential.",
      "9. TERM",
      "Sections 8 and 10 survive termination.",
      "10. RISK",
      "Each party shall indemnify the other against third-party claims.",
    ]);
    expect(TEMP_007.check(ctx)).toBeNull();
  });
});

describe("TEMP-007 — a category named only in a heading", () => {
  // In a DOCX "3. Fees and Payment." is a section heading, not a paragraph.
  it("audits the payment terms the heading names", () => {
    const ctx = buildContext(
      ["3. Fees and Payment.", "Customer shall pay the Fees within thirty (30) days of invoice."],
      [
        "4. Term and Termination.",
        "Either party may terminate on notice. Sections 7 and 9 survive termination.",
      ],
      ["7. Confidentiality.", "Each party shall keep Confidential Information confidential."],
    );
    expect(TEMP_007.check(ctx)?.title).toMatch(/payment/);
  });
});
