import { describe, expect, it } from "vitest";

describe("RISK-002 — a parent instrument named with more than one word", () => {
  // An indemnity "under the Purchase Agreement" describes a PARENT deal's
  // allocation, not an indemnity of this document, and the guard that says so
  // read only a ONE-word title: "under the Stock Purchase Agreement" fell
  // straight through, so an escrow securing the seller's obligations under it
  // was scored as seller-heavy asymmetry. The rule lowercases its sentence
  // before testing, so the word count — not capitalization — is what bounds
  // the title here.
  const GUARD = /indemnif[^.]{0,60}\bunder\s+the\s+(?:[a-z]+\s+){1,4}agreement\b/;

  it("recognizes a one-, two-, and four-word parent title", () => {
    for (const s of [
      "seller's indemnification obligations under the purchase agreement",
      "seller's indemnification obligations under the stock purchase agreement",
      "seller's indemnification obligations under the asset purchase and contribution agreement",
    ]) {
      expect(GUARD.test(s), s).toBe(true);
    }
  });

  it("does not treat 'under this Agreement' as a parent", () => {
    expect(GUARD.test("each party shall indemnify the other under this agreement")).toBe(false);
  });
});
