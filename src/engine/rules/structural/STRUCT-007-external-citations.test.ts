import { describe, expect, it } from "vitest";
import { rule as STRUCT_007 } from "./STRUCT-007.js";
import { buildContext } from "../../_test-fixtures.js";

// Guard: an EXTERNAL statutory / instrument citation must NOT be reported as a
// broken intra-document cross-reference. The doc has real Sections 1-3; each
// external cite below should be excluded, so STRUCT-007 stays silent.
const EXTERNAL: string[] = [
  "Compliance with Section 409A of the Internal Revenue Code is required.",
  "As defined in Section 13(a) of the Securities Exchange Act of 1934.",
  "The parties observe Section 302 of the Sarbanes-Oxley Act.",
  "Processing is lawful under Article 6 of the GDPR.",
  "Consent is obtained pursuant to Article 7 GDPR.",
  "Rights arise under Section 1798.100 CCPA.",
  "As permitted by Section 220 of the General Corporation Law of the State of Delaware.",
  "The transfer follows Section 17-303 of the Act.",
  "Withholding follows Treasury Regulations under Section 704(b).",
  "Remedies are set out in Section 8.2 of the Purchase Agreement.",
  "Indemnification is governed by Article VIII thereof.",
  "Reporting complies with Section 1502 of Title 15 of the United States Code.",
  "Processing is lawful under Article 6 of the GDPR.",
  "Priority is governed by Section 9-203 of the UCC.",
  "Transfers comply with Article 46 of the Directive.",
  "Rights follow Article 8 of the Convention.",
  "Obligations arise under Article 12 of the Treaty.",
  "As set out in Section 4.1 of Annex I.",
  "As required by Article 5 of the Charter.",
];

describe("STRUCT-007 external-citation FP guard", () => {
  for (const cite of EXTERNAL) {
    it(`stays silent on: ${cite.slice(0, 50)}`, () => {
      const ctx = buildContext(
        ["1. Definitions", "Terms used herein have the meanings given."],
        ["2. Obligations", cite],
        ["3. Miscellaneous", "This Agreement is the entire agreement."],
      );
      const f = STRUCT_007.check(ctx);
      expect(f, `FALSE BROKEN-REF: ${f?.description ?? ""}`).toBeNull();
    });
  }
});
