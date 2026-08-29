import { describe, expect, it } from "vitest";
import { rule as STRUCT_003 } from "./STRUCT-003.js";
import { buildContext } from "../../_test-fixtures.js";

describe("STRUCT-003 — an e-signed contract", () => {
  // A contract signed through DocuSign, Adobe Sign, or Dropbox Sign carries
  // the platform's stamp and a typed name beside a timestamp, with no
  // "Name:"/"Title:" grid beneath it. That is one weak token against a
  // two-token floor, so the executed copy of an enormous share of modern
  // contracts reported "No signature block detected" at `critical`.
  it.each([
    ["DocuSign", "DocuSign Envelope ID: 8C2A-441F-9E20-77B3"],
    ["Adobe Sign", "Adobe Acrobat Sign transaction ID: CBJCHBCAABAA"],
    ["Dropbox Sign", "Dropbox Sign document ID: 44f10c9e"],
    ["electronically signed", "Electronically signed by Dana Reyes on August 4, 2026"],
  ])("accepts an %s execution stamp", (_label, stamp) => {
    expect(
      STRUCT_003.check(
        buildContext([
          "Services Agreement",
          "Vendor shall provide the Services described in Exhibit A.",
          "ACME, INC.",
          "By: Dana Reyes (Aug 4, 2026 14:02 EDT)",
          stamp,
        ]),
      ),
    ).toBeNull();
  });

  it("still reports a document with no execution of any kind", () => {
    expect(
      STRUCT_003.check(
        buildContext([
          "Diligence Memorandum",
          "This memorandum summarizes the diligence findings for the board.",
        ]),
      ),
    ).not.toBeNull();
  });
});

describe("STRUCT-003 — a cover block is not a signature block (v1.19.0)", () => {
  // A broker's summary of insurance carries "Prepared for: … Prepared by: …
  // Date prepared: …" at the top. That yielded the distinct tokens "by" and
  // "date" in one paragraph, reaching the two-token floor and standing the
  // check down on a document nobody had signed.
  it("does not read a Prepared for / Prepared by cover block as an execution", () => {
    expect(
      STRUCT_003.check(
        buildContext([
          "Summary of Insurance",
          "Prepared for: Bramblewood Home Goods, Inc. Prepared by: Ashfield Risk Advisors LLC. Date prepared: June 18, 2026.",
          "This summary describes the coverage in force for the policy period shown.",
        ]),
      ),
    ).not.toBeNull();
  });

  it("still stands down on an approval block, which is an execution affordance", () => {
    expect(
      STRUCT_003.check(
        buildContext([
          "Data Protection Impact Assessment",
          "The assessment records the measures adopted for the processing.",
          "Measures approved by: Deirdre Salazar, General Counsel. Date: January 19, 2026.",
        ]),
      ),
    ).toBeNull();
  });
});
