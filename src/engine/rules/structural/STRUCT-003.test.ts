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
