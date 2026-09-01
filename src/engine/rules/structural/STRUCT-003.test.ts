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

describe("STRUCT-003 — an effective-date recital is not a signature field (v1.30.0)", () => {
  // Flattening a document's blank lines — a PDF copy-paste — merges the
  // "Effective Date: January 1, 2026." recital with the prose after it, and
  // "Date" plus a stray "by" reached the two-token floor. Four golden fixtures
  // engineered to LACK a signature block went silent in that layout.
  it("does not read an effective-date recital plus prose as an execution", () => {
    expect(
      STRUCT_003.check(
        buildContext([
          "Business Associate Agreement",
          "Business Associate shall safeguard PHI as required by the Security Rule.",
          "Effective Date: January 1, 2026. Execution. This BAA is executed by the Parties through their respective duly empowered officers, with execution evidenced solely by reference to the cover page of the Master Services Agreement; no separate execution lines are included.",
        ]),
      ),
    ).not.toBeNull();
  });

  it("still stands down on a real two-field signature line", () => {
    expect(
      STRUCT_003.check(
        buildContext([
          "Agreement",
          "Vendor shall provide the Services described in Exhibit A.",
          "ACME, INC.",
          "By: /s/ Dana Reyes  Name: Dana Reyes  Title: Chief Executive Officer  Date: August 4, 2026",
        ]),
      ),
    ).toBeNull();
  });
});

describe("STRUCT-003 — a policy is adopted, not signed (v1.31.0)", () => {
  // A records-retention policy and an audit committee charter have no
  // signature block, and reporting one as unsigned is a `critical` with no
  // answer. "Approved by the Audit Committee on March 2, 2026" names the BODY
  // that executed it and the date it did so.
  it("stands down on an adoption recital naming the adopting body and the date", () => {
    expect(
      STRUCT_003.check(
        buildContext([
          "Records Retention and Destruction Policy",
          "Approved by the Audit Committee on March 2, 2026. Owner: General Counsel.",
          "The retention period for each record type is set out in the schedule below.",
        ]),
      ),
    ).toBeNull();
  });

  it("reports the SAME policy when the adoption recital is removed", () => {
    // The load-bearing half: without the recital the document is identical and
    // still unsigned, so the recital is what stands the check down.
    expect(
      STRUCT_003.check(
        buildContext([
          "Records Retention and Destruction Policy",
          "Owner: General Counsel.",
          "The retention period for each record type is set out in the schedule below.",
        ]),
      ),
    ).not.toBeNull();
  });

  it("still reports an unsigned agreement whose only date is an effective date", () => {
    // The note on PUBLICATION_STAMP records why a bare "Effective Date:" must
    // not stand in for execution: plenty of SIGNED contracts carry one.
    expect(
      STRUCT_003.check(
        buildContext([
          "Services Agreement",
          "Effective Date: March 2, 2026.",
          "Provider shall perform the Services described in Exhibit A.",
        ]),
      ),
    ).not.toBeNull();
  });
});

describe("STRUCT-003 — a letter closing after a sentence end (v1.32.0)", () => {
  it("stands down when the flat layout merges the closing into the prose", () => {
    // Stripping a document's blank lines merges the whole filing into one
    // paragraph, and "Respectfully submitted," no longer starts a line.
    expect(
      STRUCT_003.check(
        buildContext([
          "Petition for a Writ of Certiorari",
          "Under this Court's Rule 10(c), the conflict among the courts of appeals warrants review. The petition should be granted. Respectfully submitted, DEVARSHI NANDAKUMAR Counsel of Record",
        ]),
      ),
    ).toBeNull();
  });

  it("does not read a mid-sentence 'respectfully submitted' as a closing", () => {
    expect(
      STRUCT_003.check(
        buildContext([
          "Memorandum",
          "Counsel respectfully submitted the exhibits to the clerk on Tuesday and awaits a ruling.",
        ]),
      ),
    ).not.toBeNull();
  });
});

describe("STRUCT-003 — the bare caption under the rule (v1.34.0)", () => {
  // A consent form, a release, a release of information, an application, an HR
  // acknowledgment: all are signed on a ruled line with a caption underneath,
  // and there is no "of" and no party name to match, because the person
  // signing is the reader and the form does not know their name yet. A BIPA
  // biometric consent laid out exactly this way reported itself unsigned at
  // `critical` — a finding with no answer, because the signature block it was
  // told to add was already there.
  it.each([
    ["a role-qualified caption", "Employee signature"],
    ["a bare caption", "Signature"],
    ["a printed-name caption", "Printed name"],
    ["a parenthetical print caption", "Name (printed)"],
  ])("accepts %s under the rule", (_label, caption) => {
    expect(
      STRUCT_003.check(
        buildContext([
          "Biometric Data Consent",
          "Halbrook Diagnostics, Inc. collects a fingerprint template for timekeeping.",
          "By signing below you consent to the collection described above.",
          `_________________________          ${caption}`,
        ]),
      ),
    ).toBeNull();
  });

  it("reads the caption beside its column neighbour", () => {
    expect(
      STRUCT_003.check(
        buildContext([
          "Biometric Data Consent",
          "Halbrook Diagnostics, Inc. collects a fingerprint template for timekeeping.",
          "_________________________          _________________________",
          "Employee signature                 Date",
        ]),
      ),
    ).toBeNull();
  });

  // The captions are matched WHOLE, which is what keeps a fill-in blank in the
  // body from standing the check down on a document nobody signed.
  it.each([
    [
      "a fill-in blank followed by a parenthetical",
      "between ________________ (Name) and the Company",
    ],
    ["a bare date column", "________________          Date"],
    ["a blank amount", "the sum of $________________ payable on the Closing Date"],
  ])("still reports %s", (_label, line) => {
    expect(
      STRUCT_003.check(
        buildContext(["Diligence Memorandum", "This memorandum summarizes the findings.", line]),
      ),
    ).not.toBeNull();
  });
});
