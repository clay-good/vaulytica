import { describe, expect, it } from "vitest";
import { rule as STRUCT_013 } from "./STRUCT-013.js";
import { buildContext } from "../../_test-fixtures.js";

describe("STRUCT-013 — unfilled template placeholders", () => {
  it("fires on [insert party name]", () => {
    const ctx = buildContext([
      "Agreement",
      `This Agreement is entered into between [insert party name], a Delaware corporation, and Beta LLC.`,
    ]);
    const f = STRUCT_013.check(ctx);
    expect(f?.severity).toBe("critical");
    expect(f?.title).toMatch(/Unfilled template placeholders: \d+/);
  });

  it("fires on [Customer Name] Title-Case placeholder", () => {
    const ctx = buildContext(["H", "Customer: [Customer Name]"]);
    expect(STRUCT_013.check(ctx)).not.toBeNull();
  });

  it("fires on [TBD], [REDACTED], [PLACEHOLDER]", () => {
    expect(STRUCT_013.check(buildContext(["H", "Renewal term: [TBD]"]))).not.toBeNull();
    expect(STRUCT_013.check(buildContext(["H", "Salary: [REDACTED]"]))).not.toBeNull();
    expect(STRUCT_013.check(buildContext(["H", "Term: [PLACEHOLDER]"]))).not.toBeNull();
  });

  it("fires on {{mustache}} placeholders", () => {
    const ctx = buildContext(["H", "Effective as of {{effective_date}}."]);
    expect(STRUCT_013.check(ctx)).not.toBeNull();
  });

  it("fires on <<angle>> placeholders", () => {
    const ctx = buildContext(["H", "Party A: <<COUNTERPARTY>>"]);
    expect(STRUCT_013.check(ctx)).not.toBeNull();
  });

  it("fires on long underscore lines and XXX placeholders", () => {
    expect(STRUCT_013.check(buildContext(["H", "Signed: __________________"]))).not.toBeNull();
    expect(
      STRUCT_013.check(buildContext(["H", "Order number XXXX from supplier."])),
    ).not.toBeNull();
  });

  it("silent on bracketed footnotes like [1] or [a]", () => {
    const ctx = buildContext(["H", "See note [1] and item [a] for details."]);
    expect(STRUCT_013.check(ctx)).toBeNull();
  });

  it("silent on a clean Common-Paper-shaped clause", () => {
    const ctx = buildContext([
      "Confidentiality",
      `Recipient shall protect Discloser's Confidential Information using the same degree of care it uses to protect its own confidential information of like importance.`,
    ]);
    expect(STRUCT_013.check(ctx)).toBeNull();
  });

  it("counts multiple placeholders", () => {
    const ctx = buildContext([
      "H",
      `Effective Date: [insert date]. Customer: [insert name]. Term: [TBD].`,
    ]);
    const f = STRUCT_013.check(ctx);
    expect(f?.title).toMatch(/\b3\b/);
  });

  it("silent on a judicial signature line", () => {
    // A court order ends in a rule and the judge's name. The bench titles were
    // missing from the recognized offices, so every order, judgment, and writ
    // reported its own signature line at `critical` as an unfilled template
    // placeholder — the one critical finding on a stipulated protective order.
    for (const line of [
      "_______________________________ Hon. Jeffrey S. Whitcombe United States District Judge",
      "_______________________________ Marisol Aguirre-Vance, United States Magistrate Judge",
      "____________ Peter Lindqvist, Judge of the Superior Court",
      "____________ Alice Nakamura, Chief Justice",
      "____________ Dermot Halloran, Clerk of the Court",
    ]) {
      expect(STRUCT_013.check(buildContext(["Signatures", line])), line).toBeNull();
    }
  });

  it("still fires on a template blank that names no signatory", () => {
    // The judicial broadening must not swallow a genuine unfilled field.
    expect(
      STRUCT_013.check(
        buildContext(["Signatures", "_______________________________ [Judge Name]"]),
      ),
    ).not.toBeNull();
  });

  it("silent on an office signature line ('____ Jordan Ellis, Director')", () => {
    expect(
      STRUCT_013.check(
        buildContext(["Signatures", "_______________________________ Jordan Ellis, Director"]),
      ),
    ).toBeNull();
    expect(
      STRUCT_013.check(
        buildContext([
          "Signatures",
          "_______________________________ Morgan Lee, Chief Financial Officer",
        ]),
      ),
    ).toBeNull();
    expect(
      STRUCT_013.check(
        buildContext([
          "Signatures",
          "_______________________________ Dana Whitfield, Incorporator",
        ]),
      ),
    ).toBeNull();
  });

  it("silent on a bare-name signature line of a known party (prenup / will style)", () => {
    expect(
      STRUCT_013.check(
        buildContext([
          "Prenuptial Agreement",
          'This Agreement is between Alexandra Reyes ("Alexandra") and Jonathan Pierce ("Jonathan"), who intend to marry.',
          "IN WITNESS WHEREOF, the parties have executed this Agreement.",
          "_______________________________ Alexandra Reyes",
          "_______________________________ Jonathan Pierce",
        ]),
      ),
    ).toBeNull();
  });

  it("silent on a bare-name signature line whose signatory is named ONLY in the block (v1.8.0)", () => {
    // A multi-member operating agreement lists its members on an exhibit, so
    // the individual signatories are never extracted as parties — the printed
    // name beneath the underscore rule is the only place they appear. A clean
    // "First Last" name still reads as a signature line, not a placeholder.
    expect(
      STRUCT_013.check(
        buildContext([
          "Operating Agreement",
          "This Agreement is entered into by and among the persons listed on Exhibit A.",
          "IN WITNESS WHEREOF, the Members have executed this Agreement.",
          "_______________________________ Jonathan Pierce",
          "_______________________________ Amara Okafor",
        ]),
      ),
    ).toBeNull();
  });

  it("silent on a bare-name signature line carrying an honorific ('____ Dr. Helena Vasquez') (v1.9.0)", () => {
    expect(
      STRUCT_013.check(
        buildContext([
          "Executive Employment Agreement",
          "IN WITNESS WHEREOF, the parties have executed this Agreement.",
          "_______________________________ Dr. Helena Vasquez",
        ]),
      ),
    ).toBeNull();
  });

  it("still fires when a bare underscore rule sits above a template field, not a name (v1.8.0)", () => {
    // The guard above must not swallow a genuine placeholder: "Company Name",
    // "Insert Party Name", "Print Name" carry a field-label token.
    expect(
      STRUCT_013.check(
        buildContext(["Signatures", "_______________________________ Company Name"]),
      ),
    ).not.toBeNull();
    expect(
      STRUCT_013.check(
        buildContext(["Signatures", "_______________________________ Insert Party Name"]),
      ),
    ).not.toBeNull();
  });

  it("silent on estate signatory lines ('____ Name, Testator', '____ Executor')", () => {
    expect(
      STRUCT_013.check(
        buildContext(["Will", "_______________________________ Margaret Holloway, Testator"]),
      ),
    ).toBeNull();
    expect(
      STRUCT_013.check(buildContext(["Will", "_______________________________ Executor"])),
    ).toBeNull();
  });

  it("silent on a medical-consent signatory line ('____ Name, Patient')", () => {
    expect(
      STRUCT_013.check(
        buildContext(["Authorization", "_______________________________ Jordan Alvarez, Patient"]),
      ),
    ).toBeNull();
  });

  it("silent on a bare-name line when the party carries a role parenthetical", () => {
    // 'Karen Whitfield (the "Petitioner")' is extracted with the parenthetical
    // attached; the printed signature is the bare name.
    expect(
      STRUCT_013.check(
        buildContext([
          "Marital Settlement Agreement",
          'This Agreement is between Karen Whitfield (the "Petitioner") and David Whitfield (the "Respondent").',
          "_______________________________ Karen Whitfield, Petitioner",
          "_______________________________ David Whitfield, Respondent",
        ]),
      ),
    ).toBeNull();
  });

  it("silent on a 'Signature of <role>' / 'Print Name of <role>' consent-form line", () => {
    expect(
      STRUCT_013.check(
        buildContext(["Consent", "_______________________________ Signature of Subject"]),
      ),
    ).toBeNull();
    expect(
      STRUCT_013.check(
        buildContext(["Consent", "_______________________________ Print Name of Witness"]),
      ),
    ).toBeNull();
  });

  it("silent on a standalone 'Notary Public' signature line", () => {
    expect(
      STRUCT_013.check(
        buildContext([
          "Acknowledgment",
          "Subscribed and sworn before me this day.",
          "_______________________________ Notary Public",
        ]),
      ),
    ).toBeNull();
  });

  it("still fires on an underscore run followed by a non-party placeholder", () => {
    expect(
      STRUCT_013.check(
        buildContext([
          "Agreement",
          "The parties agree.",
          "_______________________________ Insert Party Name Here",
        ]),
      ),
    ).not.toBeNull();
  });

  it("still fires on a real placeholder even alongside an office signature line", () => {
    expect(
      STRUCT_013.check(
        buildContext([
          "H",
          "Grant to [Grantee Name] shares.",
          "_______________________________ Jordan Ellis, Director",
        ]),
      ),
    ).not.toBeNull();
  });

  it("fires on ALL-CAPS field placeholders the Title-Case patterns missed", () => {
    for (const t of [
      "Closing shall occur on [DATE].",
      "The Buyer is [COMPANY NAME].",
      "Notices to [ADDRESS].",
      "Purchase price of [AMOUNT].",
      "Contact [EMAIL].",
    ]) {
      expect(STRUCT_013.check(buildContext(["H", t])), t).not.toBeNull();
    }
  });

  it("fires on a bracketed fill-in blank or bullet glyph", () => {
    expect(STRUCT_013.check(buildContext(["H", "The term is [__] years."]))).not.toBeNull();
    expect(STRUCT_013.check(buildContext(["H", "Amount: [ _____ ]."]))).not.toBeNull();
    expect(STRUCT_013.check(buildContext(["H", "The price is [●] dollars."]))).not.toBeNull();
    expect(STRUCT_013.check(buildContext(["H", "Deliver by [•]."]))).not.toBeNull();
  });

  it("does not flag a bracketed acronym, list marker, or empty checkbox", () => {
    for (const t of [
      "See Section [5.1].",
      "Exhibit [A] is attached.",
      "The parties [sic] agree.",
      "The [EU] regulation applies.",
      "Governed by [IV] of the Treaty.",
      "Check the box [ ] if applicable.",
    ]) {
      expect(STRUCT_013.check(buildContext(["H", t])), t).toBeNull();
    }
  });
});

describe("STRUCT-013 — a signature line labeled by office alone", () => {
  /**
   * A proposed order, decree, or QDRO leaves the bench a rule to sign over and
   * a label under it — "_______________________  Judge        Date" — with no
   * name to print until the judge signs. The by-office suppression required a
   * personal name BEFORE the office, so every such order reported its own
   * signature line at `critical` as an unfilled template placeholder.
   */
  it("does not fire on '____ Judge   Date'", () => {
    const ctx = buildContext([
      "Qualified Domestic Relations Order",
      "The Court retains jurisdiction to amend this Order.",
      "_______________________________ Judge                                    Date",
    ]);
    expect(STRUCT_013.check(ctx)).toBeNull();
  });

  it("does not fire on a consent signed '____ Secretary'", () => {
    const ctx = buildContext([
      "Written Consent",
      "The foregoing is adopted.",
      "______________________ Secretary",
    ]);
    expect(STRUCT_013.check(ctx)).toBeNull();
  });

  it("still fires on a template blank that names a field rather than an office", () => {
    const ctx = buildContext(["Order", "______________________ Company Name"]);
    expect(STRUCT_013.check(ctx)).not.toBeNull();
  });
});

describe("STRUCT-013 — a blank the reader is meant to fill in", () => {
  // "Program: ______  Date of event: ______" is the top of every consent form,
  // release, application, and intake sheet. The label is what makes it a form
  // field rather than template content the drafter forgot to replace.
  it("does not fire on a row of labeled fill-in fields", () => {
    const ctx = buildContext([
      "Photograph Release",
      "Program: ______________________________________  Date of event: ________________",
    ]);
    expect(STRUCT_013.check(ctx)).toBeNull();
  });

  it("does not fire on a bare field label under a signature rule", () => {
    const ctx = buildContext(["Release", "_______________________________ Printed name"]);
    expect(STRUCT_013.check(ctx)).toBeNull();
  });

  it("still fires when one blank in the row carries no label", () => {
    const ctx = buildContext([
      "Photograph Release",
      "Program: ______________________________________  ________________",
    ]);
    expect(STRUCT_013.check(ctx)).not.toBeNull();
  });

  // A rule that is the WHOLE paragraph, under a short heading that says what
  // to write in it, is a writing space. "EMPLOYEE COMMENTS" over a rule is a
  // line the employee fills in, and a performance improvement plan was told at
  // `critical` that it held unfilled template content.
  it("does not report a ruled writing space under its heading (v1.14.0)", () => {
    const ctx = buildContext([
      "Performance Improvement Plan",
      "Progress will be reviewed at each review date.",
      "EMPLOYEE COMMENTS",
      "_______________________________________________________________________________",
    ]);
    expect(STRUCT_013.check(ctx)).toBeNull();
  });

  it("still reports a rule left inside a sentence", () => {
    const ctx = buildContext([
      "Agreement",
      "Compensation",
      "The Company shall pay the Consultant $__________ per month during the Term.",
    ]);
    expect(STRUCT_013.check(ctx)).not.toBeNull();
  });

  // Two or more labeled blanks ANYWHERE in the document make it a form, and
  // whether the second shares a line with the first or sits three paragraphs
  // below is a fact about the layout. A HIPAA acknowledgment prints "Name of
  // patient: ____" and "Date: ____" on separate lines and was told at
  // `critical` that it held unfilled template content.
  it("does not report a form's fields laid out one per line (v1.15.0)", () => {
    const ctx = buildContext([
      "Acknowledgment of Receipt",
      "I acknowledge that I have received a copy of the Notice of Privacy Practices.",
      "Name of patient: ____________________________________________",
      "Date: ____________________",
    ]);
    expect(STRUCT_013.check(ctx)).toBeNull();
  });

  it("still reports an UNLABELED blank in a document with labeled fields", () => {
    const ctx = buildContext([
      "Agreement",
      "Name of party: ____________________",
      "Date: ____________________",
      "The Company shall pay ____________________ on the first day of each month.",
    ]);
    expect(STRUCT_013.check(ctx)).not.toBeNull();
  });

  // A blank form marks a field with prose as readily as with a colon. A HIPAA
  // authorization, which 45 C.F.R. § 164.508 requires to be a form, was told
  // at `critical` that five of its own fields were unfilled template content.
  it("does not report a form's prose-marked fields (v1.16.0)", () => {
    const ctx = buildContext([
      "Authorization for Release of Protected Health Information",
      "Patient name: ____________________________________________",
      "Date of birth: ____________________  Medical record number: ____________________",
      "Address: ____________________________________________",
      "Purpose of the disclosure: ____________________________________________",
      "Office visit notes for the period ____________________ through ____________________",
    ]);
    expect(STRUCT_013.check(ctx)).toBeNull();
  });
});
