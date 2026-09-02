import { describe, expect, it } from "vitest";
import { rule as STRUCT_006 } from "./STRUCT-006.js";
import { buildContext } from "../../_test-fixtures.js";

const doc = (heading: string, ...rest: string[]) => buildContext([heading, ...rest]);

/**
 * A document that imports its definitions is not missing them.
 *
 * "Capitalized terms used and not defined in this Amendment have the meanings
 * given in the Lease" appears in every amendment, addendum, statement of work,
 * side letter, and order form — documents whose whole point is that the parent
 * defines the vocabulary. A third amendment to an office lease was told that
 * Base Rent, Base Year, Proportionate Share, Fair Market Rental Value, and
 * Security Deposit were undefined, in a document whose Section 1 says exactly
 * where they are defined.
 */
describe("STRUCT-006 — incorporation by reference (v1.2.0)", () => {
  const AMENDMENT = [
    "Base Rent for the Existing Premises during the Extension Term is $38.50 per rentable square foot.",
    "Tenant shall continue to pay its Proportionate Share of Operating Expenses in excess of the Base Year.",
    "The Security Deposit is increased. Base Rent escalates annually and the Proportionate Share is restated.",
  ];

  it("stays silent when the document imports its definitions", () => {
    expect(
      STRUCT_006.check(
        doc(
          "Third Amendment to Office Lease",
          "Capitalized terms used and not defined in this Amendment have the meanings given in the Lease.",
          ...AMENDMENT,
        ),
      ),
    ).toBeNull();
  });

  it("still fires on the same text without the incorporation clause", () => {
    // The suppression is load-bearing, not incidental: the identical body,
    // with only the incorporation sentence removed, is exactly what the rule
    // exists to report.
    expect(STRUCT_006.check(doc("Third Amendment to Office Lease", ...AMENDMENT))).not.toBeNull();
  });

  it("is not disabled by a sentence that merely mentions defined terms", () => {
    // Both halves are required — capitalized terms not defined HERE, and their
    // meanings given THERE — so an ordinary reference does not switch the
    // check off.
    expect(
      STRUCT_006.check(
        doc(
          "Agreement",
          "The defined terms in this Agreement are listed in Schedule 1 and are used consistently throughout.",
          ...AMENDMENT,
        ),
      ),
    ).not.toBeNull();
  });
});

/**
 * A person the document names by their relationship to the declarant.
 *
 * A will, trust, power of attorney, or guardianship designation names the
 * people it benefits and appoints, and none of them is a PARTY — the only
 * party is the declarant — so the party-name subtraction could not reach them.
 * A well-drafted will was told that "Thomas Aurelio Harper" and "Nadia Harper
 * Okonkwo" are Title-Case terms it forgot to define.
 */
describe("STRUCT-006 — a named person is not an undefined term (v1.4.0)", () => {
  const WILL = (appositive: boolean) => {
    const husband = appositive ? "my husband, Thomas Aurelio Harper," : "Thomas Aurelio Harper";
    const daughter = appositive ? "my daughter, Nadia Harper Okonkwo," : "Nadia Harper Okonkwo";
    return buildContext([
      "Last Will and Testament of Eleanor Marguerite Harper",
      "I, Eleanor Marguerite Harper, of Columbus, Ohio, being of sound mind, declare this to be my Last Will and Testament.",
      `I give my residuary estate to ${husband} if he survives me by thirty days.`,
      `I appoint ${daughter} as successor Executor of this Will.`,
      "If Thomas Aurelio Harper does not survive me, my estate passes to Nadia Harper Okonkwo in equal shares.",
      "Thomas Aurelio Harper shall serve without bond, and Nadia Harper Okonkwo shall serve without bond.",
    ]);
  };

  it("is silent on the executor and the beneficiary a will appoints", () => {
    expect(STRUCT_006.check(WILL(true))).toBeNull();
  });

  // The suppression is load-bearing, not incidental: the identical will with
  // the relationship appositives removed is exactly what the rule reports.
  it("still reports the same names where nothing says they are people", () => {
    const found = STRUCT_006.check(WILL(false));
    expect(found?.description).toContain("Thomas Aurelio Harper");
    expect(found?.description).toContain("Nadia Harper Okonkwo");
  });
});

/**
 * A public OFFICE is defined by the state, not by this document (v1.5.0).
 * Every acknowledgment, affidavit, and recorded instrument names the officer
 * before whom it was taken, and none of them defines the office. A Louisiana
 * Act of Cash Sale was told that "Notary Public" is a term it forgot to
 * define.
 */
describe("STRUCT-006 — a public office is not an undefined term", () => {
  const ACT = (extra: string) =>
    buildContext([
      "Act of Cash Sale",
      "BE IT KNOWN that on this day, before me, the undersigned Notary Public, personally came and appeared the Vendor.",
      "The Vendor declared that he does grant, bargain, and sell the described property to the Purchaser.",
      "THUS DONE AND PASSED before me, Notary Public, and the undersigned competent witnesses.",
      extra,
    ]);

  it("is silent on the notary before whom the act was passed", () => {
    expect(STRUCT_006.check(ACT("The price is nine hundred thousand dollars cash."))).toBeNull();
  });

  it("still reports a Title-Case term beside it", () => {
    const found = STRUCT_006.check(
      ACT(
        "The sale is subject to the Permitted Exceptions, and the Permitted Exceptions are listed nowhere.",
      ),
    );
    expect(found?.description).toContain("Permitted Exceptions");
  });
});

/**
 * The document's OWN NAME is not a term it forgot to define (v1.6.0).
 *
 * Every instrument refers to itself in Title Case throughout — "this Written
 * Consent", "this Guaranty", "this Tolling Agreement" — and the name is
 * established by the line at the top of the page, not by a definitions
 * section. An action by written consent of a board was told that "Written
 * Consent" is an undefined term, in a document titled ACTION BY WRITTEN
 * CONSENT OF THE BOARD OF DIRECTORS. There is no drafting change that answers
 * it short of `this Written Consent (this "Written Consent")`.
 *
 * The title is read from the heading, or — when the ingest gives an unstyled
 * document none, which is what every pasted or plain-text document gets —
 * from the opening line. Reading the heading alone found the empty string and
 * suppressed nothing on exactly the documents that need it.
 */
describe("STRUCT-006 — a document's own name", () => {
  const CONSENT = (opening: string) =>
    buildContext([
      "",
      opening,
      "The undersigned, being all of the directors, adopt the following resolutions.",
      "This Written Consent may be executed in counterparts and shall be filed with the minutes.",
      "This Written Consent is effective as of February 24, 2026, and each Written Consent counterpart is an original.",
    ]);

  it("is silent on the name in the document's opening line", () => {
    expect(
      STRUCT_006.check(CONSENT("ACTION BY WRITTEN CONSENT OF THE BOARD OF DIRECTORS")),
    ).toBeNull();
  });

  // The suppression is load-bearing, not incidental: the identical body under
  // a title that does NOT name the document is exactly what the rule reports.
  it("still reports the term when the document is titled something else", () => {
    const found = STRUCT_006.check(CONSENT("MINUTES OF A SPECIAL MEETING"));
    expect(found?.description).toContain("Written Consent");
  });

  it("does not let a long opening paragraph suppress terms from its prose", () => {
    // The scan is capped, so a document whose first paragraph is body prose
    // cannot silence a term buried two hundred characters into it.
    const found = STRUCT_006.check(
      buildContext([
        "",
        "The parties acknowledge that the transactions contemplated by this instrument were negotiated at arm's length over a period of several months, and that each of them was represented by counsel of its own choosing throughout, and that the Settlement Escrow was funded accordingly.",
        "The Settlement Escrow shall be released in three tranches.",
        "Interest on the Settlement Escrow accrues to the depositor.",
      ]),
    );
    expect(found?.description).toContain("Settlement Escrow");
  });
});

/**
 * An INTERNAL FUNCTION is a department, not a defined term (v1.7.0).
 *
 * Every policy names the team that administers it — "report it to Trade
 * Compliance", "escalate to Information Security" — in Title Case, and no
 * policy stops to define its own org chart. An export control policy was told
 * that "Trade Compliance" is a term it forgot to define, in the paragraph
 * that tells employees to call them.
 */
describe("STRUCT-006 — an internal function", () => {
  const POLICY = (team: string) =>
    buildContext([
      "Export Control Policy",
      `Every counterparty is screened before shipment, and ${team} clears any hit in writing.`,
      `No controlled technology is released without a licence approved by ${team}.`,
      `${team} retains screening records for five years.`,
    ]);

  it.each([["Trade Compliance"], ["Information Security"], ["Global Procurement"]])(
    "is silent on %s",
    (team) => {
      expect(STRUCT_006.check(POLICY(team))).toBeNull();
    },
  );

  // Load-bearing: a Title-Case phrase that is NOT a function is still
  // reported from the identical sentences.
  it("still reports an ordinary undefined term in the same shape", () => {
    const found = STRUCT_006.check(POLICY("the Restricted Party List"));
    expect(found?.description).toContain("Restricted Party List");
  });
});

describe("STRUCT-006 — a document that ASSUMES a lease takes its vocabulary", () => {
  // An assignment steps one party into another's place and uses the assumed
  // instrument's vocabulary without redefining a word of it. A Virginia
  // retail-lease assignment was told that Base Rent, Additional Rent and
  // Retail Lease are terms it forgot to define — three terms the lease it
  // assumes exists to define, and which no drafting change could answer short
  // of restating the lease inside its own assignment.
  const PREAMBLE: [string, ...string[]] = [
    "Assignment and Assumption of Lease",
    'This Assignment and Assumption of Lease is made as of March 2, 2026 by and between Brambleton Optics LLC ("Assignor") and Corridor Dental Partners, PLLC ("Assignee").',
    'Assignor, as tenant, and Loudoun Gateway Holdings, L.P., as landlord, entered into that certain Retail Lease dated August 14, 2021 (the "Lease").',
  ];
  const ASSUMPTION =
    "Assignee assumes and agrees to perform all of the obligations of the tenant under the Lease, including the payment of Base Rent and Additional Rent.";
  const RETAINED =
    "Assignor remains liable for unpaid Base Rent and Additional Rent for the period ending on the Effective Date.";

  it("is silent once the assumption clause is present", () => {
    expect(
      STRUCT_006.check(buildContext([...PREAMBLE, ASSUMPTION, RETAINED] as [string, ...string[]])),
    ).toBeNull();
  });

  it("still reports the same terms when nothing is assumed", () => {
    // The assumption sentence is the whole of the difference. Say the same
    // thing WITHOUT stepping into the tenant's obligations — a direct
    // covenant to pay — and "Base Rent" is an undefined Title-Case term
    // again, which is the finding this rule is for.
    const covenant =
      "Assignee shall pay Base Rent and Additional Rent directly to Landlord on the first day of each month.";
    const finding = STRUCT_006.check(
      buildContext([...PREAMBLE, covenant, RETAINED] as [string, ...string[]]),
    );
    expect(finding?.description).toContain("Base Rent");
  });
});
