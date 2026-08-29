/**
 * v6 behavior guards — both directions (spec-v46.md §10).
 *
 * One representative check from each of the fifteen families, pinned so a
 * compliant document is left alone and a document missing the term is
 * flagged. The compliant fixtures are written the way the rule's own
 * recommendation says to write them, which is the test that the
 * recommendation is actually actionable.
 */

import { describe, expect, it } from "vitest";
import { buildContext } from "../../_test-fixtures.js";
import { V6_RULES } from "./index.js";

const rule = (id: string) => {
  const r = V6_RULES.find((x) => x.id === id);
  if (!r) throw new Error(`no v6 rule ${id}`);
  return r;
};

const doc = (heading: string, ...rest: string[]) =>
  buildContext([heading, ...rest], ["Signature", "/s/ Jane Roe, Esq."]);

const bare = (heading: string) =>
  doc(heading, "This document is submitted as of the date set forth above.");

const CASES: Array<{ id: string; heading: string; present: string[] }> = [
  {
    id: "ENG-001",
    heading: "Engagement Letter",
    present: [
      "The scope of the representation is the negotiation of the asset purchase described below.",
      "This engagement does not include tax advice, appeals, or any related matter, and we do not represent any affiliate.",
    ],
  },
  {
    id: "ENG-010",
    heading: "Contingency Fee Agreement",
    present: [
      "Our contingent fee is one-third of the recovery.",
      "Case expenses are deducted after the contingent fee is calculated, so the fee is computed on the gross recovery.",
    ],
  },
  {
    id: "ENG-011",
    heading: "Contingency Fee Agreement",
    present: [
      "Our contingent fee is 33% of the recovery.",
      "If there is no recovery, you will not be responsible for our fees, but you will owe the case expenses we advanced.",
    ],
  },
  {
    id: "ENG-018",
    heading: "Flat Fee Agreement",
    present: [
      "The flat fee of $7,500 is paid in advance and held in our client trust account until the corresponding milestone is completed.",
    ],
  },
  {
    id: "ENG-022",
    heading: "Joint Representation Conflict Waiver",
    present: [
      "Because this is a common representation, information one of you gives us will be shared with the others, and no confidences will be kept among you.",
      "In a later dispute between you, the attorney-client privilege will not protect these communications as between each other.",
    ],
  },
  {
    id: "ENG-029",
    heading: "Limited Scope Representation Agreement",
    present: [
      "You are responsible for every task not listed above, including calendaring each court deadline, filing your own papers, effecting service, and appearing at any hearing we have not agreed to cover.",
    ],
  },
  {
    id: "ENG-033",
    heading: "Closing Letter",
    present: [
      "We have no further obligation to monitor any deadline in this matter, including the statute of limitations or any appeal period, and we will not advise you of them.",
    ],
  },
  {
    id: "DISC-004",
    heading: "Requests for Production",
    present: [
      "Electronically stored information shall be produced in native format with all metadata preserved, or as single-page TIFF with load files containing the fields listed in Schedule A.",
    ],
  },
  {
    id: "DISC-009",
    heading: "Interrogatories",
    present: [
      "Each interrogatory must be answered separately and fully in writing under oath, and the answers must be signed by the person making them.",
    ],
  },
  {
    id: "DISC-012",
    heading: "Requests for Admission",
    present: [
      "You must serve a written answer or objection within 30 days of service. Any matter not answered within that period is deemed admitted under Rule 36(a)(3).",
    ],
  },
  {
    id: "DISC-018",
    heading: "Responses and Objections to Requests for Production",
    present: [
      "Responding Party objects to this request as overbroad because it seeks documents outside the 2019-2021 period.",
      "Subject to that objection, no responsive documents are being withheld on the basis of the objection.",
    ],
  },
  {
    id: "DISC-025",
    heading: "Privilege Log",
    present: [
      "Each entry states the nature of the document and its general subject matter without revealing the protected information, sufficient to enable the other parties to assess the claim.",
    ],
  },
  {
    id: "DISC-032",
    heading: "Rule 26(f) Report",
    present: [
      "The parties jointly request entry of an order under Federal Rule of Evidence 502(d) providing that production does not waive privilege, together with the clawback procedure attached.",
    ],
  },
  {
    id: "DISC-036",
    heading: "Notice of Deposition",
    present: [
      "PLEASE TAKE NOTICE that the deposition will be taken on March 14, 2026, commencing at 9:30 a.m., at the offices of Roe & Roe located at 100 Main Street.",
    ],
  },
  {
    id: "PLDG-002",
    heading: "Complaint",
    present: [
      "This Court has jurisdiction under 28 U.S.C. § 1332 because the parties are of diverse citizenship and the amount in controversy exceeds $75,000, exclusive of interest and costs.",
    ],
  },
  {
    id: "PLDG-006",
    heading: "Complaint",
    present: [
      "WHEREFORE, Plaintiff demands judgment against Defendant for compensatory damages, costs, attorneys' fees, and such other and further relief as the Court deems just.",
    ],
  },
  {
    id: "PLDG-008",
    heading: "Complaint",
    present: ["Plaintiff hereby demands a trial by jury on all issues so triable."],
  },
  {
    id: "PLDG-010",
    heading: "Answer and Affirmative Defenses",
    present: [
      "1. Defendant admits the allegations of paragraph 1.",
      "2. Defendant denies each and every allegation of paragraph 2.",
    ],
  },
  {
    id: "PLDG-012",
    heading: "Answer and Affirmative Defenses",
    present: [
      "FIRST AFFIRMATIVE DEFENSE: The claims are barred by the applicable statute of limitations.",
      "SECOND AFFIRMATIVE DEFENSE: The claims are barred by waiver, estoppel, and release.",
    ],
  },
];

describe.each(CASES)("v6 rule $id", ({ id, heading, present }) => {
  it("stays silent when the document carries the term", () => {
    const finding = rule(id).check(doc(heading, ...present));
    expect(finding, `${id} flagged a compliant clause: ${finding?.title ?? ""}`).toBeNull();
  });

  it("fires when the document does not", () => {
    const finding = rule(id).check(bare(heading));
    expect(finding, `${id} did not fire on a document missing the term`).not.toBeNull();
    expect(finding!.rule_id).toBe(id);
  });
});

describe("v6 rule ENG-006 (gated on an advance actually being taken)", () => {
  it("stays silent when the advance is held in trust", () => {
    expect(
      rule("ENG-006").check(
        doc(
          "Engagement Letter",
          "You will pay an advance retainer of $10,000, which we will deposit in our client trust account and withdraw only as fees are earned and expenses incurred.",
        ),
      ),
    ).toBeNull();
  });

  it("fires when an advance is taken with no trust-account treatment stated", () => {
    expect(
      rule("ENG-006").check(
        doc(
          "Engagement Letter",
          "You will pay an advance retainer of $10,000 before we begin work.",
        ),
      ),
    ).not.toBeNull();
  });

  it("does not demand a retainer clause from a letter that takes no advance", () => {
    expect(
      rule("ENG-006").check(
        doc("Engagement Letter", "We will bill monthly in arrears at the rates set out above."),
      ),
    ).toBeNull();
  });
});

describe("v6 applicability gates", () => {
  it("does not demand a Rule 9(b) particularity showing from a breach-only complaint", () => {
    expect(
      rule("PLDG-005").check(
        doc(
          "Complaint",
          "1. Defendant breached the Agreement by failing to deliver the goods by the delivery date.",
        ),
      ),
    ).toBeNull();
  });

  it("still demands it once fraud is pleaded", () => {
    expect(
      rule("PLDG-005").check(
        doc("Complaint", "1. Defendant made a fraudulent misrepresentation to induce the sale."),
      ),
    ).not.toBeNull();
  });

  it("does not demand 30(b)(6) topics from an individual deposition notice", () => {
    expect(
      rule("DISC-038").check(
        doc(
          "Notice of Deposition",
          "PLEASE TAKE NOTICE that the deposition of John Doe will be taken on March 14, 2026 at 9:30 a.m.",
        ),
      ),
    ).toBeNull();
  });

  it("does not demand the interrogatory verification from a document-request response", () => {
    expect(
      rule("DISC-022").check(
        doc(
          "Responses and Objections to Requests for Production",
          "Responding Party will produce all responsive, non-privileged documents by April 1, 2026.",
        ),
      ),
    ).toBeNull();
  });

  it("flags the 'subject to and without waiving' formulation only when it appears", () => {
    expect(
      rule("DISC-019").check(
        doc(
          "Responses and Objections",
          "Responding Party objects to this request as overbroad and will produce responsive documents by April 1, 2026.",
        ),
      ),
    ).toBeNull();
    expect(
      rule("DISC-019").check(
        doc(
          "Responses and Objections",
          "Subject to and without waiving the foregoing objections, Responding Party will produce responsive documents.",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("v6 engagement — the boundary as a negative sentence (v1.0.1)", () => {
  it("ENG-001 reads 'we will not represent … in any appeal' as the scope boundary", () => {
    // Rule 1.2(c) asks for the limitation, not for a particular sentence
    // shape, and the commonest drafting states it negatively. The pillar read
    // only the affirmative framings, so a letter that drew the boundary
    // exactly as the rule contemplates was told at `critical` that it had not.
    expect(
      rule("ENG-001").check(
        doc(
          "Engagement Letter",
          "SCOPE OF REPRESENTATION. We will represent the Company in the contract dispute with Boreal Freight LLC.",
          "We will not represent the Company in any appeal, in any tax matter, or in any other matter unless we agree in writing to do so.",
        ),
      ),
    ).toBeNull();
  });

  it("ENG-001 still fires on a letter that never draws the boundary", () => {
    expect(
      rule("ENG-001").check(
        doc(
          "Engagement Letter",
          "SCOPE OF REPRESENTATION. We will represent the Company in the contract dispute with Boreal Freight LLC.",
          "Our fees are based on the hourly rates set out below.",
        ),
      ),
    ).not.toBeNull();
  });

  it("ENG-001 reads the possessive limiting sentence and the undertaking not taken on (v1.0.2)", () => {
    // Found by running the rule on a hand-written engagement letter: the
    // limitation takes a possessive as readily as a demonstrative, and the
    // exclusion is as often an undertaking NOT taken on as a bare "we will
    // not represent". Both are Rule 1.2(c) drafting.
    expect(
      rule("ENG-001").check(
        doc(
          "Engagement Letter",
          "1. Scope of the Engagement. We will represent you in the trade-secret action against Cardinal Metrology, Inc.",
          "Our representation is limited to the Matter. We are not undertaking to advise you on tax, accounting, or regulatory matters.",
        ),
      ),
    ).toBeNull();
  });

  it("ENG-001 still fires when the letter only names the scope and never bounds it (v1.0.2)", () => {
    // The widened pillar must not admit a letter that merely says what it
    // covers: "limited to" and "not undertaking" are the boundary, and their
    // absence is the finding.
    expect(
      rule("ENG-001").check(
        doc(
          "Engagement Letter",
          "1. Scope of the Engagement. We will represent you in the trade-secret action against Cardinal Metrology, Inc.",
          "Our representation began on March 4, 2026, and we are undertaking it on the terms below.",
        ),
      ),
    ).not.toBeNull();
  });

  it("ENG-002 reads the constituent disclaimer stated as an undertaking not taken on (v1.0.2)", () => {
    expect(
      rule("ENG-002").check(
        doc(
          "Engagement Letter",
          "We will represent Northgate Instrument Company (the \u201CClient\u201D) in this matter.",
          "We are not undertaking to represent any parent, subsidiary, affiliate, officer, director, or employee of the Client unless we agree in a separate writing.",
        ),
      ),
    ).toBeNull();
  });

  it("ENG-002 still fires when the letter names the client but never disclaims its constituents (v1.0.2)", () => {
    expect(
      rule("ENG-002").check(
        doc(
          "Engagement Letter",
          "We will represent Northgate Instrument Company (the \u201CClient\u201D) in this matter.",
          "We are undertaking to represent the Client on the terms set out in this letter.",
        ),
      ),
    ).not.toBeNull();
  });

  it("ENG-002 reads the future tense a letter written before the work uses", () => {
    expect(
      rule("ENG-002").check(
        doc(
          "Engagement Letter",
          "We will represent Chen Manufacturing, Inc. in this matter.",
          "We do not represent its officers, directors, shareholders, or any affiliate absent a separate engagement.",
        ),
      ),
    ).toBeNull();
  });
});

describe("v6 pleadings — the state-court complaint (v1.0.1)", () => {
  it("PLDG-002 reads jurisdiction pleaded under a state long-arm statute", () => {
    // Every alternative in the grounds pillar was federal, and most complaints
    // in the United States are filed in state court.
    expect(
      rule("PLDG-002").check(
        doc(
          "Complaint at Law and Demand for Jury Trial",
          "JURISDICTION AND VENUE",
          "3. This Court has jurisdiction over Defendant because Defendant transacted business within Illinois and the claims arise from that business, pursuant to 735 ILCS 5/2-209.",
        ),
      ),
    ).toBeNull();
  });

  it("PLDG-002 still fires on a complaint that pleads the conclusion and not the grounds", () => {
    // Rule 8(a)(1) asks for the GROUNDS. A bare assertion is what the rule
    // exists to catch, so the state-court form is admitted only with a
    // because / pursuant to / under.
    expect(
      rule("PLDG-002").check(
        doc(
          "Complaint at Law",
          "JURISDICTION",
          "3. This Court has jurisdiction. Plaintiff seeks damages in an unspecified sum.",
        ),
      ),
    ).not.toBeNull();
  });

  it("PLDG-003 reads venue pleaded in a county under a state statute", () => {
    expect(
      rule("PLDG-003").check(
        doc(
          "Complaint at Law",
          "JURISDICTION AND VENUE",
          "4. Venue is proper in Cook County under 735 ILCS 5/2-101 because the transaction giving rise to the claims occurred in substantial part in this county.",
        ),
      ),
    ).toBeNull();
  });

  it("PLDG-003 still fires on a complaint that never alleges venue", () => {
    expect(
      rule("PLDG-003").check(
        doc(
          "Complaint at Law",
          "JURISDICTION",
          "3. This Court has jurisdiction over the subject matter because the amount in controversy exceeds the statutory minimum. Venue was discussed with opposing counsel.",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("v6 discovery — the verb a Rule 34 request actually uses (v1.0.1)", () => {
  it("DISC-001 reads a deadline stated on a production demand", () => {
    expect(
      rule("DISC-001").check(
        doc(
          "Plaintiff's First Requests for Production of Documents",
          "Pursuant to Rule 34, Plaintiff requests that Defendant produce the following documents for inspection and copying at the offices of undersigned counsel within 30 days of service.",
        ),
      ),
    ).toBeNull();
  });

  it("DISC-020 reads the completion date written 'on or before'", () => {
    expect(
      rule("DISC-020").check(
        doc(
          "Responses and Objections to Requests for Production",
          "Defendant will complete its production of responsive documents on or before December 15, 2026.",
        ),
      ),
    ).toBeNull();
  });

  it("DISC-020 does not accept a relevant-period bound as a completion date", () => {
    // Its first pillar is satisfied by every discovery response ever written,
    // so the date pillar is carrying the whole check: a bare "before <date>"
    // must not count.
    expect(
      rule("DISC-020").check(
        doc(
          "Responses and Objections to Requests for Production",
          "Defendant will produce responsive documents created before January 1, 2026.",
        ),
      ),
    ).not.toBeNull();
  });

  it("DISC-001 still fires when no deadline is stated at all", () => {
    expect(
      rule("DISC-001").check(
        doc(
          "Plaintiff's First Requests for Production of Documents",
          "Pursuant to Rule 34, Plaintiff requests that Defendant produce the following documents for inspection and copying at the offices of undersigned counsel.",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("the proof of service under the name its own rules give it", () => {
  /**
   * "Certificate of service" is federal practice. California and New York say
   * "Proof of Service"; some jurisdictions say "Declaration" or "Affidavit of
   * Service". A served California set of requests for admission was told at
   * `critical` that it had none.
   */
  for (const id of ["DISC-006", "DISC-011", "DISC-016", "DISC-023"]) {
    it(`${id} reads a California proof of service`, () => {
      expect(
        rule(id).check(
          doc(
            "Plaintiff's Requests for Admission, Set One",
            "PROOF OF SERVICE. On April 6, 2026 I served the foregoing document on counsel for Defendant by electronic service to the address on record.",
          ),
        ),
      ).toBeNull();
    });
  }

  it("DISC-016 still fires on a set of requests with no service record at all", () => {
    expect(
      rule("DISC-016").check(
        doc(
          "Plaintiff's Requests for Admission, Set One",
          "Request for Admission No. 1: Admit that You managed the Property on November 14, 2025.",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("a joint-representation waiver as a letter is written", () => {
  /**
   * ENG-021 wanted the letter to say "the clients are". A letter identifies
   * its clients by ADDRESSING them — the address block, the salutation, the
   * consent signature blocks — and almost never says that. ENG-023 wanted "if
   * a conflict arises" from a section headed "What happens if a conflict
   * becomes actual".
   */
  const letter = (...paragraphs: string[]) =>
    doc("Re: Joint Representation and Waiver of Conflict", ...paragraphs);

  it("ENG-021 identifies the clients from the letter's own opening", () => {
    expect(
      rule("ENG-021").check(
        letter(
          "You have each asked this firm to represent you in connection with the proposed sale of the membership interests in the Company.",
          "Rule 1.7 requires that we explain the risks of a joint representation to both of you and obtain your informed consent, confirmed in writing.",
        ),
      ),
    ).toBeNull();
  });

  it("ENG-023 reads the disagreement wording", () => {
    expect(
      rule("ENG-023").check(
        letter(
          "If a disagreement arises between you that we cannot resolve, we may be required to withdraw from representing both of you, and you would each need to retain new counsel.",
        ),
      ),
    ).toBeNull();
  });

  it("ENG-023 still fires on a waiver that says nothing about what follows", () => {
    expect(
      rule("ENG-023").check(
        letter("You each consent to our joint representation on the terms described above."),
      ),
    ).not.toBeNull();
  });
});

describe("the exclusion a fee agreement actually writes", () => {
  // "The Firm will not represent the Client on appeal, in a bankruptcy, or in
  // any other matter unless the parties sign a separate agreement" is the
  // ordinary drafting, and it carried none of the tokens ENG-012 wanted.
  it("ENG-012 reads the exclusion written as a promise", () => {
    expect(
      rule("ENG-012").check(
        doc(
          "Contingency Fee Agreement",
          "The Firm will not represent the Client on appeal, in a bankruptcy, in a related insurance coverage dispute, or in any other matter unless the parties sign a separate agreement.",
        ),
      ),
    ).toBeNull();
  });

  it("ENG-012 still fires on an agreement that bounds nothing", () => {
    expect(
      rule("ENG-012").check(
        doc(
          "Contingency Fee Agreement",
          "The Firm will represent the Client in a claim for personal injuries arising out of the incident described above.",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("a deposition notice names its deponent", () => {
  // DISC-037 wanted Rule 30(b)(1)'s own vocabulary — "the name of the deponent
  // is" — which no compliant notice contains. A notice NAMES the person.
  it("reads the name after 'the deposition of'", () => {
    expect(
      rule("DISC-037").check(
        doc(
          "Notice of Rule 30(b)(6) Deposition",
          "PLEASE TAKE NOTICE that Plaintiff will take the deposition of Defendant Halloran Precision Castings, LLC on September 17, 2026 beginning at 9:30 a.m.",
        ),
      ),
    ).toBeNull();
  });

  it("still fires on a notice that names nobody", () => {
    expect(
      rule("DISC-037").check(
        doc(
          "Notice of Deposition",
          "PLEASE TAKE NOTICE that a deposition will be taken on September 17, 2026 beginning at 9:30 a.m. at the offices of undersigned counsel.",
        ),
      ),
    ).not.toBeNull();
  });
});
