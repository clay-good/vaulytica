/**
 * v5 behavior guards — both directions (spec-v45.md §13).
 *
 * The structural test proves the wave is wired. This one proves the checks
 * mean something: for a representative rule from each sub-domain, a
 * document that carries the term is left alone, and a document that does
 * not is flagged. The silent direction matters more than the firing one —
 * a presence rule whose patterns are too narrow reports a well-drafted
 * clause as missing, which is the false accusation this product exists to
 * avoid.
 *
 * Rules are chosen for stakes, not convenience: the ones whose absence is
 * independently actionable (a § 2-207 acceptance limit, an EFAA carve-out,
 * a Medicaid payback, a BIPA release, a Rule 502(d) order).
 */

import { describe, expect, it } from "vitest";
import { buildContext } from "../../_test-fixtures.js";
import { V5_RULES } from "./index.js";

const rule = (id: string) => {
  const r = V5_RULES.find((x) => x.id === id);
  if (!r) throw new Error(`no v5 rule ${id}`);
  return r;
};

const doc = (heading: string, ...rest: string[]) =>
  buildContext([heading, ...rest], ["Signatures", "By: ____ Name: ____ Title: ____ Date: ____"]);

/** A document with a heading and one wholly unrelated paragraph. */
const bare = (heading: string) =>
  doc(heading, "The parties have entered into this document as of the date first written above.");

type Case = {
  id: string;
  /** A clause that satisfies the check. The rule must stay silent. */
  present: string[];
  /** The heading used for both directions. */
  heading: string;
};

const CASES: Case[] = [
  {
    id: "COMM-101",
    heading: "Purchase Order Terms",
    present: [
      "Acceptance of this Purchase Order is expressly limited to its terms. Any additional or different terms proposed by Seller are rejected.",
    ],
  },
  {
    id: "COMM-224",
    heading: "Official Rules",
    present: [
      "NO PURCHASE NECESSARY TO ENTER OR WIN. A purchase will not increase your chances of winning.",
      "Alternate method of entry: mail a 3x5 card to the address below.",
    ],
  },
  {
    id: "COMM-231",
    heading: "Subscription Terms",
    present: [
      "Your subscription will automatically renew at the end of each term. We disclose the renewal price and billing frequency clearly and conspicuously before we collect your billing information.",
    ],
  },
  {
    id: "GOV-107",
    heading: "Board Resolution",
    present: [
      "A quorum was present throughout, and the following resolution was duly adopted by a majority of the directors.",
    ],
  },
  {
    id: "EQT-110",
    heading: "Employee Stock Purchase Plan",
    present: [
      "No Participant may accrue the right to purchase more than $25,000 of Common Stock, determined at grant-date fair market value, for any calendar year in which such right is outstanding.",
    ],
  },
  {
    id: "MNA-118",
    heading: "Subscription Agreement",
    present: [
      "The Securities have not been registered under the Securities Act and are offered in reliance on the exemption provided by Rule 506(b) of Regulation D.",
    ],
  },
  {
    id: "RE-132",
    heading: "Quitclaim Deed",
    present: [
      "STATE OF OHIO, COUNTY OF FRANKLIN. This instrument was acknowledged before me by the Grantor. Notary Public, my commission expires 2029.",
      "After recording return to: 100 Main Street. Mail tax statements to the Grantee.",
    ],
  },
  {
    id: "EMP-102",
    heading: "Mutual Arbitration Agreement",
    present: [
      "Claims of sexual harassment or sexual assault are arbitrable only at the Employee's election, consistent with the Ending Forced Arbitration of Sexual Assault and Sexual Harassment Act.",
    ],
  },
  {
    id: "EMP-142",
    heading: "WARN Notice",
    present: [
      "This notice is provided at least 60 calendar days in advance of the separations described below, as required by the Worker Adjustment and Retraining Notification Act.",
    ],
  },
  {
    id: "SET-119",
    heading: "Stipulated Protective Order",
    present: [
      "Pursuant to Federal Rule of Evidence 502(d), the production of privileged material does not constitute a waiver in this or any other federal or state proceeding, and the clawback procedure below applies.",
    ],
  },
  {
    id: "IPL-107",
    heading: "Trademark Assignment",
    present: [
      "Assignor hereby assigns the Assigned Marks together with the goodwill of the business symbolized by the marks.",
    ],
  },
  {
    id: "PRV-101",
    heading: "Biometric Consent",
    present: [
      "I provide this written release and consent before any collection of my biometric identifier occurs.",
    ],
  },
  {
    id: "HC-102",
    heading: "Physician Employment Agreement",
    present: [
      "Compensation does not take into account, directly or indirectly, the volume or value of any referrals or other business generated between the parties.",
    ],
  },
  {
    id: "INS-104",
    heading: "Directors and Officers Liability Policy",
    present: [
      "The fraud and personal profit exclusions apply only upon a final and non-appealable adjudication in the underlying action establishing the conduct.",
    ],
  },
  {
    id: "BNK-127",
    heading: "Deposit Account Control Agreement",
    present: [
      "The Bank will comply with instructions originated by the Secured Party directing disposition of the funds in the Deposit Account without further consent by the Company, thereby giving the Secured Party control.",
    ],
  },
  {
    id: "CON-116",
    heading: "Preliminary Notice",
    present: [
      "NOTICE TO PROPERTY OWNER: a mechanic's lien may be placed against your property even if you have paid your contractor in full.",
    ],
  },
  {
    id: "EST-401",
    heading: "Irrevocable Trust Agreement",
    present: [
      "This Trust is irrevocable. The Settlor reserves no power to alter, amend, revoke, or terminate this Trust.",
    ],
  },
  {
    id: "EST-421",
    heading: "Qualified Domestic Relations Order",
    present: [
      "This Order shall not require the Plan to provide any type or form of benefit not otherwise provided under the Plan, nor to provide increased benefits determined on the basis of actuarial value.",
    ],
  },
  {
    id: "POL-111",
    heading: "Acceptable Use Policy",
    present: [
      "Nothing in this policy shall be construed to prohibit employees from exercising rights under Section 7 of the National Labor Relations Act, including discussing wages, hours, and working conditions.",
    ],
  },
  {
    id: "POL-114",
    heading: "Export Control Policy",
    present: [
      "All counterparties are screened against the Specially Designated Nationals list and the Entity List prior to each transaction and re-screened when the lists are updated.",
    ],
  },
];

describe.each(CASES)("v5 rule $id", ({ id, heading, present }) => {
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

describe("v5 rule EST-410 (gated on first-party evidence)", () => {
  const firstParty =
    "This trust is funded with the beneficiary's own assets under 42 U.S.C. 1396p(d)(4)(A).";

  it("stays silent when a first-party trust carries the payback", () => {
    expect(
      rule("EST-410").check(
        doc(
          "Special Needs Trust",
          firstParty,
          "Upon the death of the beneficiary, the Trustee shall reimburse the State for the total medical assistance paid on the beneficiary's behalf before any remaining funds are distributed.",
        ),
      ),
    ).toBeNull();
  });

  it("fires when a first-party trust omits it", () => {
    expect(rule("EST-410").check(doc("Special Needs Trust", firstParty))).not.toBeNull();
  });
});

describe("v5 rule HC-108 — a term that CLEARS the one-year minimum (v1.0.1)", () => {
  const written = "This Agreement is signed by both parties before the Services begin.";

  it("accepts a three-year term", () => {
    // The commonest way a medical directorship is written. The pillar read
    // only the literal minimum, so an agreement that comfortably clears the
    // safe harbor was told at `critical` that it failed it.
    expect(
      rule("HC-108").check(
        doc(
          "Medical Director Agreement",
          "The term of this Agreement is three (3) years commencing on the Effective Date.",
          written,
        ),
      ),
    ).toBeNull();
  });

  it("accepts a term stated in months", () => {
    expect(
      rule("HC-108").check(
        doc(
          "Medical Director Agreement",
          "The initial term is thirty-six (36) months from the Effective Date.",
          written,
        ),
      ),
    ).toBeNull();
  });

  it("accepts a document that IS a signed writing without using the word", () => {
    // The safe harbor asks for a written, signed agreement. One that closes
    // "IN WITNESS WHEREOF, the parties have executed this Agreement" over two
    // "/s/" blocks is one, and never says "signed" — reporting it as missing
    // is a false accusation on the commonest execution clause there is.
    expect(
      rule("HC-108").check(
        doc(
          "Medical Director Agreement",
          "The term of this Agreement is three (3) years commencing on the Effective Date.",
          "IN WITNESS WHEREOF, the parties have executed this Agreement as of the Effective Date.",
        ),
      ),
    ).toBeNull();
  });

  it("still fires on a month-to-month arrangement that mentions a longer period elsewhere", () => {
    // The over-suppression risk, and the reason the widened pillar is tethered
    // to the word "term" within the sentence: every one of these agreements
    // carries a four-year records-access period under 42 U.S.C.
    // § 1395x(v)(1)(I), and a bare "four (4) years" must not stand in for the
    // term of a month-to-month directorship — which is outside the safe
    // harbor entirely.
    expect(
      rule("HC-108").check(
        doc(
          "Medical Director Agreement",
          "The term of this Agreement is month to month and either party may terminate on thirty days' notice.",
          "Until the expiration of four (4) years after the furnishing of the Services, Medical Director shall make the records available to the Secretary.",
          written,
        ),
      ),
    ).not.toBeNull();
  });
});

describe("v5 applicability gates", () => {
  it("does not demand a Medicaid payback from a third-party special needs trust", () => {
    // EST-410 is gated on first-party evidence. A trust a parent funds has no
    // payback obligation, and reporting one is an affirmative drafting error.
    expect(
      rule("EST-410").check(
        doc(
          "Special Needs Trust",
          "This trust is funded solely by the Grantor, the beneficiary's parent, with the Grantor's own assets. No assets of the beneficiary have been or will be contributed.",
        ),
      ),
    ).toBeNull();
  });

  it("does not demand a lead-based paint disclosure for new construction", () => {
    expect(
      rule("RE-141").check(
        doc(
          "Residential Purchase Agreement",
          "The Property is new construction completed in 2024. Buyer shall deposit earnest money with the escrow holder.",
        ),
      ),
    ).toBeNull();
  });

  it("still demands the lead-based paint disclosure for pre-1978 housing", () => {
    expect(
      rule("RE-141").check(
        doc(
          "Residential Purchase Agreement",
          "The Property is a single-family residence built in 1962. Buyer shall deposit earnest money with the escrow holder.",
        ),
      ),
    ).not.toBeNull();
  });

  it("does not demand an intent-to-use recital from an assignment of registered marks", () => {
    expect(
      rule("IPL-108").check(
        doc(
          "Trademark Assignment",
          "Assignor assigns Registration No. 4,123,456 together with the goodwill of the business symbolized by the mark.",
        ),
      ),
    ).toBeNull();
  });

  it("does not demand DFARS cybersecurity flow-down from a civilian-agency rider", () => {
    expect(
      rule("COMM-160").check(
        doc(
          "FAR Flow-Down Rider",
          "This Rider applies to the subcontract under the Contractor's prime contract with the General Services Administration. FAR 52.222-26 and FAR 52.215-2 are incorporated by reference.",
        ),
      ),
    ).toBeNull();
  });
});

describe("v5 — the apostrophe a Word document actually contains", () => {
  // Word inserts U+2019 by default and the ingest layer leaves the drafter's
  // punctuation alone, so a recognizer written with the straight apostrophe
  // reads nothing on a real DOCX. `tests/integration/apostrophe-tolerance.test.ts`
  // proves no recognizer has that shape; this proves the behavior end to end
  // on the rule that first showed it.
  it("RE-102 reads \u201cLandlord\u2019s consent\u201d", () => {
    const r = V5_RULES.find((x) => x.id === "RE-102")!;
    const straight = r.check(
      buildContext([
        "Sublease",
        "This Sublease has no effect until Landlord's consent is delivered in the form the Prime Lease requires.",
      ]),
    );
    const curly = r.check(
      buildContext([
        "Sublease",
        "This Sublease has no effect until Landlord\u2019s consent is delivered in the form the Prime Lease requires.",
      ]),
    );
    expect(straight).toBeNull();
    expect(curly).toBeNull();
  });
});

describe("v5 — the WARN notice a real plant closing produces", () => {
  /**
   * Both checks accused a compliant notice, and both for the same reason: the
   * recognizer knew one way of saying the thing.
   *
   * EMP-147 wanted the literal phrase "mini-WARN" or one of four states, so a
   * Nevada notice reciting "Nevada Revised Statutes Chapter 613" was told at
   * `critical` that it addressed no state overlay. EMP-146 wanted the word
   * "contact" or "telephone" from a notice whose section 10 names the HR
   * director and gives her number — 20 C.F.R. § 639.7(d)(4) requires a name
   * and a number, not a vocabulary.
   */
  const notice = (...body: string[]) =>
    doc(
      "Notice of Plant Closing Under the Worker Adjustment and Retraining Notification Act",
      ...body,
    );

  it("EMP-147 reads a state mini-WARN statute cited by its own code name", () => {
    for (const cite of [
      "This letter is also intended to satisfy Nevada Revised Statutes Chapter 613 to the extent it applies.",
      "The Company has also complied with the Illinois Compiled Statutes provisions on plant closings.",
      "Notice is also given under the New York General Business Law.",
      "The Company has complied with the Tennessee Code Annotated notification requirements.",
    ]) {
      expect(rule("EMP-147").check(notice(cite)), cite).toBeNull();
    }
  });

  it("EMP-147 still fires on a federal-only notice", () => {
    expect(
      rule("EMP-147").check(
        notice(
          "This notice is given under 29 U.S.C. §§ 2101-2109 and 20 C.F.R. Part 639. Separations begin on November 5, 2026.",
        ),
      ),
    ).not.toBeNull();
  });

  it("EMP-146 reads a contact official named without the word 'contact'", () => {
    expect(
      rule("EMP-146").check(
        notice(
          "Please direct any questions about this notice to Rosalie Dumont, Director of Human Resources, at (775) 555-0148.",
        ),
      ),
    ).toBeNull();
  });

  it("EMP-146 still fires on a notice that names no one to ask", () => {
    expect(
      rule("EMP-146").check(
        notice("Separations will begin on November 5, 2026, and there are no bumping rights."),
      ),
    ).not.toBeNull();
  });
});

describe("v5 — the DGCL § 145 indemnification agreement, in both directions", () => {
  /**
   * The reachability guards prove each check CAN fire; this proves each one is
   * silent on the clause it exists to find, written the way a real agreement
   * writes it. The advancement check already needed that: its deadline window
   * was `within \w+ days`, and every real clause writes "within twenty (20)
   * days", so it reported the advancement clause missing — at `critical`, on
   * the paragraph that grants it.
   */
  const DO_PB = "director-indemnification-agreement";
  const CLAUSES: Array<[id: string, clause: string]> = [
    [
      "GOV-139",
      "The Company shall indemnify Indemnitee to the fullest extent permitted by applicable law, if Indemnitee acted in good faith and in a manner Indemnitee reasonably believed to be in or not opposed to the best interests of the Company.",
    ],
    [
      "GOV-140",
      "To the extent Indemnitee is successful, on the merits or otherwise, in defense of any Proceeding, the Company shall indemnify Indemnitee against all Expenses actually and reasonably incurred.",
    ],
    [
      "GOV-141",
      "The Company shall advance all Expenses incurred by Indemnitee in connection with any Proceeding within twenty (20) days after receipt of a written request.",
    ],
    [
      "GOV-142",
      "Indemnitee's written undertaking to repay advanced Expenses is accepted without security and without reference to Indemnitee's financial ability to make repayment.",
    ],
    [
      "GOV-143",
      "In any Proceeding by or in the right of the Company, no indemnification is made in respect of any claim as to which Indemnitee is adjudged liable to the Company, unless the Court of Chancery determines that Indemnitee is fairly and reasonably entitled to indemnity.",
    ],
    [
      "GOV-144",
      "On a written request, the determination of entitlement to indemnification shall be made by Independent Counsel selected by Indemnitee following a Change in Control.",
    ],
    [
      "GOV-145",
      "Indemnitee is presumed to be entitled to indemnification, and the Company bears the burden of proving otherwise by clear and convincing evidence.",
    ],
    [
      "GOV-146",
      "The rights under this Agreement are non-exclusive of any other rights Indemnitee may have. The Company shall maintain directors' and officers' liability insurance covering Indemnitee.",
    ],
    [
      "GOV-147",
      "This Agreement continues for so long as Indemnitee may be subject to any Proceeding, notwithstanding that Indemnitee has ceased to serve, and survives any amendment or repeal of the Certificate of Incorporation or Bylaws.",
    ],
    [
      "GOV-148",
      "Indemnitee shall notify the Company in writing of any Proceeding. The Company is entitled to assume the defense with counsel reasonably satisfactory to Indemnitee. The Company shall not settle any Proceeding that imposes liability on Indemnitee without Indemnitee's prior written consent.",
    ],
  ];

  for (const [id, clause] of CLAUSES) {
    it(`${id} is silent on the clause it checks for`, () => {
      expect(rule(id).check(doc("Indemnification Agreement", clause))).toBeNull();
    });
    it(`${id} fires on an agreement that omits it`, () => {
      const others = CLAUSES.filter(([other]) => other !== id).map(([, c]) => c);
      expect(rule(id).check(doc("Indemnification Agreement", ...others))).not.toBeNull();
    });
  }

  it("every check is scoped to the new family alone", () => {
    for (const [id] of CLAUSES) {
      expect(rule(id).applies_to_playbooks, id).toEqual([DO_PB]);
    }
  });
});
