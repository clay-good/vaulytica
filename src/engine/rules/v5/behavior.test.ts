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
import { analyzeText } from "../../../../tools/cli/api.js";

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

  // The notice must name one of the three states whose statute the rule's own
  // `why` asserts: since 1.1.0 the check is gated on them, because in Ohio a
  // federal-only notice is federal-only for the reason that federal is all
  // there is.
  it("EMP-147 still fires on a federal-only notice in a state that has one", () => {
    expect(
      rule("EMP-147").check(
        notice(
          "The affected site is in Fresno, California. This notice is given under 29 U.S.C. §§ 2101-2109 and 20 C.F.R. Part 639. Separations begin on November 5, 2026.",
        ),
      ),
    ).not.toBeNull();
  });

  it("EMP-147 is silent in a state with no plant-closing statute", () => {
    expect(
      rule("EMP-147").check(
        notice(
          "The affected site is in Akron, Ohio. This notice is given under 29 U.S.C. §§ 2101-2109 and 20 C.F.R. Part 639. Separations begin on November 5, 2026.",
        ),
      ),
    ).toBeNull();
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

describe("v5 — MNA-128 reads the amendment clause a side letter writes", () => {
  /**
   * "This letter may be amended only IN a writing SIGNED BY the Company and
   * Kestrel" is the standard drafting; the check wanted "only BY a writing" or
   * "written instrument signed", and told a side letter carrying the clause
   * that it had none.
   *
   * "written AGREEMENT signed" is deliberately NOT admitted — that is the
   * entire-agreement boilerplate every document carries, and admitting it
   * makes the check unable to fire at all (`title-vacuity.test.ts` proves it).
   */
  it("is silent on the clause as drafters write it", () => {
    for (const clause of [
      "This letter may be amended only in a writing signed by the Company and Kestrel.",
      "No amendment is effective unless made by a written instrument signed by both signatories.",
      "This letter may be amended only by a writing executed by the parties, or with the consent of the Requisite Holders.",
    ]) {
      expect(rule("MNA-128").check(doc("Side Letter", clause)), clause).toBeNull();
    }
  });

  it("still fires on a side letter that states no amendment mechanic", () => {
    expect(
      rule("MNA-128").check(
        doc(
          "Side Letter",
          "Kestrel may designate one representative to attend all meetings of the Board in a non-voting observer capacity.",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("v5 — the commonest covenant not to sue is a patent one", () => {
  /**
   * SET-106's second pillar knew only the RELEASE contrast, and SET-107's two
   * pillars wanted an adjacency the drafting does not have. Both fired at
   * `critical` on the sections that state exactly what they check for.
   */
  const cov = (...body: string[]) => doc("Covenant Not to Sue", ...body);

  it("SET-106 reads the not-a-LICENSE characterization", () => {
    expect(
      rule("SET-106").check(
        cov(
          "Covenantor irrevocably covenants not to sue Covenantee for infringement of the Patents.",
          "This Covenant is a covenant not to sue and is not a license. Covenantee acquires no right, title, or interest in the Patents.",
        ),
      ),
    ).toBeNull();
  });

  it("SET-106 still reads the not-a-release characterization", () => {
    expect(
      rule("SET-106").check(
        cov(
          "Covenantor covenants not to sue the Covenantee.",
          "This instrument is a covenant not to sue and is not a release of any claim.",
        ),
      ),
    ).toBeNull();
  });

  it("SET-106 still fires when the instrument characterizes itself as neither", () => {
    expect(
      rule("SET-106").check(
        cov("Covenantor covenants not to sue Covenantee on the claims described on Schedule A."),
      ),
    ).not.toBeNull();
  });

  it("SET-107 reads the claims phrase with its subject matter first", () => {
    expect(
      rule("SET-107").check(
        cov(
          "Covenantor will not pursue any claim, demand, or cause of action for infringement of the Patents arising from the manufacture, use, or sale of the Covered Products, whether such acts occurred before or occur after the date of this Covenant.",
        ),
      ),
    ).toBeNull();
  });

  it("SET-107 still fires on a covenant with neither a scope nor a boundary", () => {
    expect(
      rule("SET-107").check(cov("Covenantor covenants not to sue Covenantee.")),
    ).not.toBeNull();
  });
});

describe("v5 — the consent a real sublease actually asks for", () => {
  /**
   * No sublease writes the bare adjacency "Landlord's consent". It asks for
   * the landlord's PRIOR WRITTEN consent, or conditions itself on "the written
   * consent of Master Landlord" — the genitive reversed. RE-102 matched only
   * the bare form, so a sublease with a section headed "Consent of Master
   * Landlord" was reported at `critical` as having no such clause.
   */
  const re102 = () => V5_RULES.find((x) => x.id === "RE-102")!;

  it("reads the prior-written form", () => {
    expect(
      re102().check(
        buildContext([
          "Sublease",
          "This Sublease is conditioned on Landlord's prior written consent.",
        ]),
      ),
    ).toBeNull();
  });

  it("reads the reversed genitive with the master landlord named", () => {
    expect(
      re102().check(
        buildContext([
          "Sublease",
          "This Sublease is expressly conditioned on the written consent of Master Landlord.",
        ]),
      ),
    ).toBeNull();
  });

  it("still fires on a sublease that never mentions the landlord's consent", () => {
    expect(
      re102().check(
        buildContext(["Sublease", "Sublandlord subleases the Subleased Premises to Subtenant."]),
      ),
    ).not.toBeNull();
  });
});

describe("v5 — the entry line a state-court order carries", () => {
  /**
   * EST-425 wanted "so ordered" or "entered by the court". Most state-court
   * QDROs write neither: the entry line is the bare "ENTERED:" above the
   * judge's signature. An order that recited its own entry, named the plan
   * administrator, and retained jurisdiction to amend was still reported at
   * `critical` for having none of the three.
   */
  const est425 = () => V5_RULES.find((x) => x.id === "EST-425")!;

  it("reads the bare ENTERED: line", () => {
    expect(
      est425().check(
        buildContext([
          "Qualified Domestic Relations Order",
          "The Court retains jurisdiction to amend this Order to secure its qualified status.",
          "ENTERED:",
        ]),
      ),
    ).toBeNull();
  });

  it("still fires on an order with neither entry nor retained jurisdiction", () => {
    expect(
      est425().check(
        buildContext([
          "Qualified Domestic Relations Order",
          "The Alternate Payee is assigned fifty percent of the Participant's Accrued Benefit.",
        ]),
      ),
    ).not.toBeNull();
  });
});

describe("v5 — the assent and modification recitals a real terms page carries", () => {
  /**
   * COMM-201 wanted "you agree to these terms" or "by using the site". A terms
   * page writes "By accessing or using the website … you agree to be bound by
   * these Terms of Use" — a compound verb, an inserted "be bound by", and the
   * noun "website". COMM-202 wanted "we may change these terms" and could not
   * read the same sentence with one adverb in it: "We may also change these
   * Terms."
   */
  const byId = (id: string) => V5_RULES.find((x) => x.id === id)!;

  it("COMM-201 reads the browsewrap recital as written", () => {
    expect(
      byId("COMM-201").check(
        buildContext([
          "Terms of Use",
          "By accessing or using the website located at www.example.com, you agree to be bound by these Terms of Use.",
        ]),
      ),
    ).toBeNull();
  });

  it("COMM-201 still fires on a terms page that states no assent mechanism", () => {
    expect(
      byId("COMM-201").check(
        buildContext(["Terms of Use", "These Terms govern the operation of the website."]),
      ),
    ).not.toBeNull();
  });

  it("COMM-202 reads the modification right through an adverb", () => {
    expect(
      byId("COMM-202").check(
        buildContext([
          "Terms of Use",
          "We may also change these Terms. If we make a material change, we will post the revised Terms with a new Last updated date and, where required by law, provide additional notice. Changes are effective 30 days after posting.",
        ]),
      ),
    ).toBeNull();
  });

  it("COMM-202 still fires when the terms reserve no modification right", () => {
    expect(
      byId("COMM-202").check(
        buildContext(["Terms of Use", "These Terms are the entire agreement between you and us."]),
      ),
    ).not.toBeNull();
  });
});

describe("v5 — the licensure recital a patient-facing consent writes", () => {
  /**
   * HC-132's second pillar required "in THE state where THE PATIENT". A
   * telehealth consent addresses the patient as "you" and names the state with
   * the indefinite article: "your provider may treat you by telehealth only
   * when you are physically located in A state where the provider is
   * licensed". A consent whose section IS the licensure recital was reported
   * at `critical` as having none.
   */
  const hc132 = () => V5_RULES.find((x) => x.id === "HC-132")!;

  it("reads the second-person recital", () => {
    expect(
      hc132().check(
        buildContext([
          "Consent to Telehealth Services",
          "Your provider is licensed to practice in Washington. Under Washington law, your provider may treat you by telehealth only when you are physically located in a state where the provider is licensed.",
        ]),
      ),
    ).toBeNull();
  });

  it("still fires on a consent that says nothing about licensure or location", () => {
    expect(
      hc132().check(
        buildContext([
          "Consent to Telehealth Services",
          "Telehealth means we deliver health care to you using live video instead of an in-person visit.",
        ]),
      ),
    ).not.toBeNull();
  });
});

describe("v5 — the supplemental-needs recital a real trust writes", () => {
  /**
   * EST-408 wanted "shall not supplant" as three adjacent words. A first-party
   * trust writes "the Trustee shall not make any distribution that would
   * supplant, reduce, or replace any benefit the Beneficiary receives", so a
   * trust whose section is headed "Supplemental, Not Substitute" drew a
   * `critical` for having no supplemental-needs language at all.
   */
  const est408 = () => V5_RULES.find((x) => x.id === "EST-408")!;

  it("reads the recital through its intervening clause", () => {
    expect(
      est408().check(
        buildContext([
          "2.1 Supplemental, Not Substitute",
          "The Trustee shall not make any distribution that would supplant, reduce, or replace any benefit the Beneficiary receives or is eligible to receive from any federal, state, or local program, including Supplemental Security Income and Medicaid.",
        ]),
      ),
    ).toBeNull();
  });

  it("still fires on a trust that says nothing about public benefits", () => {
    expect(
      est408().check(
        buildContext([
          "2.1 Distributions",
          "The Trustee shall distribute income and principal to the Beneficiary in the Trustee's sole and absolute discretion.",
        ]),
      ),
    ).not.toBeNull();
  });
});

describe("RE-128 — the statutory quitclaim short form", () => {
  /**
   * "conveys and quitclaims to" is the granting language of RCW 64.04.050 and
   * its siblings, with no "hereby" anywhere in it — so a Washington quitclaim
   * deed was told at `critical` that it lacked the words it is written in.
   */
  const re128 = () => V5_RULES.find((x) => x.id === "RE-128")!;

  it("reads the statutory short form", () => {
    expect(
      re128().check(
        buildContext([
          "Quitclaim Deed",
          "THE GRANTOR, Rosalind Amara Ferreira, conveys and quitclaims to THE GRANTEE all right, title, and interest that the Grantor may have in the property.",
        ]),
      ),
    ).toBeNull();
  });

  it("reads the long form too", () => {
    expect(
      re128().check(
        buildContext([
          "Quitclaim Deed",
          "The Grantor does hereby remise, release, and forever quitclaim unto the Grantee all of the Grantor's right, title, and interest, if any, in the property.",
        ]),
      ),
    ).toBeNull();
  });

  it("still fires on a deed titled quitclaim that grants with warranty words", () => {
    expect(
      re128().check(
        buildContext([
          "Quitclaim Deed",
          "The Grantor grants, bargains, sells, and conveys to the Grantee the property described below, and warrants the title against all persons.",
        ]),
      ),
    ).not.toBeNull();
  });
});

/**
 * A trademark coexistence agreement's operative section, and the § 145(e)
 * undertaking in a director indemnification agreement — two clauses reported
 * missing on documents that carry them in the words the practice actually
 * uses.
 */
describe("clauses written the way practitioners write them", () => {
  const find = (id: string) => V5_RULES.find((x) => x.id === id)!;

  it("IPL-113 reads a consent that names the other party before the thing consented to", () => {
    expect(
      find("IPL-113").check(
        buildContext([
          "Trademark Coexistence Agreement",
          "Halcyon consents to Cellars' use and registration of the Cellars Mark in the United States for the Cellars Goods, and will not oppose, petition to cancel, or otherwise challenge the Cellars Mark for the Cellars Goods.",
        ]),
      ),
    ).toBeNull();
  });

  it("IPL-113 still fires where neither the consent nor the covenant is there", () => {
    expect(
      find("IPL-113").check(
        buildContext([
          "Trademark Coexistence Agreement",
          "Each party acknowledges the other party's ownership of its own mark and the goodwill associated with it, and the parties will confer annually about their respective uses.",
        ]),
      ),
    ).not.toBeNull();
  });

  it("GOV-142 reads the undertaking as a verb", () => {
    expect(
      find("GOV-142").check(
        buildContext([
          "Indemnification Agreement",
          "Indemnitee undertakes to repay the amounts advanced to the extent it is ultimately determined that Indemnitee is not entitled to be indemnified. This undertaking is an unsecured general obligation of Indemnitee and no security may be required.",
        ]),
      ),
    ).toBeNull();
  });

  it("GOV-142 still fires where advancement is conditioned on security", () => {
    expect(
      find("GOV-142").check(
        buildContext([
          "Indemnification Agreement",
          "The Company shall advance Expenses only after Indemnitee posts collateral in an amount the Board determines is sufficient to secure repayment.",
        ]),
      ),
    ).not.toBeNull();
  });
});

/**
 * COMM-107's own `fix` asks for "a price schedule and ... annual negotiation
 * with a cap". A master purchase agreement drafted to that recommendation
 * still failed the check, because the patterns wanted the NOUNS "price
 * list" / "price schedule" / "price adjustment" and the document writes the
 * ordinary sentence instead.
 */
describe("COMM-107 reads the price terms its own recommendation asks for", () => {
  it.each([
    "Unit prices are set forth in Exhibit A and are firm through December 31, 2026.",
    "The prices stated in Schedule 1 apply to each Release issued under this Agreement.",
    "Seller may propose an adjustment for the following calendar year by written notice.",
    "Prices are subject to an annual price escalation indexed to the producer price index.",
  ])("is silent on: %s", (sentence) => {
    expect(rule("COMM-107").check(doc("Price and Payment", sentence))).toBeNull();
  });

  it("still fires on a master agreement that states no price terms at all", () => {
    expect(
      rule("COMM-107").check(
        doc(
          "Structure",
          "Buyer orders Goods by issuing a written release referencing this Agreement.",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("v5 COMM-231 / COMM-233 — the subscriber's words, not the regulator's", () => {
  const page = (...body: string[]) => doc("Automatic Renewal Terms", ...body);

  it("COMM-231 reads a disclosure written for a subscriber", () => {
    // The rule wanted "clearly and conspicuously" and "before obtaining
    // billing information" — the statute's phrases, which a page required to
    // be understandable has a reason to avoid — and read the adverb only
    // BEFORE the verb. A model page says "your subscription renews
    // automatically" and "before you pay, we show you", and drew a CRITICAL
    // for a disclosure that is its entire first section.
    const ctx = page(
      "Your subscription renews automatically. Before you pay, we show you the plan name, the total recurring charge, the length of each billing period and the date of the first renewal.",
    );
    expect(rule("COMM-231").check(ctx)).toBeNull();
  });

  it("COMM-233 is a conjunction, not an OR", () => {
    // Its own rationale calls phone-only cancellation of an online signup the
    // paradigm violation, and the bare word "cancel" satisfied the whole
    // column — so the paradigm violation passed clean.
    const paradigm = page(
      "To cancel, call our support line between 9am and 4pm Central and speak to a retention specialist. Cancellations by email or through the website are not accepted.",
    );
    expect(rule("COMM-233").check(paradigm)).not.toBeNull();
  });

  it("COMM-233 still reads a self-service path in the subscriber's words", () => {
    const ok = page(
      "You may cancel at any time. Sign in, open Billing and press Cancel subscription — one step. You may also cancel by the same means you used to buy the subscription.",
    );
    expect(rule("COMM-233").check(ok)).toBeNull();
  });
});

/**
 * EMP-142 measures an interval, not a vocabulary.
 *
 * The four cases are the whole contract, and two of them were wrong before the
 * rule was computed: a compliant notice was told at `critical` that it gave no
 * sixty days, and a ten-day notice that merely SAID "60-day advance notice"
 * was silent.
 */
describe("EMP-142 — sixty-day advance timing", () => {
  const NOTICE = (dated: string, action: string, extra = "") =>
    [
      "WORKER ADJUSTMENT AND RETRAINING NOTIFICATION ACT NOTICE",
      `Date: ${dated}`,
      "To: Affected employees of Kestrel Manufacturing, Inc., Plant 3, Akron, Ohio 44305.",
      "Kestrel Manufacturing, Inc. is providing this notice under the federal Worker Adjustment and Retraining Notification Act, 29 U.S.C. 2101 et seq.",
      `${extra}The company will permanently close Plant 3. The closing is expected to begin on ${action}. The action is permanent, not a temporary layoff.`,
      "All 212 positions at Plant 3 will be eliminated. There is no bumping right.",
      "Questions to Marisol Trent, Director of Human Resources, (330) 555-0148.",
    ].join("\n\n");

  const emp142 = async (text: string) => {
    const result = await analyzeText(text, "warn.txt");
    expect(result.run.playbook_id).toBe("warn-notice");
    return result.run.findings.find((f) => f.rule_id === "EMP-142") ?? null;
  };

  it("is silent on a notice that gives ninety days without saying so", async () => {
    expect(await emp142(NOTICE("September 1, 2026", "November 30, 2026"))).toBeNull();
  });

  it("fires on a ten-day notice, and names the interval it measured", async () => {
    const f = await emp142(NOTICE("September 1, 2026", "September 11, 2026"));
    expect(f?.severity).toBe("critical");
    expect(f?.title).toBe("Sixty-day advance timing — 10 days given");
    expect(f?.description).toContain("2026-09-11");
  });

  it("still fires when the ten-day notice CALLS itself a sixty-day notice", async () => {
    const f = await emp142(
      NOTICE(
        "September 1, 2026",
        "September 11, 2026",
        "This is your 60-day advance written notice under the WARN Act. ",
      ),
    );
    expect(f?.title).toBe("Sixty-day advance timing — 10 days given");
  });

  it("is silent when the notice invokes a § 2102(b) exception", async () => {
    const f = await emp142(
      NOTICE(
        "September 1, 2026",
        "September 11, 2026",
        "The period is shortened because of unforeseeable business circumstances: the sole customer cancelled on August 29, 2026. ",
      ),
    );
    expect(f).toBeNull();
  });

  it("falls back to the words when there is nothing to subtract", async () => {
    const bare =
      "WORKER ADJUSTMENT AND RETRAINING NOTIFICATION ACT NOTICE\n\nTo: Affected employees of Kestrel Manufacturing, Inc., Plant 3, Akron, Ohio.\n\nKestrel Manufacturing, Inc. will permanently close Plant 3 and eliminate all 212 positions there. There is no bumping right. Questions to Marisol Trent, Director of Human Resources.\n";
    const f = await emp142(bare);
    expect(f?.title).toBe("Sixty-day advance timing — not found");
  });
});

/**
 * EMP-147 fires where the law it names exists.
 *
 * The rule's own `why` says a federal-only notice is non-compliant "in those
 * states" — California, New York, New Jersey — and the check fired in all
 * fifty. An Ohio plant closing, in a state with no plant-closing statute at
 * all, was told at `critical` that it addressed no state overlay.
 */
describe("EMP-147 — state mini-WARN overlay", () => {
  const NOTICE = (city: string, state: string) =>
    [
      "WORKER ADJUSTMENT AND RETRAINING NOTIFICATION ACT NOTICE",
      "Date: September 1, 2026",
      `To: Affected employees of Kestrel Manufacturing, Inc., Plant 3, ${city}, ${state}.`,
      "Kestrel Manufacturing, Inc. is providing this notice under the federal Worker Adjustment and Retraining Notification Act, 29 U.S.C. 2101 et seq.",
      "The company will permanently close Plant 3. The closing is expected to begin on November 30, 2026. The action is permanent, not a temporary layoff.",
      "All 212 positions will be eliminated. There is no bumping right.",
      "Questions to Marisol Trent, Director of Human Resources, (330) 555-0148.",
    ].join("\n\n");

  const emp147 = async (text: string) => {
    const result = await analyzeText(text, "warn.txt");
    expect(result.run.playbook_id).toBe("warn-notice");
    return result.run.findings.find((f) => f.rule_id === "EMP-147") ?? null;
  };

  it("is silent in a state with no plant-closing statute", async () => {
    expect(await emp147(NOTICE("Akron", "Ohio"))).toBeNull();
  });

  it("fires on a federal-only notice for a California closing", async () => {
    expect((await emp147(NOTICE("Fresno", "California")))?.severity).toBe("critical");
  });

  it("is satisfied when the California notice cites the state statute", async () => {
    const cited = NOTICE("Fresno", "California").replace(
      "There is no bumping right.",
      "There is no bumping right. This notice is also given under the California Labor Code § 1400 et seq.",
    );
    expect(await emp147(cited)).toBeNull();
  });
});

/**
 * A WARN notice is ISSUED, not executed.
 *
 * `warn-notice` already declined STRUCT-001, -002, and -004 — the other
 * structural checks written for a two-party bargain — and kept STRUCT-003, so
 * every WARN notice was told at `critical` that "the end of this Agreement
 * does not contain the standard signature pattern". 20 C.F.R. § 639.7 lists
 * what the notice must contain and a signature block is not on the list; the
 * DOL's own model notice closes with a contact name.
 */
describe("warn-notice structural posture", () => {
  it("is not told it is unsigned", async () => {
    const result = await analyzeText(
      [
        "WORKER ADJUSTMENT AND RETRAINING NOTIFICATION ACT NOTICE",
        "Date: September 1, 2026",
        "To: Affected employees of Kestrel Manufacturing, Inc., Plant 3, Akron, Ohio.",
        "The company will permanently close Plant 3. The closing is expected to begin on November 30, 2026. The action is permanent.",
        "All 212 positions will be eliminated. There is no bumping right.",
        "Questions to Marisol Trent, Director of Human Resources, (330) 555-0148.",
      ].join("\n\n"),
      "warn.txt",
    );
    expect(result.run.playbook_id).toBe("warn-notice");
    expect(result.run.findings.map((f) => f.rule_id)).not.toContain("STRUCT-003");
  });
});

/**
 * COMM-107 reads where a MASTER purchase agreement keeps its prices.
 *
 * Two adjacency gaps at once: the verb had to sit immediately against the
 * noun, so "Prices are THOSE stated in the applicable purchase order" matched
 * nothing over the one intervening word; and the list of places a price can
 * live was Exhibit / Schedule / Appendix / Annex, which omits the purchase
 * order — the document a master purchase agreement exists to govern, and where
 * its prices live by definition.
 */
describe("COMM-107 — the price term of a master purchase agreement", () => {
  it.each([
    ["an intervening word", "Prices are those stated in the applicable purchase order."],
    [
      "the purchase order as the place",
      "Prices for the Goods are set forth in each purchase order.",
    ],
    ["a quoted price", "Prices are quoted in the order form and are firm on acceptance."],
  ])("reads %s", (_label, text) => {
    expect(rule("COMM-107").check(doc("Master Purchase Agreement", text))).toBeNull();
  });

  it("still fires on an agreement that states no price term at all", () => {
    expect(
      rule("COMM-107").check(
        doc("Master Purchase Agreement", "Seller will sell and Buyer will purchase the Goods."),
      ),
    ).not.toBeNull();
  });
});

/**
 * RE-139 wanted the NOUN a summary uses; a form contract writes the VERB.
 *
 * "This contract is contingent on Buyer obtaining a conventional loan of
 * $720,000 within twenty-one days" is how the Texas One to Four Family
 * Residential Contract and most state forms state it — the phrase "financing
 * contingency" appears in none of them, so a contract whose paragraph 4 IS the
 * financing contingency drew a `critical` for having none.
 */
describe("RE-139 — the financing contingency stated as a verb", () => {
  it.each([
    [
      "a conventional loan",
      "This contract is contingent on Buyer obtaining a conventional loan of $720,000 within twenty-one days, and the appraisal must support the Sales Price.",
    ],
    [
      "Buyer Approval",
      "This contract is contingent upon Buyer obtaining Buyer Approval within twenty-one days; Buyer has 21 days to obtain it.",
    ],
  ])("reads %s", (_label, text) => {
    expect(rule("RE-139").check(doc("Residential Purchase Agreement", text))).toBeNull();
  });

  it("still fires on a contract that states no contingency at all", () => {
    expect(
      rule("RE-139").check(
        doc(
          "Residential Purchase Agreement",
          "Buyer agrees to buy and Seller agrees to sell the Property for $900,000, all cash at closing.",
        ),
      ),
    ).not.toBeNull();
  });
});
