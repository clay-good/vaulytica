/**
 * The known-debt ledger (spec-v53 §2).
 *
 * A tool that asks to be trusted should publish where it is known to be wrong.
 * This is where that is written down: every defect the suite has measured and
 * holds open on purpose, as a list a test asserts by EQUALITY — a new
 * divergence fails, and so does a repair that is not recorded here.
 *
 * Each debt test imports its list from this module, and so does the generator
 * for the site's `/known-limits` page (`tools/site/known-limits.ts`), so the
 * page's numbers cannot drift from what the tests enforce.
 *
 * `reason` is written for a READER, not a maintainer: one sentence saying what
 * goes wrong and on how many specimens, with `{n}` standing for the count. The
 * history of a list — which release shrank it, and why an entry is what it is
 * — stays in the comments beside its entries and in the test that owns it.
 *
 * "Specimens" are documents the project wrote for its own tests. These are
 * self-measurements on synthetic documents, not an error rate on real ones.
 */

export type KnownDebt = {
  /** One sentence for a reader. `{n}` is replaced by the count. */
  reason: string;
  /** The measured cases, exactly. Empty means the debt is paid and held at zero. */
  entries: readonly string[];
  /** For a debt the suite holds as a number rather than a list of cases. */
  count?: number;
};

/** How many cases a debt holds. */
export const debtCount = (d: KnownDebt): number => d.count ?? d.entries.length;

/** The reason with its count filled in: "On 1 specimen, …", "On 9 specimens, …". */
export function debtSentence(d: KnownDebt): string {
  const n = debtCount(d);
  return d.reason.replace(/\{n\} (specimen(?:-and-layout pair)?)s\b/, (_m, unit: string) =>
    n === 1 ? `1 ${unit}` : `${n.toLocaleString("en-US")} ${unit}s`,
  );
}

export const KNOWN_DEBT = {
  // defined-terms-format.test.ts — TERM_FORMAT_DEBT
  "defined-terms-layout": {
    reason:
      "On {n} specimen-and-layout pairs, rewriting a document's line structure (blank lines stripped, hard-wrapped, double-spaced) makes the defined-terms table gain or lose a term.",
    entries: [
      "advertising-insertion-order.txt [blank lines stripped] lost:Flight Dates gained:-",
      "coi.txt [blank lines stripped] lost:INSURERS AFFORDING COVERAGE Insurer A gained:Insurer A",
      "coi.txt [double-spaced] lost:INSURERS AFFORDING COVERAGE Insurer A gained:Insurer A",
      "construction-lien-waiver.txt [blank lines stripped] lost:Through Date gained:-",
      "credit-card.txt [blank lines stripped] lost:Minimum Interest Charge gained:-",
      "cta.txt [blank lines stripped] lost:- gained:Chief Executive Officer ACKNOWLEDGED",
      "cyber-policy.txt [blank lines stripped] lost:Continuity Date gained:-",
      "cyber-policy.txt [hard-wrapped] lost:Retroactive Date gained:Named Insured Retroactive Date",
      "demand-for-inspection.txt [blank lines stripped] lost:PROPOUNDING PARTY gained:-",
      "demand-letter.txt [blank lines stripped] lost:Our Client gained:-",
      "demand-letter.txt [hard-wrapped] lost:Our Client gained:-",
      "do-liability-policy.txt [hard-wrapped] lost:Policy Period gained:-",
      "earnout.txt [smart quotes] lost:Sellers' Representative gained:Sellers’ Representative",
      "employment-arbitration.txt [blank lines stripped] lost:- gained:Chief People Officer EMPLOYEE",
      "equipment-finance-lease.txt [blank lines stripped] lost:LLC LESSEE gained:-",
      "escrow-agreement-indemnity.txt [smart quotes] lost:Sellers' Representative gained:Sellers’ Representative",
      "fdd.txt [double-spaced] lost:- gained:TOTAL ESTIMATED INITIAL INVESTMENT",
      "information-security-policy.txt [double-spaced] lost:Thornapple Instruments Corporation Policy Owner gained:Policy Owner",
      "insurance-endorsement-additional-insured.txt [blank lines stripped] lost:Authorized Representative gained:-",
      "insurance-endorsement-additional-insured.txt [hard-wrapped] lost:Named Insured gained:-",
      "lease-loi.txt [blank lines stripped] lost:- gained:Managing Member ACKNOWLEDGED AND AGREED",
      "litigation-funding.txt [smart quotes] lost:Claimant's Counsel gained:Claimant’s Counsel",
      "option-grant.txt [blank lines stripped] lost:Expiration Date gained:-",
      "option-grant.txt [hard-wrapped] lost:Exercise Price Per Share,Expiration Date gained:-",
      "order-form.txt [blank lines stripped] lost:Effective Date gained:-",
      "partnership-agreement.txt [blank lines stripped] lost:- gained:Manager LIMITED PARTNERS",
      "payment-performance-bond.txt [blank lines stripped] lost:Penal Sum gained:-",
      "performance-bond.txt [blank lines stripped] lost:Penal Sum gained:-",
      "ppm-narrative.txt [double-spaced] lost:- gained:Minimum Investment",
      "privacy-notice-multistate.txt [blank lines stripped] lost:Last Updated gained:-",
      "quitclaim-deed.txt [blank lines stripped] lost:Parcel Number gained:-",
      "remote-work.txt [blank lines stripped] lost:- gained:Chief People Officer EMPLOYEE",
      "requests-for-admission.txt [blank lines stripped] lost:PROPOUNDING PARTY gained:-",
      "rofr-co-sale.txt [blank lines stripped] lost:- gained:Chief Executive Officer KEY HOLDER",
      "ropa-art-30.txt [hard-wrapped] lost:Data Protection Officer,EU Representative gained:-",
      "saas-order-form-fields.txt [hard-wrapped] lost:Subscription Start Date gained:Start Date Subscription Start Date",
      "secondary-stock-transfer.txt [double-spaced] lost:- gained:Priya Venkataraman Name",
      "security-incident-response-plan.txt [double-spaced] lost:Thornapple Instruments Corporation Plan Owner gained:Plan Owner",
      "side-letter.txt [blank lines stripped] lost:- gained:Managing Member ACKNOWLEDGED AND AGREED",
      "sow-numbered.txt [blank lines stripped] lost:SOW Number gained:-",
      "stockholders-agreement.txt [blank lines stripped] lost:- gained:General Partner KEY HOLDER",
      "trademark-assignment.txt [blank lines stripped] lost:- gained:Managing Member ACCEPTED",
      "tx-conditional-lien-waiver.txt [blank lines stripped] lost:Through Date gained:-",
      "ucc-1.txt [blank lines stripped] lost:IL POSTAL CODE gained:-",
      "uk-facility-agreement.txt [blank lines stripped] lost:Facility Amount,Governing Law gained:-",
      "vc-side-letter.txt [blank lines stripped] lost:- gained:Executive Officer ACKNOWLEDGED AND AGREED",
      "warrant.txt [blank lines stripped] lost:Issue Date gained:-",
    ],
  },
  // division-vocabulary.test.ts — ARTICLE_DEBT
  "section-renamed-article": {
    reason:
      "On {n} specimens that already have Articles, renaming every Section to an Article makes two numbering schemes collide, and a cross-reference finding appears that the original does not draw.",
    entries: [
      "bylaws-corporation.txt: lost - gained STRUCT-007",
      "consent-judgment.txt: lost - gained STRUCT-007",
      // 9.637.0 — the sixth clean document joins both lists for one reason: its UK
      // Addendum clause says "neither party able to end the Addendum under Section
      // 19", a reference to a section of ANOTHER instrument, named in the same
      // sentence. STRUCT-007 reports it as unresolved (correctly, against this
      // document's own outline), and the rename makes it stop being seen — so the
      // finding moves. The external-citation guard above knows STATUTES; a numbered
      // section of a named CONTRACT instrument is the same shape and is not covered.
      "dpa-complete.txt: lost STRUCT-007 gained -",
      // 9.634.0 — FOUR entries left this list when the statutory-citation guard
      // above was anchored: `equity-incentive-plan`, `executive-employment`,
      // `merger-agreement` and `option-grant` were never ambiguous documents at
      // all. The transform had been renaming "Section 409A of the Internal Revenue
      // Code" and its siblings, and the movement it measured was its own.
    ],
  },
  // division-vocabulary.test.ts — CLAUSE_DEBT
  "section-renamed-clause": {
    reason: "On {n} specimens, renaming every Section to a Clause moves a finding.",
    entries: [
      // 9.634.0 — EMPTY, for the same reason the Article list lost four: every
      // entry here was a statutory citation the transform had renamed. A relation
      // whose debt list is empty is the strongest form of the claim it makes.
      //
      // 9.637.0 — one entry, and the same one the Article list gained: a numbered
      // section of a NAMED external instrument ("the Addendum … under Section 19")
      // is the contract-world twin of the statutory citation the guard above knows.
      "dpa-complete.txt: lost STRUCT-007 gained -",
    ],
  },
  // extraction-format-invariance.test.ts — PARTY_DEBT
  "party-names-layout": {
    reason:
      "On {n} specimen-and-layout pairs, a party's name is read differently when the layout changes — most often a corporate suffix drifting in or out of the name.",
    entries: [
      "answer.txt [blank lines stripped] lost:- gained:WHEREFORE, Defendant Halloran Precision Castings||LLC|",
      "assignment-of-claim.txt [double-spaced] lost:Wexley DO GP II||| gained:Wexley DO GP II, LLC|||",
      "bylaws-corporation.txt [double-spaced] lost:WREXHAM ANALYTICS, INC||corporation|Delaware gained:WREXHAM ANALYTICS||INC|Delaware",
      "cba.txt [double-spaced] lost:RIDGELINE AEROSPACE COMPONENTS, INC|Employer|INC| gained:RIDGELINE AEROSPACE COMPONENTS||INC|",
      "charter-incorporation.txt [blank lines stripped] lost:Corvid Optical Systems, Inc||corporation| gained:CORVID OPTICAL SYSTEMS, INC. Corvid Optical Systems||Inc|,Corvid Optical Systems||Inc|",
      "conflict-of-interest-policy.txt [double-spaced] lost:Pemberton Ridge Land Conservancy||corporation|Colorado gained:-",
      "convertible-note.txt [blank lines stripped] lost:VALUE RECEIVED, Northgate Instrument Company|Company|corporation|Delaware gained:Delaware FOR VALUE RECEIVED, Northgate Instrument Company|Company|corporation|Delaware",
      "demand-letter.txt [blank lines stripped] lost:Larkspur Timber Supply LLC|Client|LLC| gained:Larkspur Timber Supply|Larkspur|LLC|",
      "dissolution-plan.txt [double-spaced] lost:Alderbrook Instruments, Inc|Company|corporation|Delaware gained:Alderbrook Instruments|Company|Inc|Delaware",
      "expert-retention.txt [double-spaced] lost:Anneke Vosberg, Ph.D., P.E. Vosberg Forensic Engineering||LLC| gained:-",
      "fdd.txt [blank lines stripped] lost:TIDEWATER BOWL COMPANY, LLC||company|Virginia gained:TIDEWATER BOWL COMPANY||LLC|Virginia",
      "fdd.txt [double-spaced] lost:TIDEWATER BOWL COMPANY, LLC||company|Virginia gained:TIDEWATER BOWL COMPANY||LLC|Virginia",
      "flat-fee-agreement.txt [double-spaced] lost:Ravi Chandrasekaran-Boyd Chandrasekaran Robotics||LLC| gained:-",
      "joint-representation-waiver-founders.txt [double-spaced] lost:Raghunathan Mr. Daniel Ostrowski Kestrel Grove Bakery||LLC| gained:-",
      "minutes.txt [blank lines stripped] lost:Harborlight Analytics, Inc|Company|corporation|Delaware gained:HARBORLIGHT ANALYTICS, INC|Board|corporation|Delaware",
      "nonprofit-bylaws.txt [double-spaced] lost:HARBORLIGHT LITERACY ALLIANCE||INC| gained:HARBORLIGHT LITERACY ALLIANCE||INC|North Carolina",
      "notice-of-furnishing.txt [blank lines stripped] lost:- gained:This is a Notice of Furnishing under Ohio Revised Code § 1311.05. It is given to|Lender||",
      "operating-agreement.txt [blank lines stripped] lost:HARBOR POINT VENTURES LLC|Company|company|Delaware gained:HARBOR POINT VENTURES|Company|LLC|Delaware",
      "operating-agreement.txt [double-spaced] lost:HARBOR POINT VENTURES LLC|Company|company|Delaware gained:HARBOR POINT VENTURES|Company|LLC|Delaware",
      "saas-order-form-fields.txt [blank lines stripped] lost:ORDER FORM Northbridge Cloud||Inc| gained:Northbridge Cloud||Inc|",
      "saas-order-form-fields.txt [double-spaced] lost:ORDER FORM Northbridge Cloud||Inc| gained:Northbridge Cloud||Inc|",
      "secondary-stock-transfer.txt [double-spaced] lost:Marcus Ellery Doyle Priya Venkataraman||| gained:-",
      "side-letter.txt [double-spaced] lost:Kestrel Deepwater GP III||LLC| gained:Kestrel Deepwater GP III, LLC||LLC|",
      'sow.txt [smart quotes] lost:Halewood Data Systems LLC ("Supplier")|MSA|| gained:Halewood Data Systems LLC (“Supplier”)|MSA||',
      "term-sheet.txt [double-spaced] lost:Kestrel Deepwater GP III||| gained:Kestrel Deepwater GP III, LLC|||",
      "trial-motion.txt [double-spaced] lost:Dashiell Tsukamoto Dashiell Tsukamoto Halloran & Tsukamoto||PLLC| gained:Dashiell Tsukamoto|||,Halloran & Tsukamoto||PLLC|",
      "uk-idta-addendum.txt [blank lines stripped] lost:- gained:Sable Notification Services||GmbH|",
    ],
  },
  // extraction-format-invariance.test.ts — JURISDICTION_DEBT
  "jurisdictions-layout": {
    reason:
      "On {n} specimen-and-layout pairs, a governing-law or venue clause is read differently when the layout changes.",
    entries: [],
  },
  // extraction-format-invariance.test.ts — AMOUNT_DEBT
  "amounts-layout": {
    reason:
      "On {n} specimen-and-layout pairs, a money amount is read differently when the layout changes.",
    entries: [],
  },
  // extraction-format-invariance.test.ts — DATE_DEBT
  "dates-layout": {
    reason: "On {n} specimen-and-layout pairs, a date is read differently when the layout changes.",
    entries: [],
  },
  // format-invariance.test.ts — HYPHEN_WRAP_DEBT
  "hyphenated-line-breaks": {
    reason:
      "On {n} specimens, when a long word is split across lines with a hyphen (as a PDF does), a finding appears or disappears because the broken word hides a phrase a rule looks for.",
    entries: [
      // Same class again, with the APA added in 9.634.0: a broken word hides the
      // phrase a suppression keys on, the suppression lifts, and the INFO venue
      // finding appears.
      "asset-purchase-complete.txt: lost - gained CHOICE-003",
      // 9.881.0 — two of the tranche B specimens, the same class: a broken
      // word hides the venue clause from its suppression in one, and the
      // phrase "liquidated damages" in the other.
      "buy-sell-agreement-complete.txt: lost - gained CHOICE-003",
      "cloud-services-agreement.txt: lost DARK-002,TEMP-004 gained -",
      "commercial-power-purchase-complete.txt: lost FIN-006 gained -",
      "construction-contract.txt: lost - gained CHOICE-006",
      "cookie-notice-uk.txt: lost - gained IPDATA-008",
      // 9.640.0 — the eighth clean document, and the THIRD instance of the one
      // shape the resolver cannot decide: a long word the document uses EXACTLY
      // ONCE. "Commonwealth" appears in this agreement's governing-law clause and
      // nowhere else, so neither of the resolver's two tests can fire — the
      // document never writes the compound unbroken, and the joined halves are not
      // a word it uses elsewhere — and "Common-wealth of Massachusetts" is what the
      // jurisdiction extractor records. Three CHOICE rules then report a
      // governing-law/venue mismatch between "Common-wealth of Massachusetts" and
      // "Massachusetts" that the document does not have.
      //
      // 🚨 Do NOT reach for a fourth resolver rule here: TAIL, HEAD and WRAP
      // GEOMETRY have all been tried and rejected, and the reasons are in
      // `hyphenation.ts`. A dictionary is what this case wants and the resolver
      // deliberately has none.
      // Added with the specimen in 9.632.0, and the same shape as the entries
      // around it: a long word broken across a line hides the phrase a suppression
      // was keying on, the suppression lifts, and an INFO finding about venue
      // appears. The document's governing-law and venue clauses are unchanged; what
      // moved is what the engine could read of them.
      "enterprise-saas-subscription.txt: lost - gained CHOICE-003",
      "executive-employment-complete.txt: lost - gained CHOICE-004",
      "hold-harmless.txt: lost RISK-010 gained -",
      "indemnification-agreement.txt: lost - gained GOV-145",
      "independent-contractor.txt: lost RISK-007 gained -",
      "internship-agreement.txt: lost - gained CHOICE-004",
      "joint-venture.txt: lost - gained CHOICE-003",
      "lease-assignment-retail.txt: lost - gained CHOICE-004",
      "ma-restrictive-covenant.txt: lost OBLI-002 gained -",
      "msa-customer-side.txt: lost TERM-001,TERM-003 gained -",
      "patent-licence-complete.txt: lost - gained CHOICE-004",
      "physician-employment.txt: lost - gained CHOICE-003",
      "saas-tos.txt: lost - gained CHOICE-003",
      "separation-agreement.txt: lost - gained RISK-001",
      "staffing-services.txt: lost TERM-001 gained -",
      "stock-purchase.txt: lost TEMP-012 gained -",
      "subcontract.txt: lost FIN-006 gained -",
      "subordination-agreement.txt: lost - gained CHOICE-003",
      "uk-contract-of-employment.txt: lost IPDATA-001,OBLI-004,OBLI-005,PERS-002,TERM-005 gained - routed employment-at-will-us->generic-fallback",
      "uk-mutual-nda.txt: lost - gained IPDATA-001",
      "unilateral-nda.txt: lost - gained CHOICE-003",
    ],
  },
  // instrument-vocabulary.test.ts — INSTRUMENT_DEBT
  "agreement-renamed-contract": {
    reason:
      "On {n} specimens, calling the document a Contract instead of an Agreement moves a finding — most often because the document's title no longer contains the word it defines.",
    entries: [
      "arbitration-demand.txt: lost - gained SET-123",
      "il-secured-promissory-note.txt: lost - gained STRUCT-006",
      "ma-restrictive-covenant.txt: lost - gained STRUCT-006",
      "ppm-narrative.txt: lost - gained STRUCT-006",
      "promissory-note-secured.txt: lost - gained STRUCT-006",
      "promissory-note.txt: lost - gained STRUCT-006",
      "stock-purchase.txt: lost - gained EQT-135",
      "tolling-agreement-standstill.txt: lost - gained STRUCT-006",
      "ucc-1.txt: lost - gained BNK-050",
      "uk-master-services-agreement.txt: lost - gained MSA-026",
    ],
  },
  // passive-voice.test.ts — PASSIVE_DEBT
  /**
   * 🚨 THE ROOT CAUSE, diagnosed s44, and why the obvious repair is unsafe.
   *
   * This entry is a SYMPTOM. The cause is that the obligation extractor reads
   * a passive clause's SUBJECT as its obligor, and in passive voice the
   * subject is the beneficiary — or not a party at all:
   *
   *   "Licensor shall be indemnified … by Licensee"  → obligor "Licensor"
   *   "The Goods shall be delivered by the Supplier" → obligor "The Goods"
   *
   * The first INVERTS who owes the duty; the second records a thing as owing
   * one. `report/exports.ts` and the DOCX obligations ledger print `obligor`
   * verbatim, so a passive-voice contract yields a ledger naming the wrong
   * party — or a crate of goods — as the obligor. Passive voice is ordinary
   * legal drafting, not a presentation artifact, so this is wrong on real
   * documents and not only under the transform.
   *
   * Measured over the corpus: **395 of 3,822 obligations (10.3%) are
   * passive.** But only **5** carry a named agent after "by", and
   * re-attributing the obligation to that agent — the repair that suggests
   * itself — is wrong on at least one of the five: "…governed by Ohio" would
   * make OHIO the obligor, where "by" introduces a governing law, not an
   * actor. The other 390 are AGENTLESS passives ("the Goods shall be
   * delivered"), where the sentence names no obligor to record at all.
   *
   * So the three available repairs each fail differently: re-attribution is
   * unsafe (measured), dropping passive obligations loses a tenth of the
   * ledger, and marking them needs a new field on `Obligation` plus a
   * presentation decision for every consumer. That is a product call, and it
   * belongs with the obligor-fragment work this debt already neighbours —
   * where the measured repair likewise adds a finding to 55% of specimens.
   */
  "passive-voice-indemnity": {
    reason:
      'On {n} specimens, rewriting an indemnity in the passive voice ("shall be indemnified by") draws a one-sided-indemnity finding the original does not.',
    entries: ["trademark-license-food.txt: gained OBLI-002"],
  },
  // register-format-invariance.test.ts — DOUBLE_SPACED_DEBT
  "critical-dates-double-spacing": {
    reason:
      "On {n} specimens, double-spacing the document changes which deadline the critical-dates register derives.",
    entries: [
      "security-incident-response-plan.txt: lost cure-window|unresolved gained notice-period|unresolved",
    ],
  },
  // shall-will.test.ts — MUST_DEBT
  "shall-written-as-must": {
    reason: 'On {n} specimens, writing every "shall" as "must" moves a finding.',
    entries: [],
  },
  // shouted-clause.test.ts — DISCLAIMER_DEBT
  "capitals-warranty-disclaimer": {
    reason:
      "On {n} specimens, setting the warranty disclaimer in capital letters (as drafters do) moves a finding.",
    entries: [
      // 9.825.0 — `asset-purchase-complete.txt` and `stock-purchase-agreement.txt`
      // LEFT this list: their STRUCT-005 was a shouted plural term ("ASSUMED
      // LIABILITIES") whose singular use ("ANY ASSUMED LIABILITY") did not match,
      // because the singular was built as "LIABILITy". Plurals now keep the case.
      "assignment-and-assumption-agreement.txt: lost STRUCT-018 gained -",
      "franchise.txt: lost STRUCT-006 gained -",
      "net-lease.txt: lost STRUCT-018 gained -",
      "warrant.txt: lost STRUCT-006 gained CHOICE-004",
    ],
  },
  // shouted-clause.test.ts — LIABILITY_DEBT
  /**
   * 🚨 TWO REPAIRS MEASURED AND REJECTED (9.891.0). Do not try either again
   * without reading this.
   *
   * The dominant shape in these three lists is a rule that depends on CASE to
   * recognize a term, losing its signal when a clause is shouted: STRUCT-006
   * and STRUCT-018 are LOST eleven times between them, because a candidate
   * needs two occurrences (`positions.length >= 2` in `definitions.ts`) and
   * shouting one of exactly two drops it below the threshold.
   *
   * **1. Matching all-caps runs to FIND candidates: rejected, 19× flood.**
   * The corpus goes from 185 undefined-term candidates to 3,615. The new ones
   * are headings, court captions and shouted sentence fragments — "RISK
   * FACTORS", "IN WITNESS WHEREOF", "COURT FOR THE NORTHERN DISTRICT", "IS
   * MADE AS OF SEPTEMBER" — every one of which the report would put to a
   * reader as a term the drafter forgot to define.
   *
   * **2. Counting a KNOWN candidate's shouted occurrences: rejected too, and
   * this one looked safe.** Discovery stays Title-Case only, so there is no
   * flood: the corpus moves 185 → 208. But 15 of those 23 are junk, because
   * the shouted pass bypasses every exclusion the Title-Case pass applies —
   * signatories, case names, city names, a clause number before the phrase,
   * and the document's own title. It promotes shouted party names from
   * signature blocks and captions ("Cascadia Surety", "Marisol
   * Ontiveros-Baez", "Internal Revenue" out of INTERNAL REVENUE CODE), a
   * division reference ("Article Five"), and — worst — the document's OWN
   * NAME ("Order Form", "Privacy Notice", "Unanimous Written Consent"), which
   * `undefinedTermCandidates` carries a documented exemption for precisely
   * because each was a real false accusation. Making it safe means routing the
   * shouted pass through all five tests, which is re-implementing the pass for
   * about seven lines of this ledger.
   *
   * A false "you forgot to define this" is a confident accusation about the
   * reader's own drafting; a finding that moves when a clause is shouted is a
   * stability wart. The wart is the better trade, and it is the reason these
   * lists stay.
   */
  "capitals-limitation-of-liability": {
    reason:
      "On {n} specimens, setting the limitation of liability in capital letters moves a finding, usually because a party name or a heading can no longer be told from the words around it.",
    entries: [
      "articles-org.txt: lost - gained STRUCT-007",
      "asset-purchase-complete.txt: lost - gained OBLI-002,RISK-002",
      // 9.634.0 — `msa-customer-side.txt` LEFT this list: it no longer gains
      // RISK-002, because the indemnity-sentence scan stopped ending at the decimal
      // point inside an amount. The harness had been measuring a truncation rather
      // than the shouting.
      "assignment-of-claim.txt: lost STRUCT-018 gained -",
      "cohabitation-agreement.txt: lost STRUCT-018 gained -",
      "commercial-indemnity-agreement.txt: lost - gained RISK-002",
      "distribution.txt: lost - gained OBLI-002",
      // 9.831.0 — the same erasure: shouting clause 12 removes one of "Project
      // Director"'s Title-Case uses, and the signature row that held another is
      // now its own paragraph, so the rule no longer sees enough uses.
      "fiscal-sponsorship.txt: lost STRUCT-006 gained -",
      "insurance-endorsement-additional-insured.txt: lost - gained STRUCT-007",
      "insurance-endorsement.txt: lost - gained STRUCT-007",
      "joint-venture.txt: lost STRUCT-017 gained -",
      "master-purchase-agreement.txt: lost - gained OBLI-002",
      "net-lease.txt: lost STRUCT-006 gained -",
      "ny-good-guy-guaranty.txt: lost STRUCT-006 gained -",
      "partnership-agreement.txt: lost OBLI-002 gained -",
      "sweepstakes.txt: lost STRUCT-006 gained -",
    ],
  },
  // shouted-clause.test.ts — INDEMNITY_DEBT
  "capitals-indemnity": {
    reason:
      "On {n} specimens, setting the indemnity clause in capital letters moves a finding; with no lowercase letters, where a sentence starts — and so who indemnifies whom — can be misread.",
    entries: [
      "commercial-indemnity-agreement.txt: lost - gained RISK-002",
      "fiscal-sponsorship.txt: lost STRUCT-006 gained -",
      "indemnification-agreement.txt: lost STRUCT-009 gained -",
      "investor-rights.txt: lost - gained OBLI-002",
      "net-lease.txt: lost STRUCT-006 gained -",
      "revolving-credit-agreement.txt: lost - gained RISK-002",
    ],
  },
  // spelled-amount.test.ts — PERCENT_DEBT
  "late-fee-rate-in-words": {
    reason:
      'On {n} specimens, a late-fee rate written in words ("five percent") is not read, so the usury check stays silent.',
    entries: [
      // 9.641.0 — the ninth clean document, and the same shape a ninth time: the
      // term loan states its late charge as "five percent (5%)", and stripping the
      // numeral leaves FIN-009 a rate it cannot read. The reason it stays
      // unrepaired is below.
      "credit-agreement-complete.txt: lost FIN-009 gained -",
      "equipment-finance.txt: lost FIN-009 gained -",
      "equipment-lease.txt: lost FIN-009 gained -",
      "il-secured-promissory-note.txt: lost FIN-009 gained -",
      "loan-agreement.txt: lost FIN-009 gained -",
      "ny-residential-lease.txt: lost FIN-009 gained -",
      // Added with the specimen in 9.633.0, and the same known shape as the seven
      // around it: FIN-009 parses the RATE and asserts usury, so a percentage
      // written in words alone ("five percent") is a rate it cannot read. The lease
      // states its late charge as "five percent (5%)"; strip the numeral and the
      // finding goes. Deliberately unrepaired — a word-parser for a rate that is
      // routinely fractional ("one and one-half percent per month") would risk a
      // confident false accusation about a legal limit.
      "office-lease-complete.txt: lost FIN-009 gained -",
      "promissory-note-secured.txt: lost FIN-009 gained -",
      "promissory-note.txt: lost FIN-009 gained -",
    ],
  },
  // insurance-limit-vs-cap.test.ts — CAP_AS_LIMIT_DEBT
  "liability-cap-as-insurance-limit": {
    reason:
      "On {n} specimens, a sum capping a party's liability is listed in the insurance summary as a coverage limit, because the clause that caps it also names a line of cover and the figure sits beside it.",
    entries: [
      // 9.888.0 — found while reading the insurance summary for a certificate.
      // The architect's cap is "the greater of $1,240,000 or the amount of
      // professional liability insurance proceeds actually available for the
      // claim", so the clause genuinely names professional liability and the
      // figure genuinely sits before it. Telling a CAP from a LIMIT needs the
      // clause's subject, not its vocabulary — the same figure in the same words
      // is a limit in an insurance schedule and a cap here — and that is a
      // separate change from reading a certificate's labels. One case.
      "architect-agreement.txt professional-liability 1240000",
    ],
  },
  // expected-defined-terms.test.ts — FALSE_ACCUSATIONS
  "expected-defined-terms": {
    reason:
      "On {n} specimens, a correct document does not use every defined term its document type expects, so enforcing that list as a rule would accuse it of a drafting defect. The list is not enforced for that reason.",
    entries: [],
    count: 27,
  },
} satisfies Record<string, KnownDebt>;
