/**
 * v5 sub-domain N′ — US trusts, benefits orders, and non-marital
 * agreements (spec-v45.md §6.N). Rule ids continue the EST namespace at
 * 401, above the assertion-gated estate-check range (EST-1xx/2xx/3xx).
 */

import type { Rule } from "../../finding.js";
import { pack } from "./_pack.js";
import { expressDenial, irs, practice, uniformAct, usc } from "./_helpers.js";

const C = "trust-estate";

const IRREVOCABLE = pack("irrevocable-trust", C, [
  {
    id: "EST-401",
    ver: "1.1.0",
    name: "Express irrevocability recital",
    cite: uniformAct("Uniform Trust Code § 602", "revocation or amendment of a revocable trust"),
    // "irrevocab" is this family's whole NAME — an Irrevocable Trust says it
    // in its title — so as a pillar it could never fail, and the conjunction
    // rested entirely on the recital below. Which is the right check: the
    // RECITAL is what makes the trust irrevocable, not the word in the title.
    pat: [
      /(may\s+not\s+be\s+(revoked|amended)|is\s+irrevocable|reserves?\s+no\s+power|no\s+power\s+to\s+(alter|revoke|amend))/i,
    ],
    why: "UTC § 602 reverses the common-law presumption: a trust is revocable unless the terms expressly provide otherwise. A trust intended to be irrevocable that does not say so is revocable in every UTC state, which destroys the estate-tax result.",
    fix: 'State expressly: "This Trust is irrevocable. The Settlor reserves no power to alter, amend, revoke, or terminate this Trust."',
    sev: "critical",
  },
  {
    id: "EST-402",
    // 1.1.0 — an express disclaimer of this column is now reported as a
    // disclaimer rather than read as compliance (`v5/_pack.ts`, `denied`).
    ver: "1.2.0",
    name: "Spendthrift clause",
    cite: uniformAct("Uniform Trust Code § 502", "spendthrift provision"),
    pat: [
      // 1.2.0 — three pillars, conjoined, because the rule's own rationale
      // is a conjunction the patterns did not enforce: UTC § 502 makes a
      // spendthrift provision valid ONLY IF it restrains both voluntary and
      // involuntary transfer, and `pat` defaults to an OR. A trust whose
      // "Spendthrift" article restrained the beneficiary alone — leaving
      // every creditor free to reach the interest, which is precisely the
      // clause § 502 says is ineffective — scored clean on a CRITICAL check,
      // as did one that barred creditors and let the beneficiary assign.
      //
      // The word itself, then the beneficiary-side restraint, then the
      // creditor-side restraint.
      /spendthrift/i,
      /(voluntar\w+|assign\w*|alienat\w+|anticipat\w+|encumber\w*|pledge\w*|hypothecat\w+)/i,
      /(involuntar\w+|creditors?|attach(?:ment|ed)?|garnish\w+|execution|legal\s+process|bankrupt\w+|claims?\s+of\s+(?:any\s+)?credit)/i,
    ],
    all: true,
    why: "UTC § 502 makes a spendthrift provision valid only if it restrains both voluntary and involuntary transfer. A clause restraining only one is ineffective as a spendthrift provision.",
    fix: "Add a spendthrift clause restraining both voluntary and involuntary transfer of a beneficiary's interest.",
    denied: expressDenial(String.raw`spendthrift\s+(?:clause|provision|protection)`),
    sev: "critical",
  },
  {
    id: "EST-403",
    name: "Distribution standard",
    cite: irs("26 U.S.C. § 2041", "powers of appointment — ascertainable standard"),
    pat: [
      /(health,?\s+education,?\s+maintenance|hems|ascertainable\s+standard)/i,
      /(support|comfort|welfare|absolute\s+discretion|sole\s+discretion)/i,
    ],
    why: "A beneficiary-trustee's power limited by an ascertainable standard under §§ 2041 and 2514 avoids a general power of appointment and estate inclusion. 'Comfort' and 'welfare' without qualification are not ascertainable.",
    fix: "State the distribution standard, and where a beneficiary serves as trustee, limit that trustee's discretion to health, education, maintenance, and support.",
    sev: "critical",
  },
  {
    id: "EST-404",
    name: "Trustee powers, succession, and removal",
    cite: uniformAct("Uniform Trust Code § 815", "general powers of trustee"),
    pat: [
      /(trustee\s+(shall\s+have\s+the\s+)?power|powers\s+of\s+the\s+trustee)/i,
      /(successor\s+trustee|resign|remov|appoint\s+a\s+successor)/i,
    ],
    why: "A trust with no succession mechanism requires a court to fill a vacancy. Beneficiary removal power must be drafted carefully — an unrestricted power to remove and appoint oneself can cause estate inclusion.",
    fix: "Enumerate the trustee's powers, the resignation and removal procedure, and the succession line, restricting any beneficiary's appointment power to independent successors.",
  },
  {
    id: "EST-405",
    name: "Crummey withdrawal rights where applicable",
    cite: irs("26 U.S.C. § 2503(b)", "gift tax — annual exclusion for present-interest gifts"),
    pat: [
      /(crummey|withdrawal\s+right|power\s+of\s+withdrawal)/i,
      /(notice|30\s+days|annual\s+exclusion|lapse|5\s+(and|or)\s+5|hanging\s+power)/i,
    ],
    why: "The annual exclusion requires a present interest, which a Crummey withdrawal right supplies — but only with real notice and a real window. Lapses above the 5-or-5 amount are themselves taxable gifts by the beneficiary.",
    fix: "Grant withdrawal rights with a stated notice procedure and window, and address the lapse using a 5-or-5 limit or a hanging power.",
    when: [
      /(crummey|withdrawal\s+right|annual\s+exclusion|life[-\s]+insurance\s+trust|ilit|gift\s+to\s+the\s+trust)/i,
    ],
  },
  {
    id: "EST-406",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Grantor-trust powers and tax reimbursement",
    cite: irs("26 U.S.C. §§ 671-679", "grantor trust rules"),
    pat: [
      /(grantor[-\s]+trust|section\s+67[1-9]|substitut(e|ion)\s+of\s+(assets|property)|non-?adverse\s+party)/i,
      /(reimburse|pay\s+the\s+income\s+tax|discretion\s+of\s+(an\s+)?independent\s+trustee)/i,
    ],
    why: "Intentional grantor-trust status lets the settlor pay the trust's income tax as an additional tax-free gift, but a mandatory reimbursement right causes estate inclusion. Discretionary reimbursement by an independent trustee is the safe form.",
    fix: "State the grantor-trust power relied on (typically a § 675(4)(C) substitution power) and make any tax reimbursement discretionary with an independent trustee, never mandatory.",
    when: [
      /(grantor[-\s]+trust|67[1-9]|idgit|intentionally\s+defective|substitution\s+of\s+assets)/i,
    ],
  },
  {
    id: "EST-407",
    name: "Situs, governing law, and decanting",
    cite: uniformAct(
      "Uniform Trust Decanting Act",
      "trustee's power to appoint trust property to a second trust",
    ),
    pat: [
      /(situs|governing\s+law|principal\s+place\s+of\s+administration)/i,
      /(decant|change\s+of\s+situs|move\s+the\s+administration|second\s+trust)/i,
    ],
    why: "Situs determines state income taxation, creditor protection, and whether decanting or nonjudicial modification is available. Choosing it deliberately, with a mechanism to change it, is worth decades of flexibility.",
    fix: "State the governing law, the principal place of administration, the mechanism to change situs, and whether the trustee may decant to a second trust.",
  },
]);

const SNT = pack("special-needs-trust", C, [
  {
    id: "EST-408",
    // 1.0.1 — written as a synonym OR, but the supplemental-not-supplanting recital and the benefits it names are distinct pillars; `ssi` alone matches inside "discussions". The check could not
    // fire on any realistic document.
    ver: "1.1.0",
    name: "Supplemental, not supplanting, benefits language",
    cite: agency_ssa(),
    pat: [
      // The recital is almost never written with the verb adjacent to "shall
      // not": "the Trustee shall not MAKE ANY DISTRIBUTION THAT WOULD supplant,
      // reduce, or replace any benefit the Beneficiary receives" is how a
      // first-party trust states it, and the adjacency read none of it — so a
      // trust whose section is headed "Supplemental, Not Substitute" drew a
      // `critical` for having no supplemental-needs language. The window is
      // bounded to one sentence and must land on a benefits object, which is
      // what keeps it off an unrelated prohibition.
      /(supplement(al)?\s+(to\s+and\s+not\s+in\s+place\s+of|and\s+not\s+(supplant|replace|impair|diminish))|shall\s+not\s+(supplant|replace|substitute\s+for)|(?:shall|will|must)\s+not\b[^.]{0,80}?\b(?:supplant|replace|substitute\s+for|impair|diminish|reduce)\b[^.]{0,60}?\b(?:benefit|assistance|eligibilit))/i,
      /(public\s+benefits|government\s+(assistance|benefits)|ssi|medicaid)/i,
    ],
    all: true,
    why: "The trust's whole purpose is to add to, not replace, means-tested benefits. Without the supplemental-needs language the trust reads as available support and can disqualify the beneficiary from SSI and Medicaid.",
    fix: "State that distributions are intended to supplement and not supplant, impair, or diminish any public benefits the beneficiary receives or may become eligible to receive.",
    sev: "critical",
  },
  {
    id: "EST-409",
    name: "First-party or third-party characterization",
    cite: usc("42", "1396p", "Medicaid — liens, adjustments, recoveries, and transfers of assets"),
    pat: [
      /(first-?party|self-?settled|d4a|\(d\)\(4\)\(a\)|third-?party)/i,
      /(funded\s+with\s+(the\s+)?beneficiary['’]?s?\s+(own\s+)?(assets|funds)|funded\s+by\s+(a\s+)?(parent|grandparent|third[-\s]+party))/i,
    ],
    why: "A first-party trust under § 1396p(d)(4)(A) must be for a disabled person under 65, established by the proper party, and carry a Medicaid payback. A third-party trust carries none of those constraints — but only if it truly holds no beneficiary assets.",
    fix: "State whose assets fund the trust and characterize it expressly as first-party (d)(4)(A) or third-party, and align the payback and age provisions accordingly.",
    sev: "critical",
  },
  {
    id: "EST-410",
    name: "Medicaid payback provision for a first-party trust",
    cite: usc("42", "1396p", "Medicaid — special needs trust payback requirement"),
    pat: [
      /(pay-?back|reimburse\s+(the\s+)?(state|medicaid))/i,
      /(upon\s+the\s+death\s+of\s+the\s+beneficiary|remaining\s+(funds|assets)|total\s+medical\s+assistance\s+paid)/i,
    ],
    why: "§ 1396p(d)(4)(A) requires the state to receive all amounts remaining at the beneficiary's death up to the total medical assistance paid. A first-party trust without the payback is not an exempt trust at all.",
    fix: "Include the payback provision naming each state that provided medical assistance, before any remainder distribution.",
    when: [
      /(first-?party|self-?settled|d4a|\(d\)\(4\)\(a\)|beneficiary['’]?s?\s+own\s+(assets|funds)|personal\s+injury\s+(settlement|recovery))/i,
    ],
    sev: "critical",
  },
  {
    id: "EST-411",
    name: "Sole-benefit and age conditions",
    cite: usc("42", "1396p", "Medicaid — sole benefit and under-65 conditions"),
    pat: [
      /(sole\s+benefit\s+of\s+the\s+beneficiary)/i,
      /(under\s+(the\s+)?age\s+of\s+65|before\s+the\s+beneficiary\s+(attained|reached)\s+age\s+65|disabled\s+(individual|as\s+defined))/i,
    ],
    why: "The (d)(4)(A) exemption requires the trust to be for the sole benefit of a disabled individual under 65 at establishment. Distributions benefiting anyone else can be treated as transfers subject to a penalty period.",
    fix: "State that the trust is for the sole benefit of the beneficiary, recite the beneficiary's disability determination and age at establishment, and restrict distributions benefiting others.",
    when: [/(first-?party|self-?settled|d4a|\(d\)\(4\)\(a\))/i],
  },
  {
    id: "EST-412",
    name: "Trustee discretion with no support obligation",
    cite: agency_ssa(),
    pat: [
      /(sole\s+and\s+absolute\s+discretion|absolute\s+discretion)/i,
      /(no\s+(duty|obligation)\s+to\s+(make\s+any\s+distribution|provide\s+support)|beneficiary\s+(has\s+)?no\s+(right|power)\s+to\s+(compel|demand))/i,
    ],
    why: "If the beneficiary can compel a distribution, the trust is an available resource under the SSI rules. Absolute trustee discretion plus an express statement that the beneficiary cannot compel is what keeps it unavailable.",
    fix: "Give the trustee sole and absolute discretion, state that no beneficiary may compel a distribution, and that the trustee has no duty to provide support.",
    sev: "critical",
  },
  {
    id: "EST-413",
    name: "Distribution limits on cash and in-kind support",
    cite: agency_ssa(),
    pat: [
      /(cash|in-?kind\s+support\s+and\s+maintenance|ISM)/i,
      /(shall\s+not\s+(distribute|pay)\s+(cash\s+)?directly|food\s+(and|or)\s+shelter|reduce\s+(the\s+)?(ssi|benefit))/i,
    ],
    why: "Cash to the beneficiary reduces SSI dollar for dollar, and payments for food or shelter reduce it by the presumed maximum value. Trustees need the rule in the document, not only in a memo.",
    fix: "Direct the trustee not to distribute cash directly to the beneficiary and to consider the in-kind support and maintenance consequences of food and shelter payments.",
  },
]);

const TRUST_AMENDMENT = pack("trust-amendment", C, [
  {
    id: "EST-414",
    name: "Original trust identified by name and date",
    cite: practice("amendment-identification", "identification of the amended instrument"),
    pat: [
      /(trust\s+(agreement|instrument)\s+dated|declaration\s+of\s+trust\s+dated|the\s+.{0,60}\s+trust,?\s+dated)/i,
      /(originally\s+(executed|established)|as\s+(previously\s+)?amended)/i,
    ],
    why: "An amendment that does not identify the instrument it amends — including prior amendments — is the reason trusts end up with contradictory provisions nobody can reconcile after the settlor's death.",
    fix: "Identify the trust by its exact name and original date, list every prior amendment by number and date, and state which are superseded.",
    sev: "critical",
  },
  {
    id: "EST-415",
    name: "Power to amend cited and its method followed",
    cite: uniformAct("Uniform Trust Code § 602", "revocation or amendment — method"),
    pat: [
      /(reserved\s+the\s+right\s+to\s+amend|power\s+to\s+amend|article\s+\w+\s+of\s+the\s+trust)/i,
      /(in\s+accordance\s+with|pursuant\s+to|as\s+provided\s+in\s+section)/i,
    ],
    why: "UTC § 602(c) requires substantial compliance with a method the trust specifies, and where the trust specifies an exclusive method, only that method works. Amendments failing the specified method are void.",
    fix: "Cite the article reserving the power to amend and recite that the amendment is made in the manner that article requires.",
    sev: "critical",
  },
  {
    id: "EST-416",
    ver: "1.1.0",
    name: "Amended provisions restated in full",
    cite: practice("restatement", "restating amended provisions in full"),
    pat: [
      /(is\s+(hereby\s+)?(amended|deleted|restated)|shall\s+read\s+as\s+follows)/i,
      /(in\s+its\s+entirety|article\s+\w+|section\s+\d)/i,
    ],
    // `all: true`. The locator pillar is `section \d`, which every instrument
    // satisfies, so an amendment that restates nothing passed the column
    // requiring amended provisions to be restated in full.
    all: true,
    why: "Amendments that describe a change without restating the provision produce reconstruction disputes years later, when nobody remembers what the original said.",
    fix: "Identify each amended article or section by number and restate it in full as amended, rather than describing the change.",
  },
  {
    id: "EST-417",
    name: "Ratification of unamended terms",
    cite: practice("ratification", "ratification of unamended trust provisions"),
    pat: [
      /(ratif|confirm|remain\s+in\s+full\s+force)/i,
      /(in\s+all\s+other\s+respects|except\s+as\s+(expressly\s+)?(amended|modified)|unchanged)/i,
    ],
    why: "Without ratification, an amendment can be argued to have superseded the whole instrument. The clause is one sentence and forecloses the argument.",
    fix: 'Add: "In all other respects the Trust as previously amended is ratified and confirmed and remains in full force and effect."',
  },
  {
    id: "EST-418",
    // 1.1.0 — an express disclaimer of this column is now reported as a
    // disclaimer rather than read as compliance (`v5/_pack.ts`, `denied`).
    ver: "1.1.0",
    name: "Settlor and trustee execution and notarization",
    cite: practice("trust-execution", "execution formalities for trust amendments"),
    pat: [
      /(settlor|trustor|grantor)/i,
      /(notary|acknowledged\s+before\s+me|trustee\s+(signature|accepts))/i,
    ],
    all: true,
    why: "Trust amendments do not require witnesses in most states, but notarization is nearly always used and is what a financial institution will demand before honoring the amended terms.",
    fix: "Add settlor and trustee signature blocks with the date and a notarial acknowledgment, matching the formality used on the original instrument.",
    denied: expressDenial(
      String.raw`notariz(?:ation|ed)|acknowledg(?:e?ment)\s+before\s+a\s+notary`,
    ),
    sev: "critical",
  },
]);

const QDRO = pack("qdro", C, [
  {
    id: "EST-419",
    name: "Plan named and participant and alternate payee identified",
    cite: usc("29", "1056", "ERISA § 206(d)(3) — qualified domestic relations orders"),
    pat: [/(the\s+plan|plan\s+name|plan[-\s]+administrator)/i, /(alternate\s+payee|participant)/i],
    why: "§ 1056(d)(3)(C) requires the order to name the plan and give the name and last known mailing address of the participant and each alternate payee. An order missing any of these cannot be qualified.",
    fix: "Name the plan exactly as it appears in the plan documents and give each party's name and last known mailing address.",
    sev: "critical",
  },
  {
    id: "EST-420",
    ver: "1.1.0",
    name: "Amount or percentage and valuation date",
    cite: usc("29", "1056", "ERISA § 206(d)(3)(C)(ii) — amount or percentage of benefits"),
    pat: [
      /(percentage|amount|\d+%|\$)/i,
      /(valuation\s+date|as\s+of\s+\w+\s+\d{1,2},?\s+\d{4}|account\s+balance\s+as\s+of|manner\s+in\s+which\s+the\s+amount)/i,
    ],
    // `all: true`. The valuation pillar is a bare date, which every executed
    // instrument carries, so the column was satisfied by the preamble.
    all: true,
    why: "The order must state the amount or percentage to be paid or the manner of determining it. A percentage with no valuation date is not determinable and is routinely rejected.",
    fix: "State the amount or percentage and the valuation date, or the formula (such as a coverture fraction) with all its inputs defined.",
    sev: "critical",
  },
  {
    id: "EST-421",
    name: "No increased-benefit requirement",
    cite: usc("29", "1056", "ERISA § 206(d)(3)(D) — limitations on qualified orders"),
    pat: [
      /(shall\s+not\s+require\s+the\s+plan\s+to\s+provide|does\s+not\s+require)/i,
      /(any\s+type\s+or\s+form\s+of\s+benefit.{0,60}not\s+otherwise\s+provided|increased\s+benefits|actuarial\s+value)/i,
    ],
    why: "§ 1056(d)(3)(D) disqualifies an order that requires a benefit form the plan does not offer, increased benefits, or benefits already assigned to another alternate payee. The negative recital is what plan administrators look for first.",
    fix: "Recite that the order does not require the plan to provide any type or form of benefit not otherwise provided, to provide increased benefits, or to pay benefits already required to be paid to another alternate payee.",
    sev: "critical",
  },
  {
    id: "EST-422",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Separate-interest or shared-payment method",
    cite: usc("29", "1056", "ERISA § 206(d)(3) — form of benefit to the alternate payee"),
    pat: [
      /(separate[-\s]+interest|shared[-\s]+payment)/i,
      /(alternate\s+payee['’]?s?\s+(own\s+)?life|when\s+the\s+participant\s+(begins|commences)|actuarially\s+adjusted)/i,
    ],
    why: "A separate interest is payable over the alternate payee's own lifetime; a shared payment depends on the participant's election and ends at the participant's death. The choice is the practical difference between security and dependence.",
    fix: "State whether the award is a separate interest or a shared payment, and for a separate interest, the actuarial adjustment and the alternate payee's own commencement rights.",
    sev: "critical",
  },
  {
    id: "EST-423",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Survivor-benefit treatment",
    cite: usc(
      "29",
      "1055",
      "ERISA § 205 — requirement of joint and survivor annuity and preretirement survivor annuity",
    ),
    pat: [
      /(survivor[-\s]+(benefit|annuity)|qpsa|qjsa|pre-?retirement\s+survivor)/i,
      /(alternate\s+payee\s+(shall\s+be\s+)?(treated\s+as\s+)?(the\s+)?(surviving\s+)?spouse|former\s+spouse)/i,
    ],
    why: "The order may treat the alternate payee as the surviving spouse for QPSA and QJSA purposes. If it does not, the alternate payee's interest in a defined benefit plan can vanish if the participant dies before retirement.",
    fix: "State whether the alternate payee is treated as the surviving spouse for QPSA and QJSA purposes and to what extent.",
    when: [/(defined\s+benefit|pension\s+plan|annuity|qpsa|qjsa)/i],
  },
  {
    id: "EST-424",
    name: "Earnings and losses allocation",
    cite: practice(
      "qdro-earnings",
      "allocation of earnings and losses between the valuation date and segregation",
    ),
    pat: [
      /(earnings|gains?\s+and\s+losses|investment\s+(experience|performance))/i,
      /(from\s+the\s+valuation\s+date|until\s+(the\s+date\s+of\s+)?(segregation|distribution|transfer)|adjusted\s+for)/i,
    ],
    why: "Months pass between the valuation date and segregation, and markets move. An order silent on earnings leaves the plan to apply its default, which may be zero.",
    fix: "State whether the alternate payee's share is adjusted for earnings and losses from the valuation date to the date of segregation, and on what basis.",
    when: [/(defined\s+contribution|401\(k\)|403\(b\)|account\s+balance|profit\s+sharing)/i],
  },
  {
    id: "EST-425",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.2.0",
    name: "Court entry and plan-administrator qualification",
    cite: usc("29", "1056", "ERISA § 206(d)(3)(G) — plan administrator determination"),
    pat: [
      // "ENTER:" / "ENTERED:" — the bare entry line an order carries above the
      // judge's signature, and the only form of court entry most state-court
      // QDROs write. Without it, an order that recites its own entry, names
      // the plan administrator, and retains jurisdiction to amend was still
      // reported at `critical` for having none of the three.
      /(entered\s+by\s+the\s+court|so\s+ordered|it\s+is\s+(hereby\s+)?ordered|submitted\s+to\s+the\s+court|(?:^|\s)enter(?:ed)?\s*:|this\s+order\s+is\s+entered|the\s+court\s+(?:hereby\s+)?(?:enters|adjudges|decrees))/i,
      /(plan[-\s]+administrator|retains?\s+jurisdiction|reserves?\s+jurisdiction)/i,
    ],
    all: true,
    why: "A DRO becomes a QDRO only when the plan administrator determines it qualifies. Courts should retain jurisdiction so the order can be amended if the administrator rejects it.",
    fix: "Provide for entry by the court, submission to the plan administrator, and the court's retained jurisdiction to amend the order to secure qualification.",
    sev: "critical",
  },
]);

const COHABITATION = pack("cohabitation-agreement", C, [
  {
    id: "EST-426",
    name: "Non-marital status recital",
    cite: practice(
      "marvin",
      "the Marvin line of cases and enforceability of non-marital agreements",
    ),
    pat: [
      /(are\s+not\s+married|not\s+(legally\s+)?married|no\s+(common\s+law\s+)?marriage)/i,
      /(cohabit|live\s+together|domestic\s+partner)/i,
    ],
    all: true,
    why: "Express agreements between unmarried cohabitants are enforceable in most states, but only if they rest on consideration independent of the relationship. The recital that the parties are unmarried frames the whole document.",
    fix: "Recite that the parties are not married, do not intend to create a common-law marriage, and that the agreement is not consideration for the relationship itself.",
    sev: "critical",
  },
  {
    id: "EST-427",
    name: "Separate versus jointly acquired property",
    cite: practice("cohabitation-property", "property characterization in cohabitation agreements"),
    pat: [
      /separate\s+property/i,
      /(joint(ly)?\s+(acquired|owned|held)|shall\s+remain\s+the\s+(sole\s+)?property|contribution)/i,
    ],
    all: true,
    why: "Without an agreement, an unmarried partner's claim to property titled in the other's name rests on constructive trust or unjust enrichment — expensive, uncertain doctrines. The agreement replaces them.",
    fix: "Schedule each party's separate property, state that it remains separate, and describe how jointly acquired property is titled, shared, and divided.",
    sev: "critical",
  },
  {
    id: "EST-428",
    name: "Support agreement and consideration",
    cite: practice("cohabitation-support", "support obligations between unmarried cohabitants"),
    pat: [
      /support/i,
      /(no\s+(claim|right)\s+(to|for)\s+support|palimony|waive|shall\s+(pay|provide))/i,
    ],
    why: "Support claims between unmarried partners — the palimony theory — are the most common cohabitation dispute. Whether support is promised or waived should be an express term, not a later inference.",
    fix: "State whether either party will provide support during or after the relationship, or waive any support claim expressly.",
  },
  {
    id: "EST-429",
    // 1.1.0 — an express disclaimer of this column is now reported as a
    // disclaimer rather than read as compliance (`v5/_pack.ts`, `denied`).
    ver: "1.1.0",
    name: "Independent counsel and financial disclosure",
    cite: practice(
      "cohabitation-procedure",
      "procedural fairness in agreements between intimate partners",
    ),
    pat: [
      /(independent\s+(legal\s+)?(counsel|advice)|represented\s+by\s+(separate|his\s+or\s+her\s+own))/i,
      /(financial\s+disclosure|schedule\s+of\s+assets|full\s+(and\s+fair\s+)?disclosure|opportunity\s+to\s+consult)/i,
    ],
    why: "Courts scrutinize agreements between intimate partners for overreaching. Independent counsel and full asset disclosure are the two facts that most reliably defeat an unconscionability challenge.",
    fix: "Recite that each party had the opportunity for independent counsel (naming counsel or recording the waiver) and attach a schedule of each party's assets, debts, and income.",
    denied: expressDenial(String.raw`(?:independent|separate)\s+counsel|financial\s+disclosure`),
    sev: "critical",
  },
  {
    id: "EST-430",
    name: "Termination on marriage or separation",
    cite: practice(
      "cohabitation-termination",
      "termination and marriage triggers in cohabitation agreements",
    ),
    pat: [
      /(terminat|ends?\s+(upon|on)|separation\s+of\s+the\s+parties)/i,
      /(marriage|marry|if\s+the\s+parties\s+(later\s+)?marry|shall\s+(become|be)\s+(void|of\s+no\s+effect))/i,
    ],
    why: "If the parties later marry, a cohabitation agreement is not a premarital agreement and generally does not survive as one. Saying what happens avoids a couple believing they are protected when they are not.",
    fix: "State the events that terminate the agreement, and state expressly whether it survives marriage or must be replaced by a premarital or postnuptial agreement.",
  },
]);

/** SSA POMS — the operating instructions the field applies to SSI trust resource determinations. */
function agency_ssa() {
  return practice(
    "ssi-trust-resource",
    "SSA Program Operations Manual System SI 01120.200 treatment of trusts as SSI resources",
  );
}

export const V5_TRUST_ESTATE_RULES: readonly Rule[] = [
  ...IRREVOCABLE,
  ...SNT,
  ...TRUST_AMENDMENT,
  ...QDRO,
  ...COHABITATION,
];
