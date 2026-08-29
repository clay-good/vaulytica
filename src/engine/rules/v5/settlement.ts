/**
 * v5 sub-domain G′ — US settlement, release, and litigation-adjacent
 * instruments (spec-v45.md §6.G). Rule ids continue the SET namespace
 * at 101.
 */

import type { Rule } from "../../finding.js";
import { pack } from "./_pack.js";
import { frcp, fre, stateLaw, practice, standardForm, modelRule } from "./_helpers.js";

const C = "settlement";

const CONSENT_JUDGMENT = pack("consent-judgment", C, [
  {
    id: "SET-101",
    name: "Court, caption, and case number",
    cite: frcp("10(a)", "form of pleadings — caption and names of parties"),
    pat: [
      /(in\s+the\s+(united\s+states\s+)?(district|superior|circuit|supreme)\s+court|court\s+of)/i,
      /(case\s+(no|number)|civil\s+action\s+no|docket\s+no)/i,
    ],
    why: "A consent judgment is a court order, not a contract. Without a conforming caption and case number the clerk cannot enter it and the parties have a settlement with no judgment behind it.",
    fix: "Add the full court caption, party names as they appear on the docket, the case number, and the judge's name where local rules require it.",
    sev: "critical",
  },
  {
    id: "SET-102",
    name: "Retention of jurisdiction to enforce",
    cite: practice(
      "kokkonen",
      "Kokkonen v. Guardian Life and the need for express retention of jurisdiction",
    ),
    pat: [
      /(retain(s|ed)?\s+jurisdiction|the\s+court\s+shall\s+retain)/i,
      /(enforce|compliance\s+with\s+(this\s+)?(judgment|order)|until\s+(fully\s+)?(satisfied|performed))/i,
    ],
    why: "Under Kokkonen a federal court has no ancillary jurisdiction to enforce a settlement unless it expressly retained jurisdiction or incorporated the terms into the order. Without it, enforcement means a new breach-of-contract suit.",
    fix: "State that the court retains jurisdiction to enforce the judgment, and incorporate the operative settlement terms into the order itself.",
    sev: "critical",
  },
  {
    id: "SET-103",
    ver: "1.1.0",
    name: "Admission or no-admission recital",
    cite: fre("408", "compromise offers and negotiations"),
    pat: [
      // "this Consent Judgment IS NOT AN ADMISSION of liability" and
      // "Defendants DENY THE ALLEGATIONS of the Complaint" are the two forms
      // a real no-admission recital takes; the pattern read "no admission"
      // and "denies liability" only.
      /(without\s+(any\s+)?admission|no\s+admission\s+of\s+(liability|wrongdoing)|not\s+an\s+admission|den(?:y|ies|ied)\s+(?:any\s+)?(?:liability|the\s+allegations))/i,
      /(admits?|acknowledges?\s+liability|stipulates?\s+to\s+liability)/i,
    ],
    // The no-admission recital lives in the WHEREAS clauses — "WHEREAS,
    // Defendants deny the allegations of the Complaint and this Consent
    // Judgment is not an admission of liability" — and the pack's text source
    // strips recitals by default, so the rule could not see the very sentence
    // it exists to find.
    recitals: true,
    why: "A consent judgment can carry collateral-estoppel and insurance-coverage consequences depending on whether liability was admitted. Silence leaves the question to a later court.",
    fix: "State expressly whether the defendant admits liability, and if not, that the judgment is entered without admission and may not be used as evidence of liability elsewhere.",
  },
  {
    id: "SET-104",
    name: "Amount, payment terms, and default acceleration",
    cite: practice(
      "consent-judgment-payment",
      "payment and acceleration terms in stipulated judgments",
    ),
    pat: [
      /(judgment\s+(is\s+)?(hereby\s+)?entered|in\s+the\s+(amount|sum)\s+of|\$)/i,
      /(payment|installment|default|acceler|interest)/i,
    ],
    why: "The value of a consent judgment is that it converts a payment promise into an executable judgment. Without an acceleration clause on default, the plaintiff must move for entry each time an installment is missed.",
    fix: "State the judgment amount, the payment schedule, the default grace period, and that the full unpaid balance accelerates and becomes immediately executable on default.",
  },
  {
    id: "SET-105",
    ver: "1.1.0",
    name: "Vacatur or satisfaction on performance",
    cite: practice("satisfaction-of-judgment", "satisfaction and vacatur of stipulated judgments"),
    pat: [
      // A consent decree is discharged by a motion to TERMINATE it after a
      // stated compliance period, not by filing a satisfaction of judgment:
      // "Defendants may MOVE TO TERMINATE this Consent Judgment after they
      // have maintained compliance for twenty-four (24) consecutive months".
      /(satisfaction\s+of\s+judgment|satisfied|vacat|(?:move|motion)\s+to\s+terminate|terminat\w+[^.;]{0,80}?(?:consent\s+(?:judgment|decree)|this\s+Decree))/i,
      /(upon\s+(full\s+)?payment|file\s+(a\s+)?(satisfaction|acknowledgment)|within\s+\d+\s+days)/i,
    ],
    why: "An unsatisfied judgment of record damages credit and title for years. The obligation to file a satisfaction, with a deadline, is the defendant's principal protection.",
    fix: "Require the plaintiff to file a satisfaction of judgment (or a stipulation to vacate) within a stated number of days after final payment, with a remedy if it does not.",
  },
]);

const COVENANT = pack("covenant-not-to-sue", C, [
  {
    id: "SET-106",
    // 1.0.1 — the second pillar knew only the RELEASE contrast, and the
    // commonest covenant not to sue is a PATENT one, whose operative
    // characterization is "this Covenant is a covenant not to sue and is not a
    // license". Same column — which instrument this is and which it is not —
    // and the check reported it missing, at `critical`, on the section that
    // states it.
    ver: "1.0.2",
    name: "Covenant versus release characterization",
    cite: practice(
      "covenant-vs-release",
      "distinction between a covenant not to sue and a release",
    ),
    pat: [
      /covenants?\s+not\s+to\s+sue/i,
      // The MIRROR characterization is just as standard: a settlement agreement
      // says "this is a general release, not a covenant not to sue". The
      // column is which instrument this is and which it is not, and it knew
      // only one direction.
      /is\s+not\s+a\s+(?:release|license|covenant\s+not\s+to\s+sue)|rather\s+than\s+a\s+(?:release|license|covenant)|does\s+not\s+release|(?:shall|will)\s+not\s+be\s+construed\s+as\s+(?:a\s+(?:release|license|covenant)|one)|not\s+a\s+license\b/i,
    ],
    all: true,
    why: "A release extinguishes the claim; a covenant not to sue leaves it alive but promises not to assert it. In joint-tortfeasor states the difference decides whether other defendants get a credit.",
    fix: "State expressly which instrument this is and that it is not to be construed as the other.",
    sev: "critical",
  },
  {
    id: "SET-107",
    // 1.0.1 — both pillars wanted an adjacency the drafting does not have.
    // The claims phrase carries its subject matter first ("any claim, demand,
    // or cause of action for infringement of the Patents ARISING FROM the
    // manufacture …"), and the time boundary is as often stated as the conduct
    // window ("whether such acts occurred BEFORE OR occur AFTER the date of
    // this Covenant") as by the "known and unknown" formula a release uses.
    ver: "1.0.1",
    name: "Scope of claims and time boundary",
    cite: practice("release-scope", "temporal and subject-matter scope of releases and covenants"),
    pat: [
      /(?:claims?|causes?\s+of\s+action|demands?)\b[^.;]{0,140}?\b(?:arising|relating|based)\s+(?:out\s+of|from|on|to)/i,
      /from\s+the\s+beginning\s+of\s+time|through\s+the\s+(?:date|effective\s+date)|known\s+(?:and|or)\s+unknown|(?:occurr\w+|acts?)\s+(?:on\s+or\s+)?(?:before|prior\s+to)\b|before\s+or\s+(?:occur\s+)?after\s+the\s+date/i,
    ],
    why: "A covenant with no temporal boundary bars claims that had not arisen when it was signed — which is usually more than either party intended and, for some statutory claims, is not permitted.",
    fix: "Define the covered claims by subject matter and bound them to conduct occurring on or before the effective date.",
    sev: "critical",
  },
  {
    id: "SET-108",
    name: "Effect on joint tortfeasors and contribution",
    cite: stateLaw(
      "contribution-among-tortfeasors",
      "the Uniform Contribution Among Tortfeasors Act and its state variations",
      "https://www.law.cornell.edu/wex/joint_and_several_liability",
    ),
    pat: [
      /(joint\s+tortfeasor|other\s+(defendants|parties)|contribution)/i,
      /(reduc|credit|set-?off|pro\s+tanto|pro\s+rata|does\s+not\s+(release|discharge))/i,
    ],
    why: "Under UCATA-style statutes, a release of one tortfeasor reduces the claim against others by the amount paid or the released party's share. A covenant that does not address it invites a settlement-credit fight at trial.",
    fix: "State the effect on non-parties: that the covenant does not release them, and how any payment is credited against the remaining claim.",
  },
  {
    id: "SET-109",
    name: "Assignment and successors",
    cite: practice("covenant-assignment", "binding successors and assigns in covenants not to sue"),
    pat: [
      /(successors?\s+and\s+assigns|heirs|executors)/i,
      /(bind|inure\s+to\s+the\s+benefit|assign)/i,
    ],
    why: "A covenant that binds only the signatory can be defeated by assigning the claim to a related entity that never promised anything.",
    fix: "Bind the covenantor's successors, assigns, heirs, and any assignee of the claim, and prohibit assignment of the covered claims.",
  },
  {
    id: "SET-110",
    name: "Breach remedy",
    cite: practice("covenant-breach", "remedies for breach of a covenant not to sue"),
    pat: [
      /(breach|violat)/i,
      /(damages|attorneys['’]?\s+fees|bar\s+to\s+(the\s+)?(action|suit)|dismiss|specific\s+performance)/i,
    ],
    why: "The classic weakness of a covenant is that breach gives a damages claim, not an automatic defense. Saying the covenant may be pleaded as a complete bar closes the gap.",
    fix: "State that the covenant may be pleaded as a complete defense and bar to any covered action, and add fee-shifting for enforcement.",
  },
]);

const ASSIGNMENT_OF_CLAIM = pack("assignment-of-claim", C, [
  {
    id: "SET-111",
    name: "Claim identified with specificity",
    cite: practice("claim-identification", "identification of assigned claims"),
    pat: [
      /(the\s+(assigned\s+)?claim|cause\s+of\s+action|judgment\s+entered)/i,
      /(against|case\s+no|arising\s+(out\s+)?of|dated)/i,
    ],
    why: "An assignment of unspecified claims is unenforceable for indefiniteness and cannot be recorded against a judgment. The debtor, the court, and the amount all need to appear.",
    fix: "Identify the claim by obligor, subject matter, case or judgment number, and amount, and state whether the assignment is partial or entire.",
    sev: "critical",
  },
  {
    id: "SET-112",
    name: "Assignability and anti-assignment review",
    cite: practice(
      "claim-assignability",
      "assignability of causes of action and anti-assignment clauses",
    ),
    pat: [
      /(assignab|may\s+be\s+assigned|no\s+(anti-?assignment|restriction))/i,
      /(personal\s+injury|tort\s+claims?|statutory\s+prohibition|contract\s+prohibits)/i,
    ],
    why: "Personal-injury and certain statutory claims are non-assignable in most states, and the underlying contract may forbid assignment of claims arising under it. Assigning a non-assignable claim transfers nothing.",
    fix: "Confirm the claim type is assignable in the governing state and that no contractual anti-assignment clause reaches it, and represent both.",
    sev: "critical",
  },
  {
    id: "SET-113",
    name: "Champerty and maintenance note",
    cite: stateLaw(
      "champerty",
      "champerty, maintenance, and barratry doctrines as applied to claim assignments",
      "https://www.law.cornell.edu/wex/champerty",
    ),
    pat: [
      /(champert|maintenance|barratry)/i,
      /(permitted|abolished|not\s+prohibited|governing\s+law|jurisdiction)/i,
    ],
    why: "A handful of states still void assignments of claims to strangers to the litigation. The doctrine is the first defense a defendant raises against an assignee plaintiff.",
    fix: "Confirm the governing state's position on champerty and recite the parties' pre-existing interest or the state's abolition of the doctrine.",
  },
  {
    id: "SET-114",
    name: "Notice to the obligor and substitution",
    cite: frcp("25(c)", "substitution of parties — transfer of interest"),
    pat: [
      /(notice\s+to\s+the\s+(obligor|debtor|defendant))/i,
      /(substitut|real\s+party\s+in\s+interest|rule\s+25|motion\s+to\s+substitute)/i,
    ],
    why: "Until the obligor has notice, payment to the assignor discharges the debt. In pending litigation, Rule 25(c) substitution or joinder is what puts the assignee before the court.",
    fix: "Require prompt written notice to the obligor and, in pending litigation, cooperation in a Rule 25(c) motion to substitute or join the assignee.",
  },
  {
    id: "SET-115",
    // 1.0.1 — written as a synonym OR, but the warranty and its subject are distinct pillars; `represent` alone matches inside "representatives". The check could not
    // fire on any realistic document.
    ver: "1.1.0",
    name: "Warranties as to title and collectability",
    cite: practice("claim-warranties", "title and collectability warranties in claim assignments"),
    pat: [
      /(warrant|represent)/i,
      // The title warranty is written as a VERB SERIES at least as often as a
      // noun phrase: "Assignor is the SOLE LEGAL AND BENEFICIAL OWNER of the
      // Claim and HAS NOT SOLD, ASSIGNED, PLEDGED, OR ENCUMBERED it". The
      // noun-only pillar read a paragraph that warrants exactly this as
      // warranting nothing about title.
      /(title\s+to\s+the\s+claim|free\s+(and\s+clear\s+)?of|no\s+(prior\s+)?(assignment|encumbrance)|makes?\s+no\s+(warranty|representation)\s+(as\s+to|regarding)\s+collect|sole\s+(?:legal\s+(?:and\s+beneficial\s+)?)?(?:and\s+beneficial\s+)?owner|(?:has\s+)?not\s+(?:[\w,]+\s+){0,4}?(?:sold|assigned|pledged|encumbered|transferred)\b)/i,
    ],
    all: true,
    why: "The assignee needs to know it is buying an unencumbered claim, and the assignor needs to be clear it is not guaranteeing recovery. Both directions must be stated.",
    fix: "Warrant title, no prior assignment, and no release of the claim, and disclaim any warranty of collectability or outcome.",
  },
]);

const PROTECTIVE_ORDER = pack("protective-order-stipulated", C, [
  {
    id: "SET-116",
    name: "Tiers of designation and their criteria",
    cite: frcp("26(c)", "protective orders"),
    pat: [
      /confidential/i,
      /(attorneys['’]?\s+eyes\s+only|highly\s+confidential|outside\s+counsel\s+only|tier)/i,
    ],
    why: "Rule 26(c) requires good cause for each protection. Undifferentiated 'confidential' designation over everything is what draws judicial criticism and sua sponte narrowing of the order.",
    fix: "Define each tier with the category of information it covers and the good-cause basis, and state that designation must be made in good faith after review.",
    sev: "critical",
  },
  {
    id: "SET-117",
    name: "Designation and de-designation procedure",
    cite: frcp("26(c)", "protective orders — procedure"),
    pat: [
      /designat/i,
      /(stamp|legend|at\s+the\s+time\s+of\s+production|within\s+\d+\s+days|de-?designat|withdraw\s+(a\s+)?designation)/i,
    ],
    why: "Documents get produced faster than they get reviewed. The order needs a mechanism for late designation of inadvertently unmarked material and for deposition-transcript designation windows.",
    fix: "State how material is designated, the window for designating deposition testimony, and the procedure for correcting an omitted designation.",
  },
  {
    id: "SET-118",
    name: "Challenge procedure with the burden on the designator",
    cite: frcp("26(c)(1)", "protective orders — burden on the party seeking protection"),
    pat: [
      /(challeng|object\s+to\s+(the\s+|a\s+)?designation)/i,
      /(burden\s+(of\s+(persuasion|proof|establishing))?\s*(remains|rests|shall\s+be)\s+(on|with)\s+the\s+designating|meet\s+and\s+confer)/i,
    ],
    why: "Placing the burden on the challenger inverts Rule 26(c) and is a term many judges strike. Keeping the burden on the designating party is the correct and enforceable allocation.",
    fix: "Provide a meet-and-confer step, a motion deadline, and an express statement that the burden of establishing confidentiality remains on the designating party.",
    sev: "critical",
  },
  {
    id: "SET-119",
    name: "FRE 502(d) non-waiver order",
    cite: fre("502(d)", "controlling effect of a court order on privilege waiver"),
    pat: [
      /502\(d\)|rule\s+502/i,
      /(no\s+waiver|does\s+not\s+(constitute|effect)\s+a\s+waiver|clawback|inadvertent\s+(production|disclosure))/i,
    ],
    why: "A Rule 502(d) order is the only mechanism that protects against waiver in other federal and state proceedings, and it applies regardless of the care taken. Relying on 502(b) instead leaves waiver to a reasonableness fight.",
    fix: "Include an express Rule 502(d) order stating that production does not waive privilege in this or any other proceeding, with the clawback and sequestration procedure.",
    sev: "critical",
  },
  {
    id: "SET-120",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Filing under seal and public-access recital",
    cite: practice(
      "sealing",
      "the common-law and First Amendment right of access to judicial records",
    ),
    pat: [
      /(under\s+seal|sealing)/i,
      /(local\s+rule|motion\s+to\s+seal|public[-\s]+(access|right)|the\s+court\s+(will|shall)\s+determine)/i,
    ],
    why: "A stipulated order cannot itself authorize sealing; courts require a separate showing that overcomes the presumption of public access. Orders that assume automatic sealing get rejected.",
    fix: "State that designation does not entitle a party to file under seal, and describe the local-rule motion required for each sealing request.",
  },
  {
    id: "SET-121",
    name: "Permitted disclosure list and acknowledgments",
    cite: frcp(
      "26(c)(1)(G)",
      "protective orders — limits on disclosure of confidential information",
    ),
    pat: [
      /(may\s+be\s+disclosed\s+(only\s+)?to|permitted\s+(persons|recipients)|access\s+(is\s+)?limited)/i,
      /(acknowledg|exhibit\s+[a-z]|agree\s+to\s+be\s+bound|undertaking)/i,
    ],
    why: "The order binds only those who agree to be bound. Experts, consultants, and vendors need to sign the acknowledgment or they are outside the court's contempt power.",
    fix: "List the categories permitted access and attach an acknowledgment form each non-party recipient must sign before receiving protected material.",
  },
  {
    id: "SET-122",
    name: "Post-litigation return or destruction",
    cite: practice("po-return", "return or destruction obligations at the end of litigation"),
    pat: [
      /(return\s+or\s+destroy|destruction)/i,
      /(within\s+\d+\s+days\s+(of|after)\s+(the\s+)?(final|conclusion|termination)|certif)/i,
    ],
    why: "Without a wind-down obligation, protected material stays in vendor systems and former experts' files indefinitely, and the order's protections outlive anyone's ability to enforce them.",
    fix: "Require return or certified destruction within a stated period after final disposition, with the usual carve-outs for work product, archival backups, and court filings.",
  },
]);

const ARB_DEMAND = pack("arbitration-demand", C, [
  {
    id: "SET-123",
    name: "Arbitration clause quoted and located",
    cite: standardForm(
      "AAA Commercial Arbitration Rules",
      "R-4 filing requirements for a demand for arbitration",
      "https://www.adr.org/Rules",
    ),
    pat: [
      /(arbitration\s+(clause|provision|agreement))/i,
      /(section\s+\d|§|quoted|provides\s+as\s+follows|attached)/i,
    ],
    why: "The administrator will not proceed without the arbitration agreement, and the respondent's first move is usually to contest arbitrability. Quoting the clause frames that fight from the outset.",
    fix: "Quote the arbitration clause in full, identify the agreement and section it comes from, and attach the agreement.",
    sev: "critical",
  },
  {
    id: "SET-124",
    name: "Nature of the dispute and claims asserted",
    cite: standardForm(
      "AAA Commercial Arbitration Rules",
      "R-4(a) statement of the nature of the dispute",
      "https://www.adr.org/Rules",
    ),
    pat: [
      /(nature\s+of\s+the\s+dispute|statement\s+of\s+(the\s+)?claim)/i,
      /(breach|claim\s+for|alleges|counts?)/i,
    ],
    why: "The demand frames the scope of the arbitrator's authority. Claims omitted from it can require amendment and, after the panel is appointed, the arbitrator's consent.",
    fix: "State the facts and each legal claim asserted with enough specificity to define the scope of the proceeding.",
  },
  {
    id: "SET-125",
    name: "Relief and amount in controversy",
    cite: standardForm(
      "AAA Commercial Arbitration Rules",
      "R-4(a) statement of the amount involved and the remedy sought",
      "https://www.adr.org/Rules",
    ),
    pat: [
      /(relief\s+sought|remedy|amount\s+(in\s+controversy|claimed))/i,
      /(\$|damages|specific\s+performance|declaratory|interest|fees)/i,
    ],
    why: "The claimed amount sets the administrative fee tier and, under expedited rules, whether the case is heard on documents or by a panel.",
    fix: "State the relief sought and the amount in controversy, or state that the amount is undetermined and why.",
  },
  {
    id: "SET-126",
    name: "Locale, seat, and governing rules",
    cite: standardForm(
      "AAA Commercial Arbitration Rules",
      "R-11 fixing of locale",
      "https://www.adr.org/Rules",
    ),
    pat: [
      /(locale|seat\s+of\s+(the\s+)?arbitration|hearing\s+location)/i,
      /(aaa|jams|commercial\s+arbitration\s+rules|employment\s+rules|governing\s+rules)/i,
    ],
    why: "If the clause fixes no locale, the administrator decides it, and a wrong-locale filing costs time and fees. The applicable rule set also determines discovery and arbitrator count.",
    fix: "State the locale from the clause (or propose one), name the administrator and the specific rule set invoked, and state the number of arbitrators.",
  },
  {
    id: "SET-127",
    name: "Service on the respondent and filing fee",
    cite: standardForm(
      "AAA Commercial Arbitration Rules",
      "R-4(b)-(c) filing and service of the demand",
      "https://www.adr.org/Rules",
    ),
    pat: [
      /(serv(e|ice|ed)\s+(on|upon))/i,
      /(filing\s+fee|administrative\s+fee|copy\s+to\s+the\s+respondent|certificate\s+of\s+service)/i,
    ],
    why: "The demand must be filed with the administrator and served on the respondent, and the filing fee must accompany it. Defective service is the most common reason a demand is not docketed.",
    fix: "State the method and date of service on the respondent, attach the certificate of service, and confirm payment of the filing fee.",
  },
]);

const EXPERT = pack("expert-witness-retention", C, [
  {
    id: "SET-128",
    name: "Testifying or consulting designation",
    cite: frcp(
      "26(b)(4)(D)",
      "trial preparation — experts retained in anticipation of litigation who will not testify",
    ),
    pat: [
      /(testifying\s+expert|consulting\s+expert|non-?testifying)/i,
      /(designat|retained\s+(as|solely)|may\s+later\s+be\s+designated)/i,
    ],
    why: "A consulting expert's work is protected from discovery absent exceptional circumstances; a testifying expert's opinions and the facts considered are discoverable. Converting one to the other mid-case waives the protection.",
    fix: "State the designation, the process for converting a consultant to a testifying expert, and the consequences for previously protected work.",
    sev: "critical",
  },
  {
    id: "SET-129",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Rule 26(b)(4) draft-report and communication protection",
    cite: frcp("26(b)(4)(B)", "trial preparation — protection of draft reports and disclosures"),
    pat: [
      /(draft[-\s]+(report|disclosure)|rule\s+26\(b\)\(4\))/i,
      /(protect|work[-\s]+product|communications\s+between\s+(the\s+)?(party['’]?s?\s+)?attorney\s+and\s+the\s+expert)/i,
    ],
    why: "The 2010 amendments protect draft reports and most attorney-expert communications, with three exceptions (compensation, facts or data provided that the expert considered, and assumptions supplied). Experts who do not know the exceptions create discoverable material.",
    fix: "Recite the Rule 26(b)(4)(B)-(C) protections and the three exceptions, and instruct the expert on document retention accordingly.",
  },
  {
    id: "SET-130",
    name: "Independence and no-contingent-fee recital",
    cite: modelRule("3.4(b)", "fairness to opposing party and counsel — inducements to a witness"),
    pat: [
      /(independent|own\s+(opinions|professional\s+judgment)|not\s+contingent)/i,
      /(outcome\s+of\s+the\s+(case|litigation)|contingen|regardless\s+of\s+the\s+result)/i,
    ],
    why: "A fee contingent on the outcome is improper for an expert in every US jurisdiction and is the first line of cross-examination. The recital is both an ethics safeguard and a credibility protection.",
    fix: "State that compensation is not contingent on the outcome or the content of the opinion, and that the expert's opinions are their own independent professional judgment.",
    sev: "critical",
  },
  {
    id: "SET-131",
    name: "Rates, retainer, and deposition-fee responsibility",
    cite: frcp("26(b)(4)(E)", "payment of expert fees by the party seeking discovery"),
    pat: [
      /(hourly\s+rate|fees?\s+(of|for)\s+\$|retainer)/i,
      /(deposition|the\s+party\s+(seeking|taking)|reasonable\s+fee)/i,
    ],
    why: "Rule 26(b)(4)(E) requires the party taking the deposition to pay the expert a reasonable fee. Whether the retaining party fronts it, and at what rate, needs to be agreed before the notice arrives.",
    fix: "State the hourly rates by activity, the retainer and replenishment terms, and who pays deposition and trial testimony time in the first instance.",
  },
  {
    id: "SET-132",
    name: "Document retention and return of case materials",
    cite: practice("expert-retention-docs", "document retention obligations of retained experts"),
    pat: [
      /(retain|preserve|document\s+retention)/i,
      /(return|destroy|at\s+the\s+conclusion|litigation\s+hold)/i,
    ],
    why: "The expert's file is discoverable to the extent it contains facts or data considered. Uncontrolled retention creates surprise exhibits; premature destruction creates spoliation.",
    fix: "State what the expert must retain, what it must not create, and the return or destruction obligation at the conclusion of the engagement, subject to any litigation hold.",
  },
]);

const STIP_DISMISSAL = pack("stipulation-of-dismissal", C, [
  {
    id: "SET-133",
    name: "Rule 41 basis and signatures of all appearing parties",
    cite: frcp("41(a)(1)(A)(ii)", "voluntary dismissal by stipulation"),
    pat: [
      /(rule\s+41|41\(a\))/i,
      /(all\s+(parties|counsel)\s+who\s+have\s+appeared|signed\s+by\s+all|stipulate)/i,
    ],
    why: "A Rule 41(a)(1)(A)(ii) stipulation must be signed by all parties who have appeared, and it is self-executing — no court order is needed. Missing one signature makes it ineffective.",
    fix: "Cite Rule 41(a)(1)(A)(ii) and obtain the signature of counsel for every party that has appeared.",
    sev: "critical",
  },
  {
    id: "SET-134",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "With- or without-prejudice election",
    cite: frcp("41(a)(1)(B)", "voluntary dismissal — effect"),
    pat: [/(with\s+prejudice|without[-\s]+prejudice)/i, /(dismiss)/i],
    all: true,
    why: "Rule 41(a)(1)(B) makes an unspecified dismissal without prejudice, and the two-dismissal rule can turn a second one into an adjudication on the merits. The election has to be conscious.",
    fix: "State expressly whether the dismissal is with or without prejudice, for each claim and each party.",
    sev: "critical",
  },
  {
    id: "SET-135",
    name: "Scope — which claims and which parties",
    cite: frcp("41(a)", "voluntary dismissal — scope"),
    pat: [
      /(all\s+claims|the\s+(entire\s+)?action|claims\s+against)/i,
      /(each\s+party|as\s+to\s+defendant|counterclaim|cross-?claim|remaining\s+claims)/i,
    ],
    why: "Partial dismissals leave counterclaims and cross-claims alive. A stipulation that does not name what survives leaves the docket ambiguous and finality uncertain for appeal.",
    fix: "State which claims and which parties are dismissed and confirm that nothing remains pending, or identify what does.",
  },
  {
    id: "SET-136",
    name: "Costs and attorneys' fees allocation",
    cite: frcp("54(d)", "costs and attorney's fees"),
    pat: [
      /(costs|attorneys['’]?\s+fees)/i,
      /(each\s+party\s+(to\s+)?bear|shall\s+bear\s+its\s+own|waive)/i,
    ],
    why: "Rule 54(d) presumes costs to the prevailing party. Silence in a stipulated dismissal invites a bill of costs after the case is supposedly over.",
    fix: "Add that each party bears its own costs and attorneys' fees, or state the agreed allocation.",
  },
  {
    id: "SET-137",
    name: "Retention of jurisdiction to enforce settlement",
    cite: practice(
      "kokkonen",
      "Kokkonen v. Guardian Life and the need for express retention of jurisdiction",
    ),
    pat: [
      /(retain(s|ed)?\s+jurisdiction|the\s+court\s+(shall|will)\s+retain)/i,
      /(enforce|settlement\s+agreement|for\s+the\s+purpose\s+of)/i,
    ],
    why: "Under Kokkonen, dismissal without retained jurisdiction leaves the court powerless to enforce the settlement; the remedy becomes a new contract suit, often in another forum.",
    fix: "Ask the court to retain jurisdiction to enforce the settlement for a stated period, or incorporate the settlement terms into the dismissal order.",
    sev: "critical",
  },
]);

const LIT_FUNDING = pack("litigation-funding-agreement", C, [
  {
    id: "SET-138",
    name: "No funder control over litigation or settlement",
    cite: modelRule(
      "5.4(c)",
      "professional independence of a lawyer — direction by a third-party payer",
    ),
    pat: [
      /(no\s+(right\s+to\s+)?control|shall\s+not\s+(control|direct|interfere))/i,
      /(litigation\s+(strategy|decisions)|settlement\s+(decisions|authority)|the\s+(claimant|client)\s+retains)/i,
    ],
    why: "Model Rule 5.4(c) forbids a third-party payer from directing the lawyer's professional judgment, and funder control is the leading ground for attacking a funding agreement as champertous or void.",
    fix: "State that all litigation and settlement decisions rest with the claimant on counsel's advice, and that the funder has no right to direct strategy or veto a settlement.",
    sev: "critical",
  },
  {
    id: "SET-139",
    name: "Proceeds waterfall and return cap",
    cite: practice(
      "funding-waterfall",
      "proceeds distribution and return multiples in litigation finance",
    ),
    pat: [
      /(waterfall|order\s+of\s+(distribution|priority)|proceeds\s+shall\s+be\s+(distributed|applied))/i,
      /(multiple|return|cap|first\s+to|then\s+to)/i,
    ],
    why: "A funding return that consumes the entire recovery is the industry's reputational problem and, in consumer cases, can be attacked as usurious or unconscionable. The waterfall must be modeled at signature.",
    fix: "State the distribution waterfall step by step, the funder's return formula and any cap, and include a worked example at two or three recovery levels.",
    sev: "critical",
  },
  {
    id: "SET-140",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Privilege and work-product protection",
    cite: fre("502", "attorney-client privilege and work product — limitations on waiver"),
    pat: [
      /(privileg|work[-\s]+product)/i,
      /(common\s+interest|shall\s+not\s+(waive|constitute\s+a\s+waiver)|confidential)/i,
    ],
    why: "Diligence materials shared with a funder are the standard target of a discovery motion. Most courts protect them as work product where a confidentiality or common-interest agreement exists; without one, the argument is much weaker.",
    fix: "State that materials are shared in confidence under a common-interest or work-product theory, that no waiver is intended, and require the funder to protect them.",
    sev: "critical",
  },
  {
    id: "SET-141",
    name: "Champerty, maintenance, and usury posture",
    cite: stateLaw(
      "champerty",
      "champerty, maintenance, and usury doctrines as applied to litigation funding",
      "https://www.law.cornell.edu/wex/champerty",
    ),
    pat: [
      /(champert|maintenance|usur)/i,
      /(non-?recourse|governing\s+law|permitted\s+in|not\s+a\s+loan)/i,
    ],
    why: "Non-recourse funding is generally outside usury law because repayment is contingent, and states differ sharply on champerty. Both are threshold defenses to any enforcement.",
    fix: "Recite the non-recourse character, the governing state's treatment of champerty and maintenance, and that the advance is not a loan.",
  },
  {
    id: "SET-142",
    name: "Disclosure obligations under local rules and standing orders",
    cite: frcp("7.1", "disclosure statement"),
    pat: [
      /disclos/i,
      /(local\s+rule|standing\s+order|court\s+order|third-?party\s+funding|shall\s+cooperate\s+in\s+(any\s+)?disclosure)/i,
    ],
    why: "The District of New Jersey and the District of Delaware require disclosure of litigation funding by standing rule, and other courts order it case by case. The agreement should not obstruct compliance.",
    fix: "Require the parties to cooperate with any court-ordered or rule-required disclosure, and state what may be disclosed without breaching confidentiality.",
  },
  {
    id: "SET-143",
    name: "Termination, budget overrun, and case-abandonment terms",
    cite: practice(
      "funding-termination",
      "termination and budget provisions in litigation funding",
    ),
    pat: [
      /(terminat|withdraw)/i,
      /(budget|overrun|additional\s+(funding|tranche)|abandon|no\s+further\s+obligation)/i,
    ],
    why: "A funder that can stop funding mid-case leaves the claimant unable to finish. What happens to the funder's return, and to counsel's fees, when funding stops has to be settled in advance.",
    fix: "State the budget, the process for approving overruns, each party's termination rights, and the funder's entitlement (if any) if it stops funding before resolution.",
  },
]);

export const V5_SETTLEMENT_RULES: readonly Rule[] = [
  ...CONSENT_JUDGMENT,
  ...COVENANT,
  ...ASSIGNMENT_OF_CLAIM,
  ...PROTECTIVE_ORDER,
  ...ARB_DEMAND,
  ...EXPERT,
  ...STIP_DISMISSAL,
  ...LIT_FUNDING,
];
