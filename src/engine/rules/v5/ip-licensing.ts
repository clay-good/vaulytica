/**
 * v5 sub-domain H′ — US IP transfers, coexistence, collaboration, and
 * escrow (spec-v45.md §6.H). Rule ids continue the IPL namespace at 101.
 */

import type { Rule } from "../../finding.js";
import { DATE_SHAPE } from "../../../extract/dates.js";
import { pack } from "./_pack.js";
import { cfr, expressDenial, practice, usc } from "./_helpers.js";

const C = "ip-licensing";

const PATENT_ASSIGNMENT = pack("patent-assignment", C, [
  {
    id: "IPL-101",
    name: "Patents and applications listed by number",
    cite: usc("35", "261", "Patents — ownership and assignment"),
    pat: [
      /(patent\s+(no|number)|application\s+(no|number|serial)|u\.?s\.?\s*\d{1,2},?\d{3},?\d{3})/i,
      /(schedule|exhibit|annexure|annex|appendix|listed|set\s+forth)/i,
    ],
    why: "The USPTO records assignments against identified property. An assignment of 'all patents' with no schedule cannot be recorded and leaves the chain of title broken for every later transaction.",
    fix: "Attach a schedule listing each patent and application by number, title, filing date, and country.",
    sev: "critical",
  },
  {
    id: "IPL-102",
    name: "Continuations, divisionals, and foreign counterparts",
    cite: usc("35", "120", "Benefit of earlier filing date in the United States"),
    pat: [
      /(continuation|divisional|continuation-?in-?part|cip)/i,
      /(reissue|reexamination|foreign\s+counterpart|pct|any\s+patents?\s+claiming\s+priority)/i,
    ],
    why: "A bare assignment of an issued patent does not carry the pending continuation or the foreign family. Buyers discover the gap when they try to enforce the child patent.",
    fix: "Assign the listed patents together with all continuations, divisionals, CIPs, reissues, reexaminations, and foreign counterparts claiming priority to them.",
    sev: "critical",
  },
  {
    id: "IPL-103",
    // 1.0.1 — written as a synonym OR, but the USPTO addressee and the recordation authorization are distinct pillars; `authoriz` alone is satisfied by "authorized representatives". The check could not
    // fire on any realistic document.
    ver: "1.0.1",
    name: "Recordation authorization to the USPTO",
    cite: cfr("37", "3.11", "Recording of assignments and other documents affecting title"),
    pat: [
      /(commissioner\s+for\s+patents|united\s+states\s+patent\s+and\s+trademark\s+office|uspto)/i,
      /(record|authori[sz]|is\s+hereby\s+(requested|directed)\s+to)/i,
    ],
    all: true,
    why: "Under 35 U.S.C. § 261 an unrecorded assignment is void against a subsequent bona fide purchaser without notice who records first. Recordation within three months protects priority.",
    fix: "Authorize and direct the Commissioner for Patents to record the assignment, and commit the assignee to record promptly.",
  },
  {
    id: "IPL-104",
    ver: "1.1.0",
    name: "Nunc pro tunc effective date",
    cite: practice(
      "nunc-pro-tunc",
      "retroactive effective dates in patent assignments and standing to sue",
    ),
    pat: [
      /(effective\s+(as\s+of|date)|nunc\s+pro\s+tunc)/i,
      // Retroactivity in SUBSTANCE, not only as the word. A patent assignment
      // writes it as the reach-back itself: "effective as of the earlier of the
      // date of execution and the date each Assignor conceived or first reduced
      // the inventions to practice". Under the conjunction below, reading only
      // "retroactive" and a literal date would have reported that assignment —
      // whose effective date reaches back to conception — as having none.
      new RegExp(
        `(as\\s+of\\s+${DATE_SHAPE}|retroactive(?:ly)?|nunc\\s+pro\\s+tunc|confirms\\s+the\\s+(prior|earlier)|earlier\\s+of|first\\s+reduced\\s+(?:the\\s+\\w+\\s+)?to\\s+practice|date\\s+of\\s+conception|prior\\s+to\\s+the\\s+date\\s+of\\s+this)`,
        "i",
      ),
    ],
    // `all: true`. The retroactivity pillar is a bare date — "as of January 5,
    // 2026" — which every executed instrument carries, so a nunc pro tunc
    // column was satisfied by the assignment's own preamble.
    all: true,
    why: "Federal Circuit law requires the plaintiff to hold title when suit is filed; a nunc pro tunc assignment executed after filing does not cure the standing defect. The effective date matters more here than in almost any other instrument.",
    fix: "State the effective date and, where the assignment confirms an earlier transfer, recite the original transfer and its date rather than relying on retroactivity alone.",
  },
  {
    id: "IPL-105",
    name: "Further assurances and power of attorney",
    cite: cfr("37", "3.73", "Establishing right of assignee to take action"),
    pat: [
      /further\s+assurances?/i,
      /(power\s+of\s+attorney|execute\s+(any\s+)?(further|additional)\s+(documents|instruments)|cooperate\s+in\s+(the\s+)?prosecution)/i,
    ],
    why: "Prosecution and foreign recordation need inventor and assignor signatures for years after closing. A cooperation covenant plus a limited power of attorney is what keeps the family alive if the assignor becomes unreachable.",
    fix: "Add a further-assurances covenant covering prosecution, enforcement, and foreign recordation, backed by a limited power of attorney.",
  },
]);

const TRADEMARK_ASSIGNMENT = pack("trademark-assignment", C, [
  {
    id: "IPL-106",
    name: "Marks and registrations listed",
    cite: usc("15", "1060", "Lanham Act § 10 — assignment of marks"),
    pat: [
      /(registration\s+(no|number)|serial\s+(no|number)|reg\.?\s*no)/i,
      /(schedule|exhibit|annexure|annex|appendix|listed|the\s+assigned\s+marks)/i,
    ],
    why: "USPTO recordation requires identification of each mark by registration or serial number. Unlisted common-law marks do not transfer with the registrations.",
    fix: "Attach a schedule listing each mark with its registration or serial number, class, and jurisdiction, and expressly include the associated common-law rights.",
    sev: "critical",
  },
  {
    id: "IPL-107",
    name: "Goodwill expressly assigned",
    cite: usc("15", "1060", "Lanham Act § 10 — assignment with the goodwill of the business"),
    pat: [
      /goodwill/i,
      /(together\s+with|of\s+the\s+business\s+(symboli[sz]ed|connected)|and\s+the\s+goodwill)/i,
    ],
    why: "§ 1060(a)(1) permits assignment only with the goodwill of the business. An assignment in gross — without goodwill — is invalid and can destroy the mark.",
    fix: 'Assign the marks "together with the goodwill of the business symbolized by the marks," and identify the business or product line transferred with them.',
    sev: "critical",
  },
  {
    id: "IPL-108",
    name: "Intent-to-use restriction respected",
    cite: usc(
      "15",
      "1060",
      "Lanham Act § 10(a)(1) — restriction on assignment of intent-to-use applications",
    ),
    pat: [
      /(intent-?to-?use|section\s+1\(b\)|1\(b\)\s+application)/i,
      /(ongoing\s+and\s+existing\s+business|successor\s+to\s+the\s+business|statement\s+of\s+use|not\s+assignable)/i,
    ],
    why: "An intent-to-use application may not be assigned before an amendment or statement of use, except to a successor to the ongoing business to which the mark pertains. A defective assignment voids the application.",
    fix: "Identify any intent-to-use applications and either exclude them or recite that the assignee is the successor to the ongoing and existing business to which the mark pertains.",
    when: [/(intent-?to-?use|section\s+1\(b\)|1\(b\)\s+application|allegation\s+of\s+use)/i],
    sev: "critical",
  },
  {
    id: "IPL-109",
    // 1.0.1 — written as a synonym OR, but the USPTO addressee and the recordation authorization are distinct pillars; `authoriz` alone is satisfied by "authorized representatives". The check could not
    // fire on any realistic document.
    ver: "1.0.1",
    name: "Recordation authorization",
    cite: cfr("37", "3.11", "Recording of assignments and other documents affecting title"),
    pat: [
      /(united\s+states\s+patent\s+and\s+trademark\s+office|uspto|commissioner\s+for\s+trademarks)/i,
      /(record|authori[sz]|is\s+hereby\s+(requested|directed))/i,
    ],
    all: true,
    why: "An unrecorded trademark assignment is void against a subsequent purchaser for value without notice who records first, under the same three-month rule as patents.",
    fix: "Authorize recordation with the USPTO and any foreign registries, and allocate the recordation costs.",
  },
  {
    id: "IPL-110",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Quality-control transition and phase-out license",
    cite: usc("15", "1055", "Lanham Act § 5 — use by related companies"),
    pat: [
      /(quality[-\s]+control|standards\s+of\s+quality)/i,
      /(transition|phase-?out|wind-?down|licen[cs]e\s+back|sell-?off\s+period)/i,
    ],
    why: "The assignor usually keeps selling branded inventory after closing. Without a short license back with quality control, that use is infringing and can support a naked-licensing attack on the mark.",
    fix: "Grant a limited, quality-controlled phase-out license for existing inventory and materials, with a stated end date and no right to produce new goods.",
  },
]);

const COEXISTENCE = pack("trademark-coexistence-agreement", C, [
  {
    id: "IPL-111",
    name: "Goods and services boundary for each party",
    cite: usc("15", "1052", "Lanham Act § 2(d) — refusal on the ground of likelihood of confusion"),
    pat: [
      /(goods\s+and\s+services|class\s+\d|international\s+class)/i,
      /((?:shall|will|must)\s+(only\s+)?use|limited\s+to|(?:shall|will|must)\s+not\s+use\s+the\s+mark\s+(on|for))/i,
    ],
    why: "A coexistence agreement works only if each party's lane is drawn precisely. The TTAB and examining attorneys give weight to consent agreements that show the parties actually addressed confusion, not merely consented.",
    fix: "State each party's permitted goods and services by class and description, and the goods each may not use its mark on.",
    sev: "critical",
  },
  {
    id: "IPL-112",
    // 1.0.1 — written as a synonym OR, but the geographic limit and the channel limit are distinct pillars; `states? of` alone is satisfied by any governing-law clause. The check could not
    // fire on any realistic document.
    ver: "1.0.1",
    name: "Geographic and channel limits",
    cite: practice(
      "coexistence-geography",
      "geographic and trade-channel limits in coexistence agreements",
    ),
    pat: [
      /(territory|geographic|region|states?\s+of)/i,
      /(channels?\s+of\s+trade|retail|online|distribution)/i,
    ],
    all: true,
    why: "Coexistence built only on goods breaks down online, where every party's channel is the same. Channel and geographic limits are what make the arrangement durable.",
    fix: "State the geographic areas and trade channels each party may use, and address internet use expressly.",
  },
  {
    id: "IPL-113",
    // 1.0.1 — neither pattern could read the clause as it is actually
    // drafted. The consent names the other party before it names the thing
    // consented to ("consents to Cellars' use and registration of the
    // Cellars Mark"), and the covenant is written with "will not", not
    // "shall not". A coexistence agreement whose sole operative section is
    // the consent was told, at `critical`, that it contained no consent.
    ver: "1.0.1",
    name: "Consent to registration and non-opposition",
    cite: usc("15", "1052", "Lanham Act § 2(d) — consent agreements"),
    pat: [
      /consents?\s+to\b[^.;]{0,60}?\b(registration|register|use)\b/i,
      /((?:shall|will|does|do|may|must)\s+not\s+(?:oppose|petition|challenge|contest|seek\s+to\s+cancel)|(?:agrees?|covenants?|undertakes?)\s+not\s+to\s+(?:oppose|petition|challenge|contest|sue)|non-?opposition|covenant\s+not\s+to\s+(?:challenge|oppose|sue))/i,
    ],
    why: "The consent is the operative deliverable for overcoming a § 2(d) refusal, and the covenant not to oppose or cancel is what buys peace for the life of the marks.",
    fix: "Include an express consent to the other party's use and registration for the agreed goods, and a covenant not to oppose or petition to cancel.",
    sev: "critical",
  },
  {
    id: "IPL-114",
    name: "Confusion-avoidance and complaint procedure",
    cite: practice(
      "coexistence-confusion",
      "confusion-avoidance measures in coexistence agreements",
    ),
    pat: [
      /(confusion)/i,
      /((?:shall|will|must)\s+(notify|cooperate|take\s+(reasonable\s+)?steps)|disclaimer|misdirected\s+(inquiries|orders)|distinguish)/i,
    ],
    why: "The TTAB looks for evidence that the parties considered and provided for actual confusion. A procedure for handling misdirected inquiries is both practical and persuasive.",
    fix: "Require cooperation to minimize confusion — distinguishing trade dress, disclaimers where needed, and a procedure for forwarding misdirected inquiries and addressing reported confusion.",
  },
  {
    id: "IPL-115",
    // 1.0.1 — written as a synonym OR, but the term and the successor binding are distinct pillars; `term` alone matches inside "terms". The check could not
    // fire on any realistic document.
    ver: "1.0.1",
    name: "Term, assignability, and successor binding",
    cite: practice("coexistence-term", "duration and successor binding in coexistence agreements"),
    pat: [
      /(term|perpetual|(?:shall|will|must)\s+continue)/i,
      /(successors?\s+and\s+assigns|binding\s+upon|assignment\s+of\s+the\s+marks)/i,
    ],
    all: true,
    why: "Marks change hands. A coexistence agreement that does not bind successors evaporates the first time either mark is sold, which is exactly when the risk returns.",
    fix: "State the term (usually perpetual), bind successors and assigns, and require any assignee of a mark to assume the agreement in writing.",
  },
]);

const JDA = pack("joint-development-agreement", C, [
  {
    id: "IPL-116",
    ver: "1.1.0",
    name: "Background IP identified and licensed",
    cite: practice("background-ip", "background IP identification in collaboration agreements"),
    pat: [
      /background\s+(ip|intellectual\s+property|technology)/i,
      /(identified|listed|schedule|licen[cs]e\s+to\s+use)/i,
    ],
    // `all: true`. "Identified" alone matched "the parties identified on the
    // signature page", so an agreement that never mentions background IP
    // satisfied the column that exists to find it.
    all: true,
    why: "Foreground IP is usually unusable without a license to the background it builds on. Undocumented background is the reason many collaborations produce results neither party can commercialize.",
    fix: "Schedule each party's background IP and grant the licenses the project and the commercialization of its results require.",
    sev: "critical",
  },
  {
    id: "IPL-117",
    name: "Foreground and joint IP ownership rule",
    cite: practice("foreground-ip", "ownership allocation of jointly developed IP"),
    pat: [
      /(foreground|developed\s+(under|in\s+the\s+course\s+of)\s+(this\s+)?(agreement|project)|project\s+ip)/i,
      /((?:shall|will|must)\s+(be\s+)?own(ed)?|title\s+to|jointly\s+owned|sole(ly)?\s+owned)/i,
    ],
    why: "Ownership by inventorship is the default and it produces unpredictable results — the allocation follows who happened to conceive what, not who paid or who needs it.",
    fix: "State the ownership rule for foreground IP (by field, by contribution, or joint), and align it with each party's commercialization needs.",
    sev: "critical",
  },
  {
    id: "IPL-118",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Section 262 joint-owner default addressed",
    cite: usc("35", "262", "Joint owners of patents"),
    pat: [
      /(joint(ly)?[-\s]+own|co-?owner)/i,
      /(262|without\s+the\s+consent\s+of|accounting\s+to\s+the\s+other|may\s+(not\s+)?licen[cs]e\s+independently)/i,
    ],
    why: "Under 35 U.S.C. § 262 each joint owner may make, use, and license the patent without the other's consent and without accounting — which usually destroys the exclusivity both parties assumed.",
    fix: "Override the § 262 default expressly: state whether independent licensing is permitted, whether consent is required, and whether an accounting is owed.",
    when: [/(joint(ly)?\s+own|co-?owner|joint\s+invention)/i],
    sev: "critical",
  },
  {
    id: "IPL-119",
    name: "Prosecution and enforcement control",
    cite: practice(
      "prosecution-control",
      "patent prosecution and enforcement control in collaborations",
    ),
    pat: [
      /(prosecut(e|ion)|file\s+(patent\s+)?applications?)/i,
      /(enforce|infringement\s+action|first\s+right|step\s+in|costs\s+of\s+prosecution)/i,
    ],
    why: "Joint owners are usually indispensable parties to an infringement suit, so a co-owner who refuses to join can block enforcement entirely. Control and joinder must be settled in advance.",
    fix: "Assign prosecution control and cost-sharing, give one party a first right to enforce with a step-in right for the other, and obtain an advance covenant to join as a party where required.",
  },
  {
    id: "IPL-120",
    name: "Publication review and delay period",
    cite: practice("publication-review", "publication review windows in research collaborations"),
    pat: [
      /publi(sh|cation)/i,
      /(review|delay|\d+\s*\)?\s*days\s+(prior|before)|remove\s+confidential|defer\s+publication)/i,
    ],
    why: "Publication before filing destroys foreign patent rights and starts the US grace period running. A short review-and-delay window is the standard reconciliation of academic and commercial interests.",
    fix: "Require pre-submission review with a stated period, a short delay to permit filing, and the right to remove the reviewing party's confidential information.",
  },
  {
    id: "IPL-121",
    name: "Exclusivity and field-of-use limits",
    cite: practice("jda-exclusivity", "exclusivity and field limits in joint development"),
    pat: [
      /exclusiv/i,
      /(field\s+of\s+use|(?:shall|will|must)\s+not\s+(develop|engage|work\s+with)|competing\s+(programme?|product)|during\s+the\s+term)/i,
    ],
    why: "Collaboration exclusivity is an antitrust-sensitive restraint between potential competitors and a serious commercial commitment. Both call for a bounded field and duration.",
    fix: "State the exclusive field and its duration, and confirm what each party remains free to do outside it.",
  },
]);

const TECH_TRANSFER = pack("technology-transfer-agreement", C, [
  {
    id: "IPL-122",
    name: "Licensed patents and field of use",
    cite: practice("license-scope", "field-of-use and territory scoping in university licenses"),
    pat: [
      /licensed\s+(patents?|technology|products?)/i,
      /(field\s+of\s+use|territory|exclusive|non-?exclusive|sublicen[cs]e)/i,
    ],
    why: "University licenses are almost always field-limited, and the field definition determines what the licensee can build and what the university can license to the next company.",
    fix: "Define the licensed patents, the licensed products, the field of use, the territory, and the exclusivity and sublicensing rights.",
    sev: "critical",
  },
  {
    id: "IPL-123",
    name: "Government license and march-in reservation",
    cite: usc("35", "202", "Bayh-Dole — disposition of rights in federally funded inventions"),
    pat: [
      /(government|federal(ly)?\s+(funded|sponsored))/i,
      /(bayh-?dole|march-?in|non-?exclusive,?\s+non-?transferable,?\s+irrevocable,?\s+paid-?up\s+licen[cs]e|35\s+u\.?s\.?c\.?\s*§?\s*20\d)/i,
    ],
    why: "For federally funded inventions the government holds a paid-up worldwide license and march-in rights under §§ 202(c)(4) and 203. A license that does not disclose them promises exclusivity the university cannot give.",
    fix: "Recite the government's retained license and march-in rights and make the license subject to them.",
    sev: "critical",
  },
  {
    id: "IPL-124",
    name: "US-manufacturing preference",
    cite: usc("35", "204", "Bayh-Dole — preference for United States industry"),
    pat: [
      /(substantially\s+manufactured\s+in\s+the\s+united\s+states|u\.?s\.?\s+manufactur)/i,
      /(204|preference|waiver|exclusive\s+right\s+to\s+use\s+or\s+sell)/i,
    ],
    why: "§ 204 bars an exclusive licensee from granting the right to use or sell in the US unless products will be substantially manufactured in the US. Waivers exist but must be sought from the funding agency.",
    fix: "Include the § 204 US-manufacturing covenant for exclusive US rights, and describe the waiver process if offshore manufacture is contemplated.",
    when: [/(bayh-?dole|federal(ly)?\s+(funded|sponsored)|government\s+(funding|support|rights))/i],
  },
  {
    id: "IPL-125",
    name: "Diligence milestones and termination for failure",
    cite: usc(
      "35",
      "203",
      "Bayh-Dole — march-in rights for failure to achieve practical application",
    ),
    pat: [
      /(diligence|milestone)/i,
      /(fail(ure)?\s+to\s+(meet|achieve)|terminate|convert\s+to\s+non-?exclusive|by\s+\w+\s+\d{4})/i,
    ],
    why: "Universities must ensure practical application or face march-in exposure, so diligence milestones with real consequences are non-negotiable in an exclusive license.",
    fix: "Set dated development and commercialization milestones, and state the consequence of missing them (cure period, conversion to non-exclusive, or termination).",
  },
  {
    id: "IPL-126",
    name: "Royalties, sublicense income, and reporting",
    cite: practice(
      "royalty-reporting",
      "royalty and sublicense income terms in university licenses",
    ),
    pat: [
      /(royalt|licen[cs]e\s+fee|milestone\s+payment)/i,
      /(sublicen[cs]e\s+(income|revenue)|net\s+sales|report|minimum\s+annual)/i,
    ],
    why: "Net sales definitions and sublicense income sharing are where the economics actually live, and university templates often define net sales more broadly than a licensee expects.",
    fix: "Define net sales with its permitted deductions, state the royalty rate, sublicense income share, minimum annual royalties, and the reporting and payment schedule.",
  },
  {
    id: "IPL-127",
    name: "Publication and academic-use reservation",
    cite: practice(
      "academic-reservation",
      "reserved academic and research rights in university licenses",
    ),
    pat: [
      /(publish|publication)/i,
      /(reserv|academic|research\s+(and\s+educational\s+)?purposes|non-?commercial\s+(research|use)|other\s+(non-?profit|academic)\s+institutions)/i,
    ],
    why: "Universities reserve the right to publish and to use the technology for research, and often to license other non-profits. A licensee that does not know the scope of the reservation is buying less exclusivity than it thinks.",
    fix: "State the reserved academic and research rights, whether they extend to other non-profit institutions, and the publication review window.",
  },
  {
    id: "IPL-128",
    // 1.1.0 — an express disclaimer of this column is now reported as a
    // disclaimer rather than read as compliance (`v5/_pack.ts`, `denied`).
    ver: "1.1.0",
    name: "Indemnity and insurance from the licensee",
    cite: practice(
      "university-indemnity",
      "indemnity and insurance requirements in university licenses",
    ),
    pat: [
      /indemnif/i,
      /(insur(e|ance)|product\s+liability|name\s+the\s+university\s+as\s+an\s+additional[-\s]+insured|[$€£¥₹₩₽]\d)/i,
    ],
    why: "The university transfers the product-liability risk entirely; the indemnity and the insurance requirement, with stated limits triggered at first commercial sale, are always in the template.",
    fix: "Provide a broad indemnity in favor of the university, its trustees, and its inventors, backed by product-liability insurance at stated limits naming them as additional insureds.",
    denied: expressDenial(
      String.raw`(?:commercial\s+general\s+liability|product\s+liability|liability)\s+insurance`,
    ),
  },
]);

const ESCROW = pack("source-code-escrow-agreement", C, [
  {
    id: "IPL-129",
    name: "Deposit contents and update cadence",
    cite: practice(
      "escrow-deposit",
      "deposit contents and update obligations in technology escrow",
    ),
    pat: [
      /deposit\s+material/i,
      /(build\s+(scripts|instructions)|documentation|update|each\s+(release|version)|quarterly|annually)/i,
    ],
    all: true,
    why: "An escrow of source code alone is usually not buildable. Build scripts, third-party dependency lists, credentials, and documentation are what make a release useful — and they are what is most often missing.",
    fix: "Enumerate the deposit contents (source, build environment, dependencies, documentation, keys) and require an update on each major release and at least annually.",
    sev: "critical",
  },
  {
    id: "IPL-130",
    name: "Verification and integrity testing rights",
    cite: practice("escrow-verification", "verification services in technology escrow"),
    pat: [
      /verif/i,
      /(integrity|compil|build\s+test|escrow\s+agent\s+((?:shall|will|must)|may)\s+(verify|test)|beneficiary\s+may\s+request)/i,
    ],
    why: "Unverified deposits fail at release more often than they succeed. Verification is the only thing that turns an escrow from a comfort item into a working continuity plan.",
    fix: "Give the beneficiary the right to request verification at stated intervals, describe the verification level, and allocate the cost.",
  },
  {
    id: "IPL-131",
    name: "Release conditions and dispute procedure",
    cite: practice(
      "escrow-release",
      "release conditions and dispute resolution in escrow agreements",
    ),
    pat: [
      /release\s+(condition|event)/i,
      /(bankrupt|insolven|ceases?\s+to\s+(support|do\s+business)|material\s+breach|dispute|objection\s+within\s+\d+\s*\)?\s*days)/i,
    ],
    why: "The depositor almost always objects to a release demand. Without a defined objection window and a fast adjudication, the escrow agent will interplead and the beneficiary waits months.",
    fix: "Define the release conditions objectively, set the demand and objection windows, and provide expedited arbitration of any dispute with the agent's duties fixed in the interim.",
    sev: "critical",
  },
  {
    id: "IPL-132",
    name: "Section 365(n) election preserved",
    cite: usc(
      "11",
      "365",
      "Bankruptcy Code § 365(n) — rejection of a contract under which the debtor is a licensor of intellectual property",
    ),
    pat: [
      /365\(n\)|section\s+365/i,
      /(bankrupt|supplementary\s+agreement|elect\s+to\s+retain|embodiment\s+of\s+the\s+intellectual\s+property)/i,
    ],
    why: "§ 365(n) lets a licensee retain its rights after rejection and demand embodiments of the IP — but the escrow must be characterized as a supplementary agreement to the license for the election to reach the deposit.",
    fix: "Recite that the license is an executory contract under which the licensor is a licensor of intellectual property, that the escrow is a supplementary agreement, and that the beneficiary may elect to retain its rights under § 365(n).",
    sev: "critical",
  },
  {
    id: "IPL-133",
    name: "License scope after release",
    cite: practice("post-release-license", "license scope following an escrow release"),
    pat: [
      /(upon\s+release|after\s+(the\s+)?release|following\s+release)/i,
      /(licen[cs]e\s+to\s+(use|modify|maintain)|internal\s+(use|purposes)|may\s+not\s+(distribute|sublicen[cs]e))/i,
    ],
    why: "A release without a license to modify and maintain gives the beneficiary code it cannot lawfully use. The scope also needs limits so the escrow does not become a backdoor source license.",
    fix: "Grant a post-release license to use, modify, and maintain the software for the beneficiary's internal purposes, with express limits on distribution and competitive use.",
  },
]);

export const V5_IP_LICENSING_RULES: readonly Rule[] = [
  ...PATENT_ASSIGNMENT,
  ...TRADEMARK_ASSIGNMENT,
  ...COEXISTENCE,
  ...JDA,
  ...TECH_TRANSFER,
  ...ESCROW,
];
