/**
 * v5 sub-domain J′ — US health care contracting (spec-v45.md §6.J).
 * Rule ids continue the HC namespace at 101.
 */

import type { Rule } from "../../finding.js";
import { pack } from "./_pack.js";
import { agency, cfr, expressDenial, practice, stateLaw, usc } from "./_helpers.js";

const C = "healthcare";

const PHYSICIAN = pack("physician-employment-agreement", C, [
  {
    id: "HC-101",
    name: "Fair market value and commercial reasonableness recital",
    cite: usc("42", "1395nn", "Stark Law — limitation on certain physician referrals"),
    pat: [
      /fair\s+market\s+value/i,
      /(commercially\s+reasonable|arm'?s\s+length|independent\s+valuation)/i,
    ],
    why: "The Stark bona fide employment exception at § 1395nn(e)(2) requires compensation consistent with fair market value and commercially reasonable even if no referrals were made. The recital is the first thing a regulator looks for.",
    fix: "Recite that compensation is consistent with fair market value and that the arrangement is commercially reasonable independent of any referrals, and document the valuation basis.",
    sev: "critical",
  },
  {
    id: "HC-102",
    name: "No compensation varying with referral volume or value",
    cite: usc("42", "1395nn", "Stark Law — bona fide employment relationship exception"),
    pat: [
      /(volume\s+or\s+value\s+of\s+(any\s+)?referrals)/i,
      /(does\s+not\s+(vary|take\s+into\s+account)|not\s+determined\s+in\s+(any\s+)?manner\s+that\s+takes\s+into\s+account)/i,
    ],
    why: "The exception fails if compensation takes into account the volume or value of referrals. This is the term Stark cases are decided on, and it must appear in the contract, not only in practice.",
    fix: "State that compensation does not take into account, directly or indirectly, the volume or value of referrals or other business generated between the parties.",
    sev: "critical",
  },
  {
    id: "HC-103",
    name: "Productivity formula",
    cite: agency(
      "CMS",
      "physician compensation methodologies and the wRVU benchmark under the Stark regulations",
      "https://www.cms.gov/medicare/regulations-guidance/physician-self-referral",
    ),
    pat: [
      /(wrvu|work\s+rvu|relative\s+value\s+unit|productivity)/i,
      /(rate\s+per|conversion\s+factor|base\s+salary|threshold)/i,
    ],
    why: "Productivity compensation is permitted for a physician's personally performed services, but the conversion factor and thresholds need to be stated to demonstrate they were set in advance at fair market value.",
    fix: "State the base salary, the wRVU conversion factor and threshold, the measurement period, and confirm the formula covers only personally performed services.",
  },
  {
    id: "HC-104",
    // 1.1.0 — an express disclaimer of this column is now reported as a
    // disclaimer rather than read as compliance (`v5/_pack.ts`, `denied`).
    ver: "1.1.0",
    name: "Malpractice coverage and tail responsibility",
    cite: practice(
      "malpractice-tail",
      "professional liability coverage and tail responsibility in physician contracts",
    ),
    pat: [
      /(professional\s+liability|malpractice)\s+(insurance|coverage)/i,
      /(tail|extended\s+reporting|nose|claims-?made|occurrence)/i,
    ],
    why: "A claims-made policy leaves no coverage for claims reported after the physician leaves. Tail premiums run into six figures, and who buys the tail is the single most valuable term after compensation.",
    fix: "State the policy type and limits, and state expressly who purchases and pays for tail coverage on each type of termination.",
    denied: expressDenial(
      String.raw`tail\s+coverage|extended\s+reporting\s+(?:period\s+)?(?:endorsement|coverage)`,
    ),
    sev: "critical",
  },
  {
    id: "HC-105",
    name: "Medical staff privileges condition",
    cite: practice("privileges", "medical staff privileges as a condition of physician employment"),
    pat: [
      /(medical\s+staff|privileges|credential)/i,
      /(obtain|maintain|condition|loss\s+of\s+privileges|termination)/i,
    ],
    why: "Employment usually depends on privileges the physician does not control. Automatic termination on any privileges action can end a career over a temporary suspension, and the peer-review interaction needs care.",
    fix: "State the privileges required, the obligation to maintain them, and the consequence of suspension versus revocation, distinguishing summary from final action.",
  },
  {
    id: "HC-106",
    name: "Restrictive covenant scope and state limits",
    cite: stateLaw(
      "physician-noncompete",
      "state statutes restricting physician non-compete agreements",
      "https://www.law.cornell.edu/wex/non-compete_clause",
    ),
    pat: [
      /(non-?compet|restrictive\s+covenant|shall\s+not\s+(practice|engage))/i,
      /(radius|miles|geographic|period\s+of\s+\d+|buy-?out)/i,
    ],
    why: "A growing number of states ban or sharply limit physician non-competes outright, and others require a buy-out option. A national form is unenforceable in several of them and creates continuity-of-care exposure everywhere.",
    fix: "State the scope, geography, and duration, add a buy-out where the state requires or permits one, and confirm enforceability under the governing state's physician-specific statute.",
    sev: "critical",
  },
  {
    id: "HC-107",
    name: "Termination, cure, and licensure triggers",
    cite: practice(
      "physician-termination",
      "termination triggers in physician employment agreements",
    ),
    pat: [
      /terminat/i,
      /(licens(e|ure)|dea|exclusion|medicare|for\s+cause|cure\s+period|without\s+cause\s+upon)/i,
    ],
    why: "Exclusion from federal health care programs, license action, or DEA loss make continued employment unlawful, so immediate-termination triggers are necessary — but they must be distinguished from ordinary cause with a cure period.",
    fix: "Separate immediate triggers (exclusion, license revocation, DEA loss, loss of insurability) from curable cause, and state the without-cause notice period for each party.",
  },
]);

const MEDICAL_DIRECTOR = pack("medical-director-agreement", C, [
  {
    id: "HC-108",
    name: "Written, signed agreement with a one-year minimum term",
    cite: cfr(
      "42",
      "1001.952(d)",
      "Anti-Kickback Statute safe harbor — personal services and management contracts",
    ),
    pat: [
      /(term\s+of\s+(at\s+least\s+)?one\s+year|one\s+\(?1\)?\s+year|twelve\s+\(?12\)?\s+months)/i,
      /(signed|in\s+writing|written\s+agreement)/i,
    ],
    why: "The personal services safe harbor at 42 C.F.R. § 1001.952(d) requires a written, signed agreement with a term of not less than one year. A month-to-month directorship falls outside it entirely.",
    fix: "Set a term of at least one year and confirm the agreement is signed by both parties before services begin.",
    sev: "critical",
  },
  {
    id: "HC-109",
    name: "Services specified and aggregate hours set in advance",
    cite: cfr("42", "1001.952(d)", "AKS safe harbor — specification of services"),
    pat: [
      /(scope\s+of\s+services|duties|services\s+to\s+be\s+(provided|performed))/i,
      /(hours\s+per\s+(month|week|year)|aggregate|schedule\s+of\s+services|specified\s+in\s+advance)/i,
    ],
    why: "The safe harbor requires the agreement to cover all services and specify them, and where services are part-time, to specify the schedule, length, and exact charge for each interval.",
    fix: "Enumerate the directorship duties, state the aggregate hours required per period, and specify the schedule where services are periodic rather than full-time.",
    sev: "critical",
  },
  {
    id: "HC-110",
    name: "Compensation set in advance at fair market value",
    cite: usc(
      "42",
      "1320a-7b",
      "Anti-Kickback Statute — criminal penalties for acts involving federal health care programs",
    ),
    pat: [
      /(compensation|fee|hourly\s+rate)/i,
      /(set\s+in\s+advance|fair\s+market\s+value|does\s+not\s+exceed|fixed)/i,
    ],
    why: "Compensation must be set in advance, consistent with fair market value, and not determined in a manner that takes into account the volume or value of referrals. Directorships are the classic vehicle for disguised referral payments.",
    fix: "State the compensation set in advance (an annual amount or an hourly rate with an annual cap), and document the fair market value basis.",
    sev: "critical",
  },
  {
    id: "HC-111",
    name: "No variation with referrals",
    cite: usc("42", "1320a-7b", "Anti-Kickback Statute — remuneration to induce referrals"),
    pat: [
      /(volume\s+or\s+value\s+of\s+(any\s+)?referrals|business\s+generated\s+between\s+the\s+parties)/i,
      /(not\s+(determined|based)|does\s+not\s+take\s+into\s+account|independent\s+of)/i,
    ],
    why: "Both Stark and the AKS turn on this. A directorship fee that moves with the director's admissions or orders is the paradigm kickback.",
    fix: "State that compensation is not determined in any manner that takes into account the volume or value of referrals or other business generated between the parties.",
    sev: "critical",
  },
  {
    id: "HC-112",
    // 1.1.0 — an express disclaimer of this column is now reported as a
    // disclaimer rather than read as compliance (`v5/_pack.ts`, `denied`).
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.2.0",
    name: "Time-record substantiation requirement",
    cite: practice(
      "directorship-time-records",
      "time records as evidence that directorship services were rendered",
    ),
    pat: [
      /(time[-\s]+(record|log|sheet)|document\s+the\s+(hours|services))/i,
      /(submit|maintain|as\s+a\s+condition\s+of\s+payment|monthly)/i,
    ],
    why: "Enforcement actions against medical directorships almost always rest on the absence of any evidence the services were performed. Contemporaneous time records are the single most valuable defensive control.",
    fix: "Require contemporaneous time records describing the services performed, submitted as a condition of payment and retained for the record-retention period.",
    denied: expressDenial(String.raw`time\s+(?:records?|sheets?|logs?)`),
    sev: "critical",
  },
  {
    id: "HC-113",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Personal-services safe-harbor recital",
    cite: cfr("42", "1001.952(d)", "AKS safe harbor — personal services and management contracts"),
    pat: [
      /(safe[-\s]+harbor|1001\.952|personal\s+services\s+and\s+management)/i,
      /(anti-?kickback|stark|intended\s+to\s+(comply|satisfy)|42\s+c\.?f\.?r)/i,
    ],
    why: "Reciting the intended safe harbor is not itself compliance, but it documents intent and disciplines the drafting to the elements — which is why the elements are usually all present when the recital is.",
    fix: "Recite that the parties intend the arrangement to satisfy the personal services and management contracts safe harbor and the Stark personal services exception.",
  },
]);

const CTA = pack("clinical-trial-agreement", C, [
  {
    id: "HC-114",
    name: "Protocol incorporation and amendment control",
    cite: cfr("21", "312.23", "FDA — IND content and format, protocols"),
    pat: [
      /protocol/i,
      /(incorporated|attached|amendment|shall\s+conduct\s+the\s+study\s+in\s+accordance)/i,
    ],
    why: "The protocol is the operative document; the CTA is the contract wrapper. Protocol amendments change the site's obligations and budget, so the amendment and re-budgeting process has to be in the agreement.",
    fix: "Incorporate the protocol by reference, and state the process and budget consequence for protocol amendments.",
    sev: "critical",
  },
  {
    id: "HC-115",
    // 1.1.0 — an express disclaimer of this column is now reported as a
    // disclaimer rather than read as compliance (`v5/_pack.ts`, `denied`).
    ver: "1.1.0",
    name: "IRB approval as a condition precedent",
    cite: cfr("21", "56.103", "FDA — circumstances in which IRB review is required"),
    pat: [
      /(institutional\s+review\s+board|irb|ethics\s+committee)/i,
      /(approval|prior\s+to\s+(enrolling|the\s+start)|condition|continuing\s+review)/i,
    ],
    why: "21 C.F.R. Part 56 requires IRB review and approval before the study begins and continuing review at least annually. Enrollment before approval is a serious finding.",
    fix: "Condition the start of study activities on documented IRB approval, and require notice of any suspension, termination, or condition imposed on continuing review.",
    denied: expressDenial(String.raw`IRB\s+approval|institutional\s+review\s+board\s+approval`),
    sev: "critical",
  },
  {
    id: "HC-116",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Subject-injury cost responsibility",
    cite: cfr("21", "50.25", "FDA — elements of informed consent, compensation for injury"),
    pat: [
      /(subject[-\s]+injury|research-?related\s+injur|study-?related\s+injur)/i,
      /(sponsor\s+(shall|will)\s+(pay|reimburse|be\s+responsible)|cost\s+of\s+(treatment|medical\s+care)|insurance)/i,
    ],
    why: "§ 50.25(a)(6) requires the consent form to explain whether compensation and medical treatment are available for injury. The CTA has to fund whatever the consent form promises — a mismatch between the two is a routine and serious defect.",
    fix: "State the sponsor's responsibility for the reasonable costs of treating research-related injury, its exclusions, and confirm the consent form language matches.",
    sev: "critical",
  },
  {
    id: "HC-117",
    name: "Informed-consent form control and language",
    cite: cfr("21", "50.20", "FDA — general requirements for informed consent"),
    pat: [
      /informed\s+consent\s+(form|document)/i,
      /(approv|template|site\s+may\s+(not\s+)?modify|language\s+(understandable|comprehensible)|translation)/i,
    ],
    why: "The site's IRB will require changes to the sponsor's template; who controls the final language, and whether the site may add local requirements, is a recurring startup delay.",
    fix: "State who provides the template, that IRB-required changes are permitted, which sections may not be changed without sponsor approval, and the translation responsibility.",
  },
  {
    id: "HC-118",
    // 1.1.0 — an express disclaimer of this column is now reported as a
    // disclaimer rather than read as compliance (`v5/_pack.ts`, `denied`).
    ver: "1.1.0",
    name: "Publication rights and sponsor review window",
    cite: agency(
      "ICMJE",
      "Recommendations for the Conduct, Reporting, Editing, and Publication of Scholarly Work in Medical Journals",
      "https://www.icmje.org/recommendations/",
    ),
    pat: [
      /publi(sh|cation)/i,
      /(review|\d+\s+days\s+(prior|before)|delay|multicenter|primary\s+publication|shall\s+not\s+(prohibit|prevent))/i,
    ],
    why: "Academic sites will not sign an agreement that gives the sponsor a veto over publication, and ICMJE requires that investigators have access to the data and control over publication decisions.",
    fix: "Give the sponsor a stated review window with a short delay for patent filing and removal of confidential information, and confirm the sponsor has no right to suppress or alter the results.",
    denied: expressDenial(String.raw`publication\s+rights?`),
    sev: "critical",
  },
  {
    id: "HC-119",
    name: "Data ownership, access, and records retention",
    cite: cfr("21", "312.62", "FDA — investigator recordkeeping and record retention"),
    pat: [
      /(data\s+(ownership|shall\s+be\s+owned)|study\s+data)/i,
      /(access|retain|records\s+for\s+(a\s+period\s+of\s+)?\d+\s+years|source\s+documents)/i,
    ],
    why: "§ 312.62(c) requires the investigator to retain records for two years after marketing approval or after the IND is discontinued. Sponsors own the study data but the site needs continuing access for its own publication and defense.",
    fix: "State sponsor ownership of study data, the site's retained copy and access rights, and the record-retention period consistent with § 312.62(c).",
  },
  {
    id: "HC-120",
    name: "Financial disclosure and debarment certification",
    cite: cfr(
      "21",
      "54.4",
      "FDA — certification and disclosure requirements for clinical investigators",
    ),
    pat: [
      /(financial\s+(disclosure|interest)|form\s+fda\s+3455|3454)/i,
      /(debar|21\s+u\.?s\.?c\.?\s*§?\s*335a|excluded|not\s+been\s+debarred)/i,
    ],
    why: "Part 54 requires the sponsor to collect investigator financial disclosures, and § 335a bars using a debarred person in any capacity in an application. Both are certifications the sponsor makes to FDA on the site's word.",
    fix: "Require investigator financial disclosure at startup and on change, and a certification that no debarred or excluded person will work on the study.",
  },
]);

const PAYER = pack("payer-provider-agreement", C, [
  {
    id: "HC-121",
    name: "Fee schedule attached and amendment notice",
    cite: practice(
      "fee-schedule",
      "fee schedule attachment and unilateral amendment in payer contracts",
    ),
    pat: [
      /fee\s+schedule/i,
      /(attached|exhibit|amend|change|notice\s+of\s+(any\s+)?(rate|fee)\s+change|\d+\s+days'?\s+(prior\s+)?notice)/i,
    ],
    why: "Payer forms routinely incorporate a fee schedule by reference to a website and reserve unilateral amendment. A provider that cannot see the rates and cannot terminate on a cut has signed an open-ended discount.",
    fix: "Attach the fee schedule, require advance written notice of any change, and give the provider a termination right if it does not accept the new rates.",
    sev: "critical",
  },
  {
    id: "HC-122",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Clean-claim definition and prompt-pay deadline",
    cite: stateLaw(
      "prompt-pay",
      "state prompt payment statutes for health insurers",
      "https://www.law.cornell.edu/wex/insurance_law",
    ),
    pat: [
      /clean[-\s]+claim/i,
      /(within\s+\d+\s+days|prompt[-\s]+pay|interest\s+(on|shall\s+accrue)|adjudicat)/i,
    ],
    why: "Every state has a prompt-pay statute with a clean-claim definition and an interest penalty. A contract that defines clean claim more narrowly than the statute is unenforceable to that extent, but providers rarely notice.",
    fix: "Define clean claim consistent with the governing state's statute, state the payment deadline and interest, and describe the process for pended and denied claims.",
  },
  {
    id: "HC-123",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Member hold-harmless and balance-billing ban",
    cite: usc(
      "42",
      "300gg-131",
      "No Surprises Act — balance billing in cases of emergency services",
    ),
    pat: [
      /hold[-\s]+harmless/i,
      /(balance[-\s]+bill|shall\s+not\s+(bill|collect)\s+(the\s+)?(member|enrollee|patient)|except\s+for\s+(copayments|deductibles|coinsurance))/i,
    ],
    why: "Hold-harmless clauses are required by state insurance law and by Medicare Advantage rules, and the No Surprises Act now bans balance billing in emergency and certain non-emergency settings regardless of the contract.",
    fix: "State the member hold-harmless covering insolvency and non-payment, permit collection only of cost-sharing amounts, and confirm the No Surprises Act obligations.",
    sev: "critical",
  },
  {
    id: "HC-124",
    name: "Credentialing and re-credentialing terms",
    cite: practice("credentialing", "credentialing and re-credentialing in payer agreements"),
    pat: [
      /credential/i,
      /(re-?credential|effective\s+date\s+of\s+participation|primary\s+source\s+verification|roster|three\s+years)/i,
    ],
    why: "Participation, and therefore payment, usually begins on credentialing approval rather than the contract date. A provider that treats before the effective date is out of network and unpaid.",
    fix: "State when participation becomes effective, the credentialing timeline and re-credentialing cycle, and how new providers are added to the roster.",
  },
  {
    id: "HC-125",
    name: "Utilization review and appeal rights",
    cite: cfr("29", "2560.503-1", "ERISA — claims procedure regulation"),
    pat: [
      /(utilization\s+(review|management)|prior\s+authorization|medical\s+necessity)/i,
      /(appeal|reconsideration|peer-?to-?peer|external\s+review|adverse\s+(benefit\s+)?determination)/i,
    ],
    why: "The ERISA claims regulation sets deadlines and content for adverse determinations and appeals. The provider's own appeal rights, distinct from the member's, must come from the contract.",
    fix: "Describe the utilization review process, the provider's appeal levels and deadlines, peer-to-peer review availability, and the interaction with the member's ERISA appeal rights.",
  },
  {
    id: "HC-126",
    name: "Termination notice and continuity of care",
    cite: usc("42", "300gg-113", "No Surprises Act — continuity of care"),
    pat: [
      /terminat/i,
      /(continuity\s+of\s+care|transition(al)?\s+care|continuing\s+care\s+patient|\d+\s+days'?\s+notice|90\s+days)/i,
    ],
    why: "The No Surprises Act requires up to 90 days of continued in-network terms for continuing care patients after a contract terminates. The contract has to accommodate the obligation it cannot contract out of.",
    fix: "State the termination notice period for each party and the continuity-of-care obligations, including the 90-day transitional period for continuing care patients.",
  },
]);

const TELEHEALTH = pack("telehealth-consent", C, [
  {
    id: "HC-127",
    name: "Description of the telehealth modality",
    cite: stateLaw(
      "telehealth-consent",
      "state statutes requiring informed consent for telehealth services",
      "https://www.cchpca.org/",
    ),
    pat: [
      /telehealth|telemedicine/i,
      /(video|audio|store-?and-?forward|asynchronous|real-?time|remote\s+patient\s+monitoring)/i,
    ],
    all: true,
    why: "Most states require telehealth-specific consent, and several require it in writing. The consent must describe what the modality actually is so the patient can weigh the limits.",
    fix: "Describe the modality used (live video, audio-only, asynchronous, remote monitoring) and how the encounter will be conducted.",
    sev: "critical",
  },
  {
    id: "HC-128",
    name: "Limitations and risks of remote evaluation",
    cite: practice("telehealth-risks", "disclosure of the limits of remote evaluation"),
    pat: [
      /(limitation|risk)/i,
      /(unable\s+to\s+(examine|perform)|physical\s+examination|may\s+not\s+be\s+(appropriate|sufficient)|delay(s)?\s+in\s+(evaluation|treatment))/i,
    ],
    why: "The consent's substance is the acknowledgment that a remote evaluation cannot include a physical examination and may miss findings — which is what makes it informed rather than a formality.",
    fix: "State the limitations of a remote evaluation, the risks (missed findings, technology failure, delay), and when an in-person visit will be required.",
  },
  {
    id: "HC-129",
    name: "Right to withdraw and receive in-person care",
    cite: practice("telehealth-withdrawal", "the right to withdraw consent to telehealth"),
    pat: [
      /(withdraw|revoke|discontinue)/i,
      /(at\s+any\s+time|without\s+(affecting|jeopardizing)|in-?person\s+(care|visit|appointment)|right\s+to\s+refuse)/i,
    ],
    why: "Consent that cannot be withdrawn without losing care is not voluntary. Several state statutes require the disclosure explicitly.",
    fix: "State that consent may be withdrawn at any time without affecting the patient's right to future care, and that in-person care remains available.",
  },
  {
    id: "HC-130",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Emergency and technology-failure protocol",
    cite: practice(
      "telehealth-emergency",
      "emergency and technology failure protocols in telehealth",
    ),
    pat: [
      /(emergenc|911|urgent)/i,
      /(technology[-\s]+(failure|disruption)|connection\s+(is\s+)?lost|call\s+back|nearest\s+emergency)/i,
    ],
    why: "The provider often does not know where the patient physically is. Confirming the patient's location and stating what happens if the connection drops is both a safety measure and a licensure issue.",
    fix: "State the protocol if the connection fails, instruct the patient to call emergency services for urgent symptoms, and confirm the patient's physical location at the start of the encounter.",
    sev: "critical",
  },
  {
    id: "HC-131",
    name: "Privacy, recording, and who may be present",
    cite: cfr("45", "164.530", "HIPAA Privacy Rule — administrative requirements"),
    pat: [
      /(privacy|confidential|hipaa)/i,
      /(record(ing|ed)?|who\s+(is|may\s+be)\s+present|third\s+part(y|ies)\s+in\s+the\s+room|secure\s+(platform|connection))/i,
    ],
    why: "Telehealth introduces recording, bystanders, and consumer platforms that the in-person privacy notice never contemplated. Patients should be told what is recorded and who else can hear.",
    fix: "State whether the encounter is recorded and why, who may be present on each side, and that a HIPAA-compliant platform is used.",
  },
  {
    id: "HC-132",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Licensure and patient-location recital",
    cite: stateLaw(
      "telehealth-licensure",
      "state medical licensure requirements based on the patient's physical location during a telehealth encounter",
      "https://www.cchpca.org/",
    ),
    pat: [
      /(licens(e|ed|ure))/i,
      /(in\s+the\s+state\s+(where|in\s+which)\s+(the\s+)?(patient|you)|patient'?s?[-\s]+location|state\s+of\s+\w+|interstate\s+(medical\s+)?licens)/i,
    ],
    why: "The practice of medicine occurs where the patient is, so the provider must be licensed in that state (or covered by a compact or an exception). A patient who travels can put an otherwise routine encounter outside the provider's licensure.",
    fix: "Recite the states in which the provider is licensed, require the patient to confirm their physical location at each encounter, and state that services may be unavailable outside those states.",
    sev: "critical",
  },
]);

export const V5_HEALTHCARE_RULES: readonly Rule[] = [
  ...PHYSICIAN,
  ...MEDICAL_DIRECTOR,
  ...CTA,
  ...PAYER,
  ...TELEHEALTH,
];
