/**
 * v5 sub-domain I′ — US consent instruments and data sharing
 * (spec-v45.md §6.I). Rule ids continue the PRV namespace at 101.
 */

import type { Rule } from "../../finding.js";
import { pack } from "./_pack.js";
import { agency, cfr, expressDenial, practice, stateLaw, usc } from "./_helpers.js";

const C = "privacy";

const BIOMETRIC = pack("biometric-consent", C, [
  {
    id: "PRV-101",
    // 1.1.0 — an express disclaimer of this column is now reported as a
    // disclaimer rather than read as compliance (`v5/_pack.ts`, `denied`).
    ver: "1.2.0",
    name: "Written release obtained before collection",
    cite: stateLaw(
      "biometric-privacy",
      "biometric privacy statutes requiring a written release before collection (740 ILCS 14/15(b); Tex. Bus. & Com. § 503.001; Wash. Rev. Code 19.375)",
      "https://www.ilga.gov/legislation/ilcs/ilcs3.asp?ActID=3004",
    ),
    pat: [
      // "I give my written consent … to that collection, storage, and use" is
      // the § 15(b)(3) release, written as the statute's own recital, and the
      // adjacent forms below could not see it.
      /(written\s+release|written\s+consent|consent\s+in\s+writing|hereby\s+(consent|authori[sz]e)|i\s+consent\s+to|(?:give|giving|provide)\s+(?:my\s+)?(?:written\s+)?(?:consent|release|authori[sz]ation)|informed\s+written\s+consent)/i,
      // BIPA § 15(b)(1) asks the form to say WHAT is being collected, and a
      // form that recites "is collecting, storing, and using a biometric
      // identifier and biometric information about me" says it.
      /(before\s+(any\s+)?(collection|capture)|prior\s+to\s+(the\s+)?(collection|capture)|collect(ion)?\s+of\s+my\s+biometric|collect\w*[^.;]{0,70}?\bbiometric|biometric\s+identifier[^.;]{0,90}?\bcollect)/i,
    ],
    all: true,
    why: "BIPA § 15(b) requires informed written consent before collection, and it carries a private right of action with statutory damages per violation — the only US biometric statute that does.",
    fix: "Obtain a signed written release before any collection, and retain proof of the date it was signed.",
    denied: expressDenial(String.raw`written\s+release`),
    sev: "critical",
  },
  {
    id: "PRV-102",
    ver: "1.1.0",
    name: "Specific purpose stated",
    cite: stateLaw(
      "biometric-purpose",
      "the specific-purpose disclosure required before collecting biometric identifiers",
      "https://www.ilga.gov/legislation/ilcs/ilcs3.asp?ActID=3004",
    ),
    pat: [
      // BIPA § 15(b)(1) asks for the specific purpose, and a compliant form
      // states it plainly: "We collect and use the template for one purpose:
      // to identify you when you clock in and out."
      /(specific\s+purpose|purpose\s+(for\s+which|of\s+(the\s+)?collection)|for\s+(?:one|a\s+single|the\s+sole|the\s+following)\s+purposes?|purposes?\s+(?:is|are)\s+to)/i,
      /(biometric|fingerprint|facial|voiceprint|retina|iris|scan\s+of\s+hand)/i,
    ],
    all: true,
    why: "§ 15(b)(2) requires disclosure of the specific purpose. A generic 'business purposes' recital has repeatedly been held insufficient.",
    fix: "State the specific purpose — timekeeping, access control, identity verification — and the specific biometric identifier collected for it.",
    sev: "critical",
  },
  {
    id: "PRV-103",
    name: "Length of term stated",
    cite: stateLaw(
      "biometric-term",
      "the length-of-term disclosure required before collecting biometric identifiers",
      "https://www.ilga.gov/legislation/ilcs/ilcs3.asp?ActID=3004",
    ),
    pat: [
      /(length\s+of\s+term|period\s+(of\s+time\s+)?(for\s+which|the\s+data\s+will\s+be)|duration)/i,
      /(collected|stored|used|retained)/i,
    ],
    why: "§ 15(b)(2) requires the length of term for collection, storage, and use — a separate element from the retention schedule, and one omitted from most consent forms.",
    fix: "State how long the biometric identifier will be collected, stored, and used — typically for the duration of employment or the relationship plus a stated period.",
    sev: "critical",
  },
  {
    id: "PRV-104",
    // 1.1.0 — an express disclaimer of this column is now reported as a
    // disclaimer rather than read as compliance (`v5/_pack.ts`, `denied`).
    ver: "1.1.0",
    name: "Publicly available retention and destruction schedule",
    cite: stateLaw(
      "biometric-retention",
      "the publicly available written retention and destruction policy required of private entities",
      "https://www.ilga.gov/legislation/ilcs/ilcs3.asp?ActID=3004",
    ),
    pat: [
      /(retention\s+(schedule|policy)|destruction\s+(schedule|policy))/i,
      /(publicly\s+available|three\s+years|when\s+the\s+(initial\s+)?purpose.{0,40}has\s+been\s+satisfied|permanently\s+destroy)/i,
    ],
    why: "§ 15(a) requires a publicly available written policy establishing a retention schedule and destruction guidelines — destroying the data when the purpose is satisfied or within three years of the last interaction, whichever is first.",
    fix: "Publish a written retention and destruction policy and reference it in the consent, stating the destruction trigger.",
    denied: expressDenial(
      String.raw`(?:retention|destruction)\s+(?:and\s+destruction\s+)?(?:schedule|policy)`,
    ),
    sev: "critical",
  },
  {
    id: "PRV-105",
    name: "No sale, lease, or trade of biometric data",
    cite: stateLaw(
      "biometric-sale",
      "the statutory prohibition on selling, leasing, trading, or profiting from biometric data",
      "https://www.ilga.gov/legislation/ilcs/ilcs3.asp?ActID=3004",
    ),
    pat: [/(sell|lease|trade|profit)/i, /(will\s+not|shall\s+not|does\s+not|prohibited)/i],
    all: true,
    why: "§ 15(c) prohibits selling, leasing, trading, or otherwise profiting from biometric data outright — there is no consent that cures it.",
    fix: "State that the entity does not and will not sell, lease, trade, or otherwise profit from the biometric data.",
  },
  {
    id: "PRV-106",
    name: "Reasonable standard of care recital",
    cite: stateLaw(
      "biometric-security",
      "the reasonable standard of care and disclosure limits for stored biometric data",
      "https://www.ilga.gov/legislation/ilcs/ilcs3.asp?ActID=3004",
    ),
    pat: [
      /(reasonable\s+(standard\s+of\s+care|care)|safeguard|protect)/i,
      /(store|transmit|same\s+manner\s+as.{0,40}confidential|other\s+confidential\s+and\s+sensitive)/i,
    ],
    why: "§ 15(e) requires storage and transmission using the reasonable standard of care in the industry and in a manner at least as protective as the entity uses for other confidential information.",
    fix: "Recite the standard of care and the security measures applied to biometric data in storage and transmission.",
  },
]);

const COPPA = pack("childrens-privacy-notice", C, [
  {
    id: "PRV-107",
    name: "Operator identity and contact details",
    cite: cfr(
      "16",
      "312.4(d)(1)",
      "COPPA Rule — direct notice to the parent, operator contact information",
    ),
    pat: [
      /(operator|name\s+of\s+the\s+(company|operator|website))/i,
      /(address|telephone|email|contact\s+(information|us))/i,
    ],
    why: "§ 312.4(d)(1) requires the name, address, telephone number, and email of all operators collecting information through the service, or of one operator designated to respond.",
    fix: "List each operator's name, physical address, telephone number, and email, or designate one operator to respond on behalf of all.",
    sev: "critical",
  },
  {
    id: "PRV-108",
    name: "Categories collected and how used",
    cite: cfr("16", "312.4(d)(2)", "COPPA Rule — what information is collected and how it is used"),
    pat: [/(collect|information\s+we\s+collect)/i, /(how\s+(we\s+)?use|purpose|disclos)/i],
    why: "The direct notice must state what personal information is collected, how it is used, and whether it is disclosed to third parties and for what purpose.",
    fix: "Describe each category collected, how it is used, whether it is disclosed and to whom, and whether collection is passive or user-initiated.",
  },
  {
    id: "PRV-109",
    // 1.1.0 — an express disclaimer of this column is now reported as a
    // disclaimer rather than read as compliance (`v5/_pack.ts`, `denied`).
    ver: "1.1.0",
    name: "Verifiable parental consent mechanism",
    cite: cfr("16", "312.5", "COPPA Rule — parental consent"),
    pat: [
      /verifiable\s+parental\s+consent/i,
      /(credit\s+card|government-?issued\s+id|video|knowledge-?based|signed\s+form|facial\s+(age|recognition))/i,
    ],
    why: "§ 312.5(b) enumerates the approved consent methods, and the method must be reasonably calculated to ensure the person giving consent is the parent. Email-plus alone is permitted only for internal use.",
    fix: "Describe the verifiable consent method used and, where email-plus is used, confirm the information is used only internally and describe the additional confirmation step.",
    denied: expressDenial(String.raw`verifiable\s+parental\s+consent`),
    sev: "critical",
  },
  {
    id: "PRV-110",
    ver: "1.1.0",
    name: "Parental review, deletion, and revocation rights",
    cite: cfr(
      "16",
      "312.6",
      "COPPA Rule — right of parent to review personal information provided by a child",
    ),
    pat: [
      // A COPPA direct notice addresses the parent in the SECOND person —
      // "You may review the personal information we have collected from your
      // child, you may refuse to permit its further collection" — which is
      // what 16 CFR 312.4(c) asks the notice to say.
      /((?:parent|you)\s+(may|can|has\s+the\s+right)\s+(to\s+)?(review|access|delete|refuse|direct))/i,
      /(revoke|withdraw\s+consent|request\s+(the\s+)?deletion|discontinue)/i,
    ],
    why: "§ 312.6 gives parents the right to review the information collected, to refuse further collection, and to direct deletion. The notice must describe how to exercise each.",
    fix: "State the parent's rights to review, refuse further collection, revoke consent, and require deletion, and describe how to make each request.",
  },
  {
    id: "PRV-111",
    name: "No conditioning participation on excess collection",
    cite: cfr(
      "16",
      "312.7",
      "COPPA Rule — prohibition against conditioning a child's participation on collection of personal information",
    ),
    pat: [
      /(condition|require)/i,
      /(participation|more\s+information\s+than\s+is\s+reasonably\s+necessary|not\s+condition)/i,
    ],
    why: "§ 312.7 prohibits conditioning a child's participation in an activity on disclosing more personal information than is reasonably necessary to participate.",
    fix: "State that participation is not conditioned on providing more information than is reasonably necessary for the activity.",
  },
  {
    id: "PRV-112",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Third-party disclosure and retention limits",
    cite: cfr("16", "312.10", "COPPA Rule — data retention and deletion requirements"),
    pat: [
      /(retain|retention)/i,
      /(only\s+as\s+long\s+as\s+is\s+reasonably\s+necessary|delete|third[-\s]+part(y|ies)|service\s+providers)/i,
    ],
    why: "§ 312.10 permits retention only as long as reasonably necessary for the purpose collected, and requires deletion using reasonable measures against unauthorized access.",
    fix: "State the retention limit tied to the collection purpose, the deletion practice, and the categories of third parties that receive the information and why.",
  },
]);

const SMS = pack("sms-consent-disclosure", C, [
  {
    id: "PRV-113",
    // 1.1.0 — an express disclaimer of this column is now reported as a
    // disclaimer rather than read as compliance (`v5/_pack.ts`, `denied`).
    ver: "1.2.0",
    name: "Express written consent language",
    cite: cfr("47", "64.1200(f)(9)", "TCPA rules — prior express written consent"),
    pat: [
      // Consumer messaging terms address the reader in the SECOND person —
      // "you consent to receive recurring automated marketing text messages" —
      // and the first-person form belongs on a paper sign-up sheet. A program
      // whose consent sentence is the CTIA-standard one was reported as
      // carrying no express-consent language, at `critical`.
      /(express(?:ly)?\s+written\s+consent|(?:i|you)\s+(?:hereby\s+)?(?:agree|consent)\s+to\s+receive|consent\s+to\s+receive)/i,
      /(text\s+messages?|sms|calls?\s+(from|by)|autodial)/i,
    ],
    all: true,
    why: "Marketing texts and autodialed marketing calls require prior express written consent that identifies the seller, the number, and the fact that consent authorizes the messages. A checkbox with no disclosure is not consent.",
    fix: "Use a consent statement identifying the seller, the telephone number consent applies to, and the fact that the consumer agrees to receive autodialed or prerecorded marketing messages.",
    denied: expressDenial(String.raw`(?:prior\s+)?express\s+written\s+consent`),
    sev: "critical",
  },
  {
    id: "PRV-114",
    name: "Consent-not-a-condition-of-purchase statement",
    cite: cfr("47", "64.1200(f)(9)(i)(B)", "TCPA rules — consent not a condition of purchase"),
    pat: [
      /(not\s+(a\s+)?condition\s+(of|to)\s+(any\s+)?purchase|consent\s+is\s+not\s+required)/i,
      /(purchase|buy|goods\s+or\s+services)/i,
    ],
    why: "The rule requires a clear and conspicuous disclosure that the consumer is not required to sign the agreement or agree to receive the messages as a condition of purchasing any goods or services.",
    fix: 'Add: "Consent is not a condition of purchase." adjacent to the consent control.',
    sev: "critical",
  },
  {
    id: "PRV-115",
    ver: "1.1.0",
    name: "Autodialer and prerecorded disclosure",
    cite: usc(
      "47",
      "227",
      "Telephone Consumer Protection Act — restrictions on the use of telephone equipment",
    ),
    pat: [
      // "Automated" is the word an SMS program uses — "recurring automated
      // marketing text messages" is the CTIA-standard phrasing, and after
      // Facebook v. Duguid almost nobody writes "autodialer" about texting.
      /(autodial|automatic\s+telephone\s+dialing|prerecorded|artificial\s+voice|automated\s+(?:marketing\s+)?(?:text|message|call))/i,
      /(may\s+be\s+(used|sent)|messages?\s+(may\s+be\s+)?sent\s+(?:using|by|via|through)|receive[^.]{0,40}?(?:automated|autodialed|prerecorded))/i,
    ],
    why: "The consent must disclose that the messages may be delivered using an automatic telephone dialing system or a prerecorded voice; without the disclosure, consent to the technology is not established.",
    fix: "Disclose that messages or calls may be delivered using automated technology or a prerecorded or artificial voice.",
  },
  {
    id: "PRV-116",
    name: "Message frequency and rates disclosure",
    cite: agency(
      "CTIA",
      "Messaging Principles and Best Practices — required program disclosures",
      "https://www.ctia.org/programs/messaging-principles-and-best-practices",
    ),
    pat: [
      /(message\s+(and\s+data\s+rates|frequency)|msg\s?&\s?data\s+rates)/i,
      /(may\s+apply|messages?\s+per\s+(month|week)|recurring)/i,
    ],
    why: "Carrier program requirements — enforced through the aggregators, not the FCC — require message frequency and 'Message and data rates may apply' at the point of opt-in. Non-compliant campaigns get shut off.",
    fix: 'Disclose the expected message frequency and add "Message and data rates may apply."',
  },
  {
    id: "PRV-117",
    // 1.1.0 — an express disclaimer of this column is now reported as a
    // disclaimer rather than read as compliance (`v5/_pack.ts`, `denied`).
    ver: "1.1.0",
    name: "STOP and HELP opt-out mechanism",
    cite: cfr("47", "64.1200(a)(10)", "TCPA rules — revocation of consent"),
    pat: [
      /(reply\s+stop|text\s+stop|opt\s?-?out)/i,
      /(help|unsubscribe|cancel|to\s+stop\s+receiving)/i,
    ],
    why: "Since the FCC's 2024 revocation order, any reasonable method of revocation is effective and must be honored within 10 business days. STOP/HELP keyword handling is also a carrier requirement.",
    fix: 'Disclose "Reply STOP to opt out, HELP for help," and confirm that any reasonable revocation method will be honored within 10 business days.',
    denied: expressDenial(String.raw`opt[- ]?out\s+(?:mechanism|instructions?)?`),
    sev: "critical",
  },
]);

const DATA_SHARING = pack("data-sharing-agreement", C, [
  {
    id: "PRV-118",
    name: "Data elements shared and purpose limitation",
    cite: practice("dsa-purpose", "purpose limitation in data sharing agreements"),
    pat: [
      /(data\s+elements|categories\s+of\s+data|the\s+shared\s+data|data\s+set)/i,
      /(solely\s+for|permitted\s+purpose|(?:shall|will|must)\s+(only\s+)?be\s+used\s+for|limited\s+to)/i,
    ],
    why: "A data sharing agreement whose scope is 'the data' and whose purpose is 'the project' cannot be audited or enforced, and fails the minimum-necessary standard every US privacy regime applies in some form.",
    fix: "Enumerate the data elements shared and state the permitted purposes exhaustively, prohibiting all other uses.",
    sev: "critical",
  },
  {
    id: "PRV-119",
    name: "De-identification standard applied",
    cite: cfr(
      "45",
      "164.514",
      "HIPAA Privacy Rule — other requirements relating to uses and disclosures of protected health information",
    ),
    pat: [
      /(de-?identif|limited\s+data\s+set|anonymi|pseudonymi)/i,
      /(safe[-\s]+harbor|expert\s+determination|18\s+identifiers|hipaa|aggregated)/i,
    ],
    why: "De-identification means something specific under HIPAA (safe harbor or expert determination) and something looser under state privacy laws. Naming the standard is what makes the claim checkable.",
    fix: "Name the de-identification standard applied and, for health data, whether safe harbor or expert determination was used and by whom.",
    when: [/(de-?identif|limited\s+data\s+set|anonymi|protected\s+health\s+information|phi)/i],
  },
  {
    id: "PRV-120",
    name: "Re-identification prohibition",
    cite: practice("reidentification", "re-identification prohibitions in data sharing agreements"),
    pat: [
      /re-?identif/i,
      /((?:shall|will|must)\s+not|prohibit|attempt\s+to\s+(identify|re-?identify)|contact\s+(the\s+)?(individuals|subjects))/i,
    ],
    why: "De-identified data stays outside the privacy regimes only while it stays de-identified. The contractual ban on re-identification and on attempting to contact individuals is what preserves the status.",
    fix: "Prohibit re-identification, linking with other datasets to identify individuals, and any attempt to contact the individuals in the data.",
    sev: "critical",
  },
  {
    id: "PRV-121",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Onward-transfer and publication limits",
    cite: practice(
      "dsa-onward",
      "onward transfer and publication controls in data sharing agreements",
    ),
    pat: [
      /(onward[-\s]+transfer|further\s+disclos|redisclos|share\s+(the\s+data\s+)?with\s+(any\s+)?third)/i,
      /(publication|publish|aggregate|cell\s+size|small\s+cell)/i,
    ],
    why: "Publication from a shared dataset can re-identify individuals through small cells even when the underlying data is de-identified. Onward transfers move the data outside the agreement entirely.",
    fix: "Prohibit onward transfer without written consent, and set publication rules including minimum cell sizes and a pre-publication review.",
  },
  {
    id: "PRV-122",
    name: "Security safeguards and breach notice",
    cite: practice("dsa-security", "security and incident notification in data sharing agreements"),
    pat: [
      /(safeguard|security\s+(measures|controls)|encrypt)/i,
      /(breach|incident|notif(y|ication)|within\s+\d+\s+(hours|days))/i,
    ],
    why: "The disclosing party remains accountable to the individuals in the data. A defined security floor and a short notification clock are the only practical controls it retains after transfer.",
    fix: "State the required safeguards (encryption in transit and at rest, access controls, logging) and a breach notification deadline with the required content.",
  },
  {
    id: "PRV-123",
    name: "Destruction or return at the end of the purpose",
    cite: practice(
      "dsa-destruction",
      "destruction and return obligations in data sharing agreements",
    ),
    pat: [
      /(destroy|destruction|return\s+the\s+data)/i,
      /(upon\s+(completion|termination|the\s+end)|certif|within\s+\d+\s*\)?\s*days|retain)/i,
    ],
    why: "Research datasets accumulate in institutional storage for decades after the project ends. A destruction obligation with certification is what converts the purpose limitation into an actual endpoint.",
    fix: "Require return or certified destruction within a stated period after the purpose is complete, with any retention exception (archival, regulatory, IRB) stated expressly.",
  },
]);

export const V5_PRIVACY_RULES: readonly Rule[] = [...BIOMETRIC, ...COPPA, ...SMS, ...DATA_SHARING];
