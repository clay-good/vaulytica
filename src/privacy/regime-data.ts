/**
 * Privacy-notice content-item data — cited, versioned data behind the
 * privacy-notice-linter pack (add-privacy-notice-pack). Each regime carries
 * an enumerated list of required content items, and each item carries a
 * stable key, its citation, source URL, retrieval date, and the regex
 * patterns (source strings, applied case-insensitively) that indicate the
 * item IS present in a notice.
 *
 * Scope: CCPA/CPRA, GDPR Articles 13 and 14, and the state acts' statutory
 * notice lists — Colorado (C.R.S. § 6-1-1308(1)(a), plus the unconditional
 * 4 CCR 904-3 Rule 6.03 regulation items), Virginia (§ 59.1-578(C)), Texas
 * (Tex. Bus. & Com. Code § 541.102, including the exact (b)–(c) mandated
 * notice texts), and Oregon (ORS 646A.578(4)).
 *
 * Data, not code: content changes are additions to this file, never silent
 * edits to shipped citations.
 */

export type RegimeId = "ccpa" | "gdpr-13" | "gdpr-14" | "co" | "va" | "tx" | "or";

export const REGIME_IDS: readonly RegimeId[] = [
  "ccpa",
  "gdpr-13",
  "gdpr-14",
  "co",
  "va",
  "tx",
  "or",
];

export type ContentItem = {
  /** Stable slug, e.g. "categories-collected". */
  key: string;
  /** Human name of the required item. */
  label: string;
  citation: string;
  url: string;
  /** YYYY-MM-DD. */
  retrieved_at: string;
  /** Regex source strings (case-insensitive) indicating the item IS present. */
  present_patterns: string[];
};

export type Regime = {
  id: RegimeId;
  name: string;
  authority_url: string;
  items: ContentItem[];
};

const RETRIEVED_AT = "2026-07-15";

const CCPA_ITEMS: ContentItem[] = [
  {
    key: "categories-collected",
    label: "Categories of personal information collected",
    citation: "Cal. Civ. Code § 1798.130(a)(5)(B)",
    url: "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=1798.130&lawCode=CIV",
    retrieved_at: RETRIEVED_AT,
    present_patterns: [
      "categor(y|ies) of personal information",
      "personal information .{0,20}collect",
    ],
  },
  {
    key: "sources",
    label: "Categories of sources of personal information",
    citation: "11 CCR § 7011(e)",
    url: "https://leginfo.legislature.ca.gov/faces/codes_displayText.xhtml?division=1.&part=4.&title=1.81.&chapter=&article=",
    retrieved_at: RETRIEVED_AT,
    present_patterns: ["categor(y|ies) of sources", "sources .{0,30}personal information"],
  },
  {
    key: "business-purpose",
    label: "Business or commercial purpose for collecting, selling, or sharing",
    citation: "11 CCR § 7011(e)",
    url: "https://leginfo.legislature.ca.gov/faces/codes_displayText.xhtml?division=1.&part=4.&title=1.81.&chapter=&article=",
    retrieved_at: RETRIEVED_AT,
    present_patterns: ["business.{0,5}purpose", "commercial purpose", "purpose.{0,20}collect"],
  },
  {
    key: "third-parties",
    label: "Categories of third parties to whom PI is disclosed",
    citation: "11 CCR § 7011(e)",
    url: "https://leginfo.legislature.ca.gov/faces/codes_displayText.xhtml?division=1.&part=4.&title=1.81.&chapter=&article=",
    retrieved_at: RETRIEVED_AT,
    present_patterns: ["third part(y|ies)", "categor(y|ies) of .{0,20}disclos"],
  },
  {
    key: "sold-shared-or-none",
    label: "Categories of PI sold/shared, or a statement that none is sold/shared",
    citation: "Cal. Civ. Code § 1798.130(a)(5)(C)",
    url: "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=1798.130&lawCode=CIV",
    retrieved_at: RETRIEVED_AT,
    present_patterns: [
      "sold or shared",
      "do not sell",
      "we do not sell",
      "not .{0,10}sell.{0,10}share",
    ],
  },
  {
    key: "consumer-rights",
    label: "Consumer rights: know, delete, correct, opt-out, limit, non-discrimination",
    citation: "Cal. Civ. Code § 1798.130(a)(5)(A)",
    url: "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=1798.130&lawCode=CIV",
    retrieved_at: RETRIEVED_AT,
    present_patterns: [
      "right to (know|access|delete|correct)",
      "your (privacy )?rights",
      "right to opt.?out",
    ],
  },
  {
    key: "correction-right",
    label: "Right to correct inaccurate personal information",
    citation: "Cal. Civ. Code § 1798.106",
    url: "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=1798.106&lawCode=CIV",
    retrieved_at: RETRIEVED_AT,
    present_patterns: [
      "right to correct",
      "correct .{0,20}inaccurate",
      "request .{0,10}correction",
    ],
  },
  {
    key: "request-methods",
    label: "Methods for submitting rights requests",
    citation: "11 CCR § 7011(e)",
    url: "https://leginfo.legislature.ca.gov/faces/codes_displayText.xhtml?division=1.&part=4.&title=1.81.&chapter=&article=",
    retrieved_at: RETRIEVED_AT,
    present_patterns: [
      "submit a request",
      "to exercise .{0,20}right",
      "toll.?free",
      "verify(ing)? your",
    ],
  },
  {
    key: "opt-out-link",
    label: "Do Not Sell or Share My Personal Information link / opt-out mechanism",
    citation: "11 CCR § 7011(e)",
    url: "https://leginfo.legislature.ca.gov/faces/codes_displayText.xhtml?division=1.&part=4.&title=1.81.&chapter=&article=",
    retrieved_at: RETRIEVED_AT,
    present_patterns: [
      "do not sell or share my personal information",
      "opt.?out .{0,10}(link|preference)",
      "limit the use",
    ],
  },
  {
    key: "sensitive-pi",
    label: "Sensitive personal information: categories + right to limit",
    citation: "11 CCR § 7011(e)",
    url: "https://leginfo.legislature.ca.gov/faces/codes_displayText.xhtml?division=1.&part=4.&title=1.81.&chapter=&article=",
    retrieved_at: RETRIEVED_AT,
    present_patterns: [
      "sensitive personal information",
      "right to limit",
      "limit the use of .{0,20}sensitive",
    ],
  },
  {
    key: "last-updated",
    label: "Date the notice was last updated",
    citation: "11 CCR § 7011(e)",
    url: "https://leginfo.legislature.ca.gov/faces/codes_displayText.xhtml?division=1.&part=4.&title=1.81.&chapter=&article=",
    retrieved_at: RETRIEVED_AT,
    present_patterns: [
      "last updated",
      "effective date",
      "last revised",
      "date of .{0,10}(last )?revision",
    ],
  },
  {
    key: "contact",
    label: "Contact information for privacy questions",
    citation: "11 CCR § 7011(e)",
    url: "https://leginfo.legislature.ca.gov/faces/codes_displayText.xhtml?division=1.&part=4.&title=1.81.&chapter=&article=",
    retrieved_at: RETRIEVED_AT,
    present_patterns: ["contact us", "privacy@", "questions .{0,20}privacy", "data protection"],
  },
];

const GDPR_13_ITEMS: ContentItem[] = [
  {
    key: "controller-identity",
    label: "Identity and contact details of the controller",
    citation: "GDPR Art. 13(1)(a)",
    url: "https://gdpr-info.eu/art-13-gdpr/",
    retrieved_at: RETRIEVED_AT,
    present_patterns: ["data controller", "controller.{0,20}(identity|contact)", "who we are"],
  },
  {
    key: "dpo-contact",
    label: "Contact details of the Data Protection Officer",
    citation: "GDPR Art. 13(1)(b)",
    url: "https://gdpr-info.eu/art-13-gdpr/",
    retrieved_at: RETRIEVED_AT,
    present_patterns: ["data protection officer", "\\bDPO\\b"],
  },
  {
    key: "purposes-legal-basis",
    label: "Purposes of processing and the legal basis",
    citation: "GDPR Art. 13(1)(c)",
    url: "https://gdpr-info.eu/art-13-gdpr/",
    retrieved_at: RETRIEVED_AT,
    present_patterns: ["legal basis", "purpose(s)? of (the )?processing", "lawful basis"],
  },
  {
    key: "legitimate-interests",
    label: "Legitimate interests pursued (where that is the basis)",
    citation: "GDPR Art. 13(1)(d)",
    url: "https://gdpr-info.eu/art-13-gdpr/",
    retrieved_at: RETRIEVED_AT,
    present_patterns: ["legitimate interest"],
  },
  {
    key: "recipients",
    label: "Recipients or categories of recipients",
    citation: "GDPR Art. 13(1)(e)",
    url: "https://gdpr-info.eu/art-13-gdpr/",
    retrieved_at: RETRIEVED_AT,
    present_patterns: ["recipient(s)?", "categor(y|ies) of recipient", "who we share"],
  },
  {
    key: "transfers",
    label: "International transfers and safeguards",
    citation: "GDPR Art. 13(1)(f)",
    url: "https://gdpr-info.eu/art-13-gdpr/",
    retrieved_at: RETRIEVED_AT,
    present_patterns: [
      "international transfer",
      "transfer .{0,20}outside",
      "standard contractual clause",
      "adequacy decision",
    ],
  },
  {
    key: "retention",
    label: "Retention period or criteria",
    citation: "GDPR Art. 13(2)(a)",
    url: "https://gdpr-info.eu/art-13-gdpr/",
    retrieved_at: RETRIEVED_AT,
    present_patterns: ["retention period", "how long .{0,20}(keep|retain)", "retain .{0,20}data"],
  },
  {
    key: "data-subject-rights",
    label: "Rights: access, rectification, erasure, restriction, objection, portability",
    citation: "GDPR Art. 13(2)(b)",
    url: "https://gdpr-info.eu/art-13-gdpr/",
    retrieved_at: RETRIEVED_AT,
    present_patterns: [
      "right to (access|rectification|erasure|object|restrict)",
      "right to be forgotten",
      "data portability",
    ],
  },
  {
    key: "withdraw-consent",
    label: "Right to withdraw consent",
    citation: "GDPR Art. 13(2)(c)",
    url: "https://gdpr-info.eu/art-13-gdpr/",
    retrieved_at: RETRIEVED_AT,
    present_patterns: ["withdraw .{0,10}consent", "withdraw your consent"],
  },
  {
    key: "lodge-complaint",
    label: "Right to lodge a complaint with a supervisory authority",
    citation: "GDPR Art. 13(2)(d)",
    url: "https://gdpr-info.eu/art-13-gdpr/",
    retrieved_at: RETRIEVED_AT,
    present_patterns: ["lodge a complaint", "supervisory authority", "data protection authority"],
  },
  {
    key: "statutory-requirement",
    label: "Whether provision is statutory/contractual and consequences",
    citation: "GDPR Art. 13(2)(e)",
    url: "https://gdpr-info.eu/art-13-gdpr/",
    retrieved_at: RETRIEVED_AT,
    present_patterns: [
      "obliged to provide",
      "statutory .{0,10}requirement",
      "consequence.{0,20}(fail|not provid)",
    ],
  },
  {
    key: "automated-decisions",
    label: "Existence of automated decision-making / profiling",
    citation: "GDPR Art. 13(2)(f)",
    url: "https://gdpr-info.eu/art-13-gdpr/",
    retrieved_at: RETRIEVED_AT,
    present_patterns: ["automated decision", "profiling", "automated processing"],
  },
];

/** Art. 14 omits the withdraw-consent and statutory-requirement items. */
const GDPR_14_OMITTED_KEYS = new Set(["withdraw-consent", "statutory-requirement"]);

/** Art. 14-specific items, on top of the shared Art. 13 items above. */
const GDPR_14_EXTRA_ITEMS: ContentItem[] = [
  {
    key: "data-categories",
    label: "Categories of personal data",
    citation: "GDPR Art. 14(1)(d)",
    url: "https://gdpr-info.eu/art-14-gdpr/",
    retrieved_at: RETRIEVED_AT,
    present_patterns: ["categor(y|ies) of (personal )?data"],
  },
  {
    key: "data-source",
    label: "Source of the personal data",
    citation: "GDPR Art. 14(2)(f)",
    url: "https://gdpr-info.eu/art-14-gdpr/",
    retrieved_at: RETRIEVED_AT,
    present_patterns: [
      "source of .{0,10}(the )?(personal )?data",
      "obtained .{0,20}from",
      "where we (got|obtained)",
    ],
  },
];

const GDPR_14_ITEMS: ContentItem[] = [
  ...GDPR_13_ITEMS.filter((item) => !GDPR_14_OMITTED_KEYS.has(item.key)),
  ...GDPR_14_EXTRA_ITEMS,
];

// ---------------------------------------------------------------------------
// State-law regimes (follow-up to the CCPA/GDPR launch). Statutory notice
// lists only, verified against the primary source (or a faithful mirror of
// it) on the retrieval date below.
// ---------------------------------------------------------------------------

const STATE_RETRIEVED_AT = "2026-07-17";

const CO_RULES_URL = "https://www.law.cornell.edu/regulations/colorado/4-CCR-904-3-6.03";

const CO_URL =
  "https://law.justia.com/codes/colorado/title-6/fair-trade-and-restraint-of-trade/article-1/part-13/section-6-1-1308/";

/** C.R.S. § 6-1-1308(1)(a)(I)–(V) — Colorado Privacy Act privacy notice. */
const CO_ITEMS: ContentItem[] = [
  {
    key: "categories-processed",
    label: "Categories of personal data collected or processed",
    citation: "C.R.S. § 6-1-1308(1)(a)(I)",
    url: CO_URL,
    retrieved_at: STATE_RETRIEVED_AT,
    present_patterns: [
      "categor(y|ies) of personal (data|information)",
      "personal (data|information) .{0,30}(collect|process)",
    ],
  },
  {
    key: "purposes",
    label: "Purposes for which the categories of personal data are processed",
    citation: "C.R.S. § 6-1-1308(1)(a)(II)",
    url: CO_URL,
    retrieved_at: STATE_RETRIEVED_AT,
    present_patterns: [
      "purpose(s)? (for|of) .{0,30}process",
      "purpose.{0,20}(collect|process)",
      "why we (collect|process|use)",
    ],
  },
  {
    key: "rights-and-appeal",
    label: "How and where to exercise consumer rights, contact information, and how to appeal",
    citation: "C.R.S. § 6-1-1308(1)(a)(III)",
    url: CO_URL,
    retrieved_at: STATE_RETRIEVED_AT,
    present_patterns: [
      "exercise .{0,30}rights",
      "right to (know|access|delete|correct|opt)",
      "\\bappeal\\b",
    ],
  },
  {
    key: "shared-categories",
    label: "Categories of personal data shared with third parties, if any",
    citation: "C.R.S. § 6-1-1308(1)(a)(IV)",
    url: CO_URL,
    retrieved_at: STATE_RETRIEVED_AT,
    present_patterns: [
      "shar(e|es|ed|ing) .{0,40}third part",
      "third part(y|ies).{0,40}shar",
      "do not share",
    ],
  },
  {
    key: "third-party-categories",
    label: "Categories of third parties, if any, with whom personal data is shared",
    citation: "C.R.S. § 6-1-1308(1)(a)(V)",
    url: CO_URL,
    retrieved_at: STATE_RETRIEVED_AT,
    present_patterns: ["categor(y|ies) of third part", "third part(y|ies)"],
  },
  // CPA regulation items (4 CCR 904-3 Rule 6.03, eff. 2023-07-01) that add
  // content beyond the statutory list above. The rule's CONDITIONAL items —
  // profiling disclosures per Rule 9.03 (6.03(A)(2)) and sensitive-data-
  // inference deletion per Rule 6.10 (6.03(A)(5)) — are intentionally
  // omitted: an unconditional presence rule cannot know whether a controller
  // profiles or draws such inferences, so demanding them of every notice
  // would be a false positive for controllers that do neither.
  {
    key: "sale-targeted-ads-profiling",
    label: "Whether personal data is sold or used for targeted advertising or profiling",
    citation: "4 CCR 904-3, Rule 6.03(A)(1)(c)",
    url: CO_RULES_URL,
    retrieved_at: STATE_RETRIEVED_AT,
    present_patterns: [
      "targeted advertising",
      "profiling",
      "\\bsell\\b.{0,40}personal (data|information)",
      "do not sell",
    ],
  },
  {
    key: "request-methods",
    label: "Methods through which a consumer may submit data-rights requests",
    citation: "4 CCR 904-3, Rule 6.03(A)(4)",
    url: CO_RULES_URL,
    retrieved_at: STATE_RETRIEVED_AT,
    present_patterns: [
      "submit a request",
      "to exercise .{0,30}right",
      "method(s)? .{0,30}request",
      "toll.?free",
    ],
  },
  {
    key: "contact-info",
    label: "Controller contact information",
    citation: "4 CCR 904-3, Rule 6.03(A)(6)",
    url: CO_RULES_URL,
    retrieved_at: STATE_RETRIEVED_AT,
    present_patterns: ["contact us", "privacy@", "e-?mail .{0,20}(address|us)", "mailing address"],
  },
  {
    key: "last-updated",
    label: "Date the privacy notice was last updated",
    citation: "4 CCR 904-3, Rule 6.03(A)(8)",
    url: CO_RULES_URL,
    retrieved_at: STATE_RETRIEVED_AT,
    present_patterns: ["last updated", "effective date", "last revised"],
  },
];

const VA_URL = "https://law.lis.virginia.gov/vacode/title59.1/section59.1-578/";

/** Va. Code § 59.1-578(C)(1)–(5) — VCDPA privacy notice. */
const VA_ITEMS: ContentItem[] = [
  {
    key: "categories-processed",
    label: "Categories of personal data processed by the controller",
    citation: "Va. Code § 59.1-578(C)(1)",
    url: VA_URL,
    retrieved_at: STATE_RETRIEVED_AT,
    present_patterns: [
      "categor(y|ies) of personal (data|information)",
      "personal (data|information) .{0,30}(collect|process)",
    ],
  },
  {
    key: "purposes",
    label: "Purpose for processing personal data",
    citation: "Va. Code § 59.1-578(C)(2)",
    url: VA_URL,
    retrieved_at: STATE_RETRIEVED_AT,
    present_patterns: [
      "purpose(s)? (for|of) .{0,30}process",
      "purpose.{0,20}(collect|process)",
      "why we (collect|process|use)",
    ],
  },
  {
    key: "rights-and-appeal",
    label: "How consumers may exercise their rights, including how to appeal a decision",
    citation: "Va. Code § 59.1-578(C)(3)",
    url: VA_URL,
    retrieved_at: STATE_RETRIEVED_AT,
    present_patterns: [
      "exercise .{0,30}rights",
      "right to (know|access|delete|correct|opt)",
      "\\bappeal\\b",
    ],
  },
  {
    key: "shared-categories",
    label: "Categories of personal data shared with third parties, if any",
    citation: "Va. Code § 59.1-578(C)(4)",
    url: VA_URL,
    retrieved_at: STATE_RETRIEVED_AT,
    present_patterns: [
      "shar(e|es|ed|ing) .{0,40}third part",
      "third part(y|ies).{0,40}shar",
      "do not share",
    ],
  },
  {
    key: "third-party-categories",
    label: "Categories of third parties, if any, with whom personal data is shared",
    citation: "Va. Code § 59.1-578(C)(5)",
    url: VA_URL,
    retrieved_at: STATE_RETRIEVED_AT,
    present_patterns: ["categor(y|ies) of third part", "third part(y|ies)"],
  },
];

const TX_URL = "https://statutes.capitol.texas.gov/Docs/BC/htm/BC.541.htm";

/**
 * Tex. Bus. & Com. Code § 541.102(b)–(c) mandated notice texts (TDPSA),
 * quoted verbatim from the statute. The exact-wording rules match these
 * whitespace-normalized and case-sensitively — an altered rendering is
 * reported as "present but altered", never silently accepted.
 */
export const TX_SENSITIVE_SALE_NOTICE = "NOTICE: We may sell your sensitive personal data.";
export const TX_BIOMETRIC_SALE_NOTICE = "NOTICE: We may sell your biometric personal data.";

/** Tex. Bus. & Com. Code § 541.102(a)(1)–(6) — TDPSA privacy notice. */
const TX_ITEMS: ContentItem[] = [
  {
    key: "categories-processed",
    label: "Categories of personal data processed, including any sensitive data",
    citation: "Tex. Bus. & Com. Code § 541.102(a)(1)",
    url: TX_URL,
    retrieved_at: STATE_RETRIEVED_AT,
    present_patterns: [
      "categor(y|ies) of personal (data|information)",
      "personal (data|information) .{0,30}(collect|process)",
    ],
  },
  {
    key: "purposes",
    label: "Purpose for processing personal data",
    citation: "Tex. Bus. & Com. Code § 541.102(a)(2)",
    url: TX_URL,
    retrieved_at: STATE_RETRIEVED_AT,
    present_patterns: [
      "purpose(s)? (for|of) .{0,30}process",
      "purpose.{0,20}(collect|process)",
      "why we (collect|process|use)",
    ],
  },
  {
    key: "rights-and-appeal",
    label: "How consumers may exercise their rights, including how to appeal a decision",
    citation: "Tex. Bus. & Com. Code § 541.102(a)(3)",
    url: TX_URL,
    retrieved_at: STATE_RETRIEVED_AT,
    present_patterns: [
      "exercise .{0,30}rights",
      "right to (know|access|delete|correct|opt)",
      "\\bappeal\\b",
    ],
  },
  {
    key: "shared-categories",
    label: "Categories of personal data shared with third parties, if any",
    citation: "Tex. Bus. & Com. Code § 541.102(a)(4)",
    url: TX_URL,
    retrieved_at: STATE_RETRIEVED_AT,
    present_patterns: [
      "shar(e|es|ed|ing) .{0,40}third part",
      "third part(y|ies).{0,40}shar",
      "do not share",
    ],
  },
  {
    key: "third-party-categories",
    label: "Categories of third parties, if any, with whom personal data is shared",
    citation: "Tex. Bus. & Com. Code § 541.102(a)(5)",
    url: TX_URL,
    retrieved_at: STATE_RETRIEVED_AT,
    present_patterns: ["categor(y|ies) of third part", "third part(y|ies)"],
  },
  {
    key: "request-methods",
    label: "Description of the methods for submitting consumer rights requests (§ 541.055)",
    citation: "Tex. Bus. & Com. Code § 541.102(a)(6)",
    url: TX_URL,
    retrieved_at: STATE_RETRIEVED_AT,
    present_patterns: [
      "submit a request",
      "to exercise .{0,30}right",
      "method(s)? .{0,30}request",
      "toll.?free",
    ],
  },
];

const OR_URL = "https://oregon.public.law/statutes/ors_646a.578";

/** ORS 646A.578(4)(a)–(i) — Oregon Consumer Privacy Act privacy notice. */
const OR_ITEMS: ContentItem[] = [
  {
    key: "categories-processed",
    label: "Categories of personal data processed, including categories of sensitive data",
    citation: "ORS 646A.578(4)(a)",
    url: OR_URL,
    retrieved_at: STATE_RETRIEVED_AT,
    present_patterns: [
      "categor(y|ies) of personal (data|information)",
      "personal (data|information) .{0,30}(collect|process)",
    ],
  },
  {
    key: "purposes",
    label: "Purposes for processing the personal data",
    citation: "ORS 646A.578(4)(b)",
    url: OR_URL,
    retrieved_at: STATE_RETRIEVED_AT,
    present_patterns: [
      "purpose(s)? (for|of) .{0,30}process",
      "purpose.{0,20}(collect|process)",
      "why we (collect|process|use)",
    ],
  },
  {
    key: "rights-and-appeal",
    label: "How consumers may exercise their rights, including how to appeal a decision",
    citation: "ORS 646A.578(4)(c)",
    url: OR_URL,
    retrieved_at: STATE_RETRIEVED_AT,
    present_patterns: [
      "exercise .{0,30}rights",
      "right to (know|access|delete|correct|opt)",
      "\\bappeal\\b",
    ],
  },
  {
    key: "shared-categories",
    label: "Categories of personal data, including sensitive data, shared with third parties",
    citation: "ORS 646A.578(4)(d)",
    url: OR_URL,
    retrieved_at: STATE_RETRIEVED_AT,
    present_patterns: [
      "shar(e|es|ed|ing) .{0,40}third part",
      "third part(y|ies).{0,40}shar",
      "do not share",
    ],
  },
  {
    key: "third-party-detail",
    label:
      "Categories of third parties, at a level of detail that lets the consumer understand what type of entity each is and how it may process personal data",
    citation: "ORS 646A.578(4)(e)",
    url: OR_URL,
    retrieved_at: STATE_RETRIEVED_AT,
    present_patterns: [
      "categor(y|ies) of third part.{0,80}(type|kind) of",
      "third part(y|ies).{0,60}(process|use) .{0,20}(personal )?(data|information)",
      "type of entity",
    ],
  },
  {
    key: "contact-method",
    label: "Email address or other online method for contacting the controller",
    citation: "ORS 646A.578(4)(f)",
    url: OR_URL,
    retrieved_at: STATE_RETRIEVED_AT,
    present_patterns: ["contact us", "privacy@", "e-?mail .{0,20}(address|us)", "electronic mail"],
  },
  {
    key: "controller-identity",
    label: "Identity of the controller, including any registered business name",
    citation: "ORS 646A.578(4)(g)",
    url: OR_URL,
    retrieved_at: STATE_RETRIEVED_AT,
    present_patterns: [
      "who we are",
      "doing business as",
      "registered .{0,40}secretary of state",
      "\\b(inc\\.|llc|ltd\\.?|corporation)\\b",
    ],
  },
  {
    key: "targeted-ads-profiling",
    label:
      "Clear and conspicuous description of targeted advertising or profiling processing, and how to opt out",
    citation: "ORS 646A.578(4)(h)",
    url: OR_URL,
    retrieved_at: STATE_RETRIEVED_AT,
    present_patterns: [
      "targeted advertising",
      "profiling",
      "opt.?out .{0,40}(targeted|profil|sale)",
    ],
  },
  {
    key: "request-methods",
    label: "Methods established for a consumer to submit a rights request",
    citation: "ORS 646A.578(4)(i)",
    url: OR_URL,
    retrieved_at: STATE_RETRIEVED_AT,
    present_patterns: [
      "submit a request",
      "to exercise .{0,30}right",
      "method(s)? .{0,30}request",
      "toll.?free",
    ],
  },
];

export const REGIMES: Readonly<Record<RegimeId, Regime>> = Object.freeze({
  ccpa: {
    id: "ccpa",
    name: "CCPA/CPRA privacy policy",
    authority_url:
      "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=1798.130&lawCode=CIV",
    items: CCPA_ITEMS,
  },
  "gdpr-13": {
    id: "gdpr-13",
    name: "GDPR Article 13 (data from the data subject)",
    authority_url: "https://gdpr-info.eu/art-13-gdpr/",
    items: GDPR_13_ITEMS,
  },
  "gdpr-14": {
    id: "gdpr-14",
    name: "GDPR Article 14 (data not from the data subject)",
    authority_url: "https://gdpr-info.eu/art-14-gdpr/",
    items: GDPR_14_ITEMS,
  },
  co: {
    id: "co",
    name: "Colorado Privacy Act notice (C.R.S. § 6-1-1308(1)(a))",
    authority_url: CO_URL,
    items: CO_ITEMS,
  },
  va: {
    id: "va",
    name: "Virginia CDPA notice (Va. Code § 59.1-578(C))",
    authority_url: VA_URL,
    items: VA_ITEMS,
  },
  tx: {
    id: "tx",
    name: "Texas DPSA notice (Tex. Bus. & Com. Code § 541.102)",
    authority_url: TX_URL,
    items: TX_ITEMS,
  },
  or: {
    id: "or",
    name: "Oregon OCPA notice (ORS 646A.578(4))",
    authority_url: OR_URL,
    items: OR_ITEMS,
  },
});

/** Look up a shipped regime by id, or `undefined` if unknown. */
export function getRegime(id: RegimeId): Regime | undefined {
  return REGIMES[id];
}
