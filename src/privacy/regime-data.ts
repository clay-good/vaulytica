/**
 * Privacy-notice content-item data — cited, versioned data behind the
 * privacy-notice-linter pack (add-privacy-notice-pack). Each regime carries
 * an enumerated list of required content items, and each item carries a
 * stable key, its citation, source URL, retrieval date, and the regex
 * patterns (source strings, applied case-insensitively) that indicate the
 * item IS present in a notice.
 *
 * Scope: CCPA/CPRA and GDPR Articles 13 and 14 only. State-law regimes
 * (Texas, Colorado, Virginia, Oregon) are a separate change.
 *
 * Data, not code: content changes are additions to this file, never silent
 * edits to shipped citations.
 */

export type RegimeId = "ccpa" | "gdpr-13" | "gdpr-14";

export const REGIME_IDS: readonly RegimeId[] = ["ccpa", "gdpr-13", "gdpr-14"];

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
    present_patterns: ["categor(y|ies) of personal information", "personal information .{0,20}collect"],
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
    present_patterns: ["sold or shared", "do not sell", "we do not sell", "not .{0,10}sell.{0,10}share"],
  },
  {
    key: "consumer-rights",
    label: "Consumer rights: know, delete, correct, opt-out, limit, non-discrimination",
    citation: "Cal. Civ. Code § 1798.130(a)(5)(A)",
    url: "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=1798.130&lawCode=CIV",
    retrieved_at: RETRIEVED_AT,
    present_patterns: ["right to (know|access|delete|correct)", "your (privacy )?rights", "right to opt.?out"],
  },
  {
    key: "correction-right",
    label: "Right to correct inaccurate personal information",
    citation: "Cal. Civ. Code § 1798.106",
    url: "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=1798.106&lawCode=CIV",
    retrieved_at: RETRIEVED_AT,
    present_patterns: ["right to correct", "correct .{0,20}inaccurate", "request .{0,10}correction"],
  },
  {
    key: "request-methods",
    label: "Methods for submitting rights requests",
    citation: "11 CCR § 7011(e)",
    url: "https://leginfo.legislature.ca.gov/faces/codes_displayText.xhtml?division=1.&part=4.&title=1.81.&chapter=&article=",
    retrieved_at: RETRIEVED_AT,
    present_patterns: ["submit a request", "to exercise .{0,20}right", "toll.?free", "verify(ing)? your"],
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
    present_patterns: ["last updated", "effective date", "last revised", "date of .{0,10}(last )?revision"],
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
    present_patterns: ["obliged to provide", "statutory .{0,10}requirement", "consequence.{0,20}(fail|not provid)"],
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

export const REGIMES: Readonly<Record<RegimeId, Regime>> = Object.freeze({
  ccpa: {
    id: "ccpa",
    name: "CCPA/CPRA privacy policy",
    authority_url: "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=1798.130&lawCode=CIV",
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
});

/** Look up a shipped regime by id, or `undefined` if unknown. */
export function getRegime(id: RegimeId): Regime | undefined {
  return REGIMES[id];
}
