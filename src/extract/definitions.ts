import type { DocumentTree } from "../ingest/types.js";
import type { DefinitionMap, DefinitionEntry, DocPosition } from "./types.js";
import { forEachParagraph, forEachSection, posInParagraph } from "./walk.js";

/**
 * Find every defined term and every use of each. Two recognition paths:
 *
 * 1. Section-level: a section whose heading matches `definitions`,
 *    `defined terms`, or `glossary` is treated as a definitions section;
 *    each paragraph within is parsed for `"Term" means …` or
 *    `Term means …` definitions.
 * 2. Inline: anywhere in the document, `"Term" means …` (with explicit
 *    quotes) is treated as an inline definition.
 *
 * After collecting definitions, the document is re-scanned to record every
 * occurrence of each defined term *outside* its definition. Terms with
 * zero outside-uses populate {@link DefinitionMap.unused_terms}.
 *
 * Finally, Title-Case multi-word phrases that appear in the body but are
 * not defined (and are not party names) are recorded as
 * `undefined_capitalized`. The list is downstream input to STRUCT-006.
 */

// Case-insensitive on `means`: a quoted term followed by "Means"/"MEANS" (common
// after a list marker, in ALL-CAPS drafting, or from OCR) is still a definition;
// without the `i` flag the whole defined term was silently dropped from
// STRUCT-004/005/006 and the definitions appendix. The quoted-term requirement
// keeps this from matching an ordinary sentence that merely contains "means".
//
// The `(?:, as/when used …,)?` aside covers the dominant drafting form that
// interposes a scope clause between the quoted term and its defining verb —
// `"Confidential Information", as used herein, means …`, `"Purchase Price",
// when used in this Agreement, means …`. Without it the closing quote was no
// longer adjacent to `means`, the term went unregistered, and STRUCT-006
// reported it as used-but-undefined. The aside is comma-anchored on
// "as/when used" and bounded by `[^,.]` so it cannot cross a sentence.
// `will` joins `shall` as an optional modal — modern drafting writes
// `"Renewal Window" will mean …` as often as `shall mean`.
//
// The quoted-term class carries `.` (and `/`, `'`) like its sibling patterns
// below: a defined term is often an abbreviation with an internal period —
// `"U.S. Person" means …`, `"U.K. Subsidiary" means …`, `"No. 5 Warehouse"
// means …` — and the bare `[\w\s\-&]` class stopped the term at the first
// period, so the closing quote never lined up and the whole definition was
// dropped (STRUCT-006 then reported the term as used-but-undefined). Safe
// because the term is quote-bounded: a period can only sit BETWEEN the quotes.
const DEFINITION_INLINE =
  /["“”']([A-Z][\w\s\-&/'’.]{1,80}?)["“”']\s*(?:,\s*(?:as|when)\s+used\b[^,.]{0,40},\s*)?(?:shall\s+|will\s+)?means?\b/gi;
// The other inline defining verbs — `"Effective Date" refers to …`, `"Territory"
// is defined as …`, `"Deliverables" shall refer to …`. DEFINITION_INLINE knows
// only "means"/"shall mean", so these terms went unregistered and STRUCT-006
// reported them as used-but-undefined. The optional `collectively` adverb
// covers the multi-instrument idiom `The "Transaction Documents" collectively
// refer to …`, where the adverb pushed "refer to" off the anchor. The
// `defined` branch also reads `is hereby defined to mean`, `shall be defined
// as`, and `is defined to include` — the modal/adverb variants of the plain
// `is defined as` form.
const DEFINITION_INLINE_REFERS =
  /["“”']([A-Z][\w\s\-&/'’.]{1,80}?)["“”']\s+(?:(?:shall|will)\s+)?(?:collectively\s+)?(?:refers?\s+to|denotes?|(?:(?:is|are)(?:\s+hereby)?|shall\s+be|will\s+be)\s+defined\s+(?:as|to\s+(?:mean|include)\b))/gi;
// A term defined by a plain COPULA and a value — `The "Valuation Cap" is
// $12,000,000`, `The "Discount Rate" is twenty percent (20%)`, `The "Cure
// Period" shall be ten (10) business days`. This is ordinary drafting for a
// term whose definition is a single number, and none of the "means" / "refers
// to" / "is defined as" matchers see it, so STRUCT-006 reported the term as
// used-but-undefined on documents that define it perfectly well. Gated three
// ways so a quoted USAGE is not swept in as a definition: the term is quoted,
// it is introduced by "The", and a NUMBER has to follow within a short window
// — which is what makes it a value rather than a comment about the term. `g`,
// not `gi`: under the `i` flag `[A-Z]` matches lowercase too, so the leading
// article is matched explicitly instead.
const DEFINITION_INLINE_COPULA =
  /\b[Tt]he\s+["“”']([A-Z][\w\s\-&/'’.]{1,80}?)["“”']\s+(?:is|are|shall\s+be|will\s+be)\s+(?=[^.]{0,60}?(?:[$€£¥₹]\s?\d|\b\d))/g;
// A period / term defined by its BOUNDS rather than by "means" — `The "Tolling
// Period" shall begin on the Effective Date and shall continue until …`, `the
// "Restricted Period" shall commence on the Closing`. The quoted term is the
// definitional marker; the loop keeps only a term ending in Period/Term (a
// bounded temporal defined term) so an ordinary quoted usage is not swept in.
const DEFINITION_INLINE_PERIOD =
  /["“”']([A-Z][\w\s\-&/'’.]{1,60}?)["“”']\s+(?:shall|will)\s+(?:begin|commence|start|run)\b/gi;
// A role a party occupies CONDITIONALLY — "each party may act as a 'Disclosing
// Party' when it discloses … and as a 'Receiving Party' when it receives". Both
// parties share each role, so it is never introduced with a "(the 'X')"
// parenthetical or "means"; the quoted term followed by "when it/the/such …" is
// the definition. This is the mutual-NDA idiom STRUCT-006 flagged as undefined.
const DEFINITION_ROLE_WHEN =
  /["“”']([A-Z][\w\s\-&/'’.]{1,40}?)["“”']\s+when\s+(?:it|the|such|either|each|a\s+party)\b/gi;
// The bare (unquoted) glossary form carries the period in its term class for the
// same reason the quoted matchers do — "U.S. Person means …", "Non-U.S. Holder
// means …" are unquoted defined terms in interpretation sections. This matcher
// only runs inside a Definitions/Interpretation section (see Pass 1), so a
// numbered-cross-reference line like "Section 4.2 means …" is not a realistic
// false positive here.
const DEFINITION_BARE = /^\s*([A-Z][\w\s\-&.]{1,80}?)\s+(?:shall\s+)?means?\b/i;
// A pure glossary entry inside a Definitions/Glossary section: a quoted term at
// the START of the paragraph, then a colon or dash, then its definition — with
// no "means"/"refers to" verb (`"Delivery Point": the loading dock`, `"Term" —
// the laws of Delaware`). Common in definition schedules and data-processing
// addenda. Used ONLY in Pass 1 (section-scoped) and anchored at paragraph start
// so an ordinary mid-sentence quotation followed by a colon is not swept in.
const GLOSSARY_ENTRY = /^\s*["“”']([A-Z][\w\s\-&/'’.]{1,80}?)["“”']\s*[:—–]\s+\S/;

/**
 * The double-alias definition: `"Protected Health Information" or "PHI"
 * means …`. DEFINITION_INLINE requires `means` right after the closing
 * quote, so only the SECOND term registered and the first — the term the
 * document then uses everywhere — was reported by STRUCT-006 as never
 * defined. Both names name the same definition.
 */
const DEFINITION_ALIASED =
  /["“”']([A-Z][\w\s\-&/'’.]{1,80}?)["“”']\s+or\s+["“”']([A-Z][\w\s\-&/'’.]{1,60}?)["“”']\s+(?:shall\s+)?means?\b/gi;

/**
 * The other inline convention, and the dominant one in commercial drafting:
 * the term is introduced by a parenthetical after the phrase it names —
 * `Acme Corp, a Delaware corporation ("Customer")`, `any Statement of Work
 * ("SOW")`, `its pre-existing tools and methodologies ("Vendor Background
 * IP")`. Recognizing only `"Term" means …` made STRUCT-004 report "Vaulytica
 * did not find a Definitions section or any inline-defined terms" on 15 of the
 * 19 minimal-PASS fixtures, every one of which defines its terms this way.
 *
 * The closing `)` must follow the quote immediately, so a quoted phrase used
 * mid-parenthetical (`(the "Services" described in Exhibit A)`) is not read as
 * a definition.
 *
 * The article may sit INSIDE the quotes as readily as outside — `("the Firm")`,
 * `("the Client")` — which is the dominant convention in UK drafting and common
 * in US practice. Requiring the quote to open on a capital missed all of them,
 * so a contingency fee agreement that defines both its parties in its first
 * sentence was reported as having no defined terms at all. The article is not
 * part of the term: the body writes "the Firm", and the term is "Firm".
 */
const DEFINITION_PARENTHETICAL =
  /\((?:\s*(?:the|this|these|each|an?|collectively|together|individually|hereinafter|referred\s+to\s+as|THE|THIS|THESE|EACH|AN?|COLLECTIVELY|TOGETHER|INDIVIDUALLY|HEREINAFTER|REFERRED\s+TO\s+AS)[,]?\s+)*["\u201C](?:(?:[Tt]he|[Tt]his|[Aa]n?)\s+)?([A-Z][\w\s\-&/'’\u2019.]{1,60}?)["\u201D]\s*\)/g;

/**
 * The paired collective/individual parenthetical \u2014 the party-definition idiom
 * DEFINITION_PARENTHETICAL cannot see because its first quoted term is not
 * immediately followed by `)`:
 *
 *   `(each a "Limited Partner" and, together with the General Partner, the "Partners")`
 *   `(individually a "Party" and collectively the "Parties")`
 *   `(the "Company" and, together with its subsidiaries, the "Group")`
 *
 * BOTH quoted names are defined terms. The two-quoted-terms requirement plus a
 * collective/individual connective between them keeps this off a single term
 * used mid-parenthetical (`(the "Services" described in Exhibit A)` \u2014 one quote,
 * no pairing connective). Without it, STRUCT-006 flagged the individual term
 * ("Limited Partner", "Party") and often the collective ("Partners") as
 * used-but-never-defined.
 */
const DEFINITION_PAIR_PARENTHETICAL =
  /\((?:\s*(?:the|this|these|each|an?|collectively|together|individually|severally|hereinafter|THE|THIS|THESE|EACH|AN?|COLLECTIVELY|TOGETHER|INDIVIDUALLY|SEVERALLY|HEREINAFTER)[,]?\s+)*["\u201C]([A-Z][\w\s\-&/'’\u2019.]{1,60}?)["\u201D][\s,]+and\b[^)]*?\b(?:collectively|together|individually|each|severally)\b[^)]*?\bthe\s+["\u201C]([A-Z][\w\s\-&/'’\u2019.]{1,60}?)["\u201D]\s*\)/g;

/**
 * A single defined term that trails a PROSE preamble inside its parenthetical:
 *
 *   `the sum of $2,000,000 (together with all interest and earnings thereon,
 *    the "Escrow Fund")`
 *   `Meridian, Inc. (as defined in Section 3, the "Company")`
 *
 * DEFINITION_PARENTHETICAL only tolerates a whitelist of lead-in words before
 * the quoted term, so an appositive that describes the term first ("together
 * with all interest and earnings thereon") strands the definition and
 * STRUCT-006 reports the term as undefined. The discriminating signal is a
 * comma followed by `the`/`collectively the`/`together the` immediately before
 * the quoted term at the close of the parenthetical; a quoted term merely USED
 * mid-parenthetical (`(a sum equal to the "Base Amount")`) has no such comma
 * and the `[^)"\u201C\u201D]*` run cannot cross another quote.
 */
const DEFINITION_TRAILING_PARENTHETICAL =
  /\([^)"\u201C\u201D]*,\s+(?:collectively\s+|together\s+|individually\s+)?the\s+["\u201C]([A-Z][\w\s\-&/'’\u2019.]{1,60}?)["\u201D]\s*\)/g;

/**
 * Meaning-by-reference: a term (or a list of terms) is defined by pointing at
 * another instrument's definition rather than stating one — the dominant
 * convention in DPAs and BAAs importing a statute's vocabulary:
 *
 *   `Personal Data, Data Subject, Processing, Controller and Processor shall
 *    have the meaning given in Article 4 GDPR.`
 *   `"Business Associate" shall have the meaning given to such term in
 *    45 CFR § 160.103.`
 *
 * Recognizing only `means …` left every such term unregistered: STRUCT-004
 * reported "no defined terms", STRUCT-006 flagged the terms as
 * used-but-undefined, and the capitalization rules never saw them at all.
 * The match anchors on the verb tail; the term list is parsed back from the
 * start of the sentence, so a fallback clause ("Capitalized terms not
 * otherwise defined herein shall have the meaning given in the MSA")
 * contributes nothing — its subject is not a Title-Case term list.
 * The tail tolerates periods inside numeric citations (`45 CFR § 160.103`).
 * The `same` adjective + `as` connector cover the statutory-import idiom
 * `"Controller" has the same meaning as in the GDPR` / `… as set forth in
 * the DPA`, which the participle-only verb list missed.
 */
const DEFINITION_MEANING_TAIL =
  /\b(?:shall\s+|will\s+)?(?:each\s+)?ha(?:ve|s)\s+the\s+(?:respective\s+|same\s+)?meanings?\s+(?:given|set\s+forth|set\s+out|ascribed|assigned|specified|defined|stated|as\s+(?:in|set|used|defined|given|ascribed|specified|that))\b(?:[^.;]|\.(?=\d))*/g;

/**
 * The derivative-form convention: `"Processing" means …, and "Process" and
 * "Processed" shall be construed accordingly.` The construed terms carry a
 * sibling definition's meaning — they are defined terms, not undefined
 * capitalized phrases.
 */
const DEFINITION_CONSTRUED_TAIL =
  /\b(?:shall|will|must|is\s+to|are\s+to)\s+(?:each\s+)?be\s+construed\s+accordingly\b/g;

/** A quoted Title-Case phrase inside a term list. */
const QUOTED_TERM = /["“]([A-Z][\w\s\-&/'’.]{0,60}?)["”]/g;

/**
 * A cover-block field label: `Issue Date: May 15, 2026` / `Principal
 * Amount: $500,000`. Term sheets, notes, and order forms constitute their
 * terms this way, and the body then uses them ("from the Issue Date") —
 * STRUCT-006 called every such term used-but-undefined. Ingest joins
 * adjacent cover lines into one paragraph, so a qualifying paragraph
 * (short, opening with a label) may carry several label:value pairs; each
 * value runs to the next label. Two-to-five Title-Case words per label, so
 * a signature block's "By:"/"Date:" or a notice's "Attn:" never registers.
 */
const FIELD_LABEL = /\b([A-Z][A-Za-z]*(?:\s+[A-Z][A-Za-z]*){1,4}):\s+/g;
const FIELD_BLOCK_MAX_LENGTH = 240;

/** A definition that points at an exhibit/schedule/section rather than stating its own text. */
const DEFINITION_REFERENCE =
  /\b(?:attached\s+(?:hereto\s+)?as|set\s+forth\s+in|described\s+in|defined\s+in|as\s+set\s+out\s+in|in)\s+((?:Exhibit|Schedule|Appendix|Annex|Attachment|Section|Article)\s+[A-Z0-9][\w.()-]*)/i;

/** A scope-gating prefix that confines a definition to a section/clause. */
const DEFINITION_SCOPE =
  /\b(?:for\s+(?:the\s+)?purposes\s+of|as\s+used\s+in|solely\s+for\s+purposes\s+of)\s+(?:this\s+)?((?:Section|Article|Clause|Paragraph)\s+[\w.()-]+)[,:\s]*$/i;

const DEFINITIONS_HEADING = /\b(definitions?|defined\s+terms|glossary|interpretation)\b/i;
// A hyphenated word is ONE word. Without that, "Dmitri Sokolov-Reyes" captured
// as "Dmitri Sokolov" — a name that matches nothing else in the document, so
// every signature-block and person guard missed it and the employee named on a
// performance improvement plan was reported as a term it forgot to define.
// "Non-Disclosure Agreement" was read as "Disclosure Agreement" for the same
// reason.
const TITLE_CASE_PHRASE =
  /\b((?:[A-Z][a-z]+(?:-[A-Z][a-z]+)*(?:\s+[A-Z][a-z]+(?:-[A-Z][a-z]+)*){1,4}))\b/g;

/**
 * Place names are proper nouns, never contractual defined terms. A
 * governing-law or address clause naming "New York" or "New Jersey" was
 * reported by STRUCT-006 as a Title-Case term "used but not defined" — a place
 * is not a term a contract defines. The two-word US states (New York, New
 * Jersey, New Mexico, New Hampshire, North/South Carolina/Dakota, West
 * Virginia, Rhode Island, District of Columbia) are the ones TITLE_CASE_PHRASE
 * captures as multi-word candidates; the single-word states never reach the
 * multi-word phrase list.
 */
/**
 * A time zone is a proper noun, never a contractual defined term.
 *
 * Every deadline in a purchase agreement, a discovery response, and a notice
 * clause is stated in one — "5:00 p.m. Eastern Time on the forty-fifth day" —
 * and the Title-Case run picks it up as a phrase the document uses twice and
 * never defines. Same class as the street-suffix and place-name guards below.
 */
const TIME_ZONE_NAMES = new Set([
  "Eastern Time",
  "Central Time",
  "Mountain Time",
  "Pacific Time",
  "Eastern Standard Time",
  "Central Standard Time",
  "Mountain Standard Time",
  "Pacific Standard Time",
  "Eastern Daylight Time",
  "Central Daylight Time",
  "Mountain Daylight Time",
  "Pacific Daylight Time",
  "Coordinated Universal Time",
  "Greenwich Mean Time",
  "Universal Time",
  "Local Time",
]);

const PLACE_NAMES = new Set([
  "New York",
  "New Jersey",
  "New Mexico",
  "New Hampshire",
  "North Carolina",
  "South Carolina",
  "North Dakota",
  "South Dakota",
  "West Virginia",
  "Rhode Island",
  "District of Columbia",
  "United States",
  "United Kingdom",
  "New York County",
  "New Castle County",
  "Los Angeles",
  "San Francisco",
  "Santa Clara",
  "Hong Kong",
  "England and Wales",
]);
const COMMON_WORDS = new Set([
  "Effective Date",
  "Agreement",
  "Section",
  "Article",
  "Exhibit",
  "Schedule",
  "Attachment",
  // Organizational units referenced by name ("report it to Human
  // Resources") — proper nouns, never document-defined terms.
  "Human Resources",
  "Legal Department",
  "Information Technology",
]);

/**
 * Proper-noun statute titles are the law's name, not a term the document
 * defines — bylaws cite "the General Corporation Law of the State of
 * Delaware" the way a contract cites "New York", and STRUCT-006 reported
 * the statute as "used but not defined". Same reasoning as PLACE_NAMES.
 */
const STATUTE_NAMES = new Set([
  "General Corporation Law",
  "Securities Act",
  "Securities Exchange Act",
  "Internal Revenue Code",
  "Uniform Commercial Code",
  "Code of Civil Procedure",
  "Fair Labor Standards Act",
  "National Labor Relations Act",
  // Named federal regulatory rules referenced by their term of art. They end in
  // "Rule", not "Act/Code/Law", so the suffix guard misses them, yet a BAA that
  // uses "Privacy Rule"/"Security Rule" is importing the HIPAA regulation's own
  // vocabulary (45 C.F.R. Parts 160/164), not leaving a term undefined. Every
  // BAA uses these without a definitions entry — flagging them told drafters to
  // define the CFR. Scoped to recognized named rules, not any "X Rule" phrase.
  "Privacy Rule",
  "Security Rule",
  "Breach Notification Rule",
  "Enforcement Rule",
  "Omnibus Rule",
  "Common Rule",
  "Red Flags Rule",
  "Volcker Rule",
]);

/**
 * Named institutions and legal terms of art that a contract uses as proper
 * nouns, never as terms it defines: "Internal Revenue Service", "Federal
 * Reserve", "New York Stock Exchange", "Force Majeure", "Generally Accepted
 * Accounting Principles". Their words run consecutively in Title Case, so —
 * unlike "Securities and Exchange Commission", which the lowercase "and" already
 * splits — TITLE_CASE_PHRASE captures them whole and, absent this list, reported
 * each as a Title-Case term the document uses twice but never defines. Keyed in
 * lowercase for a case-insensitive compare. Generic drafting terms that a
 * contract is EXPECTED to define ("Governmental Authority", "Material Adverse
 * Effect") are deliberately excluded, so a document that capitalizes them
 * without a definition is still flagged.
 */
const WELL_KNOWN_ENTITIES = new Set(
  [
    "Internal Revenue Service",
    "Federal Reserve",
    "Federal Trade Commission",
    "Federal Deposit Insurance Corporation",
    "Consumer Financial Protection Bureau",
    "Environmental Protection Agency",
    "Food and Drug Administration",
    "European Central Bank",
    "European Commission",
    "Financial Conduct Authority",
    "New York Stock Exchange",
    "Nasdaq Stock Market",
    "London Stock Exchange",
    "American Arbitration Association",
    "International Chamber of Commerce",
    "National Labor Relations Board",
    "United Nations",
    "World Health Organization",
    "Supreme Court",
    "Force Majeure",
    "Force Majeure Event",
    "Generally Accepted Accounting Principles",
    "International Financial Reporting Standards",
    "Standard Contractual Clauses",
    "Social Security",
    "Social Security Administration",
    // Geographic / political proper nouns whose consecutive Title-Case words
    // TITLE_CASE_PHRASE captures whole ("United States"/"New York" are already
    // in PLACE_NAMES; these are the ones it lacked).
    "European Union",
    "European Economic Area",
    "North America",
    "South America",
    "Great Britain",
    "Silicon Valley",
  ].map((s) => s.toLowerCase()),
);

/**
 * Corporate-office titles are designations, not defined terms: bylaws that
 * empower "the Chief Executive Officer" to call a special meeting have not
 * left a defined term undefined — the office is constituted by the officers
 * article, and every governance document capitalizes titles this way. Any
 * phrase ENDING in "Officer" is an office ("Compliance Officer", "Privacy
 * Officer", "Data Protection Officer") — offices are constituted by
 * appointment, not by a definitions section. The signature-block designations
 * ("Authorized Signatory", "Managing Partner") are the same: a title on the
 * "Title:" line an execution block, not a defined term, so they are covered
 * too.
 */
/**
 * US state names, for the named-public-body test. Two-word states already sit
 * in {@link PLACE_NAMES}; these are the single-word ones the phrase test needs
 * to recognize as a LEADING word rather than as the whole phrase.
 */
const US_STATE_NAMES = new Set([
  "Alabama",
  "Alaska",
  "Arizona",
  "Arkansas",
  "California",
  "Colorado",
  "Connecticut",
  "Delaware",
  "Florida",
  "Georgia",
  "Hawaii",
  "Idaho",
  "Illinois",
  "Indiana",
  "Iowa",
  "Kansas",
  "Kentucky",
  "Louisiana",
  "Maine",
  "Maryland",
  "Massachusetts",
  "Michigan",
  "Minnesota",
  "Mississippi",
  "Missouri",
  "Montana",
  "Nebraska",
  "Nevada",
  "Ohio",
  "Oklahoma",
  "Oregon",
  "Pennsylvania",
  "Tennessee",
  "Texas",
  "Utah",
  "Vermont",
  "Virginia",
  "Washington",
  "Wisconsin",
  "Wyoming",
]);

const OFFICER_TITLES =
  /^(?:[A-Z][\w\s]*\s(?:Officer|Committee)|(?:[A-Z][\w]*\s+)?Vice\s+President(?:,?\s+[A-Z][\w\s]*)?|(?:[A-Z][a-z]+\s+){0,2}General\s+Counsel|(?:Outside|In-?[Hh]ouse|Inside|Litigation|Regulatory|Corporate|Trial)\s+Counsel|Chair(?:person|man|woman)(?:\s+of\s+the\s+Board)?|Board\s+of\s+Directors|Managing\s+(?:Member|Director|Partner)|(?:General|Limited)\s+Partner|Authorized\s+(?:Signator(?:y|ies)|Representative|Person|Agent))$/;

/**
 * Sentence-initial words that are commonly capitalized but never
 * function as defined terms. Filtering by *first word* eliminates the
 * "Each Party," "If Client," "Neither Party" style false positives
 * that arose every time a sentence began with one of these words
 * followed by a capitalized noun. We match on the first word of the
 * candidate phrase, not on the full phrase, so legitimate phrases
 * like "Each Statement of Work" still fail this filter and so do
 * cases like "The Services" (where "The" is the leading stopword).
 */
/**
 * A signature-block label immediately before a name — "By: ", "By: /s/ ",
 * "Name: ", "Printed Name: ", or a bare conformed-signature mark.
 */
const SIGNATURE_LABEL_BEFORE =
  /(?:^|[\s|])(?:By|Name|Print(?:ed)?\s+Name|Signature|Signed)\s*:\s*(?:\/s\/\s*)?$|\/s\/\s*$/i;

const TITLE_CASE_LEADING_STOPWORDS = new Set([
  "Each",
  // "Every" sat beside "Each" in every drafter's vocabulary and not in this
  // list: "Every Owner is a member of the Association" was reported as a use
  // of an undefined term "Every Owner", on a declaration that defines "Owner"
  // in its first article. Its siblings are here for the same reason.
  "Every",
  "Certain",
  "Several",
  "Various",
  "Most",
  "Many",
  "If",
  "Neither",
  "Either",
  "Both",
  "All",
  "Any",
  "Some",
  "This",
  "These",
  "That",
  "Those",
  "The",
  "A",
  "An",
  "It",
  "He",
  "She",
  "They",
  "We",
  "You",
  "I",
  "Such",
  "Other",
  "Another",
  "No",
  "Not",
  "Nothing",
  "When",
  "Where",
  "While",
  "As",
  "For",
  "From",
  "In",
  "On",
  "Of",
  "To",
  "At",
  "Upon",
  "With",
  "By",
  "And",
  "Or",
  "But",
  "Nor",
  "So",
  "Yet",
  "After",
  "Before",
  "During",
  "Until",
  "Without",
  "Within",
  "Notwithstanding",
  "Provided",
  "Subject",
  "Including",
  "Furthermore",
  "Moreover",
  "Therefore",
  "However",
  "Otherwise",
  "Failure",
  "Each Party",
  "Either Party",
  "Neither Party",
  "Both Parties",
  "The Parties",
  "The Party",
]);

export function extractDefinitions(tree: DocumentTree): DefinitionMap {
  const definitions = new Map<string, DefinitionEntry>();

  // Pass 1: section-level definitions sections.
  forEachSection(tree, (section) => {
    if (!DEFINITIONS_HEADING.test(section.heading)) return;
    let _pIdx = 0;
    for (const p of section.paragraphs) {
      const text = p.runs.map((r) => r.text).join("");
      const inline = scanInlineDefinitions(text, {
        section_id: section.id,
        paragraph_id: p.id,
        start: p.runs[0]?.start ?? 0,
        end: p.runs[p.runs.length - 1]?.end ?? 0,
      });
      for (const d of inline) registerDefinition(definitions, d);
      const bare = DEFINITION_BARE.exec(text);
      if (bare) {
        const term = bare[1]!.trim();
        const def = text
          .slice(bare.index + bare[0].length)
          .trim()
          .replace(/^[-:]+\s*/, "");
        const start = p.runs[0]?.start ?? 0;
        const reference = cleanRef(DEFINITION_REFERENCE.exec(def)?.[1]);
        registerDefinition(definitions, {
          term,
          definition: def,
          defined_at: {
            section_id: section.id,
            paragraph_id: p.id,
            start,
            end: start + text.length,
          },
          used_at: [],
          ...(reference ? { reference } : {}),
        });
      }
      // Only when neither a verb-based inline definition nor the bare "Term
      // means …" form recognized this paragraph do we fall back to the quoted
      // colon/dash glossary form, so a paragraph that already defined a term is
      // never re-read.
      if (inline.length === 0 && !bare) {
        const glossary = GLOSSARY_ENTRY.exec(text);
        if (glossary) {
          const term = glossary[1]!.trim();
          // Slice from the END of the match, not `term.length`: the pattern
          // consumes the opening quote, the (possibly-longer-than-`term`) quoted
          // phrase, the closing quote, and the ":"/"—" separator, ending on the
          // first non-space char of the definition. Using the trimmed term's
          // length as an offset landed mid-term and prepended a stray fragment
          // ('"Delivery Point": the dock' → 't": the dock').
          const def = text
            .slice(glossary.index + glossary[0].length - 1)
            .replace(/^["“”'’\s]*/, "")
            .replace(/^[:—–]\s*/, "")
            .trim();
          const start = p.runs[0]?.start ?? 0;
          const reference = cleanRef(DEFINITION_REFERENCE.exec(def)?.[1]);
          registerDefinition(definitions, {
            term,
            definition: def,
            defined_at: {
              section_id: section.id,
              paragraph_id: p.id,
              start,
              end: start + text.length,
            },
            used_at: [],
            ...(reference ? { reference } : {}),
          });
        }
      }
      _pIdx += 1;
    }
  });

  // Pass 2: inline definitions everywhere.
  forEachParagraph(tree, (ctx) => {
    for (const d of scanInlineDefinitions(ctx.text, {
      section_id: ctx.section.id,
      paragraph_id: ctx.paragraph.id,
      start: ctx.start,
      end: ctx.end,
    })) {
      registerDefinition(definitions, d);
    }
    if (ctx.text.trim().length <= FIELD_BLOCK_MAX_LENGTH) {
      FIELD_LABEL.lastIndex = 0;
      const labels: { term: string; start: number; valueStart: number }[] = [];
      let f: RegExpExecArray | null;
      while ((f = FIELD_LABEL.exec(ctx.text)) !== null) {
        labels.push({ term: f[1]!.trim(), start: f.index, valueStart: f.index + f[0].length });
      }
      // Only a paragraph that OPENS with a label is a cover block — a
      // sentence that happens to contain "Wire Instructions: …" mid-flow
      // is prose, not a field sheet.
      if (labels.length > 0 && /^\s*$/.test(ctx.text.slice(0, labels[0]!.start))) {
        for (let i = 0; i < labels.length; i++) {
          const value = ctx.text
            .slice(labels[i]!.valueStart, labels[i + 1]?.start ?? ctx.text.length)
            .trim();
          if (!value) continue;
          registerDefinition(definitions, {
            term: labels[i]!.term,
            definition: value,
            defined_at: {
              section_id: ctx.section.id,
              paragraph_id: ctx.paragraph.id,
              start: ctx.start,
              end: ctx.end,
            },
            used_at: [],
            form: "field-label",
          });
        }
      }
    }
  });

  // Pass 3: record every use of each term outside its definition.
  for (const entry of definitions.values()) {
    // Match the term as defined and its regular plural/singular — a term
    // defined in one number is routinely used in the other ("Confidential
    // Material" … "the Confidential Materials"; "Deliverables" … "each
    // Deliverable"), which is still a use, not a template leftover.
    // The article a definition QUOTES is not part of the term the body uses:
    // '"The Berth Agreement" means …' is used as "the Berth Agreement"
    // everywhere after, and the term went unmatched. The document was then
    // told BOTH that "The Berth Agreement" is never used and that "Berth
    // Agreement" is a term it forgot to define — two findings that contradict
    // each other, about one term.
    const bare = articleLess(entry.term);
    const variants = [
      entry.term,
      regularPlural(entry.term),
      regularSingular(entry.term),
      bare,
      bare ? regularPlural(bare) : undefined,
      bare ? regularSingular(bare) : undefined,
    ].filter((v): v is string => !!v && v !== entry.term);
    const alternatives = [entry.term, ...new Set(variants)].map(escapeRegExp).join("|");
    const needle = new RegExp(`\\b(?:${alternatives})\\b`, "g");
    forEachParagraph(tree, (ctx) => {
      // Skip the definition itself. For an express definition that is the
      // whole paragraph — a term repeated inside its own definition body
      // ("… but Confidential Information does not include …") is a
      // self-reference, not a use. A PARENTHETICAL is different: it defines
      // the term mid-sentence in the operative text, and the same paragraph
      // routinely goes on to use it ('any Statement of Work ("SOW") … the SOW
      // shall control'). Skipping that whole paragraph reported the term as
      // never used.
      const inDefiningParagraph =
        entry.form !== "parenthetical" && ctx.paragraph.id === entry.defined_at.paragraph_id;
      needle.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = needle.exec(ctx.text)) !== null) {
        const pos = posInParagraph(ctx, m.index, m.index + m[0].length);
        if (pos.start >= entry.defined_at.start && pos.end <= entry.defined_at.end) continue;
        // Inside the defining paragraph, only text BEFORE the definition
        // marker is operative use — an embedded definition ('… consummates a
        // Change of Control … "Change of Control" means a merger …') is used
        // by the clause that precedes it, while a repetition AFTER the marker
        // is the definition body talking about itself ("… but Confidential
        // Information does not include …").
        if (inDefiningParagraph && pos.end > entry.defined_at.start) continue;
        entry.used_at.push(pos);
      }
    });
  }

  // A field-label term is a fact-sheet entry — "Effective Date: January 1,
  // 2026" states its fact whether or not the body ever repeats the label, so
  // its non-reuse is not the template-leftover signal unused_terms exists to
  // report.
  // A double-alias definition ('"Protected Health Information" or "PHI" means
  // …') registers both names at the SAME defined-at span, and the document then
  // uses only one of them ("PHI"). A use of either alias satisfies both, so the
  // unused one is not a template leftover.
  const usedAliasSpans = new Set(
    [...definitions.values()]
      .filter((e) => e.used_at.length > 0)
      .map((e) => `${e.defined_at.start}:${e.defined_at.end}`),
  );
  const unused_terms = [...definitions.values()]
    .filter((e) => e.used_at.length === 0 && e.form !== "field-label")
    .filter((e) => !usedAliasSpans.has(`${e.defined_at.start}:${e.defined_at.end}`))
    .map((e) => e.term)
    .sort();

  // Pass 4: undefined Title-Case phrases.
  const definedNames = new Set([...definitions.keys()]);
  // A term defined WITH its article is the same term the body uses without
  // one, so the article-less form is defined too.
  for (const key of [...definedNames]) {
    const bare = articleLess(key);
    if (bare) definedNames.add(bare.toLowerCase());
  }
  const undefinedHits = new Map<string, DocPosition[]>();
  /**
   * Title-Case phrases the document SIGNS. A phrase introduced by a signature
   * label is a person, and it is a person everywhere else it appears too — the
   * preamble, the notary acknowledgment, the body — so the term is dropped
   * entirely rather than the signed occurrence alone.
   */
  const signedNames = new Set<string>();
  /** The candidate key a phrase is recorded under (a leading article dropped). */
  const canonicalOf = (phrase: string): string => {
    const w = phrase.split(/\s+/);
    return TITLE_CASE_LEADING_STOPWORDS.has(w[0]!) && w.length > 2 ? w.slice(1).join(" ") : phrase;
  };
  const caption = captionText(tree);
  // Every HEADING the document carries, styled or standalone. A phrase that
  // names a section of this document is a cross-reference to it, not a term
  // the drafter forgot to define: a set of discovery responses is headed
  // "GENERAL OBJECTIONS" and its answers say "subject to the General
  // Objections above", and that was reported as an undefined Title-Case term.
  // The same reasoning as the numbered-heading test below — a term whose
  // section is headed with it has been addressed by that section.
  const headings = new Set<string>();
  forEachSection(tree, (section) => {
    const heading = section.heading.trim();
    if (heading) headings.add(heading.toLowerCase());
  });
  forEachParagraph(tree, (ctx) => {
    const line = ctx.text.trim();
    if (line.length > 0 && line.length <= 80 && !/[.;:!?]$/.test(line) && isTitleCaseSegment(line))
      headings.add(line.toLowerCase());
  });
  // Names of natural persons who sign or appear before a notary — collected
  // from conformed-signature lines ("/s/ Nora Castellanos") and notarial
  // recitals ("personally appeared Nora Castellanos") — are people, not
  // defined terms, wherever else they appear.
  const personNames = new Set<string>();
  // Prefixes of full entity names — "Granite Peak Lenders LLC" yields
  // "Granite Peak" and "Granite Peak Lenders" — are the SHORT FORMS a
  // document uses after introducing the entity, not defined terms. Briefs
  // and letters shorten this way without any parenthetical definition.
  const entityPrefixes = new Set<string>();
  forEachParagraph(tree, (ctx) => {
    for (const re of [
      // A conformed signature with the printed name beneath it, after the
      // paste path has joined the two lines with a space: "/s/ Adaeze Chinelo
      // Oduya Adaeze Chinelo Oduya, Settlor and Trustee". The bounded capture
      // below stops at four words, so a THREE-word name doubled runs to six
      // and the halving that follows compared "adaeze chinelo" against "oduya
      // adaeze" and found no repetition — a trust reported its own settlor as
      // a Title-Case term the drafter forgot to define. Requiring the
      // repetition with a backreference reads the doubling directly and is
      // indifferent to how many words the name has.
      /\/s\/\s+([A-Z][\w'’-]+(?:\s+[A-Z][\w'’-]+){0,3})\s+\1(?![\w'’-])/g,
      /\/s\/\s+([A-Z][\w'’-]+(?:\s+[A-Z][\w'’-]+){0,3})/g,
      /\b(?:personally\s+appeared|I,)\s+([A-Z][\w'’-]+(?:\s+[A-Z][\w'’-]+){0,3})/g,
      // The signatory name printed on a "Name:" line of an execution block —
      // "Name: Eleanor Vance" — is a person, not a defined term.
      /\bName:\s+([A-Z][\w'’-]+(?:\s+[A-Z][\w'’-]+){0,3})/g,
      // The printed name beneath a signature blank — "________ Elena Marquez,
      // Incorporator" — is a signatory (a person), not a defined term. Two-plus
      // Title-Case words after the rule so a bare "Signature of X" label form
      // (single leading word before a lowercase connector) is not swept in.
      /_{6,}\s*([A-Z][\w'’-]+(?:\s+[A-Z][\w'’-]+){1,3})\b/g,
      // A person introduced by their relationship to the drafter — "my wife
      // Priya Raghunathan Halloran", "my son Emil Halloran", "my brother
      // Cormac Halloran" — is a natural person, and a will names its family
      // this way throughout. A will has no "parties" for the party extractor
      // to find, so every family member was reported as a Title-Case term
      // the will forgot to define. Collecting them here also covers the bare
      // list form ("my children: Ana Halloran, Emil Halloran, and Soren
      // Halloran"), because the set is matched against every later use.
      /\b(?:my|his|her|their|our)\s+(?:beloved\s+|late\s+|step-?|former\s+)?(?:wife|husband|spouse|partner|son|daughter|child|brother|sister|mother|father|grandson|granddaughter|grandchild|niece|nephew|cousin|uncle|aunt|executor|trustee|guardian)\s+([A-Z][\w'’-]+(?:\s+[A-Z][\w'’-]+){0,3})/g,
    ]) {
      re.lastIndex = 0;
      let pm: RegExpExecArray | null;
      while ((pm = re.exec(ctx.text)) !== null) {
        const captured = pm[1]!.toLowerCase();
        personNames.add(captured);
        // The paste path joins a block's lines with spaces, so a conformed
        // signature and the printed name beneath it arrive as one string:
        // "/s/ Priya Raghunathan Priya Raghunathan, Member and Manager". The
        // capture then holds the name TWICE, matches no later use of it, and
        // every use was reported as a Title-Case term the document forgot to
        // define — on a document that names her four times and where she
        // signs it.
        const halves = captured.split(/\s+/);
        if (halves.length % 2 === 0) {
          const half = halves.length / 2;
          const first = halves.slice(0, half).join(" ");
          if (first === halves.slice(half).join(" ")) personNames.add(first);
        }
      }
    }
    const ENTITY_NAME =
      /\b([A-Z][\w'’-]+(?:\s+[A-Z][\w'’-]+){1,4}),?\s+(LLC|Inc\.?|Corp\.?|Ltd\.?|L\.P\.|LLLP|LLP|PLLC|P\.?C\.?|P\.?A\.?|N\.A\.|GmbH)(?![\w])/g;
    ENTITY_NAME.lastIndex = 0;
    let em: RegExpExecArray | null;
    while ((em = ENTITY_NAME.exec(ctx.text)) !== null) {
      const words = em[1]!.toLowerCase().split(/\s+/);
      for (let k = 2; k <= words.length; k++) entityPrefixes.add(words.slice(0, k).join(" "));
      // Half of these suffixes are Title-Case words, not initialisms, so the
      // candidate phrase INCLUDES the suffix — "Meridian Optics Corp." yields
      // the candidate "Meridian Optics Corp", which no prefix of "Meridian
      // Optics" matches. The addressee of a cease-and-desist letter was
      // reported as a Title-Case term the letter forgot to define.
      // Only the Title-Case suffixes; TITLE_CASE_PHRASE never reaches an
      // all-caps one, so "Acme Holdings LLC" needs nothing here.
      if (/^[A-Z][a-z]/.test(em[2]!)) {
        entityPrefixes.add(`${words.join(" ")} ${em[2]!.replace(/\.$/, "").toLowerCase()}`);
      }
    }
  });
  forEachParagraph(tree, (ctx) => {
    // A run-in heading ("4. Mutual Release by Meridian. Upon receipt …")
    // capitalizes its words as heading STYLE, not defined-term usage;
    // occurrences inside the heading segment are not uses of a term.
    const headingEnd = runInHeadingEnd(ctx.text);
    // A standalone heading LINE — a short, Title-Case, unpunctuated
    // paragraph ("Risks Related to Our Lending Business") — is heading
    // style throughout; none of its phrases are defined-term uses.
    const trimmed = ctx.text.trim();
    // A NUMBERED standalone heading ("4. Due Diligence Materials.") is the
    // same construct, and drafters end it with a period as often as not. The
    // section number is what distinguishes it from a Title-Case sentence, so
    // the terminal period is forgiven only when one is present: a commercial
    // purchase agreement was told "Due Diligence Materials" was a term it
    // forgot to define, on a document whose section 4 is headed with it.
    const numbered = /^\d+(?:\.\d+)*\.?\s+(.+?)\.?$/.exec(trimmed);
    const headingLine = numbered ? numbered[1]! : trimmed;
    if (
      headingLine.length > 0 &&
      headingLine.length <= 80 &&
      !/[.;:!?]$/.test(headingLine) &&
      isTitleCaseSegment(headingLine)
    ) {
      return;
    }
    TITLE_CASE_PHRASE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = TITLE_CASE_PHRASE.exec(ctx.text)) !== null) {
      const phrase = m[1]!;
      if (m.index < headingEnd) continue;
      // A candidate whose final word is immediately followed by ":" has bled
      // across a field boundary in a signature or cover block — ingest joins
      // "Name: Eleanor Vance" and "Title: Chief Executive Officer" into one
      // paragraph, so the phrase "Eleanor Vance Title" swept up the next label.
      // The trailing ":" marks a label, not a defined-term use.
      if (ctx.text[m.index + m[0].length] === ":") continue;
      // "in this Annual Report on Form 10-K" — a "this"-prefixed phrase is
      // the document referring to ITSELF (or to a companion instrument it
      // just named), not an undefined term.
      if (/\bthis\s+$/i.test(ctx.text.slice(Math.max(0, m.index - 8), m.index))) continue;
      // The document's caption is its NAME; a phrase inside the caption line
      // or inside an echo of it ("This Confidential Settlement Agreement and
      // Mutual Release (this 'Agreement') …") is title vocabulary.
      if (caption && insideOccurrenceOf(ctx.text, caption, m.index, phrase.length)) continue;
      // A phrase that sits inside the CAPTION is the document's own name
      // wherever else it appears, not only on the caption line. Compared case
      // -insensitively because a caption is routinely set in capitals: a HIPAA
      // form headed "ACKNOWLEDGMENT OF RECEIPT OF NOTICE OF PRIVACY PRACTICES"
      // was told that "Privacy Practices" — a fragment of its own title, which
      // the Title-Case run cuts at the lowercase "of" — was a term it forgot
      // to define.
      if (caption && caption.toLowerCase().includes(phrase.toLowerCase())) continue;
      // A phrase soon followed by a defining parenthetical is the SUBJECT
      // that parenthetical names — "This Employee Handbook (this
      // 'Handbook') …" defined the whole phrase as "Handbook"; its words are
      // not a separate undefined term.
      if (
        /^[^().;]{0,40}\(\s*(?:the|this|each|an?|collectively|together|individually|hereinafter|referred\s+to\s+as)?[,]?\s*["“]/.test(
          ctx.text.slice(m.index + phrase.length, m.index + phrase.length + 60),
        )
      ) {
        continue;
      }
      // A candidate whose first word is immediately preceded by a hyphen is the
      // tail of a hyphenated compound, not a standalone term: "Software-as-a-
      // Service Terms of Service" yielded the phantom term "Service Terms".
      if (ctx.text[m.index - 1] === "-") continue;
      // Likewise the tail of an and-joined Title-Case name: "Securities and
      // Exchange Commission" splits at the lowercase "and", yielding the
      // phantom term "Exchange Commission".
      if (/[A-Z][a-z]+\s+and\s+$/.test(ctx.text.slice(Math.max(0, m.index - 24), m.index)))
        continue;
      const phraseLower = phrase.toLowerCase();
      if (definedNames.has(phraseLower)) continue;
      // A named institution or legal term of art is a proper noun, not a term
      // the document left undefined. Test the article-stripped form too, since a
      // sentence-initial "The Federal Reserve" is canonicalized to "Federal
      // Reserve" downstream but reaches this check with the article still on.
      const wknWords = phrase.split(/\s+/);
      const wknCanonical =
        wknWords.length > 2 && TITLE_CASE_LEADING_STOPWORDS.has(wknWords[0]!)
          ? wknWords.slice(1).join(" ").toLowerCase()
          : phraseLower;
      if (WELL_KNOWN_ENTITIES.has(phraseLower) || WELL_KNOWN_ENTITIES.has(wknCanonical)) continue;
      // A SINGULAR use of a defined PLURAL term — "each Licensed Patent" where
      // "Licensed Patents" is the defined term — is that term's use, not a new
      // undefined one. (The mirror, a plural use of a defined singular, is
      // handled by isCompoundOfDefined further down.) The bare "+s"/"+es"
      // forms are kept for a final word already ending in "s" ("Asset Class" →
      // "Asset Classes"); regularPlural adds the "y" → "ies" case ("Licensed
      // Facility" → "Licensed Facilities") that neither bare form produces.
      const definedAsPlural = regularPlural(phraseLower);
      if (
        definedNames.has(`${phraseLower}s`) ||
        definedNames.has(`${phraseLower}es`) ||
        (definedAsPlural !== null && definedNames.has(definedAsPlural))
      ) {
        continue;
      }
      // TITLE_CASE_PHRASE cannot cross an all-caps word, so a candidate is
      // often a truncation of a longer defined term — "Contractor Background"
      // cut from the defined "Contractor Background IP". A word-boundary
      // prefix of a defined term is that term's use, not a new undefined one.
      let prefixOfDefined = false;
      for (const name of definedNames) {
        if (name.startsWith(`${phraseLower} `)) {
          prefixOfDefined = true;
          break;
        }
      }
      if (prefixOfDefined) continue;
      // A phrase composed entirely of defined terms is a compound USE of
      // those terms, not a new undefined one: "Process Personal Data" where
      // "Process" and "Personal Data" are both defined (GDPR vocabulary
      // imported by reference) is the two defined terms in sequence.
      if (isCompoundOfDefined(phraseLower, definedNames)) continue;
      if (COMMON_WORDS.has(phrase)) continue;
      if (PLACE_NAMES.has(phrase)) continue;
      if (TIME_ZONE_NAMES.has(phrase)) continue;
      if (STATUTE_NAMES.has(phrase)) continue;
      // A Title-Case phrase ending in "Act", "Code", or "Law" is a statute's
      // title or a body of law ("Bank Secrecy Act", "Utah Code", "Delaware
      // General Corporation Law", "Governing Law", "Applicable Law") — the
      // law's name, not a term the document defines. A phrase the document
      // genuinely defines this way ("Data Protection Law means …") is already
      // excluded as a defined term; only the undefined law reference remains.
      if (/\s(?:Act|Code|Law)$/.test(phrase)) continue;
      // The same statute title, when it runs past the five-word cap
      // TITLE_CASE_PHRASE imposes: "New York Limited Liability Company Law"
      // captures as "New York Limited Liability Company", and the suffix test
      // above cannot see the word that makes it a law. Look at what follows.
      // The statute noun can sit a couple of words further on: "Age
      // Discrimination in Employment Act" captures as "Age Discrimination",
      // because the Title-Case run stops at the lowercase "in". Every OWBPA
      // release names that Act, and every one reported the fragment as a term
      // it forgot to define.
      if (/^[^.;]{0,40}?\b(?:Act|Code|Law)\b/.test(ctx.text.slice(m.index + phrase.length)))
        continue;
      // The statute's name can also FOLLOW the noun: "Code of Civil
      // Procedure", "Rules of Civil Procedure", "Laws of New York". Every
      // California filing cites the first of those, and "Civil Procedure" was
      // reported as a term the filing forgot to define.
      if (
        /\b(?:Code|Rules?|Laws?|Acts?|Statutes?|Regulations?)\s+of\s+$/i.test(
          ctx.text.slice(Math.max(0, m.index - 24), m.index),
        )
      )
        continue;
      if (headings.has(phraseLower)) continue;
      // A person named after a PERSON FIELD label — "Author: Dana Okwuosa",
      // "Recipients: Peter Vance", "cc: Renata Silva", "Custodian: Marcus
      // Bell". A privilege log is a table of exactly these, and every name in
      // one was reported as a Title-Case term the log forgot to define. The
      // labels are mid-paragraph, so the cover-block test above cannot see
      // them.
      if (
        /\b(?:Author|Authors|Recipient|Recipients|From|To|Cc|Bcc|Custodian|Custodians|Attendees|Present|Signator(?:y|ies)|Witness|Notary|Preparer|Reviewer|Interviewer|Deponent)s?\s*:\s*$/i.test(
          ctx.text.slice(Math.max(0, m.index - 16), m.index),
        )
      )
        continue;
      // A named PUBLIC BODY: a state or country name followed by the office or
      // agency it belongs to — "Illinois Attorney General", "Nevada Governor",
      // "Oregon Health Authority". A term a contract defines does not begin
      // with the name of a state.
      // A phrase ending in an ORGANIZATION noun is an organization's NAME —
      // "Cascade Valley Hospital", "Fairhaven Trust Company", "Commercial
      // Lending Group". A contract's defined terms do not end that way; the
      // single-word "Company" and "Trust", which do, never reach this
      // multi-word candidate list.
      if (
        /\s(?:Hospital|Clinic|University|College|Institute|Foundation|Association|Bank|Laborator(?:y|ies)|Company|Corporation|Group|Partners|Ventures|Holdings|Systems)$/.test(
          phrase,
        )
      )
        continue;
      const leadWord = phrase.split(/\s+/)[0]!;
      if (PLACE_NAMES.has(leadWord) || US_STATE_NAMES.has(leadWord)) continue;
      if (OFFICER_TITLES.test(phrase)) continue;
      // A phrase introduced by an HONORIFIC is a person: "Dr. Ingrid
      // Vasconcelos-Amaru", "Hon. Marisol Aguirre-Vance", "Prof. Emil
      // Halloran". A research consent form names its principal investigator
      // that way twice — in the header block and in the contact section — and
      // the investigator was reported as a term the form forgot to define.
      if (
        /\b(?:Dr|Mr|Mrs|Ms|Mx|Prof(?:essor)?|Hon|Rev|Sir|Dame|Fr|Sr|Capt|Col|Gen|Lt|Sgt|Rabbi|Pastor|Judge|Justice)\.?\s+$/.test(
          ctx.text.slice(Math.max(0, m.index - 12), m.index),
        )
      )
        continue;
      // An office named by its ABBREVIATION — "VP Information Security", "SVP
      // Global Sales", "CISO Operations". TITLE_CASE_PHRASE cannot include the
      // all-caps abbreviation, so the capture begins one word in and the
      // office reads as a term the document forgot to define. A completed
      // security questionnaire reported "Information Security", which is the
      // job of the person who signed it.
      if (
        /\b(?:VP|SVP|EVP|AVP|CEO|CFO|CTO|COO|CIO|CISO|CHRO|CRO|GC)\s+$/.test(
          ctx.text.slice(Math.max(0, m.index - 8), m.index),
        )
      )
        continue;
      // The VALUE of a cover-block field — "Requesting organisation: Thornbury
      // Federal Credit Union" — is a fact the document states, not a term it
      // defines. Recognized only on a short paragraph that OPENS with the
      // label, which is what a cover block is; a sentence that happens to
      // carry a colon mid-flow is prose.
      const fieldValue = /^\s*[A-Z][A-Za-z]*(?:\s+[A-Za-z]+){0,4}:\s*/.exec(ctx.text);
      if (
        fieldValue &&
        ctx.text.trim().length <= FIELD_BLOCK_MAX_LENGTH &&
        m.index === fieldValue[0].length
      )
        continue;
      // A phrase immediately followed by a corporate suffix (", Inc.",
      // " LLC") is an entity NAME, not a defined term — same reasoning as
      // the street-address guard, keyed on the unambiguous suffix.
      // The list covers the non-US forms too: a European controller is named
      // "Halewood Data Systems B.V." in the notice that names it, and every
      // use of the name was reported as a Title-Case term the document forgot
      // to define.
      if (
        // The periods are OPTIONAL. A professional corporation writes itself
        // "Ridgeway Valley Pediatric Associates, PC" as often as "P.C.", and
        // the dotted spellings alone missed every medical, legal, and
        // accounting practice that drops them.
        /^,?\s*(?:Inc|L\.?L\.?C|Ltd|Corp|Co|N\.?A|P\.?C|P\.?A|GmbH|S\.?A|B\.?V|N\.?V|A\.?G|PLC|LLLP|LLP|PLLC|L\.?P|S\.p\.A|Pty|Pte|SARL)\b/.test(
          ctx.text.slice(m.index + phrase.length, m.index + phrase.length + 12),
        )
      )
        continue;
      // A street address ("88 Dockside Avenue") is a proper noun, never a
      // contractual defined term — same reasoning as PLACE_NAMES, keyed on
      // the unambiguous street-suffix last word. Likewise a named county or
      // parish ("Pierce County") in a legal description or venue recital.
      if (
        /\s(?:Avenue|Street|Road|Boulevard|Drive|Lane|Parkway|Highway|Way|Place|Court|Terrace|Circle|Plaza|Square|Trail|Row|Turnpike|Crossing|County|Parish|Borough)$/.test(
          phrase,
        )
      )
        continue;
      // "Last Will" is the front half of the document's own title, split at
      // the lowercase "and" in "my Last Will and Testament". The title is not
      // a term the instrument defines — it is what the instrument IS.
      if (/^\s*and\s+Testament\b/.test(ctx.text.slice(m.index + phrase.length))) continue;
      // An ordinal instrument name ("First Amendment", "Second Addendum") is
      // the TITLE of a companion document, not a term this one defines.
      if (
        /^(?:First|Second|Third|Fourth|Fifth|Sixth|Seventh|Eighth|Ninth|Tenth)\s+(?:Amendment|Addendum|Modification|Restatement|Supplement)$/.test(
          phrase,
        )
      )
        continue;
      // A numbered-instrument fragment: "Change Order No. 3" captures as
      // "Change Order No" (the abbreviation's word survives, its period and
      // number don't). The fragment is part of a document NUMBER, not a term.
      //
      // The number is as often alphanumeric as bare: a policy, a claim, a
      // docket, and a purchase order all carry a prefixed identifier
      // ("Policy No. CGL-4471982", "Claim No. MC-2026-118447"), and the
      // digits-only test read those as an undefined "Policy No". A short
      // letter run is admitted before the digits, which still requires a
      // digit and so cannot swallow a sentence continuing after the
      // abbreviation ("No. The parties …", "No. Section 5 applies").
      if (
        /\sNo$/.test(phrase) &&
        /^\.\s*(?:\d|[A-Za-z]{1,6}[-\u2011\u2013]?\d)/.test(ctx.text.slice(m.index + phrase.length))
      )
        continue;
      if (personNames.has(phraseLower)) continue;
      // A name carrying the lawyer's post-nominal ("Marcus Field, Esq.") is a
      // natural person. A privilege log, a certificate of service, and a
      // signature block all name people who are not parties, so the party
      // extractor's `personNames` never sees them, and each name used twice
      // was reported as a Title-Case term the document forgot to define.
      if (/^,?\s*Esq\b/.test(ctx.text.slice(m.index + phrase.length, m.index + phrase.length + 8)))
        continue;
      // A citation to an issued authority — "Federal Rule of Civil Procedure
      // 26(c)", "Local Rule 7.1", "Revenue Procedure 93-27", "Treasury
      // Regulation § 1.704-1", "Revenue Ruling 99-5" — names the authority,
      // not a term this document defines. Same reasoning as the
      // `Act`/`Code`/`Law` suffix above, but these nouns need the citation
      // shape to follow them, because a document may genuinely define a
      // "Program Rule" or a "Special Procedure".
      if (
        /\s(?:Rules?|Procedures?|Regulations?|Ruling|Bulletin|Notice|Circular)$/.test(phrase) &&
        /^\s*(?:of\s+[A-Z]|§|\d)/.test(ctx.text.slice(m.index + phrase.length))
      )
        continue;
      // The MIRROR of the same citation shape: the authority's name continues
      // AFTER an "of", and the lowercase "of" ends the Title-Case run, so the
      // tail arrives as its own candidate. "Ohio Rules of Professional
      // Conduct" yields "Ohio Rules" (caught above) and then "Professional
      // Conduct" — which every engagement letter, ethics policy, and
      // conflicts waiver cites repeatedly, and each was reported as a
      // Title-Case term the document forgot to define. Gated on the authority
      // noun immediately before the "of", so an ordinary "Schedule of Base
      // Rent Adjustments" or "Statement of Base Services" still flags.
      // "Procedures of" is deliberately NOT here: unlike Rules/Regulations/
      // Canons it names an internal process at least as often as an
      // authority, and the sibling guard above already excludes it whenever
      // the citation shape actually follows.
      if (/\b(?:Rules?|Regulations?|Canons?)\s+of\s+$/.test(ctx.text.slice(0, m.index))) continue;
      // A judicial district or division is a place inside a court's name — "the
      // United States District Court for the Northern District of Illinois" —
      // and every settlement, pleading, and forum clause names one. The
      // Title-Case run stops at the lowercase "of", so "Northern District"
      // arrived as its own candidate and was reported as a term the document
      // forgot to define.
      if (
        /\b(?:District|Circuit|Division|Department)$/.test(phrase) &&
        /^\s*of\s+[A-Z]/.test(ctx.text.slice(m.index + phrase.length))
      )
        continue;
      if (entityPrefixes.has(phraseLower)) continue;
      // The title of an attachment, on its label line — "Schedule A — Trust
      // Property", "Exhibit B – Form of Note". That is the attachment's NAME,
      // not a use of a defined term, and the standalone-heading test above
      // only catches it while the label has a paragraph to itself. A trust
      // pasted out of a PDF, where the schedule label runs on into the notary
      // block, was told "Trust Property" was a term it forgot to define.
      if (
        /\b(?:Exhibit|Schedule|Appendix|Annex|Attachment)\s+[A-Z0-9][\w.-]*\s*[—–-]\s*$/.test(
          ctx.text.slice(Math.max(0, m.index - 40), m.index),
        )
      )
        continue;
      // A phrase introduced with a residence or origin ("Diego Castellanos,
      // residing at 9 Elm Row", "Lucia Ferrante, of Burlington") is a natural
      // person, not a defined term.
      if (
        /^,\s+(?:residing|of\s+[A-Z]|whose\s+address)/.test(
          ctx.text.slice(m.index + phrase.length, m.index + phrase.length + 24),
        )
      )
        continue;
      if (TITLE_CASE_LEADING_STOPWORDS.has(phrase)) continue;
      // Only strip sentence-initial-stopword patterns from the candidate
      // list when the phrase is short (2 words). Longer phrases like
      // "The Special Reserve Fund" or "The Annual Operating Plan" are
      // ordinary capitalized noun phrases worth flagging when undefined.
      const words = phrase.split(/\s+/);
      if (words.length === 2 && TITLE_CASE_LEADING_STOPWORDS.has(words[0]!)) continue;
      // A sentence-initial article fused onto a DEFINED term is that term's
      // use: "The Escrow Agent shall release …" is the defined "Escrow
      // Agent", not an undefined "The Escrow Agent". The remainder is tested
      // the same way a non-stopword phrase is (see the isCompoundOfDefined
      // check above), so a plural of a defined singular counts too — "All
      // Licensed Products" is the defined "Licensed Product" in the plural,
      // not an undefined term. A stopword-led phrase whose remainder is NOT
      // defined ("The Special Reserve Fund") still flags.
      if (
        TITLE_CASE_LEADING_STOPWORDS.has(words[0]!) &&
        isCompoundOfDefined(words.slice(1).join(" ").toLowerCase(), definedNames)
      ) {
        continue;
      }
      // Normalize a sentence-initial article off the candidate: "The
      // Contract Sum will be increased …" and "increased the Contract Sum"
      // are occurrences of ONE term, and reporting "Contract Sum" and "The
      // Contract Sum" side by side is the same term twice.
      // A signature block names its signatory two or three times — "By: /s/
      // Ignatius Mbeki" over "Name: Ignatius Mbeki" — and that is a person
      // signing, not a term the drafter forgot to define. Nine specimens
      // reported their own signatories as undefined Title-Case terms, and the
      // shape of a personal name is not distinguishable from the shape of a
      // defined term ("Marisol Thibodeaux", "Base Rent") — but the CONTEXT is:
      // a defined term is never introduced by a signature label.
      //
      // A phrase the document SIGNS is a person, wherever else it appears: a
      // trust names its settlor in the preamble, again under the conformed
      // signature, and once more in the notary acknowledgment, and none of
      // those three is a term the drafter forgot to define. So the whole term
      // is dropped, not just the signed occurrence.
      if (SIGNATURE_LABEL_BEFORE.test(ctx.text.slice(Math.max(0, m.index - 24), m.index))) {
        signedNames.add(canonicalOf(phrase));
        continue;
      }
      let canonical = phrase;
      let start = m.index;
      if (TITLE_CASE_LEADING_STOPWORDS.has(words[0]!) && words.length > 2) {
        canonical = words.slice(1).join(" ");
        start = m.index + phrase.length - canonical.length;
      }
      const list = undefinedHits.get(canonical) ?? [];
      list.push(posInParagraph(ctx, start, start + canonical.length));
      undefinedHits.set(canonical, list);
    }
  });
  const undefined_capitalized = [...undefinedHits.entries()]
    .filter(([term]) => !signedNames.has(term))
    .filter(([, positions]) => positions.length >= 2)
    .map(([term, positions]) => ({ term, positions }))
    .sort((a, b) => a.term.localeCompare(b.term, "en"));

  const circular_terms = detectCircularDefinitions([...definitions.values()]);

  return {
    entries: [...definitions.values()].sort((a, b) => a.term.localeCompare(b.term, "en")),
    unused_terms,
    undefined_capitalized,
    ...(circular_terms.length > 0 ? { circular_terms } : {}),
  };
}

/**
 * Walk the definition graph (term A → term B when A's definition text
 * references defined term B) and return each cycle as an ordered list
 * of terms. Deterministic: terms are processed in sorted order and each
 * cycle is canonicalized to start at its alphabetically-first term.
 */
function detectCircularDefinitions(entries: DefinitionEntry[]): string[][] {
  const byTerm = new Map<string, DefinitionEntry>();
  for (const e of entries) byTerm.set(e.term, e);
  const terms = [...byTerm.keys()].sort();
  // Adjacency: A → B when B (a defined term other than A) appears in A's definition.
  const edges = new Map<string, string[]>();
  for (const a of terms) {
    const def = byTerm.get(a)!.definition;
    const targets = terms.filter(
      (b) => b !== a && new RegExp(`\\b${escapeRegExp(b)}\\b`).test(def),
    );
    edges.set(a, targets);
  }
  const cyclesByKey = new Map<string, string[]>();
  const visit = (start: string, node: string, path: string[], seen: Set<string>): void => {
    if (path.length > 8) return; // bound DFS on dense definition graphs
    for (const next of edges.get(node) ?? []) {
      if (next === start && path.length >= 2) {
        const cycle = [...path];
        const min = cycle.indexOf([...cycle].sort()[0]!);
        const rotated = [...cycle.slice(min), ...cycle.slice(0, min)];
        cyclesByKey.set(rotated.join(" "), rotated);
      } else if (!seen.has(next)) {
        seen.add(next);
        visit(start, next, [...path, next], seen);
        seen.delete(next);
      }
    }
  };
  for (const t of terms) visit(t, t, [t], new Set([t]));
  return [...cyclesByKey.values()].sort((a, b) => a.join().localeCompare(b.join(), "en"));
}

/** Trim a captured reference/scope label and strip trailing sentence punctuation. */
function cleanRef(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  const v = raw.trim().replace(/[.,;:]+$/, "");
  return v || undefined;
}

/** The first clause of a string — up to the first sentence-ending `.`/`;`. */
function firstClause(text: string): string {
  const m = /[.;]/.exec(text);
  return m ? text.slice(0, m.index) : text;
}

function scanInlineDefinitions(text: string, base: DocPosition): DefinitionEntry[] {
  const out: DefinitionEntry[] = [];
  DEFINITION_ALIASED.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = DEFINITION_ALIASED.exec(text)) !== null) {
    const definition = text.slice(m.index + m[0].length).trim();
    if (!definition) continue;
    for (const term of [m[1]!.trim(), m[2]!.trim()]) {
      out.push({
        term,
        definition,
        defined_at: {
          section_id: base.section_id,
          paragraph_id: base.paragraph_id,
          start: base.start + m.index,
          end: base.start + m.index + m[0].length,
        },
        used_at: [],
      });
    }
  }
  DEFINITION_INLINE.lastIndex = 0;
  while ((m = DEFINITION_INLINE.exec(text)) !== null) {
    const term = m[1]!.trim();
    const after = text.slice(m.index + m[0].length).trim();
    if (!after) continue;
    // Only the term's own defining clause (up to the first sentence break) can
    // supply its by-reference target — otherwise an unrelated later sentence in
    // the same paragraph ("… Exhibit B for reference only.") is mis-attributed
    // as this term's reference.
    const reference = cleanRef(DEFINITION_REFERENCE.exec(firstClause(after))?.[1]);
    const scope = cleanRef(DEFINITION_SCOPE.exec(text.slice(0, m.index))?.[1]);
    out.push({
      term,
      definition: after,
      defined_at: {
        section_id: base.section_id,
        paragraph_id: base.paragraph_id,
        start: base.start + m.index,
        end: base.start + m.index + m[0].length,
      },
      used_at: [],
      ...(reference ? { reference } : {}),
      ...(scope ? { scope } : {}),
    });
  }
  DEFINITION_INLINE_REFERS.lastIndex = 0;
  while ((m = DEFINITION_INLINE_REFERS.exec(text)) !== null) {
    const term = m[1]!.trim();
    const after = text.slice(m.index + m[0].length).trim();
    if (!after) continue;
    out.push({
      term,
      definition: after,
      defined_at: {
        section_id: base.section_id,
        paragraph_id: base.paragraph_id,
        start: base.start + m.index,
        end: base.start + m.index + m[0].length,
      },
      used_at: [],
    });
  }
  DEFINITION_INLINE_COPULA.lastIndex = 0;
  while ((m = DEFINITION_INLINE_COPULA.exec(text)) !== null) {
    const term = m[1]!.trim();
    const after = text.slice(m.index + m[0].length).trim();
    if (!after) continue;
    out.push({
      term,
      definition: after,
      defined_at: {
        section_id: base.section_id,
        paragraph_id: base.paragraph_id,
        start: base.start + m.index,
        end: base.start + m.index + m[0].length,
      },
      used_at: [],
    });
  }
  DEFINITION_INLINE_PERIOD.lastIndex = 0;
  while ((m = DEFINITION_INLINE_PERIOD.exec(text)) !== null) {
    const term = m[1]!.trim();
    // Only a bounded temporal term — "Tolling Period", "Restricted Period",
    // "Term" — is defined by "shall begin/commence"; a plain quoted noun is not.
    if (!/\b(?:Period|Term)$/.test(term)) continue;
    out.push({
      term,
      definition: text.slice(m.index + m[0].length).trim(),
      defined_at: {
        section_id: base.section_id,
        paragraph_id: base.paragraph_id,
        start: base.start + m.index,
        end: base.start + m.index + m[0].length,
      },
      used_at: [],
    });
  }
  DEFINITION_ROLE_WHEN.lastIndex = 0;
  while ((m = DEFINITION_ROLE_WHEN.exec(text)) !== null) {
    out.push({
      term: m[1]!.trim(),
      definition: text.slice(m.index + m[0].length).trim(),
      defined_at: {
        section_id: base.section_id,
        paragraph_id: base.paragraph_id,
        start: base.start + m.index,
        end: base.start + m.index + m[0].length,
      },
      used_at: [],
    });
  }
  for (const conv of [
    { tail: DEFINITION_MEANING_TAIL, form: "meaning-reference" as const },
    { tail: DEFINITION_CONSTRUED_TAIL, form: "construed" as const },
  ]) {
    conv.tail.lastIndex = 0;
    while ((m = conv.tail.exec(text)) !== null) {
      const listStart = sentenceStartBefore(text, m.index);
      const terms = parseTermList(text.slice(listStart, m.index));
      if (terms.length === 0) continue;
      const definition = m[0].trim();
      const reference = cleanRef(DEFINITION_REFERENCE.exec(definition)?.[1]);
      for (const term of terms) {
        out.push({
          term,
          definition,
          defined_at: {
            section_id: base.section_id,
            paragraph_id: base.paragraph_id,
            start: base.start + listStart,
            end: base.start + m.index + m[0].length,
          },
          used_at: [],
          ...(reference ? { reference } : {}),
          form: conv.form,
        });
      }
    }
  }
  DEFINITION_PARENTHETICAL.lastIndex = 0;
  while ((m = DEFINITION_PARENTHETICAL.exec(text)) !== null) {
    const term = m[1]!.trim();
    // The phrase the parenthetical names: the run of text before it, back to
    // the nearest clause break. That is what the drafter defined the term to
    // mean, and it keeps the entry's `definition` from swallowing the whole
    // paragraph.
    const before = text.slice(Math.max(0, m.index - 160), m.index);
    const definition =
      before
        .split(/[.;]\s/)
        .pop()
        ?.trim() ?? "";
    out.push({
      term,
      definition,
      defined_at: {
        section_id: base.section_id,
        paragraph_id: base.paragraph_id,
        start: base.start + m.index,
        end: base.start + m.index + m[0].length,
      },
      used_at: [],
      form: "parenthetical",
    });
  }
  DEFINITION_TRAILING_PARENTHETICAL.lastIndex = 0;
  while ((m = DEFINITION_TRAILING_PARENTHETICAL.exec(text)) !== null) {
    const term = m[1]!.trim();
    const before = text.slice(Math.max(0, m.index - 160), m.index);
    const definition =
      before
        .split(/[.;]\s/)
        .pop()
        ?.trim() ?? "";
    out.push({
      term,
      definition,
      defined_at: {
        section_id: base.section_id,
        paragraph_id: base.paragraph_id,
        start: base.start + m.index,
        end: base.start + m.index + m[0].length,
      },
      used_at: [],
      form: "parenthetical",
    });
  }
  DEFINITION_PAIR_PARENTHETICAL.lastIndex = 0;
  while ((m = DEFINITION_PAIR_PARENTHETICAL.exec(text)) !== null) {
    const before = text.slice(Math.max(0, m.index - 160), m.index);
    const definition =
      before
        .split(/[.;]\s/)
        .pop()
        ?.trim() ?? "";
    for (const g of [m[1]!, m[2]!]) {
      out.push({
        term: g.trim(),
        definition,
        defined_at: {
          section_id: base.section_id,
          paragraph_id: base.paragraph_id,
          start: base.start + m.index,
          end: base.start + m.index + m[0].length,
        },
        used_at: [],
        form: "parenthetical",
      });
    }
  }
  return out;
}

/**
 * The offset just after the last sentence boundary (`.`, `;`, `:`) before
 * `index`. A period followed by a digit is a numeric citation
 * (`45 CFR § 160.103`), not a boundary.
 */
function sentenceStartBefore(text: string, index: number): number {
  for (let i = index - 1; i >= 0; i--) {
    const ch = text[i]!;
    if ((ch === "." || ch === ";" || ch === ":") && !/\d/.test(text[i + 1] ?? "")) return i + 1;
  }
  return 0;
}

/**
 * Parse the subject of a meaning-tail sentence into defined-term candidates.
 * Quoted phrases win when present (they survive interior "and"s); otherwise
 * the bare list is split on commas and "and". A subject that is ordinary
 * prose ("Capitalized terms used but not defined herein") yields nothing.
 */
function parseTermList(listText: string): string[] {
  const out: string[] = [];
  QUOTED_TERM.lastIndex = 0;
  let sawQuote = false;
  let q: RegExpExecArray | null;
  while ((q = QUOTED_TERM.exec(listText)) !== null) {
    sawQuote = true;
    const term = q[1]!.trim();
    if (isPlausibleTerm(term)) out.push(term);
  }
  if (sawQuote) return out;
  for (const raw of listText.split(/,|\band\b/)) {
    const term = raw
      .trim()
      .replace(/^(?:the\s+)?(?:terms?\s+)?/i, "")
      .trim();
    if (isPlausibleTerm(term)) out.push(term);
  }
  return out;
}

/**
 * A term-list candidate must read as a defined term: every word capitalized
 * (up to two camelCase lead letters — "ePHI") or a lowercase connector, no
 * more than six words, and a lone word must not be a sentence-flow stopword
 * or boilerplate noun ("It", "Agreement").
 */
function isPlausibleTerm(term: string): boolean {
  if (term.length < 2 || term.length > 60) return false;
  const words = term.split(/\s+/);
  if (words.length > 6) return false;
  for (const w of words) {
    if (/^[a-z]{0,2}[A-Z][\w\-&/'’.]*$/.test(w)) continue;
    if (/^(?:of|and|or|for|to|in|the|a|an)$/.test(w)) continue;
    return false;
  }
  if (words.length === 1 && (TITLE_CASE_LEADING_STOPWORDS.has(term) || COMMON_WORDS.has(term))) {
    return false;
  }
  if (words.length === 2 && TITLE_CASE_LEADING_STOPWORDS.has(words[0]!)) return false;
  return /^[a-z]{0,2}[A-Z]/.test(term);
}

/** Lowercase words a Title-Case heading or caption legitimately leaves lowercase. */
const HEADING_CONNECTORS = /^(?:of|and|or|by|to|in|for|the|a|an|with|under|on|at|from)$/;

/** Every word capitalized (or a heading connector) — heading/caption style. */
function isTitleCaseSegment(segment: string): boolean {
  const words = segment.trim().split(/\s+/);
  if (words.length === 0) return false;
  for (const w of words) {
    if (/^[A-Z0-9(&]/.test(w)) continue;
    if (HEADING_CONNECTORS.test(w)) continue;
    // Title punctuation: "Employee Handbook — Halcyon Grid Systems, Inc."
    if (/^[—–-]$/.test(w)) continue;
    return false;
  }
  return true;
}

/**
 * The document's caption line — the first paragraph, when it reads as a
 * title (Title-Case throughout, short, no terminal sentence punctuation)
 * rather than as prose. Plain-text ingest keeps the caption as an ordinary
 * paragraph, so without this Pass 4 read the document's own name as a
 * defined-term candidate ("Mutual Release" from "Confidential Settlement
 * Agreement and Mutual Release").
 */
function captionText(tree: DocumentTree): string | undefined {
  const first = tree.sections[0]?.paragraphs[0];
  if (!first) return undefined;
  const text = first.runs
    .map((r) => r.text)
    .join("")
    .trim();
  if (text.length < 8 || text.length > 90) return undefined;
  // A trailing period only disqualifies a caption when it is sentence
  // punctuation — "Amended and Restated Bylaws of Beacon Instruments, Inc."
  // ends with the entity suffix's abbreviation point, and rejecting it left
  // every phrase in the caption a defined-term candidate.
  if (/[.;:!?]$/.test(text) && !/\b(?:Inc|LLC|L\.L\.C|Ltd|Corp|Co|N\.A|P\.C|S\.A)\.$/.test(text)) {
    return undefined;
  }
  if (text.split(/\s+/).length < 2) return undefined;
  return isTitleCaseSegment(text) ? text : undefined;
}

/**
 * The end offset of a run-in heading segment — a numbered or lettered list
 * marker followed by a short Title-Case phrase and a sentence break
 * ("4. Mutual Release by Meridian. Upon receipt …"). Returns 0 when the
 * paragraph does not open with one (a numbered SENTENCE — "4. Client shall
 * pay Vendor." — fails the Title-Case check and is not a heading).
 */
function runInHeadingEnd(text: string): number {
  const m = /^\s*(?:\d+(?:\.\d+)*|[A-Z])[.)]\s+([A-Z][^.;:]{0,80}?)[.;:]\s/.exec(text);
  if (!m) return 0;
  return isTitleCaseSegment(m[1]!) ? m[0].length : 0;
}

/** True when [index, index+length) lies inside an occurrence of `container` in `text`. */
function insideOccurrenceOf(
  text: string,
  container: string,
  index: number,
  length: number,
): boolean {
  let at = text.indexOf(container);
  while (at !== -1) {
    if (index >= at && index + length <= at + container.length) return true;
    at = text.indexOf(container, at + 1);
  }
  return false;
}

/**
 * True when the phrase's words segment fully into defined term names.
 * A segment matches its defined term through a trailing plural — "Your
 * Contributions" is the defined "Your" + "Contribution", and demanding the
 * exact singular reported the compound as a new undefined term.
 */
function isCompoundOfDefined(phraseLower: string, definedNames: Set<string>): boolean {
  const words = phraseLower.split(/\s+/);
  const matches = (seg: string): boolean =>
    definedNames.has(seg) ||
    (seg.endsWith("es") && definedNames.has(seg.slice(0, -2))) ||
    (seg.endsWith("s") && definedNames.has(seg.slice(0, -1)));
  const reachable: boolean[] = new Array(words.length + 1).fill(false);
  reachable[0] = true;
  for (let i = 1; i <= words.length; i++) {
    for (let j = 0; j < i; j++) {
      if (reachable[j] && matches(words.slice(j, i).join(" "))) {
        reachable[i] = true;
        break;
      }
    }
  }
  return reachable[words.length]!;
}

function registerDefinition(map: Map<string, DefinitionEntry>, entry: DefinitionEntry): void {
  const key = entry.term.toLowerCase();
  const existing = map.get(key);
  if (existing && existing.definition) return; // first definition wins
  map.set(key, entry);
}

/**
 * A term with a leading article dropped — "The Berth Agreement" → "Berth
 * Agreement" — or undefined when it has none, or nothing would be left of it.
 */
function articleLess(term: string): string | undefined {
  const words = term.split(/\s+/);
  const first = words[0] ?? "";
  // The definition map is keyed in lower case and the entry carries the term
  // as written, so the stopword test has to read both.
  const capitalized = first.charAt(0).toUpperCase() + first.slice(1).toLowerCase();
  if (words.length < 3 || !TITLE_CASE_LEADING_STOPWORDS.has(capitalized)) return undefined;
  return words.slice(1).join(" ");
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Regular English plural of a term's final word — "Confidential Material" →
 * "Confidential Materials", "Disclosing Party" → "Disclosing Parties",
 * "Franchise" → "Franchises". Returns null when no simple rule applies (the
 * final word already ends in "s", so its plural is ambiguous — "Losses" vs an
 * already-plural "Fees"). Used only to count a singular-defined term that the
 * body uses in the plural as a genuine use, so STRUCT-005 does not report it as
 * an unused template leftover.
 */
function regularPlural(term: string): string | null {
  const m = /^(.*?)(\S+)$/.exec(term);
  if (!m) return null;
  const [, head, last] = m as unknown as [string, string, string];
  if (/s$/i.test(last)) return null;
  let plural: string;
  if (/[^aeiou]y$/i.test(last)) plural = last.replace(/y$/i, "ies");
  else if (/(x|z|ch|sh)$/i.test(last)) plural = last + "es";
  else plural = last + "s";
  return head + plural;
}

/**
 * Regular English singular of a plural term's final word — the mirror of
 * {@link regularPlural}, for a term defined in the plural ("Deliverables",
 * "Affiliates", "Parties") that the body uses in the singular. Guarded by a
 * round trip: the candidate singular is only accepted when re-pluralizing it
 * reproduces the exact term, so a non-plural word ending in "s" ("Business" →
 * "Busines" → "Businesses" ≠ "Business") is rejected. Returns null when no
 * simple rule applies.
 */
function regularSingular(term: string): string | null {
  const m = /^(.*?)(\S+)$/.exec(term);
  if (!m) return null;
  const [, head, last] = m as unknown as [string, string, string];
  let singularLast: string | null = null;
  if (/[^aeiou]ies$/i.test(last)) singularLast = last.replace(/ies$/i, "y");
  else if (/(ses|xes|zes|ches|shes)$/i.test(last)) singularLast = last.replace(/es$/i, "");
  else if (/[^s]s$/i.test(last)) singularLast = last.replace(/s$/i, "");
  if (!singularLast) return null;
  const candidate = head + singularLast;
  return regularPlural(candidate) === term ? candidate : null;
}
