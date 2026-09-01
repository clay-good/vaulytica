import type { DocumentTree } from "../ingest/types.js";
import type { CrossRef, SectionOutline } from "./types.js";
import { forEachParagraph, posInParagraph } from "./walk.js";

/**
 * Resolve every "Section 4.2" / "Article III" / "§ 12(b)" reference
 * against the outline. Anything that does not resolve is flagged with
 * `unresolved: true` for STRUCT-007 to surface.
 *
 * Romans are accepted up to a reasonable bound and converted to integers
 * for matching against the outline's numbered labels.
 */

// The numeral may carry a trailing letter suffix ("409A", "280G") — captured
// so the raw text is never silently truncated to "409" and so the external
// citation guard below sees the whole label. The trailing `(?![A-Za-z])` keeps
// a bare roman numeral from matching inside a word ("Schedule i" must not match
// "Schedule identifying"; "Article V" must not match "Article Video").
const REF_RE =
  /\b(Section|Sections|Article|Articles|Exhibit|Schedule|Attachment|§§?)\s+([0-9]+(?:\.[0-9]+)*[A-Za-z]?(?:\([a-z]\))?|[IVXLCDM]+)(?![A-Za-z])/gi;

// An external statutory citation ("Section 409A of the Internal Revenue Code",
// "Section 12 of the Securities Exchange Act of 1934") is NOT a broken
// intra-document cross-reference — the document was never meant to resolve it
// against its own outline. Detected by the "of the … Code/Act/Regulations"
// qualifier that trails such a citation, or the "U.S.C." / "C.F.R." reporter
// that fronts a bare-section statutory cite. A reference matching this is
// dropped so STRUCT-007 never fabricates a broken internal reference from it.
// The trailing qualifier that marks a reference as an EXTERNAL statutory
// citation: either "of the … Code/Act/Regulation" or a regulation abbreviation
// that directly follows the number ("Article 32 GDPR", "Article 6 UK GDPR",
// "§ 1798.100 CCPA"). The EU data-protection style writes the regulation right
// after the article, with no "of the", so the "of the …" form alone missed
// every "Article NN GDPR" — 140+ in the corpus — and STRUCT-007 reported each
// as a broken internal reference to an "Article 32" the document never has.
// A statute abbreviated by its own ACRONYM, trailing the section with no
// "of the" at all, is the same shape as "Article 32 GDPR" and the list above
// had only the data-protection ones. A German Article 30 record citing
// "section 630f BGB" for its retention period and "section 26 BDSG" for its
// legal basis reported two broken internal references to sections no record
// of processing has. The list is curated rather than a bare all-caps wildcard,
// because a wildcard would suppress a genuine broken reference whenever the
// next word happened to be capitalized.
// A state statute numbers its sections with a DECIMAL — "Sections 202.010 and
// 202.007 of the Texas Property Code", "Sections 1798.100 and 1798.105 of the
// CCPA" — and the connective run below admitted only whole numbers, so the
// second section of every such pair stopped the run and the whole citation
// read as a broken internal reference. Texas, California, and Florida all
// number this way, and a Declaration of Covenants cites them by the dozen.
//
// The qualifier can trail a sub-reference and a list or range of further
// numbers before it lands — "Article 28(4) of the … Regulation", "Articles 33
// and 34 GDPR", "Articles 32 to 36 of the GDPR". Skip that connective run, then
// require the statutory qualifier.
// "Laws?" belongs in the qualifier list: "Section 220 of the General
// Corporation Law of the State of Delaware" is a statutory cite, and its
// absence made STRUCT-007 report a broken internal reference to a
// "Section 220" every set of Delaware bylaws cites externally.
// A sub-reference group can be a LETTER — the EU data-protection style is
// "Article 6(1)(b)", and the US style is "Section 4(a) of the Act". The group
// required a DIGIT, so the run stopped at the first lettered level and the
// statutory qualifier that follows was never reached: an Article 30 record
// citing its own legal bases reported four broken internal references to an
// "Article 6" the register never has.
//
// A UCC ARTICLE cite carries the hyphen on BOTH sides of the connective —
// "Sections 2A-508 through 2A-522 of the Uniform Commercial Code" — and the
// sub-reference can run to more than one level: "Section 2A-103(1)(g)". The
// leading-suffix skip took a single paren group and the connective run took no
// hyphen at all, so every UCC Article 2A/9 citation in an equipment lease or a
// security agreement read as a broken internal reference to a "Section 2A".
//
// A STATE code numbers a section with more than one hyphen — "Section 7-80-204
// of the Colorado Limited Liability Company Act", "Section 13-11-101" — and the
// leading-suffix skip took exactly one hyphen group, so every Colorado,
// Georgia, Maryland, and Utah statutory cite stopped at the second hyphen and
// read as a broken internal reference.
//
// Uniform-act sections carry a HYPHENATED number — "Section 17-303 of the
// Act", "Section 17-1101(d) of the Act" (Delaware LP/LLC Acts, UCC). REF_RE
// stops the label at the hyphen ("Section 17"), so the trailer text opens with
// the "-303" suffix before the "of the … Act" qualifier ever lands; without a
// leading-suffix skip, every DRULPA cite read as a broken internal reference to
// a "Section 17" the agreement never has. Consume that suffix first.
// The "[A-Z][^.;,]*?" preceding the qualifier keyword is OPTIONAL: "of the
// General Corporation Law" has a phrase between "the" and "Law", but "of the
// Act" / "of the Code" name the statute with the keyword itself — a required
// preceding word made the [A-Z] swallow the keyword's own first letter and the
// bare form never matched.
// Case-INSENSITIVE, because a document routinely cites a statute inside an
// ALL-CAPS title: "ELECTION … PURSUANT TO SECTION 83(b) OF THE INTERNAL
// REVENUE CODE" is the caption every § 83(b) election carries, and the
// case-sensitive "of the" never matched "OF THE" — so the reference in the
// title of the very instrument the citation defines read as a broken internal
// reference to a "SECTION 83(b)" the election never has. The leading letter of
// the optional statute-name phrase is `[A-Za-z]` rather than `[A-Z]` to say
// what it means under the flag, since `[A-Z]` matches lowercase under `i`.
const EXTERNAL_TRAILER_RE =
  /^(?:-\d+[a-z]?(?:\([a-z0-9]+\))*)*(?:\([a-z0-9]+\))*(?:\s*(?:to|through|and|or|,)\s*\d+(?:\.\d+)*[A-Za-z]?(?:-\d+[a-z]?)?(?:\([a-z0-9]+\))*)*\s+(?:of\s+(?:the\s+)?(?:[A-Za-z][^.;,]*?\s+)?(?:Code|Acts?|Laws?|Regulations?|Rules?|Directives?|Conventions?|Treat(?:y|ies)|Charters?|Constitutions?|Protocols?|Ordinances?|Statutes?|U\.?\s?S\.?\s?C\.?|C\.?\s?F\.?\s?R\.?)\b|(?:of\s+(?:the\s+)?)?(?:UK\s+|EU\s+)?(?:GDPR|CCPA|CPRA|HIPAA|LGPD|PIPEDA|UCC|DPA\s+20\d\d|BIPA|FCRA|ERISA|FLSA|NLRA|ADEA|FMLA|TCPA|COPPA|GLBA|FERPA|DMCA|VCDPA|CTDPA|UCPA|TDPSA|OCPA|DPDPA|PIPL|APPI|POPIA|BGB|BDSG|HGB|AktG|GmbHG|StGB|ZPO|TKG|TMG|UWG|IRC)\b)/i;
// "Title 7, Article 80" — a state code and the United States Code both number
// their divisions that way, and a reference under a Title is part of the
// citation, not a division of this document. Colorado's articles of
// organization cite "C.R.S. Title 7, Article 80" on their first page, and
// STRUCT-007 reported it as a broken internal reference to an "Article 80".
// A CONSTRUCTION SPECIFICATION section is numbered in MasterFormat's
// space-separated pairs — "Section 09 51 00", "Section 03 30 00" — and names a
// division of the specifications, not of this document. A change order citing
// the tile it substitutes reported a broken internal reference to a "Section
// 09" no change order has.
const SPECIFICATION_SECTION_RE = /^\s+\d{2}(?:\s+\d{2}){1,2}\b/;

// A division of ANOTHER instrument, named by the amendment that operates on
// it. An insurance endorsement writes "Section II — Who Is An Insured is
// amended to include as an additional insured …" and "the following is added
// to Section III — Limits Of Insurance": both number against the POLICY, not
// against the endorsement, which has no sections of its own. An ISO
// additional-insured endorsement reported two broken internal references.
const AMENDED_DIVISION_AFTER_RE =
  /^\s*[—–-]\s*[A-Z][^.;]{0,60}?\s+(?:is|are)\s+(?:hereby\s+)?(?:amended|added|deleted|replaced|revised|restated|modified)\b/;
const AMENDED_DIVISION_BEFORE_RE =
  /\b(?:added|amended|deleted|replaced|revised|restated|modified)\s+(?:to|in|into)\s+$/i;
const EXTERNAL_LEADER_RE =
  /\b(?:U\.?\s?S\.?\s?C\.?|C\.?\s?F\.?\s?R\.?|Stat\.)\s*$|\bTitle\s+\d+[A-Za-z]?\s*,\s*$/;

// The statutory qualifier can also PRECEDE the section: "Treasury Regulations
// under Section 704(b)", "the Internal Revenue Code pursuant to Section 409A".
// Here the Code / Act / Regulations noun and an "under" / "pursuant to"
// connector sit BEFORE the reference, so EXTERNAL_TRAILER_RE (which scans the
// text after) never saw them and STRUCT-007 reported the external cite as a
// broken internal cross-reference. Tested against the text before the match.
const EXTERNAL_LEADING_RE =
  /\b(?:Code|Acts?|Regulations?|U\.?\s?S\.?\s?C\.?|C\.?\s?F\.?\s?R\.?)\b[^.;,]{0,20}?\b(?:under|pursuant\s+to)\s+$/i;
// A Treasury Regulation citation names the regulation immediately BEFORE the
// section — "Treasury Regulations Section 1.704-1(b)(2)(iv)", "Treas. Reg. §
// 1.704-1" — with no "under"/"pursuant to" connector and no "of the … Regulation"
// trailer, so both guards above missed it and STRUCT-007 reported "Section 1.704"
// as a broken internal reference to a section the operating agreement never has.
// The statute NAMED immediately before the section, with no connector at all:
// "Minnesota Statutes Section 582.30", "Texas Property Code Section 202.010",
// "the Delaware General Corporation Law Section 262". The "under"/"pursuant
// to" guard needs a connector and the trailing "of the … Code" guard needs the
// qualifier to follow, so this — the plainest citation form there is — was
// read as a broken internal reference.
// The code's own name can carry an "of" phrase — "Code of Civil Procedure
// section 2033.010" is how every California filing cites the CCP, and
// "Rules of Civil Procedure Rule 36" and "Code of Federal Regulations
// § 425.1" are the same shape. The noun alone had to sit immediately before
// the section, so the commonest citation form in the largest state's practice
// read as a broken internal reference.
// Case-INSENSITIVE, because a guaranty set in capitals cites "MINNESOTA
// STATUTES SECTION 582.30". The optional name phrase is spelled `[A-Za-z]`
// rather than `[A-Z]` to say what it means under the flag.
// "ANNOTATED" trails the code's name in half the states — "Tennessee Code
// Annotated section 50-1-1003", "Maryland Code Ann., Labor & Empl. § 3-712" —
// and the code word had to be the last one before the section, so a social
// media policy citing the Tennessee password-protection statute was told it
// points at a "section 50" it does not have.
//
// A DIVISION may sit between the code's name and the section: "Massachusetts
// General Laws chapter 149, section 24L", "New York Business Corporation Law
// article 6, section 630". The code word had to be immediately adjacent, so
// every statute cited in the chapter-first style read as a broken internal
// reference — an internship agreement citing the Massachusetts ban on
// noncompetes with a student was told it points at a "section 24L" it does not
// have.
const EXTERNAL_NAMED_CODE_LEADING_RE =
  /\b(?:Statutes?|Code|Laws?|Acts?|Regulations?|Rules?)(?:\s+Annotated|\s+Ann\.?)?(?:\s+of\s+(?:[A-Za-z][\w.]*\s+){0,3}[A-Za-z][\w.]*)?(?:\s*,?\s*(?:chapter|ch\.?|title|tit\.?|article|art\.?|part|division|div\.?)\s+[\w.-]+)?\s*,?\s+$/i;

const EXTERNAL_REG_LEADING_RE =
  /\b(?:Treasury\s+Regulations?|Treas\.?\s+Reg(?:ulation)?s?\.?)\s+$/i;

// A reference into ANOTHER INSTRUMENT'S numbering — "Section 3.7 of the
// Agreement" in disclosure schedules refers to the SPA, "Article VIII
// thereof" to its remedies article, "Section 4.1 of Annex I" to an annex — is
// not a broken reference in THIS document. "the" is optional so the annex/
// appendix forms that drop it ("of Annex I") are caught; "of this Agreement" is
// still self-reference that resolves internally, because "this" is neither
// "the" nor a capitalized instrument word, so the branch does not match it.
// The governance instruments were missing from that list, and a company's own
// records cite them constantly: board minutes recite notice given "in
// accordance with Section 3.6 of the Company's bylaws", an option grant points
// at "Section 5.2 of the Plan", a deed at "Article VII of the Declaration".
// Each read as a broken internal reference to a section the minutes never had.
// The instrument noun is matched case-insensitively — "bylaws" is lowercase as
// often as not — and the qualifying words may carry a possessive ("the
// Company's bylaws"). `(?!th(?:is|ese)\b)` keeps SELF-reference internal: "of
// this Agreement" and "of these Bylaws" are the document talking about itself,
// and a broken reference in one still reports.
/**
 * A codicil cites the WILL's articles constantly, and not always adjacently:
 * "every provision of my Will remains in full force and effect, including the
 * tax-apportionment clause in Article VIII and the no-contest clause in
 * Article IX." Those are the will's articles; the codicil has six of its own.
 *
 * Corroboration within ONE SENTENCE, and deliberately confined to the
 * testamentary instruments: an amendment to an ordinary agreement keeps the
 * adjacency requirement, so a genuinely broken "Section 14.9" in it still
 * reports.
 */
const TESTAMENTARY_PARENT_SENTENCE =
  /\bof\s+(?:my|the|our|his|her|their)\s+(?:[A-Za-z][\w'’]*\s+){0,4}(?:Will|Codicil|Testament)\b/;

/** The sentence around an index, for a corroboration that spans a clause. */
function enclosingSentenceOf(text: string, index: number): string {
  const start = Math.max(0, text.lastIndexOf(". ", index) + 1);
  const dot = text.indexOf(". ", index);
  return text.slice(start, dot === -1 ? text.length : dot + 1);
}

const EXTERNAL_INSTRUMENT_RE =
  /^(?:\.\d+[a-z]?|\(\d+[a-z]?\))*\s+(?:of\s+(?:the\s+)?(?!th(?:is|ese)\b)(?:[A-Za-z][\w'’]*\s+){0,4}(?:Agreements?|Leases?|Sub-?leases?|Notes?|Indentures?|MSA|SPA|DPA|BAA|Contracts?|Sub-?contracts?|Annex|Appendix|By-?laws?|Charters?|Certificates?|Plans?|Polic(?:y|ies)|Declarations?|Trusts?|Deeds?|Mortgages?|Terms?|Orders?|SOWs?|Statements?\s+of\s+Work|Guarant(?:y|ies|ee|ees)|Warrant(?:y|ies)|Rules?|Manuals?|Handbooks?|Schedules?|Wills?|Codicils?|Testaments?)\b|thereof\b)/i;

// A FLAT number with a lettered subsection — "Section 414(q)", "Section
// 424(d)", "Section 423(b)(5)" — in a document that names a CODE.
//
// A contract's own outline is decimal ("Section 4.2") or roman ("Article
// VII"); it is the statutes that number a bare three-digit section and split
// it with a letter. An ESPP cites § 423 with "of the Internal Revenue Code"
// attached and then cites §§ 414(q) and 424(d) bare, because in that document
// the Code is the only thing called a Section — and both reported as broken
// internal references. Corroborated on the document naming a code, so a
// contract that numbers its own sections 101, 102 and writes "Section 101(a)"
// is untouched unless it also names one.
const STATUTE_SUBSECTION_LABEL = /^\d{2,4}\([a-z]\)/;
const NAMES_A_CODE =
  /\b(?:Internal\s+Revenue\s+Code|Bankruptcy\s+Code|Uniform\s+Commercial\s+Code|Securities\s+Act|Exchange\s+Act|ERISA|U\.S\.C\.|C\.F\.R\.)\b/;

// A four-digit-or-longer flat section number ("Section 4999", "Section 1798")
// is statutory: no contract numbers its own sections past three digits.
const STATUTE_SECTION_LABEL = /^\d{4,}$/;

// A section number the DOCUMENT ITSELF ties to a code ("Section 409A of the
// Internal Revenue Code") is statutory wherever it appears — an executive
// agreement introduces 409A/280G that way and then cites them bare in later
// headings ("6. Section 280G. If any payment …"). Corroboration-based, so a
// bare letter-suffixed reference with no statutory context anywhere still
// reports as an unresolved internal reference.
const STATUTE_LABEL_DECLARATION =
  /\b(?:[Ss]ections?|§§?)\s+(\d+(?:\.\d+)*[A-Za-z]?)(?:\([a-z0-9]+\))*\s+of\s+(?:the\s+)?[A-Z][^.;,]*?\b(?:Code|Acts?|Laws?|Regulations?|Rules?)\b/g;

/**
 * The same declaration written the other way round: the code NAMED FIRST.
 *
 * "Code of Civil Procedure section 2031.010", "Texas Property Code section
 * 202.010", "Minnesota Statutes Section 582.30" — the plainest citation form
 * there is, and the one most state practice uses.
 * {@link EXTERNAL_NAMED_CODE_LEADING_RE} already suppresses the individual
 * reference, but it did not set `declaresCode`, so the SIBLINGS a filing then
 * cites bare stayed broken. A California demand for inspection that cites the
 * CCP by name four times and then writes "waives objections under section
 * 2031.300" reported that sibling as a reference to a section no demand has.
 */
const STATUTE_LABEL_DECLARATION_LEADING =
  /\b(?:[A-Z][\w.'’]*\s+){0,5}(?:Statutes?|Code|Laws?|Acts?|Regulations?|Rules?)(?:\s+Annotated|\s+Ann\.?)?(?:\s+of\s+(?:[A-Za-z][\w.]*\s+){0,3}[A-Za-z][\w.]*)?\s*,?\s+(?:[Ss]ections?|§§?)\s+(\d+(?:\.\d+)*[A-Za-z]?)(?:\([a-z0-9]+\))*/g;

// A statute the document abbreviates — "the Delaware General Corporation Law
// (the 'DGCL')", "the Delaware Revised Uniform Limited Partnership Act
// ('DRULPA')". A later "Section 262 of the DGCL" cites that authority's own
// numbering, not this document's outline, so the acronym is collected and the
// cite reads as external. The defining phrase must end in a statute keyword
// (Code / Act / Law / Regulation), and the acronym is a single all-caps token.
const STATUTE_ACRONYM_DEFINITION =
  /\b[A-Z][A-Za-z]+(?:\s+(?:[A-Z][A-Za-z]+|of|and|the))*\s+(?:Code|Acts?|Laws?|Regulations?)\b(?:\s+of\s+\d{4})?\s*\(\s*(?:the\s+)?["“]([A-Z][A-Za-z]{1,10})["”]\s*\)/g;

/**
 * An acronym the document defines for ANOTHER INSTRUMENT — 'the Amended and
 * Restated Investors’ Rights Agreement of even date (the "IRA")', 'the
 * Loan and Security Agreement (the "Loan Agreement")'.
 *
 * `EXTERNAL_INSTRUMENT_RE` already reads "Section 3.7 of the Agreement" and
 * the three-letter forms the catalog happened to list (MSA, SPA, DPA, BAA) as
 * references into another document's numbering. It cannot read an acronym the
 * document invents, and a side letter, an amendment, a statement of work, a
 * guaranty, and an SNDA all cite their parent's sections that way: "Section
 * 3.5 of the IRA" was reported as a broken reference to a section this
 * document never had.
 *
 * Mirrors {@link STATUTE_ACRONYM_DEFINITION}, with the defining phrase ending
 * in an instrument word rather than a statute word. Both apostrophes are
 * admitted because Word inserts the curly one.
 */
const INSTRUMENT_ACRONYM_DEFINITION =
  /\b[A-Z][A-Za-z’']*(?:\s+(?:[A-Z][A-Za-z’']*|of|and|the))*\s+(?:Agreements?|Leases?|Notes?|Indentures?|Plans?|Polic(?:y|ies)|Contracts?|Charters?|By-?laws?|Declarations?|Orders?|Certificates?)\b(?:\s+of\s+even\s+date(?:\s+herewith)?)?\s*\(\s*(?:the\s+)?["“]([A-Za-z][A-Za-z\s'’-]{1,40})["”]\s*\)/g;

// A section reference trailed by "of (the) <ACRONYM>" — "Section 262 of the
// DGCL". Checked against the collected / seeded statute-acronym set.
const EXTERNAL_ACRONYM_TAIL = /^(?:\(\d+[a-z]?\))*\s+of\s+(?:the\s+)?([A-Za-z]{2,10})\b/;

// "Section 262 of the DGCL" ties section number (group 1) to a statute acronym
// (group 2). Corroborates a later BARE "Section 262" as statutory — a merger
// agreement cites "under Section 262 of the DGCL" once and then "the rights
// provided under Section 262" without the qualifier.
const STATUTE_ACRONYM_CITE =
  /\b(?:Section|Sections|§§?)\s+(\d+(?:\.\d+)*[A-Za-z]?)(?:\([a-z0-9]+\))*\s+of\s+(?:the\s+)?([A-Z][A-Za-z]{1,10})\b/g;

// Statute acronyms so ubiquitous they are cited bare, without a local
// definition — Delaware corporate law and the UCC head every M&A and secured-
// lending document.
const SEED_STATUTE_ACRONYMS = ["DGCL", "UCC", "DRULPA", "DLLCA", "ERISA", "FLSA"];

// A paragraph that OPENS with "6. Vendor Indemnity …" is section 6, even when
// the ingester never promoted it to a heading. The paste path (any pasted
// contract) keeps numbered clauses as flat paragraphs under one empty-heading
// section, so the outline carries no numbered labels and a self-reference
// ("under this Section 6") resolved to nothing — STRUCT-007 then reported a
// broken cross-reference to a section printed two lines above it. The number
// must be followed by a capitalized clause title, so a paragraph opening with a
// list marker or an amount ("5,000") is not mistaken for a section.
//
// The optional "Section" / "Sec." lead-in captures the bylaws / contract
// heading form "Section 2.1. Annual Meeting": there the number carries its own
// "Section" word, so the bare-number pattern never registered it and every one
// of those headings was BOTH unregistered AND re-read as a broken reference to
// itself (a clean set of bylaws drew a dozen unresolved-reference findings).
const LEADING_SECTION_RE = /^\s*(?:(?:Section|Sec\.?|§)\s+)?(\d+(?:\.\d+)*)\.\s+[A-Z(]/;

// The ingester keeps an article heading and its FIRST subsection in one
// paragraph — "ARTICLE II — STOCKHOLDERS Section 2.1. Annual Meeting. …" — so
// "Section 2.1" sits after the article title and `LEADING_SECTION_RE` (which
// anchors at the paragraph start) never registered it, leaving the first
// subsection of every article reported as a broken reference to itself. This
// captures that section number where it trails the article heading.
const ARTICLE_THEN_SECTION_RE =
  /^\s*(?:ARTICLE|Article)\s+[IVXLCDM\d]+\b[A-Za-z\s—–-]*?\b(?:Section|Sec\.?|§)\s+(\d+(?:\.\d+)*)\.\s+[A-Z]/;

// Bylaws style writes the multi-level number with NO trailing period —
// "7.1 Exclusive Forum. Unless …" — so LEADING_SECTION_RE never registered
// it and "this Section 7.1" reported as broken. Multi-level only: a bare
// integer without its period ("2026 Annual Meeting") is a year or an
// amount, not a clause number.
const LEADING_SUBSECTION_RE = /^\s*(\d+(?:\.\d+)+)\.?\s+[A-Z(]/;

// The same heading with NO period after the number — "Section 1.1 Registered
// Office." — which is how a Delaware corporation's bylaws are almost always
// numbered. `LEADING_SECTION_RE` requires the period and
// `LEADING_SUBSECTION_RE` anchors on the bare number, so a clean set of bylaws
// registered none of its own sections and then reported every heading as a
// broken reference to itself: 28 unresolved cross-references on a document
// with none. The "Section" keyword is REQUIRED here — without it, a paragraph
// opening "5 Business Days after the Closing" would register as a section.
const LEADING_SECTION_NO_PERIOD_RE = /^\s*(?:Section|Sec\.?|§)\s+(\d+(?:\.\d+)*)\s+[A-Z(]/;

// A RUN-IN section heading anywhere in a paragraph — "… continues in effect.
// Section 6.4. Definitions. \"Descendants\" means …". Stripping a document's
// blank lines, as a PDF copy-paste does, merges a whole article into one
// paragraph, so every heading but the first sits mid-paragraph: the anchored
// patterns above registered none of them and a clean set of nonprofit bylaws
// drew fourteen broken-reference findings against headings printed in itself.
//
// The trailing period after the number is what separates a heading from a
// reference: "Section 3.4. Vacancies." declares, "under Section 3.4" refers.
const RUN_IN_SECTION_RE = /(?:^|[.!?]\s+)(?:Section|Sec\.?|§)\s+(\d+(?:\.\d+)*)\.\s+[A-Z(]/g;

// The same run-in heading in the NO-PERIOD numbering a Delaware corporation's
// bylaws use — "… by the Board. Section 3.5 Committees. The Board of Directors
// may designate …". Without the period after the number, the heading is told
// apart from a reference by what FOLLOWS it: a short Title-Case clause title
// that itself ends in a period. "in accordance with Section 220 of the General
// Corporation Law" is not preceded by a sentence end, "This Section 8.1 does
// not apply" continues in lowercase, and "See Section 2.3 for notice
// requirements." never closes a Title-Case run — none of them register.
const RUN_IN_SECTION_NO_PERIOD_RE =
  /(?:^|[.!?]\s+)(?:Section|Sec\.?|§)\s+(\d+(?:\.\d+)*)\s+[A-Z][\w'’-]*[;,]?(?:\s+(?:[A-Z][\w'’-]*|of|and|the|to|by|for|in)[;,]?)*\.\s+[A-Z]/g;

// The flat-paste ARTICLE heading — "ARTICLE VII — FORUM SELECTION" — is a
// DECLARATION of the article, not a reference to it. It both feeds the
// label index (so "Article VII" elsewhere resolves) and is skipped as a
// reference (so STRUCT-007 stops reporting every article heading in the
// document as a broken cross-reference).
const LEADING_ARTICLE_RE = /^\s*(?:ARTICLE|Article)\s+([IVXLCDM]+|\d+)\b/;

// The same shape for SECTION, which `LEADING_SECTION_RE` above cannot see: it
// requires an ARABIC number followed by a period ("Section 2.1. Annual
// Meeting"), and an insurance policy writes "SECTION VI — NOTICE" — roman, no
// period, an em dash. Every one of those headings was BOTH unregistered and
// re-read as a broken reference to itself, and the real "Section VI" reference
// in the body failed too. Exactly the defect the ARTICLE comment above
// describes, left unfixed for the sibling keyword.
const LEADING_SECTION_ROMAN_RE = /^\s*(?:SECTION|Section)\s+([IVXLCDM]+|\d+)\s*(?:[—–-]|$)/;

export function extractCrossRefs(tree: DocumentTree, outline: SectionOutline): CrossRef[] {
  const refs: CrossRef[] = [];
  const labelIndex = buildLabelIndex(outline);
  // Section numbers this document ties to a code anywhere in its text.
  const statutoryLabels = new Set<string>();
  /**
   * True once the document ties a section number to a NAMED code. A plan of
   * dissolution says "as section 275 of the General Corporation Law of the
   * State of Delaware requires" and then cites its siblings bare — "as section
   * 277 requires", "Under section 278", "the procedure of sections 280 and
   * 281(a)". Only the first carries the qualifier; the rest read as broken
   * references to sections the plan does not have, and it has ten.
   */
  let declaresCode = false;
  let namesACode = false;
  forEachParagraph(tree, (ctx) => {
    if (NAMES_A_CODE.test(ctx.text)) namesACode = true;
  });
  // Acronyms of statutes cited into another authority's numbering.
  const statuteAcronyms = new Set<string>(SEED_STATUTE_ACRONYMS);
  // Short names the document gives to OTHER instruments it cites into.
  const instrumentAcronyms = new Set<string>();
  forEachParagraph(tree, (ctx) => {
    STATUTE_LABEL_DECLARATION.lastIndex = 0;
    let sm: RegExpExecArray | null;
    while ((sm = STATUTE_LABEL_DECLARATION.exec(ctx.text)) !== null) {
      statutoryLabels.add(sm[1]!.toUpperCase());
      declaresCode = true;
    }
    STATUTE_LABEL_DECLARATION_LEADING.lastIndex = 0;
    let lm: RegExpExecArray | null;
    while ((lm = STATUTE_LABEL_DECLARATION_LEADING.exec(ctx.text)) !== null) {
      statutoryLabels.add(lm[1]!.toUpperCase());
      declaresCode = true;
    }
    STATUTE_ACRONYM_DEFINITION.lastIndex = 0;
    let am: RegExpExecArray | null;
    while ((am = STATUTE_ACRONYM_DEFINITION.exec(ctx.text)) !== null) {
      statuteAcronyms.add(am[1]!.toUpperCase());
    }
    INSTRUMENT_ACRONYM_DEFINITION.lastIndex = 0;
    let im: RegExpExecArray | null;
    while ((im = INSTRUMENT_ACRONYM_DEFINITION.exec(ctx.text)) !== null) {
      instrumentAcronyms.add(im[1]!.trim().toUpperCase());
    }
  });
  // A second pass: with the acronym set complete, a "Section N of the <acronym>"
  // cite corroborates a bare "Section N" elsewhere as statutory.
  forEachParagraph(tree, (ctx) => {
    STATUTE_ACRONYM_CITE.lastIndex = 0;
    let cm: RegExpExecArray | null;
    while ((cm = STATUTE_ACRONYM_CITE.exec(ctx.text)) !== null) {
      if (statuteAcronyms.has(cm[2]!.toUpperCase())) statutoryLabels.add(cm[1]!.toUpperCase());
    }
  });
  // Augment the index with paragraph-leading section numbers the outline missed.
  forEachParagraph(tree, (ctx) => {
    const m =
      LEADING_SECTION_RE.exec(ctx.text) ??
      LEADING_SECTION_NO_PERIOD_RE.exec(ctx.text) ??
      LEADING_SUBSECTION_RE.exec(ctx.text);
    const norm = m ? normalizeLabel(m[1]!) : undefined;
    if (norm && !labelIndex.has(norm)) labelIndex.set(norm, ctx.paragraph.id);
    const a = LEADING_ARTICLE_RE.exec(ctx.text);
    const aNorm = a ? normalizeLabel(`article ${a[1]!}`) : undefined;
    if (aNorm && !labelIndex.has(aNorm)) labelIndex.set(aNorm, ctx.paragraph.id);
    const sr = LEADING_SECTION_ROMAN_RE.exec(ctx.text);
    const srNorm = sr ? normalizeLabel(`section ${sr[1]!}`) : undefined;
    if (srNorm && !labelIndex.has(srNorm)) labelIndex.set(srNorm, ctx.paragraph.id);
    // A first subsection sharing the article-heading paragraph.
    const ats = ARTICLE_THEN_SECTION_RE.exec(ctx.text);
    const atsNorm = ats ? normalizeLabel(ats[1]!) : undefined;
    if (atsNorm && !labelIndex.has(atsNorm)) labelIndex.set(atsNorm, ctx.paragraph.id);
    // Every run-in heading in the paragraph, for the flattened layouts where
    // an article's subsections all arrive in one.
    for (const re of [RUN_IN_SECTION_RE, RUN_IN_SECTION_NO_PERIOD_RE]) {
      re.lastIndex = 0;
      let ri: RegExpExecArray | null;
      while ((ri = re.exec(ctx.text)) !== null) {
        const riNorm = normalizeLabel(ri[1]!);
        if (riNorm && !labelIndex.has(riNorm)) labelIndex.set(riNorm, ctx.paragraph.id);
      }
    }
  });

  forEachParagraph(tree, (ctx) => {
    const leadingArticle = LEADING_ARTICLE_RE.exec(ctx.text);
    const leadingSection =
      LEADING_SECTION_RE.exec(ctx.text) ??
      LEADING_SECTION_NO_PERIOD_RE.exec(ctx.text) ??
      LEADING_SECTION_ROMAN_RE.exec(ctx.text);
    const articleThenSection = ARTICLE_THEN_SECTION_RE.exec(ctx.text);
    REF_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = REF_RE.exec(ctx.text)) !== null) {
      const keyword = m[1] ?? "";
      // The paragraph-leading article / section heading is the clause's own
      // declaration ("Section 2.1. Annual Meeting."), not a reference into the
      // outline — reading it as one reported every heading as a broken ref.
      if (leadingArticle && m.index < leadingArticle[0].length) continue;
      if (leadingSection && m.index < leadingSection[0].length) continue;
      if (articleThenSection && m.index < articleThenSection[0].length) continue;
      // Skip external statutory citations — a reference into another
      // authority's numbering, not this document's outline.
      const after = ctx.text.slice(m.index + m[0].length);
      const before = ctx.text.slice(0, m.index);
      const acronymTail = EXTERNAL_ACRONYM_TAIL.exec(after);
      // A statutory cite's SUBSECTION is part of its raw label but not part of
      // its number: the corroborating declaration "Section 1111(b)(2) of the
      // Bankruptcy Code" records "1111", while a later bare heading — "8.2
      // Section 1111(b)." — arrives as "1111(b)" and missed the lookup
      // entirely. The four-digit statutory test had the same blind spot:
      // "Section 4999" is statutory and "Section 4999(a)" was not. One
      // stripped label serves the corroboration test, the flat-number test,
      // and the outline lookup below.
      const bareLabel = (m[2] ?? "").replace(/\(.*\)$/, "");
      if (
        EXTERNAL_TRAILER_RE.test(after) ||
        SPECIFICATION_SECTION_RE.test(after) ||
        AMENDED_DIVISION_AFTER_RE.test(after) ||
        AMENDED_DIVISION_BEFORE_RE.test(before) ||
        EXTERNAL_INSTRUMENT_RE.test(after) ||
        TESTAMENTARY_PARENT_SENTENCE.test(enclosingSentenceOf(ctx.text, m.index)) ||
        EXTERNAL_LEADER_RE.test(before) ||
        EXTERNAL_LEADING_RE.test(before) ||
        EXTERNAL_REG_LEADING_RE.test(before) ||
        EXTERNAL_NAMED_CODE_LEADING_RE.test(before) ||
        STATUTE_SECTION_LABEL.test(bareLabel) ||
        (namesACode && STATUTE_SUBSECTION_LABEL.test(m[2] ?? "")) ||
        statutoryLabels.has(bareLabel.toUpperCase()) ||
        // A SIBLING of a declared code section. Bounded three ways: the
        // document must have tied some section to a named code, the reference
        // must open with a three-digit-or-longer integer (a contract numbers
        // its own sections 1..99), and it must already have failed to resolve
        // against the outline.
        //
        // The DECIMAL suffix is part of the code's numbering, not this
        // document's style: California, Texas, and Florida all number their
        // sections that way, which the file already says two guards above. The
        // integer-only form could not cover them, so a California demand for
        // inspection that cites "Code of Civil Procedure section 2031.010"
        // and then its siblings bare — "waives objections under section
        // 2031.300" — reported the sibling as a broken reference to a section
        // no demand has. The leading run still has to clear three digits, so a
        // document's own "Section 4.2" is untouched.
        (declaresCode && /^\d{3,}(?:\.\d+)*(?:\([a-z0-9]+\))*$/i.test(bareLabel)) ||
        (acronymTail != null &&
          (statuteAcronyms.has(acronymTail[1]!.toUpperCase()) ||
            instrumentAcronyms.has(acronymTail[1]!.toUpperCase())))
      ) {
        continue;
      }
      const label = bareLabel;
      // The outline models Section / Article headings only. An Exhibit,
      // Schedule, or Attachment reference must NOT resolve to a section that
      // merely shares its number — "Schedule 4.2" is not "Section 4.2". The
      // old code keyed on the number alone and confidently linked a schedule
      // to an unrelated section (unresolved:false). Attachment-type refs key
      // into a namespace absent from the section index, so they surface as
      // unresolved for STRUCT-007 instead of a wrong-entity link.
      const isAttachment = /^(?:Exhibit|Schedule|Attachment)$/i.test(keyword);
      // An ARABIC-numbered article reference — "Article 9", "Articles 3 and 4"
      // — reaches `normalizeLabel` as the bare number "9", which normalizes to
      // `section:9` and can never match the `article:9` the declaration
      // indexed. Only the roman form ("Article II") took the article branch,
      // because it is recognizable without its keyword. So every reference to
      // an arabic-numbered article was reported as broken — the numbering a
      // union contract, a policy, and most EU-style instruments use — and,
      // where the document also had a Section 9, it linked to the wrong
      // entity instead. The keyword is known here; pass it.
      const namespace = /^Articles?$/i.test(keyword)
        ? "article"
        : /^(?:Sections?|§§?)$/i.test(keyword)
          ? "section"
          : undefined;
      const normalized = isAttachment
        ? undefined
        : normalizeLabel(namespace ? `${namespace} ${label}` : label);
      const resolved = normalized ? labelIndex.get(normalized) : undefined;
      // Capture any trailing parenthetical sub-reference chain
      // ("(a)(ii)") that follows the matched label, without disturbing
      // resolution (which keys on the section number) or `raw_text`.
      const inMatch = /(\([a-z0-9]+\))+$/i.exec(m[2] ?? "")?.[0] ?? "";
      const trailing = /^(\([a-z0-9]+\))+/i.exec(ctx.text.slice(m.index + m[0].length))?.[0] ?? "";
      const subRef = `${inMatch}${trailing}`;
      refs.push({
        raw_text: m[0],
        resolved_id: resolved,
        unresolved: resolved === undefined,
        ...(subRef ? { sub_ref: subRef } : {}),
        position: posInParagraph(ctx, m.index, m.index + m[0].length),
      });
    }
  });

  return refs;
}

function buildLabelIndex(outline: SectionOutline): Map<string, string> {
  const map = new Map<string, string>();
  for (const node of Object.values(outline.by_id)) {
    if (node.numbered_label) {
      const norm = normalizeLabel(node.numbered_label);
      if (norm) map.set(norm, node.id);
    }
  }
  return map;
}

function normalizeLabel(label: string): string | undefined {
  if (!label) return undefined;
  if (/^[IVXLCDM]+$/i.test(label)) {
    const n = romanToInt(label.toUpperCase());
    return n ? `article:${n}` : undefined;
  }
  if (label.toLowerCase().startsWith("article ")) {
    const tail = label.slice(8).trim();
    if (/^[IVXLCDM]+$/i.test(tail)) {
      const n = romanToInt(tail.toUpperCase());
      return n ? `article:${n}` : undefined;
    }
    if (/^\d+$/.test(tail)) return `article:${tail}`;
  }
  // The SECTION namespace, qualified the same way. A ROMAN-numbered section —
  // "SECTION VI — NOTICE", and the "Section VI" that refers to it — took the
  // bare-roman branch above and normalized into the ARTICLE namespace, so it
  // could never match its own declaration and, in a document with an Article
  // VI, linked to the wrong one. Insurance policies number their sections in
  // roman throughout.
  if (label.toLowerCase().startsWith("section ")) {
    const tail = label.slice(8).trim();
    if (/^[IVXLCDM]+$/i.test(tail)) {
      const n = romanToInt(tail.toUpperCase());
      return n ? `section:${n}` : undefined;
    }
    if (/^\d+(?:\.\d+)*$/.test(tail)) return `section:${tail}`;
  }
  if (/^[0-9]+(?:\.[0-9]+)*$/.test(label)) return `section:${label}`;
  return undefined;
}

function romanToInt(s: string): number | null {
  const vals: Record<string, number> = { I: 1, V: 5, X: 10, L: 50, C: 100, D: 500, M: 1000 };
  let total = 0;
  let prev = 0;
  for (let i = s.length - 1; i >= 0; i -= 1) {
    const v = vals[s[i]!];
    if (v === undefined) return null;
    if (v < prev) total -= v;
    else total += v;
    prev = v;
  }
  return total > 0 ? total : null;
}
