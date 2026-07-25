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
// The qualifier can trail a sub-reference and a list or range of further
// numbers before it lands — "Article 28(4) of the … Regulation", "Articles 33
// and 34 GDPR", "Articles 32 to 36 of the GDPR". Skip that connective run, then
// require the statutory qualifier.
// "Laws?" belongs in the qualifier list: "Section 220 of the General
// Corporation Law of the State of Delaware" is a statutory cite, and its
// absence made STRUCT-007 report a broken internal reference to a
// "Section 220" every set of Delaware bylaws cites externally.
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
const EXTERNAL_TRAILER_RE =
  /^(?:-\d+[a-z]?(?:\([a-z0-9]+\))?)?(?:\(\d+[a-z]?\))*(?:\s+(?:to|through|and|or|,)\s+\d+[A-Za-z]?(?:\(\d+[a-z]?\))*)*\s+(?:of\s+(?:the\s+)?(?:[A-Z][^.;,]*?\s+)?(?:Code|Acts?|Laws?|Regulations?|Rules?|U\.?\s?S\.?\s?C\.?|C\.?\s?F\.?\s?R\.?)\b|(?:UK\s+|EU\s+)?(?:GDPR|CCPA|CPRA|HIPAA|LGPD|PIPEDA|DPA\s+20\d\d)\b)/;
const EXTERNAL_LEADER_RE = /\b(?:U\.?\s?S\.?\s?C\.?|C\.?\s?F\.?\s?R\.?|Stat\.)\s*$/;

// The statutory qualifier can also PRECEDE the section: "Treasury Regulations
// under Section 704(b)", "the Internal Revenue Code pursuant to Section 409A".
// Here the Code / Act / Regulations noun and an "under" / "pursuant to"
// connector sit BEFORE the reference, so EXTERNAL_TRAILER_RE (which scans the
// text after) never saw them and STRUCT-007 reported the external cite as a
// broken internal cross-reference. Tested against the text before the match.
const EXTERNAL_LEADING_RE =
  /\b(?:Code|Acts?|Regulations?|U\.?\s?S\.?\s?C\.?|C\.?\s?F\.?\s?R\.?)\b[^.;,]{0,20}?\b(?:under|pursuant\s+to)\s+$/i;

// A reference into ANOTHER INSTRUMENT'S numbering — "Section 3.7 of the
// Agreement" in disclosure schedules refers to the SPA, "Article VIII
// thereof" to its remedies article — is not a broken reference in THIS
// document. "of this Agreement" is self-reference and still resolves
// internally (the branch requires "the", never "this").
const EXTERNAL_INSTRUMENT_RE =
  /^(?:\(\d+[a-z]?\))*\s+(?:of\s+the\s+(?:[A-Z][\w]*\s+){0,4}(?:Agreement|Lease|Note|Indenture|MSA|SPA|DPA|BAA|Contract)\b|thereof\b)/;

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
  /\b(?:Section|Sections|§§?)\s+(\d+(?:\.\d+)*[A-Za-z]?)(?:\([a-z0-9]+\))*\s+of\s+(?:the\s+)?[A-Z][^.;,]*?\b(?:Code|Acts?|Laws?|Regulations?|Rules?)\b/g;

// A statute the document abbreviates — "the Delaware General Corporation Law
// (the 'DGCL')", "the Delaware Revised Uniform Limited Partnership Act
// ('DRULPA')". A later "Section 262 of the DGCL" cites that authority's own
// numbering, not this document's outline, so the acronym is collected and the
// cite reads as external. The defining phrase must end in a statute keyword
// (Code / Act / Law / Regulation), and the acronym is a single all-caps token.
const STATUTE_ACRONYM_DEFINITION =
  /\b[A-Z][A-Za-z]+(?:\s+(?:[A-Z][A-Za-z]+|of|and|the))*\s+(?:Code|Acts?|Laws?|Regulations?)\b(?:\s+of\s+\d{4})?\s*\(\s*(?:the\s+)?["“]([A-Z][A-Za-z]{1,10})["”]\s*\)/g;

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

// The flat-paste ARTICLE heading — "ARTICLE VII — FORUM SELECTION" — is a
// DECLARATION of the article, not a reference to it. It both feeds the
// label index (so "Article VII" elsewhere resolves) and is skipped as a
// reference (so STRUCT-007 stops reporting every article heading in the
// document as a broken cross-reference).
const LEADING_ARTICLE_RE = /^\s*(?:ARTICLE|Article)\s+([IVXLCDM]+|\d+)\b/;

export function extractCrossRefs(tree: DocumentTree, outline: SectionOutline): CrossRef[] {
  const refs: CrossRef[] = [];
  const labelIndex = buildLabelIndex(outline);
  // Section numbers this document ties to a code anywhere in its text.
  const statutoryLabels = new Set<string>();
  // Acronyms of statutes cited into another authority's numbering.
  const statuteAcronyms = new Set<string>(SEED_STATUTE_ACRONYMS);
  forEachParagraph(tree, (ctx) => {
    STATUTE_LABEL_DECLARATION.lastIndex = 0;
    let sm: RegExpExecArray | null;
    while ((sm = STATUTE_LABEL_DECLARATION.exec(ctx.text)) !== null) {
      statutoryLabels.add(sm[1]!.toUpperCase());
    }
    STATUTE_ACRONYM_DEFINITION.lastIndex = 0;
    let am: RegExpExecArray | null;
    while ((am = STATUTE_ACRONYM_DEFINITION.exec(ctx.text)) !== null) {
      statuteAcronyms.add(am[1]!.toUpperCase());
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
    const m = LEADING_SECTION_RE.exec(ctx.text) ?? LEADING_SUBSECTION_RE.exec(ctx.text);
    const norm = m ? normalizeLabel(m[1]!) : undefined;
    if (norm && !labelIndex.has(norm)) labelIndex.set(norm, ctx.paragraph.id);
    const a = LEADING_ARTICLE_RE.exec(ctx.text);
    const aNorm = a ? normalizeLabel(`article ${a[1]!}`) : undefined;
    if (aNorm && !labelIndex.has(aNorm)) labelIndex.set(aNorm, ctx.paragraph.id);
    // A first subsection sharing the article-heading paragraph.
    const ats = ARTICLE_THEN_SECTION_RE.exec(ctx.text);
    const atsNorm = ats ? normalizeLabel(ats[1]!) : undefined;
    if (atsNorm && !labelIndex.has(atsNorm)) labelIndex.set(atsNorm, ctx.paragraph.id);
  });

  forEachParagraph(tree, (ctx) => {
    const leadingArticle = LEADING_ARTICLE_RE.exec(ctx.text);
    const leadingSection = LEADING_SECTION_RE.exec(ctx.text);
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
      if (
        EXTERNAL_TRAILER_RE.test(after) ||
        EXTERNAL_INSTRUMENT_RE.test(after) ||
        EXTERNAL_LEADER_RE.test(before) ||
        EXTERNAL_LEADING_RE.test(before) ||
        STATUTE_SECTION_LABEL.test(m[2] ?? "") ||
        statutoryLabels.has((m[2] ?? "").toUpperCase()) ||
        (acronymTail != null && statuteAcronyms.has(acronymTail[1]!.toUpperCase()))
      ) {
        continue;
      }
      const label = (m[2] ?? "").replace(/\(.*\)$/, "");
      // The outline models Section / Article headings only. An Exhibit,
      // Schedule, or Attachment reference must NOT resolve to a section that
      // merely shares its number — "Schedule 4.2" is not "Section 4.2". The
      // old code keyed on the number alone and confidently linked a schedule
      // to an unrelated section (unresolved:false). Attachment-type refs key
      // into a namespace absent from the section index, so they surface as
      // unresolved for STRUCT-007 instead of a wrong-entity link.
      const isAttachment = /^(?:Exhibit|Schedule|Attachment)$/i.test(keyword);
      const normalized = isAttachment ? undefined : normalizeLabel(label);
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
