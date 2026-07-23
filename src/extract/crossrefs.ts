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
const EXTERNAL_TRAILER_RE =
  /^(?:\(\d+[a-z]?\))*(?:\s+(?:to|through|and|or|,)\s+\d+[A-Za-z]?(?:\(\d+[a-z]?\))*)*\s+(?:of\s+(?:the\s+)?[A-Z][^.;,]*?\b(?:Code|Acts?|Regulations?|Rules?|U\.?\s?S\.?\s?C\.?|C\.?\s?F\.?\s?R\.?)\b|(?:UK\s+|EU\s+)?(?:GDPR|CCPA|CPRA|HIPAA|LGPD|PIPEDA|DPA\s+20\d\d)\b)/;
const EXTERNAL_LEADER_RE = /\b(?:U\.?\s?S\.?\s?C\.?|C\.?\s?F\.?\s?R\.?|Stat\.)\s*$/;

// A paragraph that OPENS with "6. Vendor Indemnity …" is section 6, even when
// the ingester never promoted it to a heading. The paste path (any pasted
// contract) keeps numbered clauses as flat paragraphs under one empty-heading
// section, so the outline carries no numbered labels and a self-reference
// ("under this Section 6") resolved to nothing — STRUCT-007 then reported a
// broken cross-reference to a section printed two lines above it. The number
// must be followed by a capitalized clause title, so a paragraph opening with a
// list marker or an amount ("5,000") is not mistaken for a section.
const LEADING_SECTION_RE = /^\s*(\d+(?:\.\d+)*)\.\s+[A-Z(]/;

export function extractCrossRefs(tree: DocumentTree, outline: SectionOutline): CrossRef[] {
  const refs: CrossRef[] = [];
  const labelIndex = buildLabelIndex(outline);
  // Augment the index with paragraph-leading section numbers the outline missed.
  forEachParagraph(tree, (ctx) => {
    const m = LEADING_SECTION_RE.exec(ctx.text);
    const norm = m ? normalizeLabel(m[1]!) : undefined;
    if (norm && !labelIndex.has(norm)) labelIndex.set(norm, ctx.paragraph.id);
  });

  forEachParagraph(tree, (ctx) => {
    REF_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = REF_RE.exec(ctx.text)) !== null) {
      const keyword = m[1] ?? "";
      // Skip external statutory citations — a reference into another
      // authority's numbering, not this document's outline.
      const after = ctx.text.slice(m.index + m[0].length);
      const before = ctx.text.slice(0, m.index);
      if (EXTERNAL_TRAILER_RE.test(after) || EXTERNAL_LEADER_RE.test(before)) continue;
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
