import type { Rule, RuleContext, Finding } from "../../finding.js";
import type { Section } from "../../../ingest/types.js";
import type { DocPosition } from "../../../extract/types.js";
import { forEachParagraph, forEachSection } from "../../../extract/walk.js";
import { emit, isNonOperative } from "../_helpers.js";

/** A title written after a reference: `Section 7 (Confidentiality)`, `Section 4.2(a) ("Fees")`. */
const TITLE_AFTER =
  /^\s?(?:\([a-z0-9]{1,4}\)){0,4}\s?\(\s?["“]?([A-Z][A-Za-z ,&'’-]{2,60}?)["”]?\s?\)/;
/** A run-in heading: "7. Confidentiality. Each party shall …". */
const RUN_IN =
  /^\s*(?:(?:[Ss]ection|SECTION|[Aa]rticle|ARTICLE)\s+)?(?:[\dIVX]+(?:\.\d+)*\.?\s+)?([A-Z][A-Za-z ,&'’-]{2,60}?)\.\s/;
/** A paragraph that is only a numbered heading: "7. Indemnification". */
const HEADING_ONLY =
  /^\s*(?:(?:[Ss]ection|SECTION|[Aa]rticle|ARTICLE)\s+)?[\dIVX]+(?:\.\d+)*\.?\s+([A-Z][A-Za-z ,&'’-]{2,60}?)\.?\s*$/;
const SMALL = new Set(["and", "of", "the", "or", "for", "to", "in", "on", "a", "an"]);

/** The words that carry a title, cut to a stem so "Confidential" meets "Confidentiality". */
function stems(title: string): string[] {
  return title
    .toLowerCase()
    .replace(/^\s*(?:section|article|§)?\s*[\divx.]+\s+/, "")
    .split(/[^a-z]+/)
    .filter((w) => w.length > 1 && !SMALL.has(w))
    .map((w) => w.slice(0, 6));
}

/** Two titles name the same section when they share a word. */
export function titlesAgree(written: string, heading: string): boolean {
  const h = new Set(stems(heading));
  return h.size === 0 || stems(written).some((w) => h.has(w));
}

/** PROOF-005 — Cross-reference title mismatch (warning). */
export const rule: Rule = {
  id: "PROOF-005",
  version: "1.0.1",
  name: "Cross-reference title mismatch",
  category: "proofreading",
  default_severity: "warning",
  description:
    'Flags a cross-reference whose stated title is not the heading of the section it cites, such as "Section 7 (Confidentiality)" where Section 7 is "Indemnification".',
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const sections = new Map<string, Section>();
    forEachSection(ctx.tree, (s) => sections.set(s.id, s));
    const paragraphs = new Map<string, { text: string; start: number; operative: boolean }>();
    forEachParagraph(ctx.tree, (p) => {
      paragraphs.set(p.paragraph.id, {
        text: p.text,
        start: p.start,
        operative: !isNonOperative(p.text),
      });
    });
    // A reference resolves to a section, or to the numbered paragraph that
    // opens one in a document without headings; either way the title is the
    // heading, the paragraph's whole text when it is only a heading, or the
    // run-in heading that opens it.
    const headingOf = (id: string): string => {
      const own = ctx.extracted.outline.by_id[id]?.heading ?? "";
      if (stems(own).length > 0) return own;
      const text =
        paragraphs.get(id)?.text ??
        sections
          .get(id)
          ?.paragraphs[0]?.runs.map((r) => r.text)
          .join("") ??
        "";
      return HEADING_ONLY.exec(text)?.[1] ?? RUN_IN.exec(text)?.[1] ?? "";
    };
    const hits: Array<{ ref: string; title: string; heading: string; text: string }> = [];
    let firstPosition: DocPosition | undefined;
    for (const ref of ctx.extracted.crossrefs) {
      if (!ref.resolved_id || !ref.position.paragraph_id) continue;
      const p = paragraphs.get(ref.position.paragraph_id);
      if (!p?.operative) continue;
      const m = TITLE_AFTER.exec(p.text.slice(ref.position.end - p.start));
      if (!m) continue;
      const heading = headingOf(ref.resolved_id);
      if (!heading || titlesAgree(m[1]!, heading)) continue;
      hits.push({ ref: ref.raw_text, title: m[1]!, heading: heading.trim(), text: p.text });
      firstPosition ??= ref.position;
    }
    if (hits.length === 0) return null;
    const first = hits[0]!;
    return emit(ctx, rule, {
      title: `Cross-reference title does not match the section (${hits.length})`,
      description: `The document cites ${first.ref} as "${first.title}", and the heading of ${first.ref} is "${first.heading}".`,
      excerpt: first.text,
      explanation:
        "When a reference's number and its title disagree, the reader cannot tell which section was meant; sections renumbered after a draft was written are the usual cause.",
      recommendation: `Point the reference at the section titled "${first.title}", or correct the title to "${first.heading}".`,
      position: firstPosition!,
    });
  },
};
