/**
 * Internal helpers shared by the v4 CROSS-* rules.
 *
 * These build on the v3 helpers under `../_finding.ts` and
 * `../../_helpers.ts`; v4-specific bits live here so the v3 rules stay
 * untouched.
 */

import type { ConsistencyDocument } from "../../types.js";
import type { Party } from "../../../../extract/types.js";

/**
 * Normalize a party name for comparison across documents.
 *
 * Strips entity suffixes (Inc., Inc, Corp., Corp, LLC, LP, L.P., Ltd.,
 * Limited, Company, Co., Co), drops commas / periods, collapses
 * whitespace, lowercases. Two names that map to the same normalized
 * form should be the same legal entity in the eyes of a counterparty —
 * but the *original* difference is interesting because lenders, IP
 * licensors, and tax authorities sometimes care.
 */
export function normalizePartyName(name: string): string {
  return name
    .toLowerCase()
    .replace(
      /\b(inc\.?|corp\.?|corporation|llc|l\.l\.c\.|lp|l\.p\.|llp|l\.l\.p\.|ltd\.?|limited|company|co\.?|plc|gmbh|s\.?a\.?|s\.?a\.?r\.?l\.?|n\.?v\.?|ag|pte\.?|sdn\.?\s*bhd\.?)\b/g,
      "",
    )
    .replace(/[,.()]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Find pairs of parties across two documents that normalize to the
 * same canonical name but have different *original* names. Returns
 * empty when no near-duplicate pairs exist.
 */
export function findPartyNameMismatches(
  docA: ConsistencyDocument,
  docB: ConsistencyDocument,
): Array<{ a: Party; b: Party; canonical: string }> {
  // For each document, dedupe parties by canonical name and keep the
  // *longest* original-name representative. The extractor sometimes
  // returns the same party twice with subtly different boundaries
  // ("Acme Corp.," and "Acme Corp"); without dedup we'd flag the doc
  // against itself.
  const repA = canonicalReps(docA.extracted.parties);
  const repB = canonicalReps(docB.extracted.parties);
  const out: Array<{ a: Party; b: Party; canonical: string }> = [];
  for (const [canon, a] of repA) {
    const b = repB.get(canon);
    if (!b) continue;
    // Light strip-then-compare: trailing punctuation differences are
    // not a mismatch the linter should flag (they're upstream parsing
    // noise). Real mismatches differ in suffix tokens, e.g., "Inc."
    // vs "Corp." or in non-suffix tokens.
    if (stripTrailingPunctuation(a.name) === stripTrailingPunctuation(b.name)) continue;
    out.push({ a, b, canonical: canon });
  }
  return out;
}

function canonicalReps(parties: ReadonlyArray<Party>): Map<string, Party> {
  const reps = new Map<string, Party>();
  for (const p of parties) {
    const canon = normalizePartyName(p.name);
    if (!canon) continue;
    const existing = reps.get(canon);
    if (!existing || p.name.length > existing.name.length) {
      reps.set(canon, p);
    }
  }
  return reps;
}

function stripTrailingPunctuation(s: string): string {
  return s.replace(/[\s,.;:]+$/, "");
}

/**
 * Definition-text normalization for cross-doc compare. We don't
 * lowercase because punctuation + word order both matter ("means" vs
 * "shall mean" is the same; "Includes Schedule A" vs "Includes
 * Schedule B" is not). The normalizer collapses whitespace and trims.
 */
export function normalizeDefinition(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}

/**
 * Find defined terms that appear in both documents with different
 * definitions. Returns one entry per term, citing the first paragraph
 * in each document.
 */
export function findDefinedTermMismatches(
  docA: ConsistencyDocument,
  docB: ConsistencyDocument,
): Array<{
  term: string;
  a: { definition: string; section_id?: string; start: number; end: number };
  b: { definition: string; section_id?: string; start: number; end: number };
}> {
  const out: Array<{
    term: string;
    a: { definition: string; section_id?: string; start: number; end: number };
    b: { definition: string; section_id?: string; start: number; end: number };
  }> = [];
  const byTermA = new Map<string, (typeof docA.extracted.definitions.entries)[number]>();
  for (const e of docA.extracted.definitions.entries) {
    byTermA.set(e.term.toLowerCase(), e);
  }
  for (const eb of docB.extracted.definitions.entries) {
    const ea = byTermA.get(eb.term.toLowerCase());
    if (!ea) continue;
    if (normalizeDefinition(ea.definition) === normalizeDefinition(eb.definition)) continue;
    out.push({
      term: eb.term,
      a: {
        definition: ea.definition,
        section_id: ea.defined_at.section_id,
        start: ea.defined_at.start,
        end: ea.defined_at.end,
      },
      b: {
        definition: eb.definition,
        section_id: eb.defined_at.section_id,
        start: eb.defined_at.start,
        end: eb.defined_at.end,
      },
    });
  }
  return out;
}

/**
 * Look up the first absolute date in a document's extracted dates,
 * preferring a "named-anchor" Effective Date when present. Used by
 * CROSS-DATE-001 to compare the effective date stated in document A
 * against the effective date referenced in document B's body.
 */
export function effectiveDateOf(doc: ConsistencyDocument): string | null {
  for (const d of doc.extracted.dates) {
    if (d.type === "named-anchor" && /effective/i.test(d.anchor ?? "") && d.iso) {
      return d.iso;
    }
  }
  for (const d of doc.extracted.dates) {
    if (d.type === "absolute" && d.iso) return d.iso;
  }
  return null;
}

/**
 * Parse the first liability-cap amount-like phrase in a document.
 * Returns the matched MoneyReference plus the surrounding paragraph
 * text for the finding excerpt, or null when no cap is detected.
 *
 * The heuristic anchors on a small set of cap-related phrasings:
 * "aggregate liability", "shall not exceed", "limited to". For
 * fee-multiple caps ("12 months of fees") the function returns null —
 * those aren't directly comparable as dollar amounts.
 */
export function firstLiabilityCap(
  doc: ConsistencyDocument,
): { amount_usd: number; raw_text: string; section_id?: string; start: number; end: number } | null {
  // The body-text scan looks for the cap anchor; the matched paragraph
  // then surfaces its highest dollar amount as the cap value.
  const tree = doc.tree;
  const anchorRe =
    /\b(aggregate\s+liability|liability\s+(?:shall|will)\s+not\s+exceed|limitation\s+of\s+liability)\b/i;
  type Hit = { paragraph_text: string; section_id?: string; start: number; end: number };
  const slot: { value: Hit | null } = { value: null };
  walkParagraphs(tree, (p) => {
    if (slot.value) return;
    if (anchorRe.test(p.text)) {
      slot.value = { paragraph_text: p.text, section_id: p.section_id, start: p.start, end: p.end };
    }
  });
  if (!slot.value) return null;
  const found: Hit = slot.value;
  // Find the largest $X dollar amount in the paragraph.
  const amounts = [...found.paragraph_text.matchAll(/\$\s*([\d,]+(?:\.\d+)?)\s*(million|thousand|m|k)?/gi)];
  if (amounts.length === 0) return null;
  let max = 0;
  for (const m of amounts) {
    const num = Number(m[1]!.replace(/,/g, ""));
    if (!Number.isFinite(num)) continue;
    const suffix = (m[2] ?? "").toLowerCase();
    const scaled =
      suffix === "million" || suffix === "m"
        ? num * 1_000_000
        : suffix === "thousand" || suffix === "k"
          ? num * 1_000
          : num;
    if (scaled > max) max = scaled;
  }
  if (max === 0) return null;
  return {
    amount_usd: max,
    raw_text: found.paragraph_text,
    section_id: found.section_id,
    start: found.start,
    end: found.end,
  };
}

import type { DocumentTree } from "../../../../ingest/types.js";
import { forEachParagraph } from "../../../../extract/walk.js";

function walkParagraphs(
  tree: DocumentTree,
  fn: (ctx: { text: string; section_id?: string; start: number; end: number }) => void,
): void {
  forEachParagraph(tree, (p) => {
    fn({ text: p.text, section_id: p.section.id || undefined, start: p.start, end: p.end });
  });
}
