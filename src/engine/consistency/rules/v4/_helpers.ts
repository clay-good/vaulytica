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
export function firstLiabilityCap(doc: ConsistencyDocument): {
  amount_usd: number;
  raw_text: string;
  section_id?: string;
  start: number;
  end: number;
} | null {
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
  const amounts = [
    ...found.paragraph_text.matchAll(/\$\s*([\d,]+(?:\.\d+)?)\s*(million|thousand|m|k)?/gi),
  ];
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
import type { DocPosition } from "../../../../extract/types.js";
import { forEachParagraph } from "../../../../extract/walk.js";
import { fullText } from "../../_helpers.js";

/**
 * Does the document carry an "incorporation by reference" clause — the
 * standard drafting move that says undefined capitalized terms take their
 * meaning from another agreement? When present, a capitalized-but-undefined
 * term is *intentional*, not a drift, so CROSS-DEFTERM-002 must not fire.
 */
export function hasIncorporationByReference(doc: ConsistencyDocument): boolean {
  const text = fullText(doc);
  return (
    /capitalized\s+terms?\s+(?:not|used|that\s+are\s+not)\b[^.]{0,80}?(?:defined|meaning)/i.test(
      text,
    ) ||
    /(?:meanings?|definitions?)\s+(?:given|set\s+forth|assigned|ascribed)\b[^.]{0,60}?\b(?:in|under)\b/i.test(
      text,
    )
  );
}

/**
 * Defined-term *usage* drift (distinct from the *definition* drift
 * CROSS-DEFTERM-001 catches): a term is **defined** in `definer` and used
 * as a capitalized term in `user` but **not defined there**, and `user`
 * carries no incorporation-by-reference clause. The term silently borrows
 * `definer`'s meaning — a chain-of-meaning the reviewer should make explicit.
 */
export function findDefinedTermUsageDrift(
  definer: ConsistencyDocument,
  user: ConsistencyDocument,
): Array<{ term: string; definition: string; def_pos: DocPosition; use_pos: DocPosition }> {
  if (hasIncorporationByReference(user)) return [];
  const userDefined = new Set(user.extracted.definitions.entries.map((e) => e.term.toLowerCase()));
  const out: Array<{
    term: string;
    definition: string;
    def_pos: DocPosition;
    use_pos: DocPosition;
  }> = [];
  for (const def of definer.extracted.definitions.entries) {
    const key = def.term.toLowerCase();
    if (userDefined.has(key)) continue;
    // Only multi-word, Title-Case terms are unambiguous "defined-term" uses;
    // a single common word (e.g. "Services") would over-fire.
    if (!/\s/.test(def.term.trim())) continue;
    // Find the first paragraph in `user` that uses the term verbatim (with
    // its defined casing). The defined-term casing carries the signal.
    const re = new RegExp(`\\b${escapeRegExp(def.term)}\\b`);
    let usePos: DocPosition | null = null;
    forEachParagraph(user.tree, (p) => {
      if (usePos) return;
      const idx = p.text.search(re);
      if (idx >= 0) usePos = { section_id: p.section.id, start: p.start, end: p.end };
    });
    if (!usePos) continue;
    out.push({
      term: def.term,
      definition: def.definition,
      def_pos: def.defined_at,
      use_pos: usePos,
    });
  }
  return out;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Parse the first indemnification cap in a document: a paragraph that names
 * an indemnity ("indemnif…") *and* a cap phrasing, surfacing the largest $
 * amount in that paragraph. Anchors on "indemnif" (not "aggregate
 * liability"), so it covers a different surface than {@link firstLiabilityCap}
 * / CROSS-AMOUNT-001 — indemnity caps commonly sit above the general
 * liability cap, and an order form that re-states one stacks ambiguously.
 */
export function firstIndemnityCap(doc: ConsistencyDocument): {
  amount_usd: number;
  raw_text: string;
  section_id?: string;
  start: number;
  end: number;
} | null {
  const capRe = /\b(indemnif\w+)\b/i;
  const limitRe =
    /\b(not\s+to\s+exceed|shall\s+not\s+exceed|capped\s+at|limited\s+to|up\s+to|maximum\s+(?:aggregate\s+)?(?:amount|liability))\b/i;
  type Hit = { text: string; section_id?: string; start: number; end: number };
  const slot: { value: Hit | null } = { value: null };
  forEachParagraph(doc.tree, (p) => {
    if (slot.value) return;
    if (capRe.test(p.text) && limitRe.test(p.text) && /\$/.test(p.text)) {
      slot.value = {
        text: p.text,
        section_id: p.section.id || undefined,
        start: p.start,
        end: p.end,
      };
    }
  });
  if (!slot.value) return null;
  const found: Hit = slot.value;
  const amounts = [...found.text.matchAll(/\$\s*([\d,]+(?:\.\d+)?)\s*(million|thousand|m|k)?/gi)];
  let max = 0;
  for (const m of amounts) {
    const num = Number(m[1]!.replace(/,/g, ""));
    if (!Number.isFinite(num)) continue;
    const s = (m[2] ?? "").toLowerCase();
    const scaled =
      s === "million" || s === "m"
        ? num * 1_000_000
        : s === "thousand" || s === "k"
          ? num * 1_000
          : num;
    if (scaled > max) max = scaled;
  }
  if (max === 0) return null;
  return {
    amount_usd: max,
    raw_text: found.text,
    section_id: found.section_id,
    start: found.start,
    end: found.end,
  };
}

/**
 * Detect how a document treats the *survival* of confidentiality after
 * termination. Returns a normalized descriptor — a number of years, or
 * "perpetual" — plus the paragraph for the excerpt, or null when no
 * confidentiality-survival statement is found. Cross-doc conflict = two
 * documents that survive confidentiality for materially different periods.
 */
export function confidentialitySurvival(doc: ConsistencyDocument): {
  descriptor: string;
  years: number | "perpetual";
  raw_text: string;
  section_id?: string;
  start: number;
  end: number;
} | null {
  type Hit = { text: string; section_id?: string; start: number; end: number };
  const slot: { value: Hit | null } = { value: null };
  forEachParagraph(doc.tree, (p) => {
    if (slot.value) return;
    if (/\bsurviv\w+/i.test(p.text) && /\bconfidential/i.test(p.text)) {
      slot.value = {
        text: p.text,
        section_id: p.section.id || undefined,
        start: p.start,
        end: p.end,
      };
    }
  });
  if (!slot.value) return null;
  const found: Hit = slot.value;
  if (
    /\b(perpetu\w+|indefinit\w+|in\s+perpetuity|no\s+expiration|without\s+(?:limit|expiration)|forever)\b/i.test(
      found.text,
    )
  ) {
    return {
      descriptor: "perpetual",
      years: "perpetual",
      raw_text: found.text,
      section_id: found.section_id,
      start: found.start,
      end: found.end,
    };
  }
  // Match the number of years, tolerating the "three (3) years" drafting
  // form (grab the parenthetical digit) as well as a plain "3 years".
  const ym = found.text.match(/(\d+)\s*\)?\s*years?\b/i);
  if (ym) {
    const y = Number(ym[1]);
    if (Number.isFinite(y) && y > 0) {
      return {
        descriptor: `${y} year(s)`,
        years: y,
        raw_text: found.text,
        section_id: found.section_id,
        start: found.start,
        end: found.end,
      };
    }
  }
  return null;
}

/**
 * The document's dominant currency: the most-referenced currency code
 * across its extracted amounts (alphabetical tie-break for
 * determinism), with a representative excerpt. Null when the document
 * states no monetary amount. Cross-doc conflict (CROSS-CURRENCY-001) =
 * two documents in one bundle whose dominant currencies differ.
 */
export function dominantCurrency(
  doc: ConsistencyDocument,
): { currency: string; raw_text: string; section_id?: string; start: number; end: number } | null {
  const amts = doc.extracted.amounts;
  if (amts.length === 0) return null;
  const counts = new Map<string, number>();
  for (const a of amts) counts.set(a.currency, (counts.get(a.currency) ?? 0) + 1);
  let best: string | null = null;
  let bestN = 0;
  for (const [cur, n] of [...counts].sort((a, b) => a[0].localeCompare(b[0], "en"))) {
    if (n > bestN) {
      bestN = n;
      best = cur;
    }
  }
  if (!best) return null;
  const sample = amts.find((a) => a.currency === best)!;
  return {
    currency: best,
    raw_text: sample.raw_text,
    section_id: sample.position.section_id,
    start: sample.position.start,
    end: sample.position.end,
  };
}

/**
 * How a document treats termination: "convenience" (terminable on
 * notice without cause) or "cause-only" (non-terminable except for
 * cause). Returns the first posture found, the stronger "cause-only"
 * signal taking priority. Cross-doc conflict (CROSS-TERM-001) = a
 * convenience-terminable master over a cause-only companion, where
 * early termination of the master orphans the bound companion.
 */
export function terminationPosture(doc: ConsistencyDocument): {
  posture: "convenience" | "cause-only";
  raw_text: string;
  section_id?: string;
  start: number;
  end: number;
} | null {
  type Hit = { text: string; section_id?: string; start: number; end: number };
  const slot: { convenience: Hit | null; causeOnly: Hit | null } = {
    convenience: null,
    causeOnly: null,
  };
  walkParagraphs(doc.tree, (p) => {
    if (
      !slot.causeOnly &&
      (/\b(?:non-?terminable|may\s+not\s+be\s+terminated|not\s+terminable|shall\s+not\s+be\s+terminated)\b[^.]*?\b(?:except|other\s+than|save)\b[^.]*?\bcause\b/i.test(
        p.text,
      ) ||
        /\bterminat\w*\b[^.]*?\bonly\s+for\s+cause\b/i.test(p.text))
    ) {
      slot.causeOnly = { text: p.text, section_id: p.section_id, start: p.start, end: p.end };
    }
    if (!slot.convenience && /\bterminat\w*\b[^.]*?\bfor\s+convenience\b/i.test(p.text)) {
      slot.convenience = { text: p.text, section_id: p.section_id, start: p.start, end: p.end };
    }
  });
  if (slot.causeOnly) {
    const h = slot.causeOnly;
    return {
      posture: "cause-only",
      raw_text: h.text,
      section_id: h.section_id,
      start: h.start,
      end: h.end,
    };
  }
  if (slot.convenience) {
    const h = slot.convenience;
    return {
      posture: "convenience",
      raw_text: h.text,
      section_id: h.section_id,
      start: h.start,
      end: h.end,
    };
  }
  return null;
}

/** Normalized carveout categories recognized in a liability-cap exception clause. */
const CARVEOUT_TERMS: Array<[string, RegExp]> = [
  ["IP infringement", /\b(?:intellectual\s+property|ip\s+infringement|infringement)\b/i],
  ["confidentiality", /\bconfidential(?:ity)?\b/i],
  ["indemnification", /\bindemnif\w+/i],
  ["gross negligence", /\bgross\s+negligence\b/i],
  ["willful misconduct", /\b(?:willful|wilful)\s+misconduct\b/i],
  ["bodily injury", /\b(?:bodily|personal)\s+injury\b/i],
  ["death", /\bdeath\b/i],
  ["fraud", /\bfraud\b/i],
  ["data breach", /\b(?:data\s+breach|security\s+breach|breach\s+of\s+data)\b/i],
];

/**
 * The set of carveouts that a document excepts from its liability cap
 * ("the foregoing limitation shall not apply to … IP infringement,
 * confidentiality, bodily injury"). Returns the normalized category set
 * + excerpt, or null when no carveout clause is found. Cross-doc
 * conflict (CROSS-CARVEOUT-001) = two documents whose carveout sets
 * differ — an asymmetric allocation trap.
 */
export function liabilityCarveouts(
  doc: ConsistencyDocument,
): { set: string[]; raw_text: string; section_id?: string; start: number; end: number } | null {
  type Hit = { text: string; section_id?: string; start: number; end: number };
  const slot: { value: Hit | null } = { value: null };
  walkParagraphs(doc.tree, (p) => {
    if (slot.value) return;
    const capContext =
      /\b(?:liability|limitation\s+of\s+liability|shall\s+not\s+exceed|aggregate\s+liability)\b/i.test(
        p.text,
      );
    const exception =
      /\b(?:shall\s+not\s+apply|do(?:es)?\s+not\s+apply|except(?:ions?)?|excluding|other\s+than)\b/i.test(
        p.text,
      );
    if (capContext && exception) {
      slot.value = { text: p.text, section_id: p.section_id, start: p.start, end: p.end };
    }
  });
  if (!slot.value) return null;
  const found: Hit = slot.value;
  const set = CARVEOUT_TERMS.filter(([, re]) => re.test(found.text)).map(([label]) => label);
  if (set.length === 0) return null;
  return {
    set,
    raw_text: found.text,
    section_id: found.section_id,
    start: found.start,
    end: found.end,
  };
}

function walkParagraphs(
  tree: DocumentTree,
  fn: (ctx: { text: string; section_id?: string; start: number; end: number }) => void,
): void {
  forEachParagraph(tree, (p) => {
    fn({ text: p.text, section_id: p.section.id || undefined, start: p.start, end: p.end });
  });
}
