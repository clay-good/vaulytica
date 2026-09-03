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
      /\b(inc\.?|incorporated|corp\.?|corporation|llc|l\.l\.c\.|lllp|lp|l\.p\.|llp|l\.l\.p\.|ltd\.?|limited|company|co\.?|plc|gmbh|s\.?a\.?|s\.?a\.?r\.?l\.?|n\.?v\.?|ag|pte\.?|sdn\.?\s*bhd\.?)\b/g,
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
    // Compare EXPRESS definitions only. For a PARENTHETICAL term the
    // `definition` field is the text that PRECEDES the parenthetical, sliced
    // back to the last sentence break — for a preamble that is an arbitrary
    // run of the preamble itself. Two documents that both define "Buyer",
    // "Seller", "Company" or "Agreement" in their preambles therefore always
    // "disagree", and the finding quotes two garbage strings at the reader:
    // a stock purchase agreement and the covenant ancillary to it produced
    // four, one of which compared an EMPTY definition against a slice
    // beginning mid-word. A term defined differently in two documents is a
    // real and serious thing; it cannot be detected from the preamble.
    if (ea.form === "parenthetical" || eb.form === "parenthetical") continue;
    const da = normalizeDefinition(ea.definition);
    const db = normalizeDefinition(eb.definition);
    if (!da || !db) continue;
    if (da === db) continue;
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
// Magnitude suffixes, mirroring `SCALES` in src/extract/amounts.ts. This list
// had DRIFTED from that one and was missing the "mm" / "mn" / "kk" shorthands,
// which is not a cosmetic gap: "$5.5mm" does not simply fail to scale, it
// MIS-scales. The optional suffix cannot consume "mm" (the `m` alternative is
// followed by another word character, so the trailing `\b` fails), and the
// number then backtracks to "5" so the "." can supply the boundary — the cap
// reads as FIVE DOLLARS. A bundle whose MSA says "$5,500,000" and whose order
// form says "$5.5mm" would be reported as a 1,100,000x discrepancy between two
// documents that agree exactly.
//
// Full words precede the single letters so `raw_text` stays honest, and "mm"
// and "mn" precede the bare "m" so they are not shadowed by it — the same
// ordering discipline amounts.ts documents. The bare "b" is deliberately NOT
// included: amounts.ts records that it matched the "b" of "by" ("$50 by the
// tenth" read as $50 billion), and nothing here needs it.
const DOLLAR_AMOUNT_RE =
  /\$\s*([\d,]+(?:\.\d+)?)\s*(trillion|billion|million|thousand|hundred|bn|kk|mm|mn|m|k)?\b/gi;

/**
 * The slice of `text` a cap amount may legitimately live in: from the cap
 * anchor to the end of that sentence, cut short at a connective that shifts
 * the subject away from the cap.
 *
 * Both cap parsers used to take the LARGEST `$` figure anywhere in the matched
 * paragraph. Contracts routinely name a bigger, unrelated figure right beside
 * the cap — insurance coverage the party "separately maintains", an amount a
 * carve-out is "exclusive of" — and that figure won, so two documents stating
 * the same cap were reported as conflicting.
 */
const CAP_TOPIC_SHIFT =
  /\b(?:except|exclusive\s+of|other\s+than|provided\s*,?\s*(?:that|however)|separately|in\s+addition\s+to)\b/i;

/** Everything up to the first connective that shifts the subject away from the cap. */
function untilTopicShift(text: string): string {
  const shift = text.search(CAP_TOPIC_SHIFT);
  return shift === -1 ? text : text.slice(0, shift);
}

/**
 * The offset just past the sentence boundary preceding `index`, using the same
 * abbreviation-aware rule as the forward scans: a "." ends a sentence only when
 * followed by whitespace + a capital or digit. `lastIndexOf(".")` would stop at
 * any period at all, including the one in "$2.5 million".
 *
 * Residual limitation, shared with every sentence bound in this codebase: an
 * abbreviation followed by a CAPITALISED word ("Acme Corp. LLC") is
 * indistinguishable from a sentence end by this rule, so a bound taken there
 * starts late. Tightening it means treating a real sentence that ends in
 * "… Acme Inc." as continuing, which trades a false negative for a false
 * positive — the worse direction here.
 */
function sentenceStartBefore(text: string, index: number): number {
  const boundary = new RegExp(SENTENCE_END, "g");
  let start = 0;
  let m: RegExpExecArray | null;
  while ((m = boundary.exec(text)) !== null && m.index < index) {
    start = m.index + 1;
  }
  return start;
}

/**
 * The whole sentence containing `index` — the backward half of the sentence
 * bound the forward window already applies. A "." starts a new sentence only
 * when followed by whitespace + a capital/digit, so "Inc." and "$2.5" do not
 * split it.
 */
function enclosingSentence(text: string, index: number): string {
  const rest = text.slice(sentenceStartBefore(text, index));
  const end = rest.search(new RegExp(SENTENCE_END));
  return end === -1 ? rest : rest.slice(0, end + 1);
}

function capAmountWindow(text: string, anchorIndex: number): string {
  const rest = text.slice(anchorIndex);
  // A "." ends the sentence only before whitespace + a capital/digit, so
  // "Section 14." and "$2.5" are not boundaries.
  const sentenceEnd = rest.search(new RegExp(SENTENCE_END));
  const bounded = sentenceEnd === -1 ? rest : rest.slice(0, sentenceEnd + 1);
  return untilTopicShift(bounded);
}

/** Suffix → multiplier, mirroring `SCALES` in src/extract/amounts.ts. */
const DOLLAR_SCALES: Record<string, number> = {
  k: 1_000,
  kk: 1_000_000,
  m: 1_000_000,
  mm: 1_000_000,
  mn: 1_000_000,
  bn: 1_000_000_000,
  hundred: 100,
  thousand: 1_000,
  million: 1_000_000,
  billion: 1_000_000_000,
  trillion: 1_000_000_000_000,
};

/** The largest `$` amount in `text`, scaled by its magnitude suffix; 0 if none. */
function maxDollarAmount(text: string): number {
  let max = 0;
  for (const m of text.matchAll(DOLLAR_AMOUNT_RE)) {
    const num = Number(m[1]!.replace(/,/g, ""));
    if (!Number.isFinite(num)) continue;
    const suffix = (m[2] ?? "").toLowerCase();
    const scaled = num * (DOLLAR_SCALES[suffix] ?? 1);
    if (scaled > max) max = scaled;
  }
  return max;
}

/** Every index in `text` where the cap anchor matches. */
function anchorIndices(text: string, anchor: RegExp): number[] {
  const scan = new RegExp(
    anchor.source,
    anchor.flags.includes("g") ? anchor.flags : anchor.flags + "g",
  );
  const out: number[] = [];
  let m: RegExpExecArray | null;
  while ((m = scan.exec(text)) !== null) {
    out.push(m.index);
    if (m.index === scan.lastIndex) scan.lastIndex++;
  }
  return out;
}

/**
 * The cap amount for a paragraph, read from the cap window of whichever anchor
 * actually carries a figure.
 *
 * EVERY anchor is tried, not just the first, because the first is routinely
 * the section HEADING: "Limitation of Liability. Each party's aggregate
 * liability … shall not exceed ($2,000,000)." Bounding on the heading alone
 * yields "Limitation of Liability." and no amount at all — the same trap the
 * survival parser fell into, and it silently dropped the cap-mismatch bundle
 * golden's only finding.
 *
 * A cap is also often stated AHEAD of its anchor ("The sum of $500,000 shall
 * be the maximum aggregate liability …"), which the forward-only window
 * cannot see, so a second pass widens to each anchor's own SENTENCE. It stays
 * inside that sentence and still stops at the first topic shift; widening
 * further reintroduces the very bug the window exists to prevent. That took
 * two corrections: the whole paragraph let a figure behind the anchor win
 * ("exclusive of the $5,000,000 …"), and cutting only at a topic-shift
 * connective still let a PRECEDING sentence win, where there is no connective
 * to stop on ("Provider maintains $10,000,000 of cyber insurance. The sum of
 * $500,000 shall be the maximum aggregate liability …").
 */
function capAmountFrom(text: string, indices: readonly number[]): number {
  for (const i of indices) {
    const v = maxDollarAmount(capAmountWindow(text, i));
    if (v > 0) return v;
  }
  for (const i of indices) {
    const v = maxDollarAmount(untilTopicShift(enclosingSentence(text, i)));
    if (v > 0) return v;
  }
  return 0;
}

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
  type Hit = {
    paragraph_text: string;
    anchor_indices: number[];
    section_id?: string;
    start: number;
    end: number;
  };
  const slot: { value: Hit | null } = { value: null };
  walkParagraphs(tree, (p) => {
    if (slot.value) return;
    const indices = anchorIndices(p.text, anchorRe);
    if (indices.length > 0) {
      slot.value = {
        paragraph_text: p.text,
        anchor_indices: indices,
        section_id: p.section_id,
        start: p.start,
        end: p.end,
      };
    }
  });
  if (!slot.value) return null;
  const found: Hit = slot.value;
  const max = capAmountFrom(found.paragraph_text, found.anchor_indices);
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
import { forEachParagraph, SENTENCE_END } from "../../../../extract/walk.js";
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
    /capitali[sz]ed\s+terms?\s+(?:not|used|that\s+are\s+not)\b[^.]{0,80}?(?:defined|meaning)/i.test(
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
  // Added the "will/may not exceed" and "in no event … exceed" cap phrasings
  // (the same class BAA-025 broadened) so an indemnity cap written those ways is
  // not missed by the cross-document cap-stacking check.
  const limitRe =
    /\b(not\s+to\s+exceed|(?:shall|will|may|can)\s+not\s+exceed|in\s+no\s+event\s+[^.]{0,60}\bexceed|capped\s+at|limited\s+to|up\s+to|maximum\s+(?:aggregate\s+)?(?:amount|liability))\b/i;
  type Hit = {
    text: string;
    anchor_indices: number[];
    section_id?: string;
    start: number;
    end: number;
  };
  const slot: { value: Hit | null } = { value: null };
  forEachParagraph(doc.tree, (p) => {
    if (slot.value) return;
    const indices = anchorIndices(p.text, capRe);
    if (indices.length > 0 && limitRe.test(p.text) && /\$/.test(p.text)) {
      slot.value = {
        text: p.text,
        anchor_indices: indices,
        section_id: p.section.id || undefined,
        start: p.start,
        end: p.end,
      };
    }
  });
  if (!slot.value) return null;
  const found: Hit = slot.value;
  const max = capAmountFrom(found.text, found.anchor_indices);
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
 * termination. Returns a normalized duration in `months` (or "perpetual") plus
 * a human descriptor and the paragraph for the excerpt, or null when no
 * confidentiality-survival statement is found. Cross-doc conflict = two
 * documents that survive confidentiality for materially different periods; the
 * numeric `months` field is what CROSS-SURVIVAL-001 compares, so "12 months"
 * and "1 year" are correctly treated as equal.
 */
export function confidentialitySurvival(doc: ConsistencyDocument): {
  descriptor: string;
  months: number | "perpetual";
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
      months: "perpetual",
      raw_text: found.text,
      section_id: found.section_id,
      start: found.start,
      end: found.end,
    };
  }
  // Anchor the period to the survival statement itself: scan from the
  // "surviv…" keyword forward, so an unrelated earlier figure (the contract
  // Term, a lookback window) can't be read as the survival period. Match a
  // number of years OR months, tolerating the "three (3) years" drafting form
  // (grab the parenthetical digit) as well as a plain "3 years"/"18 months".
  //
  // The scan needs the same bound on its right edge. Sliced open-ended to the
  // end of the paragraph, a survival sentence that states no period at all
  // ("shall survive termination as set forth herein.") ran on into the next,
  // unrelated sentence and reported ITS figure — an audit-records retention
  // period became the confidentiality survival term.
  //
  // Every "surviv…" mention gets its own bounded sentence, because the first
  // one is routinely the section heading ("Survival. The confidentiality
  // obligations … shall survive termination for three (3) years."): bounding
  // from the heading alone yields just "Survival." and loses the real period.
  // A sentence that never says "surviv…" is never scanned, so the unrelated
  // neighbour still cannot contribute its figure.
  const ym = firstSurvivalDuration(found.text);
  if (ym) {
    const n = Number(ym[1]);
    if (Number.isFinite(n) && n > 0) {
      const isMonth = /^month/i.test(ym[2]!);
      return {
        descriptor: isMonth ? `${n} month(s)` : `${n} year(s)`,
        months: isMonth ? n : n * 12,
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
 * The first year/month duration stated inside a sentence that mentions
 * survival. Returns the regex match (group 1 = digits, group 2 = unit), or
 * null when no survival sentence in the paragraph states a period.
 */
function firstSurvivalDuration(text: string): RegExpMatchArray | null {
  const anchor = /\bsurviv\w+/gi;
  let m: RegExpExecArray | null;
  while ((m = anchor.exec(text)) !== null) {
    const rest = text.slice(m.index);
    const sentenceEnd = rest.search(new RegExp(SENTENCE_END));
    const sentence = sentenceEnd === -1 ? rest : rest.slice(0, sentenceEnd + 1);
    const ym = sentence.match(/(\d+)\s*\)?\s*(years?|months?)\b/i);
    if (ym) return ym;
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
/**
 * Negated convenience-termination: a "not / no / neither / never" that governs
 * the terminate verb feeding "for convenience". Used to keep
 * {@link terminationPosture} from mislabeling "may not be terminated for
 * convenience" as convenience-terminable. Two shapes are negated: a negator
 * that precedes the terminate verb ("may not be terminated for convenience")
 * and a negator fused directly to the phrase ("...for cause only, and not for
 * convenience"). A trailing negator that governs something else — e.g. "may
 * terminate for convenience, but not for cause" — is left affirmative because
 * its "not" is followed by "for cause", not "for convenience".
 */
const NEG_CONVENIENCE =
  /\bnot\s+for\s+convenience\b|\b(?:not|never|no|neither)\b[^.]{0,40}?\b(?:terminat\w*|terminable)\b[^.]{0,60}?\bfor\s+convenience\b/i;

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
      (/\b(?:non-?terminable|may\s+not\s+be\s+terminated|not\s+terminable|(?:shall|will)\s+not\s+be\s+terminated)\b[^.]*?\b(?:except|other\s+than|save)\b[^.]*?\bcause\b/i.test(
        p.text,
      ) ||
        /\bterminat\w*\b[^.]*?\bonly\s+for\s+cause\b/i.test(p.text))
    ) {
      slot.causeOnly = { text: p.text, section_id: p.section_id, start: p.start, end: p.end };
    }
    if (
      !slot.convenience &&
      /\bterminat\w*\b[^.]*?\bfor\s+convenience\b/i.test(p.text) &&
      // A negated convenience-termination ("may not be terminated for
      // convenience", "neither party may terminate ... for convenience", "no
      // right to terminate for convenience") is the OPPOSITE of a convenience
      // right, so it must not be read as one. The negator has to govern the
      // terminate verb that feeds "for convenience"; a trailing "not" (e.g.
      // "may terminate for convenience, but not for cause") is left affirmative.
      !NEG_CONVENIENCE.test(p.text)
    ) {
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
/** Continuation markers that mark a later exception sentence as still enumerating the same carveout list. */
const CARVEOUT_CONTINUATION =
  /\b(?:also|further(?:more)?|likewise|additionally|nor|in\s+addition)\b/i;

/**
 * The exception clauses of a paragraph: the first trigger's own sentence, plus
 * any later trigger sentence that reads as a continuation of the same list.
 * Each is bounded at the sentence end (never at a ";", which separates the
 * items of a single enumeration).
 */
function exceptionClauses(text: string, triggerRe: RegExp): string[] {
  const scan = new RegExp(triggerRe.source, "gi");
  const out: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = scan.exec(text)) !== null) {
    const rest = text.slice(m.index);
    const sentenceEnd = rest.search(new RegExp(SENTENCE_END));
    const clause = sentenceEnd === -1 ? rest : rest.slice(0, sentenceEnd + 1);
    if (out.length === 0) {
      out.push(clause);
      continue;
    }
    // Judge continuation on the whole sentence, not just the text after the
    // trigger — the marker usually sits before it ("It ALSO shall not apply").
    //
    // The backward scan has to use the same abbreviation-aware boundary as
    // every other sentence bound in this file. A plain `lastIndexOf(".")`
    // stops at any period, including one inside "Acme Corp." or "$2.5
    // million" sitting between the marker and the trigger — which starts the
    // window AFTER the marker, so the continuation is not seen and a real
    // carveout is silently dropped.
    const sentenceStart = sentenceStartBefore(text, m.index);
    if (CARVEOUT_CONTINUATION.test(text.slice(sentenceStart, m.index + clause.length))) {
      out.push(clause);
    }
  }
  return out;
}

export function liabilityCarveouts(
  doc: ConsistencyDocument,
): { set: string[]; raw_text: string; section_id?: string; start: number; end: number } | null {
  type Hit = { text: string; section_id?: string; start: number; end: number; set: string[] };
  const capContextRe =
    /\b(?:liability|limitation\s+of\s+liability|(?:shall|will)\s+not\s+exceed|aggregate\s+liability)\b/i;
  const exceptionRe =
    /\b(?:(?:shall|will)\s+not\s+apply|do(?:es)?\s+not\s+apply|except(?:ions?)?|excluding|other\s+than)\b/i;
  const slot: { value: Hit | null } = { value: null };
  walkParagraphs(doc.tree, (p) => {
    if (slot.value) return;
    if (!capContextRe.test(p.text)) return;
    const ex = exceptionRe.exec(p.text);
    if (!ex) return;
    // Scan for carveout categories only in the exception clause itself — the
    // text at and after the "shall not apply" / "except" trigger — not the whole
    // paragraph. Otherwise categories named in an unrelated earlier sentence
    // (e.g. an indemnity sentence in the same clause) are fabricated into a
    // carveout set that no cap actually excepts.
    //
    // The right edge needs the same bound: an open-ended slice ran on into a
    // LATER unrelated sentence ("… gross negligence. Except as required by
    // applicable law, breach-notification obligations are governed by Section
    // 12 …") and fabricated a "data breach" carveout the cap never excepted.
    // Stop at the next sentence, but not at a ";" — carveout enumerations are
    // routinely semicolon-separated lists.
    //
    // A list may legitimately CONTINUE into a following sentence ("… shall not
    // apply to gross negligence. It also shall not apply to breach of
    // confidentiality."), so later exception sentences contribute too — but
    // only when they carry a continuation marker. That is what separates a
    // continuation from the unrelated boilerplate this bound exists to reject:
    // "Except as required by applicable law, …" opens a new subject, and
    // nothing in it says it is still enumerating the cap's exceptions.
    const clause = exceptionClauses(p.text, exceptionRe).join(" ");
    const set = CARVEOUT_TERMS.filter(([, re]) => re.test(clause)).map(([label]) => label);
    if (set.length === 0) return;
    slot.value = { text: p.text, section_id: p.section_id, start: p.start, end: p.end, set };
  });
  if (!slot.value) return null;
  const found: Hit = slot.value;
  return {
    set: found.set,
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
