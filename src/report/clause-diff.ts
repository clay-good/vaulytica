/**
 * Clause-level text diff for version comparison (spec-v8 Part XVIII — the
 * deferred "comparison redline").
 *
 * The {@link Comparison} engine (`compare.ts`) diffs two `EngineRun`s and tells
 * you which *findings* resolved / introduced / persisted. It does not show the
 * actual clause text that moved. This module is the complement: a deterministic
 * paragraph-level diff of the two documents' text, so a reviewer sees *which
 * clauses were added, removed, or rewritten* — the redline a finding delta
 * implies but never displays.
 *
 * Posture (§3): pure and deterministic — a Myers-style LCS over normalized
 * clause text, no AI, no network, no clock. It is a *render-side* surface
 * derived from the two documents already in the tab; it lives **outside** the
 * comparison `result_hash`, so adding it churns no existing comparison golden
 * (the same precedent as model-clause references and jurisdiction overlays).
 *
 * Bounds (spec-v8 §5): the LCS table is O(base × revised) clauses. A
 * pathological pair (two 50,000-paragraph documents) would allocate billions of
 * cells, so past a cell ceiling the diff degrades to a bounded set-based diff
 * (membership, not alignment — it cannot *pair* a rewrite, only list the add
 * and the remove) and sets `truncated`. Never a timeout; always a bound.
 */

import type { DocumentTree, Section } from "../ingest/types.js";

/** A single comparable unit of document text (one non-empty paragraph). */
export type Clause = {
  /** Stable paragraph id (e.g. `s2.p3`), for provenance. */
  id: string;
  /** Nearest enclosing section heading, for context (`""` if none). */
  heading: string;
  /** Display text — the paragraph's runs joined and trimmed (original spacing). */
  text: string;
  /**
   * Match key — `text` with insignificant whitespace collapsed and a leading
   * clause number removed. The number is where a clause SITS, not what it
   * says: inserting one clause renumbers every clause after it, and with the
   * number in the key each of those read as rewritten.
   */
  key: string;
  /** The leading clause number the key dropped (`"7."`, `"(a)"`), or `""`. */
  number: string;
};

/** One run of the inline word-level redline of a rewritten clause. */
export type WordDiffSegment = { text: string; status: "equal" | "removed" | "added" };

/**
 * A base clause paired with the revised clause that replaced it, plus the
 * inline word-level redline between them (`null` when either side has too many
 * tokens to align — the renderer falls back to showing the two full texts).
 */
export type ClausePair = { base: Clause; revised: Clause; word_diff: WordDiffSegment[] | null };

export type ClauseDiff = {
  /** Clauses present in the revised document with no base counterpart. */
  added: Clause[];
  /** Clauses present in the base document with no revised counterpart. */
  removed: Clause[];
  /** A base clause rewritten into a revised clause (a replaced block). */
  changed: ClausePair[];
  /**
   * Clauses whose words are the same and whose NUMBER moved — what an
   * insertion or a deletion above them does. Not an edit, and not counted in
   * `unchanged_count`: a reader checking a renumbered draft wants to know.
   */
  renumbered: Array<{ base: Clause; revised: Clause }>;
  /** Count of clauses identical (modulo whitespace) in both documents. */
  unchanged_count: number;
  base_clause_count: number;
  revised_clause_count: number;
  /**
   * True when the documents exceeded the alignment bound and the diff fell back
   * to a set-based comparison — `changed` is empty (rewrites surface as an
   * add + a remove) and order is not considered. Honest signal, never silent.
   */
  truncated: boolean;
};

/**
 * Cell ceiling for the LCS table. 4,000,000 cells (~16 MB of Int32) caps the
 * cost of the alignment; two ~2,000-paragraph documents still align exactly,
 * and anything larger degrades to the set-based path rather than allocating
 * unboundedly. A legal contract paragraph count is in the hundreds; this is
 * orders of magnitude past any real document pair.
 */
export const MAX_CLAUSE_DIFF_CELLS = 4_000_000;

/**
 * Token ceiling per side for the inline word-level redline. A clause is short
 * (the renderer truncates display at ~600 chars ≈ a hundred-odd tokens), so
 * 600 is generous; past it the word align is skipped (the renderer shows the
 * two full texts). Bounds the O(tokens²) inner diff — never unbounded.
 */
export const MAX_WORD_DIFF_TOKENS = 600;

/** Collapse insignificant whitespace so re-wrapping is not read as an edit. */
function normalizeClause(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}

/**
 * A leading clause number: `7.`, `7.1`, `7.1.2.`, `(a)`, `(iv)`, `Section 7.`,
 * `Article 3`. A bare number needs its dot — "2023 was a difficult year" opens
 * with a year, not a clause number — unless a division noun introduces it.
 */
const CLAUSE_NUMBER =
  /^(?:(?:section|article|clause|paragraph|§)\s*\d+(?:\.\d+)*\.?|\d+(?:\.\d+)+\.?|\d+\.|\((?:[a-z]{1,2}|[ivxlc]{1,6}|\d{1,3})\))(?=\s|$)\s*/i;

/** Split a normalized clause into its leading number and the words after it. */
function splitNumber(normalized: string): { number: string; rest: string } {
  const m = CLAUSE_NUMBER.exec(normalized);
  if (!m) return { number: "", rest: normalized };
  const rest = normalized.slice(m[0].length);
  // A clause that is ONLY a number has nothing else to be matched by.
  return rest === "" ? { number: "", rest: normalized } : { number: m[0].trim(), rest };
}

/** Split into alternating whitespace / non-whitespace tokens (exact spacing kept). */
function tokenizeWords(text: string): string[] {
  return text.match(/\s+|\S+/g) ?? [];
}

/**
 * Inline word-level redline between two clause texts: a deterministic LCS over
 * word tokens, emitted as merged `equal` / `removed` / `added` segments that
 * reassemble to exactly the base text (equal+removed) and the revised text
 * (equal+added). Returns `null` when either side exceeds {@link
 * MAX_WORD_DIFF_TOKENS} so the caller can fall back to the full texts.
 */
export function diffWords(base: string, revised: string): WordDiffSegment[] | null {
  const a = tokenizeWords(base);
  const b = tokenizeWords(revised);
  if (a.length > MAX_WORD_DIFF_TOKENS || b.length > MAX_WORD_DIFF_TOKENS) return null;

  const n = a.length;
  const m = b.length;
  const w = m + 1;
  const dp = new Int32Array((n + 1) * w);
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i * w + j] =
        a[i] === b[j]
          ? dp[(i + 1) * w + (j + 1)]! + 1
          : Math.max(dp[(i + 1) * w + j]!, dp[i * w + (j + 1)]!);
    }
  }

  const segs: WordDiffSegment[] = [];
  const push = (text: string, status: WordDiffSegment["status"]): void => {
    const last = segs[segs.length - 1];
    if (last && last.status === status) last.text += text;
    else segs.push({ text, status });
  };
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      push(a[i]!, "equal");
      i++;
      j++;
    } else if (dp[(i + 1) * w + j]! >= dp[i * w + (j + 1)]!) {
      push(a[i]!, "removed");
      i++;
    } else {
      push(b[j]!, "added");
      j++;
    }
  }
  while (i < n) push(a[i++]!, "removed");
  while (j < m) push(b[j++]!, "added");
  return segs;
}

/**
 * Flatten a document tree into an ordered list of clause units — one per
 * non-empty paragraph, tagged with its nearest enclosing section heading.
 * Iterative (explicit stack) so a deeply-nested tree cannot overflow the
 * stack (spec-v8 §5), mirroring the extractor walkers.
 */
export function flattenClauses(tree: DocumentTree): Clause[] {
  const out: Clause[] = [];
  // Stack of sections to visit in document order, each carrying the heading
  // inherited from its nearest titled ancestor.
  const stack: Array<{ section: Section; inheritedHeading: string }> = [];
  for (let i = tree.sections.length - 1; i >= 0; i--) {
    stack.push({ section: tree.sections[i]!, inheritedHeading: "" });
  }
  while (stack.length > 0) {
    const { section, inheritedHeading } = stack.pop()!;
    const heading = section.heading || inheritedHeading;
    for (const p of section.paragraphs) {
      let text = "";
      for (const r of p.runs) text += r.text;
      const trimmed = text.trim();
      if (trimmed.length === 0) continue;
      const { number, rest } = splitNumber(normalizeClause(trimmed));
      out.push({ id: p.id, heading, text: trimmed, key: rest, number });
    }
    // Push children in reverse so the first child is processed next.
    for (let i = section.children.length - 1; i >= 0; i--) {
      stack.push({ section: section.children[i]!, inheritedHeading: heading });
    }
  }
  return out;
}

type Op =
  | { kind: "remove" | "add"; clause: Clause }
  /** In both documents: the revised clause, and the base clause it matched. */
  | { kind: "equal"; clause: Clause; base: Clause };

/**
 * Longest-common-subsequence edit script over the clause keys. Returns the
 * ops in document order: `equal` (in both), `remove` (base only), `add`
 * (revised only). Deterministic backtrack (prefer `remove` before `add` on a
 * tie) so the same pair always yields the same script.
 */
function lcsOps(base: Clause[], revised: Clause[]): Op[] {
  const n = base.length;
  const m = revised.length;
  // dp[i][j] = LCS length of base[i:] and revised[j:]. One flat Int32 array.
  const w = m + 1;
  const dp = new Int32Array((n + 1) * w);
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i * w + j] =
        base[i]!.key === revised[j]!.key
          ? dp[(i + 1) * w + (j + 1)]! + 1
          : Math.max(dp[(i + 1) * w + j]!, dp[i * w + (j + 1)]!);
    }
  }
  const ops: Op[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (base[i]!.key === revised[j]!.key) {
      ops.push({ kind: "equal", clause: revised[j]!, base: base[i]! });
      i++;
      j++;
    } else if (dp[(i + 1) * w + j]! >= dp[i * w + (j + 1)]!) {
      ops.push({ kind: "remove", clause: base[i]! });
      i++;
    } else {
      ops.push({ kind: "add", clause: revised[j]! });
      j++;
    }
  }
  while (i < n) ops.push({ kind: "remove", clause: base[i++]! });
  while (j < m) ops.push({ kind: "add", clause: revised[j++]! });
  return ops;
}

/**
 * Above this many candidate pairs in one replaced block, pairing falls back to
 * position. A block is a handful of clauses; this bounds a pathological one.
 */
const MAX_PAIRING_CELLS = 40_000;

/** Below this share of words in common, two clauses are not the same clause rewritten. */
const MIN_PAIR_SIMILARITY = 0.3;

const wordSet = (c: Clause): Set<string> => new Set(c.key.toLowerCase().match(/[a-z0-9]+/g) ?? []);

/** Dice coefficient over the two clauses' word sets: 0 (nothing shared) to 1. */
function similarity(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 || b.size === 0) return 0;
  let shared = 0;
  for (const w of a) if (b.has(w)) shared++;
  return (2 * shared) / (a.size + b.size);
}

/**
 * Pair the removed and added clauses of one replaced block BY WHAT THEY SAY.
 *
 * Pairing by position — first removed with first added — is right when a block
 * is one clause rewritten. It is wrong the moment a clause is inserted beside
 * an edit: "7. Governing Law" was paired with "7. Return or Destruction", two
 * clauses that share a position and nothing else. Each removed clause now takes
 * the added clause most like it; a clause with no real counterpart stays a
 * plain remove or add.
 */
function pairBlock(
  rem: Clause[],
  add: Clause[],
): { pairs: Array<[Clause, Clause]>; removed: Clause[]; added: Clause[] } {
  if (rem.length === 0 || add.length === 0) return { pairs: [], removed: rem, added: add };
  if (rem.length * add.length > MAX_PAIRING_CELLS) {
    const n = Math.min(rem.length, add.length);
    return {
      pairs: rem.slice(0, n).map((r, i) => [r, add[i]!] as [Clause, Clause]),
      removed: rem.slice(n),
      added: add.slice(n),
    };
  }
  const remWords = rem.map(wordSet);
  const addWords = add.map(wordSet);
  const scored: Array<{ r: number; a: number; score: number }> = [];
  for (let r = 0; r < rem.length; r++) {
    for (let a = 0; a < add.length; a++) {
      const score = similarity(remWords[r]!, addWords[a]!);
      if (score >= MIN_PAIR_SIMILARITY) scored.push({ r, a, score });
    }
  }
  // Best match first; ties go to the earlier clauses, so the result is stable.
  scored.sort((x, y) => y.score - x.score || x.r - y.r || x.a - y.a);
  const takenR = new Set<number>();
  const takenA = new Set<number>();
  const chosen: Array<{ r: number; a: number }> = [];
  for (const { r, a } of scored) {
    if (takenR.has(r) || takenA.has(a)) continue;
    takenR.add(r);
    takenA.add(a);
    chosen.push({ r, a });
  }
  chosen.sort((x, y) => x.r - y.r);
  return {
    pairs: chosen.map(({ r, a }) => [rem[r]!, add[a]!] as [Clause, Clause]),
    removed: rem.filter((_c, r) => !takenR.has(r)),
    added: add.filter((_c, a) => !takenA.has(a)),
  };
}

/**
 * Collapse the edit script into added / removed / changed / renumbered. A
 * maximal run of removes immediately followed by adds is a *replaced block*,
 * paired by {@link pairBlock}. A clause in both documents whose number moved
 * is `renumbered`.
 */
function classify(
  ops: Op[],
): Pick<ClauseDiff, "added" | "removed" | "changed" | "renumbered" | "unchanged_count"> {
  const added: Clause[] = [];
  const removed: Clause[] = [];
  const changed: ClausePair[] = [];
  const renumbered: ClauseDiff["renumbered"] = [];
  let unchanged = 0;
  let k = 0;
  while (k < ops.length) {
    const op = ops[k]!;
    if (op.kind === "equal") {
      if (op.base.number !== op.clause.number)
        renumbered.push({ base: op.base, revised: op.clause });
      else unchanged++;
      k++;
      continue;
    }
    // Gather a maximal remove* add* group.
    const rem: Clause[] = [];
    const add: Clause[] = [];
    while (k < ops.length && ops[k]!.kind === "remove") rem.push(ops[k++]!.clause);
    while (k < ops.length && ops[k]!.kind === "add") add.push(ops[k++]!.clause);
    const block = pairBlock(rem, add);
    for (const [base, revised] of block.pairs) {
      changed.push({ base, revised, word_diff: diffWords(base.text, revised.text) });
    }
    removed.push(...block.removed);
    added.push(...block.added);
  }
  return { added, removed, changed, renumbered, unchanged_count: unchanged };
}

/**
 * Bounded set-based fallback for oversized pairs: multiset membership only. A
 * clause key present `b` times in base and `r` times in revised matches
 * `min(b, r)` copies (counted unchanged); the `r − min` surplus revised copies
 * are `added` and the `b − min` surplus base copies are `removed`. No
 * alignment, so no `changed` pairing — honest about the loss via `truncated`.
 * (A naive `count > 0` membership test would lose the surplus of a repeated
 * boilerplate clause whose multiplicity changed.)
 */
function setDiff(base: Clause[], revised: Clause[]): ClauseDiff {
  const baseCounts = new Map<string, number>();
  for (const c of base) baseCounts.set(c.key, (baseCounts.get(c.key) ?? 0) + 1);
  const revCounts = new Map<string, number>();
  for (const c of revised) revCounts.set(c.key, (revCounts.get(c.key) ?? 0) + 1);

  // Matched copies per key = min(base, revised). Two separate budgets are
  // drawn down — one while scanning revised (unchanged vs added), one while
  // scanning base (matched vs removed) — so multiplicity is conserved.
  const matched = new Map<string, number>();
  for (const [key, b] of baseCounts) {
    const r = revCounts.get(key) ?? 0;
    if (r > 0) matched.set(key, Math.min(b, r));
  }

  const revBudget = new Map(matched);
  const added: Clause[] = [];
  let unchanged = 0;
  for (const c of revised) {
    const left = revBudget.get(c.key) ?? 0;
    if (left > 0) {
      revBudget.set(c.key, left - 1);
      unchanged++;
    } else {
      added.push(c);
    }
  }
  const baseBudget = new Map(matched);
  const removed: Clause[] = [];
  for (const c of base) {
    const left = baseBudget.get(c.key) ?? 0;
    if (left > 0) baseBudget.set(c.key, left - 1);
    else removed.push(c);
  }
  return {
    added,
    removed,
    changed: [],
    // No alignment, so a clause cannot be paired with its renumbered self.
    renumbered: [],
    unchanged_count: unchanged,
    base_clause_count: base.length,
    revised_clause_count: revised.length,
    truncated: true,
  };
}

/**
 * Compute the clause-level diff between two document trees. Pure and
 * deterministic; outside the comparison `result_hash`.
 */
export function buildClauseDiff(base: DocumentTree, revised: DocumentTree): ClauseDiff {
  const baseClauses = flattenClauses(base);
  const revisedClauses = flattenClauses(revised);

  if ((baseClauses.length + 1) * (revisedClauses.length + 1) > MAX_CLAUSE_DIFF_CELLS) {
    return setDiff(baseClauses, revisedClauses);
  }

  const ops = lcsOps(baseClauses, revisedClauses);
  const { added, removed, changed, renumbered, unchanged_count } = classify(ops);
  return {
    added,
    removed,
    changed,
    renumbered,
    unchanged_count,
    base_clause_count: baseClauses.length,
    revised_clause_count: revisedClauses.length,
    truncated: false,
  };
}
