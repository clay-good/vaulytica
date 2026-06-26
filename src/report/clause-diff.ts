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
  /** Match key — `text` with insignificant whitespace collapsed. */
  key: string;
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
      out.push({ id: p.id, heading, text: trimmed, key: normalizeClause(trimmed) });
    }
    // Push children in reverse so the first child is processed next.
    for (let i = section.children.length - 1; i >= 0; i--) {
      stack.push({ section: section.children[i]!, inheritedHeading: heading });
    }
  }
  return out;
}

type Op = { kind: "equal" | "remove" | "add"; clause: Clause };

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
      ops.push({ kind: "equal", clause: revised[j]! });
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
 * Collapse the edit script into added / removed / changed. A maximal run of
 * removes immediately followed by adds is a *replaced block*: the first
 * min(R, A) form `changed` pairs (base clause → revised clause, in order),
 * the surplus on either side stays a plain remove/add. This is the standard
 * unified-diff "replace hunk" pairing.
 */
function classify(
  ops: Op[],
): Pick<ClauseDiff, "added" | "removed" | "changed" | "unchanged_count"> {
  const added: Clause[] = [];
  const removed: Clause[] = [];
  const changed: ClausePair[] = [];
  let unchanged = 0;
  let k = 0;
  while (k < ops.length) {
    const op = ops[k]!;
    if (op.kind === "equal") {
      unchanged++;
      k++;
      continue;
    }
    // Gather a maximal remove* add* group.
    const rem: Clause[] = [];
    const add: Clause[] = [];
    while (k < ops.length && ops[k]!.kind === "remove") rem.push(ops[k++]!.clause);
    while (k < ops.length && ops[k]!.kind === "add") add.push(ops[k++]!.clause);
    const paired = Math.min(rem.length, add.length);
    for (let p = 0; p < paired; p++) {
      const base = rem[p]!;
      const revised = add[p]!;
      changed.push({ base, revised, word_diff: diffWords(base.text, revised.text) });
    }
    for (let p = paired; p < rem.length; p++) removed.push(rem[p]!);
    for (let p = paired; p < add.length; p++) added.push(add[p]!);
  }
  return { added, removed, changed, unchanged_count: unchanged };
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
  const { added, removed, changed, unchanged_count } = classify(ops);
  return {
    added,
    removed,
    changed,
    unchanged_count,
    base_clause_count: baseClauses.length,
    revised_clause_count: revisedClauses.length,
    truncated: false,
  };
}
