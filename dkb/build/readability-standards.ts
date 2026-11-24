/**
 * The `readability_standards` DKB table and its build-time provenance gate
 * (add-readability-measure task 3's remaining half).
 *
 * The same shape `mandated-texts.ts` uses, and for the same reason: the rows
 * live beside their rules, a test guards them where the source lives, but the
 * DKB is what SHIPS and what the weekly rebuild regenerates. A gate here
 * refuses to WRITE a knowledge base whose readability standards lack a
 * source, a read date or a version — so a row nobody can trace cannot reach a
 * user even if it reached `main`.
 *
 * Curated, not fetched, and deliberately so. Each of the 14 jurisdictions was
 * read at its legislature's own site by a person, and three more were examined
 * and excluded with written reasons (Texas delegates its threshold to the
 * commissioner; Colorado's official code is served through LexisNexis or
 * "personal use" downloads; California sets no Flesch minimum for insurance
 * forms). An automatic fetcher would make a threshold whatever a URL served
 * that week — and a threshold is the number a finding quotes at an attorney.
 *
 * ⚠️ Unlike a mandated text, a standard has no verbatim passage to digest, so
 * there is no `content_sha256` here and no drift check over wording. What a
 * scheduled re-read would compare is the THRESHOLD, which is a number a
 * person has to read in context — a statute that moves from "40" to "40 for
 * policies issued after a date" is not a diff a hash can report.
 */
import { READABILITY_STANDARDS } from "../../src/readability/standards.js";
import type { ReadabilityStandardEntry } from "../../src/dkb/types.js";

/** A row that cannot be trusted, and why. */
export type ReadabilityStandardDefect = { id: string; problem: string };

/**
 * Everything wrong with the committed rows, as a list.
 *
 * Every defect, not the first, so one build names them all.
 */
export function readabilityStandardDefects(
  rows: readonly ReadabilityStandardEntry[],
): readonly ReadabilityStandardDefect[] {
  const out: ReadabilityStandardDefect[] = [];
  const seen = new Set<string>();
  for (const row of rows) {
    const at = (problem: string): void => {
      out.push({ id: row.id || "(no id)", problem });
    };
    if (!row.id.trim()) at("has no id");
    if (seen.has(row.id)) at("is a duplicate id");
    seen.add(row.id);
    if (!row.citation.trim()) at("has no citation");
    if (!row.name.trim()) at("has no name");
    try {
      if (!new URL(row.source_url).hostname) at("has a source_url with no host");
    } catch {
      at(`has an unusable source_url: ${row.source_url}`);
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(row.retrieved_at)) {
      at(`has no read date in YYYY-MM-DD form (${row.retrieved_at || "empty"})`);
    }
    if (!row.version.trim()) at("records no version history from its source");
    if (!row.scope.trim()) at("states no scope, so nothing says what it covers");
    // A standard must require SOMETHING, or asserting it does nothing at all.
    if (row.min_score === undefined && row.contents_over === undefined && !row.captions_required) {
      at("sets no score, no contents requirement and no captions requirement");
    }
    if (row.min_score !== undefined && (row.min_score <= 0 || row.min_score >= 100)) {
      at(`has a Flesch minimum outside 0–100 (${row.min_score})`);
    }
    // A row that measures nothing must say what it DOES require, or a reader
    // is left with a citation and no obligation.
    if (row.min_score === undefined && !row.not_measured?.trim() && !row.captions_required) {
      at("sets no score and records nothing it does not measure");
    }
  }
  return out;
}

/** The committed rows as the DKB table. */
export function buildReadabilityStandards(): ReadabilityStandardEntry[] {
  return READABILITY_STANDARDS.map((s) => ({
    id: s.id,
    name: s.name,
    citation: s.citation,
    source_url: s.source_url,
    retrieved_at: s.retrieved_at,
    version: s.version,
    scope: s.scope,
    ...(s.min_score !== undefined ? { min_score: s.min_score } : {}),
    ...(s.min_exclusive ? { min_exclusive: s.min_exclusive } : {}),
    ...(s.contents_over !== undefined ? { contents_over: s.contents_over } : {}),
    ...(s.captions_required ? { captions_required: s.captions_required } : {}),
    ...(s.max_amount !== undefined ? { max_amount: s.max_amount } : {}),
    index_ok: s.index_ok,
    ...(s.not_measured ? { not_measured: s.not_measured } : {}),
    // Locale pinned: this order is the written file's byte order, and the
    // manifest records that file's SHA-256 (the hazard `determinism-guard`
    // does not scan for under `dkb/`).
  })).sort((a, b) => a.id.localeCompare(b.id, "en"));
}

/** The gate. Throws with every defect named. */
export function assertReadabilityStandardsUsable(rows: readonly ReadabilityStandardEntry[]): void {
  const defects = readabilityStandardDefects(rows);
  if (defects.length === 0) return;
  throw new Error(
    `dkb:build refuses to write ${defects.length} unusable readability standard row(s):\n` +
      defects.map((d) => `  ${d.id}: ${d.problem}`).join("\n"),
  );
}
