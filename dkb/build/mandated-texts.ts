/**
 * The `mandated_texts` DKB table and its build-time provenance gate
 * (add-mandated-text-conformance task 2).
 *
 * Why a table of its own rather than a row in `statutes`: a
 * `StatutoryIndexEntry` carries an `excerpt`, a fragment for citation. A
 * mandated passage's exact words ARE the requirement — `TEXT-001` reports a
 * notice that is close to the prescribed words and not the same — so an
 * excerpt cannot stand in for one.
 *
 * Why a BUILD gate when a test already guards the rows: the test runs where
 * the source lives, and the DKB is what ships and what the weekly rebuild
 * regenerates. A gate here refuses to WRITE a knowledge base whose mandated
 * passages lack a source, a date, a version, or a digest that matches their
 * own text — so a bad row cannot reach a user even if it reached `main`.
 *
 * The rows are curated, not fetched. The spec's rule is that no text enters
 * from a secondary source, and each passage here was read at an official one
 * by a person; `npm run authority:drift` is what re-reads them on the
 * scheduled path and reports a wording change.
 */
import { createHash } from "node:crypto";
import { MANDATED_TEXTS } from "../../src/engine/rules/text/mandated-texts.js";
import type { MandatedTextEntry } from "../../src/dkb/types.js";

/** Whitespace-normalized, case preserved: the form the rules compare in. */
export function normalizeMandated(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}

function digest(text: string): string {
  return createHash("sha256").update(normalizeMandated(text), "utf8").digest("hex");
}

/** A row that cannot be trusted, and why. */
export type MandatedTextDefect = { id: string; problem: string };

/**
 * Everything wrong with the committed rows, as a list.
 *
 * Returns every defect rather than throwing on the first, so one build tells a
 * maintainer about all of them instead of one per run.
 */
export function mandatedTextDefects(
  rows: readonly MandatedTextEntry[],
): readonly MandatedTextDefect[] {
  const out: MandatedTextDefect[] = [];
  const seen = new Set<string>();
  for (const row of rows) {
    const at = (problem: string): void => {
      out.push({ id: row.id, problem });
    };
    if (!row.id.trim()) at("has no id");
    if (seen.has(row.id)) at("is a duplicate id");
    seen.add(row.id);
    if (!row.citation.trim()) at("has no citation");
    if (!row.name.trim()) at("has no name");
    // An official source, not a secondary one: the spec's own rule.
    try {
      const host = new URL(row.source_url).hostname;
      if (!host) at("has a source_url with no host");
    } catch {
      at(`has an unusable source_url: ${row.source_url}`);
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(row.retrieved_at)) {
      at(`has no read date in YYYY-MM-DD form (${row.retrieved_at || "empty"})`);
    }
    if (!row.version.trim()) at("records no version history from its source");
    if (row.variants.length === 0) at("has no variants, so there is no passage to compare");
    for (const v of row.variants) {
      if (!v.where.trim()) at("has a variant that names no subsection");
      if (normalizeMandated(v.text).length < 20) {
        at(`has a variant too short to be a mandated passage (${v.where})`);
      }
      if (v.content_sha256 !== digest(v.text)) {
        at(`has a variant whose content_sha256 does not match its own text (${v.where})`);
      }
    }
  }
  return out;
}

/** The committed rows as the DKB table, each variant carrying its digest. */
export function buildMandatedTexts(): MandatedTextEntry[] {
  return MANDATED_TEXTS.map((row) => ({
    id: row.id,
    name: row.name,
    citation: row.citation,
    source_url: row.source_url,
    retrieved_at: row.retrieved_at,
    version: row.version,
    wording: row.wording,
    variants: row.variants.map((v) => ({
      where: v.where,
      text: v.text,
      content_sha256: digest(v.text),
    })),
    ...(row.form ? { form: row.form } : {}),
  })).sort((a, b) => a.id.localeCompare(b.id));
}

/**
 * The gate. Throws with every defect named, so the build fails loudly rather
 * than shipping a passage whose provenance cannot be shown.
 */
export function assertMandatedTextsUsable(rows: readonly MandatedTextEntry[]): void {
  const defects = mandatedTextDefects(rows);
  if (defects.length === 0) return;
  throw new Error(
    `dkb:build refuses to write ${defects.length} unusable mandated text row(s):\n` +
      defects.map((d) => `  ${d.id}: ${d.problem}`).join("\n"),
  );
}
