/**
 * Whose tracked change a finding came from (add-redline-two-sided-analysis
 * task 5). Render-side: nothing here enters a hash.
 *
 * An introduced finding is attributed to the insertions its quoted paragraph
 * contains, and a resolved one to the deletions its paragraph (in the
 * rejected reading) contains. A finding about something ABSENT — "no
 * limitation-of-liability clause" — quotes nothing a revision wrote, and is
 * attributed to no one: which deletion caused an absence is not something the
 * text says, and guessing would put a name to a conclusion.
 */
import type { Comparison } from "./compare.js";
import type { RevisionText } from "../ingest/docx-revisions.js";

/** A revision shorter than this ("a", "the", "60") matches too much to name anyone. */
const MIN_CHARS = 12;

const norm = (s: string): string => s.toLowerCase().replace(/\s+/g, " ").trim();

/** Finding id → the distinct authors of the revisions inside its quoted text, sorted. */
export function attributeRevisions(
  cmp: Comparison,
  revisions: readonly RevisionText[],
): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  const usable = revisions
    .map((r) => ({ ...r, text: norm(r.text) }))
    .filter((r) => r.author && r.text.length >= MIN_CHARS);
  const attribute = (
    findings: Comparison["delta"]["introduced"],
    kind: RevisionText["kind"],
  ): void => {
    for (const f of findings) {
      const quoted = norm(f.excerpt?.text ?? "");
      if (!quoted) continue;
      const authors = new Set(
        usable.filter((r) => r.kind === kind && quoted.includes(r.text)).map((r) => r.author!),
      );
      if (authors.size > 0) out[f.id] = [...authors].sort();
    }
  };
  attribute(cmp.delta.introduced, "insertion");
  attribute(cmp.delta.resolved, "deletion");
  return out;
}
