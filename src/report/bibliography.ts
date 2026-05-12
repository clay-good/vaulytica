/**
 * Bibliography builder for the report.
 *
 * Deduplicates SourceCitation entries across every Finding in document
 * order. The first time a source id appears in any finding's
 * `source_citations`, it is assigned an index (1-based); subsequent
 * mentions reuse the same index. The DKB is consulted only to
 * back-fill citations that the rule supplied by id but did not
 * materialize — in practice every rule should pass the full citation,
 * but the back-fill keeps the bibliography forgiving.
 *
 * Determinism: findings are expected to arrive in their final sorted
 * order (severity, rule_id, document_position) from
 * `sortFindings`, so the bibliography ordering depends only on the
 * Finding[] and the DKB. No randomness, no IO.
 */

import type { Finding } from "../engine/finding.js";
import type { DKB, SourceCitation } from "../dkb/types.js";

export type BibliographyEntry = {
  index: number;
  source: SourceCitation;
  /** Document-order position of the first finding to reference this source. */
  first_referenced_in: string;
};

export function buildBibliography(findings: Finding[], dkb: DKB): BibliographyEntry[] {
  const seen = new Map<string, BibliographyEntry>();
  const dkbSources = new Map(dkb.manifest.sources.map((s) => [s.id, s]));
  let next = 1;
  for (const finding of findings) {
    for (const cite of finding.source_citations) {
      if (seen.has(cite.id)) continue;
      const source = cite.source_url ? cite : (dkbSources.get(cite.id) ?? cite);
      seen.set(cite.id, {
        index: next,
        source,
        first_referenced_in: finding.id,
      });
      next++;
    }
  }
  return [...seen.values()];
}

/**
 * Look up a citation's bibliography index. Returns `undefined` if the
 * citation never appears in any finding's `source_citations` (which
 * should not happen if the bibliography was built from the same
 * Finding[]).
 */
export function citationIndex(
  bibliography: BibliographyEntry[],
  citationId: string,
): number | undefined {
  return bibliography.find((b) => b.source.id === citationId)?.index;
}
