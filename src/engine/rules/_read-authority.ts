/**
 * A citation for an authority this product read ITSELF.
 *
 * Most authorities reach a finding through the DKB, which carries each node's
 * source, url, retrieved date and licence, and the report layer computes a
 * "verify currency (retrieved <date>)" label from that date
 * (`fix-legal-authority-currency`). The newer packs do not work that way: the
 * readability statutes, the mandated texts, the court profiles and the
 * deadline profiles were each read at an official source by hand and recorded
 * in a source module beside their rules.
 *
 * 🚨 Measured at 9.1005.0: those packs emitted `source_citations: []`, so the
 * currency label could never apply to any of them. The promise — a finding
 * resting on a reading older than the horizon says so — was true only for the
 * part of the product whose authorities live in the DKB. The statute's number
 * and read date were in the explanation PROSE, where no machinery can see
 * them, and a reader had no way to tell a reading from last month from one
 * from three years ago.
 *
 * So a row that already records where and when it was read becomes a real
 * citation. Nothing new is fetched and nothing is claimed that the row does
 * not already state.
 */
import type { SourceCitation } from "../../dkb/types.js";

/** What a hand-read authority row must carry to become a citation. */
export type ReadAuthority = {
  /** The authority, as a citation: "Fla. Stat. § 627.4145". */
  citation: string;
  /** The official source it was read at. */
  source_url: string;
  /** YYYY-MM-DD, or a full ISO timestamp. */
  retrieved_at: string;
};

/**
 * A stable citation id for a hand-read authority.
 *
 * It has to be stable across runs, because it is part of the finding and so of
 * the `result_hash`: derived from the citation text, never from a clock or an
 * array index.
 */
export function authorityId(prefix: string, citation: string): string {
  const slug = citation
    .toLowerCase()
    .replace(/[§]/g, "s")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return `${prefix}-${slug}`;
}

/**
 * The citation for an authority read at an official source.
 *
 * The licence is the plain fact about United States statutes and regulations:
 * the text of the law is not copyrightable (17 U.S.C. § 105 for federal works,
 * and the government-edicts doctrine for state codes, *Georgia v.
 * Public.Resource.Org*, 590 U.S. 255 (2020)). The `license_url` points at the
 * source the text was read from, which is the honest answer to "where did this
 * come from" — there is no separate licence page to cite for a statute.
 */
export function readAuthorityCitation(prefix: string, row: ReadAuthority): SourceCitation {
  return {
    id: authorityId(prefix, row.citation),
    source: row.citation,
    source_url: row.source_url,
    // The currency machinery compares ISO timestamps. A date-only reading is
    // midnight UTC of that day, which is the earliest moment it could mean and
    // so never overstates how recent the reading is.
    retrieved_at: row.retrieved_at.includes("T")
      ? row.retrieved_at
      : `${row.retrieved_at}T00:00:00Z`,
    license: "Public domain (government edict)",
    license_url: row.source_url,
  };
}
