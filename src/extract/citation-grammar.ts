/**
 * Citation grammar — versioned, cited data behind the clean-room legal
 * citation extractor (citations.ts). Citation SYSTEMS (volume-reporter-page,
 * statute-title-code-section, "Id."/"supra" short forms) are unprotectable;
 * the grammar here is written from first principles against The Indigo
 * Book, a CC0 public-domain citation manual — not against any proprietary
 * citation guide.
 *
 * Reporters are data, not code: the list below is a reasonable set of
 * common federal and state reporter abbreviations used to decide whether a
 * "### Xxx ###" span is a well-formed case citation or a malformed one
 * (CITE-001).
 */

/** The single cited source behind this grammar. */
export const INDIGO_BOOK_SOURCE = {
  cite: "The Indigo Book 2.0 (2021)",
  url: "https://law.resource.org/pub/us/code/blue/IndigoBook.html",
  retrieved_at: "2026-07-15",
} as const;

/** Known-good reporter abbreviations, in their canonical (spaced, punctuated) form. */
export const REPORTERS: readonly string[] = [
  "U.S.",
  "S. Ct.",
  "L. Ed.",
  "L. Ed. 2d",
  "F.",
  "F.2d",
  "F.3d",
  "F.4th", // current federal appellate reporter (2021–); its absence flagged every modern circuit cite (audit)
  "F. Supp.",
  "F. Supp. 2d",
  "F. Supp. 3d",
  "F. App'x",
  "Cal.",
  "Cal. 2d",
  "Cal. 3d",
  "Cal. 4th",
  "Cal. 5th",
  "Cal. App.",
  "Cal. App. 2d",
  "Cal. App. 3d",
  "Cal. App. 4th",
  "Cal. App. 5th",
  "Cal. Rptr.",
  "Cal. Rptr. 2d",
  "Cal. Rptr. 3d",
  "N.Y.",
  "N.E.",
  "N.E.2d",
  "N.E.3d",
  "N.W.",
  "N.W.2d",
  "P.",
  "P.2d",
  "P.3d",
  "S.E.",
  "S.E.2d",
  "S.W.",
  "S.W.2d",
  "S.W.3d",
  "So.",
  "So. 2d",
  "So. 3d",
  "A.",
  "A.2d",
  "A.3d",
] as const;

/** Normalize whitespace for reporter comparison (collapse runs, trim). */
function normalizeReporter(raw: string): string {
  return raw.trim().replace(/\s+/g, " ");
}

const KNOWN_REPORTERS = new Set(REPORTERS.map(normalizeReporter));

/** True when `raw`, after whitespace normalization, is a known reporter abbreviation. */
export function isKnownReporter(raw: string): boolean {
  return KNOWN_REPORTERS.has(normalizeReporter(raw));
}
