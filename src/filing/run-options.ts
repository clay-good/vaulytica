/**
 * The run-scoped filing configuration the FILE-### rules read from
 * `ctx.options.filing`. Populated by the pipeline only when the user selects a
 * court profile (`--court` / tab picker); absent otherwise, which is what keeps
 * the pack dormant — every FILE rule returns `null` when it is missing.
 */

import type { RuleContext } from "../engine/finding.js";
import type { SourceCitation } from "../dkb/types.js";
import type { CourtProfile } from "./court-profile.js";

/** Which limit applies: a principal brief or a reply brief. */
export type BriefKind = "principal" | "reply";

export type FilingRunOptions = {
  profile: CourtProfile;
  brief_kind: BriefKind;
  /** The ingest word count of the whole document (the tool's measure). */
  word_count: number;
  /** Real page count — present only for PDF input. */
  page_count?: number;
  /** The ingest source, so the page-limit rule knows if pages are measurable. */
  source: "pdf" | "docx" | "paste";
};

/** The key under which {@link FilingRunOptions} rides in `ctx.options`. */
export const FILING_OPTIONS_KEY = "filing";

/** Read the filing config from a rule context, or `undefined` when dormant. */
export function readFilingOptions(ctx: RuleContext): FilingRunOptions | undefined {
  const raw = ctx.options?.[FILING_OPTIONS_KEY];
  return raw ? (raw as FilingRunOptions) : undefined;
}

/**
 * Build a report citation from a court-profile authority entry. Profile rules
 * are public rule text, so the license is fixed; the `retrieved_at` is carried
 * through so the receipt records when the limit was captured.
 */
export function profileCitation(entry: {
  cite: string;
  url: string;
  retrieved_at: string;
}): SourceCitation {
  return {
    id: `court-rule:${entry.cite}`,
    source: entry.cite,
    source_url: entry.url,
    retrieved_at: entry.retrieved_at,
    license: "Public rule text (U.S. government / court work)",
    license_url: "https://www.usa.gov/government-works",
  };
}
