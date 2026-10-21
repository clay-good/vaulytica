/**
 * Readability standards a user can assert (add-readability-measure, task 3).
 *
 * Each row is read at its official source, and carries where and when, so
 * the provenance guard (`readability.test.ts`) can refuse a row with none.
 * Rows enter only from an official source. The table lives beside its rules
 * until the scheduled DKB rebuild takes it in, as the mandated texts do.
 */
export type ReadabilityStandard = {
  /** The id a user asserts: `--readability fl`. */
  id: string;
  name: string;
  citation: string;
  source_url: string;
  retrieved_at: string;
  /** The history note the source prints. */
  version: string;
  /** What the statute covers, in its words. */
  scope: string;
  /** The minimum Flesch reading ease score. */
  min_score: number;
  /** A table of contents or index is required above this many words (or pages). */
  contents_over: { words: number; pages: number };
};

export const READABILITY_STANDARDS: readonly ReadabilityStandard[] = [
  {
    id: "fl",
    name: "Florida readable-language rule for insurance policies",
    citation: "Fla. Stat. § 627.4145",
    source_url:
      "https://www.leg.state.fl.us/statutes/index.cfm?App_mode=Display_Statute&URL=0600-0699/0627/Sections/0627.4145.html",
    retrieved_at: "2026-10-20",
    version:
      "ss. 368, 809(2nd), ch. 82-243; ss. 51, 79, ch. 82-386; s. 96, ch. 83-216; s. 13, ch. 83-288; s. 2, ch. 84-352; s. 114, ch. 92-318; s. 1118, ch. 2003-261",
    scope: "a policy form or endorsement filed on or after October 1, 1983",
    min_score: 45,
    contents_over: { words: 3000, pages: 3 },
  },
];

export function readabilityStandard(id: string): ReadabilityStandard | undefined {
  return READABILITY_STANDARDS.find((s) => s.id === id.toLowerCase());
}
