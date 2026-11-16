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
  /**
   * The score must be MORE than `min_score`, not at least it (Minnesota:
   * "a certified Flesch scale analysis readability score of more than 40").
   */
  min_exclusive?: boolean;
  /**
   * A table of contents or index is required above this many words (or
   * pages), or in every form ("always": Minnesota's index of major provisions).
   */
  contents_over: { words: number; pages: number } | "always";
  /**
   * Whether an index satisfies the contents requirement. Florida and Maine
   * say "a table of contents or an index"; Michigan says "a table of
   * contents" alone.
   */
  index_ok: boolean;
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
    index_ok: true,
  },
  {
    id: "me",
    name: "Maine Insurance Policy Language Simplification Act",
    citation: "24-A M.R.S. § 2441",
    source_url: "https://legislature.maine.gov/statutes/24-A/title24-Asec2441.html",
    retrieved_at: "2026-11-16",
    version: "PL 1979, c. 267, § 2 (NEW)",
    scope:
      "a life, health, casualty or property policy form delivered or issued for delivery in Maine (24-A M.R.S. §§ 2439, 2440)",
    min_score: 50,
    contents_over: { words: 3000, pages: 3 },
    index_ok: true,
  },
  {
    id: "mi",
    name: "Michigan readability requirement for personal insurance forms",
    citation: "Mich. Comp. Laws § 500.2236(3)",
    source_url: "https://www.legislature.mi.gov/Laws/MCL?objectName=mcl-500-2236",
    retrieved_at: "2026-11-16",
    version:
      "1956, Act 218; Am. 1963, Act 53; Am. 1970, Act 180; Am. 1987, Act 52; Am. 1990, Act 137; Am. 1990, Act 305; Am. 1993, Act 200; Am. 2002, Act 664; Am. 2014, Act 140; Am. 2016, Act 276",
    scope:
      "a form for an insurance policy or annuity contract for personal, family, or household purposes",
    min_score: 45,
    contents_over: { words: 3000, pages: 3 },
    index_ok: false,
  },
  {
    id: "mn",
    name: "Minnesota Readability of Insurance Policies Act",
    citation: "Minn. Stat. §§ 72C.08–72C.10",
    source_url: "https://www.revisor.mn.gov/statutes/cite/72C.10",
    retrieved_at: "2026-11-16",
    version: "1977 c 345 ss 8–10; 1980 c 353 s 2; 1986 c 444; 2006 c 255 s 61",
    scope:
      "a private passenger vehicle, homeowner's, life, or accident and health policy, and the health plan contracts Minn. Stat. § 72C.11 names",
    min_score: 40,
    min_exclusive: true,
    contents_over: "always",
    index_ok: true,
  },
  {
    id: "nv",
    name: "Nevada readability requirement for life and health policies",
    citation: "Nev. Rev. Stat. § 687B.124",
    source_url: "https://www.leg.state.nv.us/NRS/NRS-687B.html",
    retrieved_at: "2026-11-16",
    version: "Added to NRS by 1981, 927",
    scope:
      "a life or health policy, certificate or contract delivered or issued for delivery in Nevada (Nev. Rev. Stat. § 687B.122)",
    min_score: 40,
    contents_over: { words: 3000, pages: 3 },
    index_ok: true,
  },
];

export function readabilityStandard(id: string): ReadabilityStandard | undefined {
  return READABILITY_STANDARDS.find((s) => s.id === id.toLowerCase());
}
