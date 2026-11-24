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
  /**
   * The minimum Flesch reading ease score, where the statute sets one.
   *
   * Not every asserted standard does. N.Y. Gen. Oblig. Law § 5-702 sets no
   * score and no formula: it requires a consumer agreement to be written
   * "in a clear and coherent manner using words with common and every day
   * meanings" and to be "appropriately divided and captioned by its various
   * sections". The first half is not measurable and the product does not
   * pretend to measure it; the second is. A row with no `min_score` draws no
   * `READ-001`.
   */
  min_score?: number;
  /**
   * The score must be MORE than `min_score`, not at least it (Minnesota:
   * "a certified Flesch scale analysis readability score of more than 40").
   */
  min_exclusive?: boolean;
  /**
   * A table of contents or index is required above this many words (or
   * pages), or in every form ("always": Minnesota's index of major
   * provisions). Omitted where the statute requires none, which draws no
   * `READ-002`.
   */
  contents_over?: { words: number; pages: number } | "always";
  /**
   * The statute requires the document's sections to be captioned, as
   * § 5-702(a)(2) does ("appropriately divided and captioned by its various
   * sections"). Draws `READ-003`.
   */
  captions_required?: boolean;
  /**
   * An amount above which the statute does not apply, in dollars
   * (§ 5-702(a): "agreements involving amounts in excess of two hundred fifty
   * thousand dollars"). Recorded so the finding can say so; the product does
   * not read the agreement's value to decide, because the assertion is the
   * user's.
   */
  max_amount?: number;
  /**
   * Whether an index satisfies the contents requirement. Florida and Maine
   * say "a table of contents or an index"; Michigan says "a table of
   * contents" alone.
   */
  index_ok: boolean;
  /**
   * A requirement of the statute this product does NOT measure, named so the
   * finding and the docs can say what the assertion does not cover rather
   * than leaving a reader to assume it was checked.
   */
  not_measured?: string;
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
  {
    id: "oh",
    name: "Ohio readability requirement for life and health policy forms",
    citation: "Ohio Rev. Code § 3902.04",
    source_url: "https://codes.ohio.gov/ohio-revised-code/section-3902.04",
    retrieved_at: "2026-11-16",
    version: "Effective January 9, 1980; latest legislation Senate Bill 92, 113th General Assembly",
    scope:
      "a life, annuity, credit life, credit disability, or sickness and accident policy form, or a health insuring corporation's contract, delivered or issued for delivery in Ohio (Ohio Rev. Code §§ 3902.02–3902.03)",
    min_score: 40,
    contents_over: { words: 3000, pages: 3 },
    index_ok: true,
  },
  {
    id: "or",
    name: "Oregon reading ease standards for life and health policies",
    citation: "Or. Rev. Stat. § 743.106",
    source_url: "https://www.oregonlegislature.gov/bills_laws/ors/ors743.html",
    retrieved_at: "2026-11-16",
    version: "Formerly 743.365; 2015 c.515 § 5",
    scope: "a life or health insurance policy form delivered or issued for delivery in Oregon",
    min_score: 40,
    contents_over: { words: 3000, pages: 3 },
    index_ok: true,
  },
  {
    id: "mt",
    name: "Montana minimum policy language simplification standards",
    citation: "Mont. Code Ann. § 33-15-325",
    source_url:
      "https://leg.mt.gov/bills/mca/title_0330/chapter_0150/part_0030/section_0250/0330-0150-0030-0250.html",
    retrieved_at: "2026-11-16",
    version: "En. Sec. 5, Ch. 302, L. 1981 (Montana Code Annotated 2025)",
    scope:
      "a life, disability, credit life, or credit disability policy, contract or certificate delivered or issued for delivery in Montana (Mont. Code Ann. §§ 33-15-322, 33-15-323)",
    min_score: 40,
    contents_over: { words: 3000, pages: 3 },
    index_ok: true,
  },
  {
    id: "wv",
    name: "West Virginia minimum policy language simplification standards",
    citation: "W. Va. Code § 33-29-5",
    source_url: "https://code.wvlegislature.gov/33-29-5/",
    retrieved_at: "2026-11-16",
    version:
      "Current text as published by the West Virginia Legislature; the page prints no history note",
    scope:
      "a life, accident and sickness, credit life, or credit accident and sickness policy, contract or certificate delivered or issued for delivery in West Virginia (W. Va. Code §§ 33-29-2, 33-29-3)",
    min_score: 40,
    contents_over: { words: 3000, pages: 3 },
    index_ok: true,
  },
  {
    id: "nd",
    name: "North Dakota life and accident and health policy language simplification standards",
    citation: "N.D. Cent. Code §§ 26.1-33-30, 26.1-36-14",
    source_url: "https://ndlegis.gov/cencode/t26-1c36.pdf",
    retrieved_at: "2026-11-16",
    version:
      "Chapters 26.1-33 and 26.1-36 as published at ndlegis.gov (t26-1c33.pdf, t26-1c36.pdf); no history note beside the sections",
    scope:
      "a life policy form (§ 26.1-33-30), or an individual or group accident and health policy or certificate (§§ 26.1-36-13, 26.1-36-14), delivered or issued for delivery in North Dakota",
    min_score: 40,
    contents_over: { words: 3000, pages: 3 },
    index_ok: true,
  },
  {
    id: "ne",
    name: "Nebraska readability requirement for life and health policies",
    citation: "Neb. Rev. Stat. § 44-3405",
    source_url: "https://nebraskalegislature.gov/laws/statutes.php?statute=44-3405",
    retrieved_at: "2026-11-16",
    version: "Laws 1979, LB 415, § 5",
    scope:
      "a life, sickness and accident, credit life, or credit accident and health policy delivered or issued for delivery in Nebraska",
    min_score: 40,
    contents_over: { words: 3000, pages: 3 },
    index_ok: true,
  },
  {
    id: "dc",
    name: "District of Columbia policy language simplification standards",
    citation: "D.C. Code § 31-4725",
    source_url: "https://code.dccouncil.gov/us/dc/council/code/sections/31-4725",
    retrieved_at: "2026-11-16",
    version: "D.C. Law 5-160, § 3(h); D.C. Law 6-192, § 25(h); D.C. Law 11-268, § 10(j)",
    scope:
      "a policy form used in the District of Columbia under the chapter on life insurance companies (D.C. Code §§ 31-4725, 31-4727)",
    min_score: 40,
    contents_over: { words: 3000, pages: 3 },
    index_ok: true,
  },
  {
    id: "ok",
    name: "Oklahoma Life, Accident and Health Insurance Policy Language Simplification Act",
    citation: "Okla. Stat. tit. 36, § 3645",
    source_url: "https://www.oscn.net/applications/oscn/DeliverDocument.asp?CiteID=87154",
    retrieved_at: "2026-11-16",
    version: "Laws 1986, HB 1947, c. 141, § 5, eff. January 1, 1987",
    scope:
      "a life, accident or health policy form delivered or issued for delivery in Oklahoma (Okla. Stat. tit. 36, § 3644)",
    min_score: 40,
    contents_over: { words: 3000, pages: 3 },
    index_ok: true,
  },
  {
    // Last, and the odd one out: the only asserted standard that is not an
    // insurance readability statute, and the only one that sets NO SCORE.
    // Read at the New York State Senate's own site on 2026-11-23, which
    // prints "Viewing most recent revision (from 2020-04-10)". Its API
    // (legislation.nysenate.gov) answers 401 to an unauthenticated read, so
    // the public page is the official source used; no text here comes from a
    // secondary one.
    id: "ny-consumer",
    name: "New York plain-language requirement for consumer transactions",
    citation: "N.Y. Gen. Oblig. Law § 5-702",
    source_url: "https://www.nysenate.gov/legislation/laws/GOB/5-702",
    retrieved_at: "2026-11-23",
    version: "most recent revision from 2020-04-10",
    scope:
      "a written agreement entered into after November 1, 1978 for a residential lease, a lease of personal property for personal, family or household purposes, or a consumer agreement for money, property or services primarily for personal, family or household purposes",
    // § 5-702 sets no Flesch threshold and requires no table of contents, so
    // neither READ-001 nor READ-002 runs under it. What it does require is
    // captions, which is READ-003.
    captions_required: true,
    max_amount: 250_000,
    index_ok: false,
    not_measured:
      'the requirement in § 5-702(a)(1) that the agreement be "written in a clear and coherent manner using words with common and every day meanings", which is a judgment no formula makes',
  },
];

export function readabilityStandard(id: string): ReadabilityStandard | undefined {
  return READABILITY_STANDARDS.find((s) => s.id === id.toLowerCase());
}
