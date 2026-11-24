# Readability

Every JSON report carries a `readability` block: the Flesch reading ease score, counted the way the statutes count it. It is informative, outside the hashed run, and never called compliant. `--readability <id>` holds a document to one statute, and only then do findings appear.

## Where the assertion reaches

A statute is something you assert, not something a document declares — nothing in a policy form says where it was filed. So the assertion is the whole gate, and it applies to **every document in the run**: one file, or every member of a folder, a `.zip` or a deal round. Each member is scored on its own text and carries the statute in its own hashed run, so in a bundle the member below the minimum is the one named.

| Surface | How |
| --- | --- |
| CLI, one document or many | `vaulytica analyze … --readability fl` |
| `vaulytica.config.json` | `"readability": "fl"` (a flag wins over the file) |
| Browser tab, one document or a folder | the "Hold it to a readability statute" panel |

| GitHub Action | `readability: fl` (since 9.1002.0) |
| MCP server | `readability` on the analyze tool |

## The formula and the counting rules

As Fla. Stat. § 627.4145(5) prints them (read at [leg.state.fl.us](https://www.leg.state.fl.us/statutes/index.cfm?App_mode=Display_Statute&URL=0600-0699/0627/Sections/0627.4145.html) on 2026-10-20), following the NAIC model act:

```
206.835 − 1.015 × (words ÷ sentences) − 84.6 × (syllables ÷ words)
```

- A contraction, a hyphenated word, or numerals and letters set apart by spaces are one word.
- A unit of words ending with a period, semicolon or colon is one sentence. A period after "Inc." or a clause number ends nothing.
- Headings and captions are left out, and so are signature-block and table-of-contents lines.

Not applied, and the block says so: sampling a form over 10,000 words, and the exclusions a statute lets an insurer claim (defined words, medical terminology, language required by law). A score filed with a regulator can therefore differ.

Syllables come from a versioned rule set with a short exception list (`src/extract/syllables.ts`).

**Held-out accuracy: 93.2%.** Measured against `syllables-cmudict-reference.ts`, 5,000 words derived from the CMU Pronouncing Dictionary — the most frequent words across the 363 specimens that cmudict knows and gives a single syllable count (a word whose pronunciations disagree is excluded rather than guessed at). The counter's rules were fitted to a different, 348-word list, so 4,661 of these 5,000 are words it never saw: it is right about 4,346 of them.

⚠️ The figure previously quoted here was 345 of 348, or 99.1%. That measured the counter on its own training set — the rules had been corrected after reading that list's misses — and the held-out number is six points lower. The old figure is gone.

**What that does to a score, which is the number that matters.** The formula's only syllable term is `84.6 × (syllables ÷ words)`, so a per-word error of *e* moves the score by `84.6 × e` and nothing else. Across every corpus token with ground truth (324,144 of them) the mean *signed* error is −0.006 syllables per word: the counter very slightly under-counts, which very slightly overstates readability, for a bias of **0.5 of a Flesch point**. Even if every error pointed the same way the bound would be 1.8 points, against thresholds of 40 to 50. Errors in both directions largely cancel in an aggregate, which is why a counter wrong about one word in fourteen still scores a document to within a point. Both figures are held by `syllables-accuracy.test.ts`.

## The statutes

| `--readability` | Statute | Minimum score | Table of contents | Read at |
| --- | --- | --- | --- | --- |
| `fl` | Fla. Stat. § 627.4145, policy forms filed on or after October 1, 1983 | 45 | contents or index, over 3,000 words or three pages | leg.state.fl.us, 2026-10-20 |
| `me` | 24-A M.R.S. § 2441, life, health, casualty and property policy forms (§§ 2439–2440) | 50 | contents or index, over 3,000 words or three pages | legislature.maine.gov, 2026-11-16 |
| `mi` | Mich. Comp. Laws § 500.2236(3), policy and annuity forms for personal, family or household purposes | 45 | a table of contents (an index does not count), over 3,000 words or three pages; not riders or endorsements | legislature.mi.gov, 2026-11-16 |
| `nv` | Nev. Rev. Stat. § 687B.124, life and health policies, certificates and contracts (§ 687B.122) | 40 | contents or index, over 3,000 words or three pages | leg.state.nv.us, 2026-11-16 |
| `oh` | Ohio Rev. Code § 3902.04, life, annuity, credit and sickness and accident forms (§§ 3902.02–3902.03) | 40 | contents or index, over 3,000 words or three pages | codes.ohio.gov, 2026-11-16 |
| `or` | Or. Rev. Stat. § 743.106, life and health policy forms | 40 | contents or index, over 3,000 words or three pages | oregonlegislature.gov, 2026-11-16 |
| `mt` | Mont. Code Ann. § 33-15-325, life, disability and credit policies (§§ 33-15-322, -323) | 40 | contents or index, over 3,000 words or three pages | leg.mt.gov, 2026-11-16 |
| `wv` | W. Va. Code § 33-29-5, life, accident and sickness and credit policies (§§ 33-29-2, -3) | 40 | contents or index, over 3,000 words or three pages | code.wvlegislature.gov, 2026-11-16 |
| `nd` | N.D. Cent. Code §§ 26.1-33-30 (life), 26.1-36-14 (accident and health) | 40 | contents or index, over 3,000 words or three pages | ndlegis.gov, 2026-11-16 |
| `ne` | Neb. Rev. Stat. § 44-3405, life, sickness and accident and credit policies | 40 | contents or index, over 3,000 words or three pages | nebraskalegislature.gov, 2026-11-16 |
| `dc` | D.C. Code § 31-4725, policy forms of life insurers used in the District (§ 31-4727) | 40 | contents or index, over 3,000 words on three pages or over three pages | code.dccouncil.gov, 2026-11-16 |
| `ok` | Okla. Stat. tit. 36, § 3645, life, accident and health policy forms (§ 3644) | 40 | contents or index, over 3,000 words or three pages | oscn.net, 2026-11-16 |
| `mn` | Minn. Stat. §§ 72C.08–72C.10, auto, homeowner's, life and accident and health policies (§ 72C.11) | more than 40 | an index of the major provisions in every policy, whatever its length | revisor.mn.gov, 2026-11-16 |
| `ny-consumer` | N.Y. Gen. Oblig. Law § 5-702, residential leases, consumer personal-property leases and consumer agreements entered into after November 1, 1978; not agreements over $250,000 | **none — the statute sets no score** | none; it requires the agreement's sections to be **captioned** (`READ-003`) | nysenate.gov, 2026-11-23 |

Every state in the table prints the same counting rules as Florida — except New York, which is not a readability statute at all (see below); Minnesota's also leaves lists out of the sentence count, which the score does not do, and asks for a score above 40, so exactly 40 fails. Pages are not counted, so a form of more than three pages and fewer than 3,000 words is not caught. Not checked either: the type sizes (10-point in the District of Columbia, Maine, Montana, Nebraska, Nevada, North Dakota, Ohio, Oklahoma and West Virginia; 12-point for Oregon health benefit plans), Michigan's topical captions and identification of exclusions. Texas, Colorado and California are not in the table, each for a reason read at the source:

- **Texas** sets no number in statute. Tex. Ins. Code § 2301.053(c) (read at statutes.capitol.texas.gov on 2026-11-23) says a form is in plain language if it "achieves the minimum score established by the commissioner on the Flesch reading ease test **or an equivalent test selected by the commissioner**", or at the commissioner's option conforms to an NAIC model act instead. The threshold — and even which test applies — is delegated, so there is no statutory figure to record, and taking the commissioner's current number from a secondary source is not allowed here.
- **Colorado**'s official C.R.S. is served through LexisNexis or as downloads the Office of Legislative Legal Services marks "for personal use", so there is no official source this build can read and redistribute a threshold from.
- **California** sets no Flesch minimum for insurance forms at all.

Wisconsin likewise sets its minimum by agency rule rather than statute. New York's Ins. Law § 3102 is not in the table; § 5-702 now is, read at the New York Senate's own site on 2026-11-23. (Its API host, `legislation.nysenate.gov`, answers 401 to an unauthenticated read, so the public page is the source used. No text enters from a secondary source.)

### New York is the odd one out

Every other row is an insurance readability statute that sets a Flesch minimum. **N.Y. Gen. Oblig. Law § 5-702 sets no score and no formula.** It requires an agreement it covers to be two things:

1. "Written in a clear and coherent manner using words with common and every day meanings" — a judgment no formula makes. **This is not measured, and the finding says so.**
2. "Appropriately divided and captioned by its various sections" — which is measurable, and is `READ-003`.

So under `--readability ny-consumer` neither `READ-001` nor `READ-002` can fire: there is no threshold to be below, and the statute asks for no table of contents. The reading-ease score still appears in the reports, and the cover line says in as many words that this statute sets none, so the number is never mistaken for a threshold.

Two further limits of `READ-003`. It does not judge whether a caption is **appropriate** to what sits under it, only whether the agreement has captions at all. And it does not apply the statute's $250,000 ceiling, because the agreement's value is not read — asserting the standard is the reader's call, and the finding says that too.

A caption is a section heading, a numbered clause title (`3. Security Deposit.`, `1. PURPOSE AND SCOPE`), or a short heading-like line of its own. A numbered paragraph that runs straight into a sentence (`1. Tenant will pay rent of $2,450 each month.`) is divided but not captioned, which is the distinction § 5-702(a)(2) draws. The detector errs toward **accepting** a caption: asserting `ny-consumer` over all 363 specimens draws no finding, which is the guard (`readability-assertion.test.ts`), because a missed violation costs a reader nothing while calling a captioned agreement undivided is a false statement about their document.
