# Readability

Every JSON report carries a `readability` block: the Flesch reading ease score, counted the way the statutes count it. It is informative, outside the hashed run, and never called compliant. `--readability <id>` holds a document to one statute, and only then do findings appear.

## The formula and the counting rules

As Fla. Stat. § 627.4145(5) prints them (read at [leg.state.fl.us](https://www.leg.state.fl.us/statutes/index.cfm?App_mode=Display_Statute&URL=0600-0699/0627/Sections/0627.4145.html) on 2026-10-20), following the NAIC model act:

```
206.835 − 1.015 × (words ÷ sentences) − 84.6 × (syllables ÷ words)
```

- A contraction, a hyphenated word, or numerals and letters set apart by spaces are one word.
- A unit of words ending with a period, semicolon or colon is one sentence. A period after "Inc." or a clause number ends nothing.
- Headings and captions are left out, and so are signature-block and table-of-contents lines.

Not applied, and the block says so: sampling a form over 10,000 words, and the exclusions a statute lets an insurer claim (defined words, medical terminology, language required by law). A score filed with a regulator can therefore differ.

Syllables come from a versioned rule set with a short exception list (`src/extract/syllables.ts`). It reads 345 of 348 words of a committed reference list of the corpus's most frequent words right; the rules were corrected after reading that list, so the figure is not a held-out one.

## The statutes

| `--readability` | Statute | Minimum score | Table of contents | Read at |
| --- | --- | --- | --- | --- |
| `fl` | Fla. Stat. § 627.4145, policy forms filed on or after October 1, 1983 | 45 | contents or index, over 3,000 words or three pages | leg.state.fl.us, 2026-10-20 |
| `me` | 24-A M.R.S. § 2441, life, health, casualty and property policy forms (§§ 2439–2440) | 50 | contents or index, over 3,000 words or three pages | legislature.maine.gov, 2026-11-16 |
| `mi` | Mich. Comp. Laws § 500.2236(3), policy and annuity forms for personal, family or household purposes | 45 | a table of contents (an index does not count), over 3,000 words or three pages; not riders or endorsements | legislature.mi.gov, 2026-11-16 |
| `nv` | Nev. Rev. Stat. § 687B.124, life and health policies, certificates and contracts (§ 687B.122) | 40 | contents or index, over 3,000 words or three pages | leg.state.nv.us, 2026-11-16 |
| `oh` | Ohio Rev. Code § 3902.04, life, annuity, credit and sickness and accident forms (§§ 3902.02–3902.03) | 40 | contents or index, over 3,000 words or three pages | codes.ohio.gov, 2026-11-16 |
| `or` | Or. Rev. Stat. § 743.106, life and health policy forms | 40 | contents or index, over 3,000 words or three pages | oregonlegislature.gov, 2026-11-16 |
| `mn` | Minn. Stat. §§ 72C.08–72C.10, auto, homeowner's, life and accident and health policies (§ 72C.11) | more than 40 | an index of the major provisions in every policy, whatever its length | revisor.mn.gov, 2026-11-16 |

Maine, Michigan, Minnesota, Nevada, Ohio and Oregon print the same counting rules as Florida; Minnesota's also leaves lists out of the sentence count, which the score does not do, and asks for a score above 40, so exactly 40 fails. Pages are not counted, so a form of more than three pages and fewer than 3,000 words is not caught. Not checked either: the type sizes (10-point in Maine, Nevada and Ohio; 12-point for Oregon health benefit plans), Michigan's topical captions and identification of exclusions. Texas's statute site serves its text only to a browser script, so Texas waits. New York's Ins. Law § 3102 and Gen. Oblig. Law § 5-702 are not in the table: the New York Senate's site answers automated reads with a bot challenge, and no text enters from a secondary source.
