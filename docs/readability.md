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
| `fl` | Fla. Stat. § 627.4145, policy forms filed on or after October 1, 1983 | 45 | over 3,000 words or three pages | leg.state.fl.us, 2026-10-20 |

Pages are not counted, so a form of more than three pages and fewer than 3,000 words is not caught. New York's Ins. Law § 3102 and Gen. Oblig. Law § 5-702 are not in the table: the New York Senate's site answers automated reads with a bot challenge, and no text enters from a secondary source.
