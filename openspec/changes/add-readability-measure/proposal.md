# add-readability-measure

## Why

Readability is the one quality of a legal document that the law measures with a formula. The NAIC Life and Health Insurance Policy Language Simplification Model Act (#575, § 5) requires a minimum Flesch reading ease score of 40 and prescribes how to compute it: words ÷ sentences × 1.015, plus syllables ÷ words × 84.6, subtracted from 206.835; a hyphenated word or contraction is one word; a sentence ends at a period, semicolon, or colon, excluding headings and captions; forms over 10,000 words may be sampled. Most states adopted it with their own thresholds: 45 in New York (Ins. Law § 3102), Florida (§ 627.4145) and Michigan; 50 in Maine and Colorado; 40 in some thirty others (NAIC chart MC-25, Summer 2025, read 2026-10-19; each statute to be read at its official source during the build). New York's plain-language law for consumer contracts and residential leases (Gen. Oblig. Law § 5-702) has no formula but requires the agreement be "appropriately divided and captioned by its various sections", which is a structural fact the outline already carries.

The computation is deterministic, needs no clock and no model, and the engine already tokenizes words and sentences. What is missing is the syllable counter and the statute table. A tool that scores readability and then says *what the asserted statute requires* gives insurance-regulatory counsel and consumer-contract drafters a number they currently get from Word's dialog, which neither follows the statutory counting rules nor cites a threshold.

## What Changes

- **A readability block**, `readability`, computed render-side for every document and carried in JSON and in the DOCX/HTML appendix: Flesch reading ease under the NAIC counting rules, word, sentence and syllable counts, the longest sentence and its location, and a note on what was excluded (headings, captions, the table of contents, signature blocks). The syllable counter is a fixed, versioned dictionary-plus-rules function; its version enters the block so a counter improvement is visible, never silent.
- **An asserted statute**, `--readability <state>` (browser: a selector beside the state overlays), applying the state's threshold and scope from a `readability_standards` DKB table (state, citation, URL, retrieved date, threshold, lines of insurance it covers, type-size and table-of-contents requirements where the statute states them). With the assertion: a `READ-001` finding when the score is below the threshold, quoting the statute's number and the computed score, and `READ-002` when the statute requires a table of contents or index (policies over 3,000 words or three pages under the model act) and the outline has none. Without the assertion the block is informative and no finding fires; the hash is unchanged.
- **NY GOL § 5-702** as a second assertion, `--readability ny-consumer`: `READ-003` when a document in scope (residential lease, consumer agreement) has no captioned sections. The "clear and coherent manner using words with common and every day meanings" half is not measured and the finding says so.
- **Honesty:** the block states that the score follows the NAIC statutory counting method, that the statutes allow sampling and exclusions the tool does not apply (defined words, medical terminology, language required by law), and that a filing certification is the insurer's. The score is never called "compliant".

## Impact

- Affected specs: `readability` (new capability; the standards table is specified inside it)
- Affected code: new `src/report/readability.ts` and `src/extract/syllables.ts`; DKB table and fetch; `READ-*` rules assertion-gated and registered; JSON/DOCX/HTML renderers; CLI flag; `REGISTERED_ASSERTION_GATES`
- Risk: none to existing hashes (render-side block; findings only under assertion). The syllable counter's accuracy is measured against a committed word list before shipping.
