# add-proofreading-pack

## Why

The proofreading tools attorneys already pay for (Thomson Reuters Deal Proof, Litera Check, Definely) raise eight kinds of flag. Vaulytica's launch set covers five of them deterministically and well: defined-term discrepancies (STRUCT-005/006/009/014 and the definitions report), numbering (STRUCT-008/015), cross-references (STRUCT-007), open issues and placeholders (STRUCT-011/013), and signature-block parity (STRUCT-017). Three are absent:

| Deal Proof category | What it catches | Vaulytica today |
|---|---|---|
| Unpaired punctuation | an opening bracket, parenthesis, or quotation mark with no closing mark | nothing |
| Date errors | a weekday that does not match the date; a date missing its year or day | TEMP-001 catches impossible dates only |
| Non-conforming phrases | a standard phrase that appears in an altered form elsewhere in the same document | nothing within a document (CROSS-DEFTERM/PARTY work across documents) |

A LexisNexis survey found 90% of a sample of "proofread" documents still contained errors, and the common ones are typographical: punctuation, names, deleted paragraphs. These checks are cheap, deterministic, and carry no legal claim; they are the "spell-checker for legal documents" the README promises, applied to the mechanics it does not yet read.

## What Changes

- **`PROOF-001` Unpaired punctuation.** Per paragraph: `(`/`)`, `[`/`]`, `{`/`}`, straight and curly double quotes, and curly single quotes (straight single quotes are apostrophes and are not counted) must balance. Reports the paragraph and the unmatched mark. A list item that opens a parenthetical numbering `(a)` is handled by stripping leading enumerators first.
- **`PROOF-002` Weekday–date mismatch.** "Monday, March 3, 2026" where March 3, 2026 is a Tuesday. Pure calendar arithmetic, no clock. Also a date with a day but no year inside a sentence that elsewhere dates events fully ("on March 3" in a document whose other dates carry years), reported at info.
- **`PROOF-003` Repeated word.** "the the", "shall shall", excluding legitimate doubles ("had had", "that that") by a short allow-list and excluding a repeat across a sentence boundary.
- **`PROOF-004` Party-name drift within a document.** The same party registered with two spellings or two suffix forms ("Acme Corp." / "Acme Corporation" / "ACME Corp"), from the party extractor's existing canonicalization; the corporate-form presence/absence rule CROSS-PARTY-001 already uses (short form vs legal name is not drift) applies within the document.
- **`PROOF-005` Cross-reference title mismatch.** "Section 7 (Confidentiality)" where the heading of Section 7 is "Indemnification". Uses the outline and crossrefs the extractor already produces.
- **`PROOF-006` Enumeration out of sequence inside a clause.** "(a) … (b) … (d)" or "(i) (ii) (iv)"; STRUCT-015 covers section numbering, this covers in-paragraph and list enumerators. Roman and letter sequences, with the `(i)` letter-vs-roman ambiguity resolved by context (after `(h)`, `(i)` is a letter).
- **`PROOF-007` Non-conforming standard phrase.** For a small table of boilerplate phrases a document tends to repeat ("in its sole discretion", "including, without limitation", "without limiting the generality of the foregoing", "commercially reasonable efforts"), an occurrence that differs from the document's own majority form by one or two tokens ("in it's sole discretion", "including without limitations") is reported. The reference form is the document's own, never a style preference of the tool.
- All seven are always-on launch rules at info severity (PROOF-001 and PROOF-005 at warning), with `recommendation` text that quotes nothing the tool wrote, only the two forms the document already contains. They enter `result_hash` like any rule; the corpus impact is measured and the goldens re-baselined once.

## Impact

- Affected specs: `proofreading` (new capability)
- Affected code: `src/engine/rules/proofreading/`; a `PROOF` namespace in the verticals registry (always-on, so no gate); the launch-set count in docs (121 → 128)
- Risk: these fire on real documents. Each rule's corpus firing count is committed by equality before merge and each firing is read by a person; a rule with a false hit on a clean document does not ship.
