# Tasks

- [ ] 1. Read each seed authority at its official source and record text, URL, retrieved date, and version history: leginfo.legislature.ca.gov (Civ. Code § 1542, current; pre-2019 text from the chaptered SB 1431), eCFR (16 C.F.R. §§ 433.2, 429.1), statutes.capitol.texas.gov (§ 541.102), uscode.house.gov (18 U.S.C. § 1833(b)(3)). No text enters the table from a secondary source.
- [ ] 2. DKB: `mandated_texts` schema, fetch script, provenance gate in `dkb:build`, validation test; migrate the two Texas literals out of `regime-data.ts`.
- [x] 3. Matching: sliding-window token similarity with an exact whitespace-normalized fast path; threshold chosen by measuring the corpus (no false hit on the 363 specimens; every seeded paraphrase fixture caught); ReDoS-safe by construction (no regex over document text; token arrays).
- [ ] 4. `src/engine/rules/text/` factory: `TEXT-<row>` altered / superseded shapes with the word-diff redline (reuse `clause-diff` segments); `TEXT-FORM-<row>` over run properties; gating by family list or registered assertion.
- [ ] 5. DOCX ingest: expose `w:sz`, `w:caps`, `w:b` per run on the tree's formatting (bold already carried); PDF text-item size already available; pasted text reports "not checked".
- [x] 6. Conspicuousness rule over the existing clause locator for warranty disclaimers and liability caps; info severity; citation to U.C.C. § 1-201(b)(10) and § 2-316(2) with retrieved dates.
- [ ] 7. Fixtures: exact, paraphrased, superseded, and form-deficient versions of each seed passage; clean documents for each family confirm no false finding.
- [x] 8. Overlap decisions: for `COMM-206`, the § 429.1, § 1833(b) and § 1542 presence rules and the two Texas rules, decide retire-or-keep-as-absence, with a fixture proving one finding per defect, never two.
- [x] 9. Guards: `rule-completeness`, citation currency (`citation:check`), vacated-authority registry, shall/will and compound-spelling sweeps over the new rule sources; `rule-scaling`.
- [ ] 10. Land with a scheduled DKB rebuild; regenerate goldens once; CHANGELOG lists every corpus finding the change adds.
- [x] 11. Docs: `reference.md` rule table row; `/known-limits` sentence that form is checked only in DOCX and PDF; `adding-a-rule.md` section "adding a mandated text".
- [ ] 12. Full gate green.

## Progress — 9.982.0 (slice A: the FTC Holder Rule notice)

- Task 1, in part. 16 C.F.R. § 433.2 was read at eCFR through its official versioner API on 2026-10-20 (both notices, (a) and (b), and the form "in at least ten point, bold face, type"; version 40 FR 53506, Nov. 18, 1975). **Cal. Civ. Code § 1542 is blocked on access:** leginfo.legislature.ca.gov answers 403 to automated reads (both the fetch tool and a plain request), and the spec forbids a secondary source, so its current and pre-2019 rows wait for a person to read them there. §§ 429.1, 541.102 and 1833(b)(3) were not attempted in this slice.
- Task 2, built differently: the table is `src/engine/rules/text/mandated-texts.ts`, a typed source module beside its rules (as the Texas notices are in `regime-data.ts`), not a DKB table, so it lands without a DKB rebuild. The provenance gate is a test: every row names a source on an official host, an ISO date read and a version. Moving it into the DKB, and the Texas literals with it, waits for the scheduled rebuild.
- Task 3: token windows over each paragraph, no regular expression over document text beyond one linear tokenizer. Exact is case- and spacing-blind; near is a window holding at least 85% of the passage's words; a leading "NOTICE" is the passage's heading and not required in the paragraph. The window's edges are refined so the redline names only the changed words. Measured: no TEXT finding on any of the 363 specimens; every altered fixture caught.
- Task 4, in part: `TEXT-001` (present but altered, with the words dropped and added, naming the closest variant) and `TEXT-002` (not in bold face, read only where the file carries run formatting; point size not read). The superseded shape needs § 1542. The rules are ungated: each fires only on a document that carries the passage, which is the evidence it applies; no specimen does.
- Open: § 1542 (access), §§ 429.1, 541.102, 1833(b)(3); tasks 5–6 (point size, conspicuousness); 8 (overlap decisions, none needed yet: no existing rule checks the Holder notice); 10 (DKB rebuild).

## Progress — 9.983.0

16 C.F.R. § 429.1(a), read at eCFR on 2026-10-20. Its statement is required "in substantially the following form", and the rule tells the seller to alter its last sentence when the forms are not attached, so a reworded statement is not a defect. The table gained `wording: "exact" | "substantially"`; `TEXT-001` reads only exact rows, and `TEXT-002` holds the statement to its bold face ("a minimum size of 10 points"; size not read). The first sentence, which states the right, locates it. The residential-solar rules that check the statement's presence are unchanged: they ask whether it is there, this asks how it is set. § 429.1(b)'s notice form and 18 U.S.C. § 1833(b)(3) (content elements, not words, and already checked as presence) are not in the table.

## Progress — 9.984.0

Task 5, the DOCX half: a paragraph carries `min_size_pt`, the smallest point size its text is set in, resolved as Word does (the run's own `w:sz`, its character style, its paragraph style through `basedOn`, the default paragraph style, the document defaults; `docx-sizes.ts`), and absent whenever a link is missing, so a size is reported only when the file states it. `TEXT-002` now reports a notice below the authority's minimum ("set in 8-point type"), and says when the size could not be read. `w:caps` and the PDF text item's size are not read yet; no row needs capitals.

## Progress — 9.985.0

Task 6, narrowed: `TEXT-003` (info) notes a disclaimer of the warranty of merchantability that a Word file sets in regular, mixed-case body type, with no bold run, no capitals, and no heading naming it. § 1-201(b)(10) counts a heading in contrasting type as conspicuous, so a disclaimer under "Disclaimer of Warranties" is not flagged. Liability caps are NOT read, against the proposal: they fall under § 2-719, which sets no conspicuousness requirement, so a note citing § 2-316(2) for a cap would assert law that is not there. The finding never says the disclaimer fails. `COMM-206` is unchanged: it asks whether the clauses are there, from text; this asks how a Word file sets one. Task 8: no overlap to resolve, since no existing rule reads run formatting.

## Progress — 9.986.0

Task 9: the new sources run under the shall/will, compound-spelling, `rule-scaling` and ReDoS guards with the full suite (all green); `citation:check` passes (241 URLs well-formed); no authority cited is in the vacated-authority registry. Task 11: `reference.md` carries the rule row; `/known-limits` says how text is set is read only from a Word file; `adding-a-rule.md` gains "Adding a mandated text" (official source only, `wording`, variants, `form`, fixtures). Still open: § 1542 (leginfo blocks automated reads), § 541.102 (migrating the Texas literals belongs with the DKB move), the DKB table itself (task 10, with the scheduled rebuild), and task 12 once those land.
