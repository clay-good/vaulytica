# Tasks

- [ ] 1. Read each seed authority at its official source and record text, URL, retrieved date, and version history: leginfo.legislature.ca.gov (Civ. Code § 1542, current; pre-2019 text from the chaptered SB 1431), eCFR (16 C.F.R. §§ 433.2, 429.1), statutes.capitol.texas.gov (§ 541.102), uscode.house.gov (18 U.S.C. § 1833(b)(3)). No text enters the table from a secondary source.
- [ ] 2. DKB: `mandated_texts` schema, fetch script, provenance gate in `dkb:build`, validation test; migrate the two Texas literals out of `regime-data.ts`.
- [ ] 3. Matching: sliding-window token similarity with an exact whitespace-normalized fast path; threshold chosen by measuring the corpus (no false hit on the 363 specimens; every seeded paraphrase fixture caught); ReDoS-safe by construction (no regex over document text; token arrays).
- [ ] 4. `src/engine/rules/text/` factory: `TEXT-<row>` altered / superseded shapes with the word-diff redline (reuse `clause-diff` segments); `TEXT-FORM-<row>` over run properties; gating by family list or registered assertion.
- [ ] 5. DOCX ingest: expose `w:sz`, `w:caps`, `w:b` per run on the tree's formatting (bold already carried); PDF text-item size already available; pasted text reports "not checked".
- [ ] 6. Conspicuousness rule over the existing clause locator for warranty disclaimers and liability caps; info severity; citation to U.C.C. § 1-201(b)(10) and § 2-316(2) with retrieved dates.
- [ ] 7. Fixtures: exact, paraphrased, superseded, and form-deficient versions of each seed passage; clean documents for each family confirm no false finding.
- [ ] 8. Overlap decisions: for `COMM-206`, the § 429.1, § 1833(b) and § 1542 presence rules and the two Texas rules, decide retire-or-keep-as-absence, with a fixture proving one finding per defect, never two.
- [ ] 9. Guards: `rule-completeness`, citation currency (`citation:check`), vacated-authority registry, shall/will and compound-spelling sweeps over the new rule sources; `rule-scaling`.
- [ ] 10. Land with a scheduled DKB rebuild; regenerate goldens once; CHANGELOG lists every corpus finding the change adds.
- [ ] 11. Docs: `reference.md` rule table row; `/known-limits` sentence that form is checked only in DOCX and PDF; `adding-a-rule.md` section "adding a mandated text".
- [ ] 12. Full gate green.

## Progress — 9.982.0 (slice A: the FTC Holder Rule notice)

- Task 1, in part. 16 C.F.R. § 433.2 was read at eCFR through its official versioner API on 2026-10-20 (both notices, (a) and (b), and the form "in at least ten point, bold face, type"; version 40 FR 53506, Nov. 18, 1975). **Cal. Civ. Code § 1542 is blocked on access:** leginfo.legislature.ca.gov answers 403 to automated reads (both the fetch tool and a plain request), and the spec forbids a secondary source, so its current and pre-2019 rows wait for a person to read them there. §§ 429.1, 541.102 and 1833(b)(3) were not attempted in this slice.
- Task 2, built differently: the table is `src/engine/rules/text/mandated-texts.ts`, a typed source module beside its rules (as the Texas notices are in `regime-data.ts`), not a DKB table, so it lands without a DKB rebuild. The provenance gate is a test: every row names a source on an official host, an ISO date read and a version. Moving it into the DKB, and the Texas literals with it, waits for the scheduled rebuild.
- Task 3: token windows over each paragraph, no regular expression over document text beyond one linear tokenizer. Exact is case- and spacing-blind; near is a window holding at least 85% of the passage's words; a leading "NOTICE" is the passage's heading and not required in the paragraph. The window's edges are refined so the redline names only the changed words. Measured: no TEXT finding on any of the 363 specimens; every altered fixture caught.
- Task 4, in part: `TEXT-001` (present but altered, with the words dropped and added, naming the closest variant) and `TEXT-002` (not in bold face, read only where the file carries run formatting; point size not read). The superseded shape needs § 1542. The rules are ungated: each fires only on a document that carries the passage, which is the evidence it applies; no specimen does.
- Open: § 1542 (access), §§ 429.1, 541.102, 1833(b)(3); tasks 5–6 (point size, conspicuousness); 8 (overlap decisions, none needed yet: no existing rule checks the Holder notice); 10 (DKB rebuild).
