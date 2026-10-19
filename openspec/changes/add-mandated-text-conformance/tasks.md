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
