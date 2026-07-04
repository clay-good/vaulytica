# add-authority-citation-lint

## Why

Citation hygiene is the highest-anxiety mechanical task in brief-writing, and the industry's answer is AI — exactly what filing-certification orders now make radioactive. A deterministic linter can check what is mechanically decidable: citation well-formedness, dangling short forms, and table-of-authorities reconciliation. The shapes all exist in the engine: cross-reference resolution (STRUCT-007 via `src/extract/crossrefs.ts`), two-way reconciliation (STRUCT-018 exhibits), and a DKB-pinned grammar. The legal footing is verified: The Indigo Book 2.0 (2021) is a CC0 public-domain citation manual implementing the same system (citation *systems* are unprotectable; the risk that forced the 2016 rename was trademark — so the tool cites The Indigo Book and never uses the "Bluebook" name); FRAP 28(a)(3) requires a table of authorities "with references to the pages of the brief where they are cited"; eyecite (Free Law Project) proves deterministic citation parsing at 55M-citation scale. Critically, this pack must also state loudly what it does NOT do: it never checks that a cited case exists or is good law — that requires a database the no-server posture excludes — which is precisely the honest complement to the certification receipt.

## What Changes

- **Citation extractor** (`src/extract/citations.ts`): deterministic parsing of case/statute/rule citations (volume-reporter-page shapes, U.S.C./C.F.R./state-code shapes, id./supra/short forms) against a DKB-pinned grammar derived from The Indigo Book 2.0 (reporter abbreviation table, format patterns), each grammar node carrying source + `retrieved_at`.
- **CITE-### rules** (gated to the filing family): CITE-001 malformed citation (matches a citation shape but violates the grammar — e.g., unknown reporter abbreviation, missing page); CITE-002 orphaned `id.` (no citation precedes it in scope); CITE-003 dangling `supra`/short-form (refers to an authority never cited in full); CITE-004 TOA reconciliation — authorities cited in the body but absent from the table, and table entries never cited in the body (both directions, STRUCT-018 shape), citing FRAP 28(a)(3)'s requirement; CITE-005 inconsistent short forms for the same authority.
- **Scope honesty, rendered on every report where the pack ran**: formats and internal consistency were mechanically checked; the existence, accuracy, and current validity of every cited authority were NOT checked and remain the filer's duty (mirroring the certification receipt's self-limiting language). TOA *page-number* accuracy is out of scope in v1 (the flattened tree carries no page boundaries); the reconciliation is by authority, not page.

## Impact

- Affected specs: `filing-compliance`
- Affected code: new `src/extract/citations.ts` + types, DKB citation-grammar nodes + build, `src/engine/rules/filing/` CITE rules, tests (grammar fixtures, brief fixtures with seeded defects)
- Risk: none to existing hashes (gated pack; new extractor output enters `extracted` only for filing-family documents — verify with the framework's isolation property test).
