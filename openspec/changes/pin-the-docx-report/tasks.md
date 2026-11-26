# pin-the-docx-report — tasks

- [x] 1. Test the stated reason for the DOCX's absence instead of accepting it. *(Half true: the
      `nanoid` ids are real, but `report-reproducibility` had already normalized them. It compares
      two renders of the same code, so it pins determinism and NO content.)*
- [x] 2. Wire the resolver across `tools/` and `src/report/abstract.ts`. *(🥇 15 sites. The CLI's
      DOCX had been printing `—` the whole time — the `src/`-only guard went green and I reported
      the fix as done.)*
- [x] 3. Extend the reach guard to `src/` + `tools/`, and make it see a call with no options
      object. *(🥇 Proved by failing TWICE: the first guard stayed GREEN with the CLI site
      unwired, because its regex required `, {`. The rewritten scan balances delimiters and then
      found a third real site, `src/report/abstract.ts`.)*
- [x] 4. Share the document-part extraction and the one exception in `_docx-part.ts`. *(Was a
      private constant in one test while the other declared the artifact un-digestible.)*
- [x] 5. Add `docx_document_xml` to the committed digests; build `extracted` the product's way.
      *(Regen added only the two new keys — inert for every other artifact and for `result_hash`.
      🚨 The first draft called `buildDocxReport` here with six of its nine arguments and pinned a
      report **8 KB shorter** than the one the CLI writes, missing the secondary families and the
      related-documents block — a document no user receives. Now rendered through the CLI's own
      `renderDocxReport`, which cannot drift from it. Probed for embedded `(N.N ms)` timings
      first: zero, so `cli-docx-report`'s timing normalization is vestigial and the digest is
      machine-independent on that axis.)*
- [x] 6. Prove the pin. *(Removing the lookup moves both digests; renaming the `"Normalized id"`
      column moves both. Only that key moves in each case.)*
- [x] 6b. Fix what the gate caught. *(🥇 `cli-docx-report`'s "byte-identical to the builder the
      browser calls" went red — a PARITY test that hand-built its reference with a bare
      `extractAll`. With both sides bare it had compared two reports that each showed `—` and
      agreed. Third instance this session of a harness constructing `extracted` differently from
      the product.)*
- [ ] 7. Full gate, then push and confirm the deploy.
