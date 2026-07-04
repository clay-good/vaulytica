# Tasks

- [ ] 1. Draft the certificate template text (tool scope only; disclaimer block; Op. 512-aligned "attorney remains responsible" sentence); legal-review pass.
- [ ] 2. Implement `src/report/certificate.ts`: pure builder over an `EngineRun` (+ optional delivery block) → certificate model; DOCX/PDF/JSON renderers; namespaced `certificate_hash` over the canonical model.
- [ ] 3. Determinism + masking tests (no wall clock; certificate never embeds document text beyond the file name).
- [ ] 4. Tab wiring: certificate download alongside the report; CLI `--certificate` flag writing `<name>.certificate.{docx,json}`.
- [ ] 5. `verify` accepts the certificate JSON as an alternative provenance source (same fields as the report block).
- [ ] 6. Site section "For court and ethics compliance" with the standing-order/Op. 512 context, carefully scoped claims, and the reproduce-it-yourself command. Order counts must be attributed to their tracker ("300+ court directives per the Ropes & Gray tracker; ~113 binding attorney-filing orders per Legal AI Governance", as of the copy's date) — never an unattributed "300+ standing orders". Privilege case law is described as diverging (*Heppner* vs. *Warner v. Gilbarco*), not settled.
- [ ] 7. Full gate green.
