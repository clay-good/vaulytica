# Tasks

- [x] 1. Land the four live-reproduced documents as failing regression
  fixtures (FIN-001 "$1M", IPDATA-001 receivables assignment, PERS-009
  support-commitment paragraph, TEMP-003 month-to-month auto-renewal).
  *(`src/engine/rules/detection-fidelity.test.ts`; FIN-001 also re-checked
  live through the CLI — "$1M" produces zero FIN-001 findings.)*
- [x] 2. FIN-001: capture the magnitude suffix; multiply in `parseNumeral`
  (Decimal, no float math); keep the no-suffix path byte-identical.
  *(k×1e3, m/mm×1e6, b/bn×1e9, case-insensitive; rule v1.1.0.)*
- [x] 3. IPDATA-001: constrain the `hereby assigns` alternation to an IP
  object within the clause; enumerate the object terms in the rule doc.
  *(Objects: inventions, works of authorship, work product, copyrights,
  patents, trademarks, trade secrets, deliverables, intellectual property,
  moral rights, IP — within 120 chars of the assignment verb, same
  sentence; rule v1.1.0.)*
- [x] 4. PERS-009: scope duration search to the sentence containing (or a
  bounded window around) the non-solicit language. *(Sentence-scoped: the
  negative-obligation framing and the >12-month duration must share a
  sentence; rule v1.1.0.)*
- [x] 5. TEMP-003: detect auto-renewal language in the term clause; prefer
  same-paragraph term/notice pairing; document the fallback. *(Auto-renew /
  month-to-month in the term clause suppresses; same-paragraph pair keeps
  warning severity; the document-wide fallback fires at info with a
  verify-the-pairing explanation; rule v1.1.0.)*
- [x] 6. Add true-positive counter-fixtures for all four rules; wire the
  two-sided-fixture guard. *(Every fix in the regression file is a
  two-sided pair — the mis-detection case AND the true positive the rule
  was built for, in one describe per rule.)*
- [x] 7. Re-baseline affected goldens/accuracy corpus entries. *(All golden
  suites + scoreboard regenerated — the four rule-version bumps sit in
  every run's execution log, so every hash moved once.)*
- [x] 8. Full gate green. *(typecheck, lint, format:check, 3,700 tests /
  262 files, build.)*
