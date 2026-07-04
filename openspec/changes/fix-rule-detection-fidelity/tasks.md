# Tasks

- [ ] 1. Land the four live-reproduced documents as failing regression
  fixtures (FIN-001 "$1M", IPDATA-001 receivables assignment, PERS-009
  support-commitment paragraph, TEMP-003 month-to-month auto-renewal).
- [ ] 2. FIN-001: capture the magnitude suffix; multiply in `parseNumeral`
  (Decimal, no float math); keep the no-suffix path byte-identical.
- [ ] 3. IPDATA-001: constrain the `hereby assigns` alternation to an IP
  object within the clause; enumerate the object terms in the rule doc.
- [ ] 4. PERS-009: scope duration search to the sentence containing (or a
  bounded window around) the non-solicit language.
- [ ] 5. TEMP-003: detect auto-renewal language in the term clause; prefer
  same-paragraph term/notice pairing; document the fallback.
- [ ] 6. Add true-positive counter-fixtures for all four rules; wire the
  two-sided-fixture guard.
- [ ] 7. Re-baseline affected goldens/accuracy corpus entries.
- [ ] 8. Full gate green.
