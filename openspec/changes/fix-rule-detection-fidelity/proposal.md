# fix-rule-detection-fidelity

## Why

Four launch rules mis-detect on realistic contract language — all four
reproduced live through the shipped CLI:

- **FIN-001 (false critical).** The word/numeral-mismatch regex tolerates a
  magnitude suffix — `(?:k|m|mm|b|bn)?` — but never captures or applies it
  (`src/engine/rules/financial/FIN-001.ts:17`, `parseNumeral` at `:147`). "one
  million dollars ($1M)" is reported as a **critical** mismatch ("1000000 does
  not match numeral 1") on a perfectly consistent, commonly drafted amount.
  The product's most consequential severity fires on its own parsing gap.
- **IPDATA-001 (false negative).** Any `hereby assigns` anywhere in the
  document suppresses the missing-IP-ownership finding
  (`src/engine/rules/ip-and-data/IPDATA-001.ts:17`) — an assignment of
  receivables, leases, or security interests silently satisfies the IP-clause
  presence check.
- **PERS-009 (false positive).** After confirming non-solicit keywords exist
  somewhere in a paragraph, it attributes the first >12-month duration found
  **anywhere in that paragraph** to the non-solicit
  (`src/engine/rules/personnel/PERS-009.ts:100-134`). A 24-month support
  commitment in the same paragraph as a non-solicit sentence is flagged as a
  24-month non-solicit.
- **TEMP-003 (false positive).** "Initial term" and "notice period" are
  matched independently anywhere in the document with no same-clause or
  auto-renewal awareness (`src/engine/rules/temporal/TEMP-003.ts:14-25`). An
  ordinary month-to-month auto-renewing agreement with a 60-day non-renewal
  notice is flagged "notice period exceeds the contract term."

For an attorney-facing linter, a false critical erodes trust fastest, and a
false negative on a presence check is a silent gap the report never reveals.

## What Changes

- FIN-001 captures the magnitude suffix and multiplies (`k`×1e3, `m`/`mm`×1e6,
  `b`/`bn`×1e9) before comparing.
- IPDATA-001 requires the assignment's object to be IP (inventions, works,
  copyrights, patents, trademarks, trade secrets, work product, deliverables,
  intellectual property) within the matched clause.
- PERS-009 requires the duration to sit in the same sentence as (or within a
  bounded window of) the non-solicit language.
- TEMP-003 suppresses when the term clause carries auto-renewal language, and
  prefers a term and notice drawn from the same paragraph before falling back
  to document-wide pairing (downgrading confidence when it does).
- Each fix lands with the reproducing document as a regression fixture, plus
  counter-fixtures pinning that the rule still fires on the true positives it
  was built for.

## Impact

- Affected specs: `rule-accuracy` (new capability spec)
- Affected code: the four rule files, their tests, accuracy-corpus fixtures
- Risk: findings change for affected documents (that is the fix); goldens
  containing the four patterns re-baseline. No engine or schema changes.
