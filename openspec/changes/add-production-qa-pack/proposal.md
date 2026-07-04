# add-production-qa-pack

## Why

Document productions fail in mechanical, checkable ways: Bates gaps and duplicates, privilege-log entries that don't reconcile with what was actually withheld, and metadata/tracked-changes leaking out the door. The machinery is mostly built: bundle ingest with zip-bomb guards (`src/ingest/multi.ts`), the pre-disclosure scan (HANDOFF-001..005, `src/delivery/handoff.ts:34` — tracked changes, comments, hidden text, metadata, sensitive data) and the injection-guarded CSV encoder (`src/report/exports.ts:164`). Two gaps block the vertical: bundles accept only `.pdf`/`.docx` (`multi.ts:81` — a privilege-log CSV is silently skipped), and the delivery scan runs per-document with no bundle-level roll-up. The legal footing is current: FRCP 26(b)(5)(A) requires withholding parties to describe what was withheld "in a manner that … will enable other parties to assess the claim," and the December 1, 2025 amendments to Rules 26(f)(3)(D) and 16(b)(3)(B)(iv) now make privilege-log timing and method an explicit discovery-plan and scheduling-order item; Sedona Conference model ESI protocols require unique, sequential, non-overlapping Bates numbers. Timing could not be better for a tool that checks a production set *before* it goes out.

## What Changes

- **Bates extraction and PROD-### sequence rules** over a bundle: extract Bates identifiers from member filenames (prefix + zero-padded number, the dominant production convention); PROD-001 sequence gaps, PROD-002 duplicates/overlaps, PROD-003 prefix inconsistency, PROD-004 padding-width inconsistency — each citing the Sedona protocol convention, each honest that filename-derived numbering is what was checked (in-page stamp reading needs per-page text the tree does not retain; explicitly out of v1 scope).
- **Privilege-log member type**: bundles accept a `.csv` privilege log (schema: control/Bates range, date, author, recipients, privilege asserted, description) as a new non-document member; PROD-010 log entries whose Bates ranges overlap produced documents (claimed withheld but apparently produced), PROD-011 gaps in the produced sequence not covered by any log entry (missing-or-unlogged), PROD-012 duplicate/overlapping log entries, PROD-013 log rows missing the FRCP 26(b)(5)(A) minimum fields (assertion + description enabling assessment).
- **Pre-production sweep**: run the existing HANDOFF-001..005 scan across every bundle member and roll up into one bundle-level pre-production report ("3 of 41 documents carry tracked changes; 7 carry author metadata"), reusing the per-document scan unchanged.
- **Scope-of-review, stated on every production report**: numbering and log reconciliation were checked from filenames and the supplied log; page-stamp Bates, redaction integrity (burned-in or failed visual redactions), and the substantive validity of privilege claims were NOT checked.

## Impact

- Affected specs: `production-qa` (new capability spec)
- Affected code: `src/ingest/multi.ts` (csv member type), new `src/ingest/privilege-log.ts` parser, `src/engine/consistency/` new member kind + PROD rules, bundle report roll-up in `src/report/bundle.ts`, CSV export of the reconciliation; tests with fixture production sets
- Risk: bundle ingest change touches a hashed path for existing bundles — the csv member type must be additive (bundles without a csv are byte-identical; regression test pins it).
