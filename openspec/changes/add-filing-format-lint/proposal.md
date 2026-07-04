# add-filing-format-lint

## Why

Litigation filing compliance is the vertical where Vaulytica's determinism is worth the most: courts strike or bounce briefs for mechanical violations (type-volume, missing certificates, missing tables), the checks are decidable from the document alone, and the planned no-generative-AI certification receipt matters most in a filing context. Nothing checks any of it today — a brief falls to `generic-fallback` and gets contract rules. The measurable substrate already exists: `IngestResult.word_count` is computed for every input and `page_count` for PDFs (`src/ingest/types.ts:54-63`), and required-block presence is the same machinery as STRUCT-003/016/018. What's missing is a litigation-filing document family, court-profile data carrying each court's limits, and a FILE-### rule pack.

## What Changes

- **Litigation-filing document family**: classifier feature data + playbooks for `appellate-brief`, `trial-motion`, `petition`; all FILE rules gated via `applies_to_playbooks` per the vertical framework.
- **Court profiles as data** (`profiles/courts/*.json`): per-court numeric limits and required blocks, each entry citing its rule with `retrieved_at`. Launch profiles: FRAP default (principal brief ≤ 13,000 words per FRAP 32(a)(7)(B)(i), as amended 2016; reply ≤ half the principal limit per 32(a)(7)(B)(ii) — 6,500 derived, not printed in the rule; 30/15-page safe harbor per 32(a)(7)(A); certificate of compliance per 32(g)) plus one circuit-override example (9th Cir. R. 32-1) and one state example (Cal. R. Ct. 8.204). Selected by `--court <profile>` / tab picker; **no profile selected → the FILE pack stays dormant** (no guessing which court's rules apply).
- **FILE-### rules**: type-volume check honest about measurement — the flattened-text word count is the tool's measure, FRAP 32(f) excludes cover/tables/certificates from the count, so the rule fires "over limit" only when the count *after* subtracting every detected excludable block still exceeds the limit, and otherwise reports an informational margin note ("the word processor's count governs per 32(g)"); page-limit check runs only where `page_count` exists (PDF) and is explicitly reported unmeasurable for DOCX; presence checks for certificate of compliance (32(g)), certificate of service, table of contents (FRAP 28(a)(2)), table of authorities (FRAP 28(a)(3)), caption block, and signature block.
- **Out of scope, stated in the pack's scope-of-review**: typeface/point-size and margin checks (FRAP 32(a)(4)-(5)) — not reliably determinable from the flattened tree; listed as "not reviewed" rather than approximated.

## Impact

- Affected specs: `filing-compliance` (new capability spec)
- Affected code: new `profiles/courts/` data + Zod schema, classifier feature data, 3 playbooks, `src/engine/rules/filing/` FILE pack, `--court` flag in `tools/cli/run.ts` + tab picker, tests (incl. fixture briefs over/under limits)
- Risk: none to existing hashes (fully gated pack, dormant without a profile — the framework change's isolation property test covers it).
