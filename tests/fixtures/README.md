# Test corpus

Synthetic fixtures plus committed golden EngineRun outputs. The
[golden-output integration test](../integration/golden-output.test.ts)
re-runs the full pipeline against every fixture and asserts the
`result_hash` matches the golden. The DKB-rebuild workflow uses the
same test as the regression gate.

## Layout

```
tests/fixtures/
├── contracts/          # input documents (generated)
│   ├── mutual-nda.docx
│   ├── bad-nda.docx
│   ├── bad-saas.docx
│   ├── bad-employment.docx
│   ├── bad-lease.docx
│   ├── bad-contractor.docx
│   ├── bad-unilateral-nda.docx
│   ├── bad-residential-lease.docx
│   ├── bad-msa.docx
│   ├── bad-saas-vendor.docx
│   ├── bad-consulting.docx
│   ├── bad-sow.docx
│   └── pasted-mutual-nda.txt
├── expected/           # golden EngineRun JSON (committed)
│   ├── mutual-nda.json
│   ├── bad-nda.json
│   ├── bad-saas.json
│   ├── bad-employment.json
│   ├── bad-lease.json
│   ├── bad-contractor.json
│   ├── bad-unilateral-nda.json
│   ├── bad-residential-lease.json
│   ├── bad-msa.json
│   ├── bad-saas-vendor.json
│   ├── bad-consulting.json
│   ├── bad-sow.json
│   └── pasted-mutual-nda.json
├── build-fixtures.ts   # generator for contracts/
├── ingest/             # unit-test ingest fixtures (not part of golden corpus)
└── README.md           # this file
```

## What each fixture exercises

| Fixture                       | What it covers                                                                                         |
| ----------------------------- | ------------------------------------------------------------------------------------------------------ |
| `mutual-nda.docx`             | Common-Paper-shaped clean Mutual NDA. Establishes the baseline result_hash for the mutual-nda playbook. |
| `bad-nda.docx`                | Five intentional rule violations: unfilled `[insert]` placeholder, hanging cross-reference to `Section 9.4`, word/numeral amount mismatch (`fifty thousand` vs `$75,000`), uncapped liability with consequential damages, impossible date `February 30, 2026`. |
| `bad-saas.docx`                | Auto-renewal buried in §13(c), unilateral modification right, asymmetric customer-only indemnification. Hits the saas-customer playbook. |
| `bad-employment.docx`         | Seven intentional violations targeting the `employment-at-will-us` playbook + the post-1.0 personnel/dark-pattern rules: California non-compete (PERS-005), non-disparagement without NLRA/SEC carve-outs (PERS-006), asymmetric termination-for-convenience (TERM-009), one-sided jury-trial waiver (CHOICE-010), undefined `best efforts` (OBLI-008), class-action waiver (DARK-005), survival clause silent on confidentiality + IP (TEMP-012). All 7 fire. |
| `bad-lease.docx`              | Seven intentional violations targeting the `lease-commercial-multitenant` playbook: `[Premises Address]` placeholder (STRUCT-013), 10-day non-renewal window (TEMP-011), 3%/month late fee = 36%/year (FIN-009), bare `shall maintain insurance` (RISK-016), indemnification without cap (RISK-015), asymmetric pre-suit notice gate (DARK-006), one-sided jury-trial waiver (CHOICE-010). All 7 fire. |
| `bad-contractor.docx`         | Independent-contractor agreement with misclassification dark patterns (fixed hours / location / company-supplied tools / exclusivity). Surfaces through five rules: class-action waiver (DARK-005), `[insert contractor name]` placeholder (STRUCT-013), California non-compete (PERS-005), non-disparagement (PERS-006), asymmetric termination (TERM-009). No dedicated misclassification rule exists in the catalog yet — the surface emerges from the post-1.0 personnel/dark-pattern surface. |
| `bad-unilateral-nda.docx`     | One-way NDA targeting the `unilateral-nda` playbook. Intentional violations: uncapped damages (RISK-009), survival silent on confidentiality (TEMP-012), `[insert recipient name]` placeholder (STRUCT-013). |
| `bad-residential-lease.docx`  | Residential lease targeting the `lease-residential-us` playbook. Six intentional violations: 7-day non-renewal window (TEMP-011), 5%/month late fee (60%/year) (FIN-009), asymmetric pre-suit notice (DARK-006), browsewrap modification via "continued occupancy" (DARK-007), tenant-only non-disparagement (PERS-006), `[Property Address]` placeholder (STRUCT-013). |
| `bad-msa.docx`                | Master Services Agreement targeting the `msa-general` playbook. Seven intentional violations: MAC clause (OBLI-007), undefined `reasonable efforts` (OBLI-008), indemnification without cap (RISK-015), insurance without coverage minimum (RISK-016), Delaware-law/Texas-venue mismatch (CHOICE-009), asymmetric termination (TERM-009), `[Effective Date]` placeholder (STRUCT-013). |
| `bad-saas-vendor.docx`        | Vendor-side SaaS contract with aggressive commitments (99.99% uptime, perpetual IP indemnity, indemnity carved out of cap). The matcher prefers saas-customer over saas-vendor here because the two playbooks share most features for a generic SaaS doc — the sanity guard is playbook-agnostic. Surfaces FIN-009, IPDATA-007, RISK-015, OBLI-008, STRUCT-013. |
| `bad-consulting.docx`         | Hybrid IC + advisory consulting agreement targeting the `consulting-agreement` playbook. Misclassification dark pattern with explicit deliverables (consulting-typical). Fires the new PERS-007 misclassification rule plus PERS-005, PERS-006, OBLI-008, STRUCT-013. |
| `bad-sow.docx`                | Statement of Work targeting the `sow` playbook (child of `msa-general`). Intentional violations: under-defined deliverables (Customer-discretion clause), 2%/month late fee, `[TBD]` placeholder, undefined `best efforts`. |
| `bad-nda-residuals.docx`      | Mutual NDA carrying a Residuals clause + `unaided memory` language + perpetual term. Surfaces the new OBLI-009 rule. |
| `bad-nda-no-dtsa.docx`        | One-way NDA missing the DTSA 18 USC §1833(b) whistleblower notice + agency-communication bar. Surfaces OBLI-005 + STRUCT-013. |
| `bad-employment-trap.docx`    | Employment agreement with training-repayment / "TRAP" clause, AMN-style non-solicit, class-action waiver, JAMS arbitration. Surfaces the new PERS-008 rule + DARK-005 + CHOICE-010. |
| `bad-employment-choice-of-law.docx` | California-based employee with Delaware governing law + invention-assignment overreach. Surfaces the new CHOICE-011 rule + PERS-005. |
| `bad-contractor-leaseback.docx` | Independent-contractor agreement with forced equipment leaseback + hourly wages + IP sweep. Surfaces FIN-005, RISK-011, STRUCT-013. |
| `bad-saas-data-hostage.docx`  | SaaS contract with data-hostage termination, AI/ML training rights, and an aggregated/derived-data carve-out. Surfaces the new IPDATA-009 rule + FIN-009 + IPDATA-004/005. |
| `bad-saas-suspension.docx`    | SaaS contract with unilateral suspension + token SLA + audit gated behind suspension threat. Surfaces the new DARK-008 rule + OBLI-006. |
| `bad-saas-vendor-uncapped-ip.docx` | Vendor-side SaaS contract with uncapped IP indemnity, impossible portability, and 99.99% uptime promised on `best efforts`. Matched as msa-general by the playbook scorer. Surfaces IPDATA-007 + RISK-011 + STRUCT-013. |
| `bad-msa-mfn.docx`            | Master Services Agreement with most-favored-nation pricing, customer-discretion scope change, payment-acceptance waiver, and change-of-control ratchet. Surfaces OBLI-001 + FIN-005 + STRUCT-013. |
| `bad-lease-cam.docx`          | Commercial lease with uncapped CAM gross-up asymmetry, relocation right, holdover doubling, and personal guaranty. Surfaces RISK-016 + RISK-011 + STRUCT-013. |
| `bad-residential-lease-deposit.docx` | Residential lease with security-deposit overcollection (3 months), Javins implied-warranty waiver, and illegal-entry clause. Surfaces FIN-005 + STRUCT-013. |
| `bad-consulting-success-fee.docx` | Consulting agreement with success-fee + IP sweep + conflict-of-interest waiver + non-solicit. Surfaces RISK-015 + OBLI-008 + OBLI-004 + STRUCT-013. |
| `pasted-mutual-nda.txt`       | Pasted-text variant of the clean NDA — exercises the `ingestPaste` path and verifies parity with the docx ingest's tree shape. |

## Regenerating the fixtures

```
npm run fixtures
```

`build-fixtures.ts` deterministically produces every `.docx` and `.txt`
under `contracts/`. Don't hand-edit the generated files — edit the
generator and re-run.

## Regenerating golden outputs

Run **after an intentional rule / extractor / DKB change** that you've
reviewed and accepted as the new baseline:

```
npm run fixtures:regen-golden
```

This sets `VAULYTICA_REGEN_GOLDEN=1` and invokes the golden test in
write mode. Review the diff with `git diff tests/fixtures/expected/`
before committing. Every diff is a deliberate baseline change — there
is no "auto-accept" path.

The DKB-rebuild workflow ([dkb-rebuild.yml](../../.github/workflows/dkb-rebuild.yml))
runs the golden test on every weekly rebuild. A drift produces a PR
for human review; it never auto-merges a baseline change.

## What's deferred

These fixtures from spec §26 step 16 require network access or a
print-to-image step and are tracked separately:

- **Real Common Paper Mutual NDA v1.1** in DOCX from
  `github.com/CommonPaper/Mutual-NDA` (the generator above produces a
  Common-Paper-*shaped* synthetic, not the live template — those carry
  the CC BY 4.0 attribution requirement and must be vendored under
  `tests/fixtures/contracts/common-paper/` once fetched).
- **Real Common Paper One-Way NDA**.
- **Real Common Paper Cloud Service Agreement** (saas-vendor/saas-customer baseline).
- **GitHub Balanced Employee IP Agreement** in DOCX (CC0).
- **An open-licensed commercial lease**.
- **A scanned PDF variant** of `mutual-nda.docx` to exercise the OCR
  path (`ingest/ocr.ts`). Generate by printing the DOCX to PDF, then
  rasterizing each page to a 200dpi image, then re-wrapping into a
  PDF with no embedded text layer.

The golden-output test skips missing fixtures gracefully; the test
list shrinks/grows automatically with what's in `contracts/`.

## Determinism note

The golden files have `executed_at` blanked and `elapsed_ms` set to 0
for every execution-log entry — both are wall-clock measurements
excluded from the `result_hash` and would otherwise drift on every
run. See [docs/determinism.md](../../docs/determinism.md) for the
contract.
