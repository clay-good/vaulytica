# v4 overview

Vaulytica v4 expands the catalog from contracts (v1) and regulated
agreements (v3) to all logically-operative legal documents — 16
sub-domains, 700+ new rules, multi-document ingest (folder / zip /
multi-file drop), and a cross-document consistency engine. The browser-
only, no-AI, no-telemetry posture of v1–v3 is unchanged.

## Audience

v4 is built for practitioners who work across document types beyond the
MSA + DPA + BAA core: corporate counsel reviewing a cap table and voting
agreement together; real-estate counsel checking a lease, SNDA, and
estoppel certificate as a bundle; estate counsel reviewing a will,
revocable trust, and advance directive. v4 surfaces mechanical
inconsistencies across all the documents in one drop.

## Scope — 16 sub-domains

| Code | Sub-domain | Families | ~Rules |
|------|------------|----------|--------|
| A | Contracts (v1 + v3 core) | NDA, MSA, SOW, SaaS, employment, lease | ~300 |
| B | Corporate governance | Bylaws, op-agreement, charter, stockholders agreement, written consent, committee charter, partnership, nonprofit | ~80 |
| C | Equity / cap-table | SPA, IRA, voting, ROFR/co-sale, option plan, warrant, 83(b) election, SAFEs, convertible note | ~70 |
| D | M&A | Merger agreement, APA, LOI, disclosure schedules, escrow, joinder, representations & warranty | ~80 |
| E | Real estate (expanded) | Net lease, PSA, SNDA, estoppel, ground lease, easement, construction contract, management agreement, HOA CC&Rs | ~60 |
| F | Employment (expanded) | Non-compete, severance, WARN, equity grant, deferred comp, consulting, IP assignment, PTO policy | ~50 |
| G | Settlement / release / demand | Settlement agreement, release, demand letter, arbitration clause, confession of judgment, consent order | ~30 |
| H | IP and licensing (expanded) | Patent license, copyright license, trademark license, trade-secret license, software escrow, open-source compliance | ~40 |
| I | Privacy (expanded) | Cookie notice, NPP, ROPA, DPIA, privacy questionnaire, incident response plan | ~40 |
| J | Healthcare | Clinical trial agreement, IRB protocol, informed consent, research data agreement | ~25 |
| K | Insurance and risk | D&O policy, CGL, workers comp, umbrella, surety bond | ~25 |
| L | Banking and lending | Loan agreement, promissory note, security agreement, UCC financing statement, guarantee, subordination | ~50 |
| M | Construction | Prime contract, subcontract, payment bond, performance bond, change order | ~30 |
| N | Trust / estate / family | Will, revocable trust, advance directive, DPOA, UPAA prenup, family settlement | ~60 |
| O | Compliance policies | Code of conduct, anti-bribery policy, AML/BSA policy, SOX 302/906 cert, whistleblower policy, sanctions policy, LDA disclosure | ~50 |
| P | Regulatory prose | Form ADV narrative, Reg S-K Item 105, Form D, private placement memorandum, blue-sky filing | ~40 |

**Sub-domain N** carries a mandatory execution-formality disclaimer in
every report cover (wills, trusts, and advance directives have
jurisdiction-specific witness / notarization requirements that a linter
cannot verify). **Sub-domain P** carries a mandatory filing-schema
disclaimer (the linter checks prose; SEC EDGAR XBRL and FINRA WebCRD
structured-data validation is out of scope).

## What's new vs. v3

1. **16 sub-domains** (vs. v3's single-family A core). Each sub-domain
   has its own rule directory, playbooks, DKB fetchers, and fixtures.
2. **Multi-document ingest.** Drop a folder, a zip, or multiple files at
   once. Up to 50 files / 200 MB per bundle.
3. **Cross-document consistency engine** with seven CROSS-* rule
   families. See [`cross-document-rules.md`](cross-document-rules.md).
4. **Two-stage document classifier.** Automatic sub-domain and family
   detection. See [`the-document-classifier.md`](the-document-classifier.md).
5. **Consolidated bundle report.** One DOCX (or zip of JSON + DOCX)
   covering all documents with a cross-document appendix and bundle
   fingerprint.
6. **700+ new rules** on top of v3's 220.

## What v4 does not do

- **No XBRL linting.** SEC EDGAR structured-data validation (XBRL /
  iXBRL) is outside scope.
- **No FINRA WebCRD filings schema.** The prose of a Form ADV narrative
  is linted; the structured submission envelope is not.
- **No AI.** v4 preserves v1–v3's deterministic, citation-pinned posture
  exactly. Every finding points to a statute, a regulation, or a
  published model form.
- **No redline / drafting.** v4 lints; it does not rewrite.
- **No full state-law coverage.** The DKB covers CA / NY / TX / FL / IL
  for most state-keyed rules; other states surface as `N/A`.

## Documents in this directory

- [`adding-a-sub-domain.md`](adding-a-sub-domain.md) — how to add a new
  sub-domain (new letter beyond P).
- [`adding-a-family.md`](adding-a-family.md) — how to add a new family
  within an existing sub-domain.
- [`cross-document-rules.md`](cross-document-rules.md) — the seven
  CROSS-* families and how the consistency engine works.
- [`the-document-classifier.md`](the-document-classifier.md) — the
  two-stage classifier, confidence threshold, and retuning guide.
