# Vaulytica — Build Specification v3 (Compliance & Regulated-Agreement Expansion)

> **Status:** ✅ **complete (shipped, version 3.0.0).** All four anchor families (BAA / DPA / NDA-deep / MSA-deep) and their supporting documents shipped as **+220 rules** with citation-pinned sources, the two-document consistency mode, and the compliance matrix. See [`BUILD_PROGRESS.md`](../BUILD_PROGRESS.md) and [`docs/v3/`](v3/).
>
> v3 assumes v2 (see [spec.md](spec.md)) is fully implemented and deployed: the ingest layer, OCR fallback, extractors, ~80 deterministic rules across ten categories, the twelve launch playbooks (including the existing generic `mutual-nda`, `unilateral-nda`, `msa-general`, `saas-customer`, `saas-vendor`), the DOCX reporter, the DKB build pipeline, and the single-page UI are all live. v3 does not rewrite any of that. v3 extends it.
>
> The wedge for v3 is the family of agreements where the *correct* answer is dictated by statute, regulation, or a published model form rather than market norms. These are the agreements that lawyers and compliance officers most often get wrong — not because the rules are hard, but because the rules are voluminous, cross-referenced, and changed by an agency three jurisdictions away last quarter. A deterministic linter that knows the citation for each missing clause is, for these documents, more valuable than a senior associate doing a midnight read. v3 ships that.
>
> The four anchor agreement families v3 adds are: **Business Associate Agreements (BAA)** under HIPAA, **Data Processing Agreements (DPA)** under GDPR / UK GDPR / US state privacy law, deep **Non-Disclosure Agreements (NDA)** under DTSA / UTSA, and deep **Master Services Agreements (MSA)** with full indemnity / IP / warranty coverage. v3 also adds the supporting documents that almost always travel with those four: EU Standard Contractual Clauses, the UK International Data Transfer Addendum, subprocessor agreements, vendor security addenda, Certificates of Insurance (COI), end-user license agreements (EULA), SaaS terms of service, AI usage addenda, and a privacy-policy linter. The goal is that a privacy program manager, a HIPAA security officer, a vendor-risk analyst, or a startup GC can drop any document in the regulated-vendor lifecycle onto the page and get back a Word file that names every missing required clause, with the exact CFR section, GDPR article, or state-statute paragraph that requires it.
>
> Everything that made v2 defensible still applies in v3: no server, no AI, no telemetry, no login, every finding traceable to a rule ID and a regulatory citation, reproducible result hash, MIT license. v3 is more ambitious in scope but identical in posture.

---

## Table of Contents

Part I — Scope and rationale
1. Why v3 exists and who it is for
2. What v3 explicitly does and does not promise
3. The five regulated-agreement families and their adjacent documents
4. Determinism under regulatory churn

Part II — Regulatory and legal source catalog
5. HIPAA sources for BAAs
6. GDPR / UK GDPR / Swiss FADP sources for DPAs
7. US state privacy sources for DPAs and service-provider terms
8. Sectoral US sources (GLBA, FERPA, COPPA, FCRA, CJIS, IRS Pub 1075, FedRAMP)
9. International privacy sources (PIPEDA, LGPD, APPI, PIPL)
10. Trade-secret sources for NDAs (DTSA, state UTSA variants, whistleblower carve-outs)
11. Commercial-law sources for MSAs (UCC, ABA model provisions, Common Paper, CUAD-large)
12. Insurance sources for COI checking (ACORD forms, ISO endorsements, AM Best)

Part III — DKB expansion
13. New DKB node types and schema additions
14. Source-pinning protocol for citation stability
15. Fixture corpora (HHS sample BAA, EU SCC official template, ICO IDTA template, IAPP samples)
16. Citation conventions for regulatory text in the report

Part IV — Engine expansion
17. New extractors required
18. Role classification (controller, processor, sub-processor, covered entity, business associate, service provider)
19. PHI and personal-data category detection
20. Cross-border transfer language detection
21. Security-measures inventory extraction
22. Breach-notification timing extraction
23. Audit-rights and inspection-clause detection
24. Subprocessor inventory and onward-transfer extraction
25. Insurance amount, AM-Best rating, additional-insured endorsement extraction
26. Whistleblower / DTSA notice detection
27. Two-document mode (MSA + DPA pair, MSA + BAA pair, MSA + SOW pair)

Part V — Rule catalog additions (target: ~220 new rules)
28. BAA rules — ~45 rules
29. DPA rules (GDPR core) — ~55 rules
30. DPA rules (US state privacy overlays) — ~25 rules
31. International transfer rules (EU SCCs, UK IDTA, Swiss Addendum, adequacy) — ~20 rules
32. NDA deep rules — ~25 rules
33. MSA deep rules — ~30 rules
34. Vendor security addendum / subprocessor / AI addendum rules — ~20 rules

Part VI — New and revised playbooks
35. BAA (HIPAA covered-entity to business-associate)
36. BAA-Subcontractor (business-associate to subcontractor)
37. DPA-Controller-to-Processor (EU/UK)
38. DPA-Processor-to-Subprocessor
39. DPA-CCPA-Service-Provider (CPRA-aligned)
40. DPA-Multi-State-US (Colorado, Virginia, Connecticut, Utah, Texas, Oregon, Delaware)
41. SCC-Module-Two (controller to processor, EU 2021/914)
42. SCC-Module-Three (processor to processor, EU 2021/914)
43. UK-IDTA-Addendum (UK Addendum to EU SCCs + IDTA standalone)
44. Mutual-NDA-Deep (replaces v2 `mutual-nda`)
45. Unilateral-NDA-Deep (replaces v2 `unilateral-nda`)
46. MSA-Vendor-Deep (replaces v2 `saas-vendor` / `msa-general` for vendor-side)
47. MSA-Customer-Deep (replaces v2 `saas-customer` / `msa-general` for customer-side)
48. Vendor-Security-Addendum
49. AI-Addendum (generative-AI usage in vendor agreements)
50. EULA / End-User License
51. SaaS-Terms-of-Service (consumer-facing)
52. Privacy-Policy-Lint (not a contract, but a published policy compliance check)
53. COI / Certificate-of-Insurance check

Part VII — Report changes
54. The compliance-matrix section (per-regulation pass / fail / partial)
55. Citation depth (CFR, GDPR article and recital, state-statute paragraph)
56. Cross-border transfer summary
57. Subprocessor inventory page
58. Insurance summary page
59. The "two-document consistency" appendix

Part VIII — UI
60. Document-type auto-detect for the new families
61. The "compliance frame" toggle (treat-as: HIPAA / GDPR / CCPA / state-X / multi)
62. Multi-document drop (pair an MSA with its DPA; pair a BAA with its underlying MSA)
63. New empty-state copy and error states

Part IX — Build plan: 22-step Claude Code prompt sequence
64. Steps 18 through 39

Part X — Test corpus, fixtures, golden outputs

Part XI — Roadmap, non-goals, and what v4 might be

Part XII — Legal disclaimers expansion

---

# Part I — Scope and rationale

## 1. Why v3 exists and who it is for

v2 served the lawyer reading a contract at midnight and the founder trying not to sign something stupid. v3 serves a different reader: the compliance officer, the privacy program manager, the vendor-risk analyst, the HIPAA security officer, and the startup general counsel who needs to know whether the BAA the hospital sent back is actually a BAA or just a covering letter. These readers do not need help with judgment. They need help with completeness. They are evaluated quarterly on whether the agreements in the vendor folder contain the clauses the regulator will ask about, and they have between forty and four hundred such agreements in scope per audit.

The v2 product handles those readers' agreements imperfectly because v2's rules are written for "any commercial contract." They flag missing indemnity caps and surprise auto-renewals. They do not flag a BAA that omits the breach-notification deadline required by 45 CFR § 164.410, because v2 has no concept of a BAA. v3 fixes that by adding regulator-anchored rule sets, structured playbooks for each regulated-agreement family, and a report layout that maps every finding to the regulatory clause that demands it.

The audience for v3 is, in priority order: in-house privacy and compliance teams at companies that process protected health information or personal data at scale; security and vendor-risk teams that ingest hundreds of vendor agreements per year; outside counsel who service those teams and are tired of running the same fifty checks by hand; and the founder or solo operator who has just been asked to sign a BAA and has never seen one before. v3 is not for plaintiffs' lawyers, not for litigation review, not for due-diligence data rooms (although a v4 might be), and not for active negotiation drafting. v3 reads finished or near-finished documents and tells the reader what is missing or wrong relative to the applicable regulator.

## 2. What v3 explicitly does and does not promise

v3 promises to identify, with a citation to the controlling regulation or model form, every required or strongly recommended clause that is missing from the input document; every required clause that is present but materially weaker than the regulator's text; every clause whose timing, threshold, or scope is inconsistent with the controlling rule (e.g., a BAA that pegs breach notification at "promptly" rather than the sixty-day maximum the rule allows); and every internal inconsistency between two documents the user drops together (MSA cap that excludes the DPA's indemnity carve-outs, BAA that references a subprocessor list the MSA does not authorize, etc.).

v3 does not promise to tell the user whether to sign. It does not negotiate. It does not generate redlines, although it produces text the user can paste verbatim into a comment. It does not interpret ambiguous regulatory guidance — when the regulator is silent or the case law is unsettled, v3 says so and stops. It does not give legal advice. It does not establish an attorney-client relationship. It does not replace counsel. It is a linter. The same disclaimer that anchored v2 — "this is the second pair of eyes you can cite" — anchors v3, only now the citations are 45 CFR, EUR-Lex, and the state codes rather than market norms.

## 3. The five regulated-agreement families and their adjacent documents

The five families that organize v3 are: BAA, DPA, NDA, MSA, and **the transfer mechanism family** (EU SCCs, UK IDTA, Swiss Addendum, and country-specific adequacy mechanisms). The first four are documents the user signs. The fifth is a document or set of clauses incorporated by reference into the DPA — but it has its own rules and its own regulator-published model form, so v3 treats it as a first-class family.

Each family has a set of adjacent documents that almost always travel with it and that v3 must therefore recognize even if it lints them with a lighter touch. The BAA family travels with the underlying MSA (the BAA references it), the subcontractor BAA (a downstream BAA between the business associate and its subprocessor), and the security questionnaire (often delivered as an addendum rather than a contract — out of scope for v3 but flagged when present). The DPA family travels with the MSA, the SCCs, the subprocessor list, the transfer impact assessment (a Schrems II artifact the contract often references), and the data-categories schedule. The NDA family travels with the term-sheet or LOI it usually precedes and with the residual-clause carve-outs that operating companies fight about. The MSA family travels with the SOW, the order form, the DPA, the BAA, the SLA, the COI requirement schedule, and the AI-usage addendum that is increasingly bolted on. The transfer-mechanism family travels with adequacy-decision references and with country-specific supplementary measures (the Schrems II "supplementary measures" the EDPB requires when transferring to a non-adequate country).

v3 ships one playbook per signable document in each family, plus one for each adjacent document where the rule density justifies it. The full list is §§35–53. The total target is eighteen new or revised playbooks layered on top of v2's twelve.

## 4. Determinism under regulatory churn

v2 made one promise about determinism that v3 must keep harder: identical input produces identical output, every time, with a result hash to prove it. v3 strains that promise because the regulations underneath the rules change. The OCR Office for Civil Rights revises HIPAA guidance every couple of years. The European Data Protection Board publishes new opinions almost monthly. State privacy statutes pass on a six-month cycle. Adequacy decisions get litigated. v3 must remain reproducible without freezing the rule set in 2026 forever.

The mechanism is the one v2 already uses, extended. Every rule carries the version of the DKB node it depends on. The DKB is rebuilt weekly. When a rule's underlying citation changes, the rule's `dkb_version_required` advances, the test fixtures are re-baselined, and the report records both the rule version and the DKB version that produced the finding. A reader running Vaulytica on the same document with a v3.4 build will get the same answer in 2026 and 2030; a reader running v3.7 may get a slightly different answer because the law moved. That is not a determinism failure; it is the only honest way to deal with living regulations. The report names both versions on every page so the reader knows which "deterministic" answer they are looking at.

A second mechanism: regulator-published model forms are treated as ground truth. The HHS sample BAA, the EU SCC official template at EUR-Lex, the ICO IDTA template, and the IAPP-published DPA reference are vendored into the repo at pinned URLs. When the regulator updates them, the DKB build pipeline detects the change, opens a PR with the diff for human review, and refuses to auto-merge. This is the only place in the build where a human is required.

---

# Part II — Regulatory and legal source catalog

This section enumerates every source the v3 DKB ingests. Every source has a fetch URL, a license note, a parsing strategy, and an update cadence. The DKB build pipeline (extended from v2's pipeline at `src/dkb/build/`) gains a new fetcher per source.

## 5. HIPAA sources for BAAs

The controlling text is the Privacy Rule and the Security Rule, codified at 45 CFR Parts 160 and 164. The BAA-specific provisions are 45 CFR § 164.504(e) (the required contract terms between covered entities and business associates), 45 CFR § 164.314(a) (the Security Rule requirements that flow through to business associates), 45 CFR § 164.410 (business associate breach notification, with the sixty-day outer bound and the "without unreasonable delay" inner bound), 45 CFR § 164.502(e) (the rule that imposes BAA requirements on covered entities), and 45 CFR § 164.504(e)(5) (the "satisfactory assurances" the covered entity must obtain).

The fetcher pulls from eCFR (`https://www.ecfr.gov/api/versioner/v1/full/{date}/title-45.xml?part=164` for the canonical XML) and falls back to govinfo CFR archives for historical versions. The license is U.S. government work, public domain.

HHS-published model BAA language lives at `https://www.hhs.gov/hipaa/for-professionals/covered-entities/sample-business-associate-agreement-provisions/index.html`. The fetcher pulls the HTML, extracts the clause blocks, and stores them as fixture text. License: U.S. government work, public domain.

OCR enforcement actions and resolution agreements at `https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/agreements/index.html` provide the case-law-ish corpus for rules that are stricter-than-statute because of OCR posture (e.g., the "65-day breach notification has gotten companies fined" reality). These are vendored as a JSON list of (date, respondent, finding, penalty, lesson) tuples.

The HITECH Act amendments (Pub. L. 111-5) are incorporated into 45 CFR by reference; no separate fetcher is needed.

## 6. GDPR / UK GDPR / Swiss FADP sources for DPAs

The controlling text is Regulation (EU) 2016/679 — the General Data Protection Regulation. The DPA-specific provisions are Article 28 (the controller-processor contract requirements, including the eight enumerated clause categories at Art. 28(3)(a)–(h)), Article 32 (security of processing), Article 33 (controller breach notification — 72 hours), Article 34 (data-subject breach notification), Articles 35–36 (DPIA), Articles 44–49 (international transfers), and the relevant recitals (especially Recitals 81 and 82 for Article 28).

The fetcher pulls from EUR-Lex at `https://eur-lex.europa.eu/eli/reg/2016/679/oj` with the structured XML view (`/CELEX:32016R0679/{lang}/xml`). License: EUR-Lex re-use notice — free re-use with attribution.

The Standard Contractual Clauses are Commission Implementing Decision (EU) 2021/914 of 4 June 2021, with four modules (controller-to-controller, controller-to-processor, processor-to-processor, processor-to-controller). The official text is at `https://eur-lex.europa.eu/eli/dec_impl/2021/914/oj`. The official template is in the Annex. The fetcher pulls the Annex, parses each module, and stores each module's required clauses as a DKB node.

The UK GDPR is the GDPR as retained in UK law by the Data Protection Act 2018 and the Data Protection, Privacy and Electronic Communications (Amendments etc) (EU Exit) Regulations 2019, with the substantive text at `https://www.legislation.gov.uk/eur/2016/679/contents`. The UK International Data Transfer Agreement (IDTA) and the UK Addendum to the EU SCCs are published by the ICO at `https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/international-transfers/international-data-transfer-agreement-and-guidance/`. Both are vendored as fixtures.

The Swiss Federal Act on Data Protection (revFADP, in force 1 September 2023) is at `https://www.fedlex.admin.ch/eli/cc/2022/491/en`. The Swiss FDPIC's addendum to the EU SCCs (the "Swiss Addendum") is at the FDPIC site. License: Swiss Confederation, public re-use.

The European Data Protection Board's guidelines and opinions are at `https://edpb.europa.eu/our-work-tools/general-guidance/guidelines-recommendations-best-practices_en`. The fetcher pulls the index page and downloads each PDF; the parser is light (we cite to the document, not the paragraph, because EDPB documents are not stable enough for paragraph-level citation). License: EU re-use notice.

## 7. US state privacy sources for DPAs and service-provider terms

California: CCPA as amended by CPRA, Cal. Civ. Code §§ 1798.100–1798.199.100, with the service-provider / contractor / third-party contract provisions at § 1798.140(ag)–(ai) and § 1798.100(d). The implementing regulations are at Cal. Code Regs. tit. 11, §§ 7000–7304, with the service-provider contract requirements at § 7051. Fetch: `https://leginfo.legislature.ca.gov/faces/codes_displayText.xhtml?division=3.&part=4.&lawCode=CIV&title=1.81.5` and `https://oag.ca.gov/privacy/ccpa/regs`. License: public domain.

Virginia: VCDPA, Va. Code §§ 59.1-575 to 59.1-585. The processor contract requirements are at § 59.1-579. Fetch: `https://law.lis.virginia.gov/vacodefull/title59.1/chapter53/`.

Colorado: CPA, Colo. Rev. Stat. §§ 6-1-1301 to 6-1-1313. Processor requirements at § 6-1-1305. Implementing rules at 4 CCR 904-3 with the processor contract requirements at Rule 8.04.

Connecticut: CTDPA, Conn. Gen. Stat. §§ 42-515 to 42-525, with processor contract requirements at § 42-520.

Utah: UCPA, Utah Code §§ 13-61-101 to 13-61-404, processor requirements at § 13-61-301.

Texas: TDPSA, Tex. Bus. & Com. Code Ch. 541, processor requirements at § 541.104.

Oregon: OCPA, ORS §§ 646A.570 to 646A.589, processor requirements at § 646A.578.

Delaware: DPDPA, 6 Del. C. §§ 12D-101 to 12D-111, processor requirements at § 12D-107.

The state-by-state corpus is updated quarterly; new statutes pass faster than that, so the DKB carries a "statutes pending" list manually curated from IAPP's tracker (cited, not scraped).

## 8. Sectoral US sources

Gramm-Leach-Bliley Act and the Safeguards Rule, 16 CFR Part 314, for financial-data service-provider arrangements. The 2023 Safeguards Rule amendments require specific vendor-oversight contract terms (§ 314.4(f)). Fetch via eCFR.

FERPA, 20 USC 1232g and 34 CFR Part 99, for student-data service-provider arrangements ("school official" exception).

COPPA, 15 USC 6501–6506 and 16 CFR Part 312, for children's-data vendor arrangements.

FCRA, 15 USC 1681 et seq., for consumer-reporting-agency vendor relationships and the §1681e(b) accuracy obligations that flow through to service providers.

CJIS Security Policy v5.9+, for criminal-justice information vendor arrangements. Fetch from FBI CJIS publications.

IRS Publication 1075 for federal tax information vendor arrangements. Fetch from `https://www.irs.gov/pub/irs-pdf/p1075.pdf`.

FedRAMP and StateRAMP baselines: out of scope for v3 (v3 does not certify; it lints). But v3 flags when a contract references a FedRAMP authorization and the referenced authorization does not exist in the public marketplace at `https://marketplace.fedramp.gov/`.

## 9. International privacy sources

Canada PIPEDA, S.C. 2000, c. 5, with vendor-arrangement guidance from the OPC. Fetch from `https://laws-lois.justice.gc.ca/eng/acts/P-8.6/`.

Brazil LGPD, Lei nº 13.709/2018. Fetch from `https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm`. ANPD-published model clauses where available.

Japan APPI, with the 2020 amendments. Fetch from PPC publications.

China PIPL, with the cross-border transfer rules and the CAC standard contract. Fetch from CAC publications (with caution about translation provenance — v3 cites only to English translations from reputable sources and flags the translation provenance in the citation).

Each international source is rule-counted lightly in v3 launch; the goal is recognition and basic clause checking, not full audit-grade coverage. A v4 may deepen these.

## 10. Trade-secret sources for NDAs

The Defend Trade Secrets Act, 18 USC 1831–1839. Key provisions: § 1836 (federal civil cause of action), § 1839 (definitions, including the "reasonable measures" requirement for trade-secret status), and critically § 1833(b) (the whistleblower immunity notice that must appear in any NDA, employment agreement, or contractor agreement governing trade-secret use — failure to include the notice forfeits the right to recover exemplary damages and attorneys' fees against the employee).

The Uniform Trade Secrets Act, as adopted with variations in 48 states (everyone except New York and North Carolina, with New York operating under common law and North Carolina under its own statute). Fetch the ULC text at `https://www.uniformlaws.org/committees/community-home?CommunityKey=3a2538fb-e030-4e2d-a9e2-90373dc05792` and supplement with each state's enacted version from state code sources.

Common-law-of-trade-secrets references for New York via Restatement (Third) of Unfair Competition § 39.

EU Trade Secrets Directive (2016/943) for NDA matters in EU jurisdictions. Fetch from EUR-Lex.

## 11. Commercial-law sources for MSAs

UCC Article 2 (sale of goods) where the MSA covers goods. Most SaaS MSAs are services contracts and UCC Article 2 does not apply, but the analysis must be done — v3 flags when an MSA covering goods omits required UCC warranty disclaimers.

The ABA Model Stock Purchase Agreement, the ABA Model Asset Purchase Agreement, and the ABA Section of Business Law's "Model Commercial Contract Provisions" (where publicly available) for market-norm baselines on indemnity, cap, and warranty language.

Common Paper's published standards at `https://commonpaper.com/` (Cloud Service Agreement, Mutual NDA, and others) as one source of market-norm baselines for MSA and NDA rules.

CUAD (Contract Understanding Atticus Dataset) at `https://www.atticusprojectai.org/cuad` for clause classification training data and prevalence statistics.

LEDGAR for additional clause classification corpus.

State-specific commercial-contract requirements: California's specific requirements for limitation-of-liability clauses (Cal. Civ. Code § 1668 voids exculpatory clauses for willful misconduct), New York's General Obligations Law § 5-322.1 voiding indemnity for sole negligence in construction contracts, Texas's anti-indemnity statute Tex. Bus. & Com. Code Ch. 151 for construction, and the analogous provisions in roughly thirty other states.

## 12. Insurance sources for COI checking

ACORD 25 (Certificate of Liability Insurance) form layout at `https://www.acord.org/` — the standard form whose fields v3 must recognize and extract. License: ACORD owns the form; the *layout* recognition is fair-use for purposes of reading it.

ISO standard endorsements: CG 20 10 (additional insured — owners, lessees, or contractors — scheduled person or organization), CG 20 37 (the completed operations counterpart), CG 20 26 (additional insured — designated person or organization), and the waiver-of-subrogation endorsements. v3 detects references by form number.

AM Best ratings reference: v3 carries a curated list of carriers and their AM Best ratings as of the last DKB build, and flags COIs that list a carrier with a rating below the customer's required minimum (commonly A- VII).

Typical industry minimums: $1M/$2M general liability, $1M auto, $1M umbrella for low-risk professional services; $2M/$4M and $5M umbrella for healthcare / data-heavy; $5M+ professional liability and $5M+ cyber for SaaS vendors handling regulated data. v3 carries a "norms-by-vertical" table as a DKB node; the rule's output is "below the typical minimum for [vertical]," not "below the right amount," because there is no right amount.

---

# Part III — DKB expansion

## 13. New DKB node types and schema additions

v2's DKB schema (Appendix B of [spec.md](spec.md)) defines node types for `rule_source`, `clause_template`, `regulator_citation`, `market_norm`, and `classifier_corpus_entry`. v3 adds:

- `regulator_model_form`: a regulator-published model clause set with an authoritative URL, a vendored copy at a content hash, and a list of clauses each tagged with the citation that requires it.
- `statutory_clause_requirement`: a single requirement extracted from a statute (e.g., "BAA must require business associate to report security incidents") with the citation, the regulator, the jurisdiction, the effective date, and the "what counts as compliant" minimum text.
- `transfer_mechanism`: an entry describing one cross-border transfer mechanism (Adequacy Decision, EU SCC Module 2, EU SCC Module 3, UK IDTA, UK Addendum, Swiss Addendum, BCRs, Art. 49 derogations) with its scope and its required ancillary documents (TIA, supplementary measures).
- `subprocessor_requirement`: a normalized statement of subprocessor-related contract requirements per regulator (notice period, objection rights, flow-down terms, list-publication obligations).
- `insurance_norm`: a row in the norms-by-vertical table with minimum coverage amounts, required endorsements, and required carrier rating.
- `consistency_check`: a rule that operates over two documents loaded together rather than one.

Each new node type has a JSON schema sketched in Appendix B of this file. Each carries a `dkb_node_version` and a `dkb_node_last_validated_at` so the build pipeline can detect drift.

## 14. Source-pinning protocol for citation stability

Regulatory text changes. When 45 CFR § 164.504(e) is renumbered or amended, every rule that cites it must update or invalidate. The protocol is: every rule node carries `cites: [{authority, citation, dkb_node_id, content_hash_at_pin}]`. The build pipeline, on each weekly run, fetches the cited authority and compares the content hash. If the hash differs, the rule is moved to a "stale-citation" queue and the rule's `enabled` flag is set to `false` until a human resolves the diff. The report continues to run on the remaining rules. The UI surfaces the count of disabled-pending-review rules. The release tag of the DKB ships only when the queue is empty or every queued item has been triaged.

This protocol means citations in the report are always either currently-correct or absent. There is no quiet drift.

## 15. Fixture corpora

Vendored at `dkb/fixtures/v3/`:

- `hhs-sample-baa.html` and `hhs-sample-baa.parsed.json` (HHS model BAA provisions).
- `eu-scc-2021-914-module-2.docx`, `eu-scc-2021-914-module-3.docx`, parsed and clause-indexed.
- `uk-idta-template.docx` and `uk-addendum-template.docx` from ICO.
- `swiss-addendum-template.pdf` from FDPIC.
- `iapp-dpa-reference.docx` (with license clearance; if not clearable, omit and substitute with the EDPB-published DPA example).
- HHS OCR resolution-agreement summaries, one JSON per agreement, ~30 entries to start.
- A curated set of 25 real-world BAAs, 25 real-world DPAs, 15 real-world MSAs, 15 real-world NDAs collected from public sources (SEC EDGAR Form 8-K Item 1.01 exhibits and similar). These are the golden-input corpus for rule regression testing.
- ACORD 25 blank form (for layout recognition).

## 16. Citation conventions for regulatory text in the report

Every report finding in v3 must cite to the most specific authority that supports it. Conventions:

- US CFR citations as `45 CFR § 164.504(e)(2)(ii)(A)` — full title, section, and subdivisions. The clickable link in the DOCX uses `https://www.ecfr.gov/current/title-45/section-164.504#p-164.504(e)(2)(ii)(A)`.
- US statutory citations as `18 U.S.C. § 1833(b)(1)` with the `https://www.govinfo.gov/link/uscode/...` link form.
- GDPR citations as `GDPR Art. 28(3)(a)` with link to `https://eur-lex.europa.eu/eli/reg/2016/679/oj` and the article anchor.
- State-statute citations as the state's canonical citation (e.g., `Cal. Civ. Code § 1798.100(d)`, `Va. Code § 59.1-579(A)(1)`).
- Regulator-guidance citations as `[Regulator], [Title], at [page]` with stable URL.
- Each citation in the report includes the DKB node ID and the DKB version (small grey footnote text) so a reader running the report through Vaulytica's verifier can confirm provenance.

The footer of every page of the v3 report carries: the rule-set version, the DKB version, the result hash, and the legend "Citations as of [DKB build date]."

---

# Part IV — Engine expansion

## 17. New extractors required

v2 extracted: parties, definitions, headings, dates, monetary amounts, term and termination, governing law and venue, signature blocks, obligations (subject-modal-action triples), and cross-references. v3 adds:

- **Role classification**: every party labeled as one or more of {covered entity, business associate, subcontractor, controller, processor, sub-processor, joint controller, third party, service provider (CCPA), contractor (CCPA), service recipient, service supplier}. The classifier is rule-based on definitional language ("'Business Associate' means...") plus a small CUAD-derived classifier where definitions are absent.
- **PHI / personal-data category detection**: detection of category schedules (Annex I.B of EU SCCs, Schedule A of typical DPAs, the "categories of PHI" recitals in BAAs) including category enumeration and any "special categories" / Article 9 / sensitive-data flags.
- **Cross-border transfer language detection**: identification of references to SCCs, IDTA, adequacy decisions, BCRs, Article 49 derogations, and the structured location of the transfer mechanism's terms (incorporated, attached, by reference, etc.).
- **Security-measures inventory extraction**: a normalized list of stated security measures (encryption at rest, encryption in transit, MFA, pen test cadence, ISO 27001, SOC 2, vulnerability management, BCP/DR, access reviews) and their stated cadences. The extractor reads Annex II of EU SCCs, the "Security" schedule of typical DPAs, and the security exhibits of MSAs.
- **Breach-notification timing extraction**: detection of all breach-notification clauses with timing terms ("without unreasonable delay," "within X hours," "within Y days," "promptly"), the trigger event (discovery, confirmation, suspicion), the recipient (controller, regulator, data subject), and the channel (email, written, designated contact).
- **Audit rights / inspection extraction**: detection of audit-rights clauses with frequency, notice period, scope, cost allocation, and whether onsite audit is permitted vs. SOC 2 substitution.
- **Subprocessor inventory and onward-transfer extraction**: detection of subprocessor list references, the form of notice required, objection rights, and the place where the actual list lives (attached, on a URL, on request).
- **Insurance amount and endorsement extraction**: from contract insurance schedules and from COIs themselves — coverage amounts per line of insurance, additional-insured endorsements by form number, carrier name, carrier AM Best rating where stated, policy number, policy period.
- **Whistleblower / DTSA notice detection**: explicit detection of 18 USC § 1833(b)(3) notice language in NDAs, employment, and contractor agreements.

Each extractor lives in `src/extract/v3/` and exposes a deterministic function returning a normalized output. Each extractor has its own test fixture set under `tests/extract/v3/`.

## 18. Role classification

Parties have legal roles that determine which rules apply. A "vendor" in an MSA may be a "processor" in the DPA and a "business associate" in the BAA, all in one transaction. v3 extracts each role separately rather than collapsing to a single label.

The classifier first looks for explicit definitional sentences ("'Processor' means..."), then for role-establishing recitals ("Controller wishes to engage Processor to..."), then for clause-level role usage ("As a Service Provider under the CCPA, Recipient shall..."). Each detected role is attached to the party with a confidence and a source span.

When two roles conflict ("Processor" defined and "Service Provider" defined for the same party), v3 records both; the report's compliance matrix shows compliance against each applicable regime.

## 19. PHI and personal-data category detection

The extractor looks for category schedules in known locations (Annex I to EU SCCs is highly structured; BAA recitals are less so) and for inline enumeration ("Personal Data includes..."). Detected categories are mapped to a controlled vocabulary that covers HIPAA's eighteen identifiers, GDPR Article 9 special categories, GDPR Article 10 (criminal convictions), CCPA "sensitive personal information," and a residual "other" bucket. Rules can then assert, for example, "if special categories are processed, the DPA must require encryption at rest by name" (GDPR Art. 32 + EDPB guidance).

## 20. Cross-border transfer language detection

The extractor scans for the canonical phrases ("Standard Contractual Clauses," "SCC Module Two," "International Data Transfer Agreement," "UK Addendum," "Adequacy Decision," "Binding Corporate Rules," "Article 49"), classifies the asserted mechanism, locates the supporting text (annex, attachment, hyperlink, recital reference), and outputs a normalized record per detected transfer. The cross-border rules in §31 then check whether the mechanism is internally consistent (e.g., if Module 2 is invoked, both parties' roles must match controller-to-processor) and whether ancillary documents are present (a TIA reference is detected separately).

## 21. Security-measures inventory extraction

The extractor recognizes both structured schedules (Annex II tables) and prose narration ("Vendor shall maintain industry-standard security measures, including..."). The output is a normalized list of measures from a controlled vocabulary (encryption-at-rest, encryption-in-transit, MFA, SSO, vulnerability-scanning, penetration-testing, security-training, BCP-DR, incident-response, access-controls-RBAC, logging-audit, network-segmentation, hardware-tokens, secure-development-lifecycle, third-party-audits-SOC2-T2, third-party-audits-ISO-27001, third-party-audits-HITRUST). Each measure can carry a cadence (annual, biennial, continuous, on-incident) and a scope (production, all systems, in-scope systems).

Rules then assert, for example, "BAA covering ePHI at rest in cloud storage should require encryption at rest meeting FIPS 140-2 (now 140-3) standards or document why not — HHS guidance does not strictly require encryption but treats unencrypted PHI as breach-presumed."

## 22. Breach-notification timing extraction

Extractor reads notification clauses and outputs a record per clause with: trigger (discovery / confirmation / suspicion / determination), addressee (controller / regulator / data-subject / law-enforcement / customer-named-contact), maximum delay (in hours / days / "without unreasonable delay" / "promptly" / "as soon as practicable"), reporting channel, and required content. Rules assert that the maximum-delay value is no later than the regulator's outer bound (60 days for BAA per 45 CFR § 164.410; 72 hours for controller-to-supervisory-authority per GDPR Art. 33; varies by state for personal-data breach in CCPA/state laws).

## 23. Audit-rights and inspection-clause detection

Detects: audit frequency, notice period, scope (production / all systems / specific exhibits), permitted methods (onsite / remote / questionnaire-only / SOC 2 substitution), cost allocation (auditee / auditor / cost-shift on findings), confidentiality, and the right to use third-party auditors. Rules per regulator: GDPR Art. 28(3)(h) requires audit; SCC Module 2 Clause 8.9 has specific text; HIPAA is less prescriptive but OCR posture expects "satisfactory assurances" which audit rights help establish.

## 24. Subprocessor inventory and onward-transfer extraction

Detects: whether subprocessors are permitted, the form of consent (general written authorization vs. specific prior consent — Art. 28(2)), the subprocessor list location (Annex, URL, on-request), notice period for additions, objection right, objection consequences (terminate-for-convenience / terminate-the-affected-services / no-right), and flow-down (whether the same or equivalent obligations apply downstream — Art. 28(4)).

## 25. Insurance amount, AM-Best rating, additional-insured endorsement extraction

For contract insurance schedules: per-line-of-coverage amounts, per-occurrence vs. aggregate, required endorsements by form number, required carrier rating, required notice of cancellation. For COIs themselves: the same fields, plus actual policy number, policy period, named insured, additional-insured language, certificate-holder block, producer block.

## 26. Whistleblower / DTSA notice detection

Detects the presence and substantive completeness of the 18 USC § 1833(b)(3) notice. Substantive completeness means the notice covers both the disclosure-to-government-or-attorney immunity (§ 1833(b)(1)) and the under-seal-court-filing exception (§ 1833(b)(2)), and that the notice covers contractors and consultants in addition to employees. Failure to include this notice means the disclosing party cannot recover exemplary damages or attorneys' fees under DTSA against the receiving party — a real loss of statutory remedies, which v3 calls out with that exact consequence.

## 27. Two-document mode

The user drops two related documents at once: an MSA and its DPA, or an MSA and its BAA, or a BAA and its subcontractor BAA. v3 runs the playbook for each, then runs `consistency_check` rules over both. Examples: the BAA's permitted-uses must be no broader than the MSA's purpose statement; the DPA's processing purpose must match the MSA's services description; the DPA's data-categories schedule must not include categories the MSA's service description does not require; the BAA's term must not survive the MSA's termination unless the BAA explicitly says so. Up to four documents in one drop.

---

# Part V — Rule catalog additions

This part is the heart of v3. Target: ~220 new rules. The catalog below sketches each rule group. Full rule JSON schemas live in `src/engine/rules/v3/` and follow v2's `Rule` interface from `src/engine/rules/_helpers.ts`.

## 28. BAA rules — ~45 rules

Required-clause checks per 45 CFR § 164.504(e)(2)(i)–(iii):

- §164.504(e)(2)(ii)(A) — permitted-uses-and-disclosures clause present and not broader than the covered entity's permitted uses.
- §164.504(e)(2)(ii)(B) — business associate may not use PHI other than as permitted or required.
- §164.504(e)(2)(ii)(C) — safeguards clause (appropriate safeguards, including those required by Security Rule).
- §164.504(e)(2)(ii)(D) — report-improper-uses-and-disclosures clause.
- §164.504(e)(2)(ii)(E) — ensure subcontractors agree to same restrictions (flow-down).
- §164.504(e)(2)(ii)(F) — make PHI available for access (164.524).
- §164.504(e)(2)(ii)(G) — make PHI available for amendment (164.526).
- §164.504(e)(2)(ii)(H) — make PHI available for accounting (164.528).
- §164.504(e)(2)(ii)(I) — internal practices, books, records available to Secretary.
- §164.504(e)(2)(ii)(J) — return or destruction at termination.
- §164.504(e)(2)(iii) — non-permissible-uses termination right for covered entity.
- §164.314(a)(2)(i) — security-rule flow-down: comply with Security Rule administrative, physical, technical safeguards.
- §164.314(a)(2)(i)(C) — report security incidents.
- §164.314(a)(2)(ii) — subcontractor flow-down for Security Rule.
- §164.410 — breach notification timing (within 60 days, without unreasonable delay).
- §164.504(e)(5) — satisfactory-assurances posture (the document is signed by an authorized representative).

Plus quality-of-text rules: breach-notification timing is no looser than 60 days; breach-notification trigger is "discovery" and not a stricter standard; "report security incidents" is not narrowed to only "Security Incidents with successful unauthorized access" (a common narrowing that OCR has criticized); return-or-destruction has a definite outer time bound (not "as soon as practicable"); the BAA does not include indemnity caps that would impair the covered entity's remedies for HIPAA violations (a HHS-frowned-upon clause); audit rights of the covered entity are preserved; the BAA does not require the covered entity to indemnify the business associate for HIPAA violations (a common vendor overreach).

Plus consistency rules (when run in two-document mode with the underlying MSA): purposes alignment, term alignment, governing law alignment, notice alignment.

## 29. DPA rules (GDPR core) — ~55 rules

Article 28(3) enumerated clauses (eight required categories): processing only on documented instructions; confidentiality of authorized persons; Article 32 security; subprocessor terms (Art. 28(2) and 28(4)); assist controller in responding to data-subject rights; assist controller with Articles 32–36 obligations; deletion or return at end of services; make information available to controller for compliance demonstration.

Plus subject-matter / duration / nature / purpose / categories-of-data / categories-of-subjects / controller-obligations details (Art. 28(3) introductory paragraph).

Plus Article 28(2) — subprocessor authorization in writing.

Plus Article 28(9) — contract in writing including electronic form.

Plus Article 32 — appropriate technical and organizational measures; specific examples: pseudonymization, encryption, confidentiality / integrity / availability / resilience, restore from incident, regular testing.

Plus Article 33 — controller breach notification (the processor's obligation under Art. 33(2) to notify controller "without undue delay").

Plus Article 30 — records of processing assistance.

Plus Article 35 — DPIA assistance.

Plus Article 27 — EU representative reference where the processor is non-EU.

Plus Article 37 — DPO reference where required.

Plus Articles 44–49 — international-transfer mechanism present and named.

Plus quality-of-text rules: instructions must be documented and any-deviation-requires-controller-instruction; "appropriate" measures are not undefined hand-waving; breach notification is "without undue delay" or stricter, and includes the content elements Art. 33(3) requires the controller to transmit onward to the regulator; deletion-or-return choice belongs to the controller, not the processor (a common vendor overreach); audit-substitution allowing SOC 2 in lieu of onsite audit is permitted but must not eliminate the right entirely.

## 30. DPA rules (US state privacy overlays) — ~25 rules

CCPA service-provider terms per § 1798.140(ag): purpose-limitation, no-sale, no-cross-context-advertising, no-combining-with-other-data, security obligation, certification-of-understanding, allow-monitoring, allow-assistance-with-consumer-requests, allow-notification-of-unauthorized-use, subcontractor flow-down.

VCDPA § 59.1-579(B): purpose-limitation, duration, type-of-data, deletion-or-return, confidentiality, audit cooperation, subcontractor flow-down.

CPA, CTDPA, UCPA, TDPSA, OCPA, DPDPA — same eight-ish elements with state-specific variations.

A rule flags when the contract claims CCPA "Service Provider" status without containing all the required elements (a real exposure — the receiving party may be reclassified as a "third party" with no purpose limitation, triggering sale / share consequences for the disclosing party).

A rule flags when the contract spans multiple states and the strictest-required element is not used.

## 31. International transfer rules — ~20 rules

SCC Module 2 specific clauses present and unaltered (Clause 1–18, with attention to Clauses 8 / 9 / 11 / 14 / 15 / 16 / 18). The SCCs forbid material modification (Clause 2). v3 detects modification and flags it.

UK Addendum filled out correctly (the Addendum is a fill-in-the-blanks attached to the EU SCCs — v3 reads its Tables 1–4).

UK IDTA standalone: the Addendum is the preferred path post-Schrems II + Brexit but the standalone IDTA is also valid; v3 supports both.

Adequacy decisions: when a contract relies on an adequacy decision (e.g., the EU-US Data Privacy Framework, the UK extension, the Japan/Korea/Switzerland/Canada PIPEDA/Israel/Argentina/New Zealand/Andorra/Uruguay/Faroe/Guernsey/Jersey/Isle of Man decisions), v3 confirms the decision is currently in force as of the DKB build date and warns if it is under litigation (the DPF is permanently under litigation as of 2026 and v3 says so).

TIA references: where SCCs are used to transfer to a non-adequate country, v3 flags absence of a transfer impact assessment reference (EDPB Recommendations 01/2020).

Onward transfer terms: Clause 8.7 / 8.8 of SCC Module 2 + Module 3.

## 32. NDA deep rules — ~25 rules

DTSA notice present and complete (§§26 extractor).

Confidentiality term reasonable (definite term or definite-on-trade-secrets-perpetual-otherwise).

Definition of Confidential Information has all four standard exclusions (independently developed, lawfully received from third party, publicly available, already known). Missing-exclusion rules flag each one.

Residuals clause present or absent — flag for the disclosing party's awareness; not inherently wrong but consequential.

Permitted-use scope narrow enough (a "to evaluate the Purpose" formulation, not a "for any business purpose" formulation).

Return-or-destruction with attestation requirement.

Injunctive-relief clause (waiver of bond, irreparable-harm acknowledgment).

Governing law selected from a list of viable jurisdictions (Delaware, New York, California, Texas, England & Wales, etc.) rather than an unusual jurisdiction without explanation.

Most-favored-nation / no-precedent clause for the receiving party.

Non-solicitation carve-outs (employees, customers) — flag if present and confirm a general-solicitation carve-out (a typical compromise).

Term-of-confidentiality vs. term-of-agreement separation.

No-license clause.

Representation about authority and absence of conflicting obligations.

Successors-and-assigns with consent.

Non-circumvention (if a brokerage scenario).

For mutual NDAs: symmetry check — every obligation imposed on one party imposed on the other.

For unilateral NDAs: receiver-only obligation check — disclosing party has no reciprocal obligation.

## 33. MSA deep rules — ~30 rules

Indemnification: scope (third-party IP infringement, breach of confidentiality, breach of data protection, gross negligence, wilful misconduct, violation of law); procedure (notice, control of defense, settlement consent, mitigation); carve-outs from cap.

Limitation of liability: per-claim and aggregate caps; carve-outs (gross negligence, fraud, IP indemnity, confidentiality breach, breach of data-protection obligations, payment obligations); supercap structure for the carve-outs; consequential-damages waiver with mutual application; California § 1668 problem flagging.

IP: background IP retention, foreground IP allocation, feedback license, residual-knowledge clause.

Warranties: services-performed-in-workmanlike-manner; conformance-with-documentation; no-malicious-code; compliance-with-laws; non-infringement; disclaimer of implied warranties (consistent with UCC and applicable state law).

SLA reference: SLA exists, is attached or linked, has remedies, has remedy as sole-and-exclusive-or-not.

Term and termination: termination-for-cause, termination-for-convenience, termination-for-bankruptcy, effects-of-termination (which obligations survive), wind-down period for SaaS.

Data return / portability on termination.

Force majeure: balanced (cuts both ways, not just for vendor).

Assignment: change-of-control language; affiliates carve-out.

Governing law and venue alignment with disclaimers (e.g., consumer protection in California).

Notices, counterparts, severability, entire agreement, amendment-in-writing, no-waiver, headings, drafting-construction (no contra proferentem because both parties had counsel), survival.

Order-of-precedence between MSA / SOW / Order Form / DPA / BAA / SLA — explicit, and the order is internally consistent with where the operative terms actually live.

AI usage clause (v3 flags absence or, if present, checks the §34 ruleset).

## 34. Vendor security addendum / subprocessor / AI addendum rules — ~20 rules

Vendor security addendum: specific measures listed; cadence stated; right-to-audit or SOC 2 substitution; incident-response notification; vulnerability-disclosure handling; secure-development-lifecycle reference; data-classification mapping; encryption standards by name (FIPS 140-3 / AES-256); pen-test cadence stated.

Subprocessor schedule: maintained URL or attached list; notice period; objection rights; flow-down stated.

AI addendum: definitions (Generative AI, Foundation Model, Output, Training Data); prohibited uses (training on customer data without opt-in, using customer confidential information as inputs to public models, retaining outputs across customer tenants); transparency (which AI features are in the service, on by default or opt-in, on-prem vs. third-party model); IP ownership of outputs; warranties and disclaimers specific to AI outputs (no fitness for legal/medical/financial advice, hallucination risk acknowledgment, human-review obligation for high-stakes outputs); data residency for AI processing; subprocessor disclosure for AI providers (OpenAI, Anthropic, Google, etc.); deletion-of-fine-tuning-data on termination.

The AI addendum ruleset is new in 2026 territory; the citations are to industry consensus (NIST AI RMF, EU AI Act high-risk categories, FTC enforcement actions) rather than to a single regulator. v3 cites these honestly as "consensus practice, not statute" where applicable.

---

# Part VI — New and revised playbooks

Each playbook is a JSON file at `src/playbooks/v3/` following v2's playbook schema with a few additions: `regulator_frame` (which regulator's lens the playbook reads through), `applicable_jurisdictions` (US, EU, UK, multi), `companion_playbooks` (suggested two-doc pairings), `compliance_matrix_columns` (the columns the report's compliance matrix will use for this playbook). Playbooks select rules from the catalog and may re-rank, gate by frame, or add playbook-specific assertions.

Brief sketches:

**35. BAA** — covered-entity → business-associate. Frame: HIPAA. Selects the §28 ruleset. Companion: MSA-Vendor-Deep.

**36. BAA-Subcontractor** — business-associate → subcontractor. Same ruleset minus covered-entity-only items, plus flow-down assertions.

**37. DPA-Controller-to-Processor (EU/UK)** — Frame: GDPR/UK GDPR. Selects §29 ruleset. Companion: MSA + SCC-Module-2 if non-EU/UK processor.

**38. DPA-Processor-to-Subprocessor** — Frame: GDPR. Same with flow-down emphasis.

**39. DPA-CCPA-Service-Provider** — Frame: CCPA/CPRA. Selects §30 ruleset.

**40. DPA-Multi-State-US** — Frame: multi-state. Computes union of state requirements; flags when document does not meet the strictest applicable.

**41. SCC-Module-Two** — verifies the official text is incorporated unmodified; checks Annexes I, II, III; flags forbidden modifications.

**42. SCC-Module-Three** — same for processor-to-processor module.

**43. UK-IDTA-Addendum** — verifies Tables 1–4 of the UK Addendum are completed; or, if standalone IDTA, verifies Tables 1–4 of the IDTA are completed and the substantive clauses unmodified.

**44. Mutual-NDA-Deep** — replaces v2's `mutual-nda`. Selects §32 ruleset.

**45. Unilateral-NDA-Deep** — replaces v2's `unilateral-nda`.

**46. MSA-Vendor-Deep** — replaces v2's `saas-vendor` and overlaps `msa-general`. Selects §33 ruleset, oriented toward catching vendor-friendly drafting (low caps, broad disclaimers, narrow indemnity, broad limitation of liability).

**47. MSA-Customer-Deep** — replaces v2's `saas-customer`. Oriented toward catching customer-unfriendly drafting (no security commitments, no SLA, broad assignment, no data return).

**48. Vendor-Security-Addendum** — selects §34 ruleset (security-only).

**49. AI-Addendum** — selects §34 ruleset (AI portion).

**50. EULA** — end-user license rules: license grant scope, prohibited uses, ownership, updates and versions, support disclaimers, telemetry disclosure, termination, EU consumer-law minimums where applicable (CRD, Sale of Goods, Digital Content Directive).

**51. SaaS-Terms-of-Service (consumer-facing)** — FTC Click-to-Cancel rule alignment, ROSCA, state auto-renewal laws, ADA accessibility statements where required, age gates where COPPA applicable, ToS dark-pattern detection (re-using v2's dark-patterns ruleset with elevated severity).

**52. Privacy-Policy-Lint** — not a contract, but a frequently-paired document. Checks alignment with CCPA § 1798.130 disclosure requirements, GDPR Articles 13/14, COPPA disclosure, state-by-state required content. Includes a "matches your asserted DPA terms" check when run paired with a DPA.

**53. COI / Certificate-of-Insurance check** — drop an ACORD 25; extract carrier, AM Best rating, coverage amounts, endorsements; lint against a customer-supplied requirements profile (or the §12 default profile).

---

# Part VII — Report changes

## 54. The compliance-matrix section

A new section near the top of the report (after the executive summary, before the findings list). One row per applicable regulator (HIPAA, GDPR, UK GDPR, CCPA, VCDPA, CPA, CTDPA, UCPA, TDPSA, OCPA, DPDPA, plus any sectoral and international hit). One column per required-clause category. Cell values: `Pass` (green) / `Partial` (yellow) / `Fail` (red) / `N/A` (grey) with a click-through page reference into the findings list. The matrix is the page a compliance officer can paste into a slide deck.

## 55. Citation depth

Every finding cites to the most specific authority. The report appendix carries the full citation table with stable URLs and the DKB version that grounded each citation. A reader can pull any finding's citation and verify it against eCFR / EUR-Lex / the state code.

## 56. Cross-border transfer summary

A new page in the report (only present when transfer language is detected) summarizing: which transfers happen (countries), under which mechanism, whether a TIA is referenced, whether supplementary measures are listed. Each row carries the contract clause reference and the regulator-citation reference.

## 57. Subprocessor inventory page

When a subprocessor list is referenced, the report includes a page that shows: the list location, the form of authorization, the notice period, the objection right, and any subprocessors actually named in the document (not enumerating the list from a URL — v3 does not fetch).

## 58. Insurance summary page

When run in COI mode, or when an MSA insurance schedule is present, a page summarizing: coverage amounts vs. typical minimums for the relevant vertical; required endorsements present / absent; carrier rating status; cancellation-notice language.

## 59. The "two-document consistency" appendix

When two or more documents are loaded together, an appendix listing every consistency-check rule that fired with its citation to both documents.

---

# Part VIII — UI

## 60. Document-type auto-detect for the new families

v2's UI auto-detects document type from header text, definitions, and structure to suggest a playbook. v3 extends this to recognize the v3 family signals: presence of "Business Associate" definitional language → BAA; presence of "Controller" and "Processor" definitional language → DPA; presence of EU SCC clause numbering → SCC document; presence of ACORD 25 layout → COI. Detection is offered as a suggested playbook the user can accept or override.

## 61. The "compliance frame" toggle

A new UI control: a chips row near the playbook selector with toggle chips for HIPAA / GDPR / UK GDPR / CCPA / state-X / sectoral-X. Toggling a frame adds (or removes) that regulator's rule set from the run. Default toggles are inferred from the playbook but always user-overridable. The default for "DPA" is GDPR + CCPA on (because most US DPAs cover both). The default for "BAA" is HIPAA on only. The default for "MSA" is all off (because most MSAs are not themselves the privacy document — but a chip in the UI hints "looking for GDPR coverage? add a DPA").

## 62. Multi-document drop

The drop zone accepts up to four files in one drop. If accepted, the UI shows a small card per document with detected type and selected playbook. A toggle invites the user to run cross-document consistency checks (default on).

## 63. New empty-state copy and error states

Updated empty-state copy mentions the new families. Updated error states cover regulator-specific failures: "this looks like a BAA but no 'Business Associate' party is defined — did you intend to load it as a generic agreement?"; "this looks like SCC Module 2 but Annex I is empty — Vaulytica cannot lint an empty annex"; "this looks like an ACORD 25 but the certificate-holder block is illegible — try a higher-resolution scan."

---

# Part IX — Build plan: 22-step Claude Code prompt sequence

These are the prompts to issue to Claude Code, in order, to build v3 on top of a completed v2. Each prompt is sized for one focused session and is written as a self-contained briefing — the agent will not have seen this conversation and must work from the prompt plus the in-repo spec. Each prompt assumes the agent will read v2's [spec.md](spec.md) before starting and will reuse v2 structure where possible. The prompts repeatedly emphasize: no AI in the running product, deterministic only, all citations grounded in the DKB, no network calls in user flow, bundle-size budget extended from v2 by no more than 600KB compressed across all of v3.

### Step 18 — v3 repo scaffolding and namespace conventions

> You are extending an existing v2 codebase. Read [spec.md](spec.md) entirely first to understand v2; then read [spec-v3.md](spec-v3.md) fully to understand what v3 adds. Do not change v2 behavior. Create the new v3 namespace skeleton: `src/extract/v3/` with placeholder modules for role-classifier, pii-category, transfer-mechanism, security-measures, breach-timing, audit-rights, subprocessor, insurance, dtsa-notice; `src/engine/rules/v3/` with subdirectories `baa/`, `dpa-gdpr/`, `dpa-us-state/`, `transfer/`, `nda-deep/`, `msa-deep/`, `addenda/`; `src/playbooks/v3/` with placeholder JSON files for each of §§35–53; `dkb/fixtures/v3/` and `dkb/build/v3/` for the new fetchers; `tests/v3/` mirroring the source layout. Each placeholder TypeScript module exports nothing and carries a JSDoc block stating what it will contain and which spec section drives it. Each placeholder playbook JSON validates against v2's playbook schema (you may need to extend the schema as §VI describes; if so, do it now and update v2 playbooks to satisfy the extended schema without behavior change). Add a top-level `V3.md` short index pointing to spec-v3.md, this build plan, and the test corpora. Update `BUILD_PROGRESS.md` with a v3 section enumerating steps 18–39 as TODO. Run `npm run typecheck && npm test && npm run build`; expect all-green because nothing functional has changed. Commit with `feat(v3): scaffold v3 namespaces and placeholders`.

### Step 19 — DKB schema extensions

> Read [spec-v3.md](spec-v3.md) §13–§14 first, plus v2's DKB schema sketch in spec.md Appendix B. Extend the DKB JSON schemas in `src/dkb/` (or wherever v2's schema lives — find it via `src/dkb` and `dkb/build`) to add node types: `regulator_model_form`, `statutory_clause_requirement`, `transfer_mechanism`, `subprocessor_requirement`, `insurance_norm`, `consistency_check`. For each new node type, define the JSON Schema with required fields, optional fields, and a versioning convention (`dkb_node_version: integer`, `dkb_node_last_validated_at: ISO-8601`, `cites: array of {authority, citation, content_hash_at_pin, source_url, fetched_at}`). Update the DKB loader at `src/dkb/loader.ts` (find the exact path) to validate the new node types. Add at least one fixture per node type at `dkb/fixtures/v3/` so the validator has something to test against. Do not write the actual rules yet — only the schema and a sample node. Write tests under `tests/v3/dkb/` that load each fixture and assert the schema accepts it; add a negative test that asserts the validator rejects a malformed node. Run `npm run typecheck && npm test`. Commit with `feat(v3): DKB schema additions for regulated agreements`.

### Step 20 — Source-pinning protocol implementation

> Read §14 of spec-v3.md. Extend the DKB build pipeline at `dkb/build/` (find the v2 fetcher framework — it is described in v2 spec.md §15) to implement source-pinning: every node with a `cites` field gets re-fetched on each weekly build, the fetched content is hashed (SHA-256 over normalized whitespace), and the hash is compared against `content_hash_at_pin`. On mismatch, the node's downstream rules are flagged stale by setting `enabled: false` on each rule node that depends on the stale source. Implement a `staleness report` artifact produced by the pipeline (one JSON file, one row per stale source, with the diff URL and human-readable summary). Surface a UI element in the marketing site footer that reads "DKB last validated: [date]. Stale citations under review: [N]." pulled from the build artifact. The build itself must fail (non-zero exit) if any stale source exists and is not explicitly acknowledged in an `dkb-staleness-ack.yml` file at the repo root. Write tests that simulate a hash drift and confirm the pipeline marks the relevant rules stale. Do not implement the actual fetchers for v3 sources yet (that is steps 21–22). Commit with `feat(v3): source-pinning protocol with staleness gate`.

### Step 21 — HIPAA and US state-privacy fetchers

> Read spec-v3.md §5, §7, §8. Implement fetchers under `dkb/build/v3/` for: eCFR Title 45 Part 164 (full XML via the eCFR versioner API); HHS sample BAA HTML; HHS OCR resolution-agreement index (just the index for now, summaries are vendored at `dkb/fixtures/v3/ocr-resolutions/`); Cal. Civ. Code §§ 1798.100–1798.199.100 (leginfo.legislature.ca.gov); CCPA implementing regulations 11 CCR §§ 7000–7304 (oag.ca.gov); Virginia, Colorado, Connecticut, Utah, Texas, Oregon, Delaware state-privacy statutes from each state's official code repository (URLs in §7). For each fetcher: implement the HTTP fetch with conditional GET (If-Modified-Since / ETag) and exponential-backoff retry; implement a parser that produces a structured `statutory_clause_requirement` set per source; implement content-hash recording; implement a regression check that runs every produced node against the schema from step 19. Write integration tests using vendored snapshot HTML/XML fixtures at `dkb/fixtures/v3/snapshots/` so the test does not hit the network. The fetchers themselves must support an offline mode for CI that replays the snapshot fixtures. Do not yet write the rules that consume these nodes (step 23). Commit with `feat(v3): HIPAA and US state-privacy DKB fetchers`.

### Step 22 — GDPR, SCC, UK IDTA, and international fetchers

> Read spec-v3.md §6, §9. Implement fetchers for: EUR-Lex GDPR (Regulation (EU) 2016/679, full XML); EUR-Lex EU SCC Implementing Decision 2021/914 with all four module annexes; UK GDPR retained-law text at legislation.gov.uk; ICO UK Addendum and UK IDTA published-template documents (vendor them under `dkb/fixtures/v3/uk-idta/`); Swiss revFADP at fedlex.admin.ch and the FDPIC Swiss Addendum (vendored); EDPB guidelines index page at edpb.europa.eu (PDF downloads vendored, light-touch parsing — citation to document, not paragraph); PIPEDA, LGPD, APPI, PIPL text from official sources (some of these are translation-fraught; for PIPL specifically, vendor a single reputable English translation from a named source and record the translation provenance in the DKB node). Same testing discipline as step 21 with snapshot fixtures. The SCC module annexes (I, II, III) must be parsed into `regulator_model_form` nodes such that each annex's required fields are individually queryable. The UK Addendum's Tables 1–4 must be parsed likewise. Write a build-pipeline test that asserts a full DKB build succeeds offline using only snapshot fixtures. Commit with `feat(v3): GDPR/SCC/UK/international DKB fetchers`.

### Step 23 — BAA ruleset and BAA playbook

> Read spec-v3.md §§5, 28, 35. The DKB fetchers from step 21 are now producing `statutory_clause_requirement` nodes for HIPAA. Implement the ~45 rules of the BAA ruleset under `src/engine/rules/v3/baa/`, following v2's rule interface (find it at `src/engine/rules/_helpers.ts`). Each rule must: cite the specific 45 CFR § 164.x subdivision; reference a DKB node ID; reuse v2 extractors where possible and call into the v3 extractor stubs (which return empty/default results for now — that's fine, just keep the imports clean). Each rule has a Vitest unit test covering at least: a contract that satisfies the rule, a contract that fails the rule, and an edge case. The fixture for "a contract that satisfies the rule" is the HHS sample BAA from step 21. The fixture for "a contract that fails the rule" is a hand-edited copy of the HHS sample with the relevant clause removed or weakened, saved under `dkb/fixtures/v3/baa-fail-cases/`. Implement the BAA playbook at `src/playbooks/v3/baa.json` selecting all rules with `regulator_frame: 'HIPAA'` and setting the report's compliance-matrix columns. Run `npm test` and ensure the BAA ruleset is green. Commit with `feat(v3): BAA ruleset (45 rules) and playbook`.

### Step 24 — DPA-GDPR ruleset and DPA-EU playbook

> Read spec-v3.md §§6, 29, 37, 41. With the EUR-Lex and EU SCC nodes from step 22 in place, implement the ~55 rules of the DPA-GDPR ruleset under `src/engine/rules/v3/dpa-gdpr/`. Cite each rule to the specific GDPR article, paragraph, subparagraph, and (where applicable) recital. Implement the DPA-Controller-to-Processor playbook at `src/playbooks/v3/dpa-controller-processor.json` and the SCC-Module-Two playbook at `src/playbooks/v3/scc-module-2.json`. The SCC playbook should perform exact-text comparison of the SCC clauses to the fixture from step 22, flagging any material modification with the offending text excerpted. Test fixtures: the EU SCC official template (passes), the EDPB-published example DPA where available (passes mostly), and three hand-edited fail-cases per major rule category. Commit with `feat(v3): DPA-GDPR ruleset and EU SCC playbook`.

### Step 25 — DPA-US-state ruleset and multi-state playbook

> Read spec-v3.md §§7, 30, 39, 40. Implement the ~25 rules of the DPA-US-state ruleset under `src/engine/rules/v3/dpa-us-state/`. Each rule is keyed to a specific state statute paragraph (e.g., `ccpa.1798.140.ag.4` for the CCPA's no-cross-context-advertising requirement). Implement the DPA-CCPA-Service-Provider playbook and the DPA-Multi-State-US playbook. The multi-state playbook computes the union of applicable states from the contract's stated jurisdictions and flags when the contract does not meet the strictest applicable requirement; flag tied requirements (multiple states require slightly different language) by surfacing both and recommending the stricter. Test fixtures: a "fits all states" reference DPA hand-built from the strictest-each requirement; six fail-cases each missing one state's requirements. Commit with `feat(v3): DPA-US-state ruleset and multi-state playbook`.

### Step 26 — Transfer-mechanism rules and UK-IDTA playbook

> Read spec-v3.md §§6, 31, 43. Implement the ~20 rules of the transfer ruleset under `src/engine/rules/v3/transfer/`. Implement the UK-IDTA-Addendum playbook and the SCC-Module-Three playbook. The UK Addendum playbook reads Tables 1–4 from the input document and asserts each table is filled out per the ICO template; flag any modification to the Addendum's mandatory clauses. The adequacy-decision rule consults a small DKB node `adequacy-decisions-status.json` (list of active adequacy decisions with their dates and litigation status as of the DKB build); flag reliance on a litigation-pending decision (DPF) with a warning, not a fail. The TIA-reference rule flags absence of TIA language when an SCC-to-non-adequate transfer is detected. Test fixtures: blank-filled UK Addendum (passes), modified UK Addendum (fails), SCC + TIA reference (passes), SCC without TIA (fails warning), DPF reliance (passes with warning). Commit with `feat(v3): transfer-mechanism rules and UK IDTA playbook`.

### Step 27 — NDA deep ruleset and NDA playbooks

> Read spec-v3.md §§10, 32, 44, 45. Implement the ~25 rules of the NDA-deep ruleset under `src/engine/rules/v3/nda-deep/`. The DTSA-notice rule (§26 extractor) must check both presence and substantive completeness; in fail-mode the rule's text in the report must explicitly state the consequence — "without this notice the disclosing party cannot recover exemplary damages or attorneys' fees under DTSA against an employee or contractor; see 18 U.S.C. § 1833(b)." Implement Mutual-NDA-Deep and Unilateral-NDA-Deep playbooks; deprecate v2's `mutual-nda` and `unilateral-nda` playbooks by renaming them to `*-legacy` and pointing the auto-detect to the new playbooks (keep the legacy ones available for one release, then remove). Update the existing v2 NDA rules to delegate to v3 where there is overlap; do not duplicate logic. Test fixtures: Common Paper mutual NDA (passes most rules), a CUAD-derived selection of real NDAs (mixed results, expected outcomes baselined), and hand-built fail-cases for each rule. Commit with `feat(v3): NDA deep ruleset and replacement playbooks`.

### Step 28 — MSA deep ruleset and MSA playbooks

> Read spec-v3.md §§11, 33, 46, 47. Implement the ~30 rules of the MSA-deep ruleset under `src/engine/rules/v3/msa-deep/`. The state-law-overlay rules (California § 1668, New York § 5-322.1, Texas anti-indemnity, and ~30 other state provisions) must consult a DKB node `state-commercial-overlays.json`; build that node as part of this step from a curated list (cite each statute). Implement MSA-Vendor-Deep and MSA-Customer-Deep playbooks; deprecate v2's `msa-general`, `saas-vendor`, `saas-customer` playbooks the same way as in step 27. The order-of-precedence rule must check that the MSA's stated precedence is internally consistent with where operative terms actually live (e.g., MSA says "MSA controls over SOW" but the indemnity sits in the SOW — flag the conflict and quote both). Test fixtures: a Common Paper Cloud Service Agreement (passes most), 15 SEC-EDGAR-sourced real MSAs (baseline expected outcomes), hand-built fail-cases. Commit with `feat(v3): MSA deep ruleset and replacement playbooks`.

### Step 29 — Vendor security, AI addendum, EULA, ToS, privacy-policy-lint, COI playbooks

> Read spec-v3.md §§34, 48–53. Implement the ~20 rules of the addenda ruleset under `src/engine/rules/v3/addenda/`. Implement the Vendor-Security-Addendum, AI-Addendum, EULA, SaaS-ToS, Privacy-Policy-Lint, and COI playbooks. The COI playbook depends on ACORD 25 layout extraction; implement an ACORD-25 specific extractor under `src/extract/v3/acord-25.ts` that recognizes the standard form fields by spatial layout (using v2's PDF text-with-position output). The AM-Best-rating check uses a DKB node `am-best-ratings.json` curated for the build (cite the source as "AM Best public ratings as of [DKB build date]"). The Privacy-Policy-Lint playbook reads a published privacy policy (a PDF, a DOCX, or pasted text) and lints against CCPA § 1798.130, GDPR Articles 13/14, COPPA; it does not assert that the privacy policy is "good," only that it contains the regulator-required disclosures. The AI-Addendum playbook cites NIST AI RMF / EU AI Act / FTC enforcement actions and is explicit in the report that "consensus practice, not statute" applies where there is no controlling regulator. Test fixtures: a clean ACORD 25 (passes), a low-rating-carrier ACORD 25 (fails AM-Best rule), several real privacy policies (baselined), a typical SaaS AI addendum (mixed). Commit with `feat(v3): addenda rulesets and six new playbooks`.

### Step 30 — v3 extractors implementation

> Read spec-v3.md §§17–26. The rule steps (23–29) called into the v3 extractor stubs in `src/extract/v3/`. Now implement each extractor fully: role-classifier, pii-category, transfer-mechanism, security-measures, breach-timing, audit-rights, subprocessor, insurance, dtsa-notice. Each extractor is a deterministic function from the v2 document tree (paragraphs, spans, definitions, headings) to a normalized output type defined in `src/extract/v3/types.ts`. The role-classifier uses definitional-sentence parsing first, then recital-pattern matching, then a small CUAD-trained classifier as fallback (the classifier weights live in DKB; classifier-output confidence is bounded such that a low-confidence classification still emits a finding but with `low_confidence: true` in the report). Each extractor has a comprehensive unit test set under `tests/v3/extract/`. Re-run the rulesets from steps 23–29 with the real extractors and re-baseline any tests that change. Bundle-size check: confirm the total v3 bundle increase (vs. v2 baseline) is under 600KB compressed; if over, identify and remove non-essential dependencies or split-code the rarely-used playbooks behind a dynamic import. Commit with `feat(v3): full v3 extractor suite and bundle-size verification`.

### Step 31 — Consistency-check engine and two-document mode

> Read spec-v3.md §§13 (`consistency_check` node), 27, 59. Implement a consistency-check engine under `src/engine/consistency/` that accepts two or more parsed documents (the v2 parsed-document type) and runs a registered set of cross-document rules. The rule registry lives at `src/engine/consistency/rules/`. Implement the initial cross-document rules called out in §27: BAA-purpose-no-broader-than-MSA, DPA-purpose-matches-MSA-services, DPA-data-categories-not-broader-than-MSA, BAA-term-matches-MSA-or-is-explicitly-extended, governing-law-alignment, notice-alignment, order-of-precedence-consistency. Each consistency rule cites both documents and quotes the conflicting text. Wire the engine into the runner at `src/engine/runner.ts`. Write tests using paired fixtures (matching pairs from the §15 corpora). Commit with `feat(v3): consistency-check engine and cross-document rules`.

### Step 32 — Report renderer changes

> Read spec-v3.md §§54–59. Extend the v2 DOCX report builder at `src/report/` to add: the compliance-matrix section (after executive summary, before findings); the cross-border transfer summary page (conditional on transfer language detection); the subprocessor inventory page (conditional); the insurance summary page (conditional or always-on for COI playbook); the two-document consistency appendix (conditional on multi-doc mode); the citation-depth verification appendix listing every citation with stable URL and DKB version. The matrix renders as a real Word table with cell shading (Pass green / Partial yellow / Fail red / N/A grey) and uses Word's accessibility properties for screen-reader compatibility. Each finding's citation is a Word hyperlink to the stable regulator URL. The footer of every page now carries: rule-set version, DKB version, result hash, "Citations as of [DKB build date]" — keep the existing v2 footer pieces and add the new line. Write Vitest tests that snapshot the produced DOCX structure (using `docx` library's JSON intermediate) and assert the new sections appear under the right playbooks. Commit with `feat(v3): report sections for compliance matrix, transfers, subprocessors, insurance, consistency`.

### Step 33 — UI: document-type auto-detect, compliance frame toggle, multi-doc drop

> Read spec-v3.md §§60–63. Extend the v2 UI at `src/ui/` to: (1) implement v3 document-type auto-detect using the role-classifier and key-phrase signals (the new detectors should layer on v2's auto-detect, not replace it); (2) add the compliance-frame toggle chip row near the playbook selector, with sensible defaults per playbook and clear ARIA labeling; (3) extend the drop zone to accept up to four files in a single drop, render a card per file, and offer cross-document consistency as a default-on checkbox; (4) update empty-state copy and error states per §63. The toggles must be keyboard-accessible and screen-reader-labeled. The two-document mode must not block the report on the slower of the two extractions — show progress per document. Run an offline Playwright run against `tests/e2e/v3/` covering: drop a BAA, see HIPAA frame default on, see BAA playbook selected; drop a DPA and an MSA together, see consistency checkbox on, see both reports plus appendix. Commit with `feat(v3): UI auto-detect, compliance frames, multi-document drop`.

### Step 34 — End-to-end golden tests

> Read spec-v3.md §15 (fixture corpora). Build the golden-output test set at `tests/golden/v3/`. For each of the new playbooks, pick three representative input documents from the corpora (one passing, one moderately failing, one badly failing), run the full pipeline, and snapshot the DOCX-as-JSON output. The snapshots become regression baselines. Any change to a rule's wording, severity, or citation must update the affected snapshots in a reviewable diff. Add a CI job that runs the full golden set on every PR. Also add a `make verify-determinism` task that runs the full set twice and asserts byte-identical outputs (including the result hash). Commit with `test(v3): golden outputs and determinism verification`.

### Step 35 — Documentation

> Read all of [spec-v3.md](spec-v3.md). Write or update: `docs/v3/overview.md` (audience, scope, what's new vs. v2); `docs/v3/adding-a-baa-rule.md`, `docs/v3/adding-a-dpa-rule.md`, `docs/v3/adding-a-playbook.md` (mirroring v2's `docs/adding-a-rule.md` and `docs/adding-a-playbook.md` but with v3-specific examples and the citation-discipline expectations); `docs/v3/regulators.md` (the full source catalog from spec-v3.md §§5–12 in a more navigable form, with the canonical URLs for citation use); `docs/v3/two-document-mode.md` (when to use it, what the consistency rules check, examples); `docs/v3/compliance-matrix.md` (how the matrix is computed, what Partial means vs. Fail, how to cite the matrix in an audit). Update the top-level `README.md` with a short "v3 adds compliance-grade rule sets for BAA, DPA, NDA, MSA, transfer mechanisms, and adjacent documents — same browser-only posture as v2." Update `CHANGELOG.md` under a new `## [v3.0.0]` heading with a complete summary. Update `LAUNCH.md` if v3 has its own launch posture (it does — see §X below; if §X does not exist yet, propose it). Commit with `docs(v3): full documentation and changelogs`.

### Step 36 — Performance and offline verification

> Read spec.md §7 (v2 performance budgets) and verify v3 holds the line. Run a Lighthouse audit on the static site with a representative DPA + MSA pair loaded; record numbers. Confirm: time-to-interactive ≤ v2 baseline + 200ms (the v3 bundle is bigger, but extractors are lazy-loaded by playbook); first-meaningful-paint unchanged; the worker(s) for the v3 extractors run off the main thread. Confirm offline behavior end-to-end: with the network panel disabled in DevTools, drop a BAA, run, download the DOCX, and inspect that zero network requests fired during the run (the v2 service worker should already enforce this; verify it does for v3 too). Add a Playwright assertion under `tests/e2e/v3/no-network.spec.ts` that any non-asset request during a run is a test failure. Commit with `perf(v3): bundle and offline verification`.

### Step 37 — Accessibility verification

> Read spec.md §8. Run axe-core against the v3 UI states: empty, single doc loaded, multi doc loaded, compliance-frame toggles open, results visible. Fix every Level A and Level AA issue. Manually verify keyboard navigation through the new chip-row toggles and the multi-doc cards. Manually verify screen-reader output for the compliance-matrix table in the produced DOCX by opening it in Word with Narrator (or rely on the `docx` library's accessibility property settings if a manual test is impractical — assert these properties are set in tests). Commit with `a11y(v3): full audit and fixes`.

### Step 38 — Threat-model update

> Read spec.md §9 (v2 threat model). v3 introduces new attack surfaces and trust assumptions worth documenting honestly: the DKB is larger and contains regulator text the user implicitly trusts; the source-pinning protocol can fail silently if the staleness gate is bypassed; the AI-addendum ruleset relies on consensus practice rather than statute, and a user who treats it as legal advice is in trouble. Update `docs/threat-model.md` with a v3 section covering: DKB integrity (the signed manifest, content hashes); the staleness gate (when it might be bypassed and the consequence); the citation surface (a malicious DKB could lie about a CFR section, so v3 ships citations with content hashes and the runtime verifies them client-side on report render — confirm or implement); the "consensus practice" disclaimer for the AI addendum; and the explicit non-promise that v3 covers every regulator in every jurisdiction (it does not — the source catalog is what it is, and unsupported regulators surface as `N/A` in the compliance matrix with a "not yet covered" note). Commit with `docs(v3): threat model expansion`.

### Step 39 — Launch checklist execution and version bump

> Read spec-v3.md Part X (test corpus expectations) and v2's launch checklist in spec.md §27. Run the full v3 launch checklist: every playbook ships green against its passing fixture; every fail-fixture produces the expected fail with the expected citation; the determinism check passes byte-identical twice; the offline check passes; the Lighthouse numbers are within budget; the accessibility audit is clean; the docs build; the changelog is current; the v3 source catalog has zero stale citations (or all stale citations explicitly acknowledged in `dkb-staleness-ack.yml`); the README's v3 line is correct; the `CHANGELOG.md` entry is dated. Bump `package.json` version to `3.0.0` and tag the release `v3.0.0`. Run a final `npm run build` and verify the deploy artifact in `dist/` is what will ship. Open a PR titled "v3.0.0 — compliance & regulated-agreement expansion" with the changelog entry as the body, link to spec-v3.md, and include a screenshot of a sample compliance matrix from the DOCX. Commit any final fixes with `chore(v3): launch checklist resolutions`.

---

# Part X — Test corpus, fixtures, golden outputs

The v3 test corpus is large enough that it needs explicit accounting. The corpus splits four ways:

**Vendored regulator-published materials**: HHS sample BAA; EU SCC official template (all four modules); UK Addendum and UK IDTA published templates; Swiss Addendum; CCPA / VCDPA / CPA / CTDPA / UCPA / TDPSA / OCPA / DPDPA statutory text snippets; key EDPB guidelines; key OCR resolution agreements (summaries). Total ~80 documents.

**Curated real-world corpus** from public sources (SEC EDGAR 8-K Item 1.01 exhibits; CUAD; public open-source projects' own legal docs): 25 BAAs, 25 DPAs, 15 MSAs, 15 NDAs, 10 EULAs, 10 ToS, 10 privacy policies, 5 COIs. Each carries provenance metadata and a baseline expected-findings JSON. New v3 builds re-run the corpus and diff against baselines; any change in findings without a corresponding rule change is a test failure.

**Hand-built fail-cases**: for each rule with > 5% expected real-world failure rate, one hand-built fixture that fails exactly that rule, derived from a passing fixture with a minimal edit. Roughly 150 hand-built fixtures.

**Two-document pairs**: 20 pairs where both documents are present and a consistency check is expected (matching real-world MSA+DPA, MSA+BAA, MSA+SOW pairings).

Golden outputs are stored as DOCX-as-JSON (the `docx` library's intermediate representation), not as binary DOCX, so diffs are reviewable. A weekly CI job re-runs the entire corpus against the latest DKB build to surface drift from regulator updates before they reach a release branch.

---

# Part XI — Roadmap, non-goals, and what v4 might be

v3 non-goals: redline generation, contract negotiation suggestions, drafting from scratch, document storage, multi-user collaboration, accounts, telemetry, AI features in the running product. All preserved from v2.

What v3 also does not do: full coverage of every jurisdiction's privacy law (Mexico, India DPDP, Australia Privacy Act amendments, Korea PIPA, Singapore PDPA, etc. are recognized but lightly ruled); litigation discovery support; e-discovery; M&A diligence data-room organization; clinical-trial-specific regulated agreements (CRO, CDA-clinical); financial-services regulated agreements beyond GLBA (e.g., FFIEC vendor management is partially in scope but full SOX § 404 vendor controls are not); government contracting clauses (FAR/DFARS); export control clauses (EAR/ITAR/OFAC); construction contract clauses; international arbitration clause depth.

v4 candidates, in priority order: redline-with-citation (the linter outputs not just findings but suggested clause text drawn from the regulator's model form, with a "this is the regulator's exact words" caveat); FAR/DFARS for the government-vendor population; export-control for software vendors; the Asia-Pacific privacy expansion (deeper PIPL, deeper PDPA Singapore, deeper Australia Privacy Act post-2024 amendments); clinical-trial agreements (the CRO/sponsor population is large and underserved); reasoning-trace export for audit defense (every finding gets a step-by-step "here is how the engine reached this conclusion" trace, on demand).

---

# Part XII — Legal disclaimers expansion

v2's footer disclaimer is preserved verbatim. v3 adds two further disclaimers, visible in the UI and printed on every page of every v3 report:

> Vaulytica's compliance findings cite regulatory authorities as of the DKB build date shown. Regulations change. Active enforcement posture, agency interpretation, and applicable case law may have shifted since the DKB build. Verify with counsel before relying on any finding for a regulatory submission, audit response, or material business decision.

> Where v3 cites a "consensus practice" rather than a controlling regulation (notably in the AI-Addendum playbook), Vaulytica is reporting industry norms, not law. Failing one of these checks is not a regulatory violation. It is an observation worth a conversation with counsel.

Both disclaimers are dry. The marketing-site voice is allowed to be witty; the report's disclaimers are not. The reader is a compliance officer who has to answer to a regulator. The product respects that.

---

# Appendix A — Mermaid diagrams (sketch)

Three diagrams to include in `docs/v3/`:

- The expanded architecture diagram: still one box (the browser), but the in-browser engine now has a "compliance frame" router that selects rule sets per regulator and a "consistency engine" that runs cross-document rules. The DKB shape is unchanged but larger.
- The compliance-matrix anatomy: how a regulator-by-clause-category matrix is computed from the per-rule findings.
- The two-document run pipeline: parallel extraction, parallel rule runs, consistency-check pass, merged report assembly.

# Appendix B — JSON-schema sketches for v3 DKB node types

To be filled out during step 19 of the build. Sketch lives in this section so the implementer has a starting point; final schemas live in `src/dkb/schemas/v3/`.

# Appendix C — Mapping table: v3 rule IDs to citations

Generated automatically during step 35 from the rule registry. Lives at `docs/v3/citation-index.md`. Every v3 rule ID maps to (regulator, citation, DKB node, stable URL). The index is the audit-defense companion to any v3 report.

# Appendix D — The real-world corpus catalog

A CSV at `tests/golden/v3/corpus.csv` with one row per fixture: filename, type, source URL or provenance, license note, expected playbook, expected-findings baseline path, last-rebaselined date. The catalog is the single source of truth for which documents v3 is tested against.

# Appendix E — Glossary

Carried forward from v2; v3 additions: Adequacy Decision, Annex II Measures, Article 28 Contract, Business Associate, Controller, Covered Entity, Data Processing Agreement, DPF (Data Privacy Framework), DPIA, EDPB, EU SCCs, FDPIC, IDTA, Joint Controller, Module 2 / Module 3, Processor, PHI, Service Provider (CCPA), Sensitive Personal Information, Sub-processor, Standard Contractual Clauses, Supplementary Measures, Swiss Addendum, TIA (Transfer Impact Assessment), UK Addendum, UK GDPR, UTSA, DTSA.
