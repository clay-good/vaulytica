# Vaulytica v4 — The legal-document linter

> **Status:** specification, not yet implemented.
> **Scope:** expand the library of supported document types from "contracts" to "all logically-operative legal documents." UI/UX unchanged. Determinism preserved. AI still excluded.
> **Cousin docs:** [`spec.md`](spec.md) (v1, 17 steps, 1.0.0), [`spec-v3.md`](spec-v3.md) (regulated agreements, BAA/DPA/MSA/NDA-deep, addenda).

---

# Part 0 — Intent

## §1. Why we're doing this

The current value proposition — "drop a contract, get a deterministic linter" — is tight enough to be defensible but narrow enough to leave most of a legal team's daily docx on the table. Bylaws, settlement agreements, stock option grants, severance agreements, demand letters, lien waivers, prenups, Form D narratives — every one of these has the same shape Vaulytica already handles well: drafter's prose, citation-grounded checklist, asymmetric counsel, deterministic rules.

v4 expands the **catalog of recognized document families** without expanding what the engine *does*. We don't open new categories that would weaken the deterministic posture (no "is this contract good?" judgments; no financial analysis; no litigation strategy; no policy advice). We add playbooks, rulesets, and DKB nodes that follow the same pattern the engine already exercises 700-tests-deep.

## §2. What v4 explicitly is and is not

**v4 is:**
- A library expansion. New playbooks select rules from the catalog plus new rule families that follow v2's interface.
- A new ingest pathway for **multiple documents at once** (folder upload, zip upload, multi-file drop). Cross-document consistency rules surface when documents reference each other (e.g., the SAFE references the stockholders' agreement; the merger agreement references its disclosure schedules; the BAA references the underlying MSA).
- A taxonomy reset: the menu of supported document families is enumerated, ordered, and cross-referenced to the legal sub-domains they serve.

**v4 is not:**
- A UI/UX change. The drop zone, theme toggle, FAQ accordions, four document states (empty / analyzing / complete / error), and the inline-SVG architecture diagram all stay. The only visible UI surface changes are (a) the tagline copy on the hero, (b) the drop zone's accepted-types affordance, and (c) the consolidated multi-document report renderer.
- A scope creep into non-legal territory. v4 does not accept invoices, receipts, financial statements, marketing copy, résumés, scientific papers, technical specs, source code, or any document where the linter cannot ground a finding in published law or a regulator-recognized practice.
- A move away from determinism. Every new rule is pure-function `(DocumentTree[], DKB version, Playbook) → Findings`. Every cross-document rule is a deterministic walk over canonical extracted facts. The multi-doc `result_hash` is `SHA-256(sorted per-document run hashes + cross-doc rule outcomes)`.

## §3. Tagline change

Today's hero copy is `Drop contracts.` — a strong, three-syllable, action-led headline. The v4 default replacement is:

> **Drop legal docs.**

Same cadence (three syllables → four), same imperative voice, same brand register. Scope is unambiguous and the legal-only framing is preserved.

Alternatives considered (carry-forward note for the marketing-site step):
- `Drop legal.` — punchiest but reads incomplete on first scan
- `Drop the paperwork.` — friendly but loses the legal specificity that is the moat
- `Drop legal work.` — broader feel, still law-only

Spec change: in `site/index.html`, replace the H1 wordmark line and any `og:title` / `twitter:title` / `og:description` mentions of "contract" with "legal document." The `JSON-LD` Organization + SoftwareApplication + TechArticle + FAQPage blocks need parallel updates. FAQ q1 ("What kinds of documents does Vaulytica check?") gets rewritten against the §6 catalog.

---

# Part I — The catalog of supported document families

## §4. The framework filter

Before adding a family to the catalog, it must pass four gates:

1. **Drafter's text.** The document is prose drafted by a lawyer (or paralegal, or template service) and read by another lawyer or a counterparty. Not a regulator's filing schema. Not a court's procedural form.
2. **Citation-grounded checklist.** There is a published authority (statute, regulation, model form, practitioner-accepted baseline) we can cite for every assertion the linter makes. No vibes-based findings.
3. **Asymmetric counsel.** The drafting side often has more legal sophistication than the receiving side. Vaulytica creates value by giving the under-resourced side a deterministic second look.
4. **Determinism is achievable.** The rule is pattern-based or extracted-fact-based, not judgment-based ("is this lease *fair*?" — no; "does this lease specify a return-of-deposit window?" — yes).

If a candidate fails any gate, it goes in §7 (excluded surfaces) with a documented reason.

## §5. The taxonomy

Documents are grouped into 16 legal sub-domains. Each sub-domain has 2–8 document families. The full catalog is enumerated in §6.

```
LEGAL DOCUMENT FAMILIES (v4)

A. Commercial agreements                  (already shipped in v1 / v3)
B. Corporate governance
C. Equity and cap-table
D. M&A and investment
E. Real estate
F. Employment and HR
G. Settlement, release, demand
H. IP and licensing
I. Privacy and data protection            (already shipped in v3, expanded)
J. Healthcare
K. Insurance and risk
L. Banking and lending
M. Construction
N. Trust, estate, family
O. Compliance policies and disclosures
P. Regulatory filings (prose portions)
```

The sub-domain taxonomy serves three purposes: (1) the playbook registry organizes its 60+ entries under this structure; (2) the marketing-site "What I check" grid groups its tiles by sub-domain; (3) the multi-document report's table of contents uses these as section headers when the user drops a heterogeneous folder.

## §6. The catalog — every supported family

Each entry below states the family, the primary regulator-anchored citation surface, the ruleset (existing or new), and the auto-classification signals the document classifier uses to route a dropped file. Families marked **v1** / **v3** ship today; families marked **v4** are new.

### A. Commercial agreements

| # | Family | Citation surface | Ruleset | Auto-classify signals |
|---|---|---|---|---|
| A.1 | **Master Services Agreement (MSA)** | v3 §33 | `MSA_DEEP_RULES` (v3) | "master services" + "fees" + "deliverables" |
| A.2 | **Statement of Work (SOW)** | UCC Art. 2 + practice baseline | `LAUNCH_RULES` `sow` | "statement of work" + "scope" + "schedule" |
| A.3 | **Mutual NDA** | trade secret + DTSA | `NDA_DEEP_RULES` (v3) | "mutual" + "Confidential Information" |
| A.4 | **Unilateral NDA** | trade secret + DTSA | `NDA_DEEP_RULES` (v3) | "Disclosing Party" without "each party" |
| A.5 | **Consulting agreement** | IRS 20-factor + IC tests | v1 `consulting-agreement` | "consultant" + "engagement" |
| A.6 | **Independent contractor agreement** | AB-5 / DOL economic realities | v1 `independent-contractor` | "independent contractor" + IC indicators |
| A.7 | **SaaS customer / vendor agreement** | UCC Art. 2 + DMCA + COPPA | v3 MSA-deep + `vendor-security-addendum` | "subscription" + "uptime" + "Customer Data" |
| A.8 | **Reseller / distribution agreement** | antitrust + state distributor laws | new playbook v4 | "distributor" / "reseller" + territory grant |
| A.9 | **Channel partner / referral agreement** | RESPA (where housing) + general antitrust | new playbook v4 | "referral fee" / "channel partner" |
| A.10 | **Manufacturing / supply agreement** | UCC § 2-306 (output / requirements) | new playbook v4 | "manufacture" + "delivery schedule" |
| A.11 | **Marketing services agreement** | FTC endorsement guides + CAN-SPAM | new playbook v4 | "marketing services" + "campaign" |

**New v4 work in A:** A.8 reseller/distribution, A.9 channel/referral, A.10 manufacturing/supply, A.11 marketing services. Each needs a playbook JSON, ~10 rules, expected defined terms, compliance-matrix columns.

### B. Corporate governance

| # | Family | Citation surface | Ruleset | Auto-classify signals |
|---|---|---|---|---|
| B.1 | **Bylaws (corporation)** | DGCL §§ 109, 141, 211–229; MBCA §§ 2.06, 7.01–7.32 | new `BYLAWS_RULES` | "bylaws" + "Board of Directors" + "stockholders" |
| B.2 | **Operating agreement (LLC)** | DE LLC Act §§ 18-201, 18-402; RULLCA | new `OP_AGREEMENT_RULES` | "operating agreement" + "Members" + "Manager" |
| B.3 | **Articles of incorporation / Certificate of formation** | DGCL § 102; MBCA § 2.02 | new `CHARTER_RULES` | "Certificate of Incorporation" / "Articles" + "registered agent" |
| B.4 | **Stockholders' agreement** | DGCL § 218 (voting trusts), § 202 (stock transfer restrictions) | new `STOCKHOLDERS_AGREEMENT_RULES` | "Stockholders Agreement" + "Drag-Along" + "Tag-Along" |
| B.5 | **Board / written consent in lieu of meeting** | DGCL § 141(f), § 228 | new `WRITTEN_CONSENT_RULES` | "Written Consent" + "in lieu of a meeting" |
| B.6 | **Audit / compensation / nominating committee charter** | NYSE / Nasdaq listing standards; Sarbanes-Oxley § 301 | new `COMMITTEE_CHARTER_RULES` | "Committee Charter" + "independent directors" |
| B.7 | **Partnership / LP agreement** | RUPA; DE LP Act (DRULPA) | new `PARTNERSHIP_RULES` | "Partnership Agreement" + "General Partner" |
| B.8 | **Nonprofit bylaws / 501(c)(3) governance** | IRC § 501(c)(3); Form 990 governance section; ABA Model Nonprofit Corp Act | new `NONPROFIT_RULES` | "501(c)(3)" + "Board of Directors" + "tax-exempt" |

### C. Equity and cap-table

| # | Family | Citation surface | Ruleset | Auto-classify signals |
|---|---|---|---|---|
| C.1 | **SAFE (Y Combinator standard)** | Y Combinator SAFE templates (post-money + pre-money) | new `SAFE_RULES` | "Simple Agreement for Future Equity" / "SAFE" |
| C.2 | **Convertible promissory note** | UCC Art. 3; usury law per state | new `CONVERTIBLE_NOTE_RULES` | "Convertible Note" + "Maturity Date" + conversion |
| C.3 | **Stock option grant notice + agreement** | IRC § 409A; ISO IRC § 422; NSO Treas. Reg. § 1.83-7 | new `OPTION_GRANT_RULES` | "Option Grant" + "Exercise Price" + "Vesting Schedule" |
| C.4 | **RSU grant agreement** | IRC § 409A; Treas. Reg. § 1.83 | new `RSU_RULES` | "Restricted Stock Unit" + "Settlement" |
| C.5 | **Restricted stock purchase agreement (RSPA)** | IRC § 83; § 83(b) election | new `RSPA_RULES` | "Restricted Stock Purchase" + "repurchase right" |
| C.6 | **83(b) election form** | Treas. Reg. § 1.83-2 | new `ELECTION_83B_RULES` | "Section 83(b)" + "election" + "30 days" |
| C.7 | **Investor rights agreement (IRA)** | NVCA model docs | new `IRA_RULES` | "Investor Rights Agreement" + "Registration Rights" |
| C.8 | **Voting agreement / proxy** | DGCL § 218; state proxy statutes | new `VOTING_AGREEMENT_RULES` | "Voting Agreement" + "irrevocable proxy" |
| C.9 | **ROFR / co-sale agreement** | DGCL § 202 | new `ROFR_RULES` | "Right of First Refusal" + "co-sale" |

### D. M&A and investment

| # | Family | Citation surface | Ruleset | Auto-classify signals |
|---|---|---|---|---|
| D.1 | **Letter of intent / term sheet** | binding-vs-nonbinding distinction (e.g., *SIGA*, *Pennzoil*) | new `LOI_TERM_SHEET_RULES` | "Letter of Intent" / "Term Sheet" + "binding"/"non-binding" |
| D.2 | **Stock purchase agreement (SPA)** | DGCL § 251 (mergers) / § 271 (asset sales) | new `SPA_RULES` | "Stock Purchase Agreement" + "Closing" |
| D.3 | **Asset purchase agreement (APA)** | UCC § 9 (security interests); state bulk-sale laws | new `APA_RULES` | "Asset Purchase Agreement" + "Purchased Assets" |
| D.4 | **Merger agreement** | DGCL §§ 251–259 (DE); state corp codes | new `MERGER_RULES` | "Plan of Merger" + "Surviving Corporation" |
| D.5 | **Disclosure schedules** | drafting baseline + sandbagging language | new `DISCLOSURE_SCHEDULE_RULES` | "Disclosure Schedule" + "Section X(y) of the Agreement" |
| D.6 | **Escrow agreement** | UCC § 8 + state escrow statutes | new `ESCROW_AGREEMENT_RULES` | "Escrow Agent" + "Escrow Account" |
| D.7 | **Transition services agreement (TSA)** | drafting baseline (overlap with v3 MSA-deep) | new `TSA_RULES` | "Transition Services" + "Service Period" |
| D.8 | **Earnout agreement** | Delaware *Lazard / Aveta* line | new `EARNOUT_RULES` | "Earnout" + "Milestone" + "Earnout Period" |
| D.9 | **Restrictive covenant agreement (M&A flavor)** | state non-compete law + FTC NCRule | new `MA_RESTRICTIVE_COVENANT_RULES` | "Restrictive Covenant" + "Goodwill" + "Acquired Business" |

### E. Real estate

| # | Family | Citation surface | Ruleset | Auto-classify signals |
|---|---|---|---|---|
| E.1 | **Commercial lease (multi-tenant)** | UCC §§ 2A; state landlord-tenant codes | v1 `lease-commercial-multitenant` | "Premises" + "Common Area" + "Rent" |
| E.2 | **Commercial lease (single-tenant net)** | state landlord-tenant codes; CAM mechanics | new `NET_LEASE_RULES` | "Triple Net" / "NNN" + "Property Taxes" |
| E.3 | **Residential lease** | URLTA; state landlord-tenant codes | v1 `lease-residential-us` | "Tenant" + "Landlord" + "Security Deposit" |
| E.4 | **Purchase and sale agreement (PSA)** | state real estate codes; Statute of Frauds | new `PSA_RULES` | "Purchase and Sale" + "Closing" + "Earnest Money" |
| E.5 | **Ground lease** | long-term ground-lease practice baseline | new `GROUND_LEASE_RULES` | "Ground Lease" + "Term" + 99 / 50 / 49 years |
| E.6 | **Easement agreement** | state recording statutes; common law easement | new `EASEMENT_RULES` | "Easement" + "Servient" / "Dominant" |
| E.7 | **CC&Rs (covenants, conditions, restrictions)** | state HOA statutes | new `CCR_RULES` | "Declaration of Covenants" + "HOA" |
| E.8 | **Estoppel certificate** | drafting baseline + state real-property law | new `ESTOPPEL_RULES` | "Estoppel Certificate" + "no default" |
| E.9 | **SNDA (subordination, non-disturbance, attornment)** | drafting baseline + lender practice | new `SNDA_RULES` | "Subordination, Non-Disturbance" + "Lender" |
| E.10 | **Assignment of lease** | state assignment law + landlord-consent | new `LEASE_ASSIGNMENT_RULES` | "Assignment of Lease" + "Assignor" / "Assignee" |

### F. Employment and HR

| # | Family | Citation surface | Ruleset | Auto-classify signals |
|---|---|---|---|---|
| F.1 | **Employment agreement (at-will)** | state at-will doctrine + EEOC | v1 `employment-at-will-us` | "at-will" + "Employee" + "Employer" |
| F.2 | **Employment agreement (executive)** | Reg S-K Item 402; § 409A; § 280G | new `EXEC_EMPLOYMENT_RULES` | "Chief Executive" / "Chief Financial" + 280G |
| F.3 | **Offer letter** | state offer-letter doctrine (e.g., MA, NY) | new `OFFER_LETTER_RULES` | "Offer Letter" + "Start Date" |
| F.4 | **Separation / severance agreement** | OWBPA (§ 626(f)); ADEA waiver; NLRB *McLaren Macomb* | new `SEPARATION_RULES` | "Separation Agreement" + "Release" |
| F.5 | **Restrictive covenant agreement (employment flavor)** | state non-compete law + FTC NCR | new `EMP_RESTRICTIVE_COVENANT_RULES` | "Non-Compete" + duration + geography |
| F.6 | **PIIA / IP assignment agreement** | state IP assignment law (e.g., CA Lab. § 2870) | new `PIIA_RULES` | "Proprietary Information and Inventions" |
| F.7 | **Equity-grant docs (employment overlay)** | overlap with C.3 + C.4 + C.5 | reuse C ruleset | (routed via C) |
| F.8 | **Performance improvement plan (PIP)** | EEOC + state employment law | new `PIP_RULES` | "Performance Improvement Plan" + 30 / 60 / 90 days |
| F.9 | **Employee handbook policies (subset)** | NLRA § 7 + EEOC + state | new `HANDBOOK_RULES` (scoped) | "Employee Handbook" + "policies" |
| F.10 | **Statement of confidentiality / NDA (employment)** | overlap with A.3 / A.4 | reuse A ruleset | (routed via A) |

### G. Settlement, release, demand

| # | Family | Citation surface | Ruleset | Auto-classify signals |
|---|---|---|---|---|
| G.1 | **Mutual release / general release** | state release law (e.g., CA § 1542) | new `RELEASE_RULES` | "Mutual Release" / "general release" |
| G.2 | **Confidential settlement agreement** | NLRA + SEC Rule 21F-17 + state | new `SETTLEMENT_RULES` | "Settlement Agreement" + "Confidentiality" |
| G.3 | **Demand letter** | FDCPA (debt); CA Lab. § 226 (wage); Reg P; PAGA pre-suit | new `DEMAND_LETTER_RULES` | "Demand" + "respond within X days" |
| G.4 | **Cease-and-desist letter** | Lanham Act § 43; UDAAP | new `CEASE_DESIST_RULES` | "Cease and Desist" + "infringement" |
| G.5 | **Tolling agreement** | state limitations statutes | new `TOLLING_RULES` | "Tolling Agreement" + "statute of limitations" |
| G.6 | **Litigation hold notice** | FRCP 37(e); *Zubulake* | new `LIT_HOLD_RULES` | "Litigation Hold" / "Preservation Notice" |

### H. IP and licensing

| # | Family | Citation surface | Ruleset | Auto-classify signals |
|---|---|---|---|---|
| H.1 | **IP assignment agreement** | 35 U.S.C. § 261 (patent); 17 U.S.C. § 204 (copyright) | new `IP_ASSIGNMENT_RULES` | "Assignment of Intellectual Property" |
| H.2 | **Patent license agreement** | 35 U.S.C. + antitrust (FRAND, *Brulotte*) | new `PATENT_LICENSE_RULES` | "Patent License" + "Licensed Patents" |
| H.3 | **Trademark license agreement** | Lanham Act §§ 5, 32, 45; quality control | new `TM_LICENSE_RULES` | "Trademark License" + "quality control" |
| H.4 | **Copyright license agreement** | 17 U.S.C. § 201 (work-for-hire) | new `COPYRIGHT_LICENSE_RULES` | "Copyright License" + "exclusive" / "non-exclusive" |
| H.5 | **Software license (EULA)** | already shipped in v3 §50 | v3 `eula` | (routed) |
| H.6 | **Open-source contributor license agreement (CLA)** | OSI guidance; CC-attribution; DCO | new `CLA_RULES` | "Contributor License Agreement" + "Contributor" |
| H.7 | **Open-source compliance audit document** | GPL / AGPL / MIT / Apache 2 / BSD obligations | new `OSS_COMPLIANCE_RULES` | "third-party software" + license enumeration |
| H.8 | **Work-for-hire agreement** | 17 U.S.C. § 101 (specially commissioned categories) | new `WFH_RULES` | "Work Made for Hire" + § 101 |

### I. Privacy and data protection (extended)

| # | Family | Citation surface | Ruleset | Auto-classify signals |
|---|---|---|---|---|
| I.1 | **BAA / Business Associate Agreement** | already shipped v3 §28 | v3 `BAA_RULES` | (routed) |
| I.2 | **DPA / Data Processing Agreement (controller→processor)** | already shipped v3 §29 | v3 `DPA_GDPR_RULES` | (routed) |
| I.3 | **DPA — CCPA service provider** | already shipped v3 §30 | v3 `DPA_US_STATE_RULES` | (routed) |
| I.4 | **EU SCC (Module 2/3)** | already shipped v3 §31 | v3 `TRANSFER_RULES` | (routed) |
| I.5 | **UK IDTA / UK Addendum** | already shipped v3 §31 | v3 `TRANSFER_RULES` | (routed) |
| I.6 | **Privacy policy** | already shipped v3 §52 | v3 `ADDENDA_RULES` (`privacy-policy-lint`) | (routed) |
| I.7 | **Cookie / tracking notice** | GDPR Art. 7 + ePrivacy + CCPA opt-out | new `COOKIE_NOTICE_RULES` | "Cookie Notice" + "consent" + "tracking" |
| I.8 | **HIPAA Notice of Privacy Practices (NPP)** | 45 C.F.R. § 164.520 (prescribed content) | new `NPP_RULES` | "Notice of Privacy Practices" + "Protected Health" |
| I.9 | **Records of processing activities (Art. 30 ROPA)** | GDPR Art. 30 | new `ROPA_RULES` | "Records of Processing" + "Article 30" |
| I.10 | **DPIA / Data Protection Impact Assessment** | GDPR Art. 35 | new `DPIA_RULES` | "DPIA" / "Data Protection Impact Assessment" |
| I.11 | **Vendor security questionnaire (SIG / CAIQ-style)** | NIST CSF + ISO 27001 + practitioner | new `VENDOR_QUESTIONNAIRE_RULES` | "Vendor Security Questionnaire" / "SIG" / "CAIQ" |
| I.12 | **Data-incident notification template** | state breach laws + GDPR Art. 33 / 34 | new `INCIDENT_NOTIFICATION_RULES` | "Notification of Data Breach" + state thresholds |

### J. Healthcare

| # | Family | Citation surface | Ruleset | Auto-classify signals |
|---|---|---|---|---|
| J.1 | **HIPAA NPP** | I.8 | (routed) | — |
| J.2 | **BAA** | I.1 | (routed) | — |
| J.3 | **Informed consent (research / clinical, prose elements only)** | 45 C.F.R. § 46.116 (Common Rule); FDA 21 C.F.R. § 50 | new `INFORMED_CONSENT_RULES` | "Informed Consent" + "voluntary" + "withdraw" |
| J.4 | **Patient authorization for release of PHI** | 45 C.F.R. § 164.508 | new `PHI_AUTHORIZATION_RULES` | "Authorization for Release" + "PHI" |
| J.5 | **Notice of Privacy Practices acknowledgment** | 45 C.F.R. § 164.520(c)(2)(ii) | new `NPP_ACK_RULES` | "Acknowledgment" + "NPP" |

### K. Insurance and risk

| # | Family | Citation surface | Ruleset | Auto-classify signals |
|---|---|---|---|---|
| K.1 | **Certificate of Insurance (ACORD 25)** | already shipped v3 §53 | v3 `coi` | (routed) |
| K.2 | **Insurance policy summary (Declarations page review)** | state insurance codes | new `POLICY_SUMMARY_RULES` | "Declarations" + "Named Insured" + "Policy Period" |
| K.3 | **Insurance endorsement review** | ISO / AAIS forms + state filings | new `ENDORSEMENT_RULES` | "Endorsement" + "Form Number" |
| K.4 | **Indemnification agreement (standalone)** | state anti-indemnity (NY § 5-322.1, CA § 1668, TX § 151) | new `INDEMNIFICATION_AGREEMENT_RULES` | "Indemnification Agreement" + "indemnitor" |
| K.5 | **Hold harmless agreement** | state hold-harmless law | new `HOLD_HARMLESS_RULES` | "Hold Harmless" + (typically standalone) |

### L. Banking and lending

| # | Family | Citation surface | Ruleset | Auto-classify signals |
|---|---|---|---|---|
| L.1 | **Promissory note** | UCC Art. 3; state usury caps | new `PROMISSORY_NOTE_RULES` | "Promissory Note" + "Maker" + "Payee" |
| L.2 | **Loan agreement** | UCC Art. 9; Reg Z (consumer); state usury | new `LOAN_AGREEMENT_RULES` | "Loan Agreement" + "Borrower" + "Lender" |
| L.3 | **Security agreement** | UCC § 9-203 (attachment); § 9-108 (description) | new `SECURITY_AGREEMENT_RULES` | "Security Agreement" + "Collateral" |
| L.4 | **Guaranty** | state suretyship law; statute of frauds | new `GUARANTY_RULES` | "Guaranty" + "Guarantor" |
| L.5 | **Intercreditor agreement** | UCC Art. 9 + practice baseline | new `INTERCREDITOR_RULES` | "Intercreditor Agreement" + "Senior" / "Junior" |
| L.6 | **Subordination agreement** | UCC § 9-339 | new `SUBORDINATION_RULES` | "Subordination Agreement" + "Subordinated Debt" |
| L.7 | **Deed of trust / mortgage** | state real-property law | new `DEED_OF_TRUST_RULES` | "Deed of Trust" / "Mortgage" + "Trustee" |
| L.8 | **UCC-1 financing statement (prose components)** | UCC § 9-502 | new `UCC1_RULES` | "Financing Statement" + "Debtor" + "Secured Party" |

### M. Construction

| # | Family | Citation surface | Ruleset | Auto-classify signals |
|---|---|---|---|---|
| M.1 | **Construction contract (AIA-style)** | AIA A101 / A201 baseline + state lien law | new `CONSTRUCTION_CONTRACT_RULES` | "Owner" + "Contractor" + "Scope of Work" + "AIA" |
| M.2 | **Subcontractor agreement** | state lien law + flow-down | new `SUBCONTRACTOR_RULES` | "Subcontractor" + "General Contractor" |
| M.3 | **Lien waiver (conditional / unconditional, progress / final)** | state lien-waiver forms (e.g., CA Civ. Code § 8132–8138) | new `LIEN_WAIVER_RULES` | "Lien Waiver" + "Conditional" / "Unconditional" |
| M.4 | **Payment bond / performance bond** | Miller Act (federal) + state Little Miller Acts | new `BOND_RULES` | "Payment Bond" / "Performance Bond" + "Surety" |
| M.5 | **Change order** | AIA G701 + state construction-law baseline | new `CHANGE_ORDER_RULES` | "Change Order" + "Original Contract Sum" |

### N. Trust, estate, family

> **Caveat:** Vaulytica lints the text. Execution formalities (witness, notary, holographic state-specific requirements) cannot be verified from a docx alone and the report must say so explicitly on every output in this sub-domain.

| # | Family | Citation surface | Ruleset | Auto-classify signals |
|---|---|---|---|---|
| N.1 | **Last will and testament (text-only lint)** | UPC §§ 2-501–509; state will codes | new `WILL_RULES` | "Last Will and Testament" + "Testator" |
| N.2 | **Revocable living trust** | UTC; state trust codes | new `REVOCABLE_TRUST_RULES` | "Revocable Living Trust" + "Settlor" / "Grantor" |
| N.3 | **Advance directive / living will** | state advance-directive statutes | new `ADVANCE_DIRECTIVE_RULES` | "Advance Directive" + "Living Will" |
| N.4 | **Healthcare proxy / POA for healthcare** | state healthcare POA statutes | new `HEALTHCARE_POA_RULES` | "Healthcare Proxy" + "Agent" |
| N.5 | **Durable power of attorney (financial)** | UPOAA; state POA statutes | new `DURABLE_POA_RULES` | "Power of Attorney" + "Durable" + "Principal" |
| N.6 | **Prenuptial agreement** | UPAA / UPMAA + state | new `PRENUP_RULES` | "Prenuptial Agreement" + "Marriage" + "Premarital" |
| N.7 | **Postnuptial agreement** | state postnup law (varies sharply) | new `POSTNUP_RULES` | "Postnuptial Agreement" + "during the marriage" |
| N.8 | **Separation / marital settlement agreement (MSA — family-law sense)** | state divorce codes | new `FAMILY_MSA_RULES` | "Marital Settlement" / "Separation" + parenting / spousal |

### O. Compliance policies and disclosures

| # | Family | Citation surface | Ruleset | Auto-classify signals |
|---|---|---|---|---|
| O.1 | **Code of business conduct / Code of ethics** | NYSE 303A; Nasdaq 5610; SOX § 406 | new `CODE_OF_CONDUCT_RULES` | "Code of Conduct" / "Code of Ethics" |
| O.2 | **Anti-bribery / anti-corruption policy (FCPA / UKBA)** | FCPA (15 U.S.C. §§ 78dd-1 to -3); UKBA 2010 | new `FCPA_RULES` | "Anti-Bribery" + "FCPA" / "UK Bribery Act" |
| O.3 | **Anti-money-laundering policy** | BSA + OFAC + state | new `AML_RULES` | "AML" / "Anti-Money-Laundering" + "OFAC" |
| O.4 | **Insider trading policy** | Rule 10b-5 + Rule 10b5-1 plans | new `INSIDER_TRADING_RULES` | "Insider Trading" + "Material Non-Public" |
| O.5 | **Whistleblower policy** | Dodd-Frank § 922 + SOX § 806 + state | new `WHISTLEBLOWER_RULES` | "Whistleblower" + "retaliation" |
| O.6 | **Document retention policy** | SEC + IRS + state + e-discovery (Sedona) | new `DOC_RETENTION_RULES` | "Document Retention" + retention schedule |
| O.7 | **Conflict of interest policy** | IRS Form 990 governance + state nonprofit | new `COI_POLICY_RULES` | "Conflict of Interest" + "disclosure" |
| O.8 | **AI acceptable use policy (internal)** | NIST AI RMF + EU AI Act + FTC | new `AI_AUP_RULES` | "AI Use Policy" + "Generative AI" + "Acceptable Use" |
| O.9 | **Social media / external communications policy** | NLRA § 7 + SEC + FTC endorsement guides | new `SOCIAL_MEDIA_POLICY_RULES` | "Social Media Policy" + "protected concerted" |
| O.10 | **Records of lobbying / political contribution policy** | LDA + state lobbying statutes | new `LOBBYING_POLICY_RULES` | "Lobbying" / "Political Contribution" |

### P. Regulatory filings (prose portions only)

> **Caveat:** v4 lints only the **drafter's prose** in these filings — narrative risk factors, MD&A, plain-English disclosures. It does not opine on financial statements, numbers, or filing schemas. The report must say so explicitly on every output in this sub-domain.

| # | Family | Citation surface | Ruleset | Auto-classify signals |
|---|---|---|---|---|
| P.1 | **Form D narrative (Reg D)** | Reg D Rules 504/506; Form D General Instructions | new `FORM_D_RULES` | "Form D" + "Regulation D" + "exempt offering" |
| P.2 | **Form ADV brochure (Part 2A)** | Rule 204-3; Form ADV Glossary | new `FORM_ADV_RULES` | "Form ADV" + "Investment Adviser" |
| P.3 | **S-1 risk factors (prose only)** | Reg S-K Item 105; SEC plain-English rule | new `RISK_FACTORS_RULES` | "Risk Factors" + "we may not be able to" + S-1 stylings |
| P.4 | **10-K risk factors (prose only)** | Reg S-K Item 105 | reuse P.3 ruleset | "Annual Report on Form 10-K" + Risk Factors |
| P.5 | **Private placement memorandum (PPM) narrative** | Reg D + state blue-sky | new `PPM_RULES` | "Private Placement Memorandum" + "Subscription" |
| P.6 | **Reg A+ offering circular (prose)** | Reg A Tier 1/2; Form 1-A | new `REG_A_RULES` | "Regulation A" + "Tier 1" / "Tier 2" + "Offering Circular" |

## §7. Excluded surfaces (and why)

Documenting the *no* list is as important as the *yes* list — it prevents scope creep and gives the marketing page a defensible "what I do not do."

| Excluded surface | Reason |
|---|---|
| Invoices, receipts, financial statements | Numbers, not text; auditor's job, not linter's |
| Marketing copy, ad creative | Not legal-operative; no citation surface |
| Résumés, cover letters | Not legal-operative |
| Patents (claim drafting) | Examiner audience, different culture, malpractice exposure |
| Pleadings, motions, briefs | Court audience, judges hate generated content, ABA Model Rule 1.1 + 8.4 risk |
| Source code, technical specs | Not legal-operative |
| Scientific papers, technical reports | Not legal-operative |
| Trial exhibits, deposition transcripts | Not drafter's prose; not the surface |
| Bankruptcy schedules (numeric) | Schedules are forms not prose; the plan / disclosure statement is in scope |
| Federal tax returns | Numbers + IRS form schemas, not legal-operative prose |
| Immigration petitions (USCIS form schemas) | Form schema, not drafter's prose. Note: support letters in support of petitions **are** in scope under F.10 if the user wants to lint a sponsor's prose — that's drafter's text. |
| Will execution (witness / notary verification) | Cannot be verified from text alone — report must say so on every will output |
| Criminal-defense litigation work product | Wrong audience; high malpractice exposure |
| Government contracts (full FAR / DFARS depth) | Out-of-scope per spec-v3.md §35 (recognized but lightly ruled) |
| Export-control compliance certifications (EAR / ITAR / OFAC schemas) | Form-schema-driven; out-of-scope per spec-v3.md §35 |
| Construction-disputes adjudication submissions | Litigation work product |

---

# Part II — Multi-document ingest

## §8. Folder upload, zip upload, multi-file drop

The drop zone gains three new ingest modes, all behind the same single visible affordance (no UI surface change):

1. **Folder drop / folder picker.** `<input type="file" webkitdirectory>` paired with the drag-and-drop `DataTransferItem.webkitGetAsEntry()` recursive walk. Accepts any tree of `.docx` / `.pdf` files.
2. **Zip drop.** `.zip` archives are unpacked client-side via a wasm-light unzip path (target: `fflate` or equivalent — same constraint as the existing ingest stack, must run offline, must work behind the strict CSP). All contents must be `.docx` / `.pdf` (any other extension is rejected with the existing "open in Word and save as .docx" message family).
3. **Multi-file drop.** Drag-and-drop already passes `DataTransfer.files: FileList`; today we read `files[0]`. The change is to enumerate every entry and ingest each through the existing `ingestPdfBuffer` / `ingestDocxBuffer` paths.

Acceptance rules:

- Per-file cap: 50 MB (unchanged from v1).
- Per-bundle cap: 200 MB uncompressed; 50 files.
- Bundles larger than the cap fail with the spec-mandated copy: "Vaulytica analyzes up to 50 files / 200 MB at once. Split your bundle or upload fewer files."
- All ingest runs in the browser. No server. The privacy story (§9 of spec.md) is unchanged. The Playwright cross-origin assertion (§14 of spec.md) extends to the multi-doc path.

## §9. The document classifier (auto-routing)

For each ingested document, the engine routes to the correct playbook via the existing `matchPlaybook` matcher extended with a two-stage scoring pass:

1. **Sub-domain stage.** Score each of the 16 sub-domains (§5) using sub-domain title-keyword and distinguishing-phrase tables. Pick the highest. The DKB ships these tables under `dkb/v4/sub-domain-features.json`.
2. **Family stage.** Within the chosen sub-domain, score each family using the playbook's existing `match_features` table.

If the top sub-domain confidence is below 0.5, the document falls back to v1's `generic-fallback` playbook (structural + financial + temporal + dark-pattern rules only). If sub-domain is confident but no family matches above 0.5, the sub-domain has a `*-generic` playbook that runs only the sub-domain's shared rules.

Per-document classifier output is included in the per-document report: `Detected as: Corporate governance → Bylaws (confidence 0.83). Alternatives: Operating Agreement (0.21).`

## §10. Cross-document consistency rules

When multiple documents are processed in one run, an additional **consistency engine** runs over the canonical extracted facts (parties, jurisdictions, defined terms, dates, dollar amounts, named documents). v3 already stubbed this in §59; v4 ships it.

Initial cross-doc rule families:

| Rule family | Trigger | Example finding |
|---|---|---|
| **CROSS-PARTY** | Two documents reference the same party by inconsistent legal name | "*Acme Corp.* in the MSA vs. *Acme, Inc.* in the BAA — confirm same entity" |
| **CROSS-JURIS** | Two documents that operate together carry different governing-law clauses | "MSA: New York. SOW: Delaware. Order-of-precedence is silent — flag" |
| **CROSS-DEFTERM** | A defined term carries different definitions across documents | "*Customer Data* defined narrowly in the MSA but broadly in the DPA" |
| **CROSS-DATE** | A referenced effective date in one doc post-dates the referencing doc's date | "BAA effective 2026-06-01 but referenced in MSA effective 2026-01-01" |
| **CROSS-AMOUNT** | A cap referenced in one doc is inconsistent with the cap in another | "MSA cap = 12 months fees. SOW cap = $50,000. Inconsistency" |
| **CROSS-MISSING** | A required companion doc is referenced but absent from the bundle | "MSA references *DPA attached as Schedule B* but no DPA in bundle" |
| **CROSS-PRECEDENCE** | Order-of-precedence is stated in one doc but contradicted by another | "MSA says MSA controls. SOW says SOW controls. Pick one" |

Each consistency rule cites either a DKB consistency-check node (v3 schema, `node_type: "consistency_check"`) or a practitioner-baseline citation. The rule signature is:

```ts
type CrossDocRule = {
  id: string;                    // e.g., "CROSS-PARTY-001"
  version: string;
  name: string;
  description: string;
  applies_to_doc_pairs: Array<[string, string]>; // e.g., [["msa-deep", "dpa-controller-processor"]]
  // or "*" for any pair within a sub-domain
  check(runs: EngineRun[], extracted: ExtractedData[]): Finding[];
};
```

Cross-doc findings appear in their own report section (per v3 §59 — "two-document consistency appendix"). When 3+ documents are present, the appendix becomes the **transaction summary** with a matrix of which docs the consistency check covered.

## §11. The consolidated report

When multiple documents are processed, the user receives:

1. **Per-document DOCX** (one per file, as today). All deterministic. Each file's report is locally complete.
2. **Consolidated bundle DOCX**, structure:
   - Cover: bundle fingerprint (sorted SHA-256 of file hashes), engine version, DKB version, ISO date.
   - Bundle executive summary: severity counts aggregated across all docs.
   - Per-document subsection: name, detected family, top findings (capped at top 10 per doc).
   - **Cross-document consistency appendix**: every CROSS-* finding from §10.
   - Citation bibliography: deduplicated across all docs.
   - Audit trail: engine, DKB, playbook matches, every rule executed across every doc, with elapsed times.
   - The standard v1 §22 determinism / privacy / non-advice disclaimer block.
3. **Per-document JSON** (one per file) **plus a bundle JSON** (`{ runs: EngineRun[], cross_doc_findings: Finding[], bundle_fingerprint: string }`) — for tooling downstream.

Downloads use the existing pattern (object URL + hidden anchor) wrapped in a zip when more than one artifact is offered. The zip path uses the same `fflate`-equivalent dep introduced for zip ingest in §8 — one library, two paths.

---

# Part III — DKB additions

## §12. New DKB node types

The v3 DKB schema (`src/dkb/v3/types.ts`) is reused. v4 adds five domain-specific node types to support the new families:

| Node type | Purpose | Anchor example |
|---|---|---|
| `corp_governance_form` | Bylaw / charter / committee-charter model clause sets | DGCL §§ 102, 109, 141, 211 model clauses |
| `equity_grant_form` | NVCA model SAFE, option, RSU, IRA templates | NVCA model docs latest |
| `statute_of_frauds_overlay` | State-by-state SOF requirements (real estate, > 1-yr) | UCC § 2-201; CA Civ. § 1624 |
| `usury_cap_table` | Per-state max-interest tables (consumer / commercial) | State usury statutes |
| `state_release_overlay` | State-specific release rules (CA § 1542, NY GOL § 5-1502) | Cal. Civ. Code § 1542 |

Each node carries the v3 envelope (`dkb_node_version`, `dkb_node_last_validated_at`, `cites: PinnedCitation[]`) and runs through the existing staleness gate (v3 Step 20).

## §13. New fetchers

Eight new sources, each registered in `dkb/build/v3/fetchers/` following the existing pattern (rate-limited HTTP, content-addressed cache, SHA-256-pinned at fetch time, snapshot fallback):

| Source | Fetched | Surface |
|---|---|---|
| NVCA model legal documents | `nvca.org/resources/model-legal-documents` | C.* equity, D.* M&A |
| DGCL (Delaware Code Title 8) | `delcode.delaware.gov/title8` | B.*, D.* |
| MBCA (ABA Model Business Corporation Act) | (vendored excerpts) | B.* |
| UCC Articles 2, 3, 9 (Cornell LII) | `law.cornell.edu/ucc` | A.*, L.* |
| AIA contract documents catalog | `aiacontracts.com` | M.* |
| FRCP / FRE (Cornell LII) | `law.cornell.edu/rules` | G.* |
| State landlord-tenant statutes (top 10 states) | (per-state .gov URLs) | E.* |
| State trust + will codes (UPC / UTC adopters) | UPC + UTC + state codes | N.* |

The Step-20 staleness gate already covers these because every cite gets pinned at fetch time.

## §14. Bibliography expansion

The v4 launch DKB ships pinned citations for every new ruleset. The bibliography limit per spec.md §22 ("first-reference numbering, dedup, document-order") is preserved.

---

# Part IV — Determinism and reproducibility

## §15. Determinism contract

Single-document determinism is unchanged: `EngineRun = f(DocumentTree, DKB version, Playbook, Engine version)`.

**Multi-document determinism contract:**

```
BundleRun = f(
  [DocumentTree₁, DocumentTree₂, ...],   sorted by SHA-256 of file bytes
  DKB version,
  Playbook[],                            one per doc, deterministically chosen
  CrossDocRules[],                       lexicographic by id
  Engine version,
)
```

The bundle's `result_hash`:

```
bundle_result_hash = sha256(
  stableStringify({
    per_doc_hashes: sorted([run₁.result_hash, run₂.result_hash, ...]),
    cross_doc_findings: sorted by (severity, rule_id, doc_pair),
    cross_doc_rules_executed: sorted by id with fired/silent + elapsed blanked,
    dkb_version,
    engine_version,
  })
)
```

`executed_at` and per-run `elapsed_ms` are blanked, per v1's existing pattern (`computeResultHash` in `src/engine/runner.ts`). The cross-doc-rules elapsed times are blanked the same way.

## §16. Test corpus expansion

The v1 §27 corpus target was 10 real contracts. v4 expands to:
- **2–4 fixtures per new family** (synthetic, deterministic, generated by `tests/fixtures/build-fixtures.ts`).
- **5+ multi-doc bundles** exercising every cross-doc rule (e.g., MSA + DPA + BAA, merger agreement + disclosure schedules + escrow, lease + SNDA + estoppel, will + revocable trust + advance directive).
- **Golden outputs** for every fixture; goldens enforce `result_hash` stability across machine and OS (the CI test-matrix from spec.md §27 row (c) already runs on Ubuntu / macOS / Windows).

## §17. Performance budget

The v3 budget is bundle compressed ≤ v2 + 600 KB. v4's incremental budget is:
- v4 main pipeline chunk: ≤ +300 KB compressed (v3 currently ~98 KB compressed for the pipeline).
- v4 DKB: ≤ +5 MB at the manifest level. Most growth is statute text in the new fetchers (M.*, L.*, N.*).
- Multi-doc analysis: a 10-document bundle must finish in ≤ 60 s on the spec.md §17 4G mobile profile.

The dynamic-import pattern from v3 Step 14 follow-up ("vendor chunk splitting") is preserved — pdfjs / mammoth / docx / decimal / zod / tesseract remain isolated. New v4 rules cluster in a `vendor-v4-rules` chunk that loads only when a v4-family doc is detected.

---

# Part V — UI/UX — what stays the same

## §18. Hard constraints

Per the user's explicit ask, the UI/UX is fixed. The only visible changes:

1. **Tagline copy** (§3). H1 wordmark and meta tags update.
2. **Drop zone accepted-types affordance.** The microcopy on the drop zone surface shifts from "PDF or DOCX, up to 50 MB" to "PDF, DOCX, folder, or zip. Up to 50 files / 200 MB." No new UI elements; only the existing label string changes.
3. **"What I check" grid.** Tile titles update to reflect the new family list. Tile count grows from 12 to 16 (one per sub-domain). Tile *style* unchanged.
4. **FAQ.** Q1 ("What kinds of documents does Vaulytica check?") rewrites against §6 catalog. The 10-question structure stays.
5. **Footer.** No change. The `dkb-validation` element stays. The "Works offline" badge stays.

What does NOT change:
- The four document states (empty / analyzing / complete / error).
- The drag-drop visual.
- The progress bar.
- The rule ticker.
- The theme toggle.
- The accordion behavior.
- The architecture diagram (inline SVG).
- The mint accent, the typeface, the layout grid.
- The PWA install path, manifest, icons.
- The CSP, the headers, the offline behavior.

If a v4 step appears to require a new UI surface, the surface must be either (a) reusing an existing one or (b) cut from scope and revisited in v5.

---

# Part VI — Build plan

Each step is a single prompt-sized unit of work, mirroring v1's `BUILD_PROGRESS.md` pattern. Verification gate for every step: `npm run typecheck && lint && test && build` green.

| # | Step | Output |
|---|------|--------|
| 40 | v4 repo scaffolding + tagline change | `src/extract/v4/`, `src/engine/rules/v4/<sub-domain>/`, `src/playbooks/v4/`. Site H1 + meta tags updated to "Drop legal docs." Tile count 12 → 16. FAQ Q1 rewritten. |
| 41 | Multi-document ingest (folder + zip + multi-file) | `src/ingest/multi.ts` enumerates files; folder picker + `webkitGetAsEntry`. Zip path adds `fflate` (or equivalent — one new dep, audited). Per-bundle cap enforcement. |
| 42 | Document classifier (two-stage) | `src/extract/v4/classifier.ts`. Sub-domain stage scores 16; family stage scores within. `dkb/v4/sub-domain-features.json` ships. Falls back to `generic-fallback`. |
| 43 | Consistency engine | `src/engine/consistency/`. CROSS-PARTY / CROSS-JURIS / CROSS-DEFTERM / CROSS-DATE / CROSS-AMOUNT / CROSS-MISSING / CROSS-PRECEDENCE families. Determinism preserved. |
| 44 | Consolidated bundle report renderer | `src/report/bundle.ts`. Cover, exec summary, per-doc subsections, cross-doc appendix, bibliography, audit trail. Zip output via `fflate`. |
| 45 | Sub-domain B (Corporate governance) ruleset + playbooks | B.1–B.8 playbooks + `BYLAWS_RULES`, `OP_AGREEMENT_RULES`, `CHARTER_RULES`, `STOCKHOLDERS_AGREEMENT_RULES`, `WRITTEN_CONSENT_RULES`, `COMMITTEE_CHARTER_RULES`, `PARTNERSHIP_RULES`, `NONPROFIT_RULES`. Target ~80 rules across the 8 families. |
| 46 | Sub-domain C (Equity / cap-table) ruleset + playbooks | C.1–C.9 + ~70 rules. NVCA + IRS § 409A / § 422 / § 83 anchors. |
| 47 | Sub-domain D (M&A) ruleset + playbooks | D.1–D.9 + ~80 rules. NVCA + DGCL § 251 anchors. |
| 48 | Sub-domain E (Real estate, expanded) ruleset + playbooks | E.2 net lease + E.4 PSA + E.5–E.10 + ~60 rules. URLTA + state landlord-tenant anchors. |
| 49 | Sub-domain F (Employment, expanded) ruleset + playbooks | F.2–F.6, F.8–F.9 + ~50 rules. OWBPA + § 409A + § 280G + state non-compete anchors. |
| 50 | Sub-domain G (Settlement, release, demand) ruleset + playbooks | G.1–G.6 + ~30 rules. CA § 1542 + FRCP 37(e) anchors. |
| 51 | Sub-domain H (IP and licensing, expanded) ruleset + playbooks | H.1–H.4, H.6–H.8 + ~40 rules. 35 U.S.C. + 17 U.S.C. + Lanham anchors. |
| 52 | Sub-domain I (Privacy, expanded) ruleset + playbooks | I.7 cookies + I.8 NPP + I.9 ROPA + I.10 DPIA + I.11 questionnaire + I.12 incident + ~40 new rules. |
| 53 | Sub-domain J (Healthcare) ruleset + playbooks | J.3–J.5 + ~25 rules. Common Rule + 45 C.F.R. § 164.508 / § 164.520 anchors. |
| 54 | Sub-domain K (Insurance and risk) ruleset + playbooks | K.2–K.5 + ~25 rules. State anti-indemnity anchors. |
| 55 | Sub-domain L (Banking and lending) ruleset + playbooks | L.1–L.8 + ~50 rules. UCC Art. 3 + Art. 9 + Reg Z + state usury anchors. |
| 56 | Sub-domain M (Construction) ruleset + playbooks | M.1–M.5 + ~30 rules. Miller Act + state Little Miller Acts + state lien anchors. |
| 57 | Sub-domain N (Trust, estate, family) ruleset + playbooks | N.1–N.8 + ~60 rules. UPC + UTC + UPAA + state will/trust anchors. **Per-output execution-formality disclaimer is mandatory.** |
| 58 | Sub-domain O (Compliance policies) ruleset + playbooks | O.1–O.10 + ~50 rules. FCPA + BSA + SOX + Dodd-Frank + LDA anchors. |
| 59 | Sub-domain P (Regulatory prose) ruleset + playbooks | P.1–P.6 + ~40 rules. Reg S-K Item 105 + Form D / ADV instructions anchors. **Per-output filing-schema disclaimer is mandatory.** |
| 60 | DKB build pipeline part 3 (v4 fetchers) | Eight new fetchers in `dkb/build/v4/fetchers/`. Snapshot fixtures. Staleness gate coverage. |
| 61 | Test corpus expansion | 2–4 synthetic fixtures per new family. 5+ multi-doc bundles. Goldens. Sanity guards per fixture. |
| 62 | Performance verification | Bundle-size budget check. 10-doc 4G mobile run < 60 s. Lighthouse budgets re-checked. |
| 63 | Accessibility verification (axe + a11y unit) | Static-HTML test extended for the new tile titles. axe DevTools live audit on deployed site. |
| 64 | Threat-model update | `docs/threat-model.md` extended with the multi-doc surface — same posture (client-side, no exfil, SRI). |
| 65 | Documentation | `docs/v4/` overview + adding-a-sub-domain + adding-a-family + cross-document-rules + the-document-classifier. |
| 66 | Launch checklist + version bump | Full v4 launch checklist; version bump to 4.0.0; tag v4.0.0. |

Total work: **27 build steps**, roughly comparable to v1's 17 + v3's 22.

---

# Part VII — Open questions for the maintainer

Recording these here so they're tracked in one place rather than scattered in PR comments:

1. **Folder picker vs zip drop fidelity.** Folder picker is Chrome-first (`webkitdirectory`); Safari support landed in 14.1. Confirm the offline-first contract still holds on iOS Safari for a folder drop. If not, zip is the cross-platform path and folder is a Chrome enhancement.
2. **Zip dep selection.** ✅ **Resolved.** `fflate` shipped as the zip codec — it is MIT, dependency-free, and bundled from same-origin (it is part of the static asset, not fetched from a CDN), so it satisfies the spec.md §28 "every byte comes from vaulytica.com / no third-party scripts" constraint. Used in [`src/ingest/multi.ts`](../src/ingest/multi.ts) (unzip on folder/zip drop) and [`src/report/bundle.ts`](../src/report/bundle.ts) (zip the multi-report bundle).
3. **The `vendor-v4-rules` chunk.** If the per-sub-domain rule code gets large enough, splitting per-sub-domain may help; the cost is more HTTP requests on first use. Profile after Step 49 lands.
4. **State-law overlay scope.** ✅ **Resolved (2026-06-01, spec-v6 Step 101).** The proposed pattern — one consolidated node per (family × state) carrying only the delta from the federal/common-law baseline — shipped as [`src/dkb/state-overlays.ts`](../src/dkb/state-overlays.ts): employment non-compete enforceability (15 states), residential-lease deposit/return rules (10 states), and lending usury caps (10 states), broadening beyond the original CA/NY/TX/FL/IL coverage without a 50 × N explosion. Overlays are surfaced as a citable reference layer alongside the report (DOCX + JSON + UI), outside the `EngineRun`, so `result_hash` is unchanged; uncovered states are reported honestly. See [`docs/v6/jurisdiction-overlays.md`](v6/jurisdiction-overlays.md).
5. **N (trust / estate / family) disclaimer placement.** Each output in this sub-domain must say "execution formalities (witness, notary, holographic state-specific) cannot be verified from text alone." Confirm the placement: report cover, executive summary, or both?
6. **P (regulatory prose) disclaimer placement.** Same question — must say "v4 lints prose only; the SEC / FINRA / equivalent filing schema is the regulator's job, not the linter's."
7. **The CROSS-PRECEDENCE rule and v3 MSA-027 overlap.** ✅ **Resolved — kept both** (the default proposal). v3 [`MSA-027`](../src/engine/rules/v3/msa-deep/rules.ts) (order-of-precedence consistency) ships as a single-doc check and v4 [`CROSS-PRECEDENCE`](../src/engine/consistency/rules/v4/cross-doc-rules.ts) catches the cross-document case; they have disjoint scopes (one document vs. a bundle) and so do not double-fire on the same input. Single-doc users still benefit from the v3 check, and the cross-doc consistency engine only runs in bundle context — no refactor needed.
8. **Auto-classifier confidence threshold.** ✅ **Resolved (2026-05-28).** 0.5 / 0.5 was the starting point; calibrated against the labeled golden corpus once it existed. A threshold sweep over the corpus showed the 0.5 sub-domain floor rejected 25 of 53 correctly-classified fixtures (sending them to `generic-fallback`), while every *wrong* top-1 prediction scored ≤ 0.286 — so lowering the floor never admits a misclassification. The sub-domain floor was lowered to **0.4**, which recovers 10 correct detections with zero new false-accepts and keeps a 0.114 margin above the false-positive ceiling. The family floor stays **0.5** (it gates the delegated `matchPlaybook` stage, calibrated separately by the playbook-matching tests). Locked by [`tests/v4/extract/classifier-calibration.test.ts`](tests/v4/extract/classifier-calibration.test.ts), which re-runs the sweep over the corpus on every test run.

---

# Part VIII — What this gives the user

After v4 lands, the elevator pitch updates:

> "Drop your legal docs. Vaulytica deterministically lints them against published authority — every finding has a citation. Drop one doc or drop a transaction folder; it works offline and never leaves your browser. Contracts, governance, equity, M&A, real estate, employment, settlements, IP, privacy, healthcare, insurance, lending, construction, estate, compliance policy, and regulatory prose are all in scope. Financial analysis, litigation strategy, and policy advice are not."

The deterministic-linter posture is preserved. The library expands ~4×. The UI is untouched. The brand promise is still "we ground every finding; nothing leaves your browser; you can reproduce the hash."
