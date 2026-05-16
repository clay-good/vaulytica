# v3 source catalog

Every v3 citation traces to one of the sources listed below. The
catalog is the audit-defense companion to any v3 report — pull any
finding's citation and verify it against the regulator's authoritative
URL.

For each source, the **Authority URL** is the canonical regulator-
published location. The **DKB fetcher** is the module under
[`dkb/build/v3/fetchers/`](../../dkb/build/v3/fetchers/) that produces
the corresponding DKB nodes. Each fetcher writes a snapshot under
[`dkb/fixtures/v3/snapshots/`](../../dkb/fixtures/v3/snapshots/) keyed
by `sha256(source_url)` so the staleness gate at
[`dkb/build/v3/staleness.ts`](../../dkb/build/v3/staleness.ts) detects
upstream drift.

## US — HIPAA / privacy / sectoral

| Source | Authority URL | DKB fetcher |
|---|---|---|
| HIPAA Privacy / Security / Breach Rules (45 CFR §§ 160, 164) | https://www.ecfr.gov/current/title-45 | `hipaa-ecfr-title-45.ts` |
| HHS sample BAA | https://www.hhs.gov/hipaa/for-professionals/covered-entities/sample-business-associate-agreement-provisions/ | `hhs-sample-baa.ts` |
| HHS OCR resolution agreements (index) | https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/agreements/ | `hhs-ocr-resolutions.ts` |
| CCPA — Cal. Civ. Code §§ 1798.100–1798.199.100 | https://leginfo.legislature.ca.gov/faces/codes_displayexpandedbranch.xhtml?tocCode=CIV | `ccpa-civ-code.ts` |
| CCPA implementing regulations — 11 CCR §§ 7000–7304 | https://oag.ca.gov/privacy/ccpa/regs | `ccpa-regulations-11ccr.ts` |
| Virginia CDPA — Va. Code § 59.1-575 et seq. | https://law.lis.virginia.gov/vacodefull/title59.1/chapter53/ | `vcdpa.ts` |
| Colorado CPA — C.R.S. § 6-1-1301 et seq. | https://leg.colorado.gov/sites/default/files/2021a_190_signed.pdf | `cpa.ts` |
| Connecticut CTDPA — Conn. Gen. Stat. § 42-515 et seq. | https://www.cga.ct.gov/2022/ACT/PA/PDF/2022PA-00015-R00SB-00006-PA.PDF | `ctdpa.ts` |
| Utah UCPA — Utah Code § 13-61-101 et seq. | https://le.utah.gov/xcode/Title13/Chapter61/13-61.html | `ucpa.ts` |
| Texas TDPSA — Tex. Bus. & Com. Code § 541.001 et seq. | https://statutes.capitol.texas.gov/Docs/BC/htm/BC.541.htm | `tdpsa.ts` |
| Oregon OCPA — ORS § 646A.570 et seq. | https://www.oregonlegislature.gov/bills_laws/ors/ors646a.html | `ocpa.ts` |
| Delaware DPDPA | https://delcode.delaware.gov/title6/c012d/ | `dpdpa.ts` |
| GLBA Safeguards Rule (16 CFR Part 314) | https://www.ecfr.gov/current/title-16/chapter-I/subchapter-C/part-314 | (deferred to v4) |
| FERPA — 20 U.S.C. § 1232g | https://www.govinfo.gov/content/pkg/USCODE-2023-title20/html/USCODE-2023-title20-chap31-subchapIII-part4-sec1232g.htm | (deferred to v4) |

## EU — GDPR / SCCs / member state

| Source | Authority URL | DKB fetcher |
|---|---|---|
| GDPR — Regulation (EU) 2016/679 | https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32016R0679 | `gdpr.ts` |
| EU SCC Implementing Decision (EU) 2021/914 | https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32021D0914 | `eu-scc-2021-914.ts` |
| EDPB Guidelines index | https://www.edpb.europa.eu/our-work-tools/general-guidance/guidelines-recommendations-best-practices_en | `edpb-guidelines.ts` |

## UK

| Source | Authority URL | DKB fetcher |
|---|---|---|
| UK GDPR (retained Regulation (EU) 2016/679) | https://www.legislation.gov.uk/eur/2016/679 | `uk-gdpr.ts` |
| UK IDTA | https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/international-transfers/international-data-transfer-agreement-and-guidance/ | `uk-idta.ts` |
| UK Addendum (to EU SCCs) | https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/international-transfers/international-data-transfer-agreement-and-guidance/ | `uk-addendum.ts` |

## Switzerland

| Source | Authority URL | DKB fetcher |
|---|---|---|
| Swiss revFADP (FADP) | https://www.fedlex.admin.ch/eli/cc/2022/491/en | `swiss-fadp.ts` |
| Swiss Addendum (FDPIC) | https://www.edoeb.admin.ch/edoeb/en/home.html | `swiss-addendum.ts` |

## International

| Source | Authority URL | DKB fetcher |
|---|---|---|
| PIPEDA — S.C. 2000, c. 5 (Canada) | https://laws-lois.justice.gc.ca/eng/acts/P-8.6/ | `pipeda.ts` |
| LGPD — Lei nº 13.709/2018 (Brazil) | https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm | `lgpd.ts` |
| APPI — Act on the Protection of Personal Information (Japan) | https://www.ppc.go.jp/files/pdf/PPC_law.pdf | `appi.ts` |
| PIPL — Personal Information Protection Law (PRC) | https://www.npc.gov.cn/englishnpc/c23934/202112/1abd8829788946ecab270e469b13c39c.shtml | `pipl.ts` |

## Trade secrets — for NDAs

| Source | Authority URL |
|---|---|
| DTSA — 18 U.S.C. §§ 1831–1839 (with § 1833(b) whistleblower notice) | https://uscode.house.gov/view.xhtml?path=/prelim@title18/part1/chapter90 |
| UTSA (1985 amendments) | https://www.uniformlaws.org/committees/community-home?CommunityKey=3a2538fb-e030-4e2d-a9e2-90373dc05792 |
| EU Trade Secrets Directive 2016/943 | https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32016L0943 |

## Commercial law — for MSAs

| Source | Authority URL |
|---|---|
| UCC Article 2 (sale of goods) | https://www.law.cornell.edu/ucc/2 |
| Cal. Civ. Code § 1668 (exculpation of willful misconduct) | https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=1668&lawCode=CIV |
| N.Y. Gen. Oblig. Law § 5-322.1 (anti-indemnity, construction) | https://www.nysenate.gov/legislation/laws/GOB/5-322.1 |
| Tex. Bus. & Com. Code § 151.102 (anti-indemnity overlays) | https://statutes.capitol.texas.gov/Docs/BC/htm/BC.151.htm |
| UCC § 2-316 (warranty disclaimer limits) | https://www.law.cornell.edu/ucc/2/2-316 |
| UCC § 2-719 (limited remedy / fail-of-essential-purpose) | https://www.law.cornell.edu/ucc/2/2-719 |

## Insurance — for COIs

| Source | Authority URL |
|---|---|
| ACORD 25 (Certificate of Liability Insurance) form layout | https://www.acord.org/ |
| ISO standard endorsement CG 20 10 (additional insured) | https://www.iso.com/ |
| ISO standard endorsement CG 20 37 (completed operations) | https://www.iso.com/ |
| ISO standard endorsement CG 20 26 (designated person) | https://www.iso.com/ |
| AM Best rating reference (current as of last DKB build) | https://www.ambest.com/ |

## AI — consensus practice, not statute

The AI-addendum playbook (spec-v3 §34) explicitly carries "consensus
practice, not statute" framing. The citations below are practitioner
norms.

| Source | Authority URL |
|---|---|
| NIST AI Risk Management Framework 1.0 | https://www.nist.gov/itl/ai-risk-management-framework |
| EU AI Act (Regulation (EU) 2024/1689) | https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32024R1689 |
| FTC enforcement actions on AI claims | https://www.ftc.gov/business-guidance/blog/2023/02/keep-your-ai-claims-check |

## How to cite from a v3 report

Every finding in a v3 report carries a `source_citations` list. Each
citation has an `id`, a human-readable `source`, a `source_url`, and a
`retrieved_at` timestamp. The **citation index** appendix at the end
of the DOCX report (§55) lists every citation in the report with a
clickable URL and the DKB version. To verify a citation:

1. Open the citation index.
2. Click the URL — it opens the regulator's published text in your
   default browser.
3. Confirm the cited subdivision still exists at the same path.
4. If the DKB version is older than your audit horizon, re-run with a
   fresher DKB build before relying on the finding.

The DKB build pipeline runs weekly and re-fetches every cited source.
If a hash drifts, the affected rule is moved into a stale-citation
queue and disabled. See [`spec-v3.md`](../../spec-v3.md) §14 for the
full protocol.
