/**
 * Jurisdiction overlays (spec-v6 Part VI §21, Step 101).
 *
 * Several v4 families are sharply state-specific: the same clause is fine in
 * one state and void in the next. v4 already flags the federal posture and a
 * handful of named states inside individual rules; this module broadens that
 * coverage with a *consolidated per-(family × state) overlay catalog* — the
 * pattern proposed in spec-v4 §Part-VII open-question-4, which avoids a
 * 50 × N node explosion by carrying one node per (family, state) holding the
 * delta from the federal/common-law baseline.
 *
 * Posture (spec-v6 §21):
 *   - **Deterministic.** An overlay is selected purely from the matched
 *     family (a function of `playbook_id`) and the governing-law state read
 *     out of the extracted jurisdiction references — both already
 *     deterministic. Same document → same overlays, on any machine.
 *   - **Citable.** Every overlay carries a real statutory citation + URL.
 *   - **Honest N/A.** A state with no overlay node yields *nothing* — never a
 *     guessed answer. The selection result publishes which governing-law
 *     states it detected and which of them are uncovered, the same
 *     anti-silent-truncation discipline as the model-clause coverage count.
 *   - **Outside the run.** Overlays are an advisory reference layer surfaced
 *     alongside the report (like model-clause references, spec-v6 §14), *not*
 *     EngineRun findings, so every existing `result_hash` is unchanged.
 *
 * This catalog is the runtime source of truth — a frozen, hand-curated module
 * validated against {@link StateOverlaySchema} by `state-overlays.test.ts`.
 *
 * Scope: the three families spec §21 names, each a served document family
 * with state law that dominates the outcome — **employment** (non-compete
 * enforceability), **residential-lease** (security-deposit cap + return
 * window), and **lending** (usury / interest-rate caps). The residential
 * overlays gate to the *residential* lease playbook only (`lease-residential-us`);
 * the commercial-lease playbook is deliberately excluded, because a
 * residential deposit-cap statute applied to a commercial lease would be a
 * confidently-wrong answer.
 */

import { z } from "zod";
import type { SourceCitation } from "./types.js";
import type { Severity } from "../engine/finding.js";
import type { JurisdictionReference } from "../extract/types.js";

/** ISO 8601 date the public statutes below were last checked. A fixed
 * constant (never wall-clock) so the catalog and every report that embeds it
 * stay byte-identical across machines and runs. */
const CURATED_AT = "2026-06-01";

/** Families with state-law overlays. A function of the matched playbook id. */
export type OverlayFamily = "employment" | "residential-lease" | "lending";

/**
 * How the state treats the clause relative to the baseline. Drives the
 * shading discipline in the report, same as the v3 compliance matrix.
 */
export type OverlayPosture = "prohibited" | "restricted" | "permitted" | "informational";

export type StateOverlay = {
  /** Stable id, e.g. `emp-noncompete-us-ca`. */
  id: string;
  family: OverlayFamily;
  /** The state-law topic, e.g. `non-compete enforceability`. */
  topic: string;
  /** Normalized jurisdiction id, e.g. `us-ca`. */
  jurisdiction: string;
  /** Full state name, e.g. `California`. */
  state_name: string;
  posture: OverlayPosture;
  /** Short status line, e.g. `Void / unenforceable` or `Cap: 10% (general)`. */
  headline: string;
  /** Plain-language description of the state delta from the baseline. */
  summary: string;
  /** What the reviewer should check or do given this overlay. */
  recommendation: string;
  /** Suggested attention level when this overlay surfaces. */
  severity: Severity;
  citation: SourceCitation;
};

export const StateOverlaySchema = z.object({
  id: z.string().min(1),
  family: z.enum(["employment", "residential-lease", "lending"]),
  topic: z.string().min(1),
  jurisdiction: z.string().regex(/^us-[a-z]{2}$/, "jurisdiction must be us-XX"),
  state_name: z.string().min(1),
  posture: z.enum(["prohibited", "restricted", "permitted", "informational"]),
  headline: z.string().min(1),
  summary: z.string().min(1),
  recommendation: z.string().min(1),
  severity: z.enum(["critical", "warning", "info"]),
  citation: z.object({
    id: z.string().min(1),
    source: z.string().min(1),
    source_url: z.string().url(),
    retrieved_at: z.string().min(1),
    source_published_at: z.string().optional(),
    license: z.string().min(1),
    license_url: z.string().url(),
    attribution: z.string().optional(),
  }),
});

const PUBLIC_LAW_LICENSE = {
  license: "Public domain (US state government work)",
  license_url: "https://www.usa.gov/government-works",
} as const;

const cite = (id: string, source: string, source_url: string): SourceCitation => ({
  id,
  source,
  source_url,
  retrieved_at: CURATED_AT,
  ...PUBLIC_LAW_LICENSE,
});

/** Like {@link cite}, but with the entry's own verification date — used for
 * overlays re-verified after the catalog-wide `CURATED_AT` pass (the 2025
 * non-compete wave was checked against primary sources on 2026-07-04). */
const citeAt = (
  id: string,
  source: string,
  source_url: string,
  retrieved_at: string,
): SourceCitation => ({
  id,
  source,
  source_url,
  retrieved_at,
  ...PUBLIC_LAW_LICENSE,
});

/**
 * Employment — non-compete enforceability. The single most state-specific
 * employment question: identical covenant language is void in California and
 * routinely enforced in Florida. Covers the four states with statutory bans,
 * the income/notice-gated states, and the favorable-enforcement states —
 * broadening well beyond the original CA/NY/TX/FL/IL coverage.
 */
const EMPLOYMENT_NONCOMPETE: readonly StateOverlay[] = [
  {
    id: "emp-noncompete-us-ca",
    family: "employment",
    topic: "non-compete enforceability",
    jurisdiction: "us-ca",
    state_name: "California",
    posture: "prohibited",
    headline: "Void / unenforceable",
    summary:
      "California voids employee non-compete covenants by statute, with no general exception for ordinary employment. As of 2024 an employer may also not attempt to enforce a void non-compete and must have notified affected employees; doing so is an independent violation.",
    recommendation:
      "Treat any employee non-compete as unenforceable under California law. Rely on trade-secret protection and a narrowly-drawn confidentiality/non-solicit instead; confirm the 2024 employee-notice obligation was met.",
    severity: "critical",
    citation: cite(
      "ca-bus-prof-16600",
      "Cal. Bus. & Prof. Code §§ 16600, 16600.1, 16600.5",
      "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=BPC&sectionNum=16600.",
    ),
  },
  {
    id: "emp-noncompete-us-nd",
    family: "employment",
    topic: "non-compete enforceability",
    jurisdiction: "us-nd",
    state_name: "North Dakota",
    posture: "prohibited",
    headline: "Void / unenforceable",
    summary:
      "North Dakota voids contracts that restrain anyone from exercising a lawful profession, trade, or business, subject only to narrow sale-of-business and partnership-dissolution exceptions — employee non-competes are not enforceable.",
    recommendation:
      "Do not rely on an employee non-compete in North Dakota. Use confidentiality and trade-secret protections; a customer non-solicit is also vulnerable under state case law.",
    severity: "critical",
    citation: cite(
      "nd-cent-code-9-08-06",
      "N.D. Cent. Code § 9-08-06",
      "https://ndlegis.gov/cencode/t09c08.pdf",
    ),
  },
  {
    id: "emp-noncompete-us-ok",
    family: "employment",
    topic: "non-compete enforceability",
    jurisdiction: "us-ok",
    state_name: "Oklahoma",
    posture: "prohibited",
    headline: "Void / unenforceable",
    summary:
      "Oklahoma voids covenants not to compete for ordinary employees, but expressly preserves the right to bar a former employee from directly soliciting the established customers of the former employer. The non-compete itself is unenforceable.",
    recommendation:
      "Drop the non-compete for Oklahoma-based employees; a properly-scoped customer non-solicit limited to established customers is the enforceable alternative the statute allows.",
    severity: "critical",
    citation: cite(
      "ok-stat-15-219a",
      "Okla. Stat. tit. 15, §§ 219A–219B",
      "https://www.oscn.net/applications/oscn/DeliverDocument.asp?CiteID=78360",
    ),
  },
  {
    id: "emp-noncompete-us-mn",
    family: "employment",
    topic: "non-compete enforceability",
    jurisdiction: "us-mn",
    state_name: "Minnesota",
    posture: "prohibited",
    headline: "Void (agreements on/after 2023-07-01)",
    summary:
      "Minnesota voids any covenant not to compete entered into on or after July 1, 2023. Non-solicitation and confidentiality covenants remain permissible; the statute also bars out-of-state choice-of-law/venue clauses used to evade it for Minnesota residents.",
    recommendation:
      "For agreements dated on or after 2023-07-01, treat the non-compete as void in Minnesota. Confirm any choice-of-law clause does not attempt to route a Minnesota employee around the ban.",
    severity: "critical",
    citation: cite(
      "mn-stat-181-988",
      "Minn. Stat. § 181.988",
      "https://www.revisor.mn.gov/statutes/cite/181.988",
    ),
  },
  {
    id: "emp-noncompete-us-co",
    family: "employment",
    topic: "non-compete enforceability",
    jurisdiction: "us-co",
    state_name: "Colorado",
    posture: "restricted",
    headline: "Void unless worker is highly compensated",
    summary:
      "Colorado makes non-competes void unless the worker earns above an annually-adjusted highly-compensated threshold (and customer non-solicits unless above ~60% of it), requires specific advance notice, and imposes penalties for non-compliant covenants. Criminal-trade-secret and sale-of-business exceptions are narrow.",
    recommendation:
      "Confirm the worker exceeds the current highly-compensated threshold and that the statutory advance-notice requirement was met; otherwise the non-compete is void and may carry penalties.",
    severity: "warning",
    citation: cite(
      "co-rev-stat-8-2-113",
      "Colo. Rev. Stat. § 8-2-113",
      "https://leg.colorado.gov/sites/default/files/images/olls/crs2023-title-08.pdf",
    ),
  },
  {
    id: "emp-noncompete-us-wa",
    family: "employment",
    topic: "non-compete enforceability",
    jurisdiction: "us-wa",
    state_name: "Washington",
    posture: "restricted",
    headline: "Void below income threshold; ≤18 mo presumed reasonable",
    summary:
      "Washington voids non-competes for employees earning below an annually-adjusted income threshold, requires written disclosure by the offer-acceptance date, presumes any duration over 18 months unreasonable, and mandates pay during any post-termination enforcement of a laid-off worker's covenant.",
    recommendation:
      "Verify the employee's earnings exceed the current threshold and the duration is ≤18 months; confirm the disclosure-timing and (for laid-off workers) the pay-during-enforcement requirements.",
    severity: "warning",
    citation: cite(
      "wa-rcw-49-62",
      "Wash. Rev. Code ch. 49.62",
      "https://app.leg.wa.gov/rcw/default.aspx?cite=49.62",
    ),
  },
  {
    id: "emp-noncompete-us-or",
    family: "employment",
    topic: "non-compete enforceability",
    jurisdiction: "us-or",
    state_name: "Oregon",
    posture: "restricted",
    headline: "Void unless statutory conditions met; ≤12 mo",
    summary:
      "Oregon makes a non-compete voidable unless the employer gives written notice at least two weeks before the start date (or it is entered at a bona fide advancement), the employee is exempt and earns above a salary floor, and the term does not exceed 12 months.",
    recommendation:
      "Confirm the two-week advance-notice, exempt-status, salary-floor, and 12-month-cap conditions were all satisfied; a covenant missing any of them is voidable in Oregon.",
    severity: "warning",
    citation: cite(
      "or-rev-stat-653-295",
      "Or. Rev. Stat. § 653.295",
      "https://www.oregonlegislature.gov/bills_laws/ors/ors653.html",
    ),
  },
  {
    id: "emp-noncompete-us-ma",
    family: "employment",
    topic: "non-compete enforceability",
    jurisdiction: "us-ma",
    state_name: "Massachusetts",
    posture: "restricted",
    headline: "Garden-leave or consideration; ≤12 mo; notice required",
    summary:
      "Massachusetts requires a post-employment non-compete to be in writing, signed, supported by garden-leave pay (≥50% of salary) or other mutually-agreed consideration, limited to 12 months, and reviewed-by-counsel notice given. It bars non-competes for non-exempt, student, and terminated-without-cause workers.",
    recommendation:
      "Confirm the garden-leave/consideration, 12-month cap, advance-notice, and worker-eligibility requirements; a covenant missing the consideration or notice elements is unenforceable in Massachusetts.",
    severity: "warning",
    citation: cite(
      "ma-gl-149-24l",
      "Mass. Gen. Laws ch. 149, § 24L",
      "https://malegislature.gov/Laws/GeneralLaws/PartI/TitleXXI/Chapter149/Section24L",
    ),
  },
  {
    id: "emp-noncompete-us-va",
    family: "employment",
    topic: "non-compete enforceability",
    jurisdiction: "us-va",
    state_name: "Virginia",
    posture: "restricted",
    headline: "Void for low-wage and all overtime-eligible employees",
    summary:
      "Virginia prohibits non-competes for 'low-wage employees' — those earning below the state average weekly wage, any worker paid primarily by tips/commission/incentive, and (per SB 1218, eff. 2025-07-01) any employee entitled to FLSA overtime for hours over 40, regardless of earnings. Covenants for exempt higher earners remain subject to common-law reasonableness review.",
    recommendation:
      "Confirm the employee is FLSA-exempt AND earns above the current low-wage threshold; if either fails, the non-compete is prohibited and exposes the employer to statutory penalties (and the required workplace posting must reflect the amended statute).",
    severity: "warning",
    citation: citeAt(
      "va-code-40-1-28-7-8",
      "Va. Code § 40.1-28.7:8 (as amended by SB 1218, eff. July 1, 2025)",
      "https://law.lis.virginia.gov/vacode/title40.1/chapter3/section40.1-28.7:8/",
      "2026-07-04",
    ),
  },
  {
    id: "emp-noncompete-us-il",
    family: "employment",
    topic: "non-compete enforceability",
    jurisdiction: "us-il",
    state_name: "Illinois",
    posture: "restricted",
    headline: "Void below salary thresholds; notice + consideration",
    summary:
      "Illinois's Freedom to Work Act voids non-competes for employees earning at or below an annually-escalating salary threshold (and non-solicits below a lower one), requires 14 days' written notice and advice-to-consult-counsel, and codifies adequate-consideration and reasonableness requirements.",
    recommendation:
      "Verify the employee's earnings exceed the current threshold and that the 14-day notice and adequate-consideration requirements were met; otherwise the covenant is void.",
    severity: "warning",
    citation: cite(
      "il-820-ilcs-90",
      "820 Ill. Comp. Stat. 90 (Illinois Freedom to Work Act)",
      "https://www.ilga.gov/legislation/ilcs/ilcs3.asp?ActID=4012",
    ),
  },
  {
    id: "emp-noncompete-us-dc",
    family: "employment",
    topic: "non-compete enforceability",
    jurisdiction: "us-dc",
    state_name: "District of Columbia",
    posture: "restricted",
    headline: "Banned except for highly-compensated employees",
    summary:
      "The District of Columbia bans non-competes except for 'highly compensated employees' above an annually-adjusted threshold (and medical specialists), and even then imposes maximum-term, notice, and anti-retaliation requirements. Anti-moonlighting restrictions during employment are separately limited.",
    recommendation:
      "Confirm the employee exceeds the highly-compensated threshold and that the required written notice was given; for most employees a non-compete is prohibited in the District.",
    severity: "warning",
    citation: cite(
      "dc-code-32-581",
      "D.C. Code § 32-581.01 et seq. (Ban on Non-Compete Agreements Amendment Act)",
      "https://code.dccouncil.gov/us/dc/council/code/titles/32/chapters/5C",
    ),
  },
  {
    id: "emp-noncompete-us-nv",
    family: "employment",
    topic: "non-compete enforceability",
    jurisdiction: "us-nv",
    state_name: "Nevada",
    posture: "restricted",
    headline: "Enforceable with limits; no bar on hourly workers",
    summary:
      "Nevada enforces reasonable non-competes supported by valuable consideration but prohibits them for employees paid solely on an hourly wage basis, bars restrictions on serving former customers the employee did not solicit, and requires courts to revise (blue-pencil) overbroad covenants rather than void them.",
    recommendation:
      "Confirm the worker is not paid solely hourly and that scope/duration are reasonable; the covenant may be judicially narrowed rather than struck if overbroad.",
    severity: "info",
    citation: cite(
      "nv-rev-stat-613-195",
      "Nev. Rev. Stat. § 613.195",
      "https://www.leg.state.nv.us/nrs/nrs-613.html",
    ),
  },
  {
    id: "emp-noncompete-us-tx",
    family: "employment",
    topic: "non-compete enforceability",
    jurisdiction: "us-tx",
    state_name: "Texas",
    posture: "permitted",
    headline: "Enforceable if ancillary + reasonable",
    summary:
      "Texas enforces a non-compete that is ancillary to an otherwise-enforceable agreement (e.g. supported by confidential information or goodwill) and reasonable in time, geography, and scope. Courts reform overbroad covenants rather than voiding them.",
    recommendation:
      "Ensure the covenant is tied to consideration such as access to confidential information and that time/geography/scope limits are reasonable for the role; overbroad terms will be reformed.",
    severity: "info",
    citation: cite(
      "tx-bus-com-15-50",
      "Tex. Bus. & Com. Code §§ 15.50–15.52",
      "https://statutes.capitol.texas.gov/Docs/BC/htm/BC.15.htm",
    ),
  },
  {
    id: "emp-noncompete-us-fl",
    family: "employment",
    topic: "non-compete enforceability",
    jurisdiction: "us-fl",
    state_name: "Florida",
    posture: "permitted",
    headline: "Enforceable; statutorily favored — CHOICE Act adds up to 4 years",
    summary:
      "Florida enforces non-competes that protect a legitimate business interest and are reasonable in time and area (Fla. Stat. § 542.335, with presumptions of reasonableness, e.g. up to 2 years for a former employee). The 2025 CHOICE Act (Fla. Stat. §§ 542.41–542.45, eff. 2025-07-01) goes further for 'covered' high earners (above twice the county annual mean wage): covered non-compete and paid garden-leave agreements of up to 4 years carry a presumption of enforceability when the Act's notice and acknowledgment formalities are met — the pro-enforcement outlier of the 2025 state wave.",
    recommendation:
      "Tie the covenant to a statutorily-recognized legitimate business interest; for high earners, consider whether the covenant qualifies under the CHOICE Act (earnings threshold, written notice of the right to counsel, 7-day review period) for its up-to-4-year presumption. Florida is the most enforcement-friendly state.",
    severity: "info",
    citation: citeAt(
      "fl-stat-542-choice-act",
      "Fla. Stat. §§ 542.335, 542.41–542.45 (CHOICE Act, eff. July 1, 2025)",
      "https://www.flsenate.gov/Laws/Statutes/2025/542.335",
      "2026-07-04",
    ),
  },
  {
    id: "emp-noncompete-us-ny",
    family: "employment",
    topic: "non-compete enforceability",
    jurisdiction: "us-ny",
    state_name: "New York",
    posture: "permitted",
    headline: "Enforceable under common-law reasonableness",
    summary:
      "New York has no general non-compete statute; enforceability turns on the common-law test — the restraint must protect a legitimate interest (trade secrets, confidential information, or unique services), be reasonable in time and area, not harm the public, and not be unduly burdensome. A 2023 statutory ban was vetoed; review for renewed legislative activity.",
    recommendation:
      "Apply the four-part common-law reasonableness test and keep the restraint narrowly tailored; monitor for renewed New York legislation restricting non-competes.",
    severity: "info",
    citation: cite(
      "ny-bdo-seidman",
      "BDO Seidman v. Hyatt, 93 N.Y.2d 382 (1999) (New York common-law non-compete test)",
      "https://www.nycourts.gov/reporter/archives/bdo_hyatt.htm",
    ),
  },
  {
    id: "emp-noncompete-us-wy",
    family: "employment",
    topic: "non-compete enforceability",
    jurisdiction: "us-wy",
    state_name: "Wyoming",
    posture: "restricted",
    headline: "Void by statute with carve-outs (contracts on/after 2025-07-01)",
    summary:
      "Wyoming's SF 107 (Wyo. Stat. § 1-23-108, eff. 2025-07-01) voids covenants not to compete that restrict the right to receive compensation for labor, for contracts entered on or after July 1, 2025 — with carve-outs for sale-of-business covenants, trade-secret protection, recovery of relocation/education/training expenses, and executive/management personnel (and their professional staff). Physician non-competes are void outright, and a departing physician may notify patients with rare disorders of their continuing practice.",
    recommendation:
      "For Wyoming agreements signed on or after 2025-07-01, rely on a statutory carve-out (sale of business, trade secrets, executive/management role) or use non-solicit/NDA protection instead; physician non-competes are void regardless of role.",
    severity: "warning",
    citation: citeAt(
      "wy-stat-1-23-108",
      "Wyo. Stat. § 1-23-108 (SF 107, 2025 Wyo. Sess. Laws, Enrolled Act No. 87; eff. July 1, 2025)",
      "https://www.wyoleg.gov/Legislation/2025/SF0107",
      "2026-07-04",
    ),
  },
  {
    id: "emp-noncompete-us-ar",
    family: "employment",
    topic: "non-compete enforceability",
    jurisdiction: "us-ar",
    state_name: "Arkansas",
    posture: "restricted",
    headline: "Enforceable generally; void for physicians (2025)",
    summary:
      "Arkansas enforces reasonable employee non-competes under its covenant statute (Ark. Code § 4-75-101), but Act 232 of 2025 (SB 139, eff. August 2025) voids any covenant that restricts a physician's right to practice within the physician's scope of practice — covering anyone licensed under the Arkansas Medical Practice Act or licensed to practice osteopathy.",
    recommendation:
      "For physicians, treat any Arkansas non-compete as void and rely on non-solicit/confidentiality protection; for other employees, confirm the covenant meets § 4-75-101's reasonableness requirements.",
    severity: "warning",
    citation: citeAt(
      "ar-code-4-75-101",
      "Ark. Code § 4-75-101 (as amended by Act 232 of 2025 (SB 139); physician non-competes void, eff. Aug. 2025)",
      "https://arkleg.state.ar.us/Bills/Detail?id=SB139&ddBienniumSession=2025%2F2025R",
      "2026-07-04",
    ),
  },
];

/**
 * Residential lease — security-deposit cap and return window. Whether a
 * landlord may hold more than a month's rent, and how fast a deposit must come
 * back, is set state by state. Gated to the *residential* lease playbook only;
 * commercial leases are governed by different rules and are excluded.
 */
const RESIDENTIAL_LEASE_DEPOSIT: readonly StateOverlay[] = [
  {
    id: "lease-deposit-us-ca",
    family: "residential-lease",
    topic: "security-deposit cap & return",
    jurisdiction: "us-ca",
    state_name: "California",
    posture: "restricted",
    headline: "Cap: 1 month (AB 12, from 2024-07-01); return in 21 days",
    summary:
      "As of July 1, 2024 California caps a residential security deposit at one month's rent for most landlords (two months for a small-landlord exception), down from the prior 2-months-unfurnished / 3-months-furnished limit. The deposit must be returned, with an itemized statement of deductions, within 21 days of move-out.",
    recommendation:
      "Confirm the deposit does not exceed one month's rent under the current cap and that the lease commits to the 21-day itemized-return timeline.",
    severity: "warning",
    citation: cite(
      "ca-civ-1950-5",
      "Cal. Civ. Code § 1950.5 (as amended by AB 12)",
      "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1950.5.",
    ),
  },
  {
    id: "lease-deposit-us-ny",
    family: "residential-lease",
    topic: "security-deposit cap & return",
    jurisdiction: "us-ny",
    state_name: "New York",
    posture: "restricted",
    headline: "Cap: 1 month; return in 14 days",
    summary:
      "New York's Housing Stability and Tenant Protection Act (2019) caps a residential security deposit at one month's rent and requires the landlord to return it, less itemized lawful deductions, within 14 days of the tenant vacating — failing which the landlord forfeits the right to retain any of it.",
    recommendation:
      "Confirm the deposit is no more than one month's rent and the lease reflects the 14-day return-or-forfeit rule.",
    severity: "warning",
    citation: cite(
      "ny-gob-7-108",
      "N.Y. Gen. Oblig. Law § 7-108",
      "https://www.nysenate.gov/legislation/laws/GOB/7-108",
    ),
  },
  {
    id: "lease-deposit-us-ma",
    family: "residential-lease",
    topic: "security-deposit cap & return",
    jurisdiction: "us-ma",
    state_name: "Massachusetts",
    posture: "restricted",
    headline: "Cap: 1 month; interest-bearing; return in 30 days",
    summary:
      "Massachusetts caps a residential security deposit at one month's rent, requires it to be held in a separate interest-bearing escrow account in a Massachusetts bank with a receipt and annual interest to the tenant, and to be returned within 30 days. The statute carries treble-damages exposure for violations.",
    recommendation:
      "Confirm the deposit is ≤ one month's rent, held in a compliant interest-bearing escrow with the required receipt/statement-of-condition, and returned within 30 days — the treble-damages penalty makes strict compliance important.",
    severity: "warning",
    citation: cite(
      "ma-gl-186-15b",
      "Mass. Gen. Laws ch. 186, § 15B",
      "https://malegislature.gov/Laws/GeneralLaws/PartII/TitleI/Chapter186/Section15B",
    ),
  },
  {
    id: "lease-deposit-us-nj",
    family: "residential-lease",
    topic: "security-deposit cap & return",
    jurisdiction: "us-nj",
    state_name: "New Jersey",
    posture: "restricted",
    headline: "Cap: 1.5 months; return in 30 days",
    summary:
      "New Jersey caps a residential security deposit at one and one-half months' rent (and limits annual increases to 10%), requires it to be held in an interest-bearing account with notice to the tenant, and to be returned with interest within 30 days of the lease ending. Wrongful withholding exposes the landlord to double damages.",
    recommendation:
      "Confirm the deposit is ≤ 1.5 months' rent, held with the required notice, and the lease reflects the 30-day return-with-interest rule.",
    severity: "warning",
    citation: cite(
      "nj-46-8-19",
      "N.J.S.A. §§ 46:8-19 to 46:8-21.1 (Rent Security Deposit Act)",
      "https://www.njleg.state.nj.us/",
    ),
  },
  {
    id: "lease-deposit-us-dc",
    family: "residential-lease",
    topic: "security-deposit cap & return",
    jurisdiction: "us-dc",
    state_name: "District of Columbia",
    posture: "restricted",
    headline: "Cap: 1 month; interest-bearing; return in 45 days",
    summary:
      "The District of Columbia caps a residential security deposit at one month's rent, requires it to be held in an interest-bearing account with the interest paid to the tenant, and to be returned within 45 days of lease end (with a further 30 days to refund any balance after deductions).",
    recommendation:
      "Confirm the deposit is ≤ one month's rent, held in a compliant interest-bearing account, and the lease commits to the 45-day return timeline.",
    severity: "warning",
    citation: cite(
      "dc-mun-regs-14-308",
      "D.C. Mun. Regs. tit. 14, §§ 308–311",
      "https://www.dcregs.dc.gov/Common/DCMR/RuleList.aspx?ChapterNum=14-3",
    ),
  },
  {
    id: "lease-deposit-us-tx",
    family: "residential-lease",
    topic: "security-deposit cap & return",
    jurisdiction: "us-tx",
    state_name: "Texas",
    posture: "informational",
    headline: "No statutory cap; return in 30 days",
    summary:
      "Texas sets no statutory ceiling on a residential security deposit, but requires the landlord to refund it (with an itemized list of deductions) within 30 days after the tenant surrenders the premises and provides a forwarding address. Bad-faith retention exposes the landlord to treble damages plus a $100 penalty.",
    recommendation:
      "There is no cap to check, but confirm the lease reflects the 30-day itemized-return obligation; bad-faith withholding carries treble damages in Texas.",
    severity: "info",
    citation: cite(
      "tx-prop-92-103",
      "Tex. Prop. Code §§ 92.101–92.109",
      "https://statutes.capitol.texas.gov/Docs/PR/htm/PR.92.htm",
    ),
  },
  {
    id: "lease-deposit-us-fl",
    family: "residential-lease",
    topic: "security-deposit cap & return",
    jurisdiction: "us-fl",
    state_name: "Florida",
    posture: "informational",
    headline: "No statutory cap; 15-/30-day notice on deductions",
    summary:
      "Florida sets no cap on a residential security deposit but prescribes a strict procedure: the landlord must return the deposit within 15 days if no deductions are made, or give written notice of intent to impose a claim within 30 days, after which the tenant has 15 days to object. Missing the notice forfeits the right to deduct.",
    recommendation:
      "There is no cap to check, but confirm the lease and the landlord's process follow the 15-day return / 30-day notice-of-claim procedure — missing the notice forfeits deductions.",
    severity: "info",
    citation: cite(
      "fl-stat-83-49",
      "Fla. Stat. § 83.49",
      "https://www.flsenate.gov/Laws/Statutes/2023/83.49",
    ),
  },
  {
    id: "lease-deposit-us-il",
    family: "residential-lease",
    topic: "security-deposit cap & return",
    jurisdiction: "us-il",
    state_name: "Illinois",
    posture: "informational",
    headline: "No state cap; 30-/45-day return (local interest rules)",
    summary:
      "Illinois sets no statewide deposit cap; the Security Deposit Return Act requires an itemized statement within 30 days and the balance within 45 days for larger buildings, and the Security Deposit Interest Act and local ordinances (notably the Chicago RLTO) add interest-payment and stricter-timing requirements.",
    recommendation:
      "Check whether a local ordinance (e.g. the Chicago RLTO) imposes interest and tighter deadlines, and confirm the lease reflects the 30-/45-day itemized-return rules.",
    severity: "info",
    citation: cite(
      "il-765-ilcs-710",
      "765 Ill. Comp. Stat. 710 & 715 (Security Deposit Return / Interest Acts)",
      "https://www.ilga.gov/legislation/ilcs/ilcs3.asp?ActID=2202",
    ),
  },
  {
    id: "lease-deposit-us-wa",
    family: "residential-lease",
    topic: "security-deposit cap & return",
    jurisdiction: "us-wa",
    state_name: "Washington",
    posture: "informational",
    headline: "No statutory cap; return in 21 days; checklist required",
    summary:
      "Washington sets no deposit cap but requires a written move-in condition checklist (a deposit cannot be collected without one) and return of the deposit with a full itemized statement within 21 days of the tenancy ending. Non-compliance can forfeit the landlord's right to retain any of it.",
    recommendation:
      "Confirm a move-in condition checklist was provided (a prerequisite to holding any deposit) and that the lease reflects the 21-day itemized-return rule.",
    severity: "info",
    citation: cite(
      "wa-rcw-59-18-280",
      "Wash. Rev. Code §§ 59.18.260–59.18.285",
      "https://app.leg.wa.gov/rcw/default.aspx?cite=59.18.280",
    ),
  },
  {
    id: "lease-deposit-us-or",
    family: "residential-lease",
    topic: "security-deposit cap & return",
    jurisdiction: "us-or",
    state_name: "Oregon",
    posture: "informational",
    headline: "No statutory cap; return in 31 days",
    summary:
      "Oregon sets no cap on a residential security deposit but requires the landlord to return it, with a written accounting of any deductions, within 31 days after the tenancy ends. A deposit withheld in bad faith exposes the landlord to twice the amount wrongfully withheld.",
    recommendation:
      "There is no cap to check, but confirm the lease reflects the 31-day written-accounting-and-return obligation.",
    severity: "info",
    citation: cite(
      "or-rev-stat-90-300",
      "Or. Rev. Stat. § 90.300",
      "https://www.oregonlegislature.gov/bills_laws/ors/ors090.html",
    ),
  },
];

/**
 * Lending — usury / interest-rate caps. Maximum lawful interest is set by
 * each state and the consequences of exceeding it (from forfeiture of
 * interest to criminal exposure) vary sharply. Surfaced as an informational
 * reference so a reviewer can check a stated rate against the applicable cap;
 * Vaulytica does not silently compute whether a given rate is usurious.
 */
const LENDING_USURY: readonly StateOverlay[] = [
  {
    id: "lend-usury-us-ca",
    family: "lending",
    topic: "usury / interest-rate cap",
    jurisdiction: "us-ca",
    state_name: "California",
    posture: "informational",
    headline: "Cap: 10% (general loans); broad licensed-lender exemptions",
    summary:
      "California's constitutional usury limit is 10% per year for most non-exempt loans for personal/family/household use (and the higher of 10% or 5% over the Federal Reserve rate for other loans). Loans made or arranged by licensed lenders, banks, and many finance lenders are exempt, so the cap chiefly bites private/non-licensed lending.",
    recommendation:
      "Check whether the lender qualifies for a licensed-lender exemption; if not, confirm the stated rate (including fees treated as interest) stays within the 10% constitutional cap.",
    severity: "info",
    citation: cite(
      "ca-const-art-15",
      "Cal. Const. art. XV, § 1; Cal. Civ. Code § 1916-1 et seq.",
      "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CONS&article=XV",
    ),
  },
  {
    id: "lend-usury-us-ny",
    family: "lending",
    topic: "usury / interest-rate cap",
    jurisdiction: "us-ny",
    state_name: "New York",
    posture: "informational",
    headline: "Cap: 16% civil / 25% criminal",
    summary:
      "New York sets a 16% civil usury cap and a 25% criminal usury cap on the annual interest rate. Loans of $250,000–$2,500,000 are exempt from the civil (but not criminal) cap, and loans of $2,500,000 or more are exempt from both. A usurious loan can be void with forfeiture of principal and interest.",
    recommendation:
      "Confirm which cap applies given the loan amount and that the all-in rate stays within it; usury in New York can void the note entirely, not merely the excess interest.",
    severity: "info",
    citation: cite(
      "ny-gob-5-501",
      "N.Y. Gen. Oblig. Law § 5-501; N.Y. Penal Law §§ 190.40–190.42",
      "https://www.nysenate.gov/legislation/laws/GOB/5-501",
    ),
  },
  {
    id: "lend-usury-us-tx",
    family: "lending",
    topic: "usury / interest-rate cap",
    jurisdiction: "us-tx",
    state_name: "Texas",
    posture: "informational",
    headline: "Cap: 18% default; up to 28%+ by tiered ceilings",
    summary:
      "Texas caps interest at 6% absent agreement and 18% by written contract for many loans, with higher tiered 'weekly/monthly/annualized' ceilings under Finance Code ch. 303 for commercial and larger transactions. Usurious interest exposes the lender to statutory penalties (forfeiture of interest and, above thresholds, principal).",
    recommendation:
      "Identify which ch. 303 ceiling applies to the transaction type and confirm the contracted rate plus interest-equivalent charges stays within it to avoid Texas usury penalties.",
    severity: "info",
    citation: cite(
      "tx-fin-code-302-303",
      "Tex. Fin. Code chs. 302–306",
      "https://statutes.capitol.texas.gov/Docs/FI/htm/FI.303.htm",
    ),
  },
  {
    id: "lend-usury-us-fl",
    family: "lending",
    topic: "usury / interest-rate cap",
    jurisdiction: "us-fl",
    state_name: "Florida",
    posture: "informational",
    headline: "Cap: 18% (≤$500k) / 25% civil; 45% criminal",
    summary:
      "Florida caps interest at 18% per year on loans of $500,000 or less and 25% on larger loans; a rate above 25% is criminal usury and above 45% is a felony. Civil usury generally forfeits the interest (and, for willful violations above 25%, the principal).",
    recommendation:
      "Confirm the rate matches the correct tier for the loan size and that fees treated as interest do not push the effective rate past 25%, which crosses into criminal usury in Florida.",
    severity: "info",
    citation: cite(
      "fl-stat-687",
      "Fla. Stat. §§ 687.02–687.071",
      "https://www.flsenate.gov/Laws/Statutes/2023/Chapter687",
    ),
  },
  {
    id: "lend-usury-us-il",
    family: "lending",
    topic: "usury / interest-rate cap",
    jurisdiction: "us-il",
    state_name: "Illinois",
    posture: "informational",
    headline: "Cap: 9% general; 36% MAPR on consumer loans",
    summary:
      "Illinois sets a 9% general usury cap where no other rate is permitted, but business loans and many regulated lenders are broadly exempt. The Predatory Loan Prevention Act caps most consumer loans at a 36% Military-APR-style all-in rate; a loan exceeding it is null and void.",
    recommendation:
      "Distinguish a commercial loan (broadly exempt) from a consumer loan subject to the 36% PLPA cap; a consumer loan above 36% MAPR is void in Illinois.",
    severity: "info",
    citation: cite(
      "il-815-ilcs-205-123",
      "815 Ill. Comp. Stat. 205 (Interest Act); 815 ILCS 123 (Predatory Loan Prevention Act)",
      "https://www.ilga.gov/legislation/ilcs/ilcs3.asp?ActID=2389",
    ),
  },
  {
    id: "lend-usury-us-de",
    family: "lending",
    topic: "usury / interest-rate cap",
    jurisdiction: "us-de",
    state_name: "Delaware",
    posture: "informational",
    headline: "No cap on the contracted rate",
    summary:
      "Delaware sets a legal rate of 5% over the Federal Reserve discount rate only where no rate is specified; for loans of $100,000 or more not secured by a mortgage on the borrower's residence, and broadly where a rate is agreed, there is effectively no usury ceiling. This is why many lenders choose Delaware law.",
    recommendation:
      "A Delaware choice-of-law clause generally removes a usury ceiling for an agreed rate; confirm the choice-of-law is valid for the parties and that no borrower-residence-mortgage limit applies.",
    severity: "info",
    citation: cite(
      "de-6-2301",
      "6 Del. C. §§ 2301, 2306",
      "https://delcode.delaware.gov/title6/c023/index.html",
    ),
  },
  {
    id: "lend-usury-us-ma",
    family: "lending",
    topic: "usury / interest-rate cap",
    jurisdiction: "us-ma",
    state_name: "Massachusetts",
    posture: "informational",
    headline: "Criminal usury at 20% (with notice exception)",
    summary:
      "Massachusetts has no general civil usury cap but makes it criminal usury to charge an effective annual rate above 20% (interest plus expenses), unless the lender files a notice of intent with the Attorney General before making the loan. A criminally-usurious loan may be voided by the court.",
    recommendation:
      "Confirm the all-in effective rate is at or below 20%, or that the lender filed the required Attorney General notice; otherwise the loan risks being criminally usurious and voidable.",
    severity: "info",
    citation: cite(
      "ma-gl-271-49",
      "Mass. Gen. Laws ch. 271, § 49",
      "https://malegislature.gov/Laws/GeneralLaws/PartIV/TitleI/Chapter271/Section49",
    ),
  },
  {
    id: "lend-usury-us-pa",
    family: "lending",
    topic: "usury / interest-rate cap",
    jurisdiction: "us-pa",
    state_name: "Pennsylvania",
    posture: "informational",
    headline: "Cap: 6% legal rate (loans ≤ $50,000)",
    summary:
      "Pennsylvania's Act 6 sets a 6% maximum lawful interest rate on loans of $50,000 or less (with carve-outs for residential mortgages and certain obligations). Business loans above $50,000, and loans by licensed institutions, are broadly exempt. Exceeding the cap forfeits the excess interest and triple damages.",
    recommendation:
      "For a loan of $50,000 or less, confirm the rate is at or below 6% unless an exemption applies; larger commercial loans are generally outside the Act 6 cap.",
    severity: "info",
    citation: cite(
      "pa-41-ps-201",
      "41 Pa. Stat. § 201 et seq. (Act 6 of 1974)",
      "https://www.legis.state.pa.us/cfdocs/legis/LI/uconsCheck.cfm?txtType=HTM&yr=1974&sessInd=0&act=6",
    ),
  },
  {
    id: "lend-usury-us-wa",
    family: "lending",
    topic: "usury / interest-rate cap",
    jurisdiction: "us-wa",
    state_name: "Washington",
    posture: "informational",
    headline: "Cap: greater of 12% or 4% over T-bill rate",
    summary:
      "Washington caps interest at the higher of 12% per year or 4 percentage points above the average 26-week Treasury bill rate, with broad exemptions for loans primarily for business/commercial purposes and regulated lenders. Usury forfeits the interest and adds a penalty of double the interest paid.",
    recommendation:
      "Confirm whether the loan is for a business/commercial purpose (broadly exempt); for covered loans, check the rate against the current 12%-or-T-bill-plus-4% ceiling.",
    severity: "info",
    citation: cite(
      "wa-rcw-19-52",
      "Wash. Rev. Code ch. 19.52",
      "https://app.leg.wa.gov/rcw/default.aspx?cite=19.52",
    ),
  },
  {
    id: "lend-usury-us-co",
    family: "lending",
    topic: "usury / interest-rate cap",
    jurisdiction: "us-co",
    state_name: "Colorado",
    posture: "informational",
    headline: "Cap: 45% civil maximum; consumer-credit limits lower",
    summary:
      "Colorado sets a 45% per-year default maximum where no rate is agreed and treats interest above 45% as criminal usury. The Uniform Consumer Credit Code imposes substantially lower tiered finance-charge caps on consumer loans, and recent legislation further restricts high-cost consumer lending.",
    recommendation:
      "Distinguish a UCCC-governed consumer loan (lower tiered caps) from a commercial loan; in all cases keep the rate below the 45% criminal-usury ceiling.",
    severity: "info",
    citation: cite(
      "co-rev-stat-5-12-103",
      "Colo. Rev. Stat. §§ 5-12-103, 18-15-104; UCCC art. 5-2",
      "https://leg.colorado.gov/sites/default/files/images/olls/crs2023-title-05.pdf",
    ),
  },
];

/** The full curated catalog, ordered by family then id. */
export const STATE_OVERLAYS: readonly StateOverlay[] = [
  ...EMPLOYMENT_NONCOMPETE,
  ...RESIDENTIAL_LEASE_DEPOSIT,
  ...LENDING_USURY,
];

/**
 * Playbook id → overlay family. A document's family is a deterministic
 * function of the matched playbook, so an overlay is selected only when the
 * document is genuinely in a state-sensitive family. Ids mirror the v4
 * employment (`_helpers.ts` EMP_PLAYBOOK_IDS + restrictive-covenant variants)
 * and banking (`BNK_PLAYBOOK_IDS`, the lending subset) rulesets.
 */
const PLAYBOOK_FAMILY: ReadonlyMap<string, OverlayFamily> = new Map([
  // Employment — non-compete enforceability is the dominant state question.
  // `employment-at-will-us` is the served launch playbook most employment
  // documents match; the rest are the v4 specialized employment playbooks.
  ["employment-at-will-us", "employment"],
  ["executive-employment", "employment"],
  ["offer-letter", "employment"],
  ["separation-agreement", "employment"],
  ["employment-restrictive-covenant", "employment"],
  ["ma-restrictive-covenant", "employment"],
  ["piia", "employment"],
  ["employee-handbook", "employment"],
  // Residential lease — security-deposit cap + return window. Gated to the
  // residential lease playbook ONLY; the commercial-lease playbook
  // (`lease-commercial-multitenant`) is deliberately excluded because the
  // deposit-cap statutes are residential-specific.
  ["lease-residential-us", "residential-lease"],
  // Lending — usury caps. The deed-of-trust / UCC-1 / intercreditor /
  // subordination instruments do not themselves set the interest rate, so the
  // usury overlay attaches to the rate-bearing instruments only.
  ["promissory-note", "lending"],
  ["loan-agreement", "lending"],
  ["convertible-note", "lending"],
  ["guaranty", "lending"],
]);

/** Resolve the overlay family for a matched playbook id, if any. */
export function overlayFamilyForPlaybook(playbookId: string): OverlayFamily | undefined {
  return PLAYBOOK_FAMILY.get(playbookId);
}

/**
 * Normalize a governing-law `raw_text` (e.g. "State of California",
 * "Commonwealth of Massachusetts", "New York") to a `us-XX` jurisdiction id.
 * Runtime extraction does not populate `jurisdiction_id` (no DKB lookup is
 * passed), so this map is the resolver. Unknown states return `undefined` —
 * the honest-N/A path.
 */
const STATE_NAME_TO_ID: ReadonlyMap<string, string> = new Map(
  (
    [
      ["alabama", "al"],
      ["alaska", "ak"],
      ["arizona", "az"],
      ["arkansas", "ar"],
      ["california", "ca"],
      ["colorado", "co"],
      ["connecticut", "ct"],
      ["delaware", "de"],
      ["district of columbia", "dc"],
      ["florida", "fl"],
      ["georgia", "ga"],
      ["hawaii", "hi"],
      ["idaho", "id"],
      ["illinois", "il"],
      ["indiana", "in"],
      ["iowa", "ia"],
      ["kansas", "ks"],
      ["kentucky", "ky"],
      ["louisiana", "la"],
      ["maine", "me"],
      ["maryland", "md"],
      ["massachusetts", "ma"],
      ["michigan", "mi"],
      ["minnesota", "mn"],
      ["mississippi", "ms"],
      ["missouri", "mo"],
      ["montana", "mt"],
      ["nebraska", "ne"],
      ["nevada", "nv"],
      ["new hampshire", "nh"],
      ["new jersey", "nj"],
      ["new mexico", "nm"],
      ["new york", "ny"],
      ["north carolina", "nc"],
      ["north dakota", "nd"],
      ["ohio", "oh"],
      ["oklahoma", "ok"],
      ["oregon", "or"],
      ["pennsylvania", "pa"],
      ["rhode island", "ri"],
      ["south carolina", "sc"],
      ["south dakota", "sd"],
      ["tennessee", "tn"],
      ["texas", "tx"],
      ["utah", "ut"],
      ["vermont", "vt"],
      ["virginia", "va"],
      ["washington", "wa"],
      ["west virginia", "wv"],
      ["wisconsin", "wi"],
      ["wyoming", "wy"],
    ] as const
  ).map(([name, abbr]) => [name, `us-${abbr}`]),
);

/**
 * Resolve a `JurisdictionReference` to a `us-XX` id. Prefers an already-
 * normalized `jurisdiction_id` (when a DKB lookup was supplied), else
 * normalizes the raw text. The raw text may carry leading articles
 * ("the State of ...") which the governing-law extractor already strips, but
 * we defensively trim a trailing "law"/"laws" and surrounding whitespace.
 */
function jurisdictionIdOf(ref: JurisdictionReference): string | undefined {
  if (ref.jurisdiction_id && /^us-[a-z]{2}$/.test(ref.jurisdiction_id)) {
    return ref.jurisdiction_id;
  }
  const cleaned = ref.raw_text
    .toLowerCase()
    .replace(/\b(the\s+)?(state|commonwealth)\s+of\s+/g, "")
    .replace(/\s+laws?$/, "")
    .replace(/[^a-z\s]/g, "")
    .replace(/\s+/g, " ")
    .trim();
  return STATE_NAME_TO_ID.get(cleaned);
}

const BY_FAMILY_STATE: ReadonlyMap<string, StateOverlay> = (() => {
  const m = new Map<string, StateOverlay>();
  for (const o of STATE_OVERLAYS) m.set(`${o.family}:${o.jurisdiction}`, o);
  return m;
})();

/**
 * Number of distinct states covered per family — published so the report can
 * state coverage honestly ("non-compete overlays cover 15 states").
 */
export const STATE_OVERLAY_COVERAGE: ReadonlyMap<OverlayFamily, number> = (() => {
  const m = new Map<OverlayFamily, number>();
  for (const o of STATE_OVERLAYS) m.set(o.family, (m.get(o.family) ?? 0) + 1);
  return m;
})();

export type StateOverlayResult = {
  family: OverlayFamily;
  /** Overlays that matched a detected governing-law state, sorted by id. */
  matched: StateOverlay[];
  /** Distinct `us-XX` governing-law states detected in the document, sorted. */
  detected_states: string[];
  /**
   * Detected governing-law states with no overlay node for this family —
   * surfaced so coverage is honest and a gap is never read as a clean pass.
   */
  uncovered_states: string[];
  /** Total states this family's catalog covers (the honest denominator). */
  states_in_catalog: number;
};

/**
 * Select the jurisdiction overlays for a run. Returns `undefined` when the
 * document's family has no overlay catalog (the common case) so callers can
 * skip the section entirely. Pure: same `(playbookId, jurisdictions)` →
 * byte-identical result.
 */
export function selectStateOverlays(
  playbookId: string,
  jurisdictions: ReadonlyArray<JurisdictionReference>,
): StateOverlayResult | undefined {
  const family = overlayFamilyForPlaybook(playbookId);
  if (!family) return undefined;

  // Governing-law clauses are the controlling signal; venue / arbitration-seat
  // do not determine which state's substantive law governs the covenant.
  const detected = new Set<string>();
  for (const ref of jurisdictions) {
    if (ref.clause_kind !== "governing-law") continue;
    const id = jurisdictionIdOf(ref);
    if (id) detected.add(id);
  }
  const detected_states = [...detected].sort();

  const matched: StateOverlay[] = [];
  const uncovered: string[] = [];
  for (const state of detected_states) {
    const overlay = BY_FAMILY_STATE.get(`${family}:${state}`);
    if (overlay) matched.push(overlay);
    else uncovered.push(state);
  }
  matched.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  return {
    family,
    matched,
    detected_states,
    uncovered_states: uncovered,
    states_in_catalog: STATE_OVERLAY_COVERAGE.get(family) ?? 0,
  };
}
