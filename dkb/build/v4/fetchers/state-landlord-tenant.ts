/**
 * State landlord-tenant statute fetchers (spec-v4.md §13).
 *
 * Top-five-by-population states are vendored; the remaining five from
 * the spec's "top 10" list are scaffolded with a `detect` regex and
 * can be activated by adding a snapshot at a future build. Each emits
 * a `statutory_clause_requirement` node for E.* (residential lease)
 * findings.
 *
 * Surface: sub-domain E (real estate) — Steps 48.
 */

import type { StatutoryClauseRequirement } from "../../../../src/dkb/v3/types.js";
import { normalizeForHash, pin, type V4Fetcher, type V4FetcherResult } from "./_common.js";

export type StateLandlordTenantSource = {
  source_id: string;
  jurisdiction: string;
  regulator: string;
  source_url: string;
  citation_root: string;
  effective_date: string;
  requirements: Array<{
    id: string;
    citation: string;
    requirement: string;
    minimum_compliant_text: string;
    detect: RegExp;
  }>;
};

export const STATE_LANDLORD_TENANT_SOURCES: Record<string, StateLandlordTenantSource> = {
  ca: {
    source_id: "ca-landlord-tenant",
    jurisdiction: "us-ca",
    regulator: "California Civil Code",
    source_url:
      "https://leginfo.legislature.ca.gov/faces/codes_displayText.xhtml?lawCode=CIV&division=3.&title=5.&part=4.&chapter=2.",
    citation_root: "Cal. Civ. Code § 1940 et seq.",
    effective_date: "2024-01-01",
    requirements: [
      {
        id: "ca-civ-1950.5-security-deposit",
        citation: "Cal. Civ. Code § 1950.5",
        requirement:
          "Security deposit for an unfurnished unit may not exceed two months' rent (one month if the landlord is a small landlord per AB 12 / SB 1182, eff. 2024-07-01); landlord must return any unused portion with an itemized statement within 21 days of termination.",
        minimum_compliant_text:
          "Tenant shall pay a security deposit not to exceed [one / two] months' rent, which Landlord shall return, with any itemized deductions, within 21 days after termination of the tenancy pursuant to Cal. Civ. Code § 1950.5.",
        detect: /(security deposit|cal\.?\s*civ.{0,30}1950\.5|return.{0,40}21 days)/i,
      },
      {
        id: "ca-civ-1942-habitability",
        citation: "Cal. Civ. Code §§ 1941, 1942",
        requirement:
          "Landlord must maintain rental premises in habitable condition; tenant may repair defects affecting habitability and deduct the cost (capped at one month's rent) from rent if landlord fails to repair after reasonable notice.",
        minimum_compliant_text:
          "Landlord shall maintain the Premises in a habitable condition as required by Cal. Civ. Code §§ 1941, 1941.1, and 1942; if Landlord fails to do so after reasonable notice from Tenant, Tenant may exercise the statutory repair-and-deduct remedy.",
        detect: /(habitab|implied warranty of habitability|repair.{0,20}deduct)/i,
      },
    ],
  },
  ny: {
    source_id: "ny-landlord-tenant",
    jurisdiction: "us-ny",
    regulator: "New York Real Property Law",
    source_url: "https://www.nysenate.gov/legislation/laws/RPP/A7",
    citation_root: "N.Y. Real Prop. Law Art. 7",
    effective_date: "2024-01-01",
    requirements: [
      {
        id: "ny-rpl-235-b-warranty-habitability",
        citation: "N.Y. Real Prop. Law § 235-b",
        requirement:
          "Every written or oral residential lease contains an implied warranty of habitability — that the premises and all common areas are fit for human habitation and that occupants will not be subjected to conditions dangerous to life, health, or safety. The warranty cannot be waived.",
        minimum_compliant_text:
          "This Lease incorporates the non-waivable implied warranty of habitability under N.Y. Real Prop. Law § 235-b. Landlord shall maintain the Premises in conditions fit for human habitation.",
        detect: /(warranty of habitability|§\s*235-b|fit for human habitation)/i,
      },
      {
        id: "ny-gol-7-103-security-deposit",
        citation: "N.Y. Gen. Oblig. Law § 7-103",
        requirement:
          "Security deposit must be held in trust by landlord; landlords of buildings with six or more units must deposit in an interest-bearing account at the prevailing rate and remit interest (less 1% administrative fee) to tenant.",
        minimum_compliant_text:
          "Any security deposit shall be held in trust pursuant to N.Y. Gen. Oblig. Law § 7-103; for buildings with six or more units, Landlord shall deposit the security in an interest-bearing account and remit interest annually to Tenant.",
        detect: /(security deposit|§\s*7-103|interest-bearing)/i,
      },
    ],
  },
  tx: {
    source_id: "tx-landlord-tenant",
    jurisdiction: "us-tx",
    regulator: "Texas Property Code",
    source_url: "https://statutes.capitol.texas.gov/Docs/PR/htm/PR.92.htm",
    citation_root: "Tex. Prop. Code ch. 92",
    effective_date: "2023-09-01",
    requirements: [
      {
        id: "tx-prop-92-103-security-deposit",
        citation: "Tex. Prop. Code § 92.103",
        requirement:
          "Landlord must refund any security deposit, with an itemized statement of deductions, not later than the 30th day after the date the tenant surrenders the premises.",
        minimum_compliant_text:
          "Landlord shall refund the security deposit, less any lawful deductions itemized in a written statement, within 30 days after Tenant surrenders the Premises and provides a forwarding address, as required by Tex. Prop. Code § 92.103.",
        detect: /(security deposit|§\s*92\.103|30.{0,10}day)/i,
      },
      {
        id: "tx-prop-92-052-repair-duty",
        citation: "Tex. Prop. Code § 92.052",
        requirement:
          "Landlord shall make a diligent effort to repair or remedy a condition if the tenant specifies the condition in a notice, is not delinquent in rent at the time notice is given, and the condition materially affects the physical health or safety of an ordinary tenant.",
        minimum_compliant_text:
          "Upon receipt of written notice from Tenant specifying a condition that materially affects the physical health or safety of an ordinary tenant, Landlord shall make a diligent effort to repair or remedy the condition as required by Tex. Prop. Code § 92.052.",
        detect: /(repair|§\s*92\.052|diligent effort)/i,
      },
    ],
  },
  fl: {
    source_id: "fl-landlord-tenant",
    jurisdiction: "us-fl",
    regulator: "Florida Statutes",
    source_url:
      "http://www.leg.state.fl.us/statutes/index.cfm?App_mode=Display_Statute&URL=0000-0099/0083/0083.html",
    citation_root: "Fla. Stat. ch. 83",
    effective_date: "2023-07-01",
    requirements: [
      {
        id: "fl-stat-83-49-security-deposit",
        citation: "Fla. Stat. § 83.49",
        requirement:
          "Landlord must hold security deposit in a Florida bank account or post a surety bond; within 15 days after tenant vacates, landlord shall return deposit, or, if making a claim, give written notice within 30 days of the intent to impose a claim.",
        minimum_compliant_text:
          "Landlord shall hold any security deposit in accordance with Fla. Stat. § 83.49 and shall return the deposit within 15 days after Tenant vacates or, if making a claim, give written notice within 30 days as required by § 83.49(3).",
        detect: /(security deposit|§\s*83\.49|return.{0,15}15 days)/i,
      },
    ],
  },
  il: {
    source_id: "il-landlord-tenant",
    jurisdiction: "us-il",
    regulator: "Illinois Compiled Statutes",
    source_url: "https://www.ilga.gov/legislation/ilcs/ilcs3.asp?ActID=2200",
    citation_root: "765 ILCS 710 (Security Deposit Return Act)",
    effective_date: "2023-01-01",
    requirements: [
      {
        id: "il-765-710-deposit-return",
        citation: "765 ILCS 710/1",
        requirement:
          "Lessor of residential real property containing 5 or more units must return security deposit, or furnish itemized statement of damages, within 30 days after tenant vacates; failure entitles tenant to twice the deposit plus attorneys' fees.",
        minimum_compliant_text:
          "Landlord shall return any security deposit or furnish an itemized statement of damages within 30 days after Tenant vacates, as required by 765 ILCS 710/1; failure shall entitle Tenant to twice the deposit plus reasonable attorneys' fees.",
        detect: /(security deposit|§?\s*765 ILCS 710|30 days)/i,
      },
    ],
  },
};

export function parseStateLandlordTenant(
  src: StateLandlordTenantSource,
  text: string,
  nowIso: string,
): StatutoryClauseRequirement[] {
  const normalized = normalizeForHash(text);
  return src.requirements
    .filter((r) => r.detect.test(normalized))
    .map((r) => ({
      id: r.id,
      node_type: "statutory_clause_requirement",
      dkb_node_version: 1,
      dkb_node_last_validated_at: nowIso,
      regulator: src.regulator,
      jurisdiction: src.jurisdiction,
      authority: r.citation,
      citation: r.citation,
      effective_date: src.effective_date,
      requirement: r.requirement,
      minimum_compliant_text: r.minimum_compliant_text,
      applies_to_document_types: ["residential-lease"],
      cites: [
        pin({
          authority: r.citation,
          citation: r.citation,
          source_url: src.source_url,
          fetched_at: nowIso,
          text,
        }),
      ],
    }));
}

export function makeStateLandlordTenantFetcher(src: StateLandlordTenantSource): V4Fetcher {
  return async (ctx): Promise<V4FetcherResult> => {
    const text = ctx.reader.read(src.source_url);
    if (!text) throw new Error(`${src.source_id}: missing snapshot for ${src.source_url}`);
    return { source_id: ctx.source_id, nodes: parseStateLandlordTenant(src, text, ctx.nowIso) };
  };
}

export const STATE_LANDLORD_TENANT_FETCHERS: Record<string, V4Fetcher> = Object.fromEntries(
  Object.values(STATE_LANDLORD_TENANT_SOURCES).map((s) => [
    s.source_id,
    makeStateLandlordTenantFetcher(s),
  ]),
);
