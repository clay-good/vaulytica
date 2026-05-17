/**
 * State trust + will code fetchers (spec-v4.md §13).
 *
 * Surface: sub-domain N (trust / estate / family) — Step 57.
 *
 * Covers a representative set of UPC- and UTC-adopting states. The
 * per-state node carries the execution-formality requirements that the
 * v4 N ruleset's mandatory disclaimer (TEF-NNN) cites.
 */

import type { StatutoryClauseRequirement } from "../../../../src/dkb/v3/types.js";
import { normalizeForHash, pin, type V4Fetcher, type V4FetcherResult } from "./_common.js";

export type StateTrustWillSource = {
  source_id: string;
  jurisdiction: string;
  regulator: string;
  source_url: string;
  effective_date: string;
  requirements: Array<{
    id: string;
    citation: string;
    requirement: string;
    minimum_compliant_text: string;
    detect: RegExp;
  }>;
};

export const STATE_TRUST_WILL_SOURCES: Record<string, StateTrustWillSource> = {
  ca: {
    source_id: "ca-trust-will",
    jurisdiction: "us-ca",
    regulator: "California Probate Code",
    source_url:
      "https://leginfo.legislature.ca.gov/faces/codes_displayText.xhtml?lawCode=PROB&division=4.5.",
    effective_date: "2024-01-01",
    requirements: [
      {
        id: "ca-prob-6110-will-formalities",
        citation: "Cal. Prob. Code § 6110",
        requirement:
          "A will (other than a holographic or statutory will) must be in writing, signed by the testator, and witnessed by at least two persons who are present at the same time and who witnessed either the signing or the testator's acknowledgment of the signature.",
        minimum_compliant_text:
          "This Will is signed by the Testator in the presence of two competent witnesses, who, at the request of the Testator and in his/her presence and in the presence of each other, have subscribed their names hereto, satisfying Cal. Prob. Code § 6110.",
        detect: /(§\s*6110|will|witnessed by at least two)/i,
      },
      {
        id: "ca-prob-15206-trust-formalities",
        citation: "Cal. Prob. Code § 15206",
        requirement:
          "A trust in relation to real property is not valid unless evidenced by a written instrument signed by the trustee or by a written instrument conveying the trust property signed by the settlor.",
        minimum_compliant_text:
          "This Trust is evidenced by this written instrument signed by the Settlor and accepted by the Trustee, satisfying Cal. Prob. Code § 15206 for any trust property consisting of real property.",
        detect: /(§\s*15206|trust.{0,30}real property|written instrument)/i,
      },
    ],
  },
  ny: {
    source_id: "ny-trust-will",
    jurisdiction: "us-ny",
    regulator: "New York Estates, Powers & Trusts Law",
    source_url: "https://www.nysenate.gov/legislation/laws/EPT",
    effective_date: "2024-01-01",
    requirements: [
      {
        id: "ny-ept-3-2.1-will-formalities",
        citation: "N.Y. Est. Powers & Trusts Law § 3-2.1",
        requirement:
          "Every will must be in writing and signed at the end thereof by the testator (or by another person in the testator's name in the testator's presence and by his direction); the testator's signature must be made or acknowledged in the presence of each of at least two attesting witnesses, who attest within one 30-day period.",
        minimum_compliant_text:
          "I, the undersigned Testator, sign this Will at the end thereof, in the presence of each of the two undersigned witnesses, who have, at my request and in my presence and in the presence of each other, attested this Will in conformity with N.Y. Est. Powers & Trusts Law § 3-2.1.",
        detect: /(§\s*3-2\.1|signed at the end|attesting witnesses)/i,
      },
      {
        id: "ny-ept-7-1.17-trust-formalities",
        citation: "N.Y. Est. Powers & Trusts Law § 7-1.17",
        requirement:
          "Every lifetime trust shall be in writing and shall be executed and acknowledged by the initial creator and, unless such creator is the sole trustee, by at least one trustee thereof, in the manner required by the laws of this state for the recording of a conveyance of real property, or by two witnesses.",
        minimum_compliant_text:
          "This Trust is executed and acknowledged by the Settlor and Trustee in the manner required by N.Y. Est. Powers & Trusts Law § 7-1.17 for the recording of a conveyance of real property.",
        detect: /(§\s*7-1\.17|lifetime trust|executed and acknowledged)/i,
      },
    ],
  },
  tx: {
    source_id: "tx-trust-will",
    jurisdiction: "us-tx",
    regulator: "Texas Estates Code",
    source_url: "https://statutes.capitol.texas.gov/Docs/ES/htm/ES.111.htm",
    effective_date: "2024-01-01",
    requirements: [
      {
        id: "tx-est-251-051-will-formalities",
        citation: "Tex. Est. Code § 251.051",
        requirement:
          "Except as otherwise provided by law, a will must be in writing, signed by the testator in person or by another person on behalf of the testator in the testator's presence and at the testator's direction, and attested by two or more credible witnesses who are at least 14 years of age and who subscribe their names to the will in the testator's presence.",
        minimum_compliant_text:
          "The Testator signs this Will in the presence of the two credible witnesses, each at least 14 years of age, who at the Testator's request subscribe their names hereto in the Testator's presence, satisfying Tex. Est. Code § 251.051.",
        detect: /(§\s*251\.051|credible witnesses|at least 14|subscribe their names)/i,
      },
    ],
  },
  fl: {
    source_id: "fl-trust-will",
    jurisdiction: "us-fl",
    regulator: "Florida Statutes",
    source_url: "https://www.flsenate.gov/Laws/Statutes/2024/Chapter732",
    effective_date: "2024-01-01",
    requirements: [
      {
        id: "fl-stat-732-502-will-formalities",
        citation: "Fla. Stat. § 732.502",
        requirement:
          "Every will must be in writing and executed as follows: the testator must sign the will at the end (or have another person sign the testator's name at the testator's direction); the testator's signature must be made or acknowledged in the presence of at least two attesting witnesses; the attesting witnesses must sign the will in the presence of the testator and of each other.",
        minimum_compliant_text:
          "The Testator signs this Will at the end in the presence of the two attesting witnesses, who then sign in the presence of the Testator and of each other, satisfying Fla. Stat. § 732.502.",
        detect: /(§\s*732\.502|attesting witnesses|presence.{0,30}each other)/i,
      },
    ],
  },
  il: {
    source_id: "il-trust-will",
    jurisdiction: "us-il",
    regulator: "Illinois Probate Act",
    source_url: "https://www.ilga.gov/legislation/ilcs/ilcs3.asp?ActID=2104",
    effective_date: "2024-01-01",
    requirements: [
      {
        id: "il-755-5-4-3-will-formalities",
        citation: "755 ILCS 5/4-3",
        requirement:
          "Every will shall be in writing, signed by the testator or by some person in his presence and by his direction, and attested in the presence of the testator by two or more credible witnesses.",
        minimum_compliant_text:
          "This Will is in writing, signed by the Testator, and attested in the presence of the Testator by the two undersigned credible witnesses, as required by 755 ILCS 5/4-3.",
        detect: /(§?\s*755 ILCS 5\/4-3|credible witnesses|in writing.{0,30}signed by the testator)/i,
      },
    ],
  },
};

export function parseStateTrustWill(
  src: StateTrustWillSource,
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
      applies_to_document_types: ["will", "trust", "trust-amendment"],
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

export function makeStateTrustWillFetcher(src: StateTrustWillSource): V4Fetcher {
  return async (ctx): Promise<V4FetcherResult> => {
    const text = ctx.reader.read(src.source_url);
    if (!text) throw new Error(`${src.source_id}: missing snapshot for ${src.source_url}`);
    return { source_id: ctx.source_id, nodes: parseStateTrustWill(src, text, ctx.nowIso) };
  };
}

export const STATE_TRUST_WILL_FETCHERS: Record<string, V4Fetcher> = Object.fromEntries(
  Object.values(STATE_TRUST_WILL_SOURCES).map((s) => [
    s.source_id,
    makeStateTrustWillFetcher(s),
  ]),
);
