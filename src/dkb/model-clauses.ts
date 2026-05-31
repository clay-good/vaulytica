/**
 * Model-clause references (spec-v6 Part IV, Steps 95–96).
 *
 * The most common follow-up to "this clause is defective" is "so what
 * should it say?" Vaulytica does **not** draft. The posture-clean adjacent
 * thing it can do is point to an *existing public model clause* — "what
 * good looks like" — with full attribution, source URL, and license. It is
 * a reference, never a generated redline: each entry is a pointer into a
 * real, publicly-licensed model agreement plus a neutral Vaulytica summary
 * of the structural features that model exhibits. We deliberately do **not**
 * reproduce verbatim clause text we cannot accurately attribute; a model
 * reference is honest about being a pointer, not a quote — see the bright
 * line in spec-v6 §14.
 *
 * This catalog is the runtime source of truth (the DKB runtime loader does
 * not carry v3/v4 nodes; rules supply their own citations). It is a frozen,
 * hand-curated module — fully deterministic, validated against
 * {@link ModelClauseSchema} by `model-clauses.test.ts`. Provenance: every
 * referenced catalog (Common Paper, Bonterms, the European Commission SCCs)
 * is already pulled by the DKB build pipeline (`dkb/build/sources.yaml`) or
 * is a public-domain government work; `tools/build-model-clauses.ts`
 * documents how the references are regenerated.
 *
 * Coverage is honest (spec-v6 §15): only rules with a genuine public model
 * reference get one. {@link MODEL_CLAUSE_COVERAGE} publishes the count, the
 * same anti-silent-truncation discipline as v5 §10 — the report never
 * implies broader coverage than exists.
 */

import { z } from "zod";
import type { SourceCitation } from "./types.js";

/** ISO 8601 date the public sources below were last checked. A fixed
 * constant (never wall-clock) so the catalog and every report that embeds
 * it stay byte-identical across machines and runs. */
const CURATED_AT = "2026-05-31";

export type ModelClauseReference = {
  /** Stable id within the catalog, e.g. `cp-csa-limitation-of-liability`. */
  id: string;
  /** Human-readable clause title. */
  title: string;
  /** Originating public catalog, e.g. `Common Paper`, `Bonterms`. */
  source_catalog: string;
  /**
   * Vaulytica's neutral, plain-language description of the structural
   * features the referenced public model exhibits. This is Vaulytica's
   * summary of a public document — explicitly **not** a verbatim quote and
   * **not** drafting advice tailored to the user's contract.
   */
  summary: string;
  /** Source attribution: real public URL, license, and attribution string. */
  source: SourceCitation;
  /** Rule ids this model clause is the reference for. Sorted, non-empty. */
  applies_to_rules: string[];
};

export const ModelClauseSchema = z.object({
  id: z.string().min(1),
  title: z.string().min(1),
  source_catalog: z.string().min(1),
  summary: z.string().min(1),
  source: z.object({
    id: z.string().min(1),
    source: z.string().min(1),
    source_url: z.string().url(),
    retrieved_at: z.string().min(1),
    source_published_at: z.string().optional(),
    license: z.string().min(1),
    license_url: z.string().url(),
    attribution: z.string().optional(),
  }),
  applies_to_rules: z.array(z.string().min(1)).min(1),
});

const COMMON_PAPER_LICENSE = {
  license: "CC-BY-4.0",
  license_url: "https://creativecommons.org/licenses/by/4.0/",
  attribution: "Common Paper Standard Agreements, CC BY 4.0",
} as const;

const BONTERMS_LICENSE = {
  license: "Bonterms Standard License",
  license_url: "https://bonterms.com/license/",
  attribution: "Bonterms Standard Forms, used under the Bonterms Standard License",
} as const;

/**
 * The curated catalog. Each entry references a real, publicly-licensed model
 * agreement. Ordered by id; the order is a maintenance convenience.
 */
export const MODEL_CLAUSES: readonly ModelClauseReference[] = [
  {
    id: "cp-csa-limitation-of-liability",
    title: "Mutual limitation of liability with a stated cap and super-cap",
    source_catalog: "Common Paper",
    summary:
      "The Common Paper Cloud Service Agreement caps each party's aggregate liability at a stated figure tied to fees (commonly 12 months of fees on the cover page) and excludes indirect, incidental, and consequential damages — then carves out a higher 'super cap' (or uncapped exposure) for confidentiality breaches, indemnification, and a party's gross negligence or willful misconduct. The cap is reciprocal rather than one-sided, and the carve-outs are listed explicitly rather than buried.",
    source: {
      id: "cp-csa-limitation-of-liability",
      source: "Common Paper Cloud Service Agreement — Limitations on Liability",
      source_url: "https://commonpaper.com/standards/cloud-service-agreement/",
      retrieved_at: CURATED_AT,
      ...COMMON_PAPER_LICENSE,
    },
    applies_to_rules: ["RISK-004", "RISK-005", "RISK-009", "RISK-015"],
  },
  {
    id: "cp-csa-exclusion-of-damages",
    title: "Mutual exclusion of indirect and consequential damages",
    source_catalog: "Common Paper",
    summary:
      "The Common Paper Cloud Service Agreement excludes indirect, incidental, special, cover, and consequential damages for both parties symmetrically, while preserving direct damages up to the liability cap. A balanced waiver applies to both sides and is paired with the liability cap rather than standing alone as a one-way disclaimer.",
    source: {
      id: "cp-csa-exclusion-of-damages",
      source: "Common Paper Cloud Service Agreement — Exclusion of Damages",
      source_url: "https://commonpaper.com/standards/cloud-service-agreement/",
      retrieved_at: CURATED_AT,
      ...COMMON_PAPER_LICENSE,
    },
    applies_to_rules: ["RISK-007", "RISK-008"],
  },
  {
    id: "cp-csa-indemnification",
    title: "Reciprocal indemnification with defined procedure",
    source_catalog: "Common Paper",
    summary:
      "The Common Paper Cloud Service Agreement provides reciprocal indemnities (the provider indemnifies for third-party IP-infringement claims; the customer indemnifies for misuse claims) and specifies the indemnification procedure: prompt notice, control of defense, and a duty to cooperate. Indemnity obligations sit above the general liability cap, and the IP indemnity includes standard mitigation options (procure a license, modify, or refund).",
    source: {
      id: "cp-csa-indemnification",
      source: "Common Paper Cloud Service Agreement — Indemnification",
      source_url: "https://commonpaper.com/standards/cloud-service-agreement/",
      retrieved_at: CURATED_AT,
      ...COMMON_PAPER_LICENSE,
    },
    applies_to_rules: ["RISK-001", "RISK-002", "RISK-011", "RISK-012"],
  },
  {
    id: "cp-csa-term-termination",
    title: "Symmetric term, termination for cause, and effect of termination",
    source_catalog: "Common Paper",
    summary:
      "The Common Paper Cloud Service Agreement states the subscription term on the cover page, permits either party to terminate for an uncured material breach after written notice and a stated cure period, and specifies the effect of termination (access ends, fees through the effective date remain due, and each party returns or deletes the other's confidential information).",
    source: {
      id: "cp-csa-term-termination",
      source: "Common Paper Cloud Service Agreement — Term and Termination",
      source_url: "https://commonpaper.com/standards/cloud-service-agreement/",
      retrieved_at: CURATED_AT,
      ...COMMON_PAPER_LICENSE,
    },
    applies_to_rules: ["TERM-001", "TERM-002", "TERM-005"],
  },
  {
    id: "cp-csa-survival",
    title: "Explicit survival list",
    source_catalog: "Common Paper",
    summary:
      "The Common Paper Cloud Service Agreement enumerates the sections that survive termination — confidentiality, limitations of liability, indemnification, payment of accrued fees, and governing law — rather than relying on a vague 'provisions that by their nature should survive' formulation alone.",
    source: {
      id: "cp-csa-survival",
      source: "Common Paper Cloud Service Agreement — Survival",
      source_url: "https://commonpaper.com/standards/cloud-service-agreement/",
      retrieved_at: CURATED_AT,
      ...COMMON_PAPER_LICENSE,
    },
    applies_to_rules: ["TEMP-006", "TEMP-012"],
  },
  {
    id: "cp-csa-proprietary-rights",
    title: "IP ownership with pre-existing-IP carve-out",
    source_catalog: "Common Paper",
    summary:
      "The Common Paper Cloud Service Agreement allocates ownership cleanly: each party keeps its pre-existing intellectual property, the provider owns the service and any improvements, the customer owns its data, and feedback is licensed back on a non-exclusive basis. Ownership is stated rather than left implicit, and the customer-data carve-out is explicit.",
    source: {
      id: "cp-csa-proprietary-rights",
      source: "Common Paper Cloud Service Agreement — Proprietary Rights",
      source_url: "https://commonpaper.com/standards/cloud-service-agreement/",
      retrieved_at: CURATED_AT,
      ...COMMON_PAPER_LICENSE,
    },
    applies_to_rules: ["IPDATA-001", "IPDATA-002", "IPDATA-010"],
  },
  {
    id: "cp-mnda-confidentiality",
    title: "Mutual confidentiality with a defined term",
    source_catalog: "Common Paper",
    summary:
      "The Common Paper Mutual NDA defines confidential information, obligates both parties symmetrically to protect it, lists the standard exceptions (already known, independently developed, publicly available, lawfully received), and states a definite confidentiality period on the cover page rather than leaving the duration open-ended. It avoids a residuals clause that would silently undercut the confidentiality obligation.",
    source: {
      id: "cp-mnda-confidentiality",
      source: "Common Paper Mutual NDA",
      source_url: "https://commonpaper.com/standards/mutual-nda/",
      retrieved_at: CURATED_AT,
      ...COMMON_PAPER_LICENSE,
    },
    applies_to_rules: ["RISK-014", "OBLI-009"],
  },
  {
    id: "bonterms-cloud-force-majeure",
    title: "Balanced force-majeure excuse",
    source_catalog: "Bonterms",
    summary:
      "The Bonterms Standard Cloud Terms excuse a party's non-performance for events beyond its reasonable control, require prompt notice and reasonable mitigation, and — importantly — do not excuse payment obligations or allow indefinite suspension: a prolonged force-majeure event gives the other party a termination right. The clause applies to both parties.",
    source: {
      id: "bonterms-cloud-force-majeure",
      source: "Bonterms Standard Cloud Terms — Force Majeure",
      source_url: "https://bonterms.com/forms/cloud-terms/",
      retrieved_at: CURATED_AT,
      ...BONTERMS_LICENSE,
    },
    applies_to_rules: ["RISK-013"],
  },
  {
    id: "bonterms-cloud-governing-law",
    title: "Single, named governing law and venue",
    source_catalog: "Bonterms",
    summary:
      "The Bonterms Standard Cloud Terms designate a single governing law and an exclusive venue on the cover page, naming a specific US state (its internal law, excluding conflict-of-laws rules) rather than leaving the choice silent or splitting governing law from venue in a way that invites a forum dispute.",
    source: {
      id: "bonterms-cloud-governing-law",
      source: "Bonterms Standard Cloud Terms — Governing Law and Venue",
      source_url: "https://bonterms.com/forms/cloud-terms/",
      retrieved_at: CURATED_AT,
      ...BONTERMS_LICENSE,
    },
    applies_to_rules: ["CHOICE-001", "CHOICE-002"],
  },
  {
    id: "eu-scc-data-transfer",
    title: "Standard Contractual Clauses for international data transfer",
    source_catalog: "European Commission",
    summary:
      "The European Commission's 2021 Standard Contractual Clauses (Implementing Decision (EU) 2021/914) are the recognized safeguard for transferring personal data out of the EEA to a third country without an adequacy decision. They are modular (controller-to-processor, processor-to-processor, etc.); a compliant cross-border transfer clause incorporates the applicable SCC module by reference rather than leaving the transfer mechanism unspecified.",
    source: {
      id: "eu-scc-data-transfer",
      source: "Commission Implementing Decision (EU) 2021/914 — Standard Contractual Clauses",
      source_url: "https://eur-lex.europa.eu/eli/dec_impl/2021/914/oj",
      retrieved_at: CURATED_AT,
      source_published_at: "2021-06-07",
      license: "© European Union, reuse authorised (Decision 2011/833/EU)",
      license_url: "https://eur-lex.europa.eu/content/legal-notice/legal-notice.html",
      attribution: "© European Union, https://eur-lex.europa.eu/, 1998–2026",
    },
    applies_to_rules: ["IPDATA-008"],
  },
];

/** rule id → model-clause reference. Built once; a rule maps to at most one. */
const BY_RULE: ReadonlyMap<string, ModelClauseReference> = (() => {
  const m = new Map<string, ModelClauseReference>();
  for (const mc of MODEL_CLAUSES) {
    for (const ruleId of mc.applies_to_rules) {
      // First mapping wins; duplicates are a catalog error caught by the test.
      if (!m.has(ruleId)) m.set(ruleId, mc);
    }
  }
  return m;
})();

/** Look up the public model-clause reference for a rule id, if any. */
export function modelClauseForRule(ruleId: string): ModelClauseReference | undefined {
  return BY_RULE.get(ruleId);
}

/**
 * Published coverage (spec-v6 §15). `rules_with_reference` is the number of
 * distinct catalog rules that carry a model-clause reference; `model_clauses`
 * is the number of distinct public model clauses in the catalog. The report
 * surfaces these so the reader can see exactly how much of the catalog is
 * covered — never implying more.
 */
export const MODEL_CLAUSE_COVERAGE: {
  readonly rules_with_reference: number;
  readonly model_clauses: number;
} = {
  rules_with_reference: BY_RULE.size,
  model_clauses: MODEL_CLAUSES.length,
};
