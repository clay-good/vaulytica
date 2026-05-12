/**
 * DPA-US-state ruleset — placeholder.
 *
 * Spec: spec-v3.md §30.
 *
 * Will implement ~25 rules for Data Processing Agreements under US state privacy law,
 * keyed to specific statute paragraphs (e.g., ccpa.1798.140.ag.4 for the
 * no-cross-context-advertising requirement).
 *
 * Coverage: CCPA/CPRA (Cal. Civ. Code § 1798.140(ag)), VCDPA (Va. Code § 59.1-579(B)),
 * CPA (Colo. Rev. Stat. § 6-1-1305), CTDPA (Conn. Gen. Stat. § 42-520),
 * UCPA (Utah Code § 13-61-301), TDPSA (Tex. Bus. & Com. Code § 541.104),
 * OCPA (ORS § 646A.578), DPDPA (6 Del. C. § 12D-107).
 *
 * A rule flags when the contract claims CCPA "Service Provider" status without all
 * required elements; another flags when the strictest multi-state element is not used.
 *
 * Implementation lands in spec-v3.md Step 25.
 */
export const RULES: never[] = [];
