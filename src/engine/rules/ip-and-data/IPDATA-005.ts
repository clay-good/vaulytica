import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, topPosition } from "../_helpers.js";

/** IPDATA-005 — GDPR / CCPA / HIPAA reference (info). */
export const rule: Rule = {
  id: "IPDATA-005",
  version: "1.3.0",
  name: "Data regime reference (GDPR / CCPA / HIPAA)",
  category: "ip-and-data",
  default_severity: "info",
  description:
    "Flags data-heavy contracts that lack references to the applicable data-protection regime.",
  dkb_citations: ["stat-gdpr-art-28", "stat-ccpa-1798-140", "stat-45-cfr-164-504"],
  check(ctx: RuleContext): Finding | null {
    const personalData = firstParagraphMatch(
      ctx,
      /\bpersonal\s+(?:data|information)\b|\bprotected\s+health\s+information\b|\bPHI\b/i,
    );
    if (!personalData) return null;
    if (
      firstParagraphMatch(
        ctx,
        // The regime list must track the current landscape: CPRA is now the
        // operative California law, and a Data Processing Agreement / the
        // Standard Contractual Clauses are themselves the governing instrument
        // (as a BAA is for HIPAA). LGPD / PIPEDA / PIPL cover non-US personal
        // data. "SCCs" (plural / spelled) is used, not the bare "SCC", which
        // also abbreviates the Stockholm Chamber of Commerce. Because this is an
        // ABSENCE detector, a regime it does not recognize is a FALSE POSITIVE
        // ("regime missing" over a contract that names one) — so the US sector
        // laws (GLBA, FERPA, COPPA), the leading state comprehensive laws
        // (VCDPA, Colorado Privacy Act), and the current EU→US transfer
        // instruments (Data Privacy Framework, Privacy Shield) are recognized.
        // All are unambiguous data-protection references (unlike a bare "CPA").
        /\b(?:GDPR|General\s+Data\s+Protection\s+Regulation|CCPA|California\s+Consumer\s+Privacy\s+Act|CPRA|California\s+Privacy\s+Rights\s+Act|HIPAA|Business\s+Associate\s+Agreement|BAA|Covered\s+Entit(?:y|ies)|45\s+C\.?F\.?R\.?\s*(?:§\s*)?164|GLBA|Gramm[- ]Leach[- ]Bliley|FERPA|COPPA|VCDPA|Virginia\s+Consumer\s+Data\s+Protection\s+Act|Colorado\s+Privacy\s+Act|Data\s+Privacy\s+Framework|Privacy\s+Shield|LGPD|PIPEDA|PIPL|Data\s+Processing\s+(?:Agreement|Addendum)|Standard\s+Contractual\s+Clauses|SCCs)\b/i,
      )
    )
      return null;
    return emit(ctx, rule, {
      title: "Data-regime references missing",
      description: "Contract references personal data but does not cite GDPR / CCPA / HIPAA.",
      excerpt: personalData.text.slice(0, 240),
      explanation:
        "When a contract touches personal data, citing the governing regime (GDPR Art. 28, CCPA, HIPAA 45 CFR 164.504) makes obligations explicit and discoverable.",
      position: personalData.position ?? topPosition(ctx),
    });
  },
};
