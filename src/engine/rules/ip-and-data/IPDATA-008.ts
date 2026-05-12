import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit } from "../_helpers.js";
import { forEachParagraph } from "../../../extract/walk.js";

/**
 * IPDATA-008 — Cross-border data transfer without safeguard
 * (warning, ip-and-data).
 *
 * Fires when the contract authorizes data transfers outside the
 * data subject's jurisdiction (typical phrasing: `transfer outside
 * the EU/EEA/UK`, `transferred to the United States`, `processed
 * outside [your region]`) but does **not** reference a recognized
 * transfer safeguard:
 *
 *   - Standard Contractual Clauses (SCCs) — EU 2021/914, UK IDTA
 *   - Adequacy decision
 *   - Binding Corporate Rules (BCRs)
 *   - Data Privacy Framework (US-EU DPF)
 *
 * The rule is conservative: a contract that references *any* of
 * those safeguards by name in the same document stays silent. This
 * catches the most common GDPR Article 46 drafting accident — a
 * vendor with US/Indian/Philippine operations that mentions
 * cross-border transfer but forgot the transfer mechanism.
 */
export const rule: Rule = {
  id: "IPDATA-008",
  version: "1.0.0",
  name: "Cross-border data transfer without safeguard",
  category: "ip-and-data",
  default_severity: "warning",
  description:
    "Fires when cross-border data-transfer language appears without referencing SCCs, BCRs, an adequacy decision, or DPF.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    type Hit = { sectionId: string; start: number; end: number; raw: string };
    let transferHit: Hit | null = null;
    let hasSafeguard = false;

    const TRANSFER =
      /\b(?:transfer(?:red|s|ring)?\s+[^.]{0,60}?(?:to|outside|across\s+borders?)\s+(?:the\s+)?(?:EU|EEA|UK|United\s+Kingdom|United\s+States|US\b)|cross[-\s]?border\s+(?:transfer|processing|flow)|international\s+(?:data\s+)?transfer|(?:processed|process(?:es|ing))\s+(?:outside|in)\s+(?:the\s+)?(?:United\s+States|United\s+Kingdom|US\b|EU|EEA|UK|India|Philippines|third\s+countr)|outside\s+(?:the\s+)?(?:EEA|EU|UK|United\s+Kingdom))/i;
    const SAFEGUARD =
      /\b(?:standard\s+contractual\s+clauses|SCCs?|binding\s+corporate\s+rules|BCRs?|adequacy\s+decision|data\s+privacy\s+framework|DPF|IDTA|article\s+46|chapter\s+v\s+of\s+the\s+gdpr)\b/i;

    forEachParagraph(ctx.tree, (p) => {
      if (!transferHit) {
        const m = TRANSFER.exec(p.text);
        if (m) {
          transferHit = {
            sectionId: p.section.id,
            start: p.start + m.index,
            end: p.start + m.index + m[0].length,
            raw: m[0],
          };
        }
      }
      if (SAFEGUARD.test(p.text)) hasSafeguard = true;
    });

    if (!transferHit) return null;
    if (hasSafeguard) return null;
    const hit: Hit = transferHit;
    return emit(ctx, rule, {
      title: "Cross-border data transfer without safeguard reference",
      description: `The contract authorizes cross-border data transfer (\`${hit.raw}\`) but does not reference SCCs, BCRs, an adequacy decision, or the Data Privacy Framework.`,
      excerpt: hit.raw,
      explanation:
        "GDPR Article 46 (and the UK GDPR analogue) requires a documented transfer mechanism for personal data leaving the EEA/UK. Common mechanisms are EU Standard Contractual Clauses (Commission Decision 2021/914), Binding Corporate Rules, an adequacy decision, or — for US transfers — the EU-US Data Privacy Framework. A contract that authorizes cross-border transfer without naming a mechanism leaves the data exporter exposed to enforcement.",
      recommendation:
        "Add an explicit reference to the applicable transfer mechanism. For US-based vendors, the EU-US Data Privacy Framework (if certified) or 2021 SCCs are the most defensible defaults.",
      position: { section_id: hit.sectionId, start: hit.start, end: hit.end },
    });
  },
};
