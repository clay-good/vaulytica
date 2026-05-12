import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

const CONSUMER_HEADINGS = /(lease|residential|terms\s+of\s+service|employment|consumer)/i;

/** CHOICE-007 — Class-action waiver in consumer-facing contract (warning). */
export const rule: Rule = {
  id: "CHOICE-007",
  version: "1.0.0",
  name: "Class-action waiver in consumer contract",
  category: "choice-and-venue",
  default_severity: "warning",
  description: "Flags class-action waivers in consumer-facing contracts.",
  dkb_citations: ["stat-frcp-rule-23", "stat-9-usc-2"],
  check(ctx: RuleContext): Finding | null {
    const isConsumer = ctx.tree.sections.some((s) => CONSUMER_HEADINGS.test(s.heading));
    if (!isConsumer) return null;
    const hit = firstParagraphMatch(ctx, /\bclass\s+(?:action\s+)?waiver\b|\bwaive[\s\S]{0,40}class\s+action\b/i);
    if (!hit) return null;
    return emit(ctx, rule, {
      title: "Class-action waiver in a consumer-facing contract",
      description: "A class-action waiver appears in a consumer-context contract.",
      excerpt: hit.text.slice(0, 280),
      explanation:
        "Class-action waivers are enforceable in many jurisdictions under AT&T Mobility v. Concepcion, but they materially change the economics of small claims. Flag for review when the agreement is consumer-facing.",
      position: hit.position,
    });
  },
};
