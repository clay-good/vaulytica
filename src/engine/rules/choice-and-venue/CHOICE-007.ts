import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

// `\b` boundaries so "lease" does not match inside "Release" — a routine B2B /
// settlement "Release of Claims" heading is not a consumer contract, and the
// class-action-waiver warning is scoped to genuinely consumer-facing documents.
const CONSUMER_HEADINGS = /\b(lease|residential|terms\s+of\s+service|employment|consumer)\b/i;

/** CHOICE-007 — Class-action waiver in consumer-facing contract (warning). */
export const rule: Rule = {
  id: "CHOICE-007",
  version: "1.1.0",
  name: "Class-action waiver in consumer contract",
  category: "choice-and-venue",
  default_severity: "warning",
  description: "Flags class-action waivers in consumer-facing contracts.",
  dkb_citations: ["stat-frcp-rule-23", "stat-9-usc-2"],
  check(ctx: RuleContext): Finding | null {
    const isConsumer = ctx.tree.sections.some((s) => CONSUMER_HEADINGS.test(s.heading));
    if (!isConsumer) return null;
    const hit = firstParagraphMatch(
      ctx,
      /\bclass\s+(?:action\s+)?waiver\b|\bwaive[\s\S]{0,40}class\s+action\b/i,
    );
    if (!hit) return null;
    // A contract that PRESERVES class rights trips the same words — "you do NOT
    // waive your right to a class action", "NOTHING herein waives …", "this
    // agreement does NOT contain a class action waiver", "no class action
    // waiver". Skip when a negation governs the phrase: within ~12 chars
    // immediately before the match, or a sentence-leading "nothing" / "neither".
    // Scoped so an unrelated same-sentence negation ("you may not get a refund,
    // and you agree to a class action waiver") still fires.
    const before = hit.text.slice(0, hit.match.index);
    const sentence = before.slice(
      Math.max(before.lastIndexOf("."), before.lastIndexOf(";"), before.lastIndexOf("\n")) + 1,
    );
    if (
      /\b(?:not|never|no|without)\b[^.;]{0,12}$/i.test(before) ||
      /^\s*(?:nothing|neither)\b/i.test(sentence)
    )
      return null;
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
