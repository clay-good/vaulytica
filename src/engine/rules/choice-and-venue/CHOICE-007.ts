import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, clauseStartBefore } from "../_helpers.js";

// `\b` boundaries so "lease" does not match inside "Release" — a routine B2B /
// settlement "Release of Claims" heading is not a consumer contract, and the
// class-action-waiver warning is scoped to genuinely consumer-facing documents.
const CONSUMER_HEADINGS = /\b(lease|residential|terms\s+of\s+service|employment|consumer)\b/i;

/** CHOICE-007 — Class-action waiver in consumer-facing contract (warning). */
export const rule: Rule = {
  id: "CHOICE-007",
  version: "1.3.0",
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
      // v1.2.0 widens the active window from 40 to a sentence-bounded 100 so the
      // boilerplate "waives, to the fullest extent permitted by law, any right …
      // to bring or participate in a class action" reaches its object, and adds
      // a passive branch ("the right to a class action is hereby waived")
      // tempered so a negated "class action is NOT waived" cannot match — the
      // inline-negation guard below only inspects the text BEFORE the match, not
      // a negation sitting between "class action" and "waived".
      /\bclass\s+(?:action\s+)?waiver\b|\bwaive[^.]{0,100}class\s+action\b|class\s+action(?:(?!\bnot\b|\bnever\b|\bno\b)[^.;]){0,40}\bwaived\b/i,
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
    // The sentence bound is the SHARED, abbreviation-aware one. A bare
    // `lastIndexOf(".")` stopped at the "." in "Section 5.2" and in "Acme
    // Inc.", so the sentence-leading "Nothing" was cut out of view and this
    // rule accused a clause that PRESERVES class-action rights — the exact
    // false accusation the guard below exists to prevent.
    const sentence = hit.text.slice(clauseStartBefore(hit.text, hit.match.index), hit.match.index);
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
      recommendation:
        "Confirm the waiver is enforceable for this contract and this consumer population, that it sits with a workable individual-dispute mechanism, and that it does not foreclose a public-injunctive claim in a state that preserves one. State-law treatment varies and a waiver struck down takes the arbitration clause with it in some drafting.",
      position: hit.position,
    });
  },
};
