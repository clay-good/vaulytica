import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstUnnegatedParagraphMatch } from "../_helpers.js";

/** TERM-008 — Termination linked to payment status (warning). */
export const rule: Rule = {
  id: "TERM-008",
  version: "1.1.0",
  name: "Termination linked to payment status",
  category: "termination",
  default_severity: "warning",
  description: "Flags clauses that terminate on payment default with no cure period.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    // The trigger and the two verbs appear in every order in real drafting:
    // "may IMMEDIATELY TERMINATE for non-payment" (adverb-first, the only form
    // the original matched), the dominant "may TERMINATE this Agreement
    // IMMEDIATELY upon non-payment" (verb-first), and the trigger-first "upon
    // NON-PAYMENT, the Company may immediately terminate". Each branch keeps
    // termination + immediacy + a payment-default trigger inside one clause
    // (`[^.;]`), so a for-cause termination with a cure period, or an unrelated
    // "payment due immediately", does not satisfy it.
    const T = String.raw`(?:non[- ]?payment|payment\s+default|fail\w*\s+to\s+pay|default\s+in\s+(?:the\s+)?payment)`;
    const hit = firstUnnegatedParagraphMatch(
      ctx,
      new RegExp(
        String.raw`\bimmediat\w+\s+terminat\w+\b[^.;]{0,80}?\b${T}\b` +
          "|" +
          String.raw`\bterminat\w+\b[^.;]{0,60}?\bimmediat\w+\b[^.;]{0,80}?\b${T}\b` +
          "|" +
          String.raw`\b${T}\b[^.;]{0,90}?(?:\bimmediat\w+\s+terminat|\bterminat\w+\b[^.;]{0,40}?\bimmediat)`,
        "i",
      ),
    );
    if (!hit) return null;
    return emit(ctx, rule, {
      title: "Immediate termination on payment default",
      description: hit.match[0],
      excerpt: hit.text.slice(0, 280),
      explanation:
        "Termination on payment default without a cure period gives one party a fast trigger that can be triggered by routine payment delays.",
      position: hit.position,
    });
  },
};
