import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** DARK-004 — Mandatory arbitration with class waiver in consumer contract (warning). */
export const rule: Rule = {
  id: "DARK-004",
  version: "1.1.0",
  name: "Mandatory arbitration + class waiver (consumer)",
  category: "dark-patterns",
  default_severity: "warning",
  description:
    "Flags mandatory arbitration combined with a class-action waiver in consumer contexts.",
  dkb_citations: ["stat-9-usc-2", "stat-frcp-rule-23"],
  check(ctx: RuleContext): Finding | null {
    // The consumer signal is usually the document's TITLE ("Vendor Terms of
    // Service"), and a pasted document carries its title as the first
    // paragraph rather than a section heading — so keying on headings alone
    // left this rule dormant on the consumer terms it exists to police.
    const CONSUMER_CONTEXT =
      /(lease|residential|terms\s+of\s+(?:service|use)|employment|consumer)/i;
    const caption = ctx.tree.sections[0]?.paragraphs[0]?.runs.map((r) => r.text).join("") ?? "";
    const consumer =
      ctx.tree.sections.some((s) => CONSUMER_CONTEXT.test(s.heading)) ||
      CONSUMER_CONTEXT.test(caption);
    if (!consumer) return null;
    // Arbitration must be framed as MANDATORY — optional / non-binding
    // arbitration ("either party MAY elect non-binding arbitration") is not the
    // pattern. And the class-action waiver must not be NEGATED ("contains no
    // class action waiver" is the honest opposite).
    const arb = firstParagraphMatch(
      ctx,
      // "resolved by BINDING INDIVIDUAL arbitration" — the qualifier every
      // consumer arbitration clause carries sits between the adjective and the
      // noun, and the 30-character verb window stopped just short of it.
      /\b(?:mandatory|binding)\s+(?:\w+\s+){0,2}arbitration|(?:shall|must|agree\s+to)\s+(?:[^.]{0,60}?)?arbitrat|arbitration\s+(?:is|shall\s+be)\s+(?:mandatory|binding|required|the\s+(?:sole|exclusive))/i,
    );
    const cw = firstParagraphMatch(
      ctx,
      // "waive any right to a jury trial and any right to participate in a class
      // action" chains two waivers, so the class-action noun can sit well past a
      // 40-char window from "waive". Widen the window but keep it anchored to
      // "waive" and confined to the SAME sentence (`[^.]`), so a PRESERVATION
      // clause with no "waive" ("you retain the right to participate in class
      // actions") is not swept in.
      /(?<!\b(?:no|without|not)\s)class\s+action\s+waiver|\bwaives?\b[^.]{0,120}(?:class\s+action|collective\s+action|representative\s+action)/i,
    );
    if (!arb || !cw) return null;
    return emit(ctx, rule, {
      title: "Mandatory arbitration plus class-action waiver in a consumer-facing contract",
      description: "Both mandatory arbitration and a class-action waiver appear.",
      excerpt: cw.text.slice(0, 280),
      explanation:
        "Mandatory arbitration combined with a class-action waiver effectively immunizes widespread small-dollar harms from collective redress. Enforceable in many jurisdictions, but worth surfacing prominently when the agreement is consumer-facing.",
      position: cw.position,
    });
  },
};
