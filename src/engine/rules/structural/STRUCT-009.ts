import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, topPosition } from "../_helpers.js";
import { forEachParagraph } from "../../../extract/walk.js";

/** STRUCT-009 — Defined-term capitalization consistency (info). */
export const rule: Rule = {
  id: "STRUCT-009",
  version: "1.0.0",
  name: "Defined-term capitalization consistency",
  category: "structural",
  default_severity: "info",
  description: "Flags inconsistent capitalization of a defined term.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const offenders: string[] = [];
    for (const def of ctx.extracted.definitions.entries) {
      // A parenthetical term is named after the ordinary noun it follows, so
      // that noun keeps appearing in lowercase for its ordinary meaning — "is
      // a \"service provider\" as defined in Cal. Civ. Code", "more favorable
      // than those offered to any other customer". Only an express definition
      // ('"X" means …') constitutes a term whose lowercase use is a slip.
      if (def.form === "parenthetical") continue;
      const target = def.term;
      const lower = target.toLowerCase();
      let foundLower = false;
      forEachParagraph(ctx.tree, (p) => {
        if (foundLower) return;
        if (p.paragraph.id === def.defined_at.paragraph_id) return;
        const re = new RegExp(`\\b${escape(lower)}\\b`, "g");
        const text = p.text;
        let m: RegExpExecArray | null;
        while ((m = re.exec(text)) !== null) {
          const slice = text.slice(m.index, m.index + m[0].length);
          if (slice !== target) {
            foundLower = true;
            break;
          }
        }
      });
      if (foundLower) offenders.push(target);
    }
    if (offenders.length === 0) return null;
    return emit(ctx, rule, {
      title: `Inconsistent capitalization for ${offenders.length} defined term${offenders.length > 1 ? "s" : ""}`,
      description: offenders.join(", "),
      excerpt: offenders[0]!,
      explanation:
        "Defined terms should be capitalized identically wherever they appear. A lowercase use of a defined term reads as ordinary usage and can change the meaning.",
      position: topPosition(ctx),
    });
  },
};

function escape(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
