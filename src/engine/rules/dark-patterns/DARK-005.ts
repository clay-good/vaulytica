import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/**
 * DARK-005 — Class-action waiver (critical, dark-patterns).
 *
 * Detects clauses that prohibit class-action participation, force
 * individual arbitration, or waive the right to a representative
 * action. These clauses are routinely enforced against US consumers
 * and employees under the FAA following AT&T Mobility v. Concepcion
 * (2011) and Epic Systems v. Lewis (2018), but they materially limit
 * a party's recourse and are widely recognized as a dark pattern in
 * consumer- and employee-facing contracts.
 *
 * The rule is intentionally narrow — a clause that *opts out* of
 * class actions in favor of arbitration is flagged, but a clean
 * arbitration-only clause without the class-action carve-out is not
 * (that's ARB-001's territory in a future expansion).
 */
export const rule: Rule = {
  id: "DARK-005",
  version: "1.0.0",
  name: "Class-action waiver",
  category: "dark-patterns",
  default_severity: "critical",
  description:
    "Detects mandatory waivers of class-action, collective-action, and representative-action rights.",
  dkb_citations: ["stat-ftc-deception-statement"],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\b(?:waives?|waiv(?:er|ing)|gives?\s+up|relinquishes?|shall\s+not\s+(?:participate|be\s+entitled))\b[^.]{0,200}\b(?:class\s+action|class[-\s]wide|collective\s+action|representative\s+action|consolidated\s+(?:claims|arbitration))\b|\b(?:no|not)\s+(?:class\s+action|class[-\s]wide|collective\s+action|representative\s+action)\b|\bon\s+an\s+individual\s+basis\s+(?:only|and\s+not)\b/i,
    );
    if (!hit) return null;
    return emit(ctx, rule, {
      title: "Class-action waiver present",
      description: hit.match[0],
      excerpt: hit.text.slice(Math.max(0, hit.match.index - 30), hit.match.index + 240),
      explanation:
        "A class-action waiver — typically paired with mandatory arbitration — prevents the affected party from joining other similarly-situated claimants. It is enforceable under the Federal Arbitration Act in most US contexts but materially limits practical recourse: small individual claims that would not be cost-effective to litigate solo often only see remedy through collective action. Confirm this waiver is intended and that the affected party (consumer, employee, contractor) understood the trade-off.",
      recommendation:
        "If you are the party giving up class-action rights: weigh the trade-off against the realistic cost of solo arbitration. If you are the drafter: confirm whether enforceability survives in every jurisdiction the contract reaches (some states' analogous statutes are narrower than the FAA).",
      position: hit.position,
    });
  },
};
