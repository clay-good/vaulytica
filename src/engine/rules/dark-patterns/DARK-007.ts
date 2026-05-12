import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/**
 * DARK-007 — Browsewrap / "by using the Service you agree" without
 * affirmative consent (warning, dark-patterns).
 *
 * Detects browsewrap acceptance constructs — phrasings like
 * `by using the Service`, `by accessing this site`, `continued use
 * constitutes acceptance`, `you are deemed to have agreed` — where
 * the contract is purportedly formed without an affirmative
 * manifestation of assent (click-through, signature, etc.).
 *
 * Browsewrap enforceability is notoriously brittle. *Berkson v.
 * Gogo* (E.D.N.Y. 2015), *Nguyen v. Barnes & Noble* (9th Cir.
 * 2014), and *Specht v. Netscape* (2d Cir. 2002) are the modern
 * canon: a browsewrap that fails to put a reasonable user on
 * notice of the terms is unenforceable. The clause's presence is a
 * red flag for any contract that intends to bind a consumer or
 * employee.
 */
export const rule: Rule = {
  id: "DARK-007",
  version: "1.0.0",
  name: "Browsewrap / passive-acceptance language",
  category: "dark-patterns",
  default_severity: "warning",
  description:
    "Detects passive-acceptance constructs (`by using`, `continued use constitutes acceptance`, `deemed to have agreed`) that lack an affirmative consent step.",
  dkb_citations: ["stat-ftc-deception-statement"],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\b(?:by\s+(?:using|accessing|continuing\s+to\s+use|visiting|browsing)\s+(?:the|this|our)\s+(?:Service|Site|Software|Application|Platform|website)[^.]{0,80}(?:you\s+agree|you\s+accept|constitutes?\s+(?:your\s+)?(?:agreement|acceptance))|continued\s+use\s+(?:of\s+the\s+\w+\s+)?constitutes?\s+(?:your\s+)?(?:agreement|acceptance|consent)|(?:you\s+are\s+)?deemed\s+to\s+have\s+(?:agreed|accepted|consented))/i,
    );
    if (!hit) return null;
    return emit(ctx, rule, {
      title: "Browsewrap / passive-acceptance language",
      description: hit.match[0],
      excerpt: hit.text.slice(Math.max(0, hit.match.index - 30), hit.match.index + 280),
      explanation:
        "Browsewrap acceptance — `by using the Service you agree`, `continued use constitutes acceptance`, `you are deemed to have agreed` — is widely held unenforceable when the user is not given clear notice and an affirmative manifestation of assent. *Specht v. Netscape* (2d Cir. 2002), *Nguyen v. Barnes & Noble* (9th Cir. 2014), and *Berkson v. Gogo* (E.D.N.Y. 2015) are the modern canon. For consumer-facing contracts, the FTC's *.com Disclosures* guidance treats hidden or passive consent as a deceptive practice.",
      recommendation:
        "Pair the contract with an affirmative manifestation of assent — a click-through checkbox, a typed name, or an e-signature. Confirm reasonable conspicuous notice of the terms prior to the assent step.",
      position: hit.position,
    });
  },
};
