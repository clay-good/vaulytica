import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, isPresenceDisclaimed } from "../_helpers.js";
import { truncate } from "../../text.js";
import { AMOUNT_IN_WORDS, CURRENCY_TOKEN } from "../../../extract/amounts.js";

/** FIN-008 — Minimum commitment language (info). */
export const rule: Rule = {
  id: "FIN-008",
  version: "1.2.0",
  name: "Minimum commitment / take-or-pay",
  category: "financial",
  default_severity: "info",
  description: "Flags minimum-commitment or take-or-pay language.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      // The same commitment is written "minimum purchase / spend / volume /
      // quantity", "committed volume / spend", or "volume commitment" — none of
      // which the commitment/take-or-pay/minimum-fee list matched. Also common:
      // "guaranteed minimum" / "minimum guarantee", the period-first "annual /
      // monthly minimum (of $…)", "minimum revenue / royalty", and a hard
      // "purchase at least <N> …" quota. "minimum" is anchored to a commitment
      // noun so an unrelated "minimum age" / "minimum notice" does not fire.
      new RegExp(
        /\b(?:minimum\s+(?:commitment|purchase|spend|volume|quantity|order|usage|revenue|royalt(?:y|ies)|guarantee)|guaranteed\s+minimum|take[- ]or[- ]pay|minimum\s+(?:annual|monthly|quarterly)\s+(?:fee|payment|volume|quantity|spend|commitment)|(?:annual|monthly|quarterly|yearly)\s+minimum\s+(?:commitment|purchase|spend|volume|quantity|order|usage|fee|payment|amount|guarantee|of\b)|committed\s+(?:volume|spend|amount|quantity)|volume\s+commitment|(?:purchase|buy|order|procure|acquire)\s+(?:at\s+least|a\s+minimum\s+of|no\s+(?:fewer|less)\s+than)\s+[\d,]+)\b/i
          .source +
          // The commitment stated as a VALUE the purchases must reach:
          // "Distributor shall purchase Products with an aggregate invoice
          // value of at least €1,400,000". Pasted text was saved by its
          // heading ("4. Minimum Purchase Commitment."), which a DOCX gives as
          // a heading, not a paragraph.
          String.raw`|\b(?:shall|will|must|agrees?\s+to)\s+(?:purchase|buy|order|procure)\b[^.;]{0,80}?\b(?:at\s+least|a\s+minimum\s+of|no\s+less\s+than|not\s+less\s+than)\s+(?:(?:${CURRENCY_TOKEN})\s?\d|${AMOUNT_IN_WORDS})`,
        "i",
      ),
    );
    if (!hit) return null;
    if (isPresenceDisclaimed(hit.text, hit.match.index)) return null;
    return emit(ctx, rule, {
      title: "Minimum commitment clause present",
      description: "A minimum-commitment or take-or-pay clause is included.",
      excerpt: truncate(hit.text, 200),
      explanation:
        "Minimum-commitment language obliges the customer to pay regardless of consumption. Verify the commitment level is reasonable and tied to a credit (e.g., usage above the minimum reduces future minimums).",
      position: hit.position,
    });
  },
};
