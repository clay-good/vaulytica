import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, isPresenceDisclaimed } from "../_helpers.js";
import { survivalListGaps } from "./TEMP-007.js";

/** TEMP-006 — Survival clause present (info). */
export const rule: Rule = {
  id: "TEMP-006",
  version: "1.2.0",
  name: "Survival clause present",
  category: "temporal",
  default_severity: "info",
  description: "Detects 'survives termination' clauses.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      // The dominant survival phrasing LEADS with the trigger — "Upon
      // termination or expiration of this Agreement, Sections 5–8 shall
      // survive" — putting the event before the verb, which the verb-first
      // pattern missed; and survival is as often tied to "expiration" as to
      // "termination". The reversed branch is limited to "survive/survives"
      // (not the participle) so "the surviving spouse … upon termination" —
      // an unrelated person surviving — does not read as clause survival.
      /\b(?:survive|survives|surviving)\b[\s\S]{0,40}\b(?:termination|expiration|expiry)\b|\b(?:termination|expiration|expiry)\b[\s\S]{0,80}\b(?:survives?)\b/i,
    );
    if (!hit) return null;
    if (isPresenceDisclaimed(hit.text, hit.match.index)) return null;
    // TEMP-007 audits the SAME clause and only speaks when it has something to
    // say about it, so wherever it fires this note is its opening words
    // restated at the same severity on the same sentence — "Survival clause
    // present" directly above "Survival list may be missing categories:
    // indemnity, governing law". A reader told what the list omits has already
    // been told the list exists. Deferring on TEMP-007's own computation
    // rather than on a second guess at it keeps the two in step.
    if ((survivalListGaps(ctx)?.missing.length ?? 0) > 0) return null;
    return emit(ctx, rule, {
      title: "Survival clause present",
      description: "Provisions are stated to survive termination.",
      excerpt: hit.text.slice(0, 240),
      explanation:
        "A survival clause names the obligations that outlast termination — typically confidentiality, indemnity, payment obligations accrued before termination, and choice of law.",
      position: hit.position,
    });
  },
};
