import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit } from "../_helpers.js";
import { forEachParagraph } from "../../../extract/walk.js";

/**
 * CHOICE-011 — Out-of-state choice-of-law on a California-based
 * employee (warning, choice-and-venue).
 *
 * Cal. Lab. Code § 925 (eff. Jan. 1, 2017) voids out-of-state
 * choice-of-law and forum clauses in employment contracts entered
 * into / modified / extended after that date *unless* the employee
 * was individually represented by counsel in negotiating the
 * clause. Cal. Bus. & Prof. Code § 16600.5 (eff. 2024) goes further:
 * any non-compete is unenforceable regardless of where signed if
 * the employee works in California, and creates a private right of
 * action with attorneys' fees.
 *
 * Detection: California-resident or California-working language
 * present + a non-California governing-law selection.
 */
export const rule: Rule = {
  id: "CHOICE-011",
  version: "1.0.0",
  name: "Out-of-state choice-of-law on California employee",
  category: "choice-and-venue",
  default_severity: "warning",
  description:
    "Fires when a worker is identified as California-resident / California-working but the contract picks a non-California governing law.",
  dkb_citations: ["stat-ca-bp-16600"],
  check(ctx: RuleContext): Finding | null {
    let californiaWorker = false;
    forEachParagraph(ctx.tree, (p) => {
      if (
        /\b(?:based\s+in\s+[^.]{0,40}\bCalifornia|California\s+(?:resident|employee|based)|works?\s+(?:in|from)\s+(?:the\s+State\s+of\s+)?California|located\s+in\s+(?:[\w\s]{2,40},\s*)?California|(?:San\s+Francisco|Los\s+Angeles|San\s+Diego|San\s+Jose|Sacramento|Oakland|Fresno|Long\s+Beach|Bakersfield|Anaheim)[^.]{0,40}California|California\s+(?:limited\s+liability\s+company|corporation))\b/i.test(
          p.text,
        )
      ) {
        californiaWorker = true;
      }
    });
    if (!californiaWorker) return null;

    // Look for the governing-law selection. Use the jurisdictions
    // extractor's `governing-law` reference.
    const gov = ctx.extracted.jurisdictions.find((j) => j.clause_kind === "governing-law");
    if (!gov) return null;
    const raw = gov.raw_text.toLowerCase();
    if (/\bcalifornia\b/.test(raw)) return null;

    return emit(ctx, rule, {
      title: "Out-of-state choice-of-law on California-based party",
      description: `Worker / party is identified as California-based but the contract selects ${gov.raw_text} law.`,
      excerpt: gov.raw_text,
      explanation:
        "Cal. Lab. Code § 925 voids out-of-state choice-of-law clauses in employment contracts entered into, modified, or extended after Jan. 1, 2017 — unless the employee was individually represented by counsel in negotiating that specific clause. Cal. Bus. & Prof. Code § 16600.5 (2024) extends similar reasoning to non-competes: they are unenforceable regardless of where signed if the worker is in California, and create a private right of action with attorneys' fees. This pattern is commonly used to evade California's strict non-compete prohibitions; courts (e.g., *Lyon v. Neustar*) routinely refuse to enforce it.",
      recommendation:
        "Either change governing law to California, or include a §925 counsel-representation acknowledgment. Note that §16600.5 may render any non-compete unenforceable even with §925-compliant choice-of-law language.",
      position: gov.position,
    });
  },
};
