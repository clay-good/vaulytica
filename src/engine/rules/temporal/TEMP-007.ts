import type { Rule, RuleContext, Finding } from "../../finding.js";
import { allMatches, emit, expandSurvivalSectionRefs } from "../_helpers.js";
import type { ParagraphHit } from "../_helpers.js";
import { forEachParagraph } from "../../../extract/walk.js";

const EXPECTED = [
  ["confidentiality", /confidential/i],
  ["indemnity", /indemnif/i],
  ["payment", /payment|fees?\s+accrued/i],
  ["governing law", /governing\s+law|governed\s+by\s+the\s+laws?\b/i],
] as const;

/**
 * The survival sentence this document states, and the typical categories it
 * leaves out — TEMP-007's whole test, factored out so TEMP-006 can defer to it
 * on the same computation rather than on a second guess at it.
 *
 * Returns `null` when there is no survival clause to audit; `missing` is empty
 * when the clause covers every category the document actually has.
 */
export function survivalListGaps(
  ctx: RuleContext,
): { survival: ParagraphHit; missing: string[] } | null {
  // Survival can be distributed across clauses, and a numbered list
  // ("Sections 2, 5, 7, and 9 survive") incorporates those sections
  // wholesale — check the categories against every survival sentence plus
  // the sections a numbered list names, not just the first sentence.
  const survivals = allMatches(
    ctx,
    /\b(?:survive|survives|surviving)\b[\s\S]{0,400}\btermination\b/i,
  );
  const survival = survivals[0];
  if (!survival) return null;
  // A survival clause that carries ANOTHER instrument's obligations past
  // termination ("obligations under the Restrictive Covenant Agreement …
  // are incorporated by reference and survive termination in accordance
  // with their terms") is not this document's survival LIST — auditing it
  // for confidentiality/indemnity/payment/governing-law categories demands
  // a list the clause never purported to state.
  if (
    survivals.every((sv) =>
      /\bincorporated\s+by\s+reference\b|\bin\s+accordance\s+with\s+(?:its|their)\s+terms\b/i.test(
        sv.text,
      ),
    )
  ) {
    return null;
  }
  const combined = expandSurvivalSectionRefs(ctx, survivals.map((s) => s.text).join("\n"));
  // An obligation the document does not HAVE cannot be missing from its
  // survival list. A charitable grant agreement with no confidentiality
  // clause and no indemnity was told its survival list omits both — a
  // defect with no answer short of adding two clauses the instrument does
  // not want. Only a category the document states somewhere is audited.
  const present = new Set<string>();
  forEachParagraph(ctx.tree, (p) => {
    for (const [name, re] of EXPECTED) if (re.test(p.text)) present.add(name);
  });
  const missing = EXPECTED.filter(([name, re]) => present.has(name) && !re.test(combined)).map(
    ([name]) => name,
  );
  return { survival, missing };
}

/** TEMP-007 — Survival list completeness (info). */
export const rule: Rule = {
  id: "TEMP-007",
  version: "1.5.0",
  name: "Survival list completeness",
  category: "temporal",
  default_severity: "info",
  description: "Cross-checks the survival list against the typical surviving categories.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const gaps = survivalListGaps(ctx);
    if (!gaps) return null;
    const { survival, missing } = gaps;
    if (missing.length === 0) return null;
    return emit(ctx, rule, {
      title: `Survival list may be missing categories: ${missing.join(", ")}`,
      description: `Survival clause does not appear to include: ${missing.join(", ")}.`,
      excerpt: survival.text.slice(0, 240),
      explanation:
        "Typical surviving obligations include confidentiality, indemnity, accrued payment obligations, and governing law. Missing any of these is common and worth confirming.",
      position: survival.position,
    });
  },
};
