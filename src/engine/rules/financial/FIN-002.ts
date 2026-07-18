import Decimal from "decimal.js";
import type { Rule, RuleContext, Finding } from "../../finding.js";
import { makeFinding } from "../../finding.js";
import { forEachParagraph } from "../../../extract/walk.js";
import { enclosingSentence } from "../_helpers.js";

// An escalation / tiered schedule reuses the same named amount at different
// values ON PURPOSE, tying each to a distinct period. Differing values with
// this language are intended, not a drafting inconsistency, so the "conflicting
// values" warning must not fire on them.
const ESCALATION_OR_PERIOD =
  /\b(?:escalat|increas|step[-\s]?up|adjust(?:ed|ment)|Lease\s+Year|(?:first|second|third|fourth|fifth|initial|subsequent)\s+(?:Lease\s+)?(?:Year|Term|Period|Phase)|(?:Year|Month|Term|Phase|Period)\s+(?:\d|one|two|three|four|five)|per\s+annum|each\s+(?:year|anniversary)|thereafter|renewal\s+term)/i;

/**
 * FIN-002 — Inconsistent named amounts (warning).
 *
 * Detects when a defined-and-named amount (e.g., "the Cap means
 * $1,000,000") is referenced elsewhere with a different value. The
 * detection is conservative: we look for `the <Name> (e.g., "$1,000,000")`
 * or `the <Name> of $X` patterns and group by the name.
 */

const NAMED = /\bthe\s+([A-Z][\w\s]{2,30}?)\s+(?:of|equal\s+to)\s+\$([\d,]+(?:\.\d+)?)/g;

export const rule: Rule = {
  id: "FIN-002",
  version: "1.0.0",
  name: "Inconsistent named amounts",
  category: "financial",
  default_severity: "warning",
  description:
    "Flags when a named amount appears with conflicting numeric values across the document.",
  dkb_citations: [],

  check(ctx: RuleContext): Finding | null {
    const byName = new Map<
      string,
      {
        value: Decimal;
        raw: string;
        sectionId: string;
        start: number;
        end: number;
        scheduled: boolean;
      }[]
    >();

    forEachParagraph(ctx.tree, (p) => {
      NAMED.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = NAMED.exec(p.text)) !== null) {
        const name = m[1]!.trim();
        const value = new Decimal(m[2]!.replace(/,/g, ""));
        const list = byName.get(name) ?? [];
        list.push({
          value,
          raw: m[0],
          sectionId: p.section.id,
          start: p.start + m.index,
          end: p.start + m.index + m[0].length,
          scheduled: ESCALATION_OR_PERIOD.test(enclosingSentence(p.text, m.index)),
        });
        byName.set(name, list);
      }
    });

    for (const [name, list] of byName) {
      if (list.length < 2) continue;
      const distinct = new Set(list.map((e) => e.value.toString()));
      if (distinct.size < 2) continue;
      // An intentional escalation / tiered schedule (each value tied to a
      // distinct period) is not a conflict.
      if (list.some((e) => e.scheduled)) continue;
      const first = list[0]!;
      const values = [...distinct].join(", ");
      return makeFinding({
        rule,
        title: `Named amount with conflicting values: ${name}`,
        description: `"${name}" is referenced with multiple values: ${values}.`,
        excerptText: list.map((e) => e.raw).join(" / "),
        explanation:
          "When the same named amount is stated with different values in different parts of the contract, the ambiguity is exploitable. Most courts will resolve in favor of the meaning more favorable to the non-drafting party.",
        recommendation: "Pick one value and update every reference to use it.",
        position: { section_id: first.sectionId, start: first.start, end: first.end },
        source_citations: [],
      });
    }
    return null;
  },
};
