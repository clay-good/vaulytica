import type { Finding, Rule, RuleContext } from "../../finding.js";
import { emit } from "../_helpers.js";
import { MANDATED_TEXTS } from "./mandated-texts.js";
import { carriesFormatting, findMandated } from "./_match.js";

/**
 * TEXT-002 — A mandated text not in the required bold face (warning).
 *
 * Read only where the file carries run formatting (a Word file). Plain text
 * and a PDF text layer carry none, so the form is not knowable there and
 * nothing is said. The point size is not read yet.
 */
export const rule: Rule = {
  id: "TEXT-002",
  version: "1.0.0",
  name: "Mandated text not in bold",
  category: "mandated-text",
  default_severity: "warning",
  description:
    "Flags a prescribed notice the authority requires in bold face that the Word file sets in regular type.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    if (!carriesFormatting(ctx)) return null;
    for (const row of MANDATED_TEXTS) {
      if (!row.form?.bold) continue;
      const m = findMandated(ctx, row);
      if (!m || m.runs.length === 0 || m.runs.every((r) => r.bold)) continue;
      return emit(ctx, rule, {
        title: `${row.name} is not in bold face`,
        description: `${row.citation} requires the notice ${row.form.statement}; ${m.runs.every((r) => !r.bold) ? "none" : "only part"} of it is bold in this file. Its point size was not checked.`,
        excerpt: m.text,
        explanation: `The form is part of the requirement, not a style choice: ${row.citation} prescribes the notice ${row.form.statement}. Read at the official source (eCFR, ${row.retrieved_at}).`,
        recommendation: `Set the whole notice in bold face, at ${row.form.min_points ?? 10} points or larger.`,
        position: m.position,
      });
    }
    return null;
  },
};
