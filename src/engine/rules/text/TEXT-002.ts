import type { Finding, Rule, RuleContext } from "../../finding.js";
import { emit } from "../_helpers.js";
import { MANDATED_TEXTS } from "./mandated-texts.js";
import { carriesFormatting, findMandated } from "./_match.js";

/**
 * TEXT-002 — A mandated text not in the form the authority requires (warning).
 *
 * Read only where the file carries run formatting (a Word file). Plain text
 * and a PDF text layer carry none, so the form is not knowable there and
 * nothing is said. Bold is read from the runs; the point size from the
 * file's own sizes and styles, and only where they determine it.
 */
export const rule: Rule = {
  id: "TEXT-002",
  version: "1.1.0",
  name: "Mandated text not in the required form",
  category: "mandated-text",
  default_severity: "warning",
  description:
    "Flags a prescribed notice the authority requires in bold face, or at a minimum point size, that the Word file sets otherwise.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    if (!carriesFormatting(ctx)) return null;
    for (const row of MANDATED_TEXTS) {
      const form = row.form;
      if (!form) continue;
      const m = findMandated(ctx, row);
      if (!m || m.runs.length === 0) continue;
      const notBold = form.bold === true && !m.runs.every((r) => r.bold);
      const small =
        form.min_points !== undefined && m.size_pt !== undefined && m.size_pt < form.min_points;
      if (!notBold && !small) continue;
      const faults = [
        notBold ? `${m.runs.every((r) => !r.bold) ? "none" : "only part"} of it is bold` : "",
        small ? `it is set in ${m.size_pt}-point type` : "",
      ].filter(Boolean);
      const size =
        form.min_points === undefined || small
          ? ""
          : m.size_pt === undefined
            ? " Its point size is not stated in the file, so it was not checked."
            : ` It is set in ${m.size_pt}-point type.`;
      return emit(ctx, rule, {
        title: `${row.name} is not in the required ${notBold && small ? "bold face or size" : notBold ? "bold face" : "size"}`,
        description: `${row.citation} requires the notice ${form.statement}; in this file ${faults.join(", and ")}.${size}`,
        excerpt: m.text,
        explanation: `The form is part of the requirement, not a style choice: ${row.citation} prescribes the notice ${form.statement}. Read at the official source (eCFR, ${row.retrieved_at}).`,
        recommendation: `Set the whole notice in bold face, at ${form.min_points ?? 10} points or larger.`,
        position: m.position,
      });
    }
    return null;
  },
};
