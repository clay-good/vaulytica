import type { Finding, Rule, RuleContext } from "../../finding.js";
import { emit } from "../_helpers.js";
import { MANDATED_TEXTS } from "./mandated-texts.js";
import { carriesFormatting, findMandated } from "./_match.js";

/**
 * TEXT-002 — A mandated text not in the form the authority requires (warning).
 *
 * The two halves of "form" come from different places, and a file may carry
 * one without the other:
 *
 * - **Bold face** is read from run formatting, which only a Word file carries.
 * - **Point size** is read from a Word file's own sizes and styles where they
 *   determine it, and from a PDF text layer's rendered sizes.
 *
 * So a PDF is checked for size and not for bold, a Word file for both, and
 * pasted text for neither (it carries nothing, and nothing is said). The
 * finding names which half went unchecked rather than implying it passed —
 * a notice this rule stays silent about may still be set wrong in the half
 * the file could not answer for.
 */
export const rule: Rule = {
  id: "TEXT-002",
  version: "1.2.0",
  name: "Mandated text not in the required form",
  category: "mandated-text",
  default_severity: "warning",
  description:
    "Flags a prescribed notice the authority requires in bold face, or at a minimum point size, that the file sets otherwise — bold from a Word file, point size from a Word file or a PDF text layer.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    // Bold is knowable only from run formatting; the size can be known without
    // it (a PDF text layer). Bail out only when the file answers for NEITHER.
    const bolded = carriesFormatting(ctx);
    for (const row of MANDATED_TEXTS) {
      const form = row.form;
      if (!form) continue;
      const m = findMandated(ctx, row);
      if (!m || m.runs.length === 0) continue;
      // Without run formatting every run reports `bold: false`, which is the
      // absence of the information and not a notice set in regular type.
      const notBold = bolded && form.bold === true && !m.runs.every((r) => r.bold);
      const small =
        form.min_points !== undefined && m.size_pt !== undefined && m.size_pt < form.min_points;
      if (!notBold && !small) continue;
      const faults = [
        notBold ? `${m.runs.every((r) => !r.bold) ? "none" : "only part"} of it is bold` : "",
        small ? `it is set in ${m.size_pt}-point type` : "",
      ].filter(Boolean);
      // Whichever half this file could not answer for is named, so the finding
      // is never read as clearing it.
      const unchecked = [
        form.bold === true && !bolded
          ? "Whether it is bold is not recorded in this file, so it was not checked."
          : "",
        form.min_points !== undefined && !small && m.size_pt === undefined
          ? "Its point size is not stated in the file, so it was not checked."
          : "",
      ].filter(Boolean);
      const size =
        unchecked.length > 0
          ? ` ${unchecked.join(" ")}`
          : form.min_points === undefined || small
            ? ""
            : ` It is set in ${m.size_pt}-point type.`;
      return emit(ctx, rule, {
        title: `${row.name} is not in the required ${notBold && small ? "bold face or size" : notBold ? "bold face" : "size"}`,
        description: `${row.citation} requires the notice ${form.statement}; in this file ${faults.join(", and ")}.${size}`,
        excerpt: m.text,
        explanation: `The form is part of the requirement, not a style choice: ${row.citation} prescribes the notice ${form.statement}. Read at the official source (eCFR, ${row.retrieved_at}).`,
        // Only the half that was actually read is advised on. Telling a reader
        // to set a PDF's notice in bold would assert a defect this file cannot
        // show, which is the thing the rule is careful not to do.
        recommendation: notBold
          ? `Set the whole notice in bold face${form.min_points !== undefined ? `, at ${form.min_points} points or larger` : ""}.`
          : `Set the whole notice at ${form.min_points ?? 10} points or larger.`,
        position: m.position,
      });
    }
    return null;
  },
};
