import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit } from "../_helpers.js";
import { forEachParagraph } from "../../../extract/walk.js";

/**
 * TEMP-012 — Survival clause silent on confidentiality / IP /
 * indemnity (warning, temporal).
 *
 * Survival language ("the following provisions survive termination
 * …") is the contractual mechanism that keeps sticky obligations
 * alive after the contract itself ends. Confidentiality, IP
 * ownership / assignment, and indemnification are the three
 * standard sticky obligations — survival should expressly name
 * them.
 *
 * The rule fires when:
 *   - the document contains *any* sticky obligation (confidentiality,
 *     IP ownership / assignment, or indemnification language), AND
 *   - the document also contains a `survive`/`survival` clause, AND
 *   - the survival clause does not name the sticky obligations that
 *     are present in the document.
 *
 * A contract with no survival clause at all does not trigger this
 * rule (that's a different finding — covered by TERM-008).
 */
export const rule: Rule = {
  id: "TEMP-012",
  version: "1.0.0",
  name: "Survival clause silent on confidentiality / IP / indemnity",
  category: "temporal",
  default_severity: "warning",
  description:
    "Fires when sticky obligations (confidentiality / IP / indemnity) are present but the survival clause doesn't name them.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    let survivalText: string | null = null;
    let survivalSection = "";
    let survivalStart = 0;
    let survivalEnd = 0;
    let hasConfidentiality = false;
    let hasIpOwnership = false;
    let hasIndemnity = false;

    forEachParagraph(ctx.tree, (p) => {
      if (survivalText === null && /\bsurviv(?:e|es|ed|ing|al)\b/i.test(p.text)) {
        survivalText = p.text;
        survivalSection = p.section.id;
        survivalStart = p.start;
        survivalEnd = p.end;
      }
      if (/\bconfidential(?:ity)?\s+(?:information|obligations?|provisions?)/i.test(p.text))
        hasConfidentiality = true;
      if (/\b(?:work\s+for\s+hire|ip\s+(?:ownership|assignment)|intellectual\s+property\s+(?:ownership|assignment)|all\s+(?:right(?:s)?,?\s+title(?:,)?\s+and\s+interest)\s+in\s+(?:and\s+to\s+)?(?:the\s+)?work\s+product)/i.test(p.text))
        hasIpOwnership = true;
      if (/\b(?:indemnif|hold\s+\w+\s+harmless|defend\s+and\s+indemnify)/i.test(p.text))
        hasIndemnity = true;
    });

    if (survivalText === null) return null;
    const text: string = survivalText;
    if (!hasConfidentiality && !hasIpOwnership && !hasIndemnity) return null;

    const missing: string[] = [];
    if (hasConfidentiality && !/confidential/i.test(text)) missing.push("confidentiality");
    if (hasIpOwnership && !/(?:intellectual\s+property|ip\s+|work\s+for\s+hire|ownership)/i.test(text))
      missing.push("IP ownership / assignment");
    if (hasIndemnity && !/(?:indemnif|hold\s+\w+\s+harmless)/i.test(text)) missing.push("indemnification");

    if (missing.length === 0) return null;

    return emit(ctx, rule, {
      title: `Survival clause does not name ${missing.length} sticky obligation${missing.length === 1 ? "" : "s"}`,
      description: `The survival clause exists but does not name: ${missing.join(", ")}.`,
      excerpt: text.slice(0, 280),
      explanation:
        "Survival language is what keeps sticky obligations alive after a contract terminates. A survival clause that doesn't expressly enumerate the present-in-document confidentiality / IP / indemnity obligations creates ambiguity at the moment those obligations matter most — post-termination, when the contract has already ended.",
      recommendation:
        `Add explicit named references to the missing obligation(s): ${missing.join(", ")}. Standard drafting names every sticky section by number or category in the survival clause.`,
      position: { section_id: survivalSection, start: survivalStart, end: survivalEnd },
    });
  },
};
