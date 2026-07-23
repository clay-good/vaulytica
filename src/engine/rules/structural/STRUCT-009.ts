import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, topPosition } from "../_helpers.js";
import { forEachParagraph } from "../../../extract/walk.js";

/** STRUCT-009 — Defined-term capitalization consistency (info). */
export const rule: Rule = {
  id: "STRUCT-009",
  version: "1.2.0",
  name: "Defined-term capitalization consistency",
  category: "structural",
  default_severity: "info",
  description: "Flags inconsistent capitalization of a defined term.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const offenders: string[] = [];
    for (const def of ctx.extracted.definitions.entries) {
      // A parenthetical term is named after the ordinary noun it follows, so
      // that noun keeps appearing in lowercase for its ordinary meaning — "is
      // a \"service provider\" as defined in Cal. Civ. Code", "more favorable
      // than those offered to any other customer". Meaning-reference and
      // construed terms import a statute's vocabulary, which the statute
      // itself writes in lowercase ("the processing of personal data"), so a
      // lowercase use echoes the source, not a slip. Only an express
      // definition ('"X" means …') constitutes a term whose lowercase use is
      // the inconsistency this rule reports.
      if (def.form && def.form !== "means") continue;
      const target = def.term;
      const lower = target.toLowerCase();
      let foundLower = false;
      forEachParagraph(ctx.tree, (p) => {
        if (foundLower) return;
        if (p.paragraph.id === def.defined_at.paragraph_id) return;
        const re = new RegExp(`\\b${escape(lower)}\\b`, "g");
        const text = p.text;
        let m: RegExpExecArray | null;
        while ((m = re.exec(text)) !== null) {
          const slice = text.slice(m.index, m.index + m[0].length);
          if (
            slice !== target &&
            !isGenericOwnUse(text, m.index) &&
            !isStatutoryIdiomUse(text, m.index, target, m[0].length)
          ) {
            foundLower = true;
            break;
          }
        }
      });
      if (foundLower) offenders.push(target);
    }
    if (offenders.length === 0) return null;
    return emit(ctx, rule, {
      title: `Inconsistent capitalization for ${offenders.length} defined term${offenders.length > 1 ? "s" : ""}`,
      description: offenders.join(", "),
      excerpt: offenders[0]!,
      explanation:
        "Defined terms should be capitalized identically wherever they appear. A lowercase use of a defined term reads as ordinary usage and can change the meaning.",
      position: topPosition(ctx),
    });
  },
};

function escape(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * A lowercase use immediately preceded by "own" is a GENERIC reference, not a
 * miscapitalized defined term: the universal NDA reasonable-care standard is
 * "the same degree of care it uses for its OWN confidential information" —
 * that "confidential information" is the party's own (generic), deliberately
 * distinct from the defined "Confidential Information". A real slip never
 * writes "own <Term>" meaning the defined term, so this idiom must not read as
 * an inconsistency.
 */
export function isGenericOwnUse(text: string, index: number): boolean {
  return /\bown\s+$/i.test(text.slice(Math.max(0, index - 12), index));
}

/**
 * A lowercase "personal data" inside one of the GDPR's own compound terms of
 * art is the regulation's wording, not a drafting slip. Article 33 writes
 * "personal data breach" and Article 9 writes "special categories of personal
 * data" in lowercase, and every DPA that defines "Personal Data" also quotes
 * those phrases — flagging them told drafters to miscapitalize the statute.
 * Deliberately scoped to the one term where the statutory idiom is universal.
 */
export function isStatutoryIdiomUse(
  text: string,
  index: number,
  term: string,
  matchLength: number,
): boolean {
  if (term.toLowerCase() !== "personal data") return false;
  if (/^\s+breach/i.test(text.slice(index + matchLength, index + matchLength + 10))) return true;
  return /\bspecial\s+categories\s+of\s+$/i.test(text.slice(Math.max(0, index - 30), index));
}
