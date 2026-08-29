import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, topPosition } from "../_helpers.js";
import { forEachParagraph } from "../../../extract/walk.js";

/** STRUCT-009 — Defined-term capitalization consistency (info). */
export const rule: Rule = {
  id: "STRUCT-009",
  version: "1.8.0",
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
            // A lowercase occurrence BEFORE the definition is generic
            // pre-definition usage (a recital "certain confidential
            // information" preceding the Section 1 definition), not a slip.
            p.start + m.index >= def.defined_at.start &&
            !isGenericOwnUse(text, m.index) &&
            !isContrastiveUse(text, m.index) &&
            !isStatutoryIdiomUse(text, m.index, target, m[0].length) &&
            !isQuotedIdiomUse(text, m.index, m[0].length) &&
            !isAttributiveUse(text, m.index, m[0].length)
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
 * A lowercase noun immediately preceded by a CONTRASTIVE qualifier names a
 * DIFFERENT set than the defined term, not a miscapitalized use of it: a
 * distribution agreement that defines "Products" still bars the distributor
 * from carrying "competing products" — competitors' goods, deliberately not
 * the defined Products. The same holds for "other services", "similar goods",
 * "third-party materials". A real slip never writes "competing <Term>" meaning
 * the defined term, so these must not read as an inconsistency.
 */
export function isContrastiveUse(text: string, index: number): boolean {
  return /\b(?:competing|competitor['’]?s?|competitive|rival|similar|comparable|substitute|alternative|other|another|third[-\s]?party)\s+$/i.test(
    text.slice(Math.max(0, index - 20), index),
  );
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
  const lower = term.toLowerCase();
  // A CLA defines "You"/"Your" as the contributor, and its cover letter still
  // opens "Thank you for your interest in contributing" — the pleasantry is
  // ordinary English address, not a lowercase use of the defined term.
  if (lower === "you" || lower === "your") {
    return /\bthank(?:\s+you\s+for)?\s*$/i.test(text.slice(Math.max(0, index - 16), index));
  }
  // "a Delaware limited liability company" is the statutory entity type, not
  // a lowercase use of a defined "Company" — every agreement that defines
  // "Company" also recites at least one party's entity type this way.
  if (lower === "company" || lower === "corporation" || lower === "partnership") {
    return /\b(?:limited\s+liability|joint\s+stock|professional|nonprofit|non-profit|limited|general|holding)\s+$/i.test(
      text.slice(Math.max(0, index - 24), index),
    );
  }
  if (lower !== "personal data") return false;
  if (/^\s+breach/i.test(text.slice(index + matchLength, index + matchLength + 10))) return true;
  return /\bspecial\s+categories\s+of\s+$/i.test(text.slice(Math.max(0, index - 30), index));
}

/**
 * A lowercase occurrence INSIDE a quoted phrase is a quotation, not a
 * miscapitalized use of the defined term.
 *
 * Every EULA sold to the US government recites FAR 12.212: the Software "is
 * `commercial computer software`", which is the regulation's own defined
 * phrase, written in lowercase and in quotation marks because it is being
 * quoted. STRUCT-009 read the "software" inside it as a lowercase use of the
 * agreement's defined "Software" and reported an inconsistency the drafter
 * cannot fix without misquoting the regulation. The same shape covers a
 * quoted statutory definition, a quoted contractual phrase from another
 * instrument, and a quoted product name.
 *
 * Bounded to a single quoted span near the match, so an ordinary paragraph
 * that happens to contain a quotation elsewhere is unaffected.
 */
export function isQuotedIdiomUse(text: string, index: number, length: number): boolean {
  const before = text.slice(Math.max(0, index - 120), index);
  const after = text.slice(index + length, index + length + 120);
  const opensBefore = (before.match(/["\u201C]/g) ?? []).length;
  const closesBefore = (before.match(/["\u201D]/g) ?? []).length;
  // A straight quote is both opener and closer, so count parity: an odd number
  // of quote characters between the window start and the match means the match
  // sits inside a quoted span. A curly opener is counted only as an opener.
  const insideStraight = (before.match(/"/g) ?? []).length % 2 === 1;
  const insideCurly = opensBefore > closesBefore;
  if (!insideStraight && !insideCurly) return false;
  return /["\u201D]/.test(after);
}

/**
 * A lowercase use that MODIFIES a following noun names a different thing than
 * the defined term it borrows a word from. A credit agreement defines
 * "Commitment" as a lender's obligation to lend and then charges an "unused
 * commitment fee" — the fee, not the Commitment — and the same holds for a
 * "commitment letter" and a "commitment period". Reporting these as a
 * miscapitalized "Commitment" asks the drafter to capitalize a word that is
 * not the defined term.
 *
 * The head nouns are enumerated rather than inferred: an open "followed by any
 * lowercase word" test would swallow ordinary sentences, where the word after
 * the term is a verb or a preposition and the term IS the subject.
 */
const ATTRIBUTIVE_HEAD =
  /^\s+(?:fee|fees|letter|letters|date|dates|period|periods|rate|rates|price|prices|amount|amounts|notice|notices|certificate|certificates|schedule|schedules|statement|statements|report|reports|threshold|thresholds)\b/;

export function isAttributiveUse(text: string, index: number, length: number): boolean {
  return ATTRIBUTIVE_HEAD.test(text.slice(index + length, index + length + 24));
}
