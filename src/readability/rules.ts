/**
 * READ-001 and READ-002 (add-readability-measure, task 4): a policy held to an
 * asserted readability statute. They run only when the user asserts the
 * standard (`--readability fl`), never by default, because the statutes
 * govern insurance policy forms filed in a state and nothing in a document
 * says where it was filed.
 */
import type { Finding, Rule, RuleContext } from "../engine/finding.js";
import { emit } from "../engine/rules/_helpers.js";
import { forEachParagraph } from "../extract/walk.js";
import { measureReadability } from "../report/readability.js";
import type { ReadabilityStandard } from "./standards.js";

export const GATE = "readability";

const standardOf = (ctx: RuleContext): ReadabilityStandard | undefined =>
  ctx.options?.readability_standard as ReadabilityStandard | undefined;

const CAVEAT =
  "The score follows the statute's counting method but does not apply the sampling it allows for long forms, or the exclusions it lets an insurer claim (defined words, medical terminology, language required by law), so a filed score may differ. Whether a form meets the statute is the insurer's certification and the regulator's decision.";

function firstParagraph(ctx: RuleContext) {
  let first:
    | { section_id: string; paragraph_id: string; start: number; end: number; text: string }
    | undefined;
  forEachParagraph(ctx.tree, (p) => {
    if (!first && p.text.trim()) {
      first = {
        section_id: p.section.id,
        paragraph_id: p.paragraph.id,
        start: p.start,
        end: p.end,
        text: p.text,
      };
    }
  });
  return first;
}

/** READ-001 — Reading ease below the asserted statute's minimum (warning). */
export const READ_001: Rule = {
  id: "READ-001",
  version: "1.0.0",
  name: "Reading ease below the asserted standard",
  category: "readability",
  default_severity: "warning",
  description:
    "Under an asserted readability statute, flags a Flesch reading ease score below the statute's minimum.",
  dkb_citations: [],
  assertion_gate: GATE,
  check(ctx: RuleContext): Finding | null {
    const std = standardOf(ctx);
    if (!std) return null;
    const r = measureReadability(ctx.tree);
    if (r.words === 0 || r.score >= std.min_score) return null;
    const anchor = firstParagraph(ctx);
    if (!anchor) return null;
    const longest = r.longest_sentence;
    return emit(ctx, READ_001, {
      title: `Reading ease ${r.score} is below the ${std.min_score} ${std.citation} requires`,
      description: `The document scores ${r.score} on the Flesch reading ease test (${r.words} words, ${r.sentences} sentences, ${r.syllables} syllables); ${std.citation} requires at least ${std.min_score} for ${std.scope}.${longest ? ` Its longest sentence runs ${longest.words} words.` : ""}`,
      excerpt: longest?.text ?? anchor.text,
      explanation: `${std.citation} (read at its official source, ${std.retrieved_at}) sets a minimum Flesch reading ease score and prescribes how to count it. ${CAVEAT}`,
      recommendation:
        "Shorten the longest sentences and prefer shorter words; each word less per sentence and each syllable less per word raises the score.",
      position: anchor,
    });
  },
};

/** A table of contents or an index, by its heading or its dotted leaders. */
function hasContents(ctx: RuleContext): boolean {
  let found = false;
  const heading = /^\s*(?:table of contents|contents|index)\s*$/i;
  const walk = (sections: RuleContext["tree"]["sections"]): void => {
    for (const s of sections) {
      if (heading.test(s.heading ?? "")) found = true;
      walk(s.children);
    }
  };
  walk(ctx.tree.sections);
  forEachParagraph(ctx.tree, (p) => {
    if (heading.test(p.text) || /\.{4,}\s*\d+\s*$/.test(p.text)) found = true;
  });
  return found;
}

/** READ-002 — A long form with no table of contents or index (warning). */
export const READ_002: Rule = {
  id: "READ-002",
  version: "1.0.0",
  name: "No table of contents in a long form",
  category: "readability",
  default_severity: "warning",
  description:
    "Under an asserted readability statute, flags a form longer than the statute's limit with no table of contents or index.",
  dkb_citations: [],
  assertion_gate: GATE,
  check(ctx: RuleContext): Finding | null {
    const std = standardOf(ctx);
    if (!std) return null;
    const words = measureReadability(ctx.tree).words;
    if (words <= std.contents_over.words || hasContents(ctx)) return null;
    const anchor = firstParagraph(ctx);
    if (!anchor) return null;
    return emit(ctx, READ_002, {
      title: "No table of contents or index",
      description: `The document runs ${words.toLocaleString("en-US")} words, more than the ${std.contents_over.words.toLocaleString("en-US")} above which ${std.citation} requires a table of contents or an index of the principal sections, and none was found.`,
      excerpt: anchor.text,
      explanation: `${std.citation} requires a table of contents or index when the form has more than ${std.contents_over.words.toLocaleString("en-US")} words or more than ${std.contents_over.pages} pages. Pages are not counted here, so a shorter form of more than ${std.contents_over.pages} pages is not caught.`,
      recommendation: "Add a table of contents or an index of the principal sections.",
      position: anchor,
    });
  },
};

export const READABILITY_RULES: readonly Rule[] = [READ_001, READ_002];
