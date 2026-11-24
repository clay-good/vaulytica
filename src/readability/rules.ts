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

/** A dollar ceiling as a statute's reader would write it. */
const formatDollars = (n: number): string => `$${n.toLocaleString("en-US")}`;

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
    // A standard that sets no numeric score has nothing for this rule to
    // compare against (N.Y. Gen. Oblig. Law 5-702 is the first such row).
    if (!std || std.min_score === undefined) return null;
    const min = std.min_score;
    const r = measureReadability(ctx.tree);
    const passes = std.min_exclusive ? r.score > min : r.score >= min;
    if (r.words === 0 || passes) return null;
    const anchor = firstParagraph(ctx);
    if (!anchor) return null;
    const longest = r.longest_sentence;
    return emit(ctx, READ_001, {
      title: std.min_exclusive
        ? `Reading ease ${r.score} is not above the ${min} ${std.citation} requires`
        : `Reading ease ${r.score} is below the ${min} ${std.citation} requires`,
      description: `The document scores ${r.score} on the Flesch reading ease test (${r.words} words, ${r.sentences} sentences, ${r.syllables} syllables); ${std.citation} requires ${std.min_exclusive ? "more than" : "at least"} ${min} for ${std.scope}.${longest ? ` Its longest sentence runs ${longest.words} words.` : ""}`,
      excerpt: longest?.text ?? anchor.text,
      explanation: `${std.citation} (read at its official source, ${std.retrieved_at}) sets a minimum Flesch reading ease score and prescribes how to count it. ${CAVEAT}`,
      recommendation:
        "Shorten the longest sentences and prefer shorter words; each word less per sentence and each syllable less per word raises the score.",
      position: anchor,
    });
  },
};

/**
 * A table of contents (or, where the statute accepts one, an index), by its
 * heading or its dotted leaders.
 */
function hasContents(ctx: RuleContext, indexOk: boolean): boolean {
  let found = false;
  const heading = indexOk
    ? /^\s*(?:table of contents|contents|index)\s*$/i
    : /^\s*(?:table of contents|contents)\s*$/i;
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
    const over = std.contents_over;
    // 5-702 requires captions, not a table of contents; a row with no
    // contents rule draws no finding here.
    if (over === undefined) return null;
    const words = measureReadability(ctx.tree).words;
    if (words === 0 || (over !== "always" && words <= over.words)) return null;
    if (hasContents(ctx, std.index_ok)) return null;
    const anchor = firstParagraph(ctx);
    if (!anchor) return null;
    if (over === "always") {
      return emit(ctx, READ_002, {
        title: "No index of the major provisions",
        description: `${std.citation} requires every policy it covers to carry an index of its major provisions, whatever its length, and none was found.`,
        excerpt: anchor.text,
        explanation: `${std.citation} requires an index of the major provisions in every policy it covers, whatever its length. A heading reading "Index", "Contents" or "Table of Contents", or a line of dotted leaders to a page number, is taken as one.`,
        recommendation: "Add an index of the major provisions.",
        position: anchor,
      });
    }
    const required = std.index_ok
      ? "a table of contents or an index of the principal sections"
      : "a table of contents";
    return emit(ctx, READ_002, {
      title: std.index_ok ? "No table of contents or index" : "No table of contents",
      description: `The document runs ${words.toLocaleString("en-US")} words, more than the ${over.words.toLocaleString("en-US")} above which ${std.citation} requires ${required}, and none was found.`,
      excerpt: anchor.text,
      explanation: `${std.citation} requires ${std.index_ok ? "a table of contents or index" : "a table of contents (an index does not satisfy it)"} when the form has more than ${over.words.toLocaleString("en-US")} words or more than ${over.pages} pages. Pages are not counted here, so a shorter form of more than ${over.pages} pages is not caught.`,
      recommendation: `Add ${required}.`,
      position: anchor,
    });
  },
};

/**
 * A clause caption written inline, which is how a plain-text agreement carries
 * one: a clause number, then a short Title-Case title, then a full stop —
 * `3. Security Deposit.` — whether the body follows on the same line or below.
 *
 * 🚨 The outline alone CANNOT answer this question. A section heading exists in
 * the tree only where the format carries one (a Word heading style, a Markdown
 * `#`, a Setext underline); `paste.ts` promotes a plain-text line to a heading
 * on none of those grounds. So a pasted lease with textbook captions —
 * "1. Rent.", "2. Term." — arrives with its sections unheaded, and a rule that
 * read only the outline would report EVERY plain-text consumer agreement as
 * uncaptioned. That was the first draft of this rule, and the clean captioned
 * lease in `readability-assertion.test.ts` is what caught it.
 *
 * The title must read as a title and not as the opening of a sentence: at most
 * eight words, each content word capitalized, with only the usual small words
 * lowercase. `1. Tenant will pay rent of $2,450 each month.` is numbered and
 * NOT captioned, which is the distinction § 5-702(a)(2) draws by requiring an
 * agreement to be divided AND captioned.
 */
/** A clause number opening a line: `3.`, `3.1`, `(c)`, `Section 4`, `§ 4`, `ARTICLE II`. */
const CLAUSE_NUMBER =
  /^\s*(?:\d+(?:\.\d+)*\.?|\([a-z0-9]{1,4}\)|(?:ARTICLE|Article|SECTION|Section|Clause)\s+[0-9IVXLC]+\.?|§\s*\d+(?:\.\d+)*\.?)\s+/;

/** Words a title leaves lowercase. */
const SMALL_WORD = /^(?:and|or|of|to|for|the|a|an|in|on|at|by|with|from|as|under|upon)$/i;

/**
 * Is this phrase a title rather than the opening of a sentence?
 *
 * 🚨 The sweep over 363 specimens is what shaped this. The first version
 * required a terminating `.` or dash after a Title-Case phrase, which misses
 * `1. PURPOSE AND SCOPE` — a numbered ALL-CAPS caption on its own line, with
 * no terminator, which is the commonest caption form in American legal
 * drafting. It reported 32 specimens as uncaptioned and at least one of them,
 * `code-of-conduct.txt`, is captioned throughout.
 */
function isTitlePhrase(phrase: string): boolean {
  const words = phrase.trim().split(/\s+/).filter(Boolean);
  if (words.length === 0 || words.length > 8 || phrase.trim().length > 60) return false;
  let content = 0;
  for (const w of words) {
    const bare = w.replace(/[^\p{L}\p{N}'’-]/gu, "");
    if (!bare) continue;
    if (SMALL_WORD.test(bare)) continue;
    // 🚨 A NUMERAL is neutral, not a failing content word. Where a caption
    // line runs straight into its first sub-clause with no blank line —
    //   1. COMMENCEMENT AND CONTINUOUS EMPLOYMENT
    //   1.1 Your employment begins on 1 June 2026.
    // — normalization joins the two into one paragraph, and the title then
    // ends at the `.` inside `1.1`, leaving a trailing `1`. Treating that `1`
    // as an uncapitalized content word reported `uk-contract-of-employment`,
    // which is captioned throughout, as having no captions at all.
    if (/^[\p{N}]+$/u.test(bare)) continue;
    content++;
    // A content word in a title is capitalized; `will`, `pay`, `rent` are not.
    if (!/^[A-Z]/.test(bare)) return false;
  }
  return content > 0;
}

/**
 * Does this paragraph open with a caption?
 *
 * Takes the text after any clause number, up to the first sentence break, and
 * asks whether that reads as a title. `3. Security Deposit. Tenant will pay…`
 * and `1. PURPOSE AND SCOPE` both do; `1. Tenant will pay rent of $2,450 each
 * month.` is numbered and NOT captioned, which is the distinction
 * § 5-702(a)(2) draws by requiring an agreement to be divided AND captioned.
 */
function looksCaptioned(text: string): boolean {
  const firstLine = text.split("\n")[0]!;
  const numbered = CLAUSE_NUMBER.exec(firstLine);
  const rest = numbered ? firstLine.slice(numbered[0].length) : firstLine;
  // The title ends at the first full stop, colon or dash, or at the line's end.
  const head = /^([^.:—–]*)/.exec(rest)![1]!;
  if (numbered) return isTitlePhrase(head);
  // With no clause number, a caption is a heading-LIKE paragraph: a short
  // single line that is not a sentence. This is `paste.ts`'s own test for
  // promoting a line to a heading (at most 80 characters, no terminal
  // `.;:,`), reused deliberately so the two surfaces agree on what a heading
  // looks like.
  //
  // It accepts sentence case, not only capitals: "Why you are receiving this
  // notice" is a caption, and requiring ALL-CAPS reported
  // `childrens-privacy-notice` as having none. Erring toward accepting a
  // caption is the safe direction for an ABSENCE finding — a missed violation
  // costs a reader nothing, while accusing a captioned agreement of being
  // undivided is a false statement about their document.
  const line = text.trim();
  return !line.includes("\n") && line.length > 0 && line.length <= 80 && !/[.;:,]$/.test(line);
}

/**
 * Does the document divide itself into captioned sections?
 *
 * Counts both the outline's headings (a Word or Markdown document carries
 * them) and inline clause captions (a plain-text one carries those instead),
 * so the answer does not depend on the format the agreement arrived in.
 *
 * What this does NOT judge is whether a caption is APPROPRIATE to what sits
 * under it. That is the same kind of judgment as (a)(1)'s "clear and coherent
 * manner", and the finding says so rather than letting a reader assume the
 * statute has been applied in full.
 */
function captionCount(ctx: RuleContext): { captions: number; paragraphs: number } {
  let captions = 0;
  const walk = (sections: RuleContext["tree"]["sections"]): void => {
    for (const section of sections) {
      if ((section.heading ?? "").trim().length > 0) captions++;
      walk(section.children);
    }
  };
  walk(ctx.tree.sections);
  let paragraphs = 0;
  forEachParagraph(ctx.tree, (p) => {
    if (!p.text.trim()) return;
    paragraphs++;
    // 🚨 The FIRST paragraph is the document's own title — "RESIDENTIAL LEASE
    // AGREEMENT" — and an all-caps title matches the caption line pattern
    // exactly. Counting it made the uncaptioned lease look captioned and shut
    // this rule off on precisely the documents it exists for. § 5-702(a)(2)
    // asks about the agreement's SECTIONS; its title names the whole thing.
    if (paragraphs === 1) return;
    if (looksCaptioned(p.text)) captions++;
  });
  return { captions, paragraphs };
}

/**
 * READ-003 — A consumer agreement whose sections are not captioned (warning).
 *
 * N.Y. Gen. Oblig. Law § 5-702(a)(2) requires an agreement it covers to be
 * "appropriately divided and captioned by its various sections". Unlike every
 * other row in the table this is not a score: the statute sets no formula, and
 * its other half — (a)(1)'s "clear and coherent manner using words with common
 * and every day meanings" — is a judgment the product does not make. The
 * finding says both, and says that the statute's $250,000 ceiling was not
 * applied because the agreement's value is not read.
 */
export const READ_003: Rule = {
  id: "READ-003",
  version: "1.0.0",
  name: "Consumer agreement sections are not captioned",
  category: "readability",
  default_severity: "warning",
  description:
    "Under an asserted plain-language statute that requires captions, flags an agreement whose sections carry no headings.",
  dkb_citations: [],
  assertion_gate: GATE,
  check(ctx: RuleContext): Finding | null {
    const std = standardOf(ctx);
    if (!std?.captions_required) return null;
    const anchor = firstParagraph(ctx);
    if (!anchor) return null;
    const { captions, paragraphs } = captionCount(ctx);
    // A document too short to have sections is not an undivided one. Below
    // four body paragraphs there is nothing for § 5-702(a)(2) to divide, and
    // accusing a one-page letter of being uncaptioned is noise.
    if (paragraphs < 4 || captions > 0) return null;
    const ceiling =
      std.max_amount === undefined
        ? ""
        : ` The statute does not reach agreements over ${formatDollars(std.max_amount)}, and this one's value was not read — asserting the standard is the reader's call.`;
    return emit(ctx, READ_003, {
      title: "The agreement is not divided into captioned sections",
      description: `${std.citation} requires an agreement it covers to be "appropriately divided and captioned by its various sections", and none of its ${paragraphs} paragraphs carries a caption — no section heading, no numbered clause title, no capitalized caption line.${ceiling}`,
      excerpt: anchor.text,
      explanation: `${std.citation}(a)(2) (read at ${std.source_url}, ${std.retrieved_at}) requires the sections of ${std.scope} to be divided and captioned. Whether a caption is APPROPRIATE to what sits under it is not judged here, and neither is ${std.not_measured ?? "the statute's qualitative language requirement"}. A violation does not make the agreement void or voidable (§ 5-702(b)); the statute provides actual damages and a $50 penalty, with no penalty where the drafter attempted in good faith to comply.`,
      recommendation:
        "Divide the agreement into sections and give each one a heading that names what it covers.",
      position: anchor,
    });
  },
};

export const READABILITY_RULES: readonly Rule[] = [READ_001, READ_002, READ_003];
