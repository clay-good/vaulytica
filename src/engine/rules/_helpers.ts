import type { DocPosition } from "../../extract/types.js";
import type { RuleContext, Severity } from "../finding.js";
import { findSource, findStatuteCitation, makeFinding } from "../finding.js";
import { forEachParagraph } from "../../extract/walk.js";
import type { ClassifiedParagraph } from "../../extract/types.js";
import type { SourceCitation } from "../../dkb/types.js";

/**
 * Shared helpers used by the launch rules. Each helper is a pure function
 * over RuleContext so rules stay short, declarative, and easy to audit.
 */

export type ParagraphHit = {
  text: string;
  match: RegExpExecArray;
  position: DocPosition;
};

/** Find the first paragraph where `re` matches; returns the match + position. */
export function firstParagraphMatch(ctx: RuleContext, re: RegExp): ParagraphHit | null {
  let hit: ParagraphHit | null = null;
  forEachParagraph(ctx.tree, (p) => {
    if (hit) return;
    const r = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
    r.lastIndex = 0;
    const m = r.exec(p.text);
    if (!m) return;
    hit = {
      text: p.text,
      match: m,
      position: {
        section_id: p.section.id,
        paragraph_id: p.paragraph.id,
        start: p.start + m.index,
        end: p.start + m.index + m[0].length,
      },
    };
  });
  return hit;
}

/**
 * Negators that flip a trigger phrase to its disclaiming form. Checked in a
 * short window immediately before a match — "shall NOT auto-renew", "NO waiver
 * of…", "does NOT contain a non-compete", "NOTHING shall be CONSTRUED AS a
 * covenant not to compete", "shall not be subject to arbitration".
 */
const NEGATION_BEFORE =
  /\b(?:not|no|never|neither|nor|without|excludes?|excluding|nothing|waives?|waiver\s+of|waive\s+any\s+right\s+to)\b|\bconstrued\s+(?:as|to)\b/i;

/**
 * Like {@link firstParagraphMatch}, but SKIPS a match that is negated — one
 * preceded within ~50 chars (in the same clause) by a negator. A trigger-phrase
 * rule that fires on the *disclaimed* form of its own clause ("shall not
 * auto-renew" → "auto-renewal present") is a confident false accusation, the
 * worst honesty failure for an always-on rule. Returns the first UN-negated
 * match so a paragraph carrying both a disclaimer and a real clause still fires
 * on the real one. Honesty-first: an ambiguous negation suppresses the finding
 * (a missed flag is safer than a false one).
 */
export function firstUnnegatedParagraphMatch(
  ctx: RuleContext,
  re: RegExp,
  window = 50,
): ParagraphHit | null {
  let hit: ParagraphHit | null = null;
  forEachParagraph(ctx.tree, (p) => {
    if (hit) return;
    const r = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
    let m: RegExpExecArray | null;
    while ((m = r.exec(p.text)) !== null) {
      const from = Math.max(0, m.index - window);
      // Confine the negator search to the current clause (after the last
      // sentence/clause break before the match), so a negation in a prior
      // sentence never suppresses a genuine trigger.
      const before = p.text.slice(from, m.index);
      const clause = before.split(/[.;]\s|\n/).pop() ?? before;
      if (!NEGATION_BEFORE.test(clause)) {
        hit = {
          text: p.text,
          match: m,
          position: {
            section_id: p.section.id,
            paragraph_id: p.paragraph.id,
            start: p.start + m.index,
            end: p.start + m.index + m[0].length,
          },
        };
        return;
      }
      if (m[0].length === 0) r.lastIndex += 1;
    }
  });
  return hit;
}

/**
 * Markers that a clause or obligation is ABSENT / DISCLAIMED rather than
 * present: "does not include a X clause", "contains no X", "shall not [do X]",
 * "need not", "no obligation to X", "not be required to X". Used by
 * presence-detector rules ("X clause present") so they do not fire on a
 * document's explicit statement that X is NOT present — a confident false
 * accusation, the worst honesty failure for an always-on rule.
 *
 * Deliberately SPECIFIC — "not" must attach to an inclusion/action verb
 * ("does not include", "shall not use", "need not") or an explicit absence
 * phrase — NOT a bare "aux + not". A genuine operative clause routinely carries
 * an unrelated negator ("Neither party shall be liable … force majeure",
 * "Employee agrees not to disparage", "the breach would not result in a
 * material adverse effect") and must still fire; only language negating the
 * clause's PRESENCE or the actor's OBLIGATION to do the thing suppresses.
 *
 * The `nothing herein …` branch matches the disclaimer idiom every carve-out
 * uses — "nothing herein waives any right to participate in a class action",
 * "nothing in this Code restricts protected activity". The subject itself is
 * the negator, so no verb-level "not" ever appears and the branches above all
 * miss it; anchored to the end of the pre-trigger slice so it only suppresses
 * the trigger the disclaimer actually governs.
 *
 * The final `no\s*$` branch matches a bare "no" sitting immediately before the
 * trigger ("no residuals clause is granted", "grants no source-code escrow") —
 * the determiner negates the trigger noun itself. Anchored to the end of the
 * pre-trigger slice, so it only fires on "no <trigger>", never on an unrelated
 * "no" earlier in the sentence, and never on "not"/"no-hire" (no trailing
 * whitespace-to-trigger).
 */
const CLAUSE_ABSENCE =
  /\b(?:(?:do(?:es)?|shall|will|may|must)\s+not\s+(?:include|contain|provide\s+for|provide|require|impose|create|permit|allow|grant|obligate|contemplate|use)|(?:contain|include)s?\s+no\b|ha[sv]e\s+no\b|need\s+not\b|no\s+(?:obligation|provision|provisions|requirement|right|duty)\b|not\s+(?:be\s+(?:required|obligated|permitted|entitled|held|deemed|subject|construed)|have\s+(?:the\s+)?right)|nothing\s+(?:herein|contained\s+herein|in\s+th(?:is|ese)\s+[\w\s]{0,24}?)\s*(?:shall|will|may|does|is)?\s*$|no\s*$)/i;

/**
 * True when the trigger at `matchIndex` sits in a sentence whose text BEFORE
 * the match disclaims the clause's presence (see {@link CLAUSE_ABSENCE}).
 * Scoped to the enclosing sentence (cut at the last `.`/`;`/newline before the
 * match) so a disclaimer in a prior sentence never suppresses a genuine clause
 * in this one. Honesty-first: a presence-detector that would fire on the
 * disclaimed form suppresses instead — a missed flag is safer than a false one.
 */
export function isPresenceDisclaimed(paragraph: string, matchIndex: number): boolean {
  const start = Math.max(
    paragraph.lastIndexOf(". ", matchIndex),
    paragraph.lastIndexOf("; ", matchIndex),
    paragraph.lastIndexOf("\n", matchIndex),
  );
  const before = paragraph.slice(start + 1, matchIndex);
  return CLAUSE_ABSENCE.test(before);
}

/**
 * The single sentence of `paragraph` containing `matchIndex` — bounded by the
 * `.`/`;`/newline before it and the next `.`/`;`/newline after. Lets a rule
 * tally modifiers/subjects within one clause without absorbing an unrelated
 * neighbouring sentence in the same paragraph.
 */
export function enclosingSentence(paragraph: string, matchIndex: number): string {
  const start = Math.max(
    paragraph.lastIndexOf(". ", matchIndex),
    paragraph.lastIndexOf("; ", matchIndex),
    paragraph.lastIndexOf("\n", matchIndex),
  );
  const rel = paragraph.slice(matchIndex).search(/[.;\n]/);
  const end = rel === -1 ? paragraph.length : matchIndex + rel + 1;
  return paragraph.slice(start + 1, end);
}

/** Returns true if any classified paragraph belongs to `category`. */
export function hasCategory(ctx: RuleContext, category: string): boolean {
  return ctx.extracted.classified.some((c) => c.category === category);
}

/** First paragraph classified into `category`, with its position. */
export function firstByCategory(
  ctx: RuleContext,
  category: string,
): { classification: ClassifiedParagraph; text: string; position: DocPosition } | null {
  const cls = ctx.extracted.classified.find((c) => c.category === category);
  if (!cls) return null;
  type Found = { text: string; position: DocPosition };
  let found: Found | null = null;
  forEachParagraph(ctx.tree, (p) => {
    if (found) return;
    if (p.paragraph.id !== cls.paragraph_id) return;
    found = {
      text: p.text,
      position: {
        section_id: p.section.id,
        paragraph_id: p.paragraph.id,
        start: p.start,
        end: p.end,
      },
    };
  });
  if (!found) return null;
  const f = found as Found;
  return { classification: cls, text: f.text, position: f.position };
}

/** Collect every regex match across the document, with positions. */
export function allMatches(ctx: RuleContext, re: RegExp): ParagraphHit[] {
  const out: ParagraphHit[] = [];
  forEachParagraph(ctx.tree, (p) => {
    const r = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
    let m: RegExpExecArray | null;
    while ((m = r.exec(p.text)) !== null) {
      out.push({
        text: p.text,
        match: m,
        position: {
          section_id: p.section.id,
          paragraph_id: p.paragraph.id,
          start: p.start + m.index,
          end: p.start + m.index + m[0].length,
        },
      });
      // A zero-width match (e.g. a rule regex like `/x?/` or `/\b/`) does not
      // advance `lastIndex`, so without this the loop spins forever — a
      // synchronous hang of the tab, exactly the unbounded work spec-v8 §5
      // forbids. Step past it.
      if (m[0].length === 0) r.lastIndex += 1;
    }
  });
  return out;
}

/** Resolve a list of source ids to SourceCitation objects (drops nulls). */
export function resolveCitations(ctx: RuleContext, ids: readonly string[]): SourceCitation[] {
  return ids
    .map((id) => findStatuteCitation(ctx.dkb, id) ?? findSource(ctx.dkb, id))
    .filter((s): s is NonNullable<typeof s> => Boolean(s));
}

/** Short signature for rule files: one-shot finding factory with citations. */
export function emit(
  ctx: RuleContext,
  rule: import("../finding.js").Rule,
  args: {
    severity?: Severity;
    title: string;
    description: string;
    excerpt: string;
    explanation: string;
    recommendation?: string;
    position: DocPosition;
  },
): import("../finding.js").Finding {
  return makeFinding({
    rule,
    severity: args.severity,
    title: args.title,
    description: args.description,
    excerptText: args.excerpt,
    explanation: args.explanation,
    recommendation: args.recommendation,
    position: args.position,
    source_citations: resolveCitations(ctx, rule.dkb_citations),
  });
}

/** Convenience: position at the very start of the document. */
export function topPosition(ctx: RuleContext): DocPosition {
  return { section_id: ctx.tree.sections[0]?.id ?? "", start: 0, end: 0 };
}

/**
 * Expand a survival clause's numbered section list into the text of the
 * sections it names. "Sections 2, 5, 7, and 9 survive termination" keeps
 * everything in those sections alive, but a keyword test against the survival
 * sentence alone reported the categories those sections carry as un-named —
 * telling a drafter whose survival list includes the assignment section that
 * it "does not name IP ownership". Paste-ingested documents have no section
 * outline, so the numbers resolve against paragraphs opening "N. Title", the
 * same way the cross-reference resolver reads them.
 */
export function expandSurvivalSectionRefs(ctx: RuleContext, survivalText: string): string {
  // The separator must absorb the Oxford ", and" — a single-token separator
  // stopped the capture at "8" in "Sections 4, 5, 7, 8, and 15".
  const m = /\bSections?\s+(\d+(?:\.\d+)*(?:(?:\s*(?:,|and|&)\s*)+\d+(?:\.\d+)*)*)/i.exec(
    survivalText,
  );
  if (!m) return survivalText;
  const nums = new Set(m[1]!.split(/[^0-9.]+/).filter(Boolean));
  const named: string[] = [];
  forEachParagraph(ctx.tree, (p) => {
    const label = /^\s*(\d+(?:\.\d+)*)[.)]\s+/.exec(p.text)?.[1];
    if (label && nums.has(label)) named.push(p.text);
  });
  return named.length > 0 ? `${survivalText}\n${named.join("\n")}` : survivalText;
}
