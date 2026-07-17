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
  /\b(?:not|no|never|neither|nor|without|excludes?|excluding|nothing)\b|\bconstrued\s+(?:as|to)\b/i;

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
