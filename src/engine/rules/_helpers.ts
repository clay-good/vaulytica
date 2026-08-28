import type { DocPosition } from "../../extract/types.js";
import type { RuleContext, Severity } from "../finding.js";
import { findSource, findStatuteCitation, makeFinding } from "../finding.js";
import { forEachParagraph, SENTENCE_END } from "../../extract/walk.js";
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

/**
 * A table-of-contents entry: heading text, dot leaders, page number.
 *
 * A TOC is not a clause, and every negotiated agreement long enough to need
 * one has one. Reading it as document text let the TOC SATISFY presence
 * rules: appending nothing but
 *
 *   ARTICLE 4 INDEMNIFICATION ..................... 15
 *   ARTICLE 5 LIMITATION OF LIABILITY ............. 21
 *
 * to an agreement that contains neither clause silenced RISK-001, RISK-005,
 * IPDATA-001, TERM-002, and TERM-005 at once — five clauses reported present
 * because the front matter lists them.
 *
 * The dot leader is the signal, and it is one no prose produces: four dots
 * or more, so an ellipsis before a number ("shall indemnify Customer ... 30
 * days after notice") is not mistaken for one. Two entries
 * are required, or one in a short paragraph, so that a paragraph carrying a
 * real clause alongside a stray leader is still read.
 */
const TOC_ENTRY = /\.{4,}\s*\d+\s*(?=$|[^\w])/g;
const TOC_SHORT_PARAGRAPH = 160;

/**
 * The same list with a SECTION locator instead of a page number — the index
 * of defined terms a large agreement carries alongside its TOC:
 *
 *   Indemnified Party        Section 7.1
 *   Termination for Cause    Section 9.3
 *
 * which silenced RISK-001 and TERM-002. Three entries are required, and the
 * paragraph must carry no sentence punctuation once section numbers are set
 * aside — a real clause listing three cross-references ("as set forth in
 * Section 7.1, Section 8.2, and Section 9.3.") ends in a period and is read
 * normally.
 */
const SECTION_LOCATOR = /\bSection\s+\d+(?:\.\d+)*\b/g;
const SECTION_NUMBER = /\d+(?:\.\d+)+|\d+/g;
const TOC_MIN_SECTION_ENTRIES = 3;

function isLocatorIndex(text: string): boolean {
  SECTION_LOCATOR.lastIndex = 0;
  const entries = text.match(SECTION_LOCATOR)?.length ?? 0;
  if (entries < TOC_MIN_SECTION_ENTRIES) return false;
  SECTION_NUMBER.lastIndex = 0;
  return !/[.,;:!?]/.test(text.replace(SECTION_NUMBER, ""));
}

export function isTableOfContents(text: string): boolean {
  TOC_ENTRY.lastIndex = 0;
  const entries = text.match(TOC_ENTRY)?.length ?? 0;
  if (entries >= 2 || (entries === 1 && text.length <= TOC_SHORT_PARAGRAPH)) return true;
  return isLocatorIndex(text);
}

/**
 * A recital: "WHEREAS, the parties intend that all intellectual property
 * created under this Agreement be owned by Customer".
 *
 * Recitals state what the parties WANT the agreement to do. They are not
 * operative and create no obligation, which is exactly why a presence rule
 * must not read one as the clause it recites. Three whereas-clauses promising
 * an indemnity, an IP allocation, a liability cap, and a termination regime
 * silenced RISK-001, IPDATA-001, RISK-005, TERM-002, and TERM-005 on an
 * agreement whose body contained none of them.
 *
 * "WHEREAS" at the head of the paragraph is the marker, and it is
 * unambiguous — no operative clause opens with it.
 */
const RECITAL_OPENER = /^\s*["'‘’“”(]?\s*WHEREAS\b/i;

export function isRecital(text: string): boolean {
  return RECITAL_OPENER.test(text);
}

/** Front matter that lists clauses instead of stating them. */
export function isNonOperative(text: string): boolean {
  return isTableOfContents(text) || isRecital(text);
}

/** Find the first paragraph where `re` matches; returns the match + position. */
export function firstParagraphMatch(ctx: RuleContext, re: RegExp): ParagraphHit | null {
  let hit: ParagraphHit | null = null;
  forEachParagraph(ctx.tree, (p) => {
    if (hit) return;
    if (isNonOperative(p.text)) return;
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
// "disclaims" is deliberately NOT a bare negator: a warranty-disclaimer rule
// fires on "disclaims all warranties" as the PRESENCE it wants. But "disclaims
// any obligation / duty / liability to <trigger>" is an unambiguous negation of
// that trigger — scoped to those object nouns so it never suppresses a warranty
// or other disclaimer that IS the finding.
const NEGATION_BEFORE =
  /\b(?:not|no|never|neither|nor|without|excludes?|excluding|nothing|waives?|waiver\s+of|waive\s+any\s+right\s+to)\b|\bconstrued\s+(?:as|to)\b|\bdisclaims?\s+(?:any\s+|all\s+)?(?:obligation|duty|responsibilit(?:y|ies)|liabilit(?:y|ies))\b/i;

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
  /**
   * Reject a match the caller can see is not the thing, and keep scanning.
   * Returning the first hit and testing it afterwards is a trap: a document
   * whose first mention is a definitional aside then hides every real
   * occurrence behind it.
   */
  skip?: (paragraph: string, matchIndex: number) => boolean,
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
      // The clause is bounded by the SHARED sentence scan, not by a literal
      // "." split: "shall not, per Sec. 5 hereof, automatically renew" lost its
      // negator at the abbreviation and was reported as a live auto-renewal.
      // Still floored at the `window` slice, so a distant negation in the same
      // sentence cannot reach forward and suppress a genuine trigger.
      const clause = p.text.slice(Math.max(from, clauseStartBefore(p.text, m.index)), m.index);
      if (!NEGATION_BEFORE.test(clause) && !skip?.(p.text, m.index)) {
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
  /\b(?:(?:do(?:es)?|shall|will|may|must)\s+not\s+(?:include|contain|provide\s+for|provide|require|impose|create|permit|allow|grant|obligate|contemplate|use)|(?:contain|include)s?\s+no\b|ha[sv]e\s+no\b|need\s+not\b|no\s+(?:obligation|provision|provisions|requirement|right|duty)\b|no\s+(?:party|one|person|entity)\s+(?:is|are|shall\s+be|will\s+be|has|have)\s+(?:required|obligated|liable|responsible|any\s+obligation)\b|(?:is|are)\s+not\s+(?:required|obligated|permitted|entitled)\b|not\s+(?:be\s+(?:required|obligated|permitted|entitled|held|deemed|subject|construed)|have\s+(?:the\s+)?right)|exclude(?:s|d)?\s+(?:any\s+|all\s+)?$|nothing\s+(?:herein|contained\s+herein|in\s+th(?:is|ese)\s+[\w\s]{0,24}?)\s*(?:shall|will|may|does|is)?\s*(?:require|obligate|provide\s+for|provide|contain|include|contemplate|create|impose|grant|permit|allow|entitle)?s?\s*(?:for\s+)?(?:[\w\s]{0,24}?\s+to\s+)?$|no\s*$)/i;

/**
 * Index of the first character of the sentence/clause containing `at`.
 *
 * The ONE reverse boundary scan for this file. `enclosingSentence` already got
 * this right — it walks the shared, abbreviation-aware `SENTENCE_END` rather
 * than looking for a literal ". " — but two sibling helpers kept their own
 * hand-rolled `lastIndexOf(". ")` / `split(/[.;]\s|\n/)` versions, which stop
 * at the period in "Sec. 5", "Art. 28" or "No. 5". Both of those helpers exist
 * to FIND A NEGATION before the trigger, so truncating there dropped the
 * negation and let the rule fire on drafting that had plainly disclaimed the
 * clause — a confident false accusation, the failure this file's own comments
 * call the worst honesty failure for an always-on rule.
 *
 * Sharing one scan is the point: copies of this boundary rule keep drifting —
 * this was the third and fourth found in the file, and a repo-wide sweep then
 * turned up two more inside individual rules (CHOICE-007, IPDATA-009) using a
 * BARE `lastIndexOf(".")`, which stops even at the "." in "Section 5.2". Hence
 * the export: a single definition cannot drift from itself.
 */
export function clauseStartBefore(text: string, at: number): number {
  // ONE backward scan, stopping at the first boundary of any kind — which is
  // by definition the nearest, i.e. the same value the previous
  // `Math.max(dot, lastIndexOf("; "), lastIndexOf("\n"))` produced.
  //
  // Cost follows the DISTANCE BACK TO THE BOUNDARY, not the length of the
  // document, and that is the whole point. Running `SENTENCE_END` forward from
  // index 0, or calling `lastIndexOf` on a string that contains no ";" or
  // newline at all, is O(n) per call — and these helpers call this once per
  // regex match inside a loop over every match in the paragraph, so the scan
  // became super-linear overall: a 94,000-character paragraph took 190ms, and
  // doubling the input roughly quintupled the time. This repo guarantees no
  // super-linear blowup on adversarial input, and the paste limit allows a
  // single very large paragraph.
  //
  // The period test uses a STICKY regex so the result is identical to matching
  // `SENTENCE_END` at that index: `y` anchors the test at exactly `i`, and the
  // lookbehind still sees the whole string.
  const bound = new RegExp(SENTENCE_END, "y");
  for (let i = at - 1; i >= 0; i--) {
    const c = text[i];
    if (c === "\n") return i + 1;
    if (c === ";" && text[i + 1] === " ") return i + 1;
    if (c === ".") {
      bound.lastIndex = i;
      if (bound.test(text)) return i + 1;
    }
  }
  return 0;
}

/**
 * True when the trigger at `matchIndex` sits in a sentence whose text BEFORE
 * the match disclaims the clause's presence (see {@link CLAUSE_ABSENCE}).
 * Scoped to the enclosing sentence (cut at the last `.`/`;`/newline before the
 * match) so a disclaimer in a prior sentence never suppresses a genuine clause
 * in this one. Honesty-first: a presence-detector that would fire on the
 * disclaimed form suppresses instead — a missed flag is safer than a false one.
 */
export function isPresenceDisclaimed(paragraph: string, matchIndex: number): boolean {
  const before = paragraph.slice(clauseStartBefore(paragraph, matchIndex), matchIndex);
  return CLAUSE_ABSENCE.test(before);
}

/**
 * The single sentence of `paragraph` containing `matchIndex` — bounded by the
 * `.`/`;`/newline before it and the next `.`/`;`/newline after. Lets a rule
 * tally modifiers/subjects within one clause without absorbing an unrelated
 * neighbouring sentence in the same paragraph.
 */
export function enclosingSentence(paragraph: string, matchIndex: number): string {
  // A "." ends a sentence only when it is followed by whitespace + a capital
  // letter/digit (the start of the next sentence) or by the string end. A period
  // inside "vendor.com" / "160.103" (no following space) OR a corporate-suffix /
  // Latin abbreviation followed by a lowercase word ("Inc. shall", "Corp. will",
  // "C.F.R. requires", "5 p.m. deadline") is NOT a boundary — so the clause the
  // caller asked about is not silently truncated at the abbreviation. The
  // backward scan mirrors the forward one: `lastIndexOf(". ")` would have
  // stopped at "Inc. ", so it is replaced by a capital/digit-aware reverse scan.
  const start = clauseStartBefore(paragraph, matchIndex);
  const rel = paragraph.slice(matchIndex).search(new RegExp(`[;\\n]|${SENTENCE_END}`));
  const end = rel === -1 ? paragraph.length : matchIndex + rel + 1;
  return paragraph.slice(start, end);
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
  // EVERY section list in the survival text, not just the first. A survival
  // clause is frequently spread over more than one paragraph — the
  // confidentiality section says "this Section survives for seven years", the
  // termination section says "Sections 5, 6, 9, 10, 11, 12 … survive" — and
  // the joined text is scanned in document order. Taking the first match meant
  // an unrelated cross-reference in the earlier paragraph ("Nothing in this
  // Section limits the publication rights in Section 11") became the whole
  // incorporated list, so the operative enumeration was never read and
  // TEMP-012 reported the indemnity as unnamed in a clause that names it.
  const LIST = /\bSections?\s+(\d+(?:\.\d+)*(?:(?:\s*(?:,|and|&)\s*)+\d+(?:\.\d+)*)*)/gi;
  // A RANGE is as common as an enumeration — "Sections 2 through 5 and Section
  // 7 survive", "Sections 9-12 survive" — and the enumeration pattern reads
  // only its first endpoint, so the sections in between were never
  // incorporated.
  const RANGE = /\bSections?\s+(\d+)\s*(?:through|thru|to|[-–—])\s*(\d+)\b/gi;
  const nums = new Set<string>();
  LIST.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = LIST.exec(survivalText)) !== null) {
    for (const n of m[1]!.split(/[^0-9.]+/).filter(Boolean)) nums.add(n);
  }
  RANGE.lastIndex = 0;
  let r: RegExpExecArray | null;
  while ((r = RANGE.exec(survivalText)) !== null) {
    const from = Number(r[1]);
    const to = Number(r[2]);
    // Bounded so a malformed or reversed range cannot spin.
    if (Number.isFinite(from) && Number.isFinite(to) && to > from && to - from <= 60) {
      for (let n = from; n <= to; n += 1) nums.add(String(n));
    }
  }
  if (nums.size === 0) return survivalText;
  const named: string[] = [];
  forEachParagraph(ctx.tree, (p) => {
    const label = /^\s*(\d+(?:\.\d+)*)[.)]\s+/.exec(p.text)?.[1];
    if (label && nums.has(label)) named.push(p.text);
  });
  return named.length > 0 ? `${survivalText}\n${named.join("\n")}` : survivalText;
}

/**
 * Build express-disclaimer patterns for a presence rule's `denied_if`.
 *
 * `topic` is a regex source fragment naming the required clause (e.g.
 * `"ofac|sanctions\\s+screening"`). The frames below wrap it in the ways a
 * document actually disclaims an obligation. The word gap refuses to cross
 * a conditional connective, so a COMPLIANT sentence that pairs a negation
 * with the topic — "no customer shall be onboarded WITHOUT OFAC screening"
 * — is not read as a denial.
 */
export function expressDenial(topic: string): RegExp[] {
  const t = `(?:${topic})`;
  // Up to three filler words — four was measured to be too many: "this
  // Agreement shall not become effective until the REVOCATION PERIOD expires"
  // (the compliant OWBPA drafting) then reads as a denial of the revocation
  // right. The gap refuses to cross a conditional
  // connective ("...not onboard a customer WITHOUT OFAC screening"), a
  // temporal one ("data shall not be RETAINED AFTER the deletion-or-return
  // obligation is discharged" — the negation governs retention, not the
  // deletion clause), or a
  // scope verb ("this policy does not APPLY TO OFAC screening by third
  // parties"), because neither sentence denies that the clause exists.
  const gap = String.raw`(?:(?!\b(?:without|unless|except|absent|failing|prior|after|before|until|once|upon|following|appl(?:y|ies)|affect|affects|limit|limits|waive|waives|relieve|relieves|supersede|supersedes|alter|alters|modify|modifies|excuse|excuses|prevent|prevents|preclude|precludes|restrict|restricts|withhold|withholds|withholding|deny|denies|denying|refuse|refuses|refusing|impair|impairs|delay|delays|obstruct|obstructs|interfere|interferes)\b)\w+[\s,]+){0,3}`;
  // "contain" and "include" are how an INSTRUMENT denies carrying a clause —
  // "this trust contains no spendthrift provision" — as against the conduct
  // verbs, which are how a party denies doing something.
  const verb =
    "(?:perform|conduct|provide|maintain|require|undertake|implement|operate|run|have|has|make|exercise|exercises|grant|grants|contain|contains|include|includes)";
  // Past participles a denial lands on. Deliberately excludes "permitted" /
  // "allowed": "failure to file a SAR is not permitted" is a PROHIBITION of
  // the failure, i.e. the compliant drafting, not a denial of the clause.
  const done =
    "(?:required|performed|conducted|maintained|provided|undertaken|implemented|applicable|filed|retained|kept|screened|collected|identified|obtained|established|withdrawn|revoked|honored|honoured|granted|issued|suspended|available|offered|encrypted|appointed|designated|reviewed|notified|exchanged|delivered|attached|bound|deleted|destroyed|returned)";
  // A conditional connective AFTER the topic turns the sentence into a
  // REQUIREMENT, not a denial: "may not engage a subcontractor WITHOUT a
  // written contract" demands the contract, it does not disclaim it. The gap's
  // blocked list cannot see this one, because the connective trails the topic.
  const tail = String.raw`(?![^.]{0,40}?\b(?:without|unless|except)\b)`;
  return [
    // "does not perform OFAC screening" / "is not required to conduct AML training"
    new RegExp(
      String.raw`\b(?:do|does|did|shall|will|is|are|was|were|has|have|had|can|may|need)\s+not\s+(?:be\s+)?${gap}${t}${tail}`,
      "i",
    ),
    // "cannot revoke this authorization"
    new RegExp(String.raw`\bcan\s?not\s+(?:be\s+)?${gap}${t}`, "i"),
    // "is not required to ensure that any subcontractor agrees in writing".
    // The obligation verb and its object push the topic past the word gap, but
    // "not required to" is itself a strong denial marker, so the topic only has
    // to appear later in the SAME sentence.
    new RegExp(
      String.raw`\b(?:is|are|was|were|shall|will|does|do|has|have)\s+not\s+(?:be\s+)?(?:required|obligated|obliged)\s+to\b[^.]{0,60}?${t}`,
      "i",
    ),
    // "performs no OFAC screening" / "maintains no SAR procedures"
    new RegExp(String.raw`\b${verb}(?:s|es|ed)?\s+no\s+${gap}${t}`, "i"),
    // "OFAC screening is not required" / "consent may not be withdrawn"
    new RegExp(
      String.raw`\b${t}\b[^.]{0,80}?\b(?:is|are|shall\s+be|will\s+be|shall|will|may|can|must)\s+not\s+(?:be\s+)?${done}`,
      "i",
    ),
    // "consent cannot be withdrawn"
    new RegExp(String.raw`\b${t}\b[^.]{0,80}?\bcan\s?not\s+(?:be\s+)?${done}`, "i"),
    // "no OFAC screening is performed" / "no financial disclosure was exchanged"
    new RegExp(
      String.raw`\bno\s+${gap}${t}\b[^.]{0,80}?\b(?:is|are|was|were|shall\s+be|will\s+be|has\s+been|have\s+been)\s+${done}`,
      "i",
    ),
  ];
}

/**
 * A document that amends a parent agreement, recognized by its ratification
 * clause.
 *
 * An amendment, addendum, or amended-and-restated schedule changes named terms
 * and leaves everything else where it was: "Except as expressly modified by
 * this Amendment, the Lease remains in full force and effect and is ratified
 * and confirmed." That sentence is the drafting convention for saying so, and
 * it is the whole reason the document does not restate governing law, the
 * liability cap, the indemnity, the IP allocation, or the termination
 * machinery — the parent still supplies all of them.
 *
 * Reporting those as absent is a false accusation with no answer: the only
 * drafting change that would satisfy it is restating the parent agreement
 * inside its own amendment, which no one does and no reviewer wants. The
 * always-on absence checks consult this and stay silent.
 *
 * Deliberately narrow. It is NOT "the document mentions another agreement" —
 * every commercial contract incorporates exhibits by reference, and a DPA
 * incorporates the Standard Contractual Clauses; matching those would switch
 * the checks off across the catalog. It is the ratification sentence
 * specifically, which only an amending document carries. No corpus fixture
 * contains one.
 */
const RATIFIES_PARENT =
  /(?:except\s+as\s+(?:expressly\s+|otherwise\s+){0,2}(?:modified|amended|changed|provided|set\s+forth)|all\s+other\s+(?:terms|provisions|covenants)\b)[^.]{0,160}?(?:remains?|shall\s+remain|continues?|shall\s+continue|are\s+unchanged|is\s+unchanged)\s+(?:unchanged\s+and\s+)?in\s+full\s+force|in\s+all\s+other\s+respects[^.]{0,100}?(?:ratified|confirmed|unchanged)/i;

/**
 * The other half of the same shape: a document ISSUED UNDER a named parent.
 *
 * A statement of work, order form, addendum, or companion agreement is not an
 * amendment — it adds rather than changes, so it carries no ratification
 * clause — but it is subordinate in exactly the same way: "This Statement of
 * Work is entered into under and subject to the Master Services Agreement
 * dated February 12, 2024", and, where the two disagree, "the MSA controls".
 * The parent supplies governing law, the liability cap, the indemnity, the IP
 * allocation, and the termination machinery, and the child says so.
 *
 * Both halves require a NAMED parent — a capitalized instrument title, or an
 * order-of-precedence clause in which the other document controls. That is
 * what keeps it from matching an ordinary agreement: a standalone contract
 * never says another agreement governs it.
 */
const ISSUED_UNDER_PARENT =
  /\b(?:under|pursuant\s+to|issued\s+under|governed\s+by\s+the\s+terms\s+of)\s+(?:and\s+subject\s+to\s+)?(?:that\s+certain\s+)?the\s+(?:[A-Z][\w&.-]*\s+){1,5}(?:Agreement|Lease|Contract)\b/;
const PARENT_CONTROLS =
  // Case-SENSITIVE by design: the parent has to be a NAMED instrument, which
  // is what `[A-Z]` and the capitalized "Agreement" enforce. Only the leading
  // conflict phrase is case-folded, by hand, because it opens a sentence.
  /\b(?:[Ii]n\s+the\s+event\s+of\s+(?:any\s+)?(?:a\s+)?conflict|[Tt]o\s+the\s+extent\s+of\s+(?:any\s+)?conflict|[Ii]f\s+there\s+is\s+(?:any\s+)?conflict)[^.]{0,140}?\bthe\s+(?:[A-Z][\w&.-]*\s+){0,4}(?:Agreement|Lease|Contract|MSA)\s*(?:controls|prevails|governs|shall\s+control|shall\s+prevail|shall\s+govern|takes\s+precedence)/;

/**
 * Whether the document is subordinate to a named parent agreement — either
 * because it amends and ratifies one, or because it is issued under one.
 */
export function amendsParentAgreement(ctx: RuleContext): boolean {
  const parts: string[] = [];
  const walk = (sections: RuleContext["tree"]["sections"]): void => {
    for (const section of sections) {
      for (const p of section.paragraphs) for (const r of p.runs) parts.push(r.text);
      walk(section.children);
    }
  };
  walk(ctx.tree.sections);
  const text = parts.join(" ");
  return RATIFIES_PARENT.test(text) || ISSUED_UNDER_PARENT.test(text) || PARENT_CONTROLS.test(text);
}

/**
 * A context window around a match, snapped to word boundaries.
 *
 * The excerpt is what a reader actually sees — in the fix list, the HTML
 * report, and the DOCX — and a raw `slice(index - 30, index + 280)` cuts
 * whatever happens to be there: "n (11) paid holidays per contract year",
 * "perty in the ordinary course", "ter requires, and we will use reasonable
 * efforts", "al Statements. The Financial Statements attached as Schedule".
 * Sweeping the twenty-eight specimens found that on nine of them. A finding
 * that quotes half a word reads as a broken tool, whatever it says next.
 *
 * The window is widened, never narrowed: each edge moves outward to the
 * nearest boundary, by at most a word's length, so no matched text is lost.
 */
const WORD_SNAP_MAX = 24;

export function excerptWindow(text: string, index: number, before: number, after: number): string {
  let start = Math.max(0, index - before);
  let end = Math.min(text.length, index + after);
  // Move the start LEFT off a partial word.
  const limitStart = Math.max(0, start - WORD_SNAP_MAX);
  while (start > limitStart && /\w/.test(text[start - 1] ?? "") && /\w/.test(text[start] ?? "")) {
    start -= 1;
  }
  // Move the end RIGHT off a partial word.
  const limitEnd = Math.min(text.length, end + WORD_SNAP_MAX);
  while (end < limitEnd && /\w/.test(text[end - 1] ?? "") && /\w/.test(text[end] ?? "")) {
    end += 1;
  }
  return text.slice(start, end).trim();
}
