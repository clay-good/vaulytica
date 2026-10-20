import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit } from "../_helpers.js";
import { scanParagraphs } from "./_scan.js";
import { ATTACHMENT_KIND_PLURAL } from "../../../extract/attachment-kinds.js";

/** A word before "(c)" that makes it a reference to an item, not the item. */
const REFERENCE_NOUN = new RegExp(
  `\\b(?:${ATTACHMENT_KIND_PLURAL}|clauses?|paragraphs?|sub-?paragraphs?|sub-?sections?|sub-?clauses?|sections?|articles?|items?|subdivisions?|rules?|parts?|subparts?|lines?|exclusions?|exceptions?|conditions?|endorsements?|definitions?|titles?|chapters?|notes?|steps?|options?|categor(?:y|ies)|tiers?|levels?|forms?|boxes?|questions?|requests?|interrogator(?:y|ies)|counts?|claims?|§+)\\s*$`,
  "i",
);

const ROMAN: Record<string, number> = { i: 1, v: 5, x: 10, l: 50 };
function roman(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i += 1) {
    const a = ROMAN[s[i]!]!;
    const b = ROMAN[s[i + 1]!] ?? 0;
    n += a < b ? -a : a;
  }
  return n;
}
const letter = (n: number, upper = false): string => String.fromCharCode((upper ? 64 : 96) + n);
const toRoman = (n: number): string =>
  ["", "i", "ii", "iii", "iv", "v", "vi", "vii", "viii", "ix", "x", "xi", "xii"][n] ?? String(n);

export type EnumerationGap = { at: number; length: number; detail: string };

/**
 * Each enumerator that skips a place in its list: "(a) … (b) … (d)", or
 * "(i) (ii) (iv)". Read over the document's text in order, not paragraph by
 * paragraph, so a list whose items are one paragraph each and a list run into
 * one sentence are the same list — the paragraph breaks a paste moves do not
 * move this.
 *
 * Not an item, measured over the specimens (all five hits before these were
 * references): a mark attached to a citation ("1010.410(e) and (f)"); one
 * after a reference noun ("Exclusion (k)", "clauses (a) and (c)") and the
 * items coordinated with it; either end of a range ("(a) through (d)").
 * "(i)" after "(h)" is the next letter, and the same for "(v)", "(x)" and
 * "(l)"; otherwise "(i)" opens a roman list.
 */
export function enumerationGaps(text: string): EnumerationGap[] {
  const out: EnumerationGap[] = [];
  let lastLetter = 0;
  let lastUpper = 0;
  let lastRoman = 0;
  let referenceChain = false;
  for (const m of text.matchAll(/\(([a-z]|[ivxl]{1,5}|[A-Z])\)/g)) {
    const at = m.index!;
    const before = text.slice(Math.max(0, at - 40), at);
    const after = text.slice(at + m[0].length, at + m[0].length + 20);
    const reference: boolean =
      /[\w)\]]$/.test(before) ||
      REFERENCE_NOUN.test(before) ||
      /^\s?(?:through|to|–|-)\s?\(/.test(after) ||
      /(?:\bthrough|\bto|–|-)\s?$/.test(before) ||
      (referenceChain && /(?:\band|\bor|,)\s?$/.test(before));
    referenceChain = reference;
    if (reference) continue;
    const t = m[1]!;
    const gap = (expected: string): void => {
      out.push({ at, length: m[0].length, detail: `"(${t})" follows "(${expected})"` });
    };
    // A clause set in capitals capitalizes its own enumerator: "(C) ANY
    // FINANCING …" in a lowercase list is that list's next item.
    const shouted =
      /^[A-Z]$/.test(t) &&
      t.charCodeAt(0) - 64 === lastLetter + 1 &&
      !/[a-z]/.test(after) &&
      /[A-Z]{2}/.test(after);
    if (/^[A-Z]$/.test(t) && !shouted) {
      const n = t.charCodeAt(0) - 64;
      if (n === 1) lastUpper = 1;
      else if (lastUpper && n > lastUpper + 1) gap(letter(lastUpper, true));
      if (lastUpper && n === lastUpper + 1) lastUpper = n;
      continue;
    }
    const nextLetter = lastLetter + 1;
    const romanCandidate =
      !shouted && /^[ivxl]+$/.test(t) && !(t.length === 1 && t.charCodeAt(0) - 96 === nextLetter);
    if (romanCandidate && (t.length > 1 || t === "i" || lastRoman > 0)) {
      const n = roman(t);
      if (n === 1) lastRoman = 1;
      else if (lastRoman && n > lastRoman + 1) gap(toRoman(lastRoman));
      if (lastRoman && n === lastRoman + 1) lastRoman = n;
      continue;
    }
    const n = t.toLowerCase().charCodeAt(0) - 96;
    if (n === 1) {
      lastLetter = 1;
      lastRoman = 0;
    } else if (lastLetter && n > nextLetter) gap(letter(lastLetter));
    if (lastLetter && n === nextLetter) {
      lastLetter = n;
      lastRoman = 0;
    }
  }
  return out;
}

/** PROOF-006 — Enumeration out of sequence (info). */
export const rule: Rule = {
  id: "PROOF-006",
  version: "1.0.0",
  name: "Enumeration out of sequence",
  category: "proofreading",
  default_severity: "info",
  description:
    'Flags a list whose lettering or roman numbering skips a place, such as "(a) … (b) … (d)".',
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const paragraphs = scanParagraphs(ctx, (text) => [{ at: 0, length: text.length, detail: "" }]);
    // One text, in order; each paragraph begins where the previous one's
    // text ends plus the newline joining them.
    const starts: number[] = [];
    let joined = "";
    for (const p of paragraphs) {
      starts.push(joined.length);
      joined += `${p.text}\n`;
    }
    const gaps = enumerationGaps(joined);
    if (gaps.length === 0) return null;
    const first = gaps[0]!;
    let i = starts.length - 1;
    while (i > 0 && starts[i]! > first.at) i -= 1;
    const p = paragraphs[i]!;
    const local = first.at - starts[i]!;
    return emit(ctx, rule, {
      title: `Enumeration out of sequence (${gaps.length})`,
      description: `${first.detail}.`,
      excerpt: p.text,
      explanation:
        "A list that skips a letter reads as if an item was deleted — a reader, or a court, may ask what the missing item said, and a cross-reference to a later item may now point at the wrong one.",
      recommendation:
        "Restore the missing item or reletter the list, then check every cross-reference into it.",
      position: {
        ...p.position,
        start: p.position.start + local,
        end: p.position.start + local + first.length,
      },
    });
  },
};
