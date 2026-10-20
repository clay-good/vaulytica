import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit } from "../_helpers.js";
import { scanParagraphs } from "./_scan.js";

const PAIRS = [
  ["(", ")", "parenthesis"],
  ["[", "]", "bracket"],
  ["{", "}", "brace"],
] as const;

type Balance = { open: number[]; quotes: string[] };

/**
 * Each bracket kind's surplus of opening marks in one paragraph (negative for
 * a surplus of closing ones), and the quotation marks that do not pair, or
 * undefined when the paragraph is one this rule does not read.
 *
 * Measured over the 363 specimens and their format rewrites before it shipped,
 * and every exclusion here is a false hit read there:
 *   - a court caption draws ")" as its column rule ("PLAINTIFF, ) Case No."),
 *     a ")" set apart by space on both sides, which a closing mark never is;
 *   - a bare enumerator ("a)", "ii)", "3)") closes what it never opened;
 *   - a quotation that runs over several paragraphs opens each paragraph with
 *     a quotation mark and closes only the last.
 * Straight single quotes are apostrophes, and the inch marks of a dimension
 * are units; neither is counted.
 */
function balance(text: string): Balance | undefined {
  // Dropped mark by mark, so it holds whether the caption is one paragraph
  // or a paragraph per line.
  // The inch marks of a dimension ('3" x 5" card'), which Word curls as
  // closing marks. Only in a dimension: '"Severity 1"' ends a quotation.
  const p = text
    .replace(/(?<!\S)\)(?!\S)/g, " ")
    .replace(/(?<=\d)["”](?=\s?[x×]\s?\d)|(?<=[x×]\s?\d{1,4}(?:\.\d{1,3})?)["”]/g, " ");
  if (/(?:^|[\s;:])(?:[a-z]|[ivx]{1,4}|\d{1,2})\)\s/i.test(p)) return undefined;
  const n = (c: string): number => p.split(c).length - 1;
  const quotes: string[] = [];
  const opensQuote = /^\s*["“]/.test(p);
  const closesQuote = /[.;,!?]?["”][.;,]?\s*$/.test(p);
  const curly = n("“") - n("”");
  if (curly !== 0 && !(curly === 1 && opensQuote) && !(curly === -1 && closesQuote))
    quotes.push("curly quotation marks do not pair");
  if (n('"') % 2 === 1 && !opensQuote && !closesQuote)
    quotes.push("a straight quotation mark has no partner");
  return { open: PAIRS.map(([o, c]) => n(o) - n(c)), quotes };
}

function describe(b: Balance): string | undefined {
  const issues = PAIRS.flatMap(([, , name], i) =>
    b.open[i]! > 0
      ? [`an opening ${name} is never closed`]
      : b.open[i]! < 0
        ? [`a closing ${name} has no opening one`]
        : [],
  );
  issues.push(...b.quotes);
  return issues.length > 0 ? issues.join("; ") : undefined;
}

/** What in one paragraph does not pair, or undefined. */
export function unpairedMarks(text: string): string | undefined {
  const b = balance(text);
  return b ? describe(b) : undefined;
}

/**
 * The paragraphs whose marks do not pair, read in order. A mark left open at
 * the end of one paragraph and closed in the next is one aside a break fell
 * inside — a page number, a running header or a hard wrap set mid-sentence
 * splits a sentence into two paragraphs — so the two are paired first.
 */
export function unpairedParagraphs(
  texts: readonly string[],
): Array<{ index: number; detail: string }> {
  const all = texts.map((t) => balance(t));
  for (let i = 0; i + 1 < all.length; i += 1) {
    const here = all[i];
    const next = all[i + 1];
    if (!here || !next) continue;
    for (let k = 0; k < PAIRS.length; k += 1) {
      if (here.open[k]! > 0 && next.open[k]! < 0) {
        const carried = Math.min(here.open[k]!, -next.open[k]!);
        here.open[k]! -= carried;
        next.open[k]! += carried;
      }
    }
  }
  return all.flatMap((b, index) => {
    const detail = b ? describe(b) : undefined;
    return detail ? [{ index, detail }] : [];
  });
}

/** PROOF-001 — Unpaired punctuation (warning). */
export const rule: Rule = {
  id: "PROOF-001",
  version: "1.0.0",
  name: "Unpaired punctuation",
  category: "proofreading",
  default_severity: "warning",
  description:
    "Flags a paragraph whose parentheses, brackets or quotation marks do not pair — an opening mark with no closing one, or the reverse.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const paragraphs = scanParagraphs(ctx, (text) => [{ at: 0, length: text.length, detail: "" }]);
    const hits = unpairedParagraphs(paragraphs.map((p) => p.text)).map(({ index, detail }) => ({
      ...paragraphs[index]!,
      detail,
    }));
    if (hits.length === 0) return null;
    const first = hits[0]!;
    return emit(ctx, rule, {
      title: `Unpaired punctuation in ${hits.length} paragraph${hits.length === 1 ? "" : "s"}`,
      description: `${first.detail[0]!.toUpperCase()}${first.detail.slice(1)}.`,
      excerpt: first.text,
      explanation:
        "An unclosed parenthesis or quotation leaves the reader to guess where an aside, a defined term or a quotation ends — and a defined term's scope can turn on it.",
      recommendation: "Close the mark where the aside or quotation ends, or remove the stray one.",
      position: first.position,
    });
  },
};
