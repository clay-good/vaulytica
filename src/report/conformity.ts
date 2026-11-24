/**
 * Does the signed copy match the final draft? (add-executed-copy-conformity)
 *
 * The clause redline between a final draft and its executed copy, with the
 * differences execution is SUPPOSED to introduce set aside and listed:
 *
 *   - signature-block lines (`By:`, `Name:`, `Title:`, `Date:`, `/s/`,
 *     initials, witness and notary lines), on either side;
 *   - a short entry under the signature block — the printed name a signer
 *     writes on its own line — in the executed copy only;
 *   - a blank the final left for execution (`____`, `[●]`, `[DATE]`) filled
 *     in, where nothing else in the paragraph changed;
 *   - a page legend or watermark word ("FINAL", "EXECUTION VERSION",
 *     "EXECUTED", "Page 2 of 9") alone on its line.
 *
 * What remains is reported as differences, with a verdict. Nothing here says
 * whether a difference matters: a changed figure and a changed comma are both
 * differences, and the redline shows which is which.
 *
 * `conformity_hash` covers the verdict, the differences and the set-aside
 * list, namespaced apart from every `result_hash`; the comparison's own hash
 * is untouched.
 */
import type { DocumentTree } from "../ingest/types.js";
import { sha256Hex } from "../ingest/hash.js";
import { buildClauseDiff, flattenClauses, type Clause, type ClauseDiff } from "./clause-diff.js";

export const CONFORMITY_VERSION = "2";

/**
 * A signature-block line: the label a signer fills in, on its own line. Ingest
 * joins a signature rule with the printed name under it ("____ Jordan Lee"),
 * so an underline followed by a short name is one too.
 */
const SIGNATURE_LINE =
  /^(?:by|name|print(?:ed)? name|title|its|date|dated|signature|signed|witness|witnessed by|attest|initials?|address|email)\s*:|^\/s\/|^[_\s.]{6,}$|^_{4,}\s{1,3}[^.;:_]{1,60}$|^(?:notary public|my commission expires|subscribed and sworn|acknowledged before me|state of [a-z ]+\)|county of [a-z ]+\))/i;

/** A legend or watermark alone on its line. */
const LEGEND =
  /^(?:(?:final|execution|executed|execution version|execution copy|conformed copy|draft|signature page(?: follows)?|\[signature page follows\]|\[remainder of page intentionally left blank\]|page \d{1,3}(?: of \d{1,3})?)[\s.:—–-]*)+$/i;

/** A blank the final leaves for execution to fill. */
const BLANK = /_{3,}|\[\s*[●•]\s*\]|\[\s*(?:date|name|title|amount|insert[^\]]{0,40})\s*\]/gi;

const MAX_BLANKS = 6;
const OPERATIVE =
  /\b(?:shall|must|will|agrees?|waives?|releases?|indemnif\w*|notwithstanding|except|provided that|unless)\b/i;
const MAX_FILL_CHARS = 2000;

/** Where a signature block begins: the first signature-block line. */
function signatureStart(clauses: readonly Clause[]): number {
  const i = clauses.findIndex(
    (c) => SIGNATURE_LINE.test(c.text) || /^in witness whereof\b/i.test(c.text),
  );
  return i < 0 ? clauses.length : i;
}

/** The executed copy's short, sentence-less entries under the signature block. */
function isSignerEntry(c: Clause): boolean {
  const words = c.text.split(/\s+/).length;
  return (
    words <= 8 && !/[.;:]\s+\S/.test(c.text) && !/\b(?:shall|will|agrees?|must)\b/i.test(c.text)
  );
}

/** Why execution introduces this line, or undefined. */
export function executionAllowance(text: string): string | undefined {
  const t = text.trim();
  if (SIGNATURE_LINE.test(t)) return "signature-block line";
  // A signature rule that opens a short paragraph: ingest joins the rule with
  // what is printed under it — a name, a title, "Notary Public, My commission
  // expires", a date — and the whole block arrives as one paragraph.
  if (/^_{4,}/.test(t) && t.split(/\s+/).length <= 25) return "signature-block line";
  if (LEGEND.test(t)) return "legend or watermark";
  return undefined;
}

/** True when `executed` is `final` with its blanks filled and nothing else changed. */
export function fillsBlanks(final: string, executed: string): boolean {
  const norm = (s: string): string => s.replace(/\s+/g, " ").trim();
  const f = norm(final);
  // One lazy gap per blank: bounded so a long form with many blanks cannot
  // make the match backtrack without limit. Past the bound the paragraph is
  // simply compared as written.
  const blanks = f.match(BLANK)?.length ?? 0;
  if (blanks === 0 || blanks > MAX_BLANKS || f.length > MAX_FILL_CHARS) return false;
  const pattern = f
    .split(BLANK)
    .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join("(.{1,80}?)");
  const m = new RegExp(`^${pattern}$`).exec(norm(executed));
  // A blank holds a date, a name, a figure. A fill that carries an operative
  // word is new terms typed into the blank, and is a difference.
  return m !== null && !m.slice(1).some((fill) => OPERATIVE.test(fill));
}

export type SetAside = { side: "final" | "executed"; text: string; reason: string };

export type Conformity = {
  version: string;
  /**
   * `identical` outside the execution allowance, how many differences remain,
   * or `could-not-determine` when the signed copy's own text is incomplete.
   *
   * 🚨 The third state exists because the first two were both lies on a
   * partially-read document. A signed copy that arrives as a scan with a thin
   * text layer yields the words of some pages and nothing from the rest. Run
   * against that, this check used to return `differences` — asserting
   * differences it cannot substantiate — or, worse, `identical`, which is a
   * clean bill of health for pages nobody read. Neither is a verdict; the
   * honest answer is that the comparison could not be made.
   */
  verdict: "identical" | "differences" | "could-not-determine";
  /** Why no verdict could be reached, when `verdict` is `could-not-determine`. */
  unverified_reason?: string;
  /**
   * The differences that sit on text OCR was unsure of — the WORD-level join
   * (add-executed-copy-conformity task 4).
   *
   * `unverified_reason` is document-level: it says no verdict is possible. This
   * is finer, and it is the half a reader actually acts on. In an OCR'd signed
   * copy, a difference whose text carries an `[uncertain]` marker may be the
   * scanner misreading a word; a difference with no marker anywhere near it is
   * a real difference even in an OCR'd document. Sweeping both into one
   * "could not determine" tells an attorney to re-read everything, when what
   * they need is which few lines to check by eye.
   *
   * The markers are ordinary text by the time they reach here: `markLowConfidence`
   * writes `word [uncertain]` into the OCR output, so this needs no access to
   * OCR itself — only to the text it produced.
   */
  unverified_differences?: Array<{
    side: "added" | "removed" | "changed";
    text: string;
    /** The word(s) OCR was unsure of, so a reader knows what to look at. */
    uncertain_words: string[];
  }>;
  differences: Pick<ClauseDiff, "added" | "removed" | "changed">;
  /** `By:` lines on each side; unequal counts are one difference. */
  signature_blocks: { final: number; executed: number };
  difference_count: number;
  set_aside: SetAside[];
  conformity_hash: string;
};

const RESEGMENTED = "the same words, split into paragraphs differently";

/**
 * The marker `markLowConfidence` writes into OCR output for a word the scanner
 * scored below `OCR_CONFIDENCE_THRESHOLD`: `word [uncertain]`.
 */
const UNCERTAIN = /(\S+)\s+\[uncertain\]/g;

/** The words OCR was unsure of in a piece of text, in order, without repeats. */
function uncertainWords(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(UNCERTAIN)) {
    const w = m[1]!;
    if (!out.includes(w)) out.push(w);
  }
  return out;
}

/** Every heading and paragraph of a tree as a line, in document order. */
function linesOf(tree: DocumentTree): string[] {
  const out: string[] = [];
  const walk = (sections: DocumentTree["sections"]): void => {
    for (const s of sections) {
      if (s.heading?.trim()) out.push(s.heading.trim());
      for (const p of s.paragraphs) {
        const t = p.runs
          .map((r) => r.text)
          .join("")
          .trim();
        if (t) out.push(t);
      }
      walk(s.children);
    }
  };
  walk(tree.sections);
  return out;
}

/** Every section heading in a tree, in document order. */
function headingsOf(tree: DocumentTree): string[] {
  const out: string[] = [];
  const walk = (sections: DocumentTree["sections"]): void => {
    for (const s of sections) {
      if (s.heading?.trim()) out.push(s.heading.trim());
      walk(s.children);
    }
  };
  walk(tree.sections);
  return out;
}

/** Compare a final draft with its executed copy. */
export async function checkConformity(
  final: DocumentTree,
  executed: DocumentTree,
  options: {
    /**
     * Set when the EXECUTED side's text is known to be incomplete — a scan
     * whose text layer covers only some pages (`partial-text-layer`), or a
     * file read through OCR. The string is the reason, shown to a reader.
     * Given this, no verdict is returned, however the comparison came out.
     */
    executedTextIncomplete?: string;
  } = {},
): Promise<Conformity> {
  const finalClauses = flattenClauses(final);
  const executedClauses = flattenClauses(executed);
  const signerFrom = signatureStart(executedClauses);
  // An entry the final's own text already has is compared, not set aside:
  // the party name over its signature line is the draft's, not the signer's.
  const finalKeys = new Set(finalClauses.map((c) => c.key));
  const set_aside: SetAside[] = [];
  // Set aside before aligning, so a signature line is never paired with a
  // clause it does not correspond to.
  const diff = buildClauseDiff(final, executed, {
    exclude: (c, side, index) => {
      const reason =
        executionAllowance(c.text) ??
        (side === "revised" && index >= signerFrom && isSignerEntry(c) && !finalKeys.has(c.key)
          ? "signer's entry under the signature block"
          : undefined);
      if (!reason) return false;
      set_aside.push({ side: side === "base" ? "final" : "executed", text: c.text, reason });
      return true;
    },
  });
  // A form's signature rule with its label under it ("____ ____ Signature of
  // applicant Date") is set aside on the final side, and its filled copy
  // ("/s/ Ana Ruiz 06/03/2026 Signature of applicant Date") arrives as an
  // added paragraph. Filling that rule's blanks is what signing it is.
  const norm = (t: string): string => t.replace(/\s+/g, " ").trim().toLowerCase();
  // A line one ingest reads as a heading and the other as a paragraph (a Word
  // Title paragraph, a 16-point PDF line) is the same line in both files. And
  // headings are compared too: the paragraph diff never sees them, so a
  // heading the signed copy changed would otherwise pass unseen.
  const finalHeadings = headingsOf(final);
  const executedHeadings = headingsOf(executed);
  const finalHeadingSet = new Set(finalHeadings.map(norm));
  const executedHeadingSet = new Set(executedHeadings.map(norm));
  const finalTexts = new Set(finalClauses.map((c) => norm(c.text)));
  const executedTexts = new Set(executedClauses.map((c) => norm(c.text)));
  const headingElsewhere = (c: Clause, side: "final" | "executed"): boolean => {
    const other = side === "final" ? executedHeadingSet : finalHeadingSet;
    if (!other.has(norm(c.text))) return false;
    set_aside.push({ side, text: c.text, reason: "a heading in the other file" });
    return true;
  };
  const headingClause = (text: string): Clause => ({
    id: "heading",
    heading: text,
    text,
    key: norm(text),
    number: "",
  });
  const headingsRemoved = finalHeadings
    .filter((h) => !executionAllowance(h))
    .filter((h) => !executedHeadingSet.has(norm(h)) && !executedTexts.has(norm(h)))
    .map(headingClause);
  const headingsAdded = executedHeadings
    .filter((h) => !executionAllowance(h))
    .filter((h) => !finalHeadingSet.has(norm(h)) && !finalTexts.has(norm(h)))
    .map(headingClause);
  const setAsideFinal = set_aside.filter((x) => x.side === "final").map((x) => x.text);
  const added = diff.added.filter((c) => {
    if (headingElsewhere(c, "executed")) return false;
    if (!setAsideFinal.some((f) => fillsBlanks(f, c.text))) return true;
    set_aside.push({ side: "executed", text: c.text, reason: "blank filled in" });
    return false;
  });
  // A line of the final that the executed copy still carries, joined into a
  // line set aside above: filling a blank can change where ingest breaks
  // paragraphs, so "FOR OFFICE USE ONLY" arrives inside the signed line under
  // it. The text is there; it is not a difference.
  const setAsideExecuted = set_aside.filter((x) => x.side === "executed").map((x) => norm(x.text));
  const removed = diff.removed.filter((c) => {
    if (headingElsewhere(c, "final")) return false;
    const key = norm(c.text);
    if (key.length < 4 || !setAsideExecuted.some((t) => t.includes(key))) return true;
    set_aside.push({
      side: "final",
      text: c.text,
      reason: "carried inside a signature-block line",
    });
    return false;
  });
  const changed = diff.changed.filter((pair) => {
    if (!fillsBlanks(pair.base.text, pair.revised.text)) return true;
    set_aside.push({ side: "executed", text: pair.revised.text, reason: "blank filled in" });
    return false;
  });

  // Every line of an added signatory's block is an allowance on its own, so
  // the blocks are counted: a party who signs and was not in the final, or a
  // block the signed copy lacks, is a difference whatever its lines say.
  // Counted wherever the label starts a word, not only a line: a PDF ingest
  // can join "By: /s/ …" to the party name above it.
  const blocks = (cs: readonly Clause[]): number =>
    cs.reduce((n, c) => n + (c.text.match(/(?:^|\s)by\s*:/gi)?.length ?? 0), 0);
  const signature_blocks = { final: blocks(finalClauses), executed: blocks(executedClauses) };
  const blockDifference = signature_blocks.final !== signature_blocks.executed ? 1 : 0;

  removed.push(...headingsRemoved);
  added.push(...headingsAdded);
  // Paragraph boundaries are not text. A PDF ingest joins a short line to the
  // next ("Halbrook Robotics, Inc." over "Plan Year: …") where a Word file
  // keeps two paragraphs, so the same words arrive as a removed line and a
  // changed one. When every differing line on each side, read in document
  // order as one stream of words, is the same words, the difference is the
  // segmentation, and it is listed rather than counted. A moved paragraph
  // changes the order, and a changed word changes the words, so either still
  // counts.
  // A line one file joins to the lines after it, where the other keeps them
  // apart: the changed line is its old self followed, word for word, by the
  // lines that came next. Read locally, so a match of those lines elsewhere
  // in the document does not hide the join.
  const finalLines = linesOf(final).map(norm);
  const executedLines = linesOf(executed).map(norm);
  const joined = (short: string, long: string, lines: readonly string[]): string[] | undefined => {
    if (!long.startsWith(short) || long === short) return undefined;
    let rest = long.slice(short.length).trim();
    const used: string[] = [];
    for (let i = lines.indexOf(short) + 1; i > 0 && i < lines.length && rest; i++) {
      const next = lines[i]!;
      if (!rest.startsWith(next)) return undefined;
      used.push(next);
      rest = rest.slice(next.length).trim();
    }
    return rest === "" && used.length > 0 ? used : undefined;
  };
  for (let i = changed.length - 1; i >= 0; i--) {
    const pair = changed[i]!;
    const b = norm(pair.base.text);
    const r = norm(pair.revised.text);
    const intoExecuted = joined(b, r, finalLines);
    const intoFinal = intoExecuted ? undefined : joined(r, b, executedLines);
    const absorbed = intoExecuted ?? intoFinal;
    if (!absorbed) continue;
    changed.splice(i, 1);
    set_aside.push({ side: "final", text: pair.base.text, reason: RESEGMENTED });
    set_aside.push({ side: "executed", text: pair.revised.text, reason: RESEGMENTED });
    const pool = intoExecuted ? removed : added;
    for (const line of absorbed) {
      const k = pool.findIndex((c) => norm(c.text) === line);
      if (k >= 0) {
        set_aside.push({
          side: intoExecuted ? "final" : "executed",
          text: pool[k]!.text,
          reason: RESEGMENTED,
        });
        pool.splice(k, 1);
      }
    }
  }
  const finalDiffering = new Set(
    [...removed.map((c) => c.text), ...changed.map((p) => p.base.text)].map(norm),
  );
  const executedDiffering = new Set(
    [...added.map((c) => c.text), ...changed.map((p) => p.revised.text)].map(norm),
  );
  const stream = (tree: DocumentTree, keep: ReadonlySet<string>): string =>
    linesOf(tree)
      .map(norm)
      .filter((t) => keep.has(t))
      .join(" ")
      .split(/\s+/)
      .filter(Boolean)
      .join(" ");
  if (
    finalDiffering.size + executedDiffering.size > 0 &&
    stream(final, finalDiffering) === stream(executed, executedDiffering)
  ) {
    for (const c of removed) set_aside.push({ side: "final", text: c.text, reason: RESEGMENTED });
    for (const p of changed) {
      set_aside.push({ side: "final", text: p.base.text, reason: RESEGMENTED });
      set_aside.push({ side: "executed", text: p.revised.text, reason: RESEGMENTED });
    }
    for (const c of added) set_aside.push({ side: "executed", text: c.text, reason: RESEGMENTED });
    removed.length = 0;
    added.length = 0;
    changed.length = 0;
  }
  const difference_count = removed.length + added.length + changed.length + blockDifference;
  // An incomplete read disqualifies BOTH ordinary verdicts, including
  // `identical`: finding nothing in text that was never extracted is not a
  // finding of sameness.
  const unverified = options.executedTextIncomplete;
  // The WORD-level join: which of these differences sit on text OCR was
  // unsure of. Computed from the text itself, so it needs no OCR — only the
  // `[uncertain]` markers OCR left behind.
  const unverified_differences: NonNullable<Conformity["unverified_differences"]> = [];
  for (const [side, clauses] of [
    ["added", added],
    ["removed", removed],
  ] as const) {
    for (const c of clauses) {
      const words = uncertainWords(c.text);
      if (words.length > 0) {
        unverified_differences.push({ side, text: c.text, uncertain_words: words });
      }
    }
  }
  for (const pair of changed) {
    // Either side may carry a marker: the signed copy is the OCR'd one, but a
    // final read from a scan can be too.
    const words = uncertainWords(`${pair.base.text} ${pair.revised.text}`);
    if (words.length > 0) {
      unverified_differences.push({
        side: "changed",
        text: pair.revised.text,
        uncertain_words: words,
      });
    }
  }
  const verdict = unverified
    ? "could-not-determine"
    : difference_count === 0
      ? "identical"
      : "differences";
  const canonical = JSON.stringify({
    namespace: "vaulytica-conformity",
    version: CONFORMITY_VERSION,
    verdict,
    // Spread conditionally: a run with a complete text layer serializes
    // exactly the object it did before, so no existing `conformity_hash`
    // moves.
    //
    // `unverified_differences` is deliberately NOT here. It is derived
    // entirely from the text of the differences the canonical object already
    // covers, so hashing it would add nothing and would move every existing
    // conformity_hash for an OCR'd pair.
    ...(unverified ? { unverified } : {}),
    removed: removed.map((c) => c.text),
    added: added.map((c) => c.text),
    changed: changed.map((p) => [p.base.text, p.revised.text]),
    signature_blocks,
    set_aside: set_aside.map((s) => [s.side, s.reason, s.text]),
  });
  return {
    version: CONFORMITY_VERSION,
    verdict,
    ...(unverified ? { unverified_reason: unverified } : {}),
    ...(unverified_differences.length > 0 ? { unverified_differences } : {}),
    differences: { added, removed, changed },
    signature_blocks,
    difference_count,
    set_aside,
    conformity_hash: await sha256Hex(canonical),
  };
}

/** The verdict as one line a reader can act on. */
export function conformityLine(c: Conformity): string {
  if (c.verdict === "could-not-determine") {
    // Say what WAS seen, so the line is useful, but never as a count of
    // differences the comparison can stand behind.
    const seen =
      c.difference_count === 0
        ? "Nothing differed in the text that could be read"
        : `${c.difference_count} apparent difference${c.difference_count === 1 ? "" : "s"} in the text that could be read`;
    // Name the few lines to check by eye, when OCR said which they are. The
    // point of the word-level join: "re-read everything" is not advice.
    const near = c.unverified_differences?.length
      ? ` ${c.unverified_differences.length} of them sit on words OCR was unsure of (${c.unverified_differences
          .flatMap((d) => d.uncertain_words)
          .slice(0, 6)
          .join(", ")}) — check those by eye first.`
      : "";
    return `Could not determine conformity: ${c.unverified_reason ?? "the signed copy's text is incomplete"}. ${seen}, which is not a verdict either way.${near}`;
  }
  return c.verdict === "identical"
    ? "Identical to the final outside the execution allowance."
    : `${c.difference_count} difference${c.difference_count === 1 ? "" : "s"} from the final outside the execution allowance.`;
}
