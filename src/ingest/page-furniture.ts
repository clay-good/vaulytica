import { ATTACHMENT_KIND } from "../extract/attachment-kinds.js";
import type { Paragraph } from "./types.js";

/**
 * PAGE FURNITURE is not content, and it is not a paragraph boundary either.
 *
 * A contract read out of a PDF carries a page number between the text above it
 * and the text below — "Page 3 of 9", "13 of 40". Two rules had already learned
 * to skip it individually (STRUCT-013 read it as the heading a clause sits
 * under; RISK-004 read it as a clause), which is the shape a shared problem
 * takes while it is still being solved one caller at a time: the other 1,823
 * rules never learned, because nothing removed it before they ran.
 *
 * Dropping the line is only half the repair. A page break falls wherever the
 * page happens to end, which is usually mid-sentence, so the paragraph arrives
 * as two paragraphs with the furniture between them. Delete just the furniture
 * and the two halves are still two paragraphs — and every scan that reads "the
 * enclosing sentence" or "the clause" still sees a sentence cut in half. So the
 * halves are rejoined, and only when they are unambiguously halves: the text
 * above ends mid-sentence and is not heading-shaped, and the text below does
 * not open a new clause. A page that breaks BETWEEN sentences leaves two
 * paragraphs that each stand on their own, and those are left alone.
 *
 * Requiring the resumption to be lower-case was the first draft, and it was too
 * narrow in the one direction that matters: a sentence continued by a quoted
 * defined term ("Your Content" means …) resumes upper-case, and website-terms
 * lost that definition and drew STRUCT-006 for a term it does define.
 */
export const PAGE_FURNITURE =
  /^(?:[-–—\s|]*)?(?:page\s*)?\d{1,3}\s*(?:of|\/)\s*\d{1,3}[-–—\s|.]*$|^[-–—\s|]*page\s+\d{1,3}[-–—\s|.]*$/i;

/** How far into a document its own caption can still be its caption. */
const CAPTION_PARAGRAPHS = 3;

/**
 * A BATES NUMBER — "ACME-000123" — stamped on every produced page. Unlike a
 * legend it is DIFFERENT on every page, so no repetition test can find it; the
 * shape is all there is. An all-caps prefix, a hyphen or underscore, and at
 * least four digits, alone on its line, is a production stamp and nothing else.
 *
 * A SPACE was allowed as the separator in the first draft, and it made
 * `normalize` NON-IDEMPOTENT: a run holding "F3\n8011" collapses to "F3 8011"
 * on the first pass, which the pattern then read as a Bates number on the
 * second, dropping a paragraph that had survived. Found by the
 * `normalize(normalize(t))` property test, which no specimen would have caught.
 * The separator is punctuation only now — and every shape test below reads
 * WHITESPACE-COLLAPSED text, so that no pattern here can begin matching only
 * after a pass has run.
 */
const BATES_STAMP = /^[A-Z][A-Z0-9]{1,15}[-_]\d{4,10}$/;

/**
 * The vocabulary of a page LEGEND. A legend is matched word by word rather than
 * as a phrase, because it is assembled freely — "CONFIDENTIAL — ATTORNEY WORK
 * PRODUCT", "HIGHLY CONFIDENTIAL — ATTORNEYS' EYES ONLY", "PRIVILEGED AND
 * CONFIDENTIAL", "DRAFT — SUBJECT TO FRE 408". Every word must be in the list,
 * so a heading that merely contains one of them is not a legend:
 * "CONFIDENTIAL INFORMATION" fails on INFORMATION, and "CONFIDENTIALITY" is a
 * different word.
 */
const LEGEND_WORDS = new Set([
  "AND",
  "ATTORNEY",
  "ATTORNEYS",
  "CONFIDENTIAL",
  "COPY",
  "DISCUSSION",
  "DISTRIBUTION",
  "DRAFT",
  "EYES",
  "EXECUTION",
  "FOR",
  "FRE",
  "HIGHLY",
  "INTERNAL",
  "NOT",
  "ONLY",
  "ORDER",
  "PREJUDICE",
  "PRIVILEGED",
  "PRODUCT",
  "PROPRIETARY",
  "PROTECTIVE",
  "PURPOSES",
  "REDACTED",
  "RULE",
  "SECRET",
  "SUBJECT",
  "TO",
  "TRADE",
  "USE",
  "VERSION",
  "WITHOUT",
  "WORK",
  "408",
]);

function isPageLegend(text: string): boolean {
  if (text.length > 80 || text !== text.toUpperCase()) return false;
  const words = text.split(/[^A-Z0-9']+/).filter(Boolean);
  return words.length > 0 && words.length <= 10 && words.every((w) => LEGEND_WORDS.has(w));
}

/** Whitespace-collapsed, so a pattern cannot start matching after a pass. */
const collapse = (t: string): string => t.replace(/\s+/g, " ").trim();
const textOf = (p: Paragraph): string => collapse(p.runs.map((r) => r.text).join(""));
/**
 * The break is between two LINES, so the shape tests read the two lines that
 * touch it — the last of the paragraph above and the first of the one below —
 * not the whole paragraph. A notarial caption laid out over three lines
 * ("STATE OF COLORADO )" / ") ss." / "CITY AND COUNTY OF DENVER )") carries a
 * lower-case "ss." on its second line, and reading the block as one string
 * made it look like prose; the signature above it was merged into it.
 */
const lastLine = (p: Paragraph): string => collapse(p.runs[p.runs.length - 1]?.text ?? "");
const firstLine = (p: Paragraph): string => collapse(p.runs[0]?.text ?? "");

/** Ends mid-sentence: no terminal punctuation and no closing delimiter. */
const CONTINUES = /[^.;:!?)\]"'”’]$/;
/**
 * A heading also ends without punctuation, and the text under it is a new
 * paragraph however the page fell — so an unpunctuated line that carries no
 * lower-case letter at all is not treated as an interrupted sentence. The test
 * applies on BOTH sides: a signature-block name ("Margery R. Pike") ends
 * without punctuation too, and the notarial caption under it ("STATE OF
 * COLORADO )") is a new block, not the rest of her name.
 */
const HEADING_SHAPED = /^[^a-z]*$/;
/** Starts a new clause or list item, so it is not a resumption. */
const NEW_CLAUSE = /^(?:\d+(?:\.\d+)*\.?|\([a-z0-9ivxIVX]+\)|[-•*–—])\s/;
/**
 * …unless the text above cannot possibly end there. A cross-reference list
 * broken over a page — "the obligations in Sections 5, 6 and" / "8.2 survive
 * any termination" — resumes with something shaped exactly like a new clause
 * number, and source-code-escrow lost its survival clause to that reading.
 * A line ending in a conjunction, a preposition or a comma is unfinished
 * whatever the next line looks like.
 */
const DANGLING = /(?:,|\b(?:and|or|of|to|in|for|with|by|from|under|through|between)\b)$/i;
/**
 * A signature line — the rule of underscores and the name typed beside it —
 * also ends without punctuation, and it is never an unfinished sentence. A
 * warranty deed's second grantor sat on the last line of a page and the
 * notarial caption on the first line of the next, and merging the two put the
 * signature rule inside a paragraph of prose, where STRUCT-013 read it as an
 * unfilled template placeholder.
 */
const SIGNATURE_LINE = /_{3,}/;
/**
 * Opens an attachment — "Exhibit C — Data Terms". STRUCT-018 reads a title
 * like this as the attachment being PRESENT, and only at the start of a
 * paragraph, so merging one into the text above it makes an exhibit that is
 * plainly attached read as referenced-but-absent. Two specimens lost one.
 */
const ATTACHMENT_TITLE = new RegExp(String.raw`^(?:${ATTACHMENT_KIND})\s`, "i");

/**
 * A RUNNING HEADER interrupts a paragraph exactly the way a page number does,
 * and it is much harder to recognize, because a repeated line is not by itself
 * suspicious: `interrogatories` repeats "ANSWER:" eight times, an appellate
 * brief repeats counsel's name four, and three specimens repeat an execution
 * date. Ten of the 311 carry a line that appears three or more times, and every
 * one of those repetitions is content.
 *
 * What no body paragraph does is repeat the document's OWN TITLE. That is the
 * one shape reserved for the header a PDF stamps on every page, so it is the
 * only shape claimed here — and matched as a PREFIX of the document's opening
 * block rather than as the whole of it, because a letter opens with a
 * letterhead ("NORTHFIELD PATHOLOGY ASSOCIATES, P.C." and the street address
 * under it) that arrives as ONE paragraph while the running header carries only
 * its first line. Comparing whole paragraphs found no header at all there, and
 * the breach-notification letter kept reporting a privacy contact it names.
 *
 * A header that ABBREVIATES the title ("Facility Agmt — Halbrook") is not
 * caught; catching it needs a document-wide repeat analysis whose
 * false-positive risk the list above measures, and that is a separate mechanism.
 */
export function runningHeaderCopies(paragraphs: Paragraph[]): Set<Paragraph> {
  const drop = new Set<Paragraph>();
  // The opening must be chosen from what SURVIVES this pass. Choosing it before
  // the furniture is removed made `normalize` non-idempotent: a document whose
  // first paragraph was itself a page number compared every later paragraph
  // against "1 of 9", found no header, and then found one on a second pass —
  // caught by the `normalize(normalize(t))` property test, not by any specimen.
  const opening = paragraphs.find((p) => {
    const text = textOf(p);
    return text.length > 0 && !PAGE_FURNITURE.test(text) && !BATES_STAMP.test(text);
  });
  if (!opening) return drop;
  const openingText = textOf(opening);

  // A page LEGEND repeats verbatim on every page, and unlike the title it is
  // not drawn from the document at all — but the FIRST one may be the
  // document's own caption ("EXECUTION VERSION" over a signed agreement), and
  // that is a fact about the document. So the first is kept and the stamps
  // after it are dropped, exactly as for the header.
  const legends = [...paragraphs.entries()].filter(([, p]) => isPageLegend(textOf(p)));
  const legendCounts = new Map<string, number>();
  for (const [, p] of legends) legendCounts.set(textOf(p), (legendCounts.get(textOf(p)) ?? 0) + 1);
  const seenLegend = new Set<string>();
  for (const [at, p] of legends) {
    const text = textOf(p);
    if ((legendCounts.get(text) ?? 0) < 2) continue;
    // The caption is at the TOP. A legend first seen in the middle of the
    // document is a page stamp wherever it falls, and keeping it there leaves
    // the sentence it interrupted split in two — which was the whole point.
    if (!seenLegend.has(text)) {
      seenLegend.add(text);
      if (at < CAPTION_PARAGRAPHS) continue;
    }
    drop.add(p);
  }

  const byText = new Map<string, number[]>();
  for (const [i, p] of paragraphs.entries()) {
    if (p === opening) continue;
    const text = textOf(p);
    // Long enough not to be a stray fragment, and short enough to be a header.
    if (text.length < 8 || text.length > 120) continue;
    if (!openingText.startsWith(text)) continue;
    byText.set(text, [...(byText.get(text) ?? []), i]);
  }
  for (const copies of byText.values()) {
    // Two copies BEYOND the opening: one repetition could be a genuine
    // restatement of the title (a cover page, a signature-block caption); a
    // header repeats. And a header always has a PAGE between its copies, so
    // consecutive ones are content — three identical paragraphs in a row are
    // whatever the drafter wrote three times, not a header.
    if (copies.length < 2) continue;
    if (copies.some((at, k) => k > 0 && at - copies[k - 1]! < 2)) continue;
    for (const at of copies) drop.add(paragraphs[at]!);
  }
  return drop;
}

/**
 * Drop page-furniture paragraphs, rejoining a paragraph one split in two.
 * Pure: neither the input paragraphs nor their runs are mutated.
 *
 * `alsoDrop` carries the running-header copies, which can only be identified
 * across the whole document — the same treatment, decided a level up.
 */
export function stripPageFurniture(
  paragraphs: Paragraph[],
  alsoDrop: ReadonlySet<Paragraph> = new Set(),
): Paragraph[] {
  const out: Paragraph[] = [];
  let dropped = false;
  for (const p of paragraphs) {
    const text = textOf(p);
    if (alsoDrop.has(p) || (text && (PAGE_FURNITURE.test(text) || BATES_STAMP.test(text)))) {
      dropped = true;
      continue;
    }
    const prev = out[out.length - 1];
    const above = prev ? lastLine(prev) : "";
    const below = firstLine(p);
    if (
      dropped &&
      prev &&
      p.runs.length > 0 &&
      CONTINUES.test(above) &&
      !HEADING_SHAPED.test(above) &&
      !SIGNATURE_LINE.test(above) &&
      (!NEW_CLAUSE.test(below) || DANGLING.test(above)) &&
      !HEADING_SHAPED.test(below) &&
      !ATTACHMENT_TITLE.test(below)
    ) {
      out[out.length - 1] = {
        ...prev,
        // The joining space is a run of its own, so no existing run's text is
        // rewritten and `normalize` folds it the way it folds any other.
        runs: [...prev.runs, { ...p.runs[0]!, text: " " }, ...p.runs],
      };
      dropped = false;
      continue;
    }
    dropped = false;
    out.push(p);
  }
  return out;
}
