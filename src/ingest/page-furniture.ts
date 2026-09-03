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

const textOf = (p: Paragraph): string =>
  p.runs
    .map((r) => r.text)
    .join("")
    .trim();
/**
 * The break is between two LINES, so the shape tests read the two lines that
 * touch it — the last of the paragraph above and the first of the one below —
 * not the whole paragraph. A notarial caption laid out over three lines
 * ("STATE OF COLORADO )" / ") ss." / "CITY AND COUNTY OF DENVER )") carries a
 * lower-case "ss." on its second line, and reading the block as one string
 * made it look like prose; the signature above it was merged into it.
 */
const lastLine = (p: Paragraph): string => (p.runs[p.runs.length - 1]?.text ?? "").trim();
const firstLine = (p: Paragraph): string => (p.runs[0]?.text ?? "").trim();

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
 * Drop page-furniture paragraphs, rejoining a paragraph one split in two.
 * Pure: neither the input paragraphs nor their runs are mutated.
 */
export function stripPageFurniture(paragraphs: Paragraph[]): Paragraph[] {
  const out: Paragraph[] = [];
  let dropped = false;
  for (const p of paragraphs) {
    const text = textOf(p);
    if (text && PAGE_FURNITURE.test(text)) {
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
