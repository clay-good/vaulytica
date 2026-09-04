import { inflateOoxmlParts } from "./ooxml.js";

/**
 * A REDLINE is not the document it looks like.
 *
 * mammoth converts a DOCX with tracked changes to the ALL-CHANGES-ACCEPTED
 * text: a `w:ins` run arrives as ordinary agreed language, and a `w:del` run —
 * the term the counterparty is asking you to give up — does not arrive at all.
 * Neither is unreasonable as a default, and neither is discoverable: the
 * analysis read the version the counterparty WANTS and said nothing about it.
 *
 * For a tool whose whole claim is "the second pair of eyes you can cite", a
 * reviewer opening a counterparty's redline has to be told which version was
 * read. This counts the revisions so the ingest can say so. It does not change
 * what is analyzed — that is a design decision about which version of a
 * document the engine should see, not a defect to be quietly patched.
 */

const DOCUMENT_PART = new Set(["word/document.xml"]);
/** Counting stops here; the exact number past it is not what the warning says. */
const MAX_COUNT = 5000;

export type RevisionCounts = { insertions: number; deletions: number; moves: number };

function count(xml: string, re: RegExp): number {
  let n = 0;
  while (re.exec(xml) !== null && n < MAX_COUNT) n += 1;
  re.lastIndex = 0;
  return n;
}

/** Revision-element counts, or all zeros when the part cannot be read. */
export function countRevisions(bytes: ArrayBuffer): RevisionCounts {
  let xml: string;
  try {
    xml = inflateOoxmlParts(bytes, DOCUMENT_PART)["word/document.xml"] ?? "";
  } catch {
    // A container mammoth already parsed should inflate, but a warning is not
    // worth failing an ingest over.
    return { insertions: 0, deletions: 0, moves: 0 };
  }
  return {
    insertions: count(xml, /<w:ins\b/g),
    deletions: count(xml, /<w:del\b/g),
    moves: count(xml, /<w:move(?:From|To)\b/g),
  };
}

const plural = (n: number, noun: string): string => `${n} ${noun}${n === 1 ? "" : "s"}`;

/**
 * The warning a redline earns, or null. Says which version was read and what
 * was not read — the deleted text is usually the point of the review.
 */
export function trackedChangesWarning(counts: RevisionCounts): string | null {
  const { insertions, deletions, moves } = counts;
  if (insertions + deletions + moves === 0) return null;
  const parts: string[] = [];
  if (insertions > 0) parts.push(plural(insertions, "insertion"));
  if (deletions > 0) parts.push(plural(deletions, "deletion"));
  if (moves > 0) parts.push(plural(moves, "move"));
  const deleted =
    deletions > 0
      ? " Deleted text was NOT analyzed, and struck-out terms will not be reported."
      : "";
  return (
    `This document has tracked changes (${parts.join(", ")}). It was analyzed as if every change ` +
    `were ACCEPTED — inserted text is treated as agreed language.${deleted} ` +
    `To review the other version, accept or reject the changes in Word first.`
  );
}
