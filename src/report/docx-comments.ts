/**
 * Reviewed-copy export (add-word-comment-export): a byte-copy of the
 * attorney's OWN uploaded DOCX with one anchored Word comment per
 * finding — review metadata inside their draft, never a generated
 * redline or drafted language, so the lint-not-draft line holds.
 *
 * Mechanics: the original container is opened with fflate, and exactly
 * four parts are touched —
 *   - `word/document.xml` gains `w:commentRangeStart/End` +
 *     `w:commentReference` markers around each finding's anchor span
 *     (inserted at run boundaries; run internals are never rewritten);
 *   - `word/comments.xml` is created with the comment bodies;
 *   - `word/_rels/document.xml.rels` gains the comments relationship;
 *   - `[Content_Types].xml` gains the comments override.
 * Every other entry is carried through byte-identical, entries are
 * written in sorted order with a fixed epoch mtime, and the comment
 * dates are a fixed constant — same inputs, byte-identical output.
 *
 * Anchoring is deterministic text search: a finding's excerpt text is
 * located (whitespace-normalized) in the concatenation of the
 * document's `w:t` runs; the markers wrap the run(s) containing the
 * match, so the highlighted span always CONTAINS the excerpt. A
 * finding whose excerpt cannot be located lands in one document-start
 * "unanchored findings" comment — never dropped, never guessed.
 */

import { unzipSync, zipSync, strToU8, strFromU8, type Zippable } from "fflate";
import type { EngineRun, Finding } from "../engine/finding.js";

/** Fixed comment timestamp — a real date here would break determinism. */
const COMMENT_DATE = "2001-01-01T00:00:00Z";

// ---------------------------------------------------------------------------
// document.xml text model

export type TextSegment = {
  /** Character range of the segment's text within the concatenated text. */
  textStart: number;
  textEnd: number;
  /** Byte/char range of the ENCLOSING `<w:r>` run element in the XML. */
  runStart: number;
  runEnd: number;
};

export type DocumentTextIndex = {
  /** Concatenation of every `w:t` text, in document order. */
  text: string;
  segments: TextSegment[];
};

const XML_ENTITIES: Record<string, string> = {
  "&amp;": "&",
  "&lt;": "<",
  "&gt;": ">",
  "&quot;": '"',
  "&apos;": "'",
};

function decodeXml(s: string): string {
  return s.replace(/&(?:amp|lt|gt|quot|apos);|&#x?[0-9a-fA-F]+;/g, (e) => {
    if (e in XML_ENTITIES) return XML_ENTITIES[e]!;
    const hex = /^&#x([0-9a-fA-F]+);$/.exec(e);
    if (hex) return String.fromCodePoint(parseInt(hex[1]!, 16));
    const dec = /^&#(\d+);$/.exec(e);
    if (dec) return String.fromCodePoint(parseInt(dec[1]!, 10));
    return e;
  });
}

export function escapeXml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * Pure text index over `word/document.xml`: every `w:t` text node with
 * the char range of its enclosing `<w:r>` element. String processing
 * only — no DOM, no ordering surprises.
 */
export function indexDocumentText(xml: string): DocumentTextIndex {
  const segments: TextSegment[] = [];
  let text = "";
  // Every run element, non-nested by OOXML structure (runs cannot contain runs).
  const runRe = /<w:r(?:\s[^>]*)?>[\s\S]*?<\/w:r>/g;
  let rm: RegExpExecArray | null;
  while ((rm = runRe.exec(xml)) !== null) {
    const runXml = rm[0];
    const tRe = /<w:t(?:\s[^>]*)?>([\s\S]*?)<\/w:t>|<w:t(?:\s[^>]*)?\/>/g;
    let tm: RegExpExecArray | null;
    let runText = "";
    while ((tm = tRe.exec(runXml)) !== null) runText += decodeXml(tm[1] ?? "");
    // Tabs and breaks separate words in the flattened view.
    if (/<w:(?:tab|br|cr)\b/.test(runXml) && runText === "") runText = " ";
    if (runText.length === 0) continue;
    segments.push({
      textStart: text.length,
      textEnd: text.length + runText.length,
      runStart: rm.index,
      runEnd: rm.index + runXml.length,
    });
    text += runText;
  }
  return { text, segments };
}

/** Collapse whitespace for anchor matching (mammoth and OOXML disagree on it). */
function normalizeForSearch(s: string): string {
  return s.replace(/\s+/g, " ").trim();
}

/**
 * Locate `excerpt` in the indexed document text. Returns the run-range
 * to wrap, or null when the excerpt cannot be found. Deterministic:
 * first occurrence wins.
 */
export function locateExcerpt(
  index: DocumentTextIndex,
  excerpt: string,
): { firstSegment: TextSegment; lastSegment: TextSegment } | null {
  const needle = normalizeForSearch(excerpt);
  if (needle.length < 8) return null; // too short to anchor honestly
  // Build a normalized haystack with a position map back to raw offsets.
  const raw = index.text;
  const map: number[] = [];
  let norm = "";
  let lastWasSpace = true;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i]!;
    if (/\s/.test(ch)) {
      if (!lastWasSpace) {
        norm += " ";
        map.push(i);
        lastWasSpace = true;
      }
      continue;
    }
    norm += ch;
    map.push(i);
    lastWasSpace = false;
  }
  const at = norm.indexOf(needle);
  if (at < 0) return null;
  const rawStart = map[at]!;
  const rawEnd = map[at + needle.length - 1]!;
  const firstSegment = index.segments.find((s) => rawStart >= s.textStart && rawStart < s.textEnd);
  const lastSegment = index.segments.find((s) => rawEnd >= s.textStart && rawEnd < s.textEnd);
  if (!firstSegment || !lastSegment) return null;
  return { firstSegment, lastSegment };
}

// ---------------------------------------------------------------------------
// Comment content

function commentBody(f: Finding): string {
  const parts = [
    `[${f.severity.toUpperCase()}] ${f.rule_id} — ${f.title}`,
    f.explanation,
    ...(f.recommendation ? [`Recommendation: ${f.recommendation}`] : []),
    ...f.source_citations.map((c) =>
      c.source_url ? `Authority: ${c.source} — ${c.source_url}` : `Authority: ${c.source}`,
    ),
  ];
  return parts
    .map((line) => `<w:p><w:r><w:t xml:space="preserve">${escapeXml(line)}</w:t></w:r></w:p>`)
    .join("");
}

function commentXml(id: number, author: string, body: string): string {
  return `<w:comment w:id="${id}" w:author="${escapeXml(author)}" w:date="${COMMENT_DATE}" w:initials="V">${body}</w:comment>`;
}

// ---------------------------------------------------------------------------
// The writer

export type ReviewedCopyResult = {
  bytes: Uint8Array;
  anchored: number;
  unanchored: number;
};

/**
 * Produce the reviewed copy: the original DOCX bytes with one anchored
 * comment per finding (plus one document-start aggregation comment for
 * any finding whose anchor could not be located). Throws when the
 * container carries no `word/document.xml` (not a DOCX).
 */
export function buildReviewedDocx(original: ArrayBuffer, run: EngineRun): ReviewedCopyResult {
  const entries = unzipSync(new Uint8Array(original));
  const docEntry = entries["word/document.xml"];
  if (!docEntry) throw new Error("not a DOCX container: word/document.xml is missing");
  let documentXml = strFromU8(docEntry);
  const index = indexDocumentText(documentXml);
  const author = `Vaulytica ${run.version}`;

  type Insertion = { pos: number; markup: string };
  const insertions: Insertion[] = [];
  const comments: string[] = [];
  const unanchoredFindings: Finding[] = [];
  let nextId = 0;

  for (const f of run.findings) {
    const located = locateExcerpt(index, f.excerpt.text);
    if (!located) {
      unanchoredFindings.push(f);
      continue;
    }
    const id = nextId++;
    comments.push(commentXml(id, author, commentBody(f)));
    insertions.push({
      pos: located.firstSegment.runStart,
      markup: `<w:commentRangeStart w:id="${id}"/>`,
    });
    insertions.push({
      pos: located.lastSegment.runEnd,
      markup: `<w:commentRangeEnd w:id="${id}"/><w:r><w:rPr><w:rStyle w:val="CommentReference"/></w:rPr><w:commentReference w:id="${id}"/></w:r>`,
    });
  }

  if (unanchoredFindings.length > 0) {
    // Last id issued — no post-increment (nothing reads nextId after this).
    const id = nextId;
    const lines = unanchoredFindings.map(commentBody).join("");
    const header = `<w:p><w:r><w:t xml:space="preserve">${escapeXml(
      `${unanchoredFindings.length} finding(s) could not be anchored to a location in this document and are collected here:`,
    )}</w:t></w:r></w:p>`;
    comments.push(commentXml(id, author, header + lines));
    // Anchor at the first run of the document (document start).
    const firstRun = index.segments[0];
    const pos = firstRun ? firstRun.runStart : documentXml.indexOf("<w:body>") + "<w:body>".length;
    insertions.push({ pos, markup: `<w:commentRangeStart w:id="${id}"/>` });
    insertions.push({
      pos: firstRun ? firstRun.runEnd : pos,
      markup: `<w:commentRangeEnd w:id="${id}"/><w:r><w:rPr><w:rStyle w:val="CommentReference"/></w:rPr><w:commentReference w:id="${id}"/></w:r>`,
    });
  }

  // Apply insertions back-to-front so positions stay valid; stable order
  // for equal positions (range-end markup sorts before range-start of a
  // later comment only via position, which cannot collide at run
  // boundaries for distinct runs; same-position inserts keep insertion
  // order).
  insertions.sort((a, b) => b.pos - a.pos);
  for (const ins of insertions) {
    documentXml = documentXml.slice(0, ins.pos) + ins.markup + documentXml.slice(ins.pos);
  }

  if (comments.length > 0) {
    // word/comments.xml
    const commentsXml =
      `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
      `<w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
      comments.join("") +
      `</w:comments>`;
    entries["word/comments.xml"] = strToU8(commentsXml);

    // word/_rels/document.xml.rels — add the comments relationship.
    const relsPath = "word/_rels/document.xml.rels";
    const relsEntry = entries[relsPath];
    let rels = relsEntry
      ? strFromU8(relsEntry)
      : `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>`;
    if (!/comments\.xml/.test(rels)) {
      // Deterministic id: one past the highest existing numeric rId.
      const ids = [...rels.matchAll(/Id="rId(\d+)"/g)].map((m) => Number(m[1]));
      const rid = `rId${(ids.length ? Math.max(...ids) : 0) + 1}`;
      rels = rels.replace(
        "</Relationships>",
        `<Relationship Id="${rid}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/comments" Target="comments.xml"/></Relationships>`,
      );
      entries[relsPath] = strToU8(rels);
    }

    // [Content_Types].xml — add the comments override.
    const ctPath = "[Content_Types].xml";
    const ctEntry = entries[ctPath];
    if (ctEntry) {
      let ct = strFromU8(ctEntry);
      if (!/word\/comments\.xml/.test(ct)) {
        ct = ct.replace(
          "</Types>",
          `<Override PartName="/word/comments.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml"/></Types>`,
        );
        entries[ctPath] = strToU8(ct);
      }
    }
  }

  entries["word/document.xml"] = strToU8(documentXml);

  // Deterministic container: sorted entry order, fixed mtime.
  const zippable: Zippable = {};
  for (const name of Object.keys(entries).sort()) {
    // DOS zip dates must be 1980–2099 and are encoded from LOCAL date
    // fields, so a Date built from local fields is byte-stable across
    // timezones (an ISO/UTC constant would shift).
    zippable[name] = [entries[name]!, { mtime: new Date(2001, 0, 1) }];
  }
  const bytes = zipSync(zippable);
  return {
    bytes,
    anchored: run.findings.length - unanchoredFindings.length,
    unanchored: unanchoredFindings.length,
  };
}

/** Blob wrapper for the browser download path. */
export function reviewedDocxBlob(original: ArrayBuffer, run: EngineRun): Blob {
  return new Blob([buildReviewedDocx(original, run).bytes as unknown as BlobPart], {
    type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  });
}
