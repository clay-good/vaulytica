/**
 * The other reading of a redline (add-redline-two-sided-analysis).
 *
 * A DOCX with tracked changes is two documents: the draft as it stood, with
 * every change rejected, and the draft the reviser wants, with every change
 * accepted. mammoth reads only the second. This module writes the first as a
 * rewritten `word/document.xml`, which mammoth then reads like any other.
 *
 * Rejecting a change means:
 *   - an insertion (`w:ins`) or the destination of a move (`w:moveTo`) and
 *     everything inside it is removed;
 *   - a deletion (`w:del`) or the origin of a move (`w:moveFrom`) is
 *     unwrapped, and its `w:delText` / `w:delInstrText` become the ordinary
 *     `w:t` / `w:instrText` mammoth reads;
 *   - the empty markers Word puts on a paragraph mark or a table row
 *     (`<w:ins …/>`, `<w:del …/>`) are dropped.
 *
 * Formatting changes (`w:rPrChange`, `w:pPrChange`) carry no text and are
 * left alone. A rejected paragraph-mark insertion is not merged into the next
 * paragraph: the text is right and only the break differs.
 *
 * The scan is `indexOf`-based and moves forward only, so its work is linear in
 * the part's length whatever the markup. An element never closed is left as
 * written, along with everything after it: no closing tag follows it, so no
 * later element of that kind can close either, and searching again for each
 * one made a malformed file quadratic.
 */
import { strToU8, unzipSync, zipSync } from "fflate";

const MAX_PART_BYTES = 16 * 1024 * 1024;
const MAX_COMPRESSION_RATIO = 200;

/** Remove each `<tag …>…</tag>` element, and every self-closing `<tag …/>`. */
function removeElements(xml: string, tag: string): string {
  const open = `<${tag}`;
  const close = `</${tag}>`;
  let out = "";
  let at = 0;
  for (;;) {
    const start = xml.indexOf(open, at);
    if (start < 0) break;
    const next = xml[start + open.length];
    // "<w:ins" must not match "<w:insideH"; the tag name ends here.
    if (next !== " " && next !== ">" && next !== "/") {
      out += xml.slice(at, start + open.length);
      at = start + open.length;
      continue;
    }
    const tagEnd = xml.indexOf(">", start);
    if (tagEnd < 0) break;
    out += xml.slice(at, start);
    if (xml[tagEnd - 1] === "/") {
      at = tagEnd + 1;
      continue;
    }
    const end = xml.indexOf(close, tagEnd);
    if (end < 0) {
      // Never closed, and so is every later one, since no closing tag
      // follows: leave the rest as written instead of searching again.
      out += xml.slice(start);
      at = xml.length;
      break;
    }
    at = end + close.length;
  }
  return out + xml.slice(at);
}

/** Drop each `<tag …>` and `</tag>`, keeping what is between; drop `<tag …/>`. */
function unwrapElements(xml: string, tag: string): string {
  const open = `<${tag}`;
  const close = `</${tag}>`;
  let out = "";
  let at = 0;
  for (;;) {
    const start = xml.indexOf(open, at);
    if (start < 0) break;
    const next = xml[start + open.length];
    if (next !== " " && next !== ">" && next !== "/") {
      out += xml.slice(at, start + open.length);
      at = start + open.length;
      continue;
    }
    const tagEnd = xml.indexOf(">", start);
    if (tagEnd < 0) break;
    out += xml.slice(at, start);
    at = tagEnd + 1;
  }
  return (out + xml.slice(at)).split(close).join("");
}

/** `word/document.xml` with every tracked change rejected. */
export function rejectedDocumentXml(xml: string): string {
  let out = removeElements(xml, "w:ins");
  out = removeElements(out, "w:moveTo");
  out = unwrapElements(out, "w:del");
  out = unwrapElements(out, "w:moveFrom");
  return out
    .replace(/<w:delText(?=[\s>/])/g, "<w:t")
    .replace(/<\/w:delText>/g, "</w:t>")
    .replace(/<w:delInstrText(?=[\s>/])/g, "<w:instrText")
    .replace(/<\/w:delInstrText>/g, "</w:instrText>");
}

/**
 * The same DOCX with its tracked changes rejected, as bytes mammoth can read.
 * Members over the zip-bomb bounds `ooxml.ts` applies are left out; none of
 * them is text the reading needs.
 */
export function withRevisionsRejected(bytes: ArrayBuffer): ArrayBuffer {
  const files = unzipSync(new Uint8Array(bytes), {
    filter: (file) => {
      const ratio = file.size > 0 ? file.originalSize / file.size : file.originalSize;
      return ratio <= MAX_COMPRESSION_RATIO && file.originalSize <= MAX_PART_BYTES;
    },
  });
  const doc = files["word/document.xml"];
  if (doc) {
    files["word/document.xml"] = strToU8(rejectedDocumentXml(new TextDecoder().decode(doc)));
  }
  const zipped = zipSync(files);
  return zipped.buffer.slice(
    zipped.byteOffset,
    zipped.byteOffset + zipped.byteLength,
  ) as ArrayBuffer;
}
