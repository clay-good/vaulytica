/**
 * Which files are documents, by name. Dependency-free on purpose: the drop
 * zone asks this question on first paint, and importing it from `multi.ts`
 * dragged the whole bundle-ingest module into the eager entry chunk.
 */

export type AcceptedKind = "pdf" | "docx" | "text";

/** Plain-text extensions, read as pasted text is. The CLI reads the same four. */
export const TEXT_EXTENSIONS: readonly string[] = [".txt", ".md", ".markdown", ".text"];

/**
 * A text file's bytes as the string the engine reads. `ignoreBOM` KEEPS a
 * byte-order mark, which is what Node's `Buffer.toString("utf8")` does on the
 * command line — so the same file hashes the same in the tab and headless.
 */
export function decodeText(bytes: ArrayBuffer): string {
  return new TextDecoder("utf-8", { ignoreBOM: true }).decode(bytes);
}

export function classifyExtension(filename: string): AcceptedKind | null {
  const n = filename.toLowerCase();
  if (n.endsWith(".pdf")) return "pdf";
  if (n.endsWith(".docx")) return "docx";
  if (TEXT_EXTENSIONS.some((ext) => n.endsWith(ext))) return "text";
  return null;
}

export function rejectionForFilename(filename: string): string {
  if (filename.toLowerCase().endsWith(".doc")) {
    return "Open it in Word or Google Docs and save it as .docx, then come back.";
  }
  return `Vaulytica accepts .pdf, .docx, .txt and .md — not "${filename}".`;
}
