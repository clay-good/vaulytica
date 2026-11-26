/**
 * The DOCX's document part, normalized — shared by the two guards that read it.
 *
 * A `.docx` is a zip, so its raw bytes are not comparable: the archive carries
 * per-entry metadata, `docProps/core.xml` carries a creation stamp, and the
 * `docx` library mints every hyperlink's relationship id with `nanoid()`. What
 * IS comparable is `word/document.xml` with the random ids folded to a
 * placeholder — the part that holds every word a reader sees.
 *
 * 🚨 This lived as a private constant inside `report-reproducibility.test.ts`
 * while `artifact-digests.test.ts` declared in its header that the DOCX could
 * not be digested at all. Two guards reading one artifact with one exception
 * between them is exactly the shape that drifts into two spellings of the same
 * rule, so the extraction and the exception live here once.
 */
import { sha256Hex } from "../../src/ingest/hash.js";

/**
 * The ONE declared exception, with its cause.
 *
 * `docx` generates each hyperlink's relationship id with `nanoid()`
 * (`uniqueId = () => nanoid().toLowerCase()` in the shipped bundle), so every
 * citation link in a fresh render carries a fresh `r:id`. Nothing in the
 * library's public API takes a seed or a counter. Normalized here, and ONLY
 * here — the rest of the document part still has to match exactly.
 */
export const DOCX_RANDOM_REL_IDS = /r:id="rId[A-Za-z0-9_-]+"/g;

/**
 * Smallest document part either guard should ever see.
 *
 * 🚨 Both call sites assert this. A normalization that ate the document, or an
 * unzip that returned an empty entry, makes every comparison downstream pass
 * for the wrong reason — the vacuous-guard failure this repository has hit
 * repeatedly. The real parts are ~100 KB; a part under this floor is a broken
 * harness, not a small report.
 */
export const MIN_DOCUMENT_PART_CHARS = 50_000;

/** `word/document.xml` out of a rendered DOCX, with the random ids folded. */
export async function docxDocumentPart(bytes: ArrayBuffer | Uint8Array): Promise<string> {
  const { unzipSync, strFromU8 } = await import("fflate");
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const entry = unzipSync(u8)["word/document.xml"];
  if (!entry) throw new Error("rendered DOCX has no word/document.xml");
  return strFromU8(entry).replace(DOCX_RANDOM_REL_IDS, 'r:id="rIdN"');
}

/** SHA-256 of {@link docxDocumentPart}, for the committed digest set. */
export async function docxDocumentPartDigest(bytes: ArrayBuffer | Uint8Array): Promise<string> {
  const part = await docxDocumentPart(bytes);
  if (part.length < MIN_DOCUMENT_PART_CHARS) {
    throw new Error(
      `DOCX document part is ${part.length} chars, under the ${MIN_DOCUMENT_PART_CHARS} floor — ` +
        "the harness is broken, not the report",
    );
  }
  return sha256Hex(part);
}
