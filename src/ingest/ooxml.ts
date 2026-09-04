import { unzipSync, strFromU8 } from "fflate";

/** Per-OOXML-part inflate ceiling — bounds the work done on any one member. */
const MAX_PART_BYTES = 16 * 1024 * 1024;
/** Decompression-ratio ceiling — the zip-bomb guard (v8 §8, matches multi.ts). */
const MAX_COMPRESSION_RATIO = 200;

/**
 * Inflate only the named OOXML parts, applying the v8 zip-bomb guards in
 * fflate's pre-inflate filter so a malicious member is rejected BEFORE it is
 * expanded. Everything else in the archive is never inflated at all.
 *
 * This lived in `delivery/container.ts`, which was the only caller until the
 * DOCX ingest needed to know whether a document carries tracked changes.
 * Copying it would have put a second, drifting spelling of the zip-bomb guard
 * in the tree — the failure this codebase keeps finding in its own rule layer.
 */
export function inflateOoxmlParts(
  bytes: ArrayBuffer,
  parts: ReadonlySet<string>,
): Record<string, string> {
  const out: Record<string, string> = {};
  const unzipped = unzipSync(new Uint8Array(bytes), {
    filter: (file) => {
      if (!parts.has(file.name)) return false; // never inflated
      const ratio = file.size > 0 ? file.originalSize / file.size : file.originalSize;
      if (ratio > MAX_COMPRESSION_RATIO) return false;
      if (file.originalSize > MAX_PART_BYTES) return false;
      return true;
    },
  });
  for (const [name, data] of Object.entries(unzipped)) {
    if (!parts.has(name)) continue;
    out[name] = strFromU8(data);
  }
  return out;
}
