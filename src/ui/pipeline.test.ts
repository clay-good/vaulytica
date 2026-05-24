/**
 * Unit tests for the pure helpers in `./pipeline.ts` that don't need
 * the full DKB / playbook stack. `runBundlePipeline` itself is exercised
 * end-to-end through the Playwright suite in `tests/e2e/v4/` — those
 * tests need a real served page. The bundle-input expansion is pure,
 * synchronous-ish, and worth pinning here because it's the first step
 * of every multi-doc run.
 */

import { describe, expect, it } from "vitest";
import { zipSync, strToU8 } from "fflate";
import { expandBundleInputs } from "./pipeline.js";

function fakeBlobFile(name: string, bytes: Uint8Array, type = ""): File {
  // Copy into a fresh ArrayBuffer so the File constructor sees a
  // non-SharedArrayBuffer-backed view (matters under `strict` TS lib).
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return new File([copy.buffer], name, { type });
}

describe("expandBundleInputs", () => {
  it("passes through a multi-file drop as candidate shapes", async () => {
    const a = fakeBlobFile("a.pdf", strToU8("a-bytes"));
    const b = fakeBlobFile("b.docx", strToU8("b-bytes"));
    const candidates = await expandBundleInputs([a, b]);
    expect(candidates.map((c) => c.filename).sort()).toEqual(["a.pdf", "b.docx"]);
    expect(candidates[0]!.bytes.byteLength).toBeGreaterThan(0);
    expect(candidates[0]!.size_bytes).toBe(candidates[0]!.bytes.byteLength);
  });

  it("drops unsupported extensions silently in the multi-file path", async () => {
    // The dropzone already filters folder-pick + drag-drop to .pdf/.docx,
    // but multi-file paste / picker could include arbitrary mime types.
    // `expandBundleInputs` should defensively drop anything classify-
    // unsupported so `planBundle` sees a tighter list.
    const ok = fakeBlobFile("contract.pdf", strToU8("pdf"));
    const junk = fakeBlobFile("README.md", strToU8("md"));
    const txt = fakeBlobFile("notes.txt", strToU8("notes"));
    const candidates = await expandBundleInputs([ok, junk, txt]);
    expect(candidates.map((c) => c.filename)).toEqual(["contract.pdf"]);
  });

  it("expands a single .zip drop via the zip-bundle path", async () => {
    // Build a zip with two .pdf entries + one ignored README.
    const archive = zipSync({
      "first.pdf": strToU8("aaa"),
      "second.docx": strToU8("bbb"),
      "README.txt": strToU8("ignored"),
    });
    const zipFile = fakeBlobFile("docs.zip", archive, "application/zip");
    const candidates = await expandBundleInputs([zipFile]);
    expect(candidates.map((c) => c.filename).sort()).toEqual(["first.pdf", "second.docx"]);
    // README is silently skipped per spec-v4 §8 (zip path); the
    // candidate list contains only the accepted entries.
    for (const c of candidates) {
      expect(c.bytes.byteLength).toBeGreaterThan(0);
      expect(c.size_bytes).toBe(c.bytes.byteLength);
    }
  });

  it("zip-bundle path is byte-stable across runs (determinism contract)", async () => {
    const archive = zipSync({
      "first.pdf": strToU8("aaa"),
      "second.docx": strToU8("bbb"),
    });
    const zipFile = fakeBlobFile("docs.zip", archive);
    const a = await expandBundleInputs([zipFile]);
    const b = await expandBundleInputs([zipFile]);
    expect(a.map((c) => c.filename)).toEqual(b.map((c) => c.filename));
    // Per src/ingest/multi.ts `extractZipEntries` sorts entries
    // lexicographically; verify the contract holds end-to-end.
    expect(a.map((c) => c.filename)).toEqual(["first.pdf", "second.docx"]);
  });

  it("a single non-zip file is treated as multi-file path of length 1", async () => {
    // Edge case: drop a single .pdf via the multi-file input. The
    // dropzone routes ≥2 files OR a single .zip to `onFiles`; a single
    // .pdf should normally go via `onFile`, but defensively
    // `expandBundleInputs` should handle the case anyway (caller may
    // pass anything).
    const a = fakeBlobFile("only.pdf", strToU8("solo"));
    const candidates = await expandBundleInputs([a]);
    expect(candidates).toHaveLength(1);
    expect(candidates[0]!.filename).toBe("only.pdf");
  });

  it("zip path with no accepted entries returns an empty list", async () => {
    // An archive containing only ignored files (README, images, etc.)
    // returns [] from `extractZipEntries`. `runBundlePipeline` then
    // bails out at the `accepted.length < 2` guard.
    const archive = zipSync({
      "README.md": strToU8("hi"),
      "logo.png": strToU8("png"),
    });
    const zipFile = fakeBlobFile("empty.zip", archive);
    const candidates = await expandBundleInputs([zipFile]);
    expect(candidates).toHaveLength(0);
  });
});
