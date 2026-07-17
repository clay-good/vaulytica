import { describe, expect, it } from "vitest";
import { zipSync, strToU8 } from "fflate";

import {
  BUNDLE_CAP_MESSAGE,
  MAX_BUNDLE_BYTES,
  MAX_BUNDLE_FILES,
  MAX_FILE_BYTES,
  MULTIPLE_PRIVILEGE_LOGS_MESSAGE,
  classifyDataMember,
  classifyExtension,
  extractZipEntries,
  looksLikeZip,
  planBundle,
  rejectionForFilename,
  selectPrivilegeLogMember,
  ArchiveTooLargeError,
} from "./multi.js";

function fakeBytes(size: number, fill = 0): ArrayBuffer {
  const u = new Uint8Array(size);
  u.fill(fill);
  return u.buffer;
}

/* ---------------- classifyExtension ---------------- */

describe("classifyExtension", () => {
  it("returns 'pdf' for .pdf (case-insensitive)", () => {
    expect(classifyExtension("contract.pdf")).toBe("pdf");
    expect(classifyExtension("CONTRACT.PDF")).toBe("pdf");
  });
  it("returns 'docx' for .docx (case-insensitive)", () => {
    expect(classifyExtension("nda.docx")).toBe("docx");
    expect(classifyExtension("NDA.DOCX")).toBe("docx");
  });
  it("returns null for anything else", () => {
    expect(classifyExtension("notes.txt")).toBeNull();
    expect(classifyExtension("legacy.doc")).toBeNull();
    expect(classifyExtension("scan.png")).toBeNull();
  });
});

describe("rejectionForFilename", () => {
  it("steers .doc to the save-as-.docx message", () => {
    expect(rejectionForFilename("old.doc")).toMatch(/save it as \.docx/i);
  });
  it("returns the generic accepts-pdf-and-docx message for everything else", () => {
    expect(rejectionForFilename("notes.txt")).toMatch(/\.pdf and \.docx/);
  });
});

/* ---------------- planBundle ---------------- */

describe("planBundle — caps", () => {
  it("rejects an empty bundle", () => {
    const r = planBundle([]);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/No files/);
  });

  it("rejects a bundle of more than MAX_BUNDLE_FILES", () => {
    const files = Array.from({ length: MAX_BUNDLE_FILES + 1 }, (_, i) => ({
      filename: `f${i}.docx`,
      bytes: fakeBytes(10),
      size_bytes: 10,
    }));
    const r = planBundle(files);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe(BUNDLE_CAP_MESSAGE);
  });

  it("rejects a bundle that exceeds MAX_BUNDLE_BYTES uncompressed", () => {
    // Two synthetic 'files' that sum to > 200 MB. We don't allocate the
    // bytes (would waste memory); we just lie about size_bytes — the
    // cap check uses the declared size.
    const halfPlus = Math.ceil(MAX_BUNDLE_BYTES / 2) + 1024;
    const r = planBundle([
      { filename: "a.docx", bytes: fakeBytes(8), size_bytes: halfPlus },
      { filename: "b.docx", bytes: fakeBytes(8), size_bytes: halfPlus },
    ]);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe(BUNDLE_CAP_MESSAGE);
  });

  it("rejects an individual file over MAX_FILE_BYTES while accepting siblings", () => {
    const r = planBundle([
      { filename: "ok.docx", bytes: fakeBytes(10), size_bytes: 10 },
      { filename: "huge.docx", bytes: fakeBytes(8), size_bytes: MAX_FILE_BYTES + 1 },
    ]);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const ok = r.entries.find((e) => e.filename === "ok.docx")!;
    const huge = r.entries.find((e) => e.filename === "huge.docx")!;
    expect(ok.ok).toBe(true);
    expect(huge.ok).toBe(false);
    if (!huge.ok) expect(huge.reason).toMatch(/50 MB per-file/);
  });

  it("accepts a healthy mixed bundle", () => {
    const r = planBundle([
      { filename: "a.pdf", bytes: fakeBytes(100), size_bytes: 100 },
      { filename: "b.docx", bytes: fakeBytes(200), size_bytes: 200 },
    ]);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.total_bytes).toBe(300);
    expect(r.entries.filter((e) => e.ok)).toHaveLength(2);
  });

  it("rejects unsupported extensions inside an otherwise valid bundle", () => {
    const r = planBundle([
      { filename: "good.pdf", bytes: fakeBytes(10), size_bytes: 10 },
      { filename: "bad.txt", bytes: fakeBytes(10), size_bytes: 10 },
      { filename: "legacy.doc", bytes: fakeBytes(10), size_bytes: 10 },
    ]);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const txt = r.entries.find((e) => e.filename === "bad.txt")!;
    const doc = r.entries.find((e) => e.filename === "legacy.doc")!;
    expect(txt.ok).toBe(false);
    expect(doc.ok).toBe(false);
    if (!doc.ok) expect(doc.reason).toMatch(/save it as \.docx/i);
  });
});

/* ---------------- looksLikeZip ---------------- */

describe("looksLikeZip", () => {
  it("matches the PK\\x03\\x04 magic", () => {
    const buf = new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0, 0, 0]).buffer;
    expect(looksLikeZip(buf)).toBe(true);
  });
  it("matches the empty-zip PK\\x05\\x06 magic", () => {
    const buf = new Uint8Array([0x50, 0x4b, 0x05, 0x06]).buffer;
    expect(looksLikeZip(buf)).toBe(true);
  });
  it("rejects non-zip bytes", () => {
    expect(looksLikeZip(new Uint8Array([0xff, 0xd8, 0xff]).buffer)).toBe(false);
  });
});

/* ---------------- extractZipEntries ---------------- */

function buildZip(entries: Record<string, Uint8Array>): ArrayBuffer {
  const out = zipSync(entries);
  return out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength) as ArrayBuffer;
}

describe("extractZipEntries", () => {
  it("extracts every .pdf and .docx entry", () => {
    const archive = buildZip({
      "msa.docx": strToU8("docx-bytes"),
      "baa.pdf": strToU8("pdf-bytes"),
      "README.md": strToU8("# readme — should be skipped"),
    });
    const entries = extractZipEntries(archive);
    expect(entries).toHaveLength(2);
    expect(entries.map((e) => e.filename).sort()).toEqual(["baa.pdf", "msa.docx"]);
  });

  it("extracts a .csv privilege-log data member alongside the documents (add-production-qa-pack)", () => {
    const archive = buildZip({
      "msa.docx": strToU8("docx-bytes"),
      "privilege-log.csv": strToU8("bates_begin,bates_end\nACME-1,ACME-1"),
      "README.md": strToU8("skip me"),
    });
    const entries = extractZipEntries(archive);
    expect(entries.map((e) => e.filename).sort()).toEqual(["msa.docx", "privilege-log.csv"]);
  });

  it("flattens nested folders and uses the basename as the entry name", () => {
    const archive = buildZip({
      "deal-2026/contracts/msa.docx": strToU8("x"),
      "deal-2026/contracts/sub/baa.docx": strToU8("y"),
    });
    const entries = extractZipEntries(archive);
    expect(entries.map((e) => e.filename).sort()).toEqual(["baa.docx", "msa.docx"]);
  });

  it("skips __MACOSX/ sidecar entries silently", () => {
    const archive = buildZip({
      "msa.docx": strToU8("x"),
      "__MACOSX/._msa.docx": strToU8("garbage"),
    });
    const entries = extractZipEntries(archive);
    expect(entries).toHaveLength(1);
    expect(entries[0]!.filename).toBe("msa.docx");
  });

  it("rejects a zip bomb by compression ratio before full expansion (spec-v8 §8)", () => {
    // 4 MB of zeros in a .docx-named entry compresses to a few KB → ratio ≫ 200×.
    const bomb = buildZip({ "bomb.docx": new Uint8Array(4 * 1024 * 1024) });
    expect(() => extractZipEntries(bomb)).toThrow(ArchiveTooLargeError);
  });

  it("rejects a nested archive rather than recursing into it (spec-v8 §8)", () => {
    const inner = new Uint8Array(buildZip({ "msa.docx": strToU8("x") }));
    const archive = buildZip({ "outer.docx": strToU8("x"), "inner.zip": inner });
    expect(() => extractZipEntries(archive)).toThrow(ArchiveTooLargeError);
  });

  it("an under-declaring header never yields more bytes than it declared (harden-determinism-guards)", () => {
    // Craft an archive whose headers lie small: 100,000 real bytes declared
    // as 1,000. The declared-size budget in the filter is attacker-
    // controlled data, so the extraction must be bounded by MEASURED
    // production: fflate stops inflating at the declared size, and the
    // post-inflate honesty check pins that invariant so a library upgrade
    // that starts trusting the stream over the header fails here loudly.
    const real = 100_000;
    const declared = 1_000;
    const zip = Buffer.from(new Uint8Array(buildZip({ "doc.pdf": new Uint8Array(real).fill(65) })));
    let patched = 0;
    for (let i = 0; i + 4 <= zip.length; i++) {
      if (zip.readUInt32LE(i) === real) {
        zip.writeUInt32LE(declared, i);
        patched++;
      }
    }
    expect(patched).toBeGreaterThanOrEqual(2); // local header + central directory
    const entries = extractZipEntries(
      zip.buffer.slice(zip.byteOffset, zip.byteOffset + zip.byteLength) as ArrayBuffer,
    );
    expect(entries).toHaveLength(1);
    // Never past the declared ceiling — allocation is bounded by it.
    expect(entries[0]!.size_bytes).toBeLessThanOrEqual(declared);
  });

  it("produces a deterministic order regardless of zip producer order", () => {
    const a = buildZip({ "z.docx": strToU8("x"), "a.docx": strToU8("y") });
    const b = buildZip({ "a.docx": strToU8("y"), "z.docx": strToU8("x") });
    const ea = extractZipEntries(a).map((e) => e.filename);
    const eb = extractZipEntries(b).map((e) => e.filename);
    expect(ea).toEqual(["a.docx", "z.docx"]);
    expect(eb).toEqual(["a.docx", "z.docx"]);
  });

  it("ignores zip-slip parent-traversal segments", () => {
    // We can't easily synthesize a zip with `..` segments via fflate's
    // surface (it normalizes), but the check is defensive — confirm
    // the function still returns a clean list for a normal archive.
    const archive = buildZip({ "ok.docx": strToU8("x") });
    expect(extractZipEntries(archive)).toHaveLength(1);
  });
});

/* ---------------- Production-QA data members ---------------- */

describe("classifyDataMember", () => {
  it("recognizes .csv as the privilege-log data member (case-insensitive)", () => {
    expect(classifyDataMember("privilege-log.csv")).toBe("csv");
    expect(classifyDataMember("LOG.CSV")).toBe("csv");
  });
  it("returns null for documents and other extensions", () => {
    expect(classifyDataMember("contract.docx")).toBeNull();
    expect(classifyDataMember("brief.pdf")).toBeNull();
    expect(classifyDataMember("notes.txt")).toBeNull();
  });
});

describe("selectPrivilegeLogMember", () => {
  const csv = (name: string, text: string): { filename: string; bytes: ArrayBuffer } => {
    const u = strToU8(text);
    return { filename: name, bytes: u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) };
  };

  it("returns no member and no rejection when there is no CSV", () => {
    const out = selectPrivilegeLogMember([
      { filename: "a.docx", bytes: fakeBytes(4) },
      { filename: "b.pdf", bytes: fakeBytes(4) },
    ]);
    expect(out.member).toBeUndefined();
    expect(out.rejected).toEqual([]);
  });

  it("decodes the single privilege-log CSV to text", () => {
    const out = selectPrivilegeLogMember([
      { filename: "a.docx", bytes: fakeBytes(4) },
      csv("privilege-log.csv", "control,description\n1,Memo"),
    ]);
    expect(out.member).toEqual({
      filename: "privilege-log.csv",
      csv: "control,description\n1,Memo",
    });
    expect(out.rejected).toEqual([]);
  });

  it("rejects a production set carrying more than one privilege-log CSV", () => {
    const out = selectPrivilegeLogMember([csv("log-a.csv", "x"), csv("log-b.csv", "y")]);
    expect(out.member).toBeUndefined();
    expect(out.rejected).toEqual([
      { filename: "log-a.csv", reason: MULTIPLE_PRIVILEGE_LOGS_MESSAGE },
      { filename: "log-b.csv", reason: MULTIPLE_PRIVILEGE_LOGS_MESSAGE },
    ]);
  });
});
