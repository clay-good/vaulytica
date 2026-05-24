import { describe, expect, it, vi } from "vitest";
import { bindDropzone, isZipFile, validateFile, type DropResult } from "./dropzone.js";

function fakeFile(name: string, type = "application/pdf"): File {
  return new File(["x"], name, { type });
}

describe("validateFile", () => {
  it("accepts .pdf", () => {
    const r = validateFile(fakeFile("contract.pdf"));
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.kind).toBe("pdf");
  });

  it("accepts .docx", () => {
    const r = validateFile(fakeFile("nda.DOCX"));
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.kind).toBe("docx");
  });

  it("rejects .doc with the fix-it message", () => {
    const r = validateFile(fakeFile("legacy.doc"));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/save it as \.docx/i);
  });

  it("rejects unknown extensions with a generic message", () => {
    const r = validateFile(fakeFile("notes.txt", "text/plain"));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/\.pdf and \.docx/);
  });
});

describe("bindDropzone", () => {
  it("fires onFile when Enter is pressed and the picker returns a file", () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    const calls: DropResult[] = [];
    const cleanup = bindDropzone(dz, { onFile: (r) => calls.push(r) });

    // Synthetic Enter key — opens the picker; the file input change is
    // what actually surfaces the file. Simulate it directly.
    const input = dz.querySelector<HTMLInputElement>("input[type=file]");
    expect(input).not.toBeNull();
    const file = fakeFile("x.pdf");
    Object.defineProperty(input!, "files", {
      configurable: true,
      get: () => [file],
    });
    input!.dispatchEvent(new Event("change"));

    expect(calls).toHaveLength(1);
    expect(calls[0]?.ok).toBe(true);
    cleanup();
    document.body.removeChild(dz);
  });

  it("fires onDragState(true) on dragenter and (false) on dragleave/drop", () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    const states: boolean[] = [];
    const cleanup = bindDropzone(dz, {
      onFile: () => {},
      onDragState: (a) => states.push(a),
    });
    dz.dispatchEvent(new DragEvent("dragenter"));
    dz.dispatchEvent(new DragEvent("dragleave"));
    expect(states).toEqual([true, false]);
    cleanup();
    document.body.removeChild(dz);
  });

  it("Enter triggers the file picker click", () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    bindDropzone(dz, { onFile: () => {} });
    const input = dz.querySelector<HTMLInputElement>("input[type=file]")!;
    const clickSpy = vi.spyOn(input, "click");
    dz.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter" }));
    expect(clickSpy).toHaveBeenCalledTimes(1);
    document.body.removeChild(dz);
  });

  it("exposes input[multiple] so the v4 multi-doc e2e probe matches", () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    bindDropzone(dz, { onFile: () => {} });
    const input = dz.querySelector<HTMLInputElement>("input[type=file]")!;
    expect(input.multiple).toBe(true);
    // spec-v4 §8 accept list must include .zip alongside .pdf/.docx
    expect(input.accept.split(",")).toEqual(
      expect.arrayContaining([".pdf", ".docx", ".zip"]),
    );
    document.body.removeChild(dz);
  });

  it("routes ≥ 2 files to onFiles, not onFile", () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    const singles: DropResult[] = [];
    const bundles: File[][] = [];
    bindDropzone(dz, {
      onFile: (r) => singles.push(r),
      onFiles: (fs) => bundles.push(fs),
    });
    const input = dz.querySelector<HTMLInputElement>("input[type=file]")!;
    const a = fakeFile("a.pdf");
    const b = fakeFile("b.docx");
    Object.defineProperty(input, "files", {
      configurable: true,
      get: () => [a, b],
    });
    input.dispatchEvent(new Event("change"));
    expect(singles).toHaveLength(0);
    expect(bundles).toHaveLength(1);
    expect(bundles[0]!.map((f) => f.name)).toEqual(["a.pdf", "b.docx"]);
    document.body.removeChild(dz);
  });

  it("routes a single .zip drop to onFiles (zip-bundle path)", () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    const singles: DropResult[] = [];
    const bundles: File[][] = [];
    bindDropzone(dz, {
      onFile: (r) => singles.push(r),
      onFiles: (fs) => bundles.push(fs),
    });
    const input = dz.querySelector<HTMLInputElement>("input[type=file]")!;
    const z = fakeFile("docs.zip", "application/zip");
    Object.defineProperty(input, "files", {
      configurable: true,
      get: () => [z],
    });
    input.dispatchEvent(new Event("change"));
    expect(singles).toHaveLength(0);
    expect(bundles).toHaveLength(1);
    expect(bundles[0]![0]!.name).toBe("docs.zip");
    document.body.removeChild(dz);
  });

  it("falls back to onFile when ≥ 2 files arrive but onFiles is not provided", () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    const singles: DropResult[] = [];
    bindDropzone(dz, { onFile: (r) => singles.push(r) });
    const input = dz.querySelector<HTMLInputElement>("input[type=file]")!;
    Object.defineProperty(input, "files", {
      configurable: true,
      get: () => [fakeFile("a.pdf"), fakeFile("b.docx")],
    });
    input.dispatchEvent(new Event("change"));
    expect(singles).toHaveLength(1);
    expect(singles[0]?.ok).toBe(true);
    document.body.removeChild(dz);
  });
});

describe("isZipFile", () => {
  it("matches .zip case-insensitively", () => {
    expect(isZipFile(new File([], "x.zip"))).toBe(true);
    expect(isZipFile(new File([], "X.ZIP"))).toBe(true);
    expect(isZipFile(new File([], "x.docx"))).toBe(false);
  });
});
