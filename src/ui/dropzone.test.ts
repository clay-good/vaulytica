import { describe, expect, it, vi } from "vitest";
import { bindDropzone, validateFile, type DropResult } from "./dropzone.js";

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
});
