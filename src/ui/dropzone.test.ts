import { describe, expect, it, vi } from "vitest";
import {
  bindDropzone,
  collectFilesFromEntries,
  isZipFile,
  validateFile,
  type DropResult,
} from "./dropzone.js";

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

  it("injects a visually-hidden file input with an aria-label as the keyboard entry point", () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    bindDropzone(dz, { onFile: () => {} });
    const input = dz.querySelector<HTMLInputElement>("input[type=file]:not([webkitdirectory])")!;
    expect(input, "primary file input must exist").toBeTruthy();
    // sr-only class keeps the input in the tab order (Enter/Space
    // opens the native picker) without visually rendering it.
    expect(input.className).toBe("sr-only");
    expect(input.getAttribute("aria-label")).toMatch(/PDF|DOCX/i);
    // The webkitdirectory sibling input is JS-driven only — out of
    // tab order and aria-hidden so it doesn't surface as a second
    // unlabeled file picker.
    const dirInput = dz.querySelector<HTMLInputElement>("input[webkitdirectory]")!;
    expect(dirInput.tabIndex).toBe(-1);
    expect(dirInput.getAttribute("aria-hidden")).toBe("true");
    document.body.removeChild(dz);
  });

  it("exposes input[multiple] so the v4 multi-doc e2e probe matches", () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    bindDropzone(dz, { onFile: () => {} });
    const input = dz.querySelector<HTMLInputElement>("input[type=file]")!;
    expect(input.multiple).toBe(true);
    // spec-v4 §8 accept list must include .zip alongside .pdf/.docx
    expect(input.accept.split(",")).toEqual(expect.arrayContaining([".pdf", ".docx", ".zip"]));
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

describe("folder picker (webkitdirectory)", () => {
  it("exposes input[webkitdirectory] so the v4-o probe selector matches", () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    bindDropzone(dz, { onFile: () => {} });
    const dirInput = dz.querySelector<HTMLInputElement>('input[type="file"][webkitdirectory]');
    expect(dirInput).not.toBeNull();
    expect(dirInput!.multiple).toBe(true);
    document.body.removeChild(dz);
  });

  it("a click on [data-role=folder-pick] opens the directory picker, not the file picker", () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    dz.innerHTML = `<button data-role="folder-pick">choose folder</button>`;
    bindDropzone(dz, { onFile: () => {} });
    const inputs = dz.querySelectorAll<HTMLInputElement>('input[type="file"]');
    const fileInput = Array.from(inputs).find((i) => !i.hasAttribute("webkitdirectory"))!;
    const dirInput = Array.from(inputs).find((i) => i.hasAttribute("webkitdirectory"))!;
    const fileClick = vi.spyOn(fileInput, "click");
    const dirClick = vi.spyOn(dirInput, "click");
    (dz.querySelector('[data-role="folder-pick"]') as HTMLButtonElement).click();
    expect(dirClick).toHaveBeenCalledTimes(1);
    expect(fileClick).toHaveBeenCalledTimes(0);
    document.body.removeChild(dz);
  });

  it("folder-picker change keeps .pdf/.docx + the privilege-log .csv, drops junk, routes to onFiles", () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    const bundles: File[][] = [];
    bindDropzone(dz, {
      onFile: () => {},
      onFiles: (fs) => bundles.push(fs),
    });
    const dirInput = dz.querySelector<HTMLInputElement>('input[type="file"][webkitdirectory]')!;
    const a = fakeFile("a.pdf");
    const b = fakeFile("b.docx");
    // add-production-qa-pack: a privilege log dropped with the production set
    // must survive to the bundle pipeline (it drives Bates/log reconciliation).
    const log = fakeFile("privilege-log.csv", "text/csv");
    const junk = fakeFile(".DS_Store", "application/octet-stream");
    const readme = fakeFile("README.md", "text/plain");
    Object.defineProperty(dirInput, "files", {
      configurable: true,
      get: () => [a, junk, b, log, readme],
    });
    dirInput.dispatchEvent(new Event("change"));
    expect(bundles).toHaveLength(1);
    expect(bundles[0]!.map((f) => f.name).sort()).toEqual(["a.pdf", "b.docx", "privilege-log.csv"]);
    document.body.removeChild(dz);
  });

  it("still rejects a lone .csv — a privilege log is not a document to analyze alone", () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    const results: DropResult[] = [];
    bindDropzone(dz, {
      onFile: (r) => results.push(r),
      onFiles: () => {},
    });
    const input = dz.querySelector<HTMLInputElement>('input[type="file"]:not([webkitdirectory])')!;
    const log = fakeFile("privilege-log.csv", "text/csv");
    Object.defineProperty(input, "files", { configurable: true, get: () => [log] });
    input.dispatchEvent(new Event("change"));
    expect(results).toHaveLength(1);
    expect(results[0]!.ok).toBe(false);
    document.body.removeChild(dz);
  });
});

describe("collectFilesFromEntries", () => {
  // Build a minimal in-memory FileSystemEntry tree: one root directory
  // containing two files and one nested subdirectory with a third file.
  function makeFileEntry(name: string): FileSystemFileEntry {
    return {
      isFile: true,
      isDirectory: false,
      name,
      fullPath: `/${name}`,
      filesystem: null as unknown as FileSystem,
      file: (cb: (file: File) => void) => cb(new File(["x"], name)),
      getParent: () => {},
    } as unknown as FileSystemFileEntry;
  }
  function makeDirEntry(name: string, children: FileSystemEntry[]): FileSystemDirectoryEntry {
    let read = false;
    return {
      isFile: false,
      isDirectory: true,
      name,
      fullPath: `/${name}`,
      filesystem: null as unknown as FileSystem,
      createReader: () => ({
        readEntries: (ok: (entries: FileSystemEntry[]) => void) => {
          if (read) {
            ok([]);
            return;
          }
          read = true;
          ok(children);
        },
      }),
      getFile: () => {},
      getDirectory: () => {},
    } as unknown as FileSystemDirectoryEntry;
  }

  it("walks nested directories and returns every File in order", async () => {
    const tree = makeDirEntry("root", [
      makeFileEntry("a.pdf"),
      makeDirEntry("sub", [makeFileEntry("c.docx")]),
      makeFileEntry("b.docx"),
    ]);
    const files = await collectFilesFromEntries([tree]);
    expect(files.map((f) => f.name)).toEqual(["a.pdf", "c.docx", "b.docx"]);
  });

  it("flattens a flat list of FileSystemFileEntries", async () => {
    const files = await collectFilesFromEntries([makeFileEntry("a.pdf"), makeFileEntry("b.docx")]);
    expect(files.map((f) => f.name)).toEqual(["a.pdf", "b.docx"]);
  });
});
