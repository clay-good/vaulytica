/**
 * Drop zone — drag, paste, and click-to-pick interactions. The DOM
 * element is the same in all three pipeline states; the runtime state
 * is toggled via `data-state` so CSS can style transitions without
 * the JS swapping markup.
 *
 * Validation rules per spec §26 step 12:
 *   - .pdf  → accept (route to ingestPdf)
 *   - .docx → accept (route to ingestDocx)
 *   - .doc  → reject with the user-facing fix-it message
 *   - other → reject with a generic message
 *
 * Multi-document mode (spec-v4.md §8, Step 41 UI hookup, LAUNCH row v4-d):
 *   - The file input carries `multiple` so users can pick more than one
 *     file in a single picker gesture.
 *   - When ≥ 2 files arrive (drag-drop or picker), the bundle callback
 *     `onFiles` fires instead of `onFile`. The pipeline routes those
 *     through `src/ingest/multi.ts` + `runEngineMulti` +
 *     `buildBundleDocxReport`.
 *   - A single `.zip` drop is also treated as a bundle — the pipeline
 *     unpacks it client-side via `fflate`. We surface this through
 *     `onFiles([zip])` so the pipeline owns the zip-vs-multi-file split.
 *
 * Accessibility: role="button" + tabindex="0" + Enter/Space activation
 * + focus-visible outline live in `site/index.html`. The handlers
 * preventDefault() on drag events so the browser doesn't navigate.
 */

export type AcceptedKind = "pdf" | "docx";

export type DropResult =
  | { ok: true; file: File; kind: AcceptedKind }
  | { ok: false; reason: string };

export function validateFile(file: File): DropResult {
  const name = file.name.toLowerCase();
  if (name.endsWith(".pdf")) return { ok: true, file, kind: "pdf" };
  if (name.endsWith(".docx")) return { ok: true, file, kind: "docx" };
  if (name.endsWith(".doc")) {
    return {
      ok: false,
      reason: "Open it in Word or Google Docs and save it as .docx, then come back.",
    };
  }
  return { ok: false, reason: `Vaulytica accepts .pdf and .docx — not "${file.name}".` };
}

/** True if the filename indicates a zip archive bundle (spec-v4 §8). */
export function isZipFile(file: File): boolean {
  return file.name.toLowerCase().endsWith(".zip");
}

export type DropzoneOptions = {
  /** Called with the validated single file. */
  onFile: (result: DropResult) => void;
  /**
   * Called with the dropped/picked file list when ≥ 2 files arrive
   * **or** when a single `.zip` arrives. The pipeline owns the bundle
   * branch. When omitted, multi-file drops fall back to `onFile` on
   * the first entry (preserves v1/v3 single-doc behavior).
   */
  onFiles?: (files: File[]) => void;
  /** Called when a drag-over begins/ends so CSS can pulse the border. */
  onDragState?: (active: boolean) => void;
};

export function bindDropzone(dz: HTMLElement, opts: DropzoneOptions): () => void {
  const input = document.createElement("input");
  input.type = "file";
  // Multi-doc accept list adds .zip for the zip-bundle path (spec-v4 §8).
  // The pipeline still distinguishes ≥ 2 files vs a single `.zip` and
  // rejects unsupported extensions upstream via `validateFile` /
  // `planBundle`.
  input.accept = ".pdf,.docx,.zip";
  input.multiple = true;
  input.style.display = "none";
  dz.appendChild(input);

  const dispatch = (files: File[]): void => {
    if (files.length === 0) return;
    const isBundle =
      files.length >= 2 || (files.length === 1 && isZipFile(files[0]!));
    if (isBundle && opts.onFiles) {
      opts.onFiles(files);
      return;
    }
    opts.onFile(validateFile(files[0]!));
  };

  const onPick = (): void => {
    input.value = "";
    input.click();
  };
  const onInputChange = (): void => {
    const list = input.files;
    if (!list || list.length === 0) return;
    const files: File[] = [];
    for (let i = 0; i < list.length; i++) files.push(list[i]!);
    dispatch(files);
  };
  const onKey = (e: KeyboardEvent): void => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      onPick();
    }
  };
  const onClick = (e: Event): void => {
    if (e.target === input) return;
    // The dropzone hosts interactive children in the "complete" / "error"
    // states (download anchors, retry button, "why this playbook?"
    // disclosure). Clicks on those must NOT also re-open the file
    // picker — otherwise macOS shows its NSOpenPanel ("Open" button)
    // on top of the download flow and the file never gets saved.
    const target = e.target as HTMLElement | null;
    if (target?.closest("a, button, summary, details, input, label")) return;
    onPick();
  };
  const onDragEnter = (e: DragEvent): void => {
    e.preventDefault();
    opts.onDragState?.(true);
  };
  const onDragOver = (e: DragEvent): void => {
    e.preventDefault();
  };
  const onDragLeave = (e: DragEvent): void => {
    e.preventDefault();
    opts.onDragState?.(false);
  };
  const onDrop = (e: DragEvent): void => {
    e.preventDefault();
    opts.onDragState?.(false);
    const list = e.dataTransfer?.files;
    if (!list || list.length === 0) return;
    const files: File[] = [];
    for (let i = 0; i < list.length; i++) files.push(list[i]!);
    dispatch(files);
  };

  dz.addEventListener("click", onClick);
  dz.addEventListener("keydown", onKey);
  dz.addEventListener("dragenter", onDragEnter as EventListener);
  dz.addEventListener("dragover", onDragOver as EventListener);
  dz.addEventListener("dragleave", onDragLeave as EventListener);
  dz.addEventListener("drop", onDrop as EventListener);
  input.addEventListener("change", onInputChange);

  return () => {
    dz.removeEventListener("click", onClick);
    dz.removeEventListener("keydown", onKey);
    dz.removeEventListener("dragenter", onDragEnter as EventListener);
    dz.removeEventListener("dragover", onDragOver as EventListener);
    dz.removeEventListener("dragleave", onDragLeave as EventListener);
    dz.removeEventListener("drop", onDrop as EventListener);
    input.removeEventListener("change", onInputChange);
    dz.removeChild(input);
  };
}
