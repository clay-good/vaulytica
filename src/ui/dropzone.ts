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

export type DropzoneOptions = {
  /** Called with the validated file. */
  onFile: (result: DropResult) => void;
  /** Called when a drag-over begins/ends so CSS can pulse the border. */
  onDragState?: (active: boolean) => void;
};

export function bindDropzone(dz: HTMLElement, opts: DropzoneOptions): () => void {
  const input = document.createElement("input");
  input.type = "file";
  input.accept = ".pdf,.docx";
  input.style.display = "none";
  dz.appendChild(input);

  const handleFile = (file: File | undefined): void => {
    if (!file) return;
    opts.onFile(validateFile(file));
  };

  const onPick = (): void => {
    input.value = "";
    input.click();
  };
  const onInputChange = (): void => {
    handleFile(input.files?.[0] ?? undefined);
  };
  const onKey = (e: KeyboardEvent): void => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      onPick();
    }
  };
  const onClick = (e: Event): void => {
    if (e.target === input) return;
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
    const file = e.dataTransfer?.files?.[0];
    handleFile(file ?? undefined);
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
