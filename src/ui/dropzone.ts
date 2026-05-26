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
 *   - **Folder mode** (spec-v4 §8 step 1, LAUNCH row v4-o): a second
 *     hidden `<input type="file" webkitdirectory multiple>` plus a
 *     visible "Choose folder…" affordance lets users pick a directory
 *     tree. Folder drag-drop is handled in the `drop` listener via
 *     `DataTransferItem.webkitGetAsEntry()` + the recursive walker
 *     exported from `src/ingest/multi.ts`. In both cases the
 *     enumerated `File[]` is dispatched through the same `onFiles`
 *     channel — pipeline routing is uniform.
 *
 * Accessibility: the dropzone wrapper is a generic <div> (no role,
 * no tabindex) so it never wraps interactive complete-state children
 * (downloads, <details>, chip row) and trips axe's nested-interactive
 * rule. The keyboard hook is the visually-hidden `<input type="file">`
 * the binder injects with `class="sr-only"` and an aria-label — Tab
 * focuses it, Enter/Space opens the native file picker, and the
 * dropzone's `:focus-within` CSS rule paints a visible focus ring
 * around the whole container. The handlers preventDefault() on drag
 * events so the browser doesn't navigate.
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
  /**
   * Optional sibling container that hosts the folder-pick affordance
   * (an element with `data-role="folder-pick"`). When provided,
   * `bindDropzone` listens for clicks on this element separately so
   * the folder-pick `<button>` does not have to live inside the
   * dropzone (which carries `role="button"`) and trigger axe's
   * `nested-interactive` rule. When omitted, the legacy in-dropzone
   * delegation still works for backwards-compatible unit tests.
   */
  folderPickContainer?: HTMLElement | null;
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
  // Visually hidden but keyboard-focusable. The dropzone wrapper has
  // no role/tabindex of its own; this input is the page's keyboard
  // entry point into the analysis flow. Tab focuses it (the parent
  // dropzone gets a `:focus-within` ring); Enter/Space opens the
  // native file picker. The aria-label is the accessible name.
  input.className = "sr-only";
  input.setAttribute("aria-label", "Drop a PDF or DOCX here, or click to choose");
  dz.appendChild(input);

  // Secondary input wired to the folder-picker affordance (spec-v4 §8
  // step 1, LAUNCH row v4-o). `webkitdirectory` is non-standard but
  // widely supported (Chromium 7+, Firefox 50+, Safari 14.1+). Browsers
  // that don't recognise the attribute fall through to the multi-file
  // input automatically. Each enumerated File carries `webkitRelativePath`
  // so the bundle pipeline can de-duplicate by basename if needed.
  const inputDir = document.createElement("input");
  inputDir.type = "file";
  inputDir.accept = ".pdf,.docx";
  inputDir.multiple = true;
  // Set both the property and the attribute so the e2e probe selector
  // `#dropzone input[type="file"][webkitdirectory]` matches.
  (inputDir as unknown as { webkitdirectory: boolean }).webkitdirectory = true;
  inputDir.setAttribute("webkitdirectory", "");
  // Out of Tab order — this input is JS-driven only (via the
  // folder-pick button); putting it in the tab order would create a
  // second focusable file-picker on the page with no visible label.
  inputDir.tabIndex = -1;
  inputDir.setAttribute("aria-hidden", "true");
  inputDir.style.display = "none";
  dz.appendChild(inputDir);

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
  const onPickFolder = (): void => {
    inputDir.value = "";
    inputDir.click();
  };
  const filesFromList = (list: FileList | null | undefined): File[] => {
    if (!list || list.length === 0) return [];
    const out: File[] = [];
    for (let i = 0; i < list.length; i++) out.push(list[i]!);
    return out;
  };
  const onInputChange = (): void => {
    dispatch(filesFromList(input.files));
  };
  const onInputDirChange = (): void => {
    // Folder picker may include arbitrary files (.DS_Store, README,
    // images). Filter to the PDF/DOCX subset before dispatch so the
    // pipeline doesn't have to second-guess the user. The pipeline's
    // `planBundle` would reject the rest anyway, but rejecting here
    // also keeps the file-count cap (50) measured against the
    // accepted set rather than the raw tree.
    const all = filesFromList(inputDir.files);
    const accepted = all.filter((f) => {
      const n = f.name.toLowerCase();
      return n.endsWith(".pdf") || n.endsWith(".docx");
    });
    dispatch(accepted);
  };
  const onClick = (e: Event): void => {
    if (e.target === input || e.target === inputDir) return;
    const target = e.target as HTMLElement | null;
    // Folder-pick affordance: an element annotated with
    // `data-role="folder-pick"` opens the directory picker. The match
    // happens before the generic interactive-child guard so the click
    // still routes to `onPickFolder` even though the element is a
    // <button> / <a>.
    if (target?.closest('[data-role="folder-pick"]')) {
      e.stopPropagation();
      onPickFolder();
      return;
    }
    // The dropzone hosts interactive children in the "complete" / "error"
    // states (download anchors, retry button, "why this playbook?"
    // disclosure). Clicks on those must NOT also re-open the file
    // picker — otherwise macOS shows its NSOpenPanel ("Open" button)
    // on top of the download flow and the file never gets saved.
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

    // Folder drag-drop path (spec-v4 §8 step 1). When any dropped
    // DataTransferItem resolves to a directory entry, walk the tree
    // via `webkitGetAsEntry()` and dispatch the enumerated File[]
    // through the same `onFiles` channel. If no directory entry is
    // present we use the cheaper `dataTransfer.files` path below.
    const items = e.dataTransfer?.items;
    const hasItemsApi =
      items && items.length > 0 && typeof (items[0] as DataTransferItem | undefined)
        ?.webkitGetAsEntry === "function";
    if (hasItemsApi) {
      const entries: FileSystemEntry[] = [];
      let anyDir = false;
      for (let i = 0; i < items!.length; i++) {
        const entry = items![i]!.webkitGetAsEntry?.();
        if (!entry) continue;
        if (entry.isDirectory) anyDir = true;
        entries.push(entry);
      }
      if (anyDir && entries.length > 0) {
        void collectFilesFromEntries(entries).then((files) => {
          const accepted = files.filter((f) => {
            const n = f.name.toLowerCase();
            return n.endsWith(".pdf") || n.endsWith(".docx");
          });
          dispatch(accepted);
        });
        return;
      }
    }

    dispatch(filesFromList(e.dataTransfer?.files));
  };

  // Folder-pick clicks on the external container (preferred path).
  const onExternalFolderClick = (e: Event): void => {
    const target = e.target as HTMLElement | null;
    if (target?.closest('[data-role="folder-pick"]')) {
      e.stopPropagation();
      onPickFolder();
    }
  };

  dz.addEventListener("click", onClick);
  dz.addEventListener("dragenter", onDragEnter as EventListener);
  dz.addEventListener("dragover", onDragOver as EventListener);
  dz.addEventListener("dragleave", onDragLeave as EventListener);
  dz.addEventListener("drop", onDrop as EventListener);
  input.addEventListener("change", onInputChange);
  inputDir.addEventListener("change", onInputDirChange);
  if (opts.folderPickContainer) {
    opts.folderPickContainer.addEventListener("click", onExternalFolderClick);
  }

  return () => {
    dz.removeEventListener("click", onClick);
    dz.removeEventListener("dragenter", onDragEnter as EventListener);
    dz.removeEventListener("dragover", onDragOver as EventListener);
    dz.removeEventListener("dragleave", onDragLeave as EventListener);
    dz.removeEventListener("drop", onDrop as EventListener);
    input.removeEventListener("change", onInputChange);
    inputDir.removeEventListener("change", onInputDirChange);
    if (opts.folderPickContainer) {
      opts.folderPickContainer.removeEventListener("click", onExternalFolderClick);
    }
    dz.removeChild(input);
    dz.removeChild(inputDir);
  };
}

/* -------------------------------------------------------------------------- */
/* Folder drag-drop helpers                                                   */
/* -------------------------------------------------------------------------- */

/**
 * Recursively enumerate every `File` reachable from a flat list of
 * `FileSystemEntry`s (the result of `DataTransferItem.webkitGetAsEntry()`).
 * Skips inaccessible entries silently — the drop UX should never throw
 * because one subdirectory wasn't readable.
 *
 * Exported for tests. Mirrors the candidate-shape walker in
 * `src/ingest/multi.ts` but returns `File[]` so the pipeline's
 * `expandBundleInputs` (which already understands `File[]`) handles
 * the rest.
 */
export async function collectFilesFromEntries(
  entries: ReadonlyArray<FileSystemEntry>,
): Promise<File[]> {
  const out: File[] = [];
  for (const entry of entries) {
    await walkEntry(entry, out);
  }
  return out;
}

async function walkEntry(entry: FileSystemEntry, out: File[]): Promise<void> {
  if (entry.isFile) {
    const fileEntry = entry as FileSystemFileEntry;
    try {
      const file = await new Promise<File>((resolve, reject) => {
        fileEntry.file(resolve, reject);
      });
      out.push(file);
    } catch {
      // Inaccessible / permission-denied entries are silently skipped.
    }
    return;
  }
  if (entry.isDirectory) {
    const dir = entry as FileSystemDirectoryEntry;
    const reader = dir.createReader();
    const children = await readAllDirectoryEntries(reader);
    for (const child of children) await walkEntry(child, out);
  }
}

function readAllDirectoryEntries(
  reader: FileSystemDirectoryReader,
): Promise<FileSystemEntry[]> {
  return new Promise((resolve, reject) => {
    const acc: FileSystemEntry[] = [];
    const next = (): void => {
      reader.readEntries((batch) => {
        if (batch.length === 0) {
          resolve(acc);
          return;
        }
        for (const e of batch) acc.push(e);
        next();
      }, reject);
    };
    next();
  });
}
