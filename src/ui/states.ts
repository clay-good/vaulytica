/**
 * Drop-zone state machine (spec §23). The same DOM element transforms
 * in place through three states. CSS keys off `data-state` to swap
 * the inner content stack.
 */

export type DropzoneState =
  | { kind: "empty" }
  | { kind: "analyzing"; filename: string; dkb_version?: string }
  | {
      kind: "complete";
      filename: string;
      playbook_name: string;
      match_reasoning?: string;
      counts: { critical: number; warning: number; info: number };
      docx_blob: Blob;
      json_blob: Blob;
      /** Pre-formatted filenames for the two downloads. */
      docx_filename: string;
      json_filename: string;
    }
  | { kind: "error"; message: string };

const TEMPLATES: Record<DropzoneState["kind"], string> = {
  empty: `
    <span class="icon" aria-hidden="true">
      <svg viewBox="0 0 24 24"><path d="M12 3v12"></path><path d="m7 8 5-5 5 5"></path><path d="M5 21h14"></path></svg>
    </span>
    <div class="dropzone-title">Drop a PDF or DOCX here, or click to choose</div>
    <div class="dropzone-sub">analysis runs locally · nothing is uploaded</div>
  `,
  analyzing: `
    <div class="dropzone-title" data-role="analyzing-filename"></div>
    <div class="dropzone-sub" data-role="analyzing-dkb"></div>
    <div class="progress" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0" data-role="progress"></div>
    <div class="rule-ticker" data-role="ticker"></div>
  `,
  complete: `
    <div class="dropzone-title" data-role="complete-filename"></div>
    <div class="counts" data-role="counts"></div>
    <details class="playbook-disclosure">
      <summary>Why this playbook?</summary>
      <div data-role="reasoning"></div>
    </details>
    <button class="btn btn-primary" type="button" data-role="docx-download">Download report (Word)</button>
    <button class="btn-link" type="button" data-role="json-download">Download structured data (JSON)</button>
    <div class="download-status" data-role="download-status" aria-live="polite"></div>
  `,
  error: `
    <div class="dropzone-title" data-role="error-title">Something went wrong</div>
    <div class="dropzone-sub" data-role="error-message"></div>
    <button class="btn-link" type="button" data-role="error-reset">Try another file</button>
  `,
};

export function renderState(dz: HTMLElement, state: DropzoneState): void {
  dz.setAttribute("data-state", state.kind);
  dz.innerHTML = TEMPLATES[state.kind];

  if (state.kind === "analyzing") {
    select(dz, "analyzing-filename")!.textContent = state.filename;
    select(dz, "analyzing-dkb")!.textContent = state.dkb_version
      ? `DKB ${state.dkb_version}`
      : "loading…";
  }
  if (state.kind === "complete") {
    select(dz, "complete-filename")!.textContent = state.filename;
    select(dz, "counts")!.innerHTML = countsHtml(state.counts);
    select(dz, "reasoning")!.textContent =
      state.match_reasoning ?? `Auto-selected ${state.playbook_name}.`;
    const docxBtn = select<HTMLButtonElement>(dz, "docx-download")!;
    const jsonBtn = select<HTMLButtonElement>(dz, "json-download")!;
    const status = select<HTMLElement>(dz, "download-status")!;
    docxBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      void saveBlob(state.docx_blob, state.docx_filename, status);
    });
    jsonBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      void saveBlob(state.json_blob, state.json_filename, status);
    });
  }
  if (state.kind === "error") {
    select(dz, "error-message")!.textContent = state.message;
  }
}

export function select<T extends HTMLElement = HTMLElement>(
  root: HTMLElement,
  role: string,
): T | null {
  return root.querySelector<T>(`[data-role="${role}"]`);
}

function countsHtml(counts: { critical: number; warning: number; info: number }): string {
  return `
    <span class="count count--critical"><strong>${counts.critical}</strong> critical</span>
    <span class="count count--warning"><strong>${counts.warning}</strong> warnings</span>
    <span class="count count--info"><strong>${counts.info}</strong> informational</span>
  `;
}

export function baseName(filename: string): string {
  const i = filename.lastIndexOf(".");
  return i > 0 ? filename.slice(0, i) : filename;
}

const DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
const JSON_MIME = "application/json";

type FsaWritable = {
  write: (data: BlobPart) => Promise<void>;
  close: () => Promise<void>;
};
type FsaHandle = { createWritable: () => Promise<FsaWritable> };
type FsaWindow = Window & {
  showSaveFilePicker?: (options: {
    suggestedName?: string;
    types?: Array<{ description?: string; accept: Record<string, string[]> }>;
  }) => Promise<FsaHandle>;
};

/**
 * Reliable, user-confirmable "Save As" for a Blob.
 *
 * Two paths, in order of preference:
 *
 * 1. **File System Access API** (`showSaveFilePicker`). Available on
 *    Chrome / Edge / Opera desktop. Pops up the native macOS save
 *    panel with the proper "Save" button — the user sees exactly
 *    where the file lands and can rename it. We only flip status to
 *    "Saved X" *after* the writable stream's `close()` resolves,
 *    so the message reflects an actual on-disk write, not just an
 *    intent.
 *
 * 2. **Synthetic anchor fallback**. Used by Safari, Firefox, and any
 *    browser without FSA. Creates a hidden `<a download>` over a
 *    fresh `URL.createObjectURL(blob)`, clicks it inside the user
 *    gesture, removes it, and revokes the URL 60s later so Chrome's
 *    download manager has time to read every byte (revoking earlier
 *    was the cause of the "stuck at 60% in toolbar with nothing in
 *    chrome://downloads" bug). Status here is "Download started —
 *    check your Downloads folder" because the page can't see whether
 *    the OS actually persisted the file.
 *
 * Empty / zero-byte blobs are caught up front so a silent pipeline
 * bug surfaces as a visible error message instead of a phantom save.
 */
export async function saveBlob(
  blob: Blob,
  filename: string,
  statusEl: HTMLElement,
): Promise<void> {
  if (!blob || blob.size === 0) {
    statusEl.textContent = `Could not save ${filename}: the report blob is empty.`;
    return;
  }

  const ext = filename.toLowerCase().endsWith(".docx") ? "docx" : "json";
  // Defensively re-wrap if the upstream blob lost its MIME type. macOS
  // associates files by MIME, and a blob of type "" lands as an
  // unrecognized binary in some browsers.
  const typedBlob =
    blob.type === "" ? new Blob([blob], { type: ext === "docx" ? DOCX_MIME : JSON_MIME }) : blob;

  const fsa = (window as FsaWindow).showSaveFilePicker;
  if (typeof fsa === "function") {
    statusEl.textContent = `Saving ${filename}…`;
    try {
      const accept: Record<string, string[]> =
        ext === "docx" ? { [DOCX_MIME]: [".docx"] } : { [JSON_MIME]: [".json"] };
      const description = ext === "docx" ? "Word document" : "JSON";
      const handle = await fsa.call(window, {
        suggestedName: filename,
        types: [{ description, accept }],
      });
      const writable = await handle.createWritable();
      await writable.write(typedBlob);
      await writable.close();
      statusEl.textContent = `Saved ${filename}`;
      return;
    } catch (err) {
      const e = err as { name?: string; message?: string };
      if (e.name === "AbortError") {
        statusEl.textContent = "Save canceled.";
        return;
      }
      // Permission denied, NotAllowedError, etc. — fall through to anchor.
      statusEl.textContent = `Falling back to direct download (${e.message ?? "fsa unavailable"})…`;
    }
  }

  try {
    const url = URL.createObjectURL(typedBlob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.rel = "noopener";
    a.style.display = "none";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
    statusEl.textContent = `Download started: ${filename}. Check your Downloads folder.`;
  } catch (err) {
    statusEl.textContent = `Could not save: ${err instanceof Error ? err.message : String(err)}`;
  }
}
