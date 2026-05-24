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
      /**
       * v3 family detection (spec-v3 §60). When `family === "unknown"`
       * or the field is omitted, no chip is rendered. Otherwise a
       * read-only "Detected: X" pill appears under the playbook name.
       */
      v3_family?: {
        family: string;
        label: string;
        confidence: number;
      };
      /**
       * v3 compliance-frame chip row (spec-v3 §61, LAUNCH row v3-o).
       * When omitted, the chip row is not rendered. `frames_on` is the
       * initial toggle state; the renderer wires `role="switch"` +
       * `aria-checked` + Space/Enter handlers so the chips are
       * keyboard-operable (matches `tests/e2e/v3/a11y-keyboard.spec.ts`
       * probe).
       */
      v3_frames?: {
        available: ReadonlyArray<string>;
        on: ReadonlyArray<string>;
        hint?: string;
      };
      /**
       * Invoked with the full current set of active frames whenever
       * the user toggles a chip. The main UI uses this to re-run the
       * engine against the cached `PreparedDocument` with the new
       * frame set (spec-v3 §61). When omitted, toggling is purely
       * presentational — useful for unit tests.
       */
      on_frames_change?: (active_frames: ReadonlyArray<string>) => void;
    }
  | {
      kind: "bundle-complete";
      document_count: number;
      counts: { critical: number; warning: number; info: number };
      cross_doc_findings: number;
      bundle_docx_blob: Blob;
      bundle_json_blob: Blob;
      bundle_docx_filename: string;
      bundle_json_filename: string;
      /**
       * Per-doc v3 family labels (spec-v3 §60, LAUNCH row v3-o bundle
       * side). Optional; only documents whose family is non-"unknown"
       * are typically included. Rendered as a "Detected: X, Y" line
       * under the cross-doc summary.
       */
      detected_families?: ReadonlyArray<string>;
    }
  | { kind: "error"; message: string };

const TEMPLATES: Record<DropzoneState["kind"], string> = {
  empty: `
    <span class="icon" aria-hidden="true">
      <svg viewBox="0 0 24 24"><path d="M12 3v12"></path><path d="m7 8 5-5 5 5"></path><path d="M5 21h14"></path></svg>
    </span>
    <div class="dropzone-title">Drop a PDF or DOCX here, or click to choose</div>
    <div class="dropzone-sub">analysis runs locally · nothing is uploaded</div>
    <div class="dropzone-sub dropzone-sub--secondary">
      Multiple files? Drop a folder or
      <button type="button" class="btn-link" data-role="folder-pick">choose a folder…</button>
    </div>
  `,
  analyzing: `
    <div class="dropzone-title" data-role="analyzing-filename"></div>
    <div class="dropzone-sub" data-role="analyzing-dkb"></div>
    <div class="progress" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0" data-role="progress"></div>
    <div class="rule-ticker" data-role="ticker"></div>
  `,
  complete: `
    <div class="dropzone-title" data-role="complete-filename"></div>
    <div class="v3-family-chip" data-role="v3-family" hidden></div>
    <div class="counts" data-role="counts"></div>
    <div class="compliance-frame-chips" data-role="compliance-frame-chips" role="group" aria-label="Compliance frames" hidden></div>
    <div class="dropzone-sub compliance-frame-hint" data-role="compliance-frame-hint" hidden></div>
    <details class="playbook-disclosure">
      <summary>Why this playbook?</summary>
      <div data-role="reasoning"></div>
    </details>
    <button class="btn btn-primary" type="button" data-role="docx-download">Download report (Word)</button>
    <button class="btn-link" type="button" data-role="json-download">Download structured data (JSON)</button>
    <div class="download-status" data-role="download-status" aria-live="polite"></div>
  `,
  "bundle-complete": `
    <div class="dropzone-title" data-role="bundle-title"></div>
    <div class="counts" data-role="counts"></div>
    <div class="dropzone-sub" data-role="cross-doc-summary"></div>
    <div class="dropzone-sub bundle-detected-families" data-role="bundle-detected-families" hidden></div>
    <button class="btn btn-primary" type="button" data-role="bundle-download">Download consolidated report (Word)</button>
    <button class="btn-link" type="button" data-role="bundle-json-download">Download bundle data (JSON)</button>
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
    renderV3FamilyChip(dz, state.v3_family);
    renderComplianceFrameChips(dz, state.v3_frames, state.on_frames_change);
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
  if (state.kind === "bundle-complete") {
    select(dz, "bundle-title")!.textContent =
      `${state.document_count} documents analyzed`;
    select(dz, "counts")!.innerHTML = countsHtml(state.counts);
    select(dz, "cross-doc-summary")!.textContent =
      state.cross_doc_findings === 0
        ? "No cross-document inconsistencies found."
        : `${state.cross_doc_findings} cross-document finding${state.cross_doc_findings === 1 ? "" : "s"}.`;
    const detectedEl = select<HTMLElement>(dz, "bundle-detected-families")!;
    if (state.detected_families && state.detected_families.length > 0) {
      detectedEl.hidden = false;
      detectedEl.textContent = `Detected: ${state.detected_families.join(", ")}`;
    } else {
      detectedEl.hidden = true;
      detectedEl.textContent = "";
    }
    const docxBtn = select<HTMLButtonElement>(dz, "bundle-download")!;
    const jsonBtn = select<HTMLButtonElement>(dz, "bundle-json-download")!;
    const status = select<HTMLElement>(dz, "download-status")!;
    docxBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      void saveBlob(state.bundle_docx_blob, state.bundle_docx_filename, status);
    });
    jsonBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      void saveBlob(state.bundle_json_blob, state.bundle_json_filename, status);
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

/* -------------------------------------------------------------------------- */
/* v3 detection + compliance-frame chip-row renderers (spec-v3 §§60–61)       */
/* -------------------------------------------------------------------------- */

function renderV3FamilyChip(
  dz: HTMLElement,
  detection: { family: string; label: string; confidence: number } | undefined,
): void {
  const chip = select<HTMLElement>(dz, "v3-family");
  if (!chip) return;
  if (!detection || detection.family === "unknown") {
    chip.hidden = true;
    chip.textContent = "";
    return;
  }
  chip.hidden = false;
  const pct = Math.round(detection.confidence * 100);
  chip.setAttribute("data-confidence", String(pct));
  chip.textContent = `Detected: ${detection.label}`;
}

function renderComplianceFrameChips(
  dz: HTMLElement,
  frames:
    | { available: ReadonlyArray<string>; on: ReadonlyArray<string>; hint?: string }
    | undefined,
  onChange?: (active: ReadonlyArray<string>) => void,
): void {
  const row = select<HTMLElement>(dz, "compliance-frame-chips");
  const hintEl = select<HTMLElement>(dz, "compliance-frame-hint");
  if (!row || !hintEl) return;
  if (!frames || frames.available.length === 0) {
    row.hidden = true;
    row.innerHTML = "";
    hintEl.hidden = true;
    hintEl.textContent = "";
    return;
  }

  row.hidden = false;
  row.innerHTML = "";
  // The active set is shared across all chip handlers so each toggle
  // can notify the parent with the *current* union, not just the
  // chip that fired.
  const active = new Set(frames.on);
  for (const frame of frames.available) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "compliance-chip";
    btn.setAttribute("role", "switch");
    btn.setAttribute("data-frame", frame);
    const checked = active.has(frame);
    btn.setAttribute("aria-checked", checked ? "true" : "false");
    btn.tabIndex = 0;
    btn.textContent = frame;
    const toggle = (e: Event): void => {
      e.stopPropagation();
      const cur = btn.getAttribute("aria-checked") === "true";
      btn.setAttribute("aria-checked", cur ? "false" : "true");
      if (cur) active.delete(frame);
      else active.add(frame);
      onChange?.([...active]);
    };
    btn.addEventListener("click", toggle);
    btn.addEventListener("keydown", (e) => {
      if (e.key === " " || e.key === "Enter") {
        e.preventDefault();
        toggle(e);
      }
    });
    row.appendChild(btn);
  }

  if (frames.hint) {
    hintEl.hidden = false;
    hintEl.textContent = frames.hint;
  } else {
    hintEl.hidden = true;
    hintEl.textContent = "";
  }
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
