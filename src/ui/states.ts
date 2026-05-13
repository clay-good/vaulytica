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

/**
 * Programmatic, browser-agnostic "Save As" for a Blob.
 *
 * Why not `<a href="blob:..." download>`? On macOS Chrome + Cloudflare
 * Pages we hit two failure modes with the bare anchor:
 *
 *   1. The dropzone's own click handler intercepted the bubbling click
 *      and re-opened the file picker (NSOpenPanel) — user saw an
 *      "Open" dialog instead of a save flow. Fixed in `dropzone.ts`
 *      by ignoring clicks on interactive children.
 *
 *   2. The previous implementation revoked the blob URL one render
 *      tick after creation, so Chrome's download manager streamed a
 *      partial blob, stalled at ~50–60% in the toolbar's circular
 *      progress indicator, and never showed up in chrome://downloads.
 *
 * The synthetic-anchor approach below is the canonical
 * cross-browser pattern: create the URL fresh, append a hidden
 * anchor, click it inside the user's gesture, remove it, and
 * `revokeObjectURL` after a generous delay so the download manager
 * has finished reading the bytes. Status is surfaced in the live
 * region so users see "Saved X.docx" right where they clicked.
 */
async function saveBlob(blob: Blob, filename: string, statusEl: HTMLElement): Promise<void> {
  statusEl.textContent = `Saving ${filename}…`;
  try {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.rel = "noopener";
    a.style.display = "none";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    // Give the browser's download manager time to start streaming
    // before we revoke the URL. 60 seconds is more than enough even
    // for very large reports; revoking too early was the cause of the
    // stuck-at-60% Chrome toolbar bug.
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
    statusEl.textContent = `Saved ${filename}`;
  } catch (err) {
    statusEl.textContent = `Could not save: ${err instanceof Error ? err.message : String(err)}`;
  }
}
