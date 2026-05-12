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
      docx_url: string;
      json_url: string;
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
    <a class="btn btn-primary" data-role="docx-download" download>Download report (Word)</a>
    <a class="btn-link" data-role="json-download" download>Download structured data (JSON)</a>
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
    const docx = select<HTMLAnchorElement>(dz, "docx-download")!;
    docx.href = state.docx_url;
    docx.setAttribute("download", `${baseName(state.filename)}-vaulytica.docx`);
    const json = select<HTMLAnchorElement>(dz, "json-download")!;
    json.href = state.json_url;
    json.setAttribute("download", `${baseName(state.filename)}-vaulytica.json`);
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

function baseName(filename: string): string {
  const i = filename.lastIndexOf(".");
  return i > 0 ? filename.slice(0, i) : filename;
}
