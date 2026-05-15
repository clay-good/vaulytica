/**
 * Multi-document drop-zone state model (spec-v3.md §62).
 *
 * The v2 drop zone accepts one file at a time and walks through
 * `empty → analyzing → complete | error`. v3 accepts up to four files in a
 * single drop, renders a card per document, and offers cross-document
 * consistency as a default-on checkbox.
 *
 * This module is the pure state model that the v3 UI extension will
 * render against. The actual DOM rendering and the wiring to the
 * pipeline live in `src/ui/v3/main-multi.ts` (forthcoming UI hookup).
 *
 * The model is independent of the analysis pipeline: it exposes
 * `addDocument`, `markAnalyzing`, `markComplete`, `markError`,
 * `removeDocument`, and `setConsistencyEnabled` — each returns a new
 * state, never mutates. Keeping the reducer pure makes the UI testable
 * without spinning up a browser.
 */

export const MAX_DOCUMENTS = 4;

export type DocumentCard =
  | { id: string; filename: string; kind: "pdf" | "docx"; status: "queued" }
  | {
      id: string;
      filename: string;
      kind: "pdf" | "docx";
      status: "analyzing";
      progress: number;
      dkb_version?: string;
    }
  | {
      id: string;
      filename: string;
      kind: "pdf" | "docx";
      status: "complete";
      playbook_id: string;
      playbook_name: string;
      result_hash: string;
      counts: { critical: number; warning: number; info: number };
    }
  | { id: string; filename: string; kind: "pdf" | "docx"; status: "error"; message: string };

export type MultiDocState = {
  documents: DocumentCard[];
  /** User toggle; defaults to true when ≥2 docs are queued/complete. */
  consistency_enabled: boolean;
  /**
   * Set after the consistency engine has run. The UI uses this to render
   * the consistency findings count next to the chip row.
   */
  consistency_findings_count?: number;
};

export const EMPTY_MULTI_DOC_STATE: MultiDocState = {
  documents: [],
  consistency_enabled: true,
};

export type AddDocumentResult =
  | { ok: true; state: MultiDocState }
  | { ok: false; state: MultiDocState; reason: string };

export function addDocument(
  state: MultiDocState,
  doc: { id: string; filename: string; kind: "pdf" | "docx" },
): AddDocumentResult {
  if (state.documents.length >= MAX_DOCUMENTS) {
    return {
      ok: false,
      state,
      reason: `Vaulytica accepts up to ${MAX_DOCUMENTS} files in a single drop. Remove one to add another.`,
    };
  }
  if (state.documents.some((d) => d.id === doc.id)) {
    return { ok: false, state, reason: `${doc.filename} is already in the bundle.` };
  }
  const next: MultiDocState = {
    ...state,
    documents: [...state.documents, { ...doc, status: "queued" }],
  };
  return { ok: true, state: next };
}

export function removeDocument(state: MultiDocState, id: string): MultiDocState {
  const documents = state.documents.filter((d) => d.id !== id);
  return { ...state, documents };
}

export function markAnalyzing(
  state: MultiDocState,
  id: string,
  progress: number,
  dkb_version?: string,
): MultiDocState {
  return mapDocument(state, id, (d) => ({
    id: d.id,
    filename: d.filename,
    kind: d.kind,
    status: "analyzing" as const,
    progress: clamp01(progress),
    dkb_version,
  }));
}

export function markComplete(
  state: MultiDocState,
  id: string,
  result: {
    playbook_id: string;
    playbook_name: string;
    result_hash: string;
    counts: { critical: number; warning: number; info: number };
  },
): MultiDocState {
  return mapDocument(state, id, (d) => ({
    id: d.id,
    filename: d.filename,
    kind: d.kind,
    status: "complete" as const,
    ...result,
  }));
}

export function markError(state: MultiDocState, id: string, message: string): MultiDocState {
  return mapDocument(state, id, (d) => ({
    id: d.id,
    filename: d.filename,
    kind: d.kind,
    status: "error" as const,
    message,
  }));
}

export function setConsistencyEnabled(state: MultiDocState, enabled: boolean): MultiDocState {
  return { ...state, consistency_enabled: enabled };
}

export function setConsistencyFindingsCount(state: MultiDocState, n: number): MultiDocState {
  return { ...state, consistency_findings_count: n };
}

/** True when every document is `complete` or `error`. */
export function isReadyForConsistency(state: MultiDocState): boolean {
  if (state.documents.length < 2) return false;
  return state.documents.every((d) => d.status === "complete" || d.status === "error");
}

/** True when at least two documents have completed successfully. */
export function hasUsableConsistencyBundle(state: MultiDocState): boolean {
  const completed = state.documents.filter((d) => d.status === "complete");
  return completed.length >= 2;
}

function mapDocument(
  state: MultiDocState,
  id: string,
  fn: (d: DocumentCard) => DocumentCard,
): MultiDocState {
  return {
    ...state,
    documents: state.documents.map((d) => (d.id === id ? fn(d) : d)),
  };
}

function clamp01(n: number): number {
  if (!Number.isFinite(n)) return 0;
  if (n < 0) return 0;
  if (n > 1) return 1;
  return n;
}
