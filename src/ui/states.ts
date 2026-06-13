/**
 * Drop-zone state machine (spec §23). The same DOM element transforms
 * in place through three states. CSS keys off `data-state` to swap
 * the inner content stack.
 */
import { EMPTY_STATE_COPY, v3ErrorMessage } from "./v3/copy.js";

export type DropzoneState =
  | { kind: "empty" }
  | { kind: "analyzing"; filename: string; dkb_version?: string }
  | {
      kind: "complete";
      filename: string;
      playbook_name: string;
      /**
       * When the matched playbook carries `deprecated: true` in its
       * JSON, the complete-state reasoning line is annotated with a
       * "Legacy playbook" hint and (when present) the id of the
       * playbook that supersedes it. Optional / back-compat: omitting
       * preserves the prior reasoning-line output.
       */
      playbook_deprecation?: { superseded_by?: string };
      match_reasoning?: string;
      counts: { critical: number; warning: number; info: number };
      docx_blob: Blob;
      json_blob: Blob;
      /** Pre-formatted filenames for the two downloads. */
      docx_filename: string;
      json_filename: string;
      /**
       * v6 Part III findings-to-action exports (Steps 87–88) + v8 Thrust C
       * reach formats (Steps 141–142). When present, the complete-state
       * renders an "Export" row beneath the primary downloads: fix-list
       * (Markdown), fix-list (CSV), obligations (CSV), a deadlines `.ics`,
       * the machine-readable SARIF, and a standalone HTML report. Optional /
       * back-compat: omitting it hides the export row entirely, so existing
       * call sites and tests that don't supply exports are unaffected.
       */
      exports?: {
        fixlist_md_blob: Blob;
        fixlist_csv_blob: Blob;
        obligations_csv_blob: Blob;
        deadlines_ics_blob: Blob;
        sarif_blob: Blob;
        html_blob: Blob;
        fixlist_md_filename: string;
        fixlist_csv_filename: string;
        obligations_csv_filename: string;
        deadlines_ics_filename: string;
        sarif_filename: string;
        html_filename: string;
        /** spec-v9 Thrust C — critical-dates calendar / register, present only when non-empty. */
        critical_dates_ics_blob?: Blob;
        critical_dates_md_blob?: Blob;
        critical_dates_ics_filename?: string;
        critical_dates_md_filename?: string;
        /** spec-v9 Thrust B — closing checklist, present only when there is a readiness item. */
        closing_checklist_md_blob?: Blob;
        closing_checklist_csv_blob?: Blob;
        closing_checklist_md_filename?: string;
        closing_checklist_csv_filename?: string;
        /** spec-v10 Thrust B — negotiation posture export + sheet, present only with positions. */
        negotiation_posture_md_blob?: Blob;
        negotiation_posture_csv_blob?: Blob;
        negotiation_sheet_blob?: Blob;
        negotiation_posture_md_filename?: string;
        negotiation_posture_csv_filename?: string;
        negotiation_sheet_filename?: string;
      };
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
      /**
       * v6 Part I version comparison (Step 90). When provided, the
       * complete-state renders a "Compare a revised version…" affordance:
       * a button that opens a file picker and invokes this callback with
       * the chosen second document. The main UI runs the engine on it and
       * transitions to the `comparison-complete` state. Optional /
       * back-compat: omitting it hides the compare row.
       */
      on_compare?: (file: File) => void;
      /**
       * v6 Part II bring-your-own-playbook provenance (Step 92). Present only
       * when a user-supplied playbook drove this run. Renders a line under the
       * counts distinguishing "your standard flagged this" from the built-in
       * catalog, plus how many of the team's rules could not be evaluated on
       * this document. Optional / back-compat: omitting hides the line.
       */
      custom_playbook?: {
        name: string;
        mode: "augment" | "replace";
        custom_finding_count: number;
        unevaluable_count: number;
      };
      /**
       * Multi-family activation (spec-v6). Additional families the document
       * also clearly contains, each scanned with its own rule set. Rendered
       * as a labeled "Additional checks from other detected families" block
       * under the counts; the full findings live in the downloadable report.
       * Optional / back-compat: omitting hides the block.
       */
      secondary_families?: ReadonlyArray<{
        playbook_id: string;
        playbook_name: string;
        counts: { critical: number; warning: number; info: number };
      }>;
      /**
       * Jurisdiction overlays (spec-v6 Part VI §21, Step 101). State-law
       * deltas for the governing-law state(s) this document names, for the
       * families where state law dominates (employment non-compete, lending
       * usury). Rendered as a labeled, citable reference block under the
       * counts — never findings, so the result hash is unchanged.
       * `uncovered_states` keeps coverage honest. Optional / back-compat:
       * omitting hides the block.
       */
      jurisdiction_overlays?: {
        family: string;
        states_in_catalog: number;
        matched: ReadonlyArray<{
          state_name: string;
          posture: "prohibited" | "restricted" | "permitted" | "informational";
          topic: string;
          headline: string;
          summary: string;
          recommendation: string;
          citation: { source: string; source_url: string };
        }>;
        uncovered_states: ReadonlyArray<string>;
      };
      /**
       * Pre-disclosure / "Clean to Send" scan (spec-v9 Thrust A). Surfaced as
       * a prominent block above the findings counts: tracked changes, comments,
       * hidden content, authoring metadata, and sensitive-data patterns
       * recovered from the ORIGINAL container bytes. Presence-only — never a
       * clean bill of health. Optional / back-compat: omitting hides the block.
       */
      delivery?: {
        inspectable: boolean;
        note?: string;
        summary: string;
        findings: ReadonlyArray<{
          rule_id: string;
          severity: "critical" | "warning" | "info";
          title: string;
          description: string;
          count: number;
          evidence: ReadonlyArray<string>;
        }>;
      };
      /**
       * Critical-dates register (spec-v9 Thrust C). The deadlines the
       * document's own terms compute to — auto-renewal notice, cure window,
       * opt-out window, survival end, notice period — as absolute dates. Only
       * the absolute date is shown; never a relative-to-today value (§3
       * corollary 4). Optional / back-compat: omitting hides the block.
       */
      critical_dates?: {
        resolved_count: number;
        unresolved_count: number;
        rows: ReadonlyArray<{
          rule_id: string;
          kind: string;
          resolved: boolean;
          computed_date: string | null;
          window?: readonly [string, string];
          trigger: string;
          anchor: string;
          responsible: string;
          section?: string;
          reason?: string;
        }>;
      };
      /**
       * Closing checklist (spec-v9 Thrust B). Consolidated execution-readiness
       * items projected from the run's findings + the delivery handoff items.
       * Presence-only — an empty list is hidden; it never certifies "ready to
       * sign." Optional / back-compat: omitting hides the block.
       */
      closing_checklist?: {
        open_count: number;
        items: ReadonlyArray<{
          category: string;
          rule_id: string;
          label: string;
          section?: string;
        }>;
      };
      /**
       * Negotiation posture (spec-v10 Thrust A). Present only when a custom
       * playbook with `negotiation_positions` ran: which rung of the team's
       * ideal/acceptable ladder the draft meets on each dimension. Advisory —
       * never a legal conclusion. Optional / back-compat: omitting hides it.
       */
      negotiation_posture?: {
        counts: { ideal: number; acceptable: number; below_acceptable: number; unevaluable: number };
        positions: ReadonlyArray<{
          dimension: string;
          tier: "ideal" | "acceptable" | "below-acceptable" | "unevaluable";
          guidance?: string;
          detail?: string;
          reason?: string;
          section_id?: string;
        }>;
      };
    }
  | {
      kind: "comparison-complete";
      base_filename: string;
      revised_filename: string;
      /** Plain-language headline verdict (net improvement / regression / …). */
      verdict: string;
      counts: {
        resolved: { critical: number; warning: number; info: number; total: number };
        introduced: { critical: number; warning: number; info: number; total: number };
        unchanged: { critical: number; warning: number; info: number; total: number };
        carried_clean_count: number;
      };
      /** True when the two runs used different DKB versions (flagged, not blocked). */
      dkb_mismatch: boolean;
      /**
       * Clause-level redline summary (spec-v8 Part XVIII). Present when the two
       * documents were diffed; renders a one-line "N changed · M added · K
       * removed" under the counts. The full redline is in the DOCX/JSON exports.
       * Optional / back-compat: omitting it hides the line.
       */
      clause_diff?: {
        added: number;
        removed: number;
        changed: number;
        truncated: boolean;
      };
      docx_blob: Blob;
      json_blob: Blob;
      docx_filename: string;
      json_filename: string;
      /** Start over (return to the empty drop zone). */
      on_reset?: () => void;
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
       * Bundle "everything" archive (spec-v8 §25). When present, the
       * bundle-complete state offers a "Download everything (.zip)" link —
       * the consolidated DOCX + bundle JSON + per-document fix-list / CSV /
       * `.ics` / JSON in one archive. Optional / back-compat: omitting it
       * hides the link, so existing call sites and tests are unaffected.
       */
      bundle_zip_blob?: Blob;
      bundle_zip_filename?: string;
      /**
       * Per-doc v3 family labels (spec-v3 §60, LAUNCH row v3-o bundle
       * side). Optional; only documents whose family is non-"unknown"
       * are typically included. Rendered as a "Detected: X, Y" line
       * under the cross-doc summary.
       */
      detected_families?: ReadonlyArray<string>;
      /**
       * Per-document summary cards (spec-v3 §62: "the UI shows a small
       * card per document with detected type and selected playbook").
       * When provided, the bundle-complete state renders an `<ul>` of
       * `<li>` cards under the counts row, each surfacing filename +
       * family label + playbook name + per-doc finding totals.
       *
       * Each card also exposes two download buttons — `docx_blob` /
       * `json_blob` — so users can grab a single document's report
       * without re-running the analysis. The bundle-level Download
       * Consolidated Report (Word) remains the primary affordance;
       * per-doc downloads are the secondary, "drill in" path.
       */
      documents?: ReadonlyArray<{
        filename: string;
        family_label?: string;
        /**
         * Optional `detectV3Family` confidence in `[0, 1]`. When
         * present, the card meta line appends "(0.83)" next to the
         * family label and renders the entry with a `.low-confidence`
         * class when the score is below 0.5 so ambiguous detections
         * are visually distinct from confident ones (spec-v3 §60
         * "below 0.4 the suggestion should be presented faintly").
         */
        detection_confidence?: number;
        playbook_name: string;
        /**
         * When the matched playbook is deprecated, the card's playbook
         * label is suffixed with " (legacy)" so a reader scanning the
         * bundle-complete page can spot a legacy match without opening
         * the per-doc Word report. Optional / back-compat: omitting
         * preserves prior card output.
         */
        playbook_deprecated?: boolean;
        counts: { critical: number; warning: number; info: number };
        /**
         * Multi-family activation (spec-v6). Additional families this bundled
         * document also clearly contains beyond its primary match — the same
         * families a composite document gets when dropped alone. Rendered as a
         * compact "Also checked" line on the card; full findings live in the
         * per-doc download. Optional / back-compat: omitting hides the line.
         */
        secondary_families?: ReadonlyArray<{
          playbook_name: string;
          counts: { critical: number; warning: number; info: number };
        }>;
        docx_blob: Blob;
        json_blob: Blob;
        docx_filename: string;
        json_filename: string;
      }>;
      /**
       * Cross-document consistency toggle (spec-v3 §62). When set,
       * a checkbox is rendered above the cross-doc summary. The default
       * checked state is `true` (consistency on, as required by §62).
       * When the user toggles the checkbox the renderer (a) mirrors the
       * new state into the cross-doc summary line — switching it to
       * "Cross-document consistency disabled." when off, restoring the
       * count/zero message when on — and (b) invokes `on_consistency_toggle`
       * so the caller can rebuild the bundle DOCX/JSON without the
       * cross-doc appendix. Omitting both fields skips the toggle
       * (back-compat with existing call sites).
       */
      cross_doc_active?: boolean;
      on_consistency_toggle?: (active: boolean) => void;
      /**
       * Files in the dropped bundle that the planner refused to ingest
       * (unsupported extension, oversized, etc.). When non-empty, the
       * bundle-complete state renders a small "Skipped" list under the
       * counts row so the user understands why their file count went
       * down. Each entry is `{ filename, reason }`; the reason comes
       * straight from `planBundle` / `rejectionForFilename` so the
       * user-facing string is already polished.
       */
      rejected?: ReadonlyArray<{ filename: string; reason: string }>;
    }
  | {
      kind: "error";
      message: string;
      /**
       * Optional v3 error code (spec-v3 §63). When provided, the renderer
       * looks up a structured title + detail via `v3ErrorMessage`; the
       * `message` field is used as a fallback / unknown-code passthrough.
       */
      code?: string;
      /**
       * Optional secondary action button. Used by the version-comparison
       * flow (Step 90) to offer "Compare anyway" when a cross-family
       * pairing is refused — the message explains the refusal, the action
       * lets the user confirm the pairing.
       */
      action?: { label: string; on_click: () => void };
    };

const TEMPLATES: Record<DropzoneState["kind"], string> = {
  empty: `
    <span class="icon" aria-hidden="true">
      <svg viewBox="0 0 24 24"><path d="M12 3v12"></path><path d="m7 8 5-5 5 5"></path><path d="M5 21h14"></path></svg>
    </span>
    <div class="dropzone-title" id="dropzone-title" data-role="empty-headline">${EMPTY_STATE_COPY.headline}</div>
    <div class="dropzone-sub" id="dropzone-sub" data-role="empty-sub">${EMPTY_STATE_COPY.sub}</div>
  `,
  analyzing: `
    <div class="dropzone-title" data-role="analyzing-filename"></div>
    <div class="dropzone-sub" data-role="analyzing-dkb"></div>
    <div class="progress" role="progressbar" aria-label="Analysis progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0" data-role="progress"></div>
    <div class="rule-ticker" data-role="ticker"></div>
  `,
  complete: `
    <div class="dropzone-title" data-role="complete-filename"></div>
    <div class="v3-family-chip" data-role="v3-family" hidden></div>
    <div class="delivery-section" data-role="delivery" hidden></div>
    <div class="closing-checklist-section" data-role="closing-checklist" hidden></div>
    <div class="critical-dates-section" data-role="critical-dates" hidden></div>
    <div class="negotiation-section" data-role="negotiation" hidden></div>
    <div class="counts" data-role="counts"></div>
    <div class="playbook-provenance" data-role="playbook-provenance" hidden></div>
    <div class="secondary-families" data-role="secondary-families" hidden></div>
    <div class="jurisdiction-overlays" data-role="jurisdiction-overlays" hidden></div>
    <div class="compliance-frame-chips" data-role="compliance-frame-chips" role="group" aria-label="Compliance frames" hidden></div>
    <div class="dropzone-sub compliance-frame-hint" data-role="compliance-frame-hint" hidden></div>
    <details class="playbook-disclosure">
      <summary>Why this playbook?</summary>
      <div data-role="reasoning"></div>
    </details>
    <button class="btn btn-primary" type="button" data-role="docx-download">Download report (Word)</button>
    <button class="btn-link" type="button" data-role="json-download">Download structured data (JSON)</button>
    <div class="export-row" data-role="export-row" role="group" aria-label="Export findings to action" hidden>
      <span class="export-row-label">Export:</span>
      <button class="btn-link" type="button" data-role="export-fixlist-md">Fix list (Markdown)</button>
      <button class="btn-link" type="button" data-role="export-fixlist-csv">Fix list (CSV)</button>
      <button class="btn-link" type="button" data-role="export-obligations-csv">Obligations (CSV)</button>
      <button class="btn-link" type="button" data-role="export-deadlines-ics">Deadlines (.ics)</button>
      <button class="btn-link" type="button" data-role="export-closing-checklist-md" hidden>Closing checklist (Markdown)</button>
      <button class="btn-link" type="button" data-role="export-closing-checklist-csv" hidden>Closing checklist (CSV)</button>
      <button class="btn-link" type="button" data-role="export-critical-dates-ics" hidden>Critical dates (.ics)</button>
      <button class="btn-link" type="button" data-role="export-critical-dates-md" hidden>Critical dates (Markdown)</button>
      <button class="btn-link" type="button" data-role="export-negotiation-sheet" hidden>Negotiation sheet (HTML)</button>
      <button class="btn-link" type="button" data-role="export-negotiation-md" hidden>Negotiation posture (Markdown)</button>
      <button class="btn-link" type="button" data-role="export-negotiation-csv" hidden>Negotiation posture (CSV)</button>
      <button class="btn-link" type="button" data-role="export-html">HTML report</button>
      <button class="btn-link" type="button" data-role="export-sarif">SARIF</button>
    </div>
    <div class="compare-row" data-role="compare-row" hidden>
      <button class="btn-link" type="button" data-role="compare-button">Compare a revised version…</button>
      <input type="file" accept=".pdf,.docx" data-role="compare-input" hidden aria-hidden="true" tabindex="-1" />
    </div>
    <div class="download-status" data-role="download-status" aria-live="polite"></div>
  `,
  "comparison-complete": `
    <div class="dropzone-title" data-role="comparison-title">Version comparison</div>
    <div class="dropzone-sub" data-role="comparison-versions"></div>
    <div class="dropzone-sub comparison-verdict" data-role="comparison-verdict"></div>
    <div class="comparison-counts" data-role="comparison-counts"></div>
    <div class="dropzone-sub comparison-redline" data-role="comparison-redline" hidden></div>
    <div class="dropzone-sub comparison-dkb-warning" data-role="comparison-dkb-warning" hidden></div>
    <button class="btn btn-primary" type="button" data-role="comparison-docx-download">Download comparison (Word)</button>
    <button class="btn-link" type="button" data-role="comparison-json-download">Download comparison data (JSON)</button>
    <button class="btn-link" type="button" data-role="comparison-reset">Analyze another document</button>
    <div class="download-status" data-role="download-status" aria-live="polite"></div>
  `,
  "bundle-complete": `
    <div class="dropzone-title" data-role="bundle-title"></div>
    <div class="counts" data-role="counts"></div>
    <label class="cross-doc-toggle" data-role="cross-doc-toggle" hidden>
      <input type="checkbox" data-role="cross-doc-toggle-input" checked />
      <span>Run cross-document consistency checks</span>
    </label>
    <div class="dropzone-sub" data-role="cross-doc-summary"></div>
    <div class="dropzone-sub bundle-detected-families" data-role="bundle-detected-families" hidden></div>
    <div class="bundle-rejected" data-role="bundle-rejected" hidden>
      <div class="bundle-rejected-heading">Skipped</div>
      <ul class="bundle-rejected-list" data-role="bundle-rejected-list" aria-label="Files skipped from this bundle"></ul>
    </div>
    <ul class="multi-doc-cards" data-role="multi-doc-cards" aria-label="Per-document summary" hidden></ul>
    <button class="btn btn-primary" type="button" data-role="bundle-download">Download consolidated report (Word)</button>
    <button class="btn-link" type="button" data-role="bundle-json-download">Download bundle data (JSON)</button>
    <button class="btn-link" type="button" data-role="bundle-zip-download" hidden>Download everything (.zip)</button>
    <div class="download-status" data-role="download-status" aria-live="polite"></div>
  `,
  error: `
    <div class="dropzone-title" data-role="error-title">Something went wrong</div>
    <div class="dropzone-sub" data-role="error-message"></div>
    <button class="btn-link" type="button" data-role="error-action" hidden></button>
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
    const baseReasoning =
      state.match_reasoning ?? `Auto-selected ${state.playbook_name}.`;
    const legacySuffix =
      state.playbook_deprecation
        ? state.playbook_deprecation.superseded_by
          ? ` Legacy playbook — superseded by ${state.playbook_deprecation.superseded_by}.`
          : " Legacy playbook."
        : "";
    select(dz, "reasoning")!.textContent = `${baseReasoning}${legacySuffix}`;
    renderV3FamilyChip(dz, state.v3_family);
    renderDelivery(dz, state.delivery);
    renderClosingChecklist(dz, state.closing_checklist);
    renderCriticalDates(dz, state.critical_dates);
    renderNegotiationPosture(dz, state.negotiation_posture);
    renderPlaybookProvenance(dz, state.custom_playbook);
    renderSecondaryFamilies(dz, state.secondary_families);
    renderJurisdictionOverlays(dz, state.jurisdiction_overlays);
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
    if (state.exports) {
      const ex = state.exports;
      select(dz, "export-row")!.removeAttribute("hidden");
      const wire = (role: string, blob: Blob, filename: string): void => {
        select<HTMLButtonElement>(dz, role)!.addEventListener("click", (e) => {
          e.stopPropagation();
          void saveBlob(blob, filename, status);
        });
      };
      wire("export-fixlist-md", ex.fixlist_md_blob, ex.fixlist_md_filename);
      wire("export-fixlist-csv", ex.fixlist_csv_blob, ex.fixlist_csv_filename);
      wire("export-obligations-csv", ex.obligations_csv_blob, ex.obligations_csv_filename);
      wire("export-deadlines-ics", ex.deadlines_ics_blob, ex.deadlines_ics_filename);
      // spec-v9 Thrust B — closing checklist, shown only when there is a readiness item.
      if (ex.closing_checklist_md_blob && ex.closing_checklist_md_filename) {
        select<HTMLButtonElement>(dz, "export-closing-checklist-md")!.removeAttribute("hidden");
        wire("export-closing-checklist-md", ex.closing_checklist_md_blob, ex.closing_checklist_md_filename);
      }
      if (ex.closing_checklist_csv_blob && ex.closing_checklist_csv_filename) {
        select<HTMLButtonElement>(dz, "export-closing-checklist-csv")!.removeAttribute("hidden");
        wire("export-closing-checklist-csv", ex.closing_checklist_csv_blob, ex.closing_checklist_csv_filename);
      }
      // spec-v9 Thrust C — critical-dates calendar / register, shown only when present.
      if (ex.critical_dates_ics_blob && ex.critical_dates_ics_filename) {
        const btn = select<HTMLButtonElement>(dz, "export-critical-dates-ics")!;
        btn.removeAttribute("hidden");
        wire("export-critical-dates-ics", ex.critical_dates_ics_blob, ex.critical_dates_ics_filename);
      }
      if (ex.critical_dates_md_blob && ex.critical_dates_md_filename) {
        const btn = select<HTMLButtonElement>(dz, "export-critical-dates-md")!;
        btn.removeAttribute("hidden");
        wire("export-critical-dates-md", ex.critical_dates_md_blob, ex.critical_dates_md_filename);
      }
      // spec-v10 Thrust B — negotiation posture export + sheet, shown only with positions.
      if (ex.negotiation_sheet_blob && ex.negotiation_sheet_filename) {
        select<HTMLButtonElement>(dz, "export-negotiation-sheet")!.removeAttribute("hidden");
        wire("export-negotiation-sheet", ex.negotiation_sheet_blob, ex.negotiation_sheet_filename);
      }
      if (ex.negotiation_posture_md_blob && ex.negotiation_posture_md_filename) {
        select<HTMLButtonElement>(dz, "export-negotiation-md")!.removeAttribute("hidden");
        wire("export-negotiation-md", ex.negotiation_posture_md_blob, ex.negotiation_posture_md_filename);
      }
      if (ex.negotiation_posture_csv_blob && ex.negotiation_posture_csv_filename) {
        select<HTMLButtonElement>(dz, "export-negotiation-csv")!.removeAttribute("hidden");
        wire("export-negotiation-csv", ex.negotiation_posture_csv_blob, ex.negotiation_posture_csv_filename);
      }
      wire("export-html", ex.html_blob, ex.html_filename);
      wire("export-sarif", ex.sarif_blob, ex.sarif_filename);
    }
    if (state.on_compare) {
      const onCompare = state.on_compare;
      const row = select<HTMLElement>(dz, "compare-row")!;
      row.removeAttribute("hidden");
      const btn = select<HTMLButtonElement>(dz, "compare-button")!;
      const input = select<HTMLInputElement>(dz, "compare-input")!;
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        input.click();
      });
      input.addEventListener("click", (e) => e.stopPropagation());
      input.addEventListener("change", (e) => {
        e.stopPropagation();
        const file = input.files?.[0];
        if (file) onCompare(file);
      });
    }
  }
  if (state.kind === "comparison-complete") {
    select(dz, "comparison-versions")!.textContent =
      `Base: ${state.base_filename} → Revised: ${state.revised_filename}`;
    select(dz, "comparison-verdict")!.textContent = state.verdict;
    select(dz, "comparison-counts")!.innerHTML = comparisonCountsHtml(state.counts);
    const redline = select<HTMLElement>(dz, "comparison-redline")!;
    if (state.clause_diff) {
      const cd = state.clause_diff;
      if (cd.added + cd.removed + cd.changed === 0) {
        redline.textContent = "Redline: no clause-level text changes between the two versions.";
      } else {
        redline.textContent =
          `Redline: ${cd.changed} clause${cd.changed === 1 ? "" : "s"} rewritten · ` +
          `${cd.added} added · ${cd.removed} removed` +
          (cd.truncated ? " (large documents — approximate)" : "") +
          ". Full text diff in the Word/JSON export.";
      }
      redline.hidden = false;
    }
    const dkbWarn = select<HTMLElement>(dz, "comparison-dkb-warning")!;
    if (state.dkb_mismatch) {
      dkbWarn.hidden = false;
      dkbWarn.textContent =
        "The two versions were analyzed against different DKB versions, so a finding may differ because the underlying authority changed, not the document.";
    }
    const status = select<HTMLElement>(dz, "download-status")!;
    const docxBtn = select<HTMLButtonElement>(dz, "comparison-docx-download")!;
    const jsonBtn = select<HTMLButtonElement>(dz, "comparison-json-download")!;
    docxBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      void saveBlob(state.docx_blob, state.docx_filename, status);
    });
    jsonBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      void saveBlob(state.json_blob, state.json_filename, status);
    });
    const resetBtn = select<HTMLButtonElement>(dz, "comparison-reset")!;
    if (state.on_reset) {
      const onReset = state.on_reset;
      resetBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        onReset();
      });
    } else {
      resetBtn.hidden = true;
    }
  }
  if (state.kind === "bundle-complete") {
    select(dz, "bundle-title")!.textContent =
      `${state.document_count} documents analyzed`;
    select(dz, "counts")!.innerHTML = countsHtml(state.counts);
    const summaryEl = select(dz, "cross-doc-summary")!;
    const renderCrossDocSummary = (active: boolean): void => {
      if (!active) {
        summaryEl.textContent = "Cross-document consistency disabled.";
        return;
      }
      summaryEl.textContent =
        state.cross_doc_findings === 0
          ? "No cross-document inconsistencies found."
          : `${state.cross_doc_findings} cross-document finding${state.cross_doc_findings === 1 ? "" : "s"}.`;
    };
    const initialActive = state.cross_doc_active ?? true;
    renderCrossDocSummary(initialActive);
    // Cross-document consistency toggle (spec-v3 §62). Visible whenever
    // the bundle-complete state is rendered with at least 2 documents.
    const toggleWrap = select<HTMLLabelElement>(dz, "cross-doc-toggle");
    const toggleInput = select<HTMLInputElement>(dz, "cross-doc-toggle-input");
    if (toggleWrap && toggleInput && state.document_count >= 2) {
      toggleWrap.hidden = false;
      toggleInput.checked = initialActive;
      toggleInput.addEventListener("change", (e) => {
        e.stopPropagation();
        const active = toggleInput.checked;
        renderCrossDocSummary(active);
        state.on_consistency_toggle?.(active);
      });
      // Prevent click on label/checkbox from bubbling to the dropzone
      // (which would re-open the file picker).
      toggleWrap.addEventListener("click", (e) => e.stopPropagation());
    }
    const detectedEl = select<HTMLElement>(dz, "bundle-detected-families")!;
    if (state.detected_families && state.detected_families.length > 0) {
      detectedEl.hidden = false;
      detectedEl.textContent = `Detected: ${state.detected_families.join(", ")}`;
    } else {
      detectedEl.hidden = true;
      detectedEl.textContent = "";
    }
    renderRejectedFiles(dz, state.rejected);
    renderMultiDocCards(dz, state.documents);
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
    if (state.bundle_zip_blob && state.bundle_zip_filename) {
      const zipBlob = state.bundle_zip_blob;
      const zipName = state.bundle_zip_filename;
      const zipBtn = select<HTMLButtonElement>(dz, "bundle-zip-download")!;
      zipBtn.removeAttribute("hidden");
      zipBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        void saveBlob(zipBlob, zipName, status);
      });
    }
  }
  if (state.kind === "error") {
    // Spec-v3 §63: when an error code is provided, look up the
    // structured title + detail. Falls back to the generic
    // "Something went wrong" title + freeform message for legacy
    // call sites that pass only `message`.
    if (state.code) {
      const msg = v3ErrorMessage(state.code);
      select(dz, "error-title")!.textContent = msg.title;
      select(dz, "error-message")!.textContent = msg.detail;
    } else {
      select(dz, "error-message")!.textContent = state.message;
    }
    const actionBtn = select<HTMLButtonElement>(dz, "error-action")!;
    if (state.action) {
      const action = state.action;
      actionBtn.hidden = false;
      actionBtn.textContent = action.label;
      actionBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        action.on_click();
      });
    }
  }
}

export function select<T extends HTMLElement = HTMLElement>(
  root: HTMLElement,
  role: string,
): T | null {
  return root.querySelector<T>(`[data-role="${role}"]`);
}

type BucketCounts = { critical: number; warning: number; info: number; total: number };

function comparisonCountsHtml(counts: {
  resolved: BucketCounts;
  introduced: BucketCounts;
  unchanged: BucketCounts;
  carried_clean_count: number;
}): string {
  const line = (label: string, klass: string, c: BucketCounts): string =>
    `<span class="comparison-count comparison-count--${klass}"><strong>${c.total}</strong> ${label}` +
    `<span class="comparison-count-detail"> (${c.critical}C · ${c.warning}W · ${c.info}I)</span></span>`;
  return `
    ${line("resolved", "resolved", counts.resolved)}
    ${line("introduced", "introduced", counts.introduced)}
    ${line("unchanged", "unchanged", counts.unchanged)}
    <span class="comparison-count comparison-count--clean"><strong>${counts.carried_clean_count}</strong> carried clean</span>
  `;
}

function countsHtml(counts: { critical: number; warning: number; info: number }): string {
  return `
    <span class="count count--critical"><strong>${counts.critical}</strong> critical</span>
    <span class="count count--warning"><strong>${counts.warning}</strong> warnings</span>
    <span class="count count--info"><strong>${counts.info}</strong> informational</span>
  `;
}

/**
 * Render per-document summary cards inside the bundle-complete state
 * (spec-v3 §62). Each `<li>` card shows filename / detected family /
 * matched playbook / per-doc finding counts, plus two download
 * buttons that save the per-doc DOCX report and JSON. Native
 * `<button>` elements keep keyboard accessibility free (Tab focuses
 * each, Enter/Space activates). The container `<ul>` is `hidden`
 * when no document list is provided so existing callers / tests
 * stay green.
 */
function renderMultiDocCards(
  dz: HTMLElement,
  documents:
    | ReadonlyArray<{
        filename: string;
        family_label?: string;
        detection_confidence?: number;
        playbook_name: string;
        playbook_deprecated?: boolean;
        counts: { critical: number; warning: number; info: number };
        secondary_families?: ReadonlyArray<{
          playbook_name: string;
          counts: { critical: number; warning: number; info: number };
        }>;
        docx_blob: Blob;
        json_blob: Blob;
        docx_filename: string;
        json_filename: string;
      }>
    | undefined,
): void {
  const list = select<HTMLUListElement>(dz, "multi-doc-cards");
  if (!list) return;
  if (!documents || documents.length === 0) {
    list.hidden = true;
    list.innerHTML = "";
    return;
  }
  list.hidden = false;
  list.innerHTML = documents
    .map((d, i) => {
      const conf = typeof d.detection_confidence === "number" ? d.detection_confidence : null;
      const confSuffix =
        conf !== null
          ? ` <span class="multi-doc-card-confidence">(${conf.toFixed(2)})</span>`
          : "";
      const family = d.family_label
        ? `<span class="multi-doc-card-family">${escapeHtml(d.family_label)}${confSuffix}</span>`
        : "";
      const legacyHint = d.playbook_deprecated === true ? " (legacy)" : "";
      const playbook = `<span class="multi-doc-card-playbook">${escapeHtml(d.playbook_name)}${legacyHint}</span>`;
      const c = d.counts;
      const countsLine = `${c.critical} critical · ${c.warning} warnings · ${c.info} info`;
      const lowConfClass = conf !== null && conf < 0.5 ? " low-confidence" : "";
      const secondary =
        d.secondary_families && d.secondary_families.length > 0
          ? `<div class="multi-doc-card-secondary">Also checked: ${d.secondary_families
              .map(
                (f) =>
                  `${escapeHtml(f.playbook_name)} (${f.counts.critical}C · ${f.counts.warning}W · ${f.counts.info}I)`,
              )
              .join("; ")}</div>`
          : "";
      return `<li class="multi-doc-card${lowConfClass}" data-role="multi-doc-card">
        <div class="multi-doc-card-filename">${escapeHtml(d.filename)}</div>
        <div class="multi-doc-card-meta">${family}${family ? " · " : ""}${playbook}</div>
        <div class="multi-doc-card-counts">${countsLine}</div>
        ${secondary}
        <div class="multi-doc-card-actions">
          <button class="btn-link" type="button" data-role="card-docx-download" data-card-index="${i}" aria-label="Download Word report for ${escapeHtml(d.filename)}">Word</button>
          <button class="btn-link" type="button" data-role="card-json-download" data-card-index="${i}" aria-label="Download JSON for ${escapeHtml(d.filename)}">JSON</button>
        </div>
      </li>`;
    })
    .join("");

  // Wire the per-card download buttons. Status is reported through
  // the shared `[data-role="download-status"]` element rendered in
  // the bundle-complete template (aria-live="polite").
  const status = select<HTMLElement>(dz, "download-status");
  list.querySelectorAll<HTMLButtonElement>('[data-role="card-docx-download"]').forEach(
    (btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const idx = Number(btn.getAttribute("data-card-index"));
        const doc = documents[idx];
        if (doc && status) {
          void saveBlob(doc.docx_blob, doc.docx_filename, status);
        }
      });
    },
  );
  list.querySelectorAll<HTMLButtonElement>('[data-role="card-json-download"]').forEach(
    (btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const idx = Number(btn.getAttribute("data-card-index"));
        const doc = documents[idx];
        if (doc && status) {
          void saveBlob(doc.json_blob, doc.json_filename, status);
        }
      });
    },
  );
}

/**
 * Render the "Skipped" block inside the bundle-complete state. The
 * planner already returns a polished per-entry reason string
 * (`rejectionForFilename`, "exceeds the 50 MB per-file limit", etc.),
 * so the UI just needs to enumerate them. Hidden when nothing was
 * rejected so the surface stays quiet for the common case.
 */
function renderRejectedFiles(
  dz: HTMLElement,
  rejected: ReadonlyArray<{ filename: string; reason: string }> | undefined,
): void {
  const wrap = select<HTMLElement>(dz, "bundle-rejected");
  const list = select<HTMLUListElement>(dz, "bundle-rejected-list");
  if (!wrap || !list) return;
  if (!rejected || rejected.length === 0) {
    wrap.hidden = true;
    list.innerHTML = "";
    return;
  }
  wrap.hidden = false;
  list.innerHTML = rejected
    .map(
      (r) =>
        `<li class="bundle-rejected-item"><span class="bundle-rejected-filename">${escapeHtml(r.filename)}</span><span class="bundle-rejected-reason">${escapeHtml(r.reason)}</span></li>`,
    )
    .join("");
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
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
  // Spec-v3 §60: render the numeric confidence next to the family
  // label, and flag low-confidence (< 0.5) detections with a class so
  // CSS can present them faintly. Mirrors the affordance on the
  // bundle-complete multi-doc cards (`.multi-doc-card.low-confidence`).
  chip.classList.toggle("low-confidence", detection.confidence < 0.5);
  chip.textContent = `Detected: ${detection.label} (${detection.confidence.toFixed(2)})`;
}

/**
 * Render the bring-your-own-playbook provenance line (spec-v6 Part II,
 * Step 92). Distinguishes the team's standard from the built-in catalog and
 * notes any custom rules that could not be evaluated on this document.
 * Hidden when the run was not driven by a custom playbook.
 */
function renderPlaybookProvenance(
  dz: HTMLElement,
  custom:
    | { name: string; mode: "augment" | "replace"; custom_finding_count: number; unevaluable_count: number }
    | undefined,
): void {
  const el = select<HTMLElement>(dz, "playbook-provenance");
  if (!el) return;
  if (!custom) {
    el.hidden = true;
    el.textContent = "";
    return;
  }
  el.hidden = false;
  const modeWord = custom.mode === "replace" ? "only your playbook" : "your playbook + the built-in catalog";
  const findings = `${custom.custom_finding_count} finding${custom.custom_finding_count === 1 ? "" : "s"} from ${escapeHtml(custom.name)}`;
  const unevaluable =
    custom.unevaluable_count > 0
      ? ` · ${custom.unevaluable_count} custom rule${custom.unevaluable_count === 1 ? "" : "s"} could not be evaluated on this document`
      : "";
  el.textContent = `Enforcing ${modeWord}: ${findings}${unevaluable}.`;
}

/**
 * Render the "additional checks from other detected families" block
 * (spec-v6 multi-family activation). Lists each secondary family the
 * document also contains, with its finding counts, so the reviewer sees
 * that a present family was scanned even though it wasn't the primary
 * match. The full findings are in the downloadable report. Hidden when no
 * secondary family was activated.
 */
function renderSecondaryFamilies(
  dz: HTMLElement,
  families:
    | ReadonlyArray<{
        playbook_id: string;
        playbook_name: string;
        counts: { critical: number; warning: number; info: number };
      }>
    | undefined,
): void {
  const el = select<HTMLElement>(dz, "secondary-families");
  if (!el) return;
  if (!families || families.length === 0) {
    el.hidden = true;
    el.innerHTML = "";
    return;
  }
  el.hidden = false;
  const items = families
    .map((f) => {
      const c = f.counts;
      const total = c.critical + c.warning + c.info;
      const detail =
        total === 0
          ? "no findings"
          : `${c.critical} critical · ${c.warning} warnings · ${c.info} info`;
      return `<li class="secondary-family"><span class="secondary-family-name">${escapeHtml(
        f.playbook_name,
      )}</span> <span class="secondary-family-counts">${detail}</span></li>`;
    })
    .join("");
  el.innerHTML = `
    <div class="secondary-families-heading">Also checked (other detected families)</div>
    <ul class="secondary-families-list" data-role="secondary-families-list">${items}</ul>
  `;
}

/**
 * Jurisdiction overlays (spec-v6 Part VI §21, Step 101). State-law deltas for
 * the governing-law state(s) the document names, for the state-sensitive
 * families. A citable reference block, not findings; honest about the states
 * it does not cover. Hidden when there is no overlay to show.
 */
function renderDelivery(
  dz: HTMLElement,
  delivery: Extract<DropzoneState, { kind: "complete" }>["delivery"],
): void {
  const el = select<HTMLElement>(dz, "delivery");
  if (!el) return;
  // Hide entirely when the scan found nothing AND the container was
  // inspectable — a clean inspectable document needs no banner. An
  // uninspectable input with a note is also hidden here (the main report
  // suffices); we surface the block only when there is something to show.
  if (!delivery || (delivery.findings.length === 0 && delivery.inspectable)) {
    el.hidden = true;
    el.innerHTML = "";
    return;
  }
  if (delivery.findings.length === 0) {
    el.hidden = true;
    el.innerHTML = "";
    return;
  }
  el.hidden = false;
  const worst = delivery.findings.some((f) => f.severity === "critical")
    ? "critical"
    : delivery.findings.some((f) => f.severity === "warning")
      ? "warning"
      : "info";
  const cards = delivery.findings
    .map((f) => {
      const evidence = f.evidence
        .slice(0, 6)
        .map((e) => `<li>${escapeHtml(e)}</li>`)
        .join("");
      const more =
        f.count > 6 ? `<li class="delivery-more">…and ${f.count - 6} more</li>` : "";
      return `<li class="delivery-card delivery-${f.severity}">
        <div class="delivery-card-head"><span class="delivery-rule">${escapeHtml(
          f.rule_id,
        )}</span> <span class="delivery-card-title">${escapeHtml(f.title)}</span></div>
        <div class="delivery-card-desc">${escapeHtml(f.description)}</div>
        <ul class="delivery-evidence">${evidence}${more}</ul>
      </li>`;
    })
    .join("");
  el.innerHTML = `
    <div class="delivery-heading delivery-heading-${worst}">
      <span class="delivery-badge">Clean to send?</span>
      <span class="delivery-summary">${escapeHtml(delivery.summary)}</span>
    </div>
    <ul class="delivery-list">${cards}</ul>
    <div class="delivery-note">Vaulytica reports what it found in the original file and where — it never removes it (that is your edit in Word) and never certifies the document clean.</div>
  `;
}

const CHECKLIST_CATEGORY_LABEL: Record<string, string> = {
  signature: "Signatures",
  attachment: "Attachments",
  formality: "Execution formalities",
  blank: "Unfilled content",
  handoff: "Pre-send cleanup",
};
const CHECKLIST_CATEGORY_ORDER = ["signature", "attachment", "formality", "blank", "handoff"];

/**
 * Closing-checklist view (spec-v9 Thrust B). The consolidated readiness items
 * as a mobile-safe, grouped checklist. Presence-only: hidden when empty, and
 * it never certifies the document "ready to sign."
 */
function renderClosingChecklist(
  dz: HTMLElement,
  cl: Extract<DropzoneState, { kind: "complete" }>["closing_checklist"],
): void {
  const el = select<HTMLElement>(dz, "closing-checklist");
  if (!el) return;
  if (!cl || cl.items.length === 0) {
    el.hidden = true;
    el.innerHTML = "";
    return;
  }
  el.hidden = false;
  const groups = CHECKLIST_CATEGORY_ORDER.map((cat) => {
    const items = cl.items.filter((i) => i.category === cat);
    if (items.length === 0) return "";
    const lis = items
      .map((i) => {
        const where = i.section ? ` <span class="cl-section">§${escapeHtml(i.section)}</span>` : "";
        return `<li class="cl-item"><span class="cl-rule">${escapeHtml(i.rule_id)}</span> ${escapeHtml(i.label)}${where}</li>`;
      })
      .join("");
    return `<div class="cl-group"><div class="cl-group-head">${escapeHtml(CHECKLIST_CATEGORY_LABEL[cat] ?? cat)} (${items.length})</div><ul class="cl-list">${lis}</ul></div>`;
  }).join("");
  el.innerHTML = `
    <div class="cl-heading">
      <span class="cl-badge">Ready to sign?</span>
      <span class="cl-summary">${cl.open_count} readiness item${cl.open_count === 1 ? "" : "s"} to resolve</span>
    </div>
    ${groups}
    <div class="cl-note">A deterministic projection of the findings — it lists what is left to resolve before closing; it does not certify the document is ready to sign or validly executed.</div>
  `;
}

const NEGOTIATION_TIER_LABEL: Record<string, { label: string; cls: string }> = {
  ideal: { label: "Ideal", cls: "np-ideal" },
  acceptable: { label: "Acceptable", cls: "np-acceptable" },
  "below-acceptable": { label: "Below floor — escalate", cls: "np-below" },
  unevaluable: { label: "Not stated — verify", cls: "np-uneval" },
};

/**
 * Negotiation-posture view (spec-v10 Thrust A). Shows which rung of the team's
 * ideal/acceptable ladder the draft meets on each dimension. Mobile-safe;
 * advisory — never a legal conclusion. Hidden when empty.
 */
function renderNegotiationPosture(
  dz: HTMLElement,
  np: Extract<DropzoneState, { kind: "complete" }>["negotiation_posture"],
): void {
  const el = select<HTMLElement>(dz, "negotiation");
  if (!el) return;
  if (!np || np.positions.length === 0) {
    el.hidden = true;
    el.innerHTML = "";
    return;
  }
  el.hidden = false;
  const c = np.counts;
  const cards = np.positions
    .map((p) => {
      const tier = NEGOTIATION_TIER_LABEL[p.tier] ?? { label: p.tier, cls: "cd-unresolved" };
      const detail = p.detail ?? p.reason ?? "";
      const guide = p.guidance ? `<div class="np-guide">Guidance: ${escapeHtml(p.guidance)}</div>` : "";
      const where = p.section_id ? ` <span class="cd-kind">§${escapeHtml(p.section_id)}</span>` : "";
      return `<li class="np-card ${tier.cls}">
        <div class="np-head"><span class="np-dim">${escapeHtml(p.dimension)}</span> <span class="np-tier">${escapeHtml(tier.label)}</span>${where}</div>
        ${detail ? `<div class="np-detail">${escapeHtml(detail)}</div>` : ""}
        ${guide}
      </li>`;
    })
    .join("");
  el.innerHTML = `
    <div class="np-heading">
      <span class="np-badge">Negotiation posture</span>
      <span class="np-summary">${c.ideal} ideal · ${c.acceptable} acceptable · ${c.below_acceptable} below floor · ${c.unevaluable} not stated</span>
    </div>
    <ul class="np-list">${cards}</ul>
    <div class="np-note">Computed deterministically from your playbook's positions — it shows where the draft sits on your ladder; it is not a legal conclusion.</div>
  `;
}

const CRITICAL_DATE_KIND_LABEL: Record<string, string> = {
  "auto-renewal-notice": "Auto-renewal notice",
  "cure-window": "Cure window",
  "opt-out-window": "Opt-out / termination",
  "survival-end": "Survival end",
  "notice-period": "Notice deadline",
};

/**
 * Critical-dates view (spec-v9 Thrust C). Renders the computed deadlines as
 * a mobile-safe list of cards — each shows the absolute computed date (or a
 * "verify manually" badge), the deadline type, anchor, and the clause it
 * derives from. Only absolute dates are shown; no "days remaining" (§3
 * corollary 4). Hidden when the register is empty.
 */
function renderCriticalDates(
  dz: HTMLElement,
  cd: Extract<DropzoneState, { kind: "complete" }>["critical_dates"],
): void {
  const el = select<HTMLElement>(dz, "critical-dates");
  if (!el) return;
  if (!cd || cd.rows.length === 0) {
    el.hidden = true;
    el.innerHTML = "";
    return;
  }
  el.hidden = false;
  const cards = cd.rows
    .map((r) => {
      const label = CRITICAL_DATE_KIND_LABEL[r.kind] ?? "Deadline";
      const date = r.resolved
        ? r.window
          ? `${escapeHtml(r.window[0])} – ${escapeHtml(r.window[1])}`
          : escapeHtml(r.computed_date ?? "")
        : "Verify manually";
      const meta: string[] = [];
      if (r.anchor) meta.push(`anchor: ${escapeHtml(r.anchor)}`);
      if (r.responsible) meta.push(`responsible: ${escapeHtml(r.responsible)}`);
      if (r.section) meta.push(`§${escapeHtml(r.section)}`);
      const reason = !r.resolved && r.reason ? `<div class="cd-reason">${escapeHtml(r.reason)}</div>` : "";
      return `<li class="cd-card cd-${r.resolved ? "resolved" : "unresolved"}">
        <div class="cd-card-head"><span class="cd-date">${date}</span> <span class="cd-kind">${escapeHtml(label)}</span></div>
        <div class="cd-trigger">${escapeHtml(r.trigger)}</div>
        ${meta.length ? `<div class="cd-meta">${meta.join(" · ")}</div>` : ""}
        ${reason}
      </li>`;
    })
    .join("");
  el.innerHTML = `
    <div class="cd-heading">
      <span class="cd-badge">Your calendar, computed</span>
      <span class="cd-summary">${cd.resolved_count} computed · ${cd.unresolved_count} to verify manually</span>
    </div>
    <ul class="cd-list">${cards}</ul>
    <div class="cd-note">Each date is computed from the document's own terms by calendar arithmetic — it is not a determination that a deadline is met, missed, or binding.</div>
  `;
}

function renderJurisdictionOverlays(
  dz: HTMLElement,
  overlays: Extract<DropzoneState, { kind: "complete" }>["jurisdiction_overlays"],
): void {
  const el = select<HTMLElement>(dz, "jurisdiction-overlays");
  if (!el) return;
  if (!overlays || (overlays.matched.length === 0 && overlays.uncovered_states.length === 0)) {
    el.hidden = true;
    el.innerHTML = "";
    return;
  }
  el.hidden = false;
  const topic = overlays.matched[0]?.topic ?? overlays.family;
  const cards = overlays.matched
    .map(
      (o) => `<li class="overlay-card overlay-${o.posture}">
        <div class="overlay-card-head"><span class="overlay-state">${escapeHtml(
          o.state_name,
        )}</span> <span class="overlay-status">${escapeHtml(o.headline)}</span></div>
        <div class="overlay-summary">${escapeHtml(o.summary)}</div>
        <div class="overlay-reco">${escapeHtml(o.recommendation)}</div>
        <a class="overlay-cite" href="${escapeHtml(
          o.citation.source_url,
        )}" target="_blank" rel="noopener noreferrer">${escapeHtml(o.citation.source)}</a>
      </li>`,
    )
    .join("");
  const uncovered =
    overlays.uncovered_states.length > 0
      ? `<div class="overlay-uncovered">No overlay on file for ${overlays.uncovered_states
          .map((s) => s.replace(/^us-/, "").toUpperCase())
          .join(", ")} — an honest coverage gap, not a clean pass. Verify ${escapeHtml(
          topic,
        )} for ${overlays.uncovered_states.length === 1 ? "that state" : "those states"} manually.</div>`
      : "";
  el.innerHTML = `
    <div class="overlay-heading">Jurisdiction overlays <span class="overlay-coverage">${escapeHtml(
      topic,
    )} · ${overlays.states_in_catalog} states covered</span></div>
    <ul class="overlay-list">${cards}</ul>
    ${uncovered}
  `;
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

/**
 * File-type metadata keyed by extension. Drives both the defensive MIME
 * re-wrap and the File System Access `accept` filter. Adding an export
 * format (v6 Part III) is one entry here.
 */
const FILE_TYPES: Record<string, { mime: string; description: string; ext: string }> = {
  docx: { mime: DOCX_MIME, description: "Word document", ext: ".docx" },
  json: { mime: JSON_MIME, description: "JSON", ext: ".json" },
  md: { mime: "text/markdown", description: "Markdown", ext: ".md" },
  csv: { mime: "text/csv", description: "CSV", ext: ".csv" },
  ics: { mime: "text/calendar", description: "iCalendar", ext: ".ics" },
};

function fileTypeFor(filename: string): { mime: string; description: string; ext: string } {
  const dot = filename.lastIndexOf(".");
  const ext = dot >= 0 ? filename.slice(dot + 1).toLowerCase() : "";
  return FILE_TYPES[ext] ?? FILE_TYPES.json!;
}

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

  const fileType = fileTypeFor(filename);
  // Defensively re-wrap if the upstream blob lost its MIME type. macOS
  // associates files by MIME, and a blob of type "" lands as an
  // unrecognized binary in some browsers.
  const typedBlob =
    blob.type === "" ? new Blob([blob], { type: fileType.mime }) : blob;

  const fsa = (window as FsaWindow).showSaveFilePicker;
  if (typeof fsa === "function") {
    statusEl.textContent = `Saving ${filename}…`;
    try {
      const accept: Record<string, string[]> = { [fileType.mime]: [fileType.ext] };
      const description = fileType.description;
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
