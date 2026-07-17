/**
 * Bring-your-own-playbook panel (spec-v6 Part II §8, §10, Step 92).
 *
 * A small affordance beside the drop zone that lets a team load *its own*
 * playbook `.json`, see it validated and previewed, choose augment vs
 * replace, and have the next analysis enforce that standard. The active
 * playbook is reported to the host (`main.ts`) via `onActiveChange`; the
 * host threads it into the pipeline.
 *
 * Posture (spec-v6 Part VII): the file is read with the in-tab File API and
 * held in memory only — **no bytes leave the tab**. Validation + preview run
 * client-side. To keep `zod` and the rule catalog out of the eager
 * marketing-page bundle, the heavy validate-and-preview step is reached
 * through a `validate` callback that, by default, dynamic-imports the
 * (already-preloaded) pipeline chunk. Tests inject a lightweight validator.
 */

// Type-only imports — erased at build, so the eager marketing-page bundle
// stays free of `zod` and the rule catalog. The full playbook object is
// forwarded opaquely to the host; the panel reads only the preview for display.
import type { CustomPlaybook, CustomPlaybookPreview } from "../playbooks/index.js";

export type PlaybookPreview = CustomPlaybookPreview;

/** The validated playbook the panel forwards to the host on activation. */
export type LoadedPlaybook = CustomPlaybook;

export type PlaybookValidationResult =
  | { ok: true; playbook: LoadedPlaybook; preview: PlaybookPreview }
  | { ok: false; errors: string[] };

export type PlaybookValidator = (
  text: string,
) => Promise<PlaybookValidationResult> | PlaybookValidationResult;

/** Positions with the chosen party role applied (`role_variants` stripped). */
export type ResolvedPositions = NonNullable<CustomPlaybook["negotiation_positions"]>;

export type RoleResolutionResult =
  | { ok: true; positions: ResolvedPositions; role?: string }
  | { ok: false; error: string };

/**
 * Resolve a playbook's positions for a chosen party role
 * (add-negotiation-ladder-playbooks — the tab counterpart of the CLI's
 * `--role`). Defaults to dynamic-importing the pipeline chunk's
 * `resolvePositionsForRole` (same bundle discipline as `validate`).
 * Injected in tests.
 */
export type RoleResolver = (
  playbook: LoadedPlaybook,
  role: string,
) => Promise<RoleResolutionResult> | RoleResolutionResult;

export type PlaybookPanelOptions = {
  /**
   * Called whenever the active playbook changes: the validated playbook with
   * the user's chosen augment/replace mode applied when one is loaded, or
   * `null` when cleared. The host runs the next analysis with it.
   */
  onActiveChange: (playbook: LoadedPlaybook | null) => void;
  /**
   * Validate + preview raw playbook JSON. Defaults to dynamic-importing the
   * pipeline chunk's `validateAndPreviewPlaybook`. Injected in tests.
   */
  validate?: PlaybookValidator;
  /** Apply a chosen party role to the loaded playbook's positions. */
  resolveRole?: RoleResolver;
};

const PANEL_HTML = `
  <button type="button" class="btn-link" data-role="playbook-load">Enforce your own playbook…</button>
  <input type="file" accept=".json,application/json" data-role="playbook-input" hidden aria-hidden="true" tabindex="-1" />
  <div class="playbook-status" data-role="playbook-status" aria-live="polite"></div>
`;

const defaultValidator: PlaybookValidator = async (text) => {
  const mod = await import("./pipeline.js");
  return mod.validateAndPreviewPlaybook(text) as PlaybookValidationResult;
};

const defaultRoleResolver: RoleResolver = async (playbook, role) => {
  const mod = await import("./pipeline.js");
  return mod.resolvePositionsForRole(playbook, role) as RoleResolutionResult;
};

export function bindPlaybookPanel(container: HTMLElement, opts: PlaybookPanelOptions): () => void {
  const validate = opts.validate ?? defaultValidator;
  const resolveRole = opts.resolveRole ?? defaultRoleResolver;
  container.innerHTML = PANEL_HTML;

  const loadBtn = sel<HTMLButtonElement>(container, "playbook-load")!;
  const input = sel<HTMLInputElement>(container, "playbook-input")!;
  const status = sel<HTMLElement>(container, "playbook-status")!;

  const openPicker = (e: Event): void => {
    e.stopPropagation();
    input.value = "";
    input.click();
  };

  const onPick = async (e: Event): Promise<void> => {
    e.stopPropagation();
    const file = input.files?.[0];
    if (!file) return;
    status.textContent = `Validating ${file.name}…`;
    let text: string;
    try {
      text = await file.text();
    } catch (err) {
      renderErrors(status, [`could not read ${file.name}: ${errMsg(err)}`]);
      opts.onActiveChange(null);
      return;
    }
    let result: PlaybookValidationResult;
    try {
      result = await validate(text);
    } catch (err) {
      renderErrors(status, [`validation failed: ${errMsg(err)}`]);
      opts.onActiveChange(null);
      return;
    }
    if (!result.ok) {
      renderErrors(status, result.errors);
      opts.onActiveChange(null);
      return;
    }
    // Renders the preview and activates the playbook — immediately for a
    // single-role one, or once a party role is chosen for a role-varying one.
    renderPreview(
      status,
      file.name,
      result.playbook,
      result.preview,
      opts.onActiveChange,
      resolveRole,
    );
  };

  loadBtn.addEventListener("click", openPicker);
  input.addEventListener("click", (e) => e.stopPropagation());
  input.addEventListener("change", (e) => void onPick(e));

  return () => {
    loadBtn.removeEventListener("click", openPicker);
    container.innerHTML = "";
  };
}

function renderErrors(status: HTMLElement, errors: ReadonlyArray<string>): void {
  status.innerHTML = `
    <div class="playbook-error" role="alert">
      <div class="playbook-error-heading">This playbook is not valid:</div>
      <ul class="playbook-error-list" data-role="playbook-errors">
        ${errors.map((e) => `<li>${escapeHtml(e)}</li>`).join("")}
      </ul>
    </div>
  `;
}

function renderPreview(
  status: HTMLElement,
  filename: string,
  playbook: LoadedPlaybook,
  preview: PlaybookPreview,
  onActiveChange: (playbook: LoadedPlaybook | null) => void,
  resolveRole: RoleResolver,
): void {
  const warnings: string[] = [];
  if (preview.catalog_version_mismatch) {
    warnings.push(
      `Authored for a different catalog version than the running catalog (${escapeHtml(
        preview.catalog_version,
      )}). Some referenced rules may have changed.`,
    );
  }
  if (preview.unknown_selection_rule_ids.length > 0) {
    warnings.push(
      `Unknown rule ids in rule_selection: ${escapeHtml(preview.unknown_selection_rule_ids.join(", "))}.`,
    );
  }
  if (preview.unknown_override_rule_ids.length > 0) {
    warnings.push(
      `Unknown rule ids in rule_overrides: ${escapeHtml(preview.unknown_override_rule_ids.join(", "))}.`,
    );
  }
  if (preview.uncited_custom_rule_ids.length > 0) {
    warnings.push(
      `${preview.uncited_custom_rule_ids.length} custom rule${
        preview.uncited_custom_rule_ids.length === 1 ? "" : "s"
      } with no citation — findings will be marked "uncited (team policy)".`,
    );
  }

  const warningsHtml =
    warnings.length > 0
      ? `<ul class="playbook-warnings" data-role="playbook-warnings">${warnings
          .map((w) => `<li>${w}</li>`)
          .join("")}</ul>`
      : "";

  const builtinLine =
    preview.mode === "replace"
      ? "Built-in catalog: <strong>disabled</strong> (replace mode)."
      : `Built-in catalog: <strong>${preview.selected_builtin_rule_ids.length}</strong> rules` +
        (preview.excluded_builtin_count > 0 ? ` (${preview.excluded_builtin_count} excluded)` : "");

  // add-negotiation-ladder-playbooks — the tab counterpart of the CLI's
  // `--role`. A playbook whose positions vary by party role activates only
  // once a side is chosen (never a silent default); the chosen role's ladder
  // is resolved into concrete positions BEFORE anything evaluates or hashes.
  const declaredRoles = playbook.party_roles ?? [];
  const variesByRole = (playbook.negotiation_positions ?? []).some(
    (p) => p.role_variants && Object.keys(p.role_variants).length > 0,
  );
  const roleHtml = variesByRole
    ? `<fieldset class="playbook-role" data-role="playbook-role-picker">
        <legend>Party role</legend>
        <div class="playbook-role-hint" data-role="playbook-role-hint">This playbook's positions vary by party role — choose your side to activate it.</div>
        <select data-role="playbook-role-select" aria-label="Party role">
          <option value="" selected disabled>Choose a role…</option>
          ${declaredRoles
            .map((r) => `<option value="${escapeHtml(r)}">${escapeHtml(r)}</option>`)
            .join("")}
        </select>
      </fieldset>`
    : "";

  status.innerHTML = `
    <div class="playbook-loaded" data-role="playbook-loaded">
      <div class="playbook-loaded-name"><strong>${escapeHtml(playbook.name)}</strong> <span class="playbook-loaded-file">(${escapeHtml(
        filename,
      )})</span></div>
      <div class="playbook-loaded-summary">
        ${builtinLine}<br />
        Your positions: <strong>${preview.custom_rule_count}</strong> custom rule${
          preview.custom_rule_count === 1 ? "" : "s"
        }, <strong>${preview.required_clause_count}</strong> required clause${
          preview.required_clause_count === 1 ? "" : "s"
        }.
      </div>
      ${warningsHtml}
      <fieldset class="playbook-mode" data-role="playbook-mode">
        <legend>Enforcement mode</legend>
        <label><input type="radio" name="playbook-mode" value="augment" data-role="mode-augment" /> Augment — built-in catalog + your positions</label>
        <label><input type="radio" name="playbook-mode" value="replace" data-role="mode-replace" /> Replace — only your positions</label>
      </fieldset>
      ${roleHtml}
      <button type="button" class="btn-link" data-role="playbook-clear">Clear playbook</button>
    </div>
  `;

  const augmentRadio = sel<HTMLInputElement>(status, "mode-augment")!;
  const replaceRadio = sel<HTMLInputElement>(status, "mode-replace")!;
  augmentRadio.checked = preview.mode === "augment";
  replaceRadio.checked = preview.mode === "replace";

  // Positions with the chosen role applied; null while a role-varying playbook
  // still awaits a choice (it stays inactive until then).
  let resolvedPositions: ResolvedPositions | null = null;

  const notify = (): void => {
    const mode = replaceRadio.checked ? "replace" : "augment";
    if (variesByRole && resolvedPositions === null) {
      onActiveChange(null);
      return;
    }
    onActiveChange({
      ...playbook,
      mode,
      ...(resolvedPositions ? { negotiation_positions: resolvedPositions } : {}),
    });
  };

  const notifyMode = (e: Event): void => {
    e.stopPropagation();
    notify();
  };
  augmentRadio.addEventListener("change", notifyMode);
  replaceRadio.addEventListener("change", notifyMode);

  const roleSelect = sel<HTMLSelectElement>(status, "playbook-role-select");
  if (roleSelect) {
    roleSelect.addEventListener("click", (e) => e.stopPropagation());
    roleSelect.addEventListener("change", (e) => {
      e.stopPropagation();
      void (async () => {
        const role = roleSelect.value;
        const hint = sel<HTMLElement>(status, "playbook-role-hint")!;
        let result: RoleResolutionResult;
        try {
          result = await resolveRole(playbook, role);
        } catch (err) {
          result = { ok: false, error: errMsg(err) };
        }
        if (!result.ok) {
          resolvedPositions = null;
          hint.textContent = `Could not apply the role: ${result.error}`;
          onActiveChange(null);
          return;
        }
        resolvedPositions = result.positions;
        hint.textContent = `Positions scored as ${role}.`;
        notify();
      })();
    });
  }

  // Activate immediately with the preview's mode (the default / authored
  // mode) — or report inactive when a party role must be chosen first.
  notify();

  const clearBtn = sel<HTMLButtonElement>(status, "playbook-clear")!;
  clearBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    status.textContent = "";
    onActiveChange(null);
  });
}

function sel<T extends HTMLElement = HTMLElement>(root: HTMLElement, role: string): T | null {
  return root.querySelector<T>(`[data-role="${role}"]`);
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
