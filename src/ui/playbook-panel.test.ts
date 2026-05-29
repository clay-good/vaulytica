import { describe, expect, it, vi } from "vitest";
import {
  bindPlaybookPanel,
  type LoadedPlaybook,
  type PlaybookPreview,
  type PlaybookValidationResult,
} from "./playbook-panel.js";

function loaded(mode: "augment" | "replace" = "augment"): LoadedPlaybook {
  return {
    schema_version: "1.0",
    catalog_version: "0.1.0",
    id: "team",
    name: "Team Standard",
    description: "A team standard.",
    mode,
  };
}

function makePreview(over: Partial<PlaybookPreview> = {}): PlaybookPreview {
  return {
    playbook_id: "team",
    name: "Team Standard",
    mode: "augment",
    catalog_version: "0.1.0",
    catalog_version_mismatch: false,
    selected_builtin_rule_ids: ["AAA-001", "BBB-002"],
    excluded_builtin_count: 0,
    custom_rule_count: 2,
    required_clause_count: 1,
    uncited_custom_rule_ids: [],
    unknown_selection_rule_ids: [],
    unknown_override_rule_ids: [],
    ...over,
  };
}

function panel(): HTMLElement {
  const el = document.createElement("div");
  document.body.appendChild(el);
  return el;
}

function pickFile(container: HTMLElement, content: string, name = "playbook.json"): void {
  const input = container.querySelector<HTMLInputElement>('[data-role="playbook-input"]')!;
  const file = new File([content], name, { type: "application/json" });
  Object.defineProperty(input, "files", { configurable: true, get: () => [file] });
  input.dispatchEvent(new Event("change"));
}

const flush = (): Promise<void> => new Promise((r) => setTimeout(r, 0));

describe("bindPlaybookPanel", () => {
  it("renders the load affordance", () => {
    const el = panel();
    bindPlaybookPanel(el, { onActiveChange: () => {} });
    expect(el.querySelector('[data-role="playbook-load"]')).not.toBeNull();
    expect(el.querySelector('[data-role="playbook-input"]')).not.toBeNull();
  });

  it("shows validation errors and does not activate a bad playbook", async () => {
    const el = panel();
    const changes: Array<LoadedPlaybook | null> = [];
    const validate = vi.fn(
      (): PlaybookValidationResult => ({ ok: false, errors: ["id: Required", "name: Required"] }),
    );
    bindPlaybookPanel(el, { onActiveChange: (p) => changes.push(p), validate });
    pickFile(el, "{}");
    await flush();
    const errs = el.querySelectorAll('[data-role="playbook-errors"] li');
    expect(errs).toHaveLength(2);
    expect(changes).toEqual([null]);
  });

  it("renders a preview and activates the playbook on a valid load", async () => {
    const el = panel();
    const changes: Array<LoadedPlaybook | null> = [];
    const validate = vi.fn(
      (): PlaybookValidationResult => ({
        ok: true,
        playbook: loaded("augment"),
        preview: makePreview(),
      }),
    );
    bindPlaybookPanel(el, { onActiveChange: (p) => changes.push(p), validate });
    pickFile(el, '{"ok":true}');
    await flush();
    expect(el.querySelector('[data-role="playbook-loaded"]')).not.toBeNull();
    // Activated once with the authored (augment) mode.
    expect(changes).toHaveLength(1);
    expect(changes[0]).toEqual(loaded("augment"));
  });

  it("surfaces warnings for uncited rules + catalog mismatch", async () => {
    const el = panel();
    const validate = vi.fn(
      (): PlaybookValidationResult => ({
        ok: true,
        playbook: loaded("augment"),
        preview: makePreview({
          catalog_version_mismatch: true,
          uncited_custom_rule_ids: ["T-1"],
          unknown_selection_rule_ids: ["NOPE-9"],
        }),
      }),
    );
    bindPlaybookPanel(el, { onActiveChange: () => {}, validate });
    pickFile(el, "{}");
    await flush();
    const warnings = el.querySelector('[data-role="playbook-warnings"]')!;
    expect(warnings.textContent).toMatch(/uncited/i);
    expect(warnings.textContent).toMatch(/different catalog version/i);
    expect(warnings.textContent).toMatch(/NOPE-9/);
  });

  it("re-notifies with replace mode when the radio is switched", async () => {
    const el = panel();
    const changes: Array<LoadedPlaybook | null> = [];
    const validate = vi.fn(
      (): PlaybookValidationResult => ({
        ok: true,
        playbook: loaded("augment"),
        preview: makePreview({ mode: "augment" }),
      }),
    );
    bindPlaybookPanel(el, { onActiveChange: (p) => changes.push(p), validate });
    pickFile(el, "{}");
    await flush();
    const replaceRadio = el.querySelector<HTMLInputElement>('[data-role="mode-replace"]')!;
    replaceRadio.checked = true;
    replaceRadio.dispatchEvent(new Event("change"));
    expect(changes[changes.length - 1]).toEqual(loaded("replace"));
  });

  it("clears the active playbook on Clear", async () => {
    const el = panel();
    const changes: Array<LoadedPlaybook | null> = [];
    const validate = vi.fn(
      (): PlaybookValidationResult => ({
        ok: true,
        playbook: loaded("augment"),
        preview: makePreview(),
      }),
    );
    bindPlaybookPanel(el, { onActiveChange: (p) => changes.push(p), validate });
    pickFile(el, "{}");
    await flush();
    const clearBtn = el.querySelector<HTMLButtonElement>('[data-role="playbook-clear"]')!;
    clearBtn.dispatchEvent(new MouseEvent("click"));
    expect(changes[changes.length - 1]).toBeNull();
  });
});
