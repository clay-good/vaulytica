import { describe, expect, it } from "vitest";

import { bindEstatePanel, ESTATE_STATE_CHOICES, type EstateAssertion } from "./estate-panel.js";
import { US_STATE_CODES } from "../dkb/estate-formalities.js";

function panel(): HTMLElement {
  const el = document.createElement("div");
  document.body.appendChild(el);
  return el;
}

function toggle(el: HTMLElement, checked: boolean): void {
  const box = el.querySelector<HTMLInputElement>('[data-role="estate-toggle"]')!;
  box.checked = checked;
  box.dispatchEvent(new Event("change"));
}

function pickState(el: HTMLElement, value: string): void {
  const sel = el.querySelector<HTMLSelectElement>('[data-role="estate-state"]')!;
  sel.value = value;
  sel.dispatchEvent(new Event("change"));
}

describe("bindEstatePanel", () => {
  it("offers exactly the 50 states + DC — the hand-copied list cannot drift", () => {
    expect(ESTATE_STATE_CHOICES.map((c) => c.id).sort()).toEqual(
      US_STATE_CODES.map((c) => `us-${c}`).sort(),
    );
  });

  it("renders with nothing asserted by default", () => {
    const el = panel();
    bindEstatePanel(el, { onChange: () => {} });
    expect(el.querySelector<HTMLInputElement>('[data-role="estate-toggle"]')!.checked).toBe(false);
    expect(el.querySelector<HTMLSelectElement>('[data-role="estate-state"]')!.value).toBe("");
    document.body.removeChild(el);
  });

  it("asserts the checks via the checkbox, and clears on uncheck", () => {
    const el = panel();
    const seen: EstateAssertion[] = [];
    bindEstatePanel(el, { onChange: (a) => seen.push(a) });
    toggle(el, true);
    expect(seen[seen.length - 1]).toEqual({ checks: true });
    toggle(el, false);
    expect(seen[seen.length - 1]).toEqual({ checks: false });
    document.body.removeChild(el);
  });

  it("selecting a state implies the checks and locks the checkbox", () => {
    const el = panel();
    const seen: EstateAssertion[] = [];
    bindEstatePanel(el, { onChange: (a) => seen.push(a) });
    pickState(el, "us-pa");
    expect(seen[seen.length - 1]).toEqual({ checks: true, state: "us-pa" });
    const box = el.querySelector<HTMLInputElement>('[data-role="estate-toggle"]')!;
    expect(box.checked).toBe(true);
    expect(box.disabled).toBe(true);
    document.body.removeChild(el);
  });

  it("clearing the state unlocks the checkbox and keeps its assertion", () => {
    const el = panel();
    const seen: EstateAssertion[] = [];
    bindEstatePanel(el, { onChange: (a) => seen.push(a) });
    pickState(el, "us-la");
    pickState(el, "");
    const last = seen[seen.length - 1]!;
    expect(last.state).toBeUndefined();
    // The checkbox stays checked (it was implied on) but is editable again.
    expect(last.checks).toBe(true);
    expect(el.querySelector<HTMLInputElement>('[data-role="estate-toggle"]')!.disabled).toBe(false);
    document.body.removeChild(el);
  });

  it("unbind clears the container", () => {
    const el = panel();
    const unbind = bindEstatePanel(el, { onChange: () => {} });
    unbind();
    expect(el.innerHTML).toBe("");
    document.body.removeChild(el);
  });
});
