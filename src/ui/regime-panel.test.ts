import { describe, expect, it } from "vitest";

import { bindRegimePanel, REGIME_CHOICES } from "./regime-panel.js";
import { REGIME_IDS } from "../privacy/regime-data.js";

function panel(): HTMLElement {
  const el = document.createElement("div");
  document.body.appendChild(el);
  return el;
}

function check(el: HTMLElement, id: string, checked = true): void {
  const box = [...el.querySelectorAll<HTMLInputElement>('[data-role="regime-choice"]')].find(
    (b) => b.value === id,
  )!;
  box.checked = checked;
  box.dispatchEvent(new Event("change"));
}

describe("bindRegimePanel", () => {
  it("offers exactly the shipped regimes — the hand-copied list cannot drift", () => {
    expect(REGIME_CHOICES.map((c) => c.id)).toEqual([...REGIME_IDS]);
  });

  it("renders one checkbox per regime, none asserted by default", () => {
    const el = panel();
    bindRegimePanel(el, { onChange: () => {} });
    const boxes = el.querySelectorAll<HTMLInputElement>('[data-role="regime-choice"]');
    expect(boxes).toHaveLength(REGIME_CHOICES.length);
    expect([...boxes].every((b) => !b.checked)).toBe(true);
    document.body.removeChild(el);
  });

  it("reports the asserted regimes sorted, and removal on uncheck", () => {
    const el = panel();
    const seen: Array<readonly string[]> = [];
    bindRegimePanel(el, { onChange: (r) => seen.push(r) });
    check(el, "tx");
    check(el, "ccpa");
    expect(seen[seen.length - 1]).toEqual(["ccpa", "tx"]);
    check(el, "tx", false);
    expect(seen[seen.length - 1]).toEqual(["ccpa"]);
    document.body.removeChild(el);
  });

  it("cleanup empties the container", () => {
    const el = panel();
    const unbind = bindRegimePanel(el, { onChange: () => {} });
    unbind();
    expect(el.innerHTML).toBe("");
    document.body.removeChild(el);
  });
});
