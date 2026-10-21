/** The tab's readability-statute selector (add-readability-measure, task 4). */
import { describe, expect, it, vi } from "vitest";
import { READABILITY_STANDARDS } from "../readability/standards.js";
import { READABILITY_CHOICES, bindReadabilityPanel } from "./readability-panel.js";

describe("readability panel", () => {
  it("offers exactly the standards the table holds", () => {
    expect(READABILITY_CHOICES.map((c) => c.id)).toEqual(READABILITY_STANDARDS.map((s) => s.id));
  });

  it("asserts nothing by default, and reports a chosen statute", () => {
    const host = document.createElement("div");
    const onChange = vi.fn();
    bindReadabilityPanel(host, { onChange });
    const select = host.querySelector<HTMLSelectElement>('[data-role="readability-standard"]')!;
    expect(select.value).toBe("");
    select.value = "fl";
    select.dispatchEvent(new Event("change"));
    expect(onChange).toHaveBeenLastCalledWith("fl");
    select.value = "";
    select.dispatchEvent(new Event("change"));
    expect(onChange).toHaveBeenLastCalledWith(undefined);
  });
});
