import { describe, expect, it } from "vitest";
import { createProgressBar } from "./progress.js";
import { createRuleTicker } from "./ticker.js";

describe("createProgressBar", () => {
  it("sets --progress and aria-valuenow on .set()", () => {
    const el = document.createElement("div");
    const bar = createProgressBar(el);
    bar.set(0.5);
    expect(el.style.getPropertyValue("--progress")).toBe("50.00%");
    expect(el.getAttribute("aria-valuenow")).toBe("50");
    bar.set(1.4); // clamped
    expect(el.style.getPropertyValue("--progress")).toBe("100.00%");
    expect(el.getAttribute("aria-valuenow")).toBe("100");
    bar.set(-1); // clamped
    expect(el.style.getPropertyValue("--progress")).toBe("0.00%");
  });

  it(".reset() returns to 0", () => {
    const el = document.createElement("div");
    const bar = createProgressBar(el);
    bar.set(0.7);
    bar.reset();
    expect(el.style.getPropertyValue("--progress")).toBe("0%");
  });
});

describe("createRuleTicker", () => {
  it("appends lines and caps visible count", () => {
    const el = document.createElement("div");
    const t = createRuleTicker(el);
    for (let i = 0; i < 12; i++) t.push(`R-${i}`, `Rule ${i}`);
    expect(el.children.length).toBeLessThanOrEqual(8);
    expect(el.lastChild?.textContent).toContain("R-11");
  });

  it("sets aria-live polite on the host", () => {
    const el = document.createElement("div");
    createRuleTicker(el);
    expect(el.getAttribute("role")).toBe("log");
    expect(el.getAttribute("aria-live")).toBe("polite");
  });

  it("clear() empties the host", () => {
    const el = document.createElement("div");
    const t = createRuleTicker(el);
    t.push("X-001", "x");
    t.clear();
    expect(el.children.length).toBe(0);
  });
});
