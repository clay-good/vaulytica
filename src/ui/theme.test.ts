import { describe, expect, it } from "vitest";
import { applyTheme, bindThemeToggle, currentTheme } from "./theme.js";

describe("theme", () => {
  it("applyTheme sets data-theme on the root", () => {
    const root = document.createElement("html");
    applyTheme(root, "light");
    expect(root.getAttribute("data-theme")).toBe("light");
  });

  it("currentTheme defaults to 'dark' when the attribute is missing", () => {
    const root = document.createElement("html");
    expect(currentTheme(root)).toBe("dark");
  });

  it("bindThemeToggle flips light↔dark on click", () => {
    const root = document.createElement("html");
    applyTheme(root, "light");
    const button = document.createElement("button");
    bindThemeToggle(root, button);
    button.click();
    expect(currentTheme(root)).toBe("dark");
    button.click();
    expect(currentTheme(root)).toBe("light");
  });
});
