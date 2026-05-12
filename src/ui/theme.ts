/**
 * Light/dark theme toggle. Refactored from the inline IIFE in
 * `site/index.html` so the rest of the UI can share the same
 * localStorage key and `data-theme` attribute contract.
 */

export type Theme = "light" | "dark";

const STORAGE_KEY = "vaulytica-theme";

export function readPersistedTheme(): Theme | undefined {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v === "light" || v === "dark") return v;
  } catch {
    /* ignore storage exceptions (private mode, etc.) */
  }
  return undefined;
}

export function persistTheme(theme: Theme): void {
  try {
    localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    /* ignore */
  }
}

export function applyTheme(root: HTMLElement, theme: Theme): void {
  root.setAttribute("data-theme", theme);
}

export function currentTheme(root: HTMLElement): Theme {
  return root.getAttribute("data-theme") === "light" ? "light" : "dark";
}

export function bindThemeToggle(root: HTMLElement, button: HTMLElement): () => void {
  const handler = (): void => {
    const next: Theme = currentTheme(root) === "light" ? "dark" : "light";
    applyTheme(root, next);
    persistTheme(next);
  };
  button.addEventListener("click", handler);
  return () => button.removeEventListener("click", handler);
}
