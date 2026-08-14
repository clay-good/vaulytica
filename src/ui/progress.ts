/**
 * Horizontal progress bar. The host page renders the static markup;
 * this module mutates `--progress` on the host element so CSS
 * transitions handle the visual interpolation.
 *
 * The bar shows fractional progress through the rule engine: after
 * each rule completes, the runner reports a value in [0, 1].
 */

export type ProgressBar = {
  set(fraction: number): void;
  reset(): void;
  destroy(): void;
};

export function createProgressBar(host: HTMLElement): ProgressBar {
  const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
  if (reduce) host.style.setProperty("--progress-transition", "none");
  return {
    set(fraction: number) {
      // A non-finite fraction (a NaN from an upstream `n / 0` page-count, or
      // ±Infinity) survives Math.max/min unchanged, leaving `aria-valuenow`
      // and the `--progress` CSS var as the literal "NaN" — an invalid ARIA
      // value and a broken bar. Treat any non-finite input as 0.
      const clamped = Number.isFinite(fraction) ? Math.max(0, Math.min(1, fraction)) : 0;
      host.style.setProperty("--progress", `${(clamped * 100).toFixed(2)}%`);
      host.setAttribute("aria-valuenow", `${Math.round(clamped * 100)}`);
    },
    reset() {
      host.style.setProperty("--progress", "0%");
      host.setAttribute("aria-valuenow", "0");
    },
    destroy() {
      host.style.removeProperty("--progress");
      host.style.removeProperty("--progress-transition");
      host.removeAttribute("aria-valuenow");
    },
  };
}
