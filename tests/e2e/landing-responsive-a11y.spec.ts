/**
 * The full marketing landing page is responsive and WCAG 2 AA — in both
 * themes (spec-v7 Part XVI; complements `v3/a11y-axe.spec.ts`).
 *
 * The live `a11y-axe.spec.ts` scans the deployed page but **disables the
 * `color-contrast` and `region` rules** and only runs the default (dark)
 * theme. So the marketing page's contrast — across both themes, and across
 * all its static content (hero, feature sections, FAQ, footer) — was never
 * gated. This spec renders the real `site/index.html` via `page.setContent`
 * (no server) with **color-contrast enabled**, pins each theme
 * deterministically via the `data-theme` attribute, and asserts: no
 * horizontal overflow at 320 / 390 / 768 / 1280 px, and zero axe violations.
 * Deterministic (static colours, no network).
 */

import { test, expect, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const LANDING_HTML = readFileSync(join(__dirname, "..", "..", "site", "index.html"), "utf8");

const BREAKPOINTS = [
  { label: "320px", width: 320, height: 720 },
  { label: "390px", width: 390, height: 844 },
  { label: "768px", width: 768, height: 1024 },
  { label: "1280px", width: 1280, height: 800 },
];

/**
 * Load the landing page pinned to a theme. The inline theme-init script
 * would otherwise re-pick the theme from `prefers-color-scheme` at parse
 * time (non-deterministic across runners), so we strip that one bare inline
 * `<script>` and set `data-theme` directly — the same attribute the script
 * and the in-app toggle set, so the rendered palette is identical to the
 * real app, just deterministically chosen.
 */
async function loadLanding(page: Page, theme: "dark" | "light"): Promise<void> {
  const html = LANDING_HTML.replace(/<script>[\s\S]*?<\/script>/, "").replace(
    /<html([^>]*?)\sdata-theme="[^"]*"/,
    `<html$1 data-theme="${theme}"`,
  );
  await page.setContent(html, { waitUntil: "domcontentloaded" });
}

for (const theme of ["dark", "light"] as const) {
  test(`landing page scrolls vertically only — ${theme} theme`, async ({ page }) => {
    await loadLanding(page, theme);
    for (const bp of BREAKPOINTS) {
      await page.setViewportSize({ width: bp.width, height: bp.height });
      await page.evaluate(() => new Promise<void>((r) => requestAnimationFrame(() => r())));
      const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
      );
      expect(
        overflow,
        `landing (${theme}) overflows horizontally by ${overflow}px at ${bp.label}`,
      ).toBeLessThanOrEqual(1);
    }
  });

  test(`landing page has zero axe violations (WCAG 2 AA) — ${theme} theme`, async ({ page }) => {
    await loadLanding(page, theme);
    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
      .analyze();
    expect(
      results.violations,
      `axe found ${results.violations.length} violation(s) (${theme}): ${results.violations
        .map((v) => `${v.id} (${v.nodes.length}: ${v.nodes[0]?.target})`)
        .join("; ")}`,
    ).toEqual([]);
  });
}
