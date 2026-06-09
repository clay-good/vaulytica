/**
 * The bring-your-own-playbook panel's dynamic sub-states are responsive and
 * WCAG 2 AA in both themes (spec-v6 Part II).
 *
 * The panel (`#playbook-panel`) is populated by JS at runtime into three
 * sub-states — **error** (invalid JSON / schema), **loaded** (a valid
 * playbook preview + enforcement-mode radios), and **warnings** — none of
 * which is part of the `DropzoneState` union the other gates cover, so they
 * were never tested. This matters: the error message tells a user *why* their
 * playbook was rejected, and it rendered in `#b00020` dark-red at ~2.7:1 on
 * the dark theme's near-black surface — barely legible. This spec renders the
 * panel markup (mirroring `src/ui/playbook-panel.ts`) with the real page CSS
 * via `page.setContent` and asserts: no horizontal overflow at 320–1280 px,
 * and zero axe violations, in both themes.
 */

import { test, expect, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PAGE_CSS = (() => {
  const html = readFileSync(join(__dirname, "..", "..", "site", "index.html"), "utf8");
  return html.match(/<style[^>]*>([\s\S]*?)<\/style>/)![1];
})();

// Mirrors `playbook-panel.ts` renderErrors / renderPreview output. The error
// item and a custom-rule id are deliberately long + unbreakable to stress wrap.
const ERROR_STATUS = `
  <div class="playbook-error" role="alert">
    <div class="playbook-error-heading">This playbook is not valid:</div>
    <ul class="playbook-error-list">
      <li>custom_rules.0.assert.metric: invalid_metric_name_that_is_quite_long_and_unbreakable is not a recognized numeric metric</li>
      <li>rule_overrides.NDA-001.severity: expected one of critical | warning | info</li>
    </ul>
  </div>`;

const LOADED_STATUS = `
  <div class="playbook-loaded" data-role="playbook-loaded">
    <div class="playbook-loaded-name"><strong>Acme Corporation Outside-Counsel Data-Processing Standard (rev 2026-Q2)</strong> <span class="playbook-loaded-file">(acme-standard-2026-q2-final.json)</span></div>
    <div class="playbook-loaded-summary">Built-in catalog: <strong>112</strong> rules.<br />Your positions: <strong>4</strong> custom rules, <strong>2</strong> required clauses.</div>
    <ul class="playbook-warnings"><li>Authored for a different catalog version than the running catalog (1.0.0). Some referenced rules may have changed.</li></ul>
    <fieldset class="playbook-mode" data-role="playbook-mode">
      <legend>Enforcement mode</legend>
      <label><input type="radio" name="playbook-mode" value="augment" checked /> Augment — built-in catalog + your positions</label>
      <label><input type="radio" name="playbook-mode" value="replace" /> Replace — only your positions</label>
    </fieldset>
    <button type="button" class="btn-link">Clear playbook</button>
  </div>`;

function pageHtml(statusInner: string, theme: "dark" | "light"): string {
  return [
    "<!doctype html>",
    `<html lang="en" data-theme="${theme}"><head><meta charset="utf-8">`,
    '<meta name="viewport" content="width=device-width, initial-scale=1"><title>Vaulytica</title>',
    `<style>${PAGE_CSS}</style></head><body>`,
    '<main id="main" class="wrap"><div class="playbook-panel" id="playbook-panel" role="group" aria-label="Bring your own playbook">',
    '<button type="button" class="btn-link">Enforce your own playbook…</button>',
    `<div class="playbook-status" aria-live="polite">${statusInner}</div>`,
    "</div></main></body></html>",
  ].join("");
}

const BREAKPOINTS = [320, 390, 768, 1280];

async function expectNoOverflow(page: Page, label: string): Promise<void> {
  for (const width of BREAKPOINTS) {
    await page.setViewportSize({ width, height: 800 });
    await page.evaluate(() => new Promise<void>((r) => requestAnimationFrame(() => r())));
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    expect(overflow, `${label} overflows by ${overflow}px at ${width}px`).toBeLessThanOrEqual(1);
  }
}

const SUBSTATES = [
  { name: "error", status: ERROR_STATUS },
  { name: "loaded", status: LOADED_STATUS },
];

for (const { name, status } of SUBSTATES) {
  for (const theme of ["dark", "light"] as const) {
    test(`playbook panel ${name} sub-state — responsive (${theme})`, async ({ page }) => {
      await page.setContent(pageHtml(status, theme));
      await expectNoOverflow(page, `${name}/${theme}`);
    });

    test(`playbook panel ${name} sub-state — zero axe violations (${theme})`, async ({ page }) => {
      await page.setContent(pageHtml(status, theme));
      const results = await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
        .analyze();
      expect(
        results.violations,
        `axe found ${results.violations.length} in ${name}/${theme}: ${results.violations
          .map((v) => `${v.id} (${v.nodes.length})`)
          .join("; ")}`,
      ).toEqual([]);
    });
  }
}
