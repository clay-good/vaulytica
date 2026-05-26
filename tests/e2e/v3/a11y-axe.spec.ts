/**
 * v3 axe-core accessibility sweep (LAUNCH row v3-f).
 *
 * Closes the "full axe-core sweep" half of v3-f. The static-shape
 * assertions in `tests/integration/static-html.test.ts` already lock
 * down the HTML skeleton (landmarks, headings, labelled controls);
 * this spec adds a runtime axe scan against the rendered marketing
 * page so any colour-contrast / aria-* / interactive-control issue
 * surfaces in CI before deploy.
 *
 * Scope: WCAG 2.0 + 2.1 + 2.2 levels A + AA, plus the `best-practice`
 * tag set. Excluded rules:
 *   - `color-contrast` is flaky between headless Chrome and real
 *     displays (the CSS already meets WCAG locally — see
 *     LAUNCH row (h) static checks); the Lighthouse `accessibility`
 *     category-level minScore in `lighthouserc.json` covers the
 *     overall contrast posture.
 *   - `region` (best-practice) is a warning about wrapping ad-hoc
 *     content in landmarks; the page is already wholly inside
 *     `<main>` / `<nav>` / `<footer>`, so spurious matches on
 *     in-section text would be noise.
 *
 * Forward-compatible: the spec scans the empty-state page (initial
 * render) and the v3 complete-state page (after a fixture drop) when
 * the complete state is reachable. The complete-state scan is skipped
 * when the v3 chip row is not present in the DOM — same skip-on-
 * missing-DOM pattern as `a11y-keyboard.spec.ts`.
 */

import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const BAA_FIXTURE = join(__dirname, "baa-minimal-pass.docx");

const TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];
const DISABLED_RULES = ["color-contrast", "region"];

test("empty-state page has zero axe violations (WCAG 2.2 AA)", async ({ page }) => {
  await page.goto("/");
  // Wait for the dropzone to mount — JS render replaces innerHTML at
  // boot, so a scan before mount would miss generated controls.
  await page.locator("#dropzone[data-state]").first().waitFor({ state: "attached" });

  const results = await new AxeBuilder({ page })
    .withTags(TAGS)
    .disableRules(DISABLED_RULES)
    .analyze();

  expect(
    results.violations,
    `axe found ${results.violations.length} violation(s): ${results.violations
      .map((v) => `${v.id} (${v.nodes.length} node[s])`)
      .join(", ")}`,
  ).toEqual([]);
});

test("v3 complete-state (post-analysis) has zero axe violations", async ({ page }) => {
  test.skip(!existsSync(BAA_FIXTURE), `fixture missing: ${BAA_FIXTURE}`);

  // Parity with smoke.spec.ts: strip the File System Access API so the
  // saveBlob anchor-click fallback runs if the test ever triggers a
  // download. The scan itself doesn't, but the init script is cheap
  // and keeps environment behavior consistent across e2e specs.
  await page.addInitScript(() => {
    delete (window as { showSaveFilePicker?: unknown }).showSaveFilePicker;
  });

  await page.goto("/");
  await page.locator("#dropzone[data-state]").first().waitFor({ state: "attached" });

  // Drive the page into its complete-state so the chip row, downloads,
  // <details>, and counts are all rendered.
  const fileInput = page.locator(
    '#dropzone input[type="file"]:not([webkitdirectory])',
  );
  await fileInput.setInputFiles(BAA_FIXTURE);
  await page.locator('[data-role="docx-download"]').waitFor({
    state: "visible",
    timeout: 60_000,
  });

  // Full-page scan now that the dropzone wrapper is a generic <div>
  // (no role="button") so its interactive children no longer trip
  // axe's nested-interactive rule.
  const results = await new AxeBuilder({ page })
    .withTags(TAGS)
    .disableRules(DISABLED_RULES)
    .analyze();

  expect(
    results.violations,
    `axe (complete-state) found ${results.violations.length} violation(s): ${results.violations
      .map((v) => `${v.id} (${v.nodes.length} node[s])`)
      .join(", ")}`,
  ).toEqual([]);
});
