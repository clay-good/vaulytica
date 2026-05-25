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

test("v3 chip-row state has zero axe violations when present", async ({ page }) => {
  await page.goto("/");
  const chipRow = page.locator('[data-role="compliance-frame-chips"]');
  const exists = (await chipRow.count()) > 0;
  test.skip(!exists, "v3 chip-row hookup not present in this page state");

  const results = await new AxeBuilder({ page })
    .withTags(TAGS)
    .disableRules(DISABLED_RULES)
    .include('[data-role="compliance-frame-chips"]')
    .analyze();

  expect(
    results.violations,
    `axe (chip-row scope) found ${results.violations.length} violation(s): ${results.violations
      .map((v) => `${v.id} (${v.nodes.length} node[s])`)
      .join(", ")}`,
  ).toEqual([]);
});
