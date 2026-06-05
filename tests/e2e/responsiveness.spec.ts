/**
 * Responsiveness-as-a-test (spec-v7 Part XVI / Step 125).
 *
 * Turns the recurring manual responsiveness audit into a CI gate: at
 * 320 / 390 / 768 / 1280 px, no rendered view-state may overflow
 * horizontally — `document.documentElement.scrollWidth` must not exceed
 * `clientWidth` (the page scrolls vertically only). A coarse oracle by
 * design (it catches overflow, not ugliness), kept alongside the
 * periodic visual audit per spec-v7 Open Question #7.
 *
 * Covers the reliably-reachable, highest-traffic states using the same
 * proven flow as `tests/e2e/v3/a11y-axe.spec.ts`: the landing page +
 * empty app state (initial render) and the complete state (after a
 * fixture drop). The comparison / bundle / error states stay covered by
 * the periodic visual audit (their flows are not pinned here).
 */

import { test, expect, type Page } from "@playwright/test";
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const BAA_FIXTURE = join(__dirname, "v3", "baa-minimal-pass.docx");

/** Breakpoints: small phone, modern phone, tablet, desktop. */
const BREAKPOINTS = [
  { label: "320px (small phone)", width: 320, height: 720 },
  { label: "390px (modern phone)", width: 390, height: 844 },
  { label: "768px (tablet)", width: 768, height: 1024 },
  { label: "1280px (desktop)", width: 1280, height: 800 },
];

/** Assert no horizontal overflow at each breakpoint (1px sub-pixel tolerance). */
async function expectNoHorizontalOverflow(page: Page, state: string): Promise<void> {
  for (const bp of BREAKPOINTS) {
    await page.setViewportSize({ width: bp.width, height: bp.height });
    // Let layout settle after the resize before measuring.
    await page.evaluate(
      () => new Promise<void>((r) => requestAnimationFrame(() => r())),
    );
    const overflow = await page.evaluate(() => {
      const el = document.documentElement;
      return el.scrollWidth - el.clientWidth;
    });
    expect(
      overflow,
      `${state} overflows horizontally by ${overflow}px at ${bp.label}`,
    ).toBeLessThanOrEqual(1);
  }
}

test("landing + empty app state never overflow horizontally", async ({ page }) => {
  await page.goto("/");
  await page.locator("#dropzone[data-state]").first().waitFor({ state: "attached" });
  await expectNoHorizontalOverflow(page, "empty state");
});

test("complete state (post-analysis) never overflows horizontally", async ({ page }) => {
  test.skip(!existsSync(BAA_FIXTURE), `fixture missing: ${BAA_FIXTURE}`);

  await page.addInitScript(() => {
    delete (window as { showSaveFilePicker?: unknown }).showSaveFilePicker;
  });

  await page.goto("/");
  await page.locator("#dropzone[data-state]").first().waitFor({ state: "attached" });

  const fileInput = page.locator('#dropzone input[type="file"]:not([webkitdirectory])');
  await fileInput.setInputFiles(BAA_FIXTURE);
  await page.locator('[data-role="docx-download"]').waitFor({
    state: "visible",
    timeout: 60_000,
  });

  await expectNoHorizontalOverflow(page, "complete state");
});
