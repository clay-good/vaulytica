/**
 * The results page in the real tab (add-results-page). The legend NDA is
 * pasted the way a user pastes it; the page must say "6 things to raise", open
 * a row in place to its evidence, save nothing on its own, send nothing
 * anywhere, and fit a 360 px phone without scrolling sideways.
 */
import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const NDA = join(__dirname, "..", "fixtures", "specimens", "legend-nda.txt");

for (const width of [1280, 360]) {
  test(`the pasted NDA's results page at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    const pageOrigin = new URL(testInfo.project.use.baseURL ?? "http://127.0.0.1").origin;
    const external: string[] = [];
    page.on("request", (req) => {
      const u = new URL(req.url());
      if (u.origin !== pageOrigin && u.protocol !== "data:" && u.protocol !== "blob:") {
        external.push(req.url());
      }
    });
    const downloads: string[] = [];
    page.on("download", (d) => downloads.push(d.suggestedFilename()));

    await page.goto("/");
    await page.locator('[data-role="paste-open"]').click();
    await page.locator("#paste-text").fill(readFileSync(NDA, "utf8"));
    await page.locator('[data-role="paste-submit"]').click();

    const headline = page.locator('[data-role="results-headline"]');
    await headline.waitFor({ state: "visible", timeout: 60_000 });
    await expect(headline).toHaveText("6 things to raise before you sign");
    // The pasted-text notice is above the headline.
    const above = await page.evaluate(() => {
      const notice = document.querySelector('[data-role="input-notice"]')!;
      const head = document.querySelector('[data-role="results-headline"]')!;
      return Boolean(notice.compareDocumentPosition(head) & Node.DOCUMENT_POSITION_FOLLOWING);
    });
    expect(above).toBe(true);

    const rows = page.locator('[data-role="results-todo"] [data-role="result-row"]');
    await expect(rows).toHaveCount(6);
    const row = rows.filter({ hasText: "consent-to-assignment" });
    await row.click();
    await expect(row).toHaveAttribute("aria-expanded", "true");
    const detail = page.locator(`#${await row.getAttribute("aria-controls")}`);
    await expect(detail).toBeVisible();
    await expect(detail).toContainText("Not in the document: (clause absent from the document)");
    await expect(detail).toContainText("Suggested change: Add:");
    await expect(detail.locator(".result-quote")).toHaveCount(0);
    // Opening a row is not a request for another file.
    await expect(page.locator("#dropzone")).toHaveAttribute("data-state", "complete");

    await expect(page.locator('[data-role="also-noted-summary"]')).toHaveText("Also noted (2)");
    // A fold with nothing in it is not shown (no custom playbook was loaded).
    await expect(page.locator('[data-role="negotiation-fold"]')).toBeHidden();
    await expect(page.locator('[data-role="dates-fold"]')).toBeVisible();
    const terms = page.locator('[data-role="key-terms"]');
    await expect(terms).toContainText("Signed by");
    await expect(terms).toContainText("Not found in the text");

    expect(downloads, "nothing is saved without a click").toEqual([]);
    expect(external, "expected zero cross-origin requests").toEqual([]);
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    expect(overflow, "no horizontal scroll").toBeLessThanOrEqual(0);
  });
}
