/**
 * The results page for several documents and for two versions
 * (extend-results-page-to-bundles-and-comparisons), in the real tab at phone
 * width: one count everywhere, rows that open in place, nothing saved without a
 * click, nothing sent anywhere, and no sideways scroll.
 */
import { test, expect, type Page } from "@playwright/test";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const BUNDLE = join(__dirname, "sample-docs", "bundle");
const DPA = join(BUNDLE, "data-processing-addendum.docx");
const MSA = join(BUNDLE, "master-services-agreement.docx");
const singleFileInput = '#dropzone input[type="file"]:not([webkitdirectory])';

function guard(page: Page, baseURL: string | undefined) {
  const origin = new URL(baseURL ?? "http://127.0.0.1").origin;
  const external: string[] = [];
  const downloads: string[] = [];
  page.on("request", (req) => {
    const u = new URL(req.url());
    if (u.origin !== origin && u.protocol !== "data:" && u.protocol !== "blob:") {
      external.push(req.url());
    }
  });
  page.on("download", (d) => downloads.push(d.suggestedFilename()));
  return { external, downloads };
}

async function noSidewaysScroll(page: Page): Promise<void> {
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(overflow, "no horizontal scroll").toBeLessThanOrEqual(0);
}

const countIn = (text: string | null): number =>
  Number(/(\d+) things? to raise/.exec(text ?? "")?.[1]);

test.beforeEach(async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 900 });
});

test("a DPA and an MSA: conflicts first, then each document's own page", async ({
  page,
}, testInfo) => {
  const seen = guard(page, testInfo.project.use.baseURL);
  await page.goto("/");

  // The DPA alone, for its own count.
  await page.locator(singleFileInput).setInputFiles(DPA);
  const headline = page.locator('[data-role="results-headline"]');
  await headline.waitFor({ state: "visible", timeout: 60_000 });
  const alone = countIn(await headline.textContent());
  expect(alone).toBeGreaterThan(0);

  await page.goto("/");
  await page.locator(singleFileInput).setInputFiles([DPA, MSA]);
  await expect(headline).toContainText("across 2 documents", { timeout: 120_000 });

  const docRows = page.locator('[data-role="results-documents"] > li > [data-role="result-row"]');
  await expect(docRows).toHaveCount(2);
  const dpaRow = docRows.filter({ hasText: "data-processing-addendum.docx" });
  await expect(dpaRow).toContainText(`${alone} to raise`);

  // Opening a document's row shows that document's own page, in place.
  await dpaRow.click();
  const detail = page.locator(`#${await dpaRow.getAttribute("aria-controls")}`);
  await expect(detail).toBeVisible();
  await expect(detail.locator(".results-headline--nested")).toHaveText(
    `${alone} things to raise before you sign`,
  );
  await expect(page.locator("#dropzone")).toHaveAttribute("data-state", "bundle-complete");

  expect(seen.downloads, "nothing is saved without a click").toEqual([]);
  expect(seen.external, "expected zero cross-origin requests").toEqual([]);
  await noSidewaysScroll(page);
});

test("a document compared against itself: nothing added or resolved, its own count open", async ({
  page,
}, testInfo) => {
  const seen = guard(page, testInfo.project.use.baseURL);
  await page.goto("/");
  await page.locator(singleFileInput).setInputFiles(DPA);
  const headline = page.locator('[data-role="results-headline"]');
  await headline.waitFor({ state: "visible", timeout: 60_000 });
  const alone = countIn(await headline.textContent());

  await page.locator('[data-role="compare-input"]').setInputFiles(DPA);
  await expect(page.locator("#dropzone")).toHaveAttribute("data-state", "comparison-complete", {
    timeout: 60_000,
  });
  await expect(headline).toHaveText(`The revision added 0, resolved 0, left ${alone} open`);

  const first = page.locator('[data-role="results-open"] [data-role="result-row"]').first();
  await first.click();
  await expect(page.locator(`#${await first.getAttribute("aria-controls")}`)).toBeVisible();

  expect(seen.downloads, "nothing is saved without a click").toEqual([]);
  expect(seen.external, "expected zero cross-origin requests").toEqual([]);
  await noSidewaysScroll(page);
});
