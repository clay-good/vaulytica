/**
 * The results page for several documents and for two versions
 * (extend-results-page-to-bundles-and-comparisons), in the real tab at phone
 * width: one count everywhere, rows that open in place, nothing saved without a
 * click, nothing sent anywhere, and no sideways scroll.
 */
import { test, expect, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { redlineDocx } from "../../src/delivery/_fixtures.js";

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

test("a Word redline compares both of its readings, and names who wrote the change", async ({
  page,
}, testInfo) => {
  // add-redline-two-sided-analysis task 6: the tab's affordance on a DOCX
  // with tracked changes is the CLI's `compare --redline` on the same bytes.
  const seen = guard(page, testInfo.project.use.baseURL);
  // Take the plain download path so the saved JSON can be read.
  await page.addInitScript(() => {
    delete (window as { showSaveFilePicker?: unknown }).showSaveFilePicker;
  });
  await page.goto("/");
  await page.locator(singleFileInput).setInputFiles({
    name: "supply-redline.docx",
    mimeType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    buffer: Buffer.from(redlineDocx()),
  });
  const button = page.locator('[data-role="compare-redline-button"]');
  await button.waitFor({ state: "visible", timeout: 60_000 });
  await button.click();
  await expect(page.locator("#dropzone")).toHaveAttribute("data-state", "comparison-complete", {
    timeout: 60_000,
  });
  await expect(page.locator('[data-role="comparison-versions"]')).toHaveText(
    "Base: supply-redline.docx (every change rejected) → Revised: supply-redline.docx (every change accepted)",
  );
  // Striking the liability cap is what the markup added.
  await expect(page.locator('[data-role="results-headline"]')).toHaveText(
    /^The revision added [1-9]\d*, resolved \d+, left \d+ open$/,
  );

  expect(seen.downloads, "nothing is saved without a click").toEqual([]);

  // The comparison data names the author of the inserted, uncapped indemnity.
  await page.locator('[data-role="download-fold"] > summary').click();
  await page.locator('[data-role="other-formats"] > summary').click();
  const [d] = await Promise.all([
    page.waitForEvent("download"),
    page.locator('[data-role="comparison-json-download"]').click(),
  ]);
  const json = JSON.parse(readFileSync((await d.path())!, "utf8")) as {
    revision_authors?: Record<string, string[]>;
  };
  expect(Object.values(json.revision_authors ?? {}).flat()).toContain("Opposing Counsel");

  expect(seen.external, "expected zero cross-origin requests").toEqual([]);
  await noSidewaysScroll(page);
});

test("a document with no tracked changes offers no redline comparison", async ({ page }) => {
  await page.goto("/");
  await page.locator(singleFileInput).setInputFiles(DPA);
  await page
    .locator('[data-role="results-headline"]')
    .waitFor({ state: "visible", timeout: 60_000 });
  await expect(page.locator('[data-role="compare-button"]')).toBeVisible();
  await expect(page.locator('[data-role="compare-redline-button"]')).toBeHidden();
});
