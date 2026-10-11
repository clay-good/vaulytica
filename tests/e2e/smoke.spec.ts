/**
 * Post-deploy smoke test for Vaulytica (spec §26 step 14).
 *
 * Loads the marketing page, drops a fixture contract onto the
 * dropzone, waits for the "Download report (Word)" button, downloads
 * the file, and verifies it is a valid OOXML zip (PK\x03\x04 magic
 * bytes + non-zero size).
 *
 * The fixture path defaults to `tests/fixtures/contracts/mutual-nda.docx`
 * (Step 16 fixture). For CI runs before Step 16 lands, set
 * `VAULYTICA_E2E_FIXTURE` to any committed .docx or .pdf path.
 */

import { test, expect } from "@playwright/test";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

const FIXTURE = process.env.VAULYTICA_E2E_FIXTURE
  ? join(process.cwd(), process.env.VAULYTICA_E2E_FIXTURE)
  : join(__dirname, "..", "fixtures", "contracts", "mutual-nda.docx");

test("drop-zone → analyze → DOCX download path is intact", async ({ page }, testInfo) => {
  test.skip(!existsSync(FIXTURE), `fixture missing: ${FIXTURE}`);

  // Confirm zero outbound requests during analysis (the privacy promise).
  // Compare against the configured baseURL rather than `page.url()` —
  // the latter is "about:blank" for the very first navigation, which
  // would mis-classify the initial document request as cross-origin.
  const baseURL =
    process.env.VAULYTICA_E2E_BASE_URL ??
    `http://127.0.0.1:${process.env.VAULYTICA_E2E_PORT ?? "4173"}`;
  const pageOrigin = new URL(baseURL).origin;
  const externalRequests: string[] = [];
  page.on("request", (req) => {
    const u = new URL(req.url());
    if (u.origin !== pageOrigin && u.protocol !== "data:" && u.protocol !== "blob:") {
      externalRequests.push(req.url());
    }
  });

  // The production saveBlob path prefers `window.showSaveFilePicker`
  // (File System Access API) when present; in headless Chromium that
  // path can't render a system file picker and never fires a browser
  // `download` event. Strip it before page load so the anchor-click
  // fallback runs and Playwright can intercept the download.
  await page.addInitScript(() => {
    delete (window as { showSaveFilePicker?: unknown }).showSaveFilePicker;
  });

  await page.goto("/");
  await expect(page.locator("#dropzone")).toBeVisible();

  // Find the hidden file input bindDropzone injects. v4 added a
  // second `webkitdirectory` input for folder-pick, so we scope to
  // the multi-file (non-directory) one.
  const fileInput = page.locator('#dropzone input[type="file"]:not([webkitdirectory])');
  await fileInput.setInputFiles(FIXTURE);

  const downloadButton = page.locator('[data-role="docx-download"]');
  await downloadButton.waitFor({ state: "visible", timeout: 60_000 });

  const [download] = await Promise.all([page.waitForEvent("download"), downloadButton.click()]);
  const path = await download.path();
  expect(path).toBeTruthy();
  const bytes = readFileSync(path!);
  expect(bytes.byteLength).toBeGreaterThan(1024);
  expect(bytes[0]).toBe(0x50); // P
  expect(bytes[1]).toBe(0x4b); // K
  expect(bytes[2]).toBe(0x03);
  expect(bytes[3]).toBe(0x04);

  await testInfo.attach("report.docx", {
    path: path!,
    contentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  });

  expect(externalRequests, "expected zero cross-origin requests during analysis").toEqual([]);
});

test("paste text → analyze → report, with nothing sent anywhere (spec-v50 §1)", async ({
  page,
}) => {
  const SAMPLE = join(__dirname, "sample-docs", "pasted-services-agreement.txt");
  test.skip(!existsSync(SAMPLE), `sample missing: ${SAMPLE}`);

  const baseURL =
    process.env.VAULYTICA_E2E_BASE_URL ??
    `http://127.0.0.1:${process.env.VAULYTICA_E2E_PORT ?? "4173"}`;
  const pageOrigin = new URL(baseURL).origin;
  const externalRequests: string[] = [];
  page.on("request", (req) => {
    const u = new URL(req.url());
    if (u.origin !== pageOrigin && u.protocol !== "data:" && u.protocol !== "blob:") {
      externalRequests.push(req.url());
    }
  });

  await page.goto("/");
  const panel = page.locator("#paste-panel");
  await expect(panel).toBeHidden();
  await page.locator('[data-role="paste-open"]').click();
  await expect(panel).toBeVisible();

  // An empty paste starts nothing and says why, beside the box.
  await page.locator('[data-role="paste-submit"]').click();
  await expect(page.locator('[data-role="paste-note"]')).toContainText("Paste the contract");
  await expect(page.locator("#dropzone")).toHaveAttribute("data-state", "empty");

  await page.locator("#paste-text").fill(readFileSync(SAMPLE, "utf8"));
  await page.locator('[data-role="paste-submit"]').click();

  await page.locator('[data-role="docx-download"]').waitFor({ state: "visible", timeout: 60_000 });
  // The report names the text the way the command line would.
  await expect(page.locator("#dropzone")).toContainText("pasted-text.txt");
  await expect(panel).toBeHidden();
  expect(externalRequests, "expected zero cross-origin requests during analysis").toEqual([]);
});
