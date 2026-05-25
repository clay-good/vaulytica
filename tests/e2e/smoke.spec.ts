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
  const externalRequests: string[] = [];
  page.on("request", (req) => {
    const u = new URL(req.url());
    const origin = new URL(page.url() || "http://localhost").origin;
    if (u.origin !== origin && u.protocol !== "data:" && u.protocol !== "blob:") {
      externalRequests.push(req.url());
    }
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

  await testInfo.attach("report.docx", { path: path!, contentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document" });

  expect(externalRequests, "expected zero cross-origin requests during analysis").toEqual([]);
});
