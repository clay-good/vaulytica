/**
 * The two end-to-end scenarios spec-v3 Step 33 names by hand.
 *
 * `BUILD_PROGRESS.md` has carried step 33 as 🟡 partial since it was written,
 * and after the 9.520.0 re-verification these two paths were the *only* reason
 * left: everything else the note listed had long since shipped. Adjacent
 * coverage existed — the chip row is exercised for keyboard operability, the
 * BAA flow for offline behaviour, the multi-doc cards for download buttons —
 * but neither named path was asserted.
 *
 * They are named because they are the two claims a reader of the spec would
 * check first:
 *
 *   1. Drop a BAA and the HIPAA compliance frame is on by default. The whole
 *      point of the frame row is that the right regulator is pre-selected for
 *      the document you dropped; a row that renders but defaults wrong is
 *      worse than no row.
 *   2. Drop a DPA and an MSA and the cross-document consistency toggle appears,
 *      defaulted on, with the cross-document summary alongside it. That toggle
 *      is the user's control over the only analysis that reads two documents
 *      against each other.
 *
 * Both drive the real page through a real analysis — no stubs — so they fail
 * if the DOM hookup, the frame defaults, the bundle path, or the consistency
 * pass regress.
 */

import { test, expect } from "@playwright/test";
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

/** The binary BAA that landed for step 36; the dropzone accepts .docx / .pdf only. */
const BAA = join(__dirname, "baa-minimal-pass.docx");
/** The bundle sample pair — a real DPA and a real MSA. */
const BUNDLE = join(__dirname, "..", "sample-docs", "bundle");
const DPA = join(BUNDLE, "data-processing-addendum.docx");
const MSA = join(BUNDLE, "master-services-agreement.docx");

/** Headless Chromium cannot render the system save dialog. */
async function stubSavePicker(page: import("@playwright/test").Page): Promise<void> {
  await page.addInitScript(() => {
    delete (window as { showSaveFilePicker?: unknown }).showSaveFilePicker;
  });
}

const singleFileInput = '#dropzone input[type="file"]:not([webkitdirectory])';

test("drop a BAA and the HIPAA compliance frame is on by default", async ({ page }) => {
  test.skip(!existsSync(BAA), `fixture missing: ${BAA}`);
  await stubSavePicker(page);
  await page.goto("/");

  await page.locator(singleFileInput).setInputFiles(BAA);
  await page.locator('[data-role="docx-download"]').waitFor({ state: "visible", timeout: 60_000 });

  const chips = page.locator('[data-role="compliance-frame-chips"]');
  await expect(chips, "the frame row must render for a BAA").toBeVisible();

  // `defaultFramesForPlaybook` puts HIPAA in `on` for the BAA family; the chip
  // carries the frame id in `data-frame`, so this asserts the DEFAULT and not
  // merely that a chip exists.
  const hipaa = chips.locator('[role="switch"][data-frame="HIPAA"]');
  await expect(hipaa, "a BAA must offer a HIPAA frame chip").toHaveCount(1);
  await expect(hipaa, "HIPAA must be ON by default for a BAA").toHaveAttribute(
    "aria-checked",
    "true",
  );
});

test("drop a DPA and an MSA and the cross-document consistency toggle is on", async ({ page }) => {
  test.skip(!existsSync(DPA) || !existsSync(MSA), `bundle fixtures missing: ${DPA} / ${MSA}`);
  await stubSavePicker(page);
  await page.goto("/");

  await page.locator(singleFileInput).setInputFiles([DPA, MSA]);

  // Bundle-complete: the consolidated download lands with the per-document
  // cards and the cross-document controls.
  await page
    .locator('[data-role="bundle-download"]')
    .waitFor({ state: "visible", timeout: 120_000 });

  const toggle = page.locator('[data-role="cross-doc-toggle"]');
  await expect(toggle, "two documents must surface the consistency toggle").toBeVisible();

  const input = page.locator('[data-role="cross-doc-toggle-input"]');
  await expect(input, "cross-document consistency defaults ON (spec-v3 §62)").toBeChecked();

  // The summary line beside it is what reports the cross-document result; an
  // empty one would mean the toggle controls nothing the reader can see.
  await expect(page.locator('[data-role="cross-doc-summary"]')).not.toBeEmpty();

  // And both documents really were analyzed — the per-document cards are the
  // bundle's own evidence that this was a two-document run.
  await expect(page.locator('[data-role="multi-doc-card"]')).toHaveCount(2);
});
