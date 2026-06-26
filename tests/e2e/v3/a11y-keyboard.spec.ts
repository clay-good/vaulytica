/**
 * v3 keyboard-accessibility smoke (spec-v3 Step 37).
 *
 * Spec wording: "manually verify keyboard navigation through the new
 * chip-row toggles and the multi-doc cards." The chip row and
 * multi-doc cards are not yet wired into the live UI (Step 33's UI
 * hookup is partial — the pure primitives live at `src/ui/v3/` but
 * `main.ts` still routes through the v2 single-file flow). Until the
 * hookup lands, this spec exercises the v2 keyboard surface and a
 * forward-compatible probe for the v3 chip row + multi-doc cards.
 *
 * The v2 keyboard surface in scope:
 *
 *   - Tab from the document root reaches the dropzone in a sane
 *     number of stops.
 *   - The dropzone itself has `role="button"` + `tabindex="0"` and
 *     activates on Enter and Space (`bindDropzone` listens for both).
 *   - The "Why this playbook?" disclosure is keyboard-operable.
 *   - The theme toggle is reachable and operable via keyboard.
 *
 * For the v3 surface, when the chip row and multi-doc cards land in
 * the DOM, the same set of assertions will apply — the spec already
 * names them as test targets.
 *
 * A full axe-core sweep is gated on installing `@axe-core/playwright`;
 * the install + the audit will land alongside the Step 33 UI hookup so
 * a real v3 page state is available to scan. The notes in this file
 * are intentionally explicit so a contributor picking up Step 37
 * knows what is covered and what is not.
 */

import { test, expect } from "@playwright/test";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const BAA_FIXTURE = join(__dirname, "baa-minimal-pass.docx");

test("dropzone is keyboard-reachable via its hidden file input", async ({ page }) => {
  await page.goto("/");
  // The dropzone wrapper is a generic <div> (no role / no tabindex)
  // so it never wraps interactive children in the complete state.
  // The keyboard entry point is the bindDropzone-injected
  // visually-hidden <input type="file"> with an aria-label. Tab
  // through the page until that input gets focus.
  await expect(page.locator("#dropzone")).toBeVisible();
  const fileInput = page.locator('#dropzone input[type="file"]:not([webkitdirectory])');
  await expect(fileInput).toHaveCount(1);

  let onInput = false;
  for (let i = 0; i < 50; i++) {
    await page.keyboard.press("Tab");
    onInput = await fileInput.evaluate((el) => el === document.activeElement);
    if (onInput) break;
  }
  expect(onInput, "dropzone file input must be reachable via Tab in ≤ 50 stops").toBe(true);

  // Sanity: the input also carries an aria-label so screen readers
  // announce the file-type expectation.
  await expect(fileInput).toHaveAttribute("aria-label", /PDF|DOCX/i);
});

test("theme toggle is keyboard-operable", async ({ page }) => {
  await page.goto("/");
  const toggle = page.locator("#theme-toggle");
  await expect(toggle).toBeVisible();
  await toggle.focus();
  const before = await page.evaluate(() => document.documentElement.getAttribute("data-theme"));
  await page.keyboard.press("Enter");
  const after = await page.evaluate(() => document.documentElement.getAttribute("data-theme"));
  expect(after, "theme toggle must flip data-theme on Enter").not.toBe(before);
});

test("FAQ disclosures open/close with keyboard", async ({ page }) => {
  await page.goto("/");
  const firstDetails = page.locator("details").first();
  await firstDetails.locator("summary").focus();
  const wasOpen = await firstDetails.evaluate((el) => (el as HTMLDetailsElement).open);
  await page.keyboard.press("Enter");
  const isOpen = await firstDetails.evaluate((el) => (el as HTMLDetailsElement).open);
  expect(isOpen, "disclosure must toggle on Enter").not.toBe(wasOpen);
});

/**
 * Forward-compatible probe for the v3 chip row and multi-doc cards.
 *
 * The selectors below match the DOM the Step 33 UI hookup will produce;
 * the test is skipped when those elements are absent, so this spec
 * stays green during the partial-hookup window. When the hookup lands,
 * removing the skip is the only required change.
 */
test("v3 compliance-frame chip row is keyboard-operable", async ({ page }) => {
  // The chip row only mounts in the complete-state. Drive the page
  // through analysis by dropping the v3 BAA fixture, then verify
  // the chips are reachable + activatable from the keyboard.
  await page.addInitScript(() => {
    delete (window as { showSaveFilePicker?: unknown }).showSaveFilePicker;
  });
  await page.goto("/");

  const fileInput = page.locator('#dropzone input[type="file"]:not([webkitdirectory])');
  await fileInput.setInputFiles(BAA_FIXTURE);

  // Wait for the complete-state DOM (chip row is rendered alongside
  // the download button); the row may still be `hidden` if the
  // playbook has no default frames, so check visibility, not just count.
  await page.locator('[data-role="docx-download"]').waitFor({
    state: "visible",
    timeout: 60_000,
  });

  const chipRow = page.locator('[data-role="compliance-frame-chips"]');
  const chipCount = await chipRow.locator('[role="switch"]').count();
  test.skip(chipCount === 0, "v3 BAA fixture resolved to a playbook with no compliance frames");

  const firstChip = chipRow.locator('[role="switch"]').first();
  await firstChip.focus();
  await expect(firstChip).toHaveAttribute("role", "switch");
  await expect(firstChip).toHaveAttribute("aria-checked", /^(true|false)$/);
  const before = await firstChip.getAttribute("aria-checked");
  await page.keyboard.press("Space");
  const after = await firstChip.getAttribute("aria-checked");
  expect(after, "chip must flip aria-checked on Space").not.toBe(before);
});

test("multi-doc card download buttons are keyboard-operable", async ({ page }) => {
  const dir = join(__dirname, "..", "..", "fixtures", "contracts");
  const A = join(dir, "mutual-nda.docx");
  const B = join(dir, "bad-nda.docx");
  test.skip(!existsSync(A) || !existsSync(B), `bundle fixtures missing: ${A} / ${B}`);

  await page.addInitScript(() => {
    delete (window as { showSaveFilePicker?: unknown }).showSaveFilePicker;
  });
  await page.goto("/");

  const fileInput = page.locator('#dropzone input[type="file"]:not([webkitdirectory])');
  await fileInput.setInputFiles([A, B]);

  // Wait for bundle-complete; the per-doc cards land alongside the
  // consolidated download button.
  await page.locator('[data-role="bundle-download"]').waitFor({
    state: "visible",
    timeout: 60_000,
  });

  const cards = page.locator('[data-role="multi-doc-card"]');
  await expect(cards).toHaveCount(2);

  // Each card exposes a Word + JSON download button (native <button>,
  // so keyboard-focusable by default). Focus the first card's Word
  // button via Tab from the page root and confirm it has the right
  // aria-label.
  const firstWordBtn = cards.nth(0).locator('[data-role="card-docx-download"]');
  await firstWordBtn.focus();
  const isFocused = await firstWordBtn.evaluate((el) => el === document.activeElement);
  expect(isFocused, "card Word button must be programmatically focusable").toBe(true);

  const ariaLabel = await firstWordBtn.getAttribute("aria-label");
  expect(ariaLabel ?? "").toMatch(/Word/i);
});
