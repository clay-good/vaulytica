/**
 * v4 multi-doc offline-verification smoke test (spec-v4.md §8 / LAUNCH row v4-d).
 *
 * Spec wording (spec-v4.md §8): "folder upload / zip / multi-file drop —
 * all processing must remain fully client-side with zero cross-origin
 * requests." This spec enforces the same privacy posture as the v3
 * offline spec (`tests/e2e/v3/no-network.spec.ts`) but exercises the
 * v4-specific multi-doc drop path added by `src/ingest/multi.ts`.
 *
 * Forward-compatible probe pattern
 * ---------------------------------
 * The multi-doc ingest library (`src/ingest/multi.ts`) ships as a
 * production-ready module, but the live marketing page (`site/index.html`)
 * still routes every drop through the v2 single-file `bindDropzone`
 * (`src/ui/dropzone.ts`), which only reads `input.files?.[0]`.  The DOM
 * affordances required to drive multi-doc mode (a `[data-role="multi-doc-
 * dropzone"]`, an `input[multiple]` / `input[webkitdirectory]` wired
 * inside `#dropzone`, or a `[data-role="bundle-download"]` button) will
 * land alongside the Step 33-equivalent UI hookup for v4.
 *
 * This spec uses `test.skip(!exists, ...)` — the same pattern used in
 * `tests/e2e/v3/a11y-keyboard.spec.ts` for the v3 chip-row probes — to
 * detect whether the multi-doc affordances are present.  Today the spec
 * skips gracefully because none of those selectors exist in the live DOM.
 * The moment the UI hookup lands, the skip is lifted automatically and
 * the spec becomes an active gate with no code change required here.
 *
 * What the test does when the UI is wired
 * ----------------------------------------
 *   1. Loads the marketing page and waits for `#dropzone`.
 *   2. Records every network request from this point forward.
 *   3. Detects multi-doc UI affordances (any one of the probe selectors
 *      is sufficient to proceed).
 *   4. Drops 2–3 fixture files via the multi-file input.
 *   5. Waits for a bundle-download or standard docx-download button.
 *   6. Downloads the file and asserts valid OOXML zip magic bytes + size.
 *   7. Asserts zero cross-origin requests fired during the whole run.
 *
 * Multi-doc library entry point: `src/ingest/multi.ts`
 *
 * Run locally:
 *
 *   npm run e2e:install   # one-time chromium install
 *   npm run e2e
 */

import { test, expect } from "@playwright/test";
import { readFileSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

const __dirname = dirname(fileURLToPath(import.meta.url));

// Use two committed .docx fixtures. mutual-nda.docx is the canonical
// clean baseline; bad-nda.docx provides a second distinct document so
// the multi-doc path sees a real two-file bundle.
const FIXTURE_DIR = join(__dirname, "..", "..", "fixtures", "contracts");
const FIXTURE_A = join(FIXTURE_DIR, "mutual-nda.docx");
const FIXTURE_B = join(FIXTURE_DIR, "bad-nda.docx");

/**
 * Resolve the two fixture paths. If only one exists, copy it to a temp
 * dir under a distinct name so the multi-doc path sees two separate
 * logical files (it would be nonsensical to drop the exact same path
 * twice — some browsers deduplicate identical-path entries in a
 * multi-file input).
 */
function resolveFixtures(): { pathA: string; pathB: string } | null {
  if (!existsSync(FIXTURE_A)) return null;
  if (existsSync(FIXTURE_B)) {
    return { pathA: FIXTURE_A, pathB: FIXTURE_B };
  }
  // Fall back: copy FIXTURE_A to a temp file with a different name.
  const tmp = join(tmpdir(), "vaulytica-e2e-v4");
  mkdirSync(tmp, { recursive: true });
  const copy = join(tmp, "mutual-nda-copy.docx");
  writeFileSync(copy, readFileSync(FIXTURE_A));
  return { pathA: FIXTURE_A, pathB: copy };
}

// Probe selectors that indicate the multi-doc UI is wired into the page.
// Any one present is sufficient to lift the forward-compatible skip.
const MULTI_DOC_SELECTORS = [
  '[data-role="multi-doc-dropzone"]',
  '#dropzone input[type="file"][multiple]',
  '#dropzone input[type="file"][webkitdirectory]',
  '[data-role="bundle-download"]',
];

test("v4 multi-doc drop makes zero non-asset network requests", async ({
  page,
}) => {
  const fixtures = resolveFixtures();
  test.skip(
    fixtures === null,
    `fixture missing: ${FIXTURE_A} — run \`npm run fixtures\` to generate`,
  );

  const requests: string[] = [];
  await page.goto("/");
  await expect(page.locator("#dropzone")).toBeVisible();

  // Probe for multi-doc UI affordances. The test skips if none are found.
  let multiDocPresent = false;
  for (const sel of MULTI_DOC_SELECTORS) {
    const count = await page.locator(sel).count();
    if (count > 0) {
      multiDocPresent = true;
      break;
    }
  }
  test.skip(
    !multiDocPresent,
    "multi-doc UI affordances not yet wired into the live page " +
      "(src/ingest/multi.ts ships as a library; UI hookup pending). " +
      "This test will activate automatically once any of these selectors " +
      "appears in the DOM: " +
      MULTI_DOC_SELECTORS.join(", "),
  );

  // From this point on, every request must be a same-origin asset or a
  // data:/blob: URL. Mirror the v3 no-network spec's allowlist exactly.
  const pageOrigin = new URL(page.url()).origin;
  page.on("request", (req) => {
    const u = req.url();
    const parsed = new URL(u);
    if (parsed.protocol === "data:" || parsed.protocol === "blob:") return;
    if (parsed.origin === pageOrigin) return;
    requests.push(u);
  });

  // Find the best multi-file input available. Prefer the dedicated multi-
  // doc dropzone input, fall back to any multi/webkitdirectory input
  // inside #dropzone, then fall back to the standard single-file input
  // (the bundle-download button path may not need a file input at all).
  let fileInput =
    page.locator('[data-role="multi-doc-dropzone"] input[type="file"]').first();
  if ((await fileInput.count()) === 0) {
    fileInput = page
      .locator(
        '#dropzone input[type="file"][multiple], #dropzone input[type="file"][webkitdirectory]',
      )
      .first();
  }
  if ((await fileInput.count()) === 0) {
    fileInput = page.locator('#dropzone input[type="file"]').first();
  }

  // Drop both fixture files via the file input.
  // `setInputFiles` accepts an array and sets the FileList in one call.
  await fileInput.setInputFiles([fixtures!.pathA, fixtures!.pathB]);

  // Wait for either a bundle-download (v4 multi-doc path) or the
  // standard docx-download (v3/v2 single-doc fallback). Timeout after
  // 60 s — same ceiling as the v3 spec.
  const bundleButton = page.locator('[data-role="bundle-download"]');
  const docxButton = page.locator('[data-role="docx-download"]');

  let downloadButton = bundleButton;
  try {
    await bundleButton.waitFor({ state: "visible", timeout: 60_000 });
  } catch {
    await docxButton.waitFor({ state: "visible", timeout: 60_000 });
    downloadButton = docxButton;
  }

  // Download the file and assert it is a valid OOXML zip. Belt-and-
  // suspenders: a regression that breaks the docx writer would manifest
  // as an empty or non-OOXML download. Mirror v3 spec's check exactly.
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    downloadButton.click(),
  ]);
  const path = await download.path();
  expect(path).toBeTruthy();
  const bytes = readFileSync(path!);
  expect(bytes.byteLength).toBeGreaterThan(1024);
  expect(bytes[0]).toBe(0x50); // P
  expect(bytes[1]).toBe(0x4b); // K
  expect(bytes[2]).toBe(0x03);
  expect(bytes[3]).toBe(0x04);

  expect(
    requests,
    "v4 multi-doc analysis must not initiate any cross-origin request",
  ).toEqual([]);
});
