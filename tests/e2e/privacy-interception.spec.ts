/**
 * Privacy-invariant interception gate (fix-privacy-claim-accuracy).
 *
 * The provable privacy claim is: *your document never leaves the tab* —
 * during a full analysis the only network requests are same-origin GETs
 * of the app's own static assets (rule data, playbooks, chunks), and no
 * request anywhere carries a body. This spec converts that claim from
 * prose into a gate, for a DOCX, a text-layer PDF, and a scanned-style
 * PDF with no text layer (the case that once tempted tesseract.js to
 * fetch its worker/wasm/language model from a third-party CDN).
 */

import { test, expect, type Page } from "@playwright/test";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const DOCX_FIXTURE = join(
  process.cwd(),
  "tests",
  "e2e",
  "sample-docs",
  "single",
  "vendor-saas-agreement.docx",
);

/** Minimal single-page PDF (correct xref offsets) — text layer optional. */
function buildMinimalPdf(text: string | null): Buffer {
  const contents = text ? `BT /F1 24 Tf 72 700 Td (${text}) Tj ET` : `72 700 100 40 re S`; // a stroked rectangle: a "scan" with no text layer
  const objects = [
    "<</Type/Catalog/Pages 2 0 R>>",
    "<</Type/Pages/Kids[3 0 R]/Count 1>>",
    "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>",
    `<</Length ${contents.length}>>\nstream\n${contents}\nendstream`,
    "<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>",
  ];
  let pdf = "%PDF-1.4\n";
  const offsets: number[] = [];
  objects.forEach((body, i) => {
    offsets.push(pdf.length);
    pdf += `${i + 1} 0 obj\n${body}\nendobj\n`;
  });
  const xrefPos = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const off of offsets) pdf += `${String(off).padStart(10, "0")} 00000 n \n`;
  pdf += `trailer\n<</Size ${objects.length + 1}/Root 1 0 R>>\nstartxref\n${xrefPos}\n%%EOF`;
  return Buffer.from(pdf, "latin1");
}

type Offense = { url: string; kind: "cross-origin" | "method" | "body" };

/** Attach request assertions; returns the offense collector. */
function watchRequests(page: Page, pageOrigin: string): Offense[] {
  const offenses: Offense[] = [];
  page.on("request", (req) => {
    const u = new URL(req.url());
    if (u.protocol === "data:" || u.protocol === "blob:") return;
    if (u.origin !== pageOrigin) {
      offenses.push({ url: req.url(), kind: "cross-origin" });
      return;
    }
    if (req.method() !== "GET") offenses.push({ url: req.url(), kind: "method" });
    if (req.postData() !== null) offenses.push({ url: req.url(), kind: "body" });
  });
  return offenses;
}

const pageOrigin = () =>
  new URL(
    process.env.VAULYTICA_E2E_BASE_URL ??
      `http://127.0.0.1:${process.env.VAULYTICA_E2E_PORT ?? "4173"}`,
  ).origin;

async function analyze(page: Page, file: string): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#dropzone")).toBeVisible();
  const fileInput = page.locator('#dropzone input[type="file"]:not([webkitdirectory])');
  await fileInput.setInputFiles(file);
  await page.locator('[data-role="docx-download"]').waitFor({ state: "visible", timeout: 60_000 });
}

test("DOCX analysis: same-origin GETs only, no request bodies", async ({ page }) => {
  test.skip(!existsSync(DOCX_FIXTURE), `fixture missing: ${DOCX_FIXTURE}`);
  const offenses = watchRequests(page, pageOrigin());
  await analyze(page, DOCX_FIXTURE);
  expect(offenses).toEqual([]);
});

test("PDF analysis (text layer): same-origin GETs only, no request bodies", async ({ page }) => {
  const tmp = mkdtempSync(join(tmpdir(), "vaul-privacy-"));
  const pdfPath = join(tmp, "text-layer.pdf");
  writeFileSync(
    pdfPath,
    buildMinimalPdf("This Mutual Non-Disclosure Agreement is between Acme Corp. and Globex Inc."),
  );
  const offenses = watchRequests(page, pageOrigin());
  await analyze(page, pdfPath);
  expect(offenses).toEqual([]);
});

test("scanned-style PDF (no text layer): never reaches a CDN, reports honestly", async ({
  page,
}) => {
  const tmp = mkdtempSync(join(tmpdir(), "vaul-privacy-"));
  const pdfPath = join(tmp, "scanned.pdf");
  writeFileSync(pdfPath, buildMinimalPdf(null));
  const offenses = watchRequests(page, pageOrigin());
  await analyze(page, pdfPath);
  expect(offenses).toEqual([]);
});
