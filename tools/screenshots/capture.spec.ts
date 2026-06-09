/**
 * Regenerates docs/images/report-mobile.png from the *current* complete-state
 * UI (the real renderState + page CSS) so the README's product shot stays
 * accurate as the UI evolves. Not part of the e2e suite (lives outside
 * tests/e2e); run on demand:
 *   npx playwright test tools/screenshots/capture.spec.ts --config=tools/screenshots/pw.config.ts
 */
import { test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Window } from "happy-dom";
import { renderState, type DropzoneState } from "../../src/ui/states.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..", "..");
const CSS = readFileSync(join(ROOT, "site", "index.html"), "utf8").match(/<style[^>]*>([\s\S]*?)<\/style>/)![1];
const blob = (s: string): Blob => new Blob([s]);
const c = { critical: 2, warning: 7, info: 3 };

const state: DropzoneState = {
  kind: "complete",
  filename: "Acme-Vendor-MSA-2026-EXECUTION.docx",
  playbook_name: "Master Services Agreement",
  counts: c,
  match_reasoning: "Selected Master Services Agreement (vendor side).",
  docx_blob: blob("d"), json_blob: blob("j"), docx_filename: "r.docx", json_filename: "r.json",
  exports: {
    fixlist_md_blob: blob("m"), fixlist_csv_blob: blob("c"), obligations_csv_blob: blob("o"),
    deadlines_ics_blob: blob("i"), sarif_blob: blob("s"), html_blob: blob("h"),
    fixlist_md_filename: "f.md", fixlist_csv_filename: "f.csv", obligations_csv_filename: "o.csv",
    deadlines_ics_filename: "d.ics", sarif_filename: "r.sarif.json", html_filename: "r.html",
  },
  v3_family: { family: "msa", label: "Master Services Agreement", confidence: 0.88 },
  jurisdiction_overlays: {
    family: "employment-noncompete", states_in_catalog: 15,
    matched: [{
      state_name: "California", posture: "prohibited", topic: "Non-compete enforceability",
      headline: "Non-competes are void and unenforceable for employees",
      summary: "California voids employee non-compete covenants as a matter of public policy, with narrow statutory exceptions.",
      recommendation: "Remove the non-compete; do not rely on an out-of-state choice-of-law clause.",
      citation: { source: "Cal. Bus. & Prof. Code § 16600", source_url: "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=BPC&sectionNum=16600" },
    }],
    uncovered_states: [],
  },
  on_compare: () => {},
};

test("capture report-mobile.png", async ({ page }) => {
  const g = globalThis as { document?: unknown; window?: unknown };
  const win = new Window();
  g.document = win.document; g.window = win;
  const dz = win.document.createElement("div");
  dz.className = "dropzone"; dz.id = "dropzone"; dz.setAttribute("data-state", "complete");
  renderState(dz as unknown as HTMLElement, state);
  const html = `<!doctype html><html lang="en" data-theme="dark"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1"><title>Vaulytica</title>
    <style>${CSS}</style><style>body{padding:16px;display:flex;justify-content:center;}#main{margin:0;}</style></head>
    <body><main id="main" class="wrap">${dz.outerHTML}</main></body></html>`;
  await page.setViewportSize({ width: 360, height: 980 });
  await page.setContent(html);
  await page.evaluate(() => new Promise<void>((r) => requestAnimationFrame(() => r())));
  const card = page.locator("#dropzone");
  await card.screenshot({ path: join(ROOT, "docs", "images", "report-mobile.png") });
});
