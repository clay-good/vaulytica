/**
 * Responsiveness for **every** view-state (spec-v7 Part XVI / Step 125,
 * extended).
 *
 * The original `responsiveness.spec.ts` drives the live app and so can only
 * reach the states a fixture-drop produces (empty + complete) against a
 * deployed/preview server. This spec covers the **full** `DropzoneState`
 * union — including the comparison / bundle / error / analyzing states the
 * old spec left to the periodic visual audit — by rendering each state with
 * the real `renderState` (in happy-dom) and the real page CSS (extracted from
 * `site/index.html`), injected via `page.setContent`. No server is required,
 * so the layout of every state is pinned at 320 / 390 / 768 / 1280 px: the
 * page must scroll vertically only — `scrollWidth ≤ clientWidth`.
 *
 * Each fixture deliberately *stresses* overflow: very long filenames, long
 * citation URLs, many per-document cards, long skip reasons, long error
 * messages — the inputs most likely to push a layout past the viewport.
 */

import { test, expect, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Window } from "happy-dom";
import { renderState, type DropzoneState } from "../../src/ui/states.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SITE_INDEX = join(__dirname, "..", "..", "site", "index.html");

/** The app's single inlined <style> block — the real CSS under test. */
const PAGE_CSS = (() => {
  const html = readFileSync(SITE_INDEX, "utf8");
  const m = html.match(/<style[^>]*>([\s\S]*?)<\/style>/);
  if (!m) throw new Error("could not extract <style> from site/index.html");
  return m[1];
})();

/** Render a state to the same DOM the app mounts, as an HTML string. */
function renderStateHtml(state: DropzoneState): string {
  const win = new Window();
  const dz = win.document.createElement("div");
  dz.className = "dropzone";
  dz.id = "dropzone";
  // renderState sets data-state + innerHTML and populates fields; outerHTML
  // captures the resulting markup (event listeners are irrelevant to layout).
  renderState(dz as unknown as HTMLElement, state);
  return `<main id="main" class="wrap">${dz.outerHTML}</main>`;
}

/** Themes: default (no attribute) is the dark palette; `light` opts in. */
type Theme = "default" | "light";

function pageHtml(state: DropzoneState, theme: Theme = "default"): string {
  const themeAttr = theme === "light" ? ' data-theme="light"' : "";
  return [
    "<!doctype html>",
    `<html lang="en"${themeAttr}><head><meta charset="utf-8">`,
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    "<title>Vaulytica report view</title>",
    `<style>${PAGE_CSS}</style></head><body>`,
    renderStateHtml(state),
    "</body></html>",
  ].join("");
}

const BREAKPOINTS = [
  { label: "320px (small phone)", width: 320, height: 720 },
  { label: "390px (modern phone)", width: 390, height: 844 },
  { label: "768px (tablet)", width: 768, height: 1024 },
  { label: "1280px (desktop)", width: 1280, height: 800 },
];

async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  for (const bp of BREAKPOINTS) {
    await page.setViewportSize({ width: bp.width, height: bp.height });
    await page.evaluate(() => new Promise<void>((r) => requestAnimationFrame(() => r())));
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    expect(overflow, `${label} overflows horizontally by ${overflow}px at ${bp.label}`).toBeLessThanOrEqual(1);
  }
}

const blob = (s: string): Blob => new Blob([s], { type: "application/octet-stream" });
const LONG_NAME =
  "Master_Services_Agreement_and_Data_Processing_Addendum_between_Acme_Corporation_and_Globex_Industries_FINAL_v12_executed.pdf";

const counts3 = { critical: 3, warning: 7, info: 12 };
const counts4 = (n: number) => ({ critical: n, warning: n, info: n, total: n * 3 });

/** Every state in the union, with overflow-stressing data. */
const STATES: Array<{ name: string; state: DropzoneState }> = [
  { name: "empty", state: { kind: "empty" } },
  { name: "analyzing", state: { kind: "analyzing", filename: LONG_NAME, dkb_version: "v2026-06-07-local" } },
  {
    name: "complete",
    state: {
      kind: "complete",
      filename: LONG_NAME,
      playbook_name: "DPA — Controller/Processor (GDPR Art. 28)",
      counts: counts3,
      match_reasoning:
        "Auto-selected because the document defines Controller and Processor and references Article 28(3) sub-processor obligations across multiple long clauses.",
      docx_blob: blob("d"),
      json_blob: blob("j"),
      docx_filename: "report.docx",
      json_filename: "report.json",
      exports: {
        fixlist_md_blob: blob("m"),
        fixlist_csv_blob: blob("c"),
        obligations_csv_blob: blob("o"),
        deadlines_ics_blob: blob("i"),
        sarif_blob: blob("s"),
        html_blob: blob("h"),
        fixlist_md_filename: "f.md",
        fixlist_csv_filename: "f.csv",
        obligations_csv_filename: "o.csv",
        deadlines_ics_filename: "d.ics",
        sarif_filename: "r.sarif.json",
        html_filename: "r.html",
      },
      secondary_families: [
        { playbook_id: "baa", playbook_name: "Business Associate Agreement (HIPAA §164.504(e))", counts: counts3 },
      ],
    },
  },
  {
    name: "comparison-complete",
    state: {
      kind: "comparison-complete",
      base_filename: LONG_NAME,
      revised_filename: LONG_NAME.replace("v12", "v13"),
      verdict:
        "Net improvement: this revision resolved 2 critical findings and 3 warnings while introducing 1 new informational finding.",
      counts: {
        resolved: counts4(2),
        introduced: counts4(1),
        unchanged: counts4(5),
        carried_clean_count: 4,
      },
      dkb_mismatch: true,
      docx_blob: blob("d"),
      json_blob: blob("j"),
      docx_filename: "cmp.docx",
      json_filename: "cmp.json",
    },
  },
  {
    name: "bundle-complete",
    state: {
      kind: "bundle-complete",
      document_count: 4,
      counts: counts3,
      cross_doc_findings: 5,
      bundle_docx_blob: blob("d"),
      bundle_json_blob: blob("j"),
      bundle_docx_filename: "bundle.docx",
      bundle_json_filename: "bundle.json",
      bundle_zip_blob: blob("z"),
      bundle_zip_filename: "bundle.zip",
      detected_families: ["Mutual NDA", "MSA / Commercial", "DPA — Controller/Processor", "BAA"],
      documents: [0, 1, 2, 3].map((i) => ({
        filename: `${LONG_NAME.slice(0, 40)}_part_${i}.pdf`,
        family_label: "DPA — Controller/Processor (GDPR Art. 28)",
        detection_confidence: 0.42,
        playbook_name: "DPA — Controller/Processor",
        playbook_deprecated: i === 0,
        counts: counts3,
        secondary_families: [{ playbook_name: "Business Associate Agreement (HIPAA)", counts: counts3 }],
        docx_blob: blob("d"),
        json_blob: blob("j"),
        docx_filename: `doc${i}.docx`,
        json_filename: `doc${i}.json`,
      })),
      rejected: [
        {
          filename: "scanned_appendix_with_a_very_long_unbreakable_filename_that_should_wrap.tiff",
          reason: "Unsupported file type — only PDF and DOCX are analyzed; this entry was skipped.",
        },
      ],
      cross_doc_active: true,
    },
  },
  {
    name: "error",
    state: {
      kind: "error",
      message:
        "The document could not be analyzed because the uploaded file appears to be a password-protected or corrupted PDF that no text layer or OCR pass could recover. Please re-export it and try again.",
    },
  },
];

test.describe("every view-state scrolls vertically only (320–1280px)", () => {
  for (const { name, state } of STATES) {
    test(`${name} state never overflows horizontally`, async ({ page }) => {
      await page.setContent(pageHtml(state));
      await expectNoHorizontalOverflow(page, `${name} state`);
    });
  }
});

// The live `a11y-axe.spec.ts` scans only the empty + complete states; this
// covers the rest of the union — and both palettes, since contrast depends on
// the theme (the default dark and the opt-in light) — so a low-contrast colour
// in the comparison / bundle / error states can no longer ship unnoticed.
test.describe("every view-state has zero axe violations (WCAG 2 AA, both themes)", () => {
  for (const { name, state } of STATES) {
    for (const theme of ["default", "light"] as const) {
      test(`${name} state is accessible (${theme} theme)`, async ({ page }) => {
        await page.setContent(pageHtml(state, theme));
        const results = await new AxeBuilder({ page })
          .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
          .analyze();
        expect(
          results.violations,
          `axe found ${results.violations.length} violation(s) in ${name}/${theme}: ${results.violations
            .map((v) => `${v.id} (${v.nodes.length}: ${v.nodes[0]?.target})`)
            .join("; ")}`,
        ).toEqual([]);
      });
    }
  }
});
