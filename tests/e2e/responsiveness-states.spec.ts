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
  // Some rich-content renderers (jurisdiction overlays, compliance chips) build
  // nodes via the global `document` — present in the browser and in vitest's
  // happy-dom env, but not under a bare `new Window()`. Expose it for the call.
  const g = globalThis as { document?: unknown; window?: unknown };
  const prevDoc = g.document;
  const prevWin = g.window;
  g.document = win.document;
  g.window = win;
  try {
    const dz = win.document.createElement("div");
    dz.className = "dropzone";
    dz.id = "dropzone";
    // renderState sets data-state + innerHTML and populates fields; outerHTML
    // captures the resulting markup (event listeners are irrelevant to layout).
    renderState(dz as unknown as HTMLElement, state);
    return `<main id="main" class="wrap">${dz.outerHTML}</main>`;
  } finally {
    g.document = prevDoc;
    g.window = prevWin;
  }
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
      // Rich complete-state content — these render long citations, chips, and
      // provenance lines that are prime overflow / contrast candidates.
      v3_family: { family: "dpa-controller-processor", label: "Data Processing Agreement (Controller↔Processor)", confidence: 0.92 },
      v3_frames: {
        available: ["GDPR", "CCPA", "HIPAA", "UK GDPR", "ISO 27001", "SOC 2", "PCI DSS", "NIST 800-53"],
        on: ["GDPR", "CCPA", "HIPAA"],
        hint: "Toggle a framework to re-scan against its specific obligations.",
      },
      custom_playbook: {
        name: "Acme Corporation Outside-Counsel Data-Processing Standard (revision 2026-Q2)",
        mode: "augment",
        custom_finding_count: 4,
        unevaluable_count: 2,
      },
      jurisdiction_overlays: {
        family: "employment-noncompete",
        states_in_catalog: 15,
        matched: [
          {
            state_name: "California",
            posture: "prohibited",
            topic: "Non-compete enforceability",
            headline: "Non-competes are void and unenforceable for employees",
            summary:
              "California voids employee non-compete covenants as a matter of public policy, with narrow statutory exceptions (sale of business, dissolution of partnership). A choice-of-law clause selecting another state generally will not save a non-compete against a California-resident employee.",
            recommendation: "Remove the non-compete or scope it to a permitted statutory exception; do not rely on an out-of-state choice-of-law clause.",
            citation: {
              source: "California Business and Professions Code § 16600 (and §§ 16601–16602.5 exceptions)",
              source_url:
                "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=BPC&sectionNum=16600",
            },
          },
        ],
        uncovered_states: ["Wyoming", "Mississippi", "West Virginia"],
      },
      // v9 Thrust A pre-disclosure scan — long author names, an unbroken
      // template path, and masked spans are prime overflow candidates.
      delivery: {
        inspectable: true,
        summary:
          "Delivery: 3 tracked changes, 2 comments, 5 metadata fields, 4 sensitive-data spans — review before sending.",
        findings: [
          {
            rule_id: "HANDOFF-001",
            severity: "critical",
            title: "Tracked changes are still present",
            description: "3 tracked-change revisions remain in the document's container.",
            count: 3,
            evidence: [
              "insertion by Opposing Counsel — Wilson Sonsini Goodrich & Rosati: “indemnify and hold harmless from any and all claims whatsoever arising”",
              "deletion by Jane Q. Partner: “net thirty (30) days from the date of invoice”",
            ],
          },
          {
            rule_id: "HANDOFF-004",
            severity: "critical",
            title: "Authoring metadata is present",
            description: "5 authoring-metadata fields are embedded in the container. 2 identity fields name an entity not among the document's parties (a likely cross-matter leak).",
            count: 5,
            evidence: [
              "template: C:\\Users\\jdrafter\\AppData\\Roaming\\Microsoft\\Templates\\PriorClient_Globex_MSA_FINAL_v7.dotx ⚠ not a named party",
              "company: Globex Industries International Holdings LLC ⚠ not a named party",
            ],
          },
          {
            rule_id: "HANDOFF-005",
            severity: "critical",
            title: "Sensitive-data patterns are present",
            description: "4 spans match sensitive-data formats that are routinely redacted before disclosure.",
            count: 4,
            evidence: ["ssn (high confidence): ***-**-6789", "card (high confidence): ************4242"],
          },
        ],
      },
      // v9 Thrust B closing checklist — long labels are overflow candidates.
      closing_checklist: {
        open_count: 4,
        items: [
          {
            category: "signature",
            rule_id: "STRUCT-017",
            label:
              "Declared parties with no signature line: 2 — Globex Industries International Holdings LLC and Initech Worldwide Incorporated have no attributable signature line",
            section: "s12.4",
          },
          {
            category: "attachment",
            rule_id: "STRUCT-018",
            label:
              "Referenced attachments not present: 3 — Exhibit C, Schedule 2.4, and Annex IV are referenced but not attached to the document",
            section: "s3.1",
          },
          {
            category: "formality",
            rule_id: "STRUCT-019",
            label: "Recited notarization with no notary block",
            section: "s14",
          },
          {
            category: "handoff",
            rule_id: "HANDOFF-001",
            label: "3 tracked changes still in the document — not send-ready",
          },
        ],
      },
      // v9 Thrust C critical-dates register — long triggers + windows.
      critical_dates: {
        resolved_count: 2,
        unresolved_count: 1,
        rows: [
          {
            rule_id: "DATE-001",
            kind: "auto-renewal-notice",
            resolved: true,
            computed_date: "2025-11-01",
            trigger:
              "sixty (60) days prior to each anniversary of the Effective Date unless either party gives written notice of non-renewal",
            anchor: "Renewal Date",
            responsible: "Globex Industries International Holdings LLC",
            section: "s8.2",
          },
          {
            rule_id: "DATE-002",
            kind: "cure-window",
            resolved: true,
            computed_date: "2026-02-28",
            window: ["2026-02-28", "2026-03-30"],
            trigger: "thirty to sixty days after written notice of breach to cure the default",
            anchor: "Notice Date",
            responsible: "",
            section: "s11",
          },
          {
            rule_id: "DATE-005",
            kind: "notice-period",
            resolved: false,
            computed_date: null,
            trigger: "fifteen (15) business days after the date of the final regulatory approval",
            anchor: "Approval Date",
            responsible: "",
            section: "s9.3",
            reason:
              "business-day deadline (15 business days) — no holiday calendar is asserted; verify manually",
          },
        ],
      },
      // spec-v10 negotiation posture — long dimensions/details/guidance.
      negotiation_posture: {
        counts: { ideal: 1, acceptable: 1, below_acceptable: 1, unevaluable: 1 },
        positions: [
          {
            dimension: "Liability cap (as a multiple of trailing twelve months of fees)",
            tier: "below-acceptable",
            detail: "Found liability_cap_multiple = 3; your playbook requires liability_cap_multiple ≥ 6.",
            guidance: "Below our 6x floor — escalate to the deal lead before agreeing to anything lower.",
            section_id: "s7.4",
          },
          {
            dimension: "Termination-for-convenience notice period",
            tier: "acceptable",
            detail: "Found notice_period_days = 45; ideal requires notice_period_days ≤ 30.",
            guidance: "Up to 60 days is tolerable; push for 30 if you have leverage.",
            section_id: "s12",
          },
          { dimension: "Governing law", tier: "ideal", guidance: "Delaware — our preferred forum; hold." },
          {
            dimension: "Uptime service-level commitment",
            tier: "unevaluable",
            reason: "could not locate a value for the uptime SLA in the document",
          },
        ],
      },
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
      // spec-v11 negotiation-posture movement — long dimension labels stress wrap.
      posture_movement: {
        counts: {
          improved: 1,
          regressed: 1,
          unchanged: 1,
          "newly-stated": 1,
          "now-unstated": 1,
          appeared: 0,
          disappeared: 0,
        },
        dimensions: [
          {
            dimension:
              "Aggregate limitation of liability cap as a multiple of trailing-twelve-month fees paid",
            base_tier: "below-acceptable",
            revised_tier: "acceptable",
            movement: "improved",
          },
          {
            dimension: "Governing law and exclusive forum selection for all disputes arising hereunder",
            base_tier: "ideal",
            revised_tier: "acceptable",
            movement: "regressed",
          },
          {
            dimension: "Mutuality of the indemnification obligations between the contracting parties",
            base_tier: "below-acceptable",
            revised_tier: "below-acceptable",
            movement: "unchanged",
          },
          {
            dimension: "Auto-renewal non-renewal notice window expressed in calendar days before term end",
            base_tier: "unevaluable",
            revised_tier: "acceptable",
            movement: "newly-stated",
          },
          {
            dimension: "Uptime / availability service-level commitment as a percentage of the month",
            base_tier: "acceptable",
            revised_tier: "unevaluable",
            movement: "now-unstated",
          },
        ],
      },
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
      // spec-v12 posture coherence — long dimension labels + filenames stress wrap.
      posture_coherence: {
        counts: { aligned: 1, divergent: 1, single: 1, unstated: 0 },
        dimensions: [
          {
            dimension:
              "Aggregate limitation of liability cap as a multiple of trailing-twelve-month fees paid",
            coherence: "divergent",
            tiers: [
              { document: `${LONG_NAME.slice(0, 40)}_master_services_agreement.pdf`, tier: "ideal" },
              { document: `${LONG_NAME.slice(0, 40)}_order_form.pdf`, tier: "below-acceptable" },
            ],
            weakest_tier: "below-acceptable",
            weakest_documents: [`${LONG_NAME.slice(0, 40)}_order_form.pdf`],
          },
          {
            dimension: "Governing law and exclusive forum selection for all disputes arising hereunder",
            coherence: "aligned",
            tiers: [
              { document: "msa.pdf", tier: "ideal" },
              { document: "order_form.pdf", tier: "ideal" },
            ],
            weakest_tier: "ideal",
            weakest_documents: ["msa.pdf", "order_form.pdf"],
          },
          {
            dimension: "Mutuality of the indemnification obligations between the contracting parties",
            coherence: "single",
            tiers: [
              { document: "msa.pdf", tier: "acceptable" },
              { document: "order_form.pdf", tier: "unevaluable" },
            ],
            weakest_tier: "acceptable",
            weakest_documents: ["msa.pdf"],
          },
        ],
      },
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
