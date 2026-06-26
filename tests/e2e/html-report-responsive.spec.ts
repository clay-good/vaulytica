/**
 * The standalone HTML report is responsive and accessible (spec-v8 §21).
 *
 * The single-file HTML report is a *shareable web page* a user opens, emails,
 * and prints — so it is subject to the same "no horizontal scroll on any
 * device" contract as the app, and to the same WCAG 2 AA bar. This spec
 * renders the real `buildHtmlReport` output (via `page.setContent`, no server)
 * at 320 / 390 / 768 / 1280 px with an overflow-*stressing* run — a long
 * underscore-joined filename, a 64-char SHA-256 / result hash, a long citation
 * source + URL, multi-severity findings — asserts the document scrolls
 * vertically only, and runs an axe-core sweep for zero violations.
 */

import { test, expect, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { buildHtmlReport } from "../../src/report/html.js";
import { loadStarterDkbSync } from "../../src/engine/_test-fixtures.js";
import type { EngineRun, Finding } from "../../src/engine/finding.js";
import type { IngestResult } from "../../src/ingest/types.js";

const LONG_NAME =
  "Master_Services_Agreement_and_Data_Processing_Addendum_between_Acme_Corporation_and_Globex_Industries_FINAL_v12_executed.pdf";

const ingest: IngestResult = {
  tree: { type: "document", sections: [] },
  source: "pdf",
  word_count: 4200,
  page_count: 38,
  sha256: "a".repeat(64),
  warnings: [],
};

function finding(id: string, severity: Finding["severity"]): Finding {
  return {
    id,
    rule_id: "DPA-001-sub-processor-governance-flow-down",
    rule_version: "1.0.0",
    severity,
    title:
      "Missing sub-processor governance: the agreement does not bind sub-processors to the same data-protection terms required of the processor under GDPR Article 28(4)",
    description: "d",
    excerpt: {
      text: "x",
      section_id: "section-12.3.4-confidentiality-and-data-protection",
      start_offset: 0,
      end_offset: 1,
    },
    explanation:
      "Article 28(4) requires the processor to impose, by contract, the same obligations on any sub-processor it engages.",
    recommendation: "Add a flow-down clause binding sub-processors to the Article 28(3) terms.",
    source_citations: [
      {
        id: "gdpr-28",
        source:
          "Regulation (EU) 2016/679 (GDPR), Article 28 — Processor obligations and sub-processor flow-down requirements",
        source_url:
          "https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32016R0679&from=EN#d1e3252-1-1",
        retrieved_at: "2026-05-11T00:00:00Z",
        license: "CC-BY-4.0",
        license_url: "https://creativecommons.org/licenses/by/4.0/",
      },
    ],
    document_position: 0,
  };
}

const run: EngineRun = {
  version: "0.1.0",
  dkb_version: "v2026-06-07-local",
  playbook_id: "dpa-controller-processor",
  source_file: { name: LONG_NAME, sha256: "a".repeat(64), size_bytes: 1024 },
  executed_at: "2026-06-08T00:00:00Z",
  findings: [finding("c1", "critical"), finding("w1", "warning"), finding("i1", "info")],
  execution_log: [],
  result_hash: "b".repeat(64),
};

// v9 "Last Look" surfaces with overflow-prone content (long author/template
// paths, a 60-day-before clause, a leak-named entity) — so the new HTML
// sections are width- and a11y-tested alongside the findings.
const v9 = {
  delivery: {
    source: "docx" as const,
    inspectable: true,
    summary:
      "Delivery: 3 tracked changes, 2 comments, 5 metadata fields, 4 sensitive-data spans — review before sending.",
    findings: [
      {
        rule_id: "HANDOFF-004",
        severity: "critical" as const,
        title: "Authoring metadata is present",
        description:
          "5 authoring-metadata fields are embedded in the container. 2 identity fields name an entity not among the document's parties (a likely cross-matter leak).",
        count: 5,
        evidence: [
          "template: C:\\Users\\jdrafter\\AppData\\Roaming\\Microsoft\\Templates\\PriorClient_Globex_MSA_FINAL_v7.dotx ⚠ not a named party",
          "company: Globex Industries International Holdings LLC ⚠ not a named party",
        ],
      },
    ],
    delivery_hash: "d".repeat(64),
  },
  closingChecklist: {
    open_count: 2,
    items: [
      {
        category: "signature" as const,
        rule_id: "STRUCT-017",
        label:
          "Declared parties with no signature line: 2 — Globex Industries International Holdings LLC and Initech Worldwide Incorporated have no attributable signature line",
        section: "s12.4",
      },
      {
        category: "attachment" as const,
        rule_id: "STRUCT-018",
        label: "Referenced attachments not present: 3 — Exhibit C, Schedule 2.4, and Annex IV",
        section: "s3.1",
      },
    ],
  },
  criticalDates: {
    resolved_count: 1,
    unresolved_count: 1,
    critical_dates_hash: "e".repeat(64),
    register: [
      {
        rule_id: "DATE-001",
        kind: "auto-renewal-notice" as const,
        resolved: true,
        computed_date: "2025-11-01",
        trigger:
          "sixty (60) days prior to each anniversary of the Effective Date unless either party gives written notice of non-renewal",
        anchor: "Renewal Date",
        responsible: "Globex Industries International Holdings LLC",
        section: "s8.2",
      },
      {
        rule_id: "DATE-005",
        kind: "notice-period" as const,
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
};

// spec-v10 negotiation posture — overflow-prone dimensions/details/guidance.
const posture = {
  counts: { ideal: 1, acceptable: 1, below_acceptable: 1, unevaluable: 1 },
  posture_hash: "f".repeat(64),
  positions: [
    {
      dimension: "Liability cap (as a multiple of trailing twelve months of fees paid)",
      tier: "below-acceptable" as const,
      detail:
        "Found liability_cap_multiple = 3; your playbook requires liability_cap_multiple ≥ 6.",
      guidance: "Below our 6x floor — escalate to the deal lead before agreeing to anything lower.",
      section_id: "s7.4",
    },
    {
      dimension: "Termination-for-convenience notice period",
      tier: "acceptable" as const,
      detail: "Found notice_period_days = 45; ideal requires notice_period_days ≤ 30.",
      guidance: "Up to 60 days is tolerable.",
      section_id: "s12",
    },
    { dimension: "Governing law", tier: "ideal" as const, guidance: "Delaware — hold." },
    {
      dimension: "Uptime service-level commitment",
      tier: "unevaluable" as const,
      reason: "could not locate a value for the uptime SLA in the document",
    },
  ],
};

const BREAKPOINTS = [
  { label: "320px", width: 320, height: 720 },
  { label: "390px", width: 390, height: 844 },
  { label: "768px", width: 768, height: 1024 },
  { label: "1280px", width: 1280, height: 800 },
];

async function expectNoHorizontalOverflow(page: Page): Promise<void> {
  for (const bp of BREAKPOINTS) {
    await page.setViewportSize({ width: bp.width, height: bp.height });
    await page.evaluate(() => new Promise<void>((r) => requestAnimationFrame(() => r())));
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    expect(
      overflow,
      `HTML report overflows horizontally by ${overflow}px at ${bp.label}`,
    ).toBeLessThanOrEqual(1);
  }
}

test("standalone HTML report scrolls vertically only (320–1280px)", async ({ page }) => {
  const html = buildHtmlReport(run, ingest, loadStarterDkbSync(), undefined, v9, posture);
  await page.setContent(html);
  await expectNoHorizontalOverflow(page);
});

test("standalone HTML report has zero axe violations (WCAG 2 AA)", async ({ page }) => {
  await page.setContent(buildHtmlReport(run, ingest, loadStarterDkbSync(), undefined, v9, posture));
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(
    results.violations,
    `axe found ${results.violations.length} violation(s): ${results.violations
      .map((v) => `${v.id} (${v.nodes.length})`)
      .join(", ")}`,
  ).toEqual([]);
});
