/**
 * The standalone negotiation sheet is responsive and accessible (spec-v10
 * Thrust B, Step 170).
 *
 * The sheet is a *shareable web page* a negotiator opens, prints, and emails —
 * so it is held to the same "no horizontal scroll on any device" contract and
 * the same WCAG 2 AA bar as the app. This spec renders the real
 * `buildNegotiationSheet` output (via `page.setContent`, no server) at
 * 320 / 390 / 768 / 1280 px with overflow-stressing positions (long dimensions,
 * details, and guidance), asserts the document scrolls vertically only, and
 * runs an axe-core sweep for zero violations.
 */

import { test, expect, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { buildNegotiationSheet } from "../../src/report/negotiation-sheet.js";
import type { NegotiationPosture } from "../../src/playbooks/custom-interpreter.js";

const posture: NegotiationPosture = {
  counts: { ideal: 1, acceptable: 1, below_acceptable: 1, unevaluable: 1 },
  posture_hash: "f".repeat(64),
  positions: [
    {
      dimension:
        "Liability cap (as a multiple of trailing twelve months of fees paid under the agreement)",
      tier: "below-acceptable",
      detail:
        "Found liability_cap_multiple = 3; your playbook requires liability_cap_multiple ≥ 6.",
      guidance:
        "Below our 6x floor — escalate to the deal lead before agreeing to anything lower; do not concede on this without sign-off from the principal.",
      section_id: "s7.4",
    },
    {
      dimension: "Termination-for-convenience notice period",
      tier: "acceptable",
      detail: "Found notice_period_days = 45; ideal requires notice_period_days ≤ 30.",
      guidance: "Up to 60 days is tolerable; push for 30 if you have leverage on price.",
      section_id: "s12",
    },
    {
      dimension: "Governing law",
      tier: "ideal",
      guidance: "Delaware — our preferred forum; hold.",
    },
    {
      dimension: "Uptime service-level commitment",
      tier: "unevaluable",
      reason: "could not locate a value for the uptime SLA in the document",
    },
  ],
};

const TITLE = "Acme_SaaS_Buyer_Standard_vs_Globex_Master_Subscription_Agreement_FINAL_v12.pdf";

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
      `negotiation sheet overflows horizontally by ${overflow}px at ${bp.label}`,
    ).toBeLessThanOrEqual(1);
  }
}

test("standalone negotiation sheet scrolls vertically only (320–1280px)", async ({ page }) => {
  await page.setContent(buildNegotiationSheet(posture, TITLE));
  await expectNoHorizontalOverflow(page);
});

test("standalone negotiation sheet has zero axe violations (WCAG 2 AA)", async ({ page }) => {
  await page.setContent(buildNegotiationSheet(posture, TITLE));
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
