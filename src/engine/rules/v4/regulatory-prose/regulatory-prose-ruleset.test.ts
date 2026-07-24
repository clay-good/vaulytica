import { describe, expect, it } from "vitest";

import { REGULATORY_PROSE_RULES } from "./rules.js";
import { REG_PLAYBOOK_IDS } from "./_helpers.js";
import { buildContext } from "../../../_test-fixtures.js";
import { runEngine } from "../../../runner.js";
import type { Playbook, RuleContext } from "../../../finding.js";

const FORM_D_PB: Playbook = { id: "form-d-narrative", version: "1.0.0" };
const ADV_PB: Playbook = { id: "form-adv-brochure", version: "1.0.0" };
const S1_PB: Playbook = { id: "s-1-risk-factors", version: "1.0.0" };
const TENK_PB: Playbook = { id: "10-k-risk-factors", version: "1.0.0" };
const PPM_PB: Playbook = { id: "ppm-narrative", version: "1.0.0" };
const REGA_PB: Playbook = { id: "reg-a-plus-circular", version: "1.0.0" };

const SRC = { name: "test.docx", sha256: "0".repeat(64), size_bytes: 100 };

function withPb(ctx: RuleContext, pb: Playbook): RuleContext {
  return { ...ctx, playbook: pb };
}

describe("v4 Regulatory-prose ruleset — registry contract", () => {
  it("exports exactly 40 rules with stable REG-NNN ids", () => {
    expect(REGULATORY_PROSE_RULES.length).toBe(40);
    const ids = REGULATORY_PROSE_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(40);
    for (const r of REGULATORY_PROSE_RULES) {
      expect(r.id, r.id).toMatch(/^REG-\d{3}$/);
      expect(r.version, r.id).toMatch(/^\d+\.\d+\.\d+$/);
      expect(r.category, r.id).toBe("regulatory-prose");
      expect(r.applies_to_playbooks, r.id).toBeDefined();
    }
  });

  it("scopes every rule to one or more regulatory-prose playbooks", () => {
    const allowed = new Set<string>(REG_PLAYBOOK_IDS);
    for (const r of REGULATORY_PROSE_RULES) {
      for (const pb of r.applies_to_playbooks ?? []) {
        expect(allowed.has(pb), `${r.id} → ${pb}`).toBe(true);
      }
    }
  });

  it("does not fire under a non-regulatory-prose playbook", async () => {
    const ctx = buildContext(["Some other doc", "No filing content."]);
    const run = await runEngine({ rules: REGULATORY_PROSE_RULES, ctx, source_file: SRC });
    expect(run.findings.length).toBe(0);
    expect(run.execution_log.every((e) => !e.fired)).toBe(true);
  });
});

describe("v4 Regulatory-prose — REG-040 disclaimer always fires", () => {
  it.each([
    ["Form D", FORM_D_PB],
    ["Form ADV", ADV_PB],
    ["S-1", S1_PB],
    ["10-K", TENK_PB],
    ["PPM", PPM_PB],
    ["Reg A+", REGA_PB],
  ] as const)("fires REG-040 disclaimer under %s playbook", async (_label, pb) => {
    const ctx = withPb(
      buildContext(["Document", "Any text — disclaimer applies unconditionally."]),
      pb,
    );
    const run = await runEngine({ rules: REGULATORY_PROSE_RULES, ctx, source_file: SRC });
    const disclaimer = run.findings.find((f) => f.rule_id === "REG-040");
    expect(disclaimer, "REG-040 must fire on every run").toBeDefined();
    expect(disclaimer?.severity).toBe("info");
  });
});

describe("v4 Regulatory-prose — failure cases", () => {
  it("REG-002 fires when Form D narrative omits exemption claimed", async () => {
    const ctx = withPb(
      buildContext([
        "Form D Narrative",
        "Issuer Acme Inc., a Delaware corporation, CIK 0001234567. Accredited investors only; verification per income or net worth test. General solicitation prohibited. Bad-actor disqualification screening performed; no covered-persons issues. Offering size $5,000,000 with $25,000 minimum subscription. State notice filings to be made.",
      ]),
      FORM_D_PB,
    );
    const run = await runEngine({ rules: REGULATORY_PROSE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "REG-002")).toBe(true);
  });

  it("REG-010 fires when Form ADV brochure omits fees and compensation", async () => {
    const ctx = withPb(
      buildContext([
        "Form ADV Part 2A Brochure",
        "Cover page dated 2026. Item 2 material changes summary. Item 4 advisory business: discretionary investment management; AUM $250 million. Item 8 methods of analysis, investment strategies, and risk of loss described. Item 9 disciplinary information: none. Item 11 code of ethics and personal trading addressed. Item 12 brokerage practices. Item 15 custody addressed.",
      ]),
      ADV_PB,
    );
    const run = await runEngine({ rules: REGULATORY_PROSE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "REG-010")).toBe(true);
  });

  it("REG-018 fires on generic boilerplate risk factor", async () => {
    const ctx = withPb(
      buildContext([
        "Risk Factors",
        "We may not be able to attract and retain qualified personnel. General economic conditions may adversely affect our business. Cybersecurity coverage is described.",
      ]),
      S1_PB,
    );
    const run = await runEngine({ rules: REGULATORY_PROSE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "REG-018")).toBe(true);
  });

  it("REG-027 fires when PPM omits suitability standards", async () => {
    const ctx = withPb(
      buildContext([
        "Private Placement Memorandum",
        "Overview: Acme is offering preferred equity; use of proceeds is working capital. Risk Factors: dilution and lockup. Subscription procedure via questionnaire and agreement, with minimum subscription. Transfer restrictions per Rule 144 legend. Conflicts of interest disclosed. Tax considerations addressed; Circular 230 disclaimer applies. State blue-sky notice filings made via selling agents registered with FINRA.",
      ]),
      PPM_PB,
    );
    const run = await runEngine({ rules: REGULATORY_PROSE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "REG-027")).toBe(true);
  });

  it("REG-033 fires when Reg A+ circular omits Tier election", async () => {
    const ctx = withPb(
      buildContext([
        "Offering Circular",
        "Form 1-A Part I notification + Part II offering circular + Part III exhibits. Risk factors specific to the offering. Use of proceeds + plan of distribution described. Investment limitation 10% for non-accredited investors. Audited financial statements for 2 years. Ongoing reporting via Form 1-K, Form 1-SA, and Form 1-U.",
      ]),
      REGA_PB,
    );
    const run = await runEngine({ rules: REGULATORY_PROSE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "REG-033")).toBe(true);
  });
});

describe("REG-018 — the issuer-first generic boilerplate (v1.1.0)", () => {
  const run1 = async (body: string) => {
    const ctx = withPb(buildContext(["Risk Factors", body]), TENK_PB);
    const run = await runEngine({ rules: REGULATORY_PROSE_RULES, ctx, source_file: SRC });
    return new Set(run.findings.map((f) => f.rule_id));
  };

  it("fires on 'we may be adversely affected by general economic conditions … factors beyond our control'", async () => {
    expect(
      (
        await run1(
          "We may be adversely affected by general economic conditions, competition, and other factors beyond our control.",
        )
      ).has("REG-018"),
    ).toBe(true);
  });

  it("stays silent on a specific, quantified risk factor", async () => {
    expect(
      (
        await run1(
          "Our net interest margin declined from 3.4% in 2025 to 2.9% in 2026 as deposit costs repriced faster than loan yields.",
        )
      ).has("REG-018"),
    ).toBe(false);
  });
});
