import { describe, expect, it } from "vitest";

import { EQUITY_RULES } from "./rules.js";
import { EQT_PLAYBOOK_IDS } from "./_helpers.js";
import { buildContext } from "../../../_test-fixtures.js";
import { runEngine } from "../../../runner.js";
import type { Playbook, RuleContext } from "../../../finding.js";

const SAFE_PB: Playbook = { id: "safe-yc", version: "1.0.0" };
const CONV_NOTE_PB: Playbook = { id: "convertible-note", version: "1.0.0" };
const OPTION_PB: Playbook = { id: "stock-option-grant", version: "1.0.0" };
const E83B_PB: Playbook = { id: "section-83b-election", version: "1.0.0" };

const SRC = { name: "test.docx", sha256: "0".repeat(64), size_bytes: 100 };

function withPb(ctx: RuleContext, pb: Playbook): RuleContext {
  return { ...ctx, playbook: pb };
}

describe("v4 Equity ruleset — registry contract", () => {
  it("exports exactly 70 rules with stable EQT-NNN ids", () => {
    expect(EQUITY_RULES.length).toBe(70);
    const ids = EQUITY_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(70);
    for (const r of EQUITY_RULES) {
      expect(r.id, r.id).toMatch(/^EQT-\d{3}$/);
      expect(r.version, r.id).toMatch(/^\d+\.\d+\.\d+$/);
      expect(r.category, r.id).toBe("equity");
      expect(r.applies_to_playbooks, r.id).toBeDefined();
    }
  });

  it("scopes every rule to one or more equity playbooks", () => {
    const allowed = new Set<string>(EQT_PLAYBOOK_IDS);
    for (const r of EQUITY_RULES) {
      for (const pb of r.applies_to_playbooks ?? []) {
        expect(allowed.has(pb), `${r.id} → ${pb}`).toBe(true);
      }
    }
  });

  it("does not fire any rule under a non-equity playbook", async () => {
    const ctx = buildContext(["Some other doc", "No equity content here."]);
    const run = await runEngine({ rules: EQUITY_RULES, ctx, source_file: SRC });
    expect(run.findings.length).toBe(0);
    expect(run.execution_log.every((e) => !e.fired)).toBe(true);
  });
});

const COMPLIANT_SAFE: [string, ...string[]][] = [
  [
    "SAFE",
    "This Post-Money SAFE is entered into between Acme Inc. and the Investor. Definitions include Equity Financing, Liquidity Event, and Dissolution Event. Post-Money Valuation Cap: $20,000,000. Discount Rate: 80%. Most Favored Nation applies to any subsequent convertible instrument issued before the Equity Financing. Investor represents it is an accredited investor. This SAFE shall be governed by the laws of the State of Delaware. Upon a Liquidity Event the Investor shall receive the greater of cash-back or as-converted. Upon Dissolution the Investor has priority over Common Stock.",
  ],
];

describe("v4 Equity — compliant SAFE fixture", () => {
  it("emits no critical findings against the compliant SAFE fixture", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_SAFE), SAFE_PB);
    const run = await runEngine({ rules: EQUITY_RULES, ctx, source_file: SRC });
    const criticals = run.findings.filter((f) => f.severity === "critical");
    expect(criticals.map((f) => f.rule_id)).toEqual([]);
  });

  it("is deterministic across runs", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_SAFE), SAFE_PB);
    const a = await runEngine({ rules: EQUITY_RULES, ctx, source_file: SRC });
    const b = await runEngine({ rules: EQUITY_RULES, ctx, source_file: SRC });
    expect(a.result_hash).toEqual(b.result_hash);
  });
});

describe("v4 Equity — failure cases", () => {
  it("EQT-008 fires when a SAFE carries interest-accrual language", async () => {
    const ctx = withPb(
      buildContext([
        "SAFE",
        "This SAFE shall bear interest at the rate of 5% per annum until conversion.",
      ]),
      SAFE_PB,
    );
    const run = await runEngine({ rules: EQUITY_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "EQT-008")).toBe(true);
  });

  it("EQT-012 fires when a convertible note carries an interest rate at 30% per annum", async () => {
    const ctx = withPb(
      buildContext([
        "Convertible Note",
        "Interest shall accrue at the rate of 30% per annum, compounded annually.",
      ]),
      CONV_NOTE_PB,
    );
    const run = await runEngine({ rules: EQUITY_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "EQT-012")).toBe(true);
  });

  it("EQT-020 fires when an option grant omits exercise price", async () => {
    const ctx = withPb(
      buildContext([
        "Stock Option Grant",
        "Grant Date: January 1, 2026. Number of Shares Subject to the Option: 10,000. Vesting Schedule: 4-year monthly with 1-year cliff. The Option is an Incentive Stock Option under section 422.",
      ]),
      OPTION_PB,
    );
    const run = await runEngine({ rules: EQUITY_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "EQT-020")).toBe(true);
  });

  it("EQT-048 fires when a § 83(b) election omits the procedural recitals", async () => {
    const ctx = withPb(
      buildContext([
        "Section 83(b) Election",
        "The undersigned hereby makes an election under section 83(b) of the Internal Revenue Code with respect to restricted stock.",
      ]),
      E83B_PB,
    );
    const run = await runEngine({ rules: EQUITY_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "EQT-048")).toBe(true);
  });
});
