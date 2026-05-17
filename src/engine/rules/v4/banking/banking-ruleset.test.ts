import { describe, expect, it } from "vitest";

import { BANKING_RULES } from "./rules.js";
import { BNK_PLAYBOOK_IDS } from "./_helpers.js";
import { buildContext } from "../../../_test-fixtures.js";
import { runEngine } from "../../../runner.js";
import type { Playbook, RuleContext } from "../../../finding.js";

const NOTE_PB: Playbook = { id: "promissory-note", version: "1.0.0" };
const LOAN_PB: Playbook = { id: "loan-agreement", version: "1.0.0" };
const SEC_PB: Playbook = { id: "security-agreement", version: "1.0.0" };
const GTY_PB: Playbook = { id: "guaranty", version: "1.0.0" };
const IC_PB: Playbook = { id: "intercreditor-agreement", version: "1.0.0" };
const SUB_PB: Playbook = { id: "subordination-agreement", version: "1.0.0" };
const DOT_PB: Playbook = { id: "deed-of-trust", version: "1.0.0" };
const UCC1_PB: Playbook = { id: "ucc-1-financing-statement", version: "1.0.0" };

const SRC = { name: "test.docx", sha256: "0".repeat(64), size_bytes: 100 };

function withPb(ctx: RuleContext, pb: Playbook): RuleContext {
  return { ...ctx, playbook: pb };
}

describe("v4 Banking ruleset — registry contract", () => {
  it("exports exactly 50 rules with stable BNK-NNN ids", () => {
    expect(BANKING_RULES.length).toBe(50);
    const ids = BANKING_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(50);
    for (const r of BANKING_RULES) {
      expect(r.id, r.id).toMatch(/^BNK-\d{3}$/);
      expect(r.version, r.id).toMatch(/^\d+\.\d+\.\d+$/);
      expect(r.category, r.id).toBe("banking");
      expect(r.applies_to_playbooks, r.id).toBeDefined();
    }
  });

  it("scopes every rule to one or more banking playbooks", () => {
    const allowed = new Set<string>(BNK_PLAYBOOK_IDS);
    for (const r of BANKING_RULES) {
      for (const pb of r.applies_to_playbooks ?? []) {
        expect(allowed.has(pb), `${r.id} → ${pb}`).toBe(true);
      }
    }
  });

  it("does not fire under a non-banking playbook", async () => {
    const ctx = buildContext(["Some other doc", "No banking content."]);
    const run = await runEngine({ rules: BANKING_RULES, ctx, source_file: SRC });
    expect(run.findings.length).toBe(0);
    expect(run.execution_log.every((e) => !e.fired)).toBe(true);
  });
});

const COMPLIANT_NOTE: [string, ...string[]][] = [
  [
    "Promissory Note",
    "Maker: Acme Corp. Payee: BigBank. Principal Amount: $1,000,000. Maker absolutely and unconditionally promises to pay to the order of Payee. Interest rate: 8.0% per annum, not to exceed the highest lawful rate. Maturity date: 2031-01-01. Events of Default: payment default, insolvency, bankruptcy. Acceleration: holder may declare full principal and accrued interest immediately due. Waivers: maker waives presentment, demand, notice of dishonor, and protest.",
  ],
];

describe("v4 Banking — compliant promissory-note fixture", () => {
  it("emits no critical findings against the compliant note fixture", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_NOTE), NOTE_PB);
    const run = await runEngine({ rules: BANKING_RULES, ctx, source_file: SRC });
    const criticals = run.findings.filter((f) => f.severity === "critical");
    expect(criticals.map((f) => f.rule_id)).toEqual([]);
  });

  it("is deterministic across runs", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_NOTE), NOTE_PB);
    const a = await runEngine({ rules: BANKING_RULES, ctx, source_file: SRC });
    const b = await runEngine({ rules: BANKING_RULES, ctx, source_file: SRC });
    expect(a.result_hash).toEqual(b.result_hash);
  });
});

describe("v4 Banking — failure cases", () => {
  it("BNK-002 fires when note omits unconditional-promise language", async () => {
    const ctx = withPb(
      buildContext([
        "Note",
        "Maker Acme owes Payee BigBank $1,000,000 due 2031-01-01 with interest at 8% per annum, not to exceed the highest lawful rate. Maker waives presentment.",
      ]),
      NOTE_PB,
    );
    const run = await runEngine({ rules: BANKING_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "BNK-002")).toBe(true);
  });

  it("BNK-010 fires when loan agreement omits negative covenants", async () => {
    const ctx = withPb(
      buildContext([
        "Loan Agreement",
        "Loan amount: $50,000,000 term loan; use of proceeds: working capital. Interest: SOFR + 350 bps spread, 1.00% floor. Affirmative covenants: financial statements quarterly, maintenance of existence. Financial covenants: minimum liquidity $5M. Events of Default: payment default, cross-default, insolvency, 30-day cure period.",
      ]),
      LOAN_PB,
    );
    const run = await runEngine({ rules: BANKING_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "BNK-010")).toBe(true);
  });

  it("BNK-015 fires when security agreement omits granting clause", async () => {
    const ctx = withPb(
      buildContext([
        "Security Agreement",
        "Debtor Acme. Secured Party BigBank. Collateral: all accounts, inventory, equipment, and general intangibles. Representations: Debtor owns the collateral free of liens. Authorization to file UCC-1 financing statements. Remedies on default per UCC Article 9 — commercially reasonable disposition, repossession, deficiency.",
      ]),
      SEC_PB,
    );
    const run = await runEngine({ rules: BANKING_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "BNK-015")).toBe(true);
  });

  it("BNK-023 fires when guaranty omits suretyship-defenses waiver", async () => {
    const ctx = withPb(
      buildContext([
        "Guaranty",
        "Guarantor: Jane Smith. Obligee: BigBank. Underlying obligation: Note dated 2026-01-01. Type: continuing guaranty of payment, absolute. Cap: $1,000,000. Subrogation deferred until paid in full. Reinstatement clause for preferences applies.",
      ]),
      GTY_PB,
    );
    const run = await runEngine({ rules: BANKING_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "BNK-023")).toBe(true);
  });

  it("BNK-035 fires when subordination omits payment subordination / blockage", async () => {
    const ctx = withPb(
      buildContext([
        "Subordination Agreement",
        "Subordinated Debt: Junior Note dated 2026-01-01. Senior Debt: Senior facility including refinancings. Permitted payments: scheduled interest absent senior default. Section 510(a) of the Bankruptcy Code applies.",
      ]),
      SUB_PB,
    );
    const run = await runEngine({ rules: BANKING_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "BNK-035")).toBe(true);
  });

  it("BNK-040 fires when deed of trust omits legal description", async () => {
    const ctx = withPb(
      buildContext([
        "Deed of Trust",
        "Grantor: Acme. Trustee: First American Title. Beneficiary: BigBank. Property at 100 Main Street. Grants and conveys the property in trust to have and to hold. Power of sale with state notice procedure. Due on sale applies under Garn-St Germain. Notarized below.",
      ]),
      DOT_PB,
    );
    const run = await runEngine({ rules: BANKING_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "BNK-040")).toBe(true);
  });

  it("BNK-047 fires when UCC-1 prose omits collateral indication", async () => {
    const ctx = withPb(
      buildContext([
        "Financing Statement",
        "Debtor: Acme Corp (exact legal name from Delaware Secretary of State public organic record). Secured Party: BigBank, 1 Main St, mailing address. Filing office: Delaware Secretary of State, UCC Division. Lapse: 5 years; continuation 6 months before lapse. Authorized by Security Agreement of 2026-01-01.",
      ]),
      UCC1_PB,
    );
    const run = await runEngine({ rules: BANKING_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "BNK-047")).toBe(true);
  });

  it("BNK-027 fires when intercreditor omits priorities", async () => {
    const ctx = withPb(
      buildContext([
        "Intercreditor",
        "Payment blockage applies during default. Turnover required. 180-day enforcement standstill. Bankruptcy: DIP financing, 363 sale, plan support. Buy-out option at par plus accrued. Amendments require consent of each creditor party.",
      ]),
      IC_PB,
    );
    const run = await runEngine({ rules: BANKING_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "BNK-027")).toBe(true);
  });
});
