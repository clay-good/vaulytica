import { describe, expect, it } from "vitest";

import { M_AND_A_RULES } from "./rules.js";
import { MA_PLAYBOOK_IDS } from "./_helpers.js";
import { buildContext } from "../../../_test-fixtures.js";
import { runEngine } from "../../../runner.js";
import type { Playbook, RuleContext } from "../../../finding.js";

const LOI_PB: Playbook = { id: "loi-term-sheet", version: "1.0.0" };
const SPA_PB: Playbook = { id: "stock-purchase-agreement", version: "1.0.0" };
const APA_PB: Playbook = { id: "asset-purchase-agreement", version: "1.0.0" };
const EARNOUT_PB: Playbook = { id: "earnout-agreement", version: "1.0.0" };
const DS_PB: Playbook = { id: "disclosure-schedules", version: "1.0.0" };

const SRC = { name: "test.docx", sha256: "0".repeat(64), size_bytes: 100 };

function withPb(ctx: RuleContext, pb: Playbook): RuleContext {
  return { ...ctx, playbook: pb };
}

describe("v4 M&A ruleset — registry contract", () => {
  it("exports exactly 80 rules with stable MNA-NNN ids", () => {
    expect(M_AND_A_RULES.length).toBe(80);
    const ids = M_AND_A_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(80);
    for (const r of M_AND_A_RULES) {
      expect(r.id, r.id).toMatch(/^MNA-\d{3}$/);
      expect(r.version, r.id).toMatch(/^\d+\.\d+\.\d+$/);
      expect(r.category, r.id).toBe("m-and-a");
      expect(r.applies_to_playbooks, r.id).toBeDefined();
    }
  });

  it("scopes every rule to one or more M&A playbooks", () => {
    const allowed = new Set<string>(MA_PLAYBOOK_IDS);
    for (const r of M_AND_A_RULES) {
      for (const pb of r.applies_to_playbooks ?? []) {
        expect(allowed.has(pb), `${r.id} → ${pb}`).toBe(true);
      }
    }
  });

  it("does not fire any rule under a non-M&A playbook", async () => {
    const ctx = buildContext(["Some other doc", "No M&A content here."]);
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    expect(run.findings.length).toBe(0);
    expect(run.execution_log.every((e) => !e.fired)).toBe(true);
  });
});

const COMPLIANT_LOI: [string, ...string[]][] = [
  [
    "Letter of Intent",
    "This Letter of Intent reflects the parties' good-faith outline. Binding provisions: confidentiality, exclusivity (45 days), expenses, governing law, and forum. Non-Binding: purchase price ($50M aggregate consideration), structure (stock purchase), and definitive-agreement terms. Confidentiality: each party shall hold the other's information in confidence. Exclusivity: seller will not solicit competing offers during the no-shop period. Purchase Price: $50,000,000 aggregate consideration, cash. Structure: stock purchase of all outstanding shares. Conditions: due diligence, financing, HSR clearance. Expenses: each party shall bear its own expenses. Termination: this LOI expires on the drop-dead date. Governing Law: Delaware. Forum: Delaware Chancery.",
  ],
];

describe("v4 M&A — compliant LOI fixture", () => {
  it("emits no critical findings against the compliant LOI fixture", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_LOI), LOI_PB);
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    const criticals = run.findings.filter((f) => f.severity === "critical");
    expect(criticals.map((f) => f.rule_id)).toEqual([]);
  });

  it("is deterministic across runs", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_LOI), LOI_PB);
    const a = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    const b = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    expect(a.result_hash).toEqual(b.result_hash);
  });
});

describe("v4 M&A — failure cases", () => {
  it("MNA-001 fires when LOI omits binding / non-binding demarcation", async () => {
    const ctx = withPb(
      buildContext([
        "LOI",
        "The parties intend to consummate the transaction at $50M with no further detail provided.",
      ]),
      LOI_PB,
    );
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "MNA-001")).toBe(true);
  });

  it("MNA-010 fires when SPA omits the operative purchase-and-sale clause", async () => {
    const ctx = withPb(
      buildContext([
        "Stock Purchase Agreement",
        "Definitions: the Company, the Buyer, the Sellers. Representations and warranties of the Company. Indemnification and survival. Closing conditions including bring-down. Material Adverse Effect carve-outs. Governing Law is Delaware.",
      ]),
      SPA_PB,
    );
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "MNA-010")).toBe(true);
  });

  it("MNA-040 fires on disclosure-schedule data-room reference", async () => {
    const ctx = withPb(
      buildContext([
        "Disclosure Schedule",
        "Section 3.10 Material Contracts: see the data room folder Contracts/.",
      ]),
      DS_PB,
    );
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "MNA-040")).toBe(true);
  });

  it("MNA-067 fires when earnout disclaims duty to maximize", async () => {
    const ctx = withPb(
      buildContext([
        "Earnout Agreement",
        "Buyer has no duty to maximize the earnout and may operate the business in its sole discretion notwithstanding any effect on the earnout.",
      ]),
      EARNOUT_PB,
    );
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "MNA-067")).toBe(true);
  });

  it("MNA-024 fires when APA omits bulk-sales-law clause", async () => {
    const ctx = withPb(
      buildContext([
        "Asset Purchase Agreement",
        "Purchased Assets: equipment and inventory. Excluded Assets: cash. Assumed Liabilities: trade payables. Excluded Liabilities: tax. Purchase Price Allocation per IRC § 1060. Required Consents listed in Schedule. Bill of Sale and Assignment and Assumption Agreement are attached.",
      ]),
      APA_PB,
    );
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "MNA-024")).toBe(true);
  });
});

describe("MNA presence forms an APA actually writes (v1.1.0)", () => {
  it("accepts 'governed by the laws of' and a named third-party consent", async () => {
    const ctx = withPb(
      buildContext(
        [
          "8. Conditions to Closing",
          "Buyer's obligation to close is conditioned on assignment of the lease for the premises with the landlord's written consent.",
        ],
        [
          "11. General",
          "This Agreement is governed by the laws of the State of Michigan, and any dispute arising out of this Agreement shall be resolved in the state courts located in Grand Traverse County, Michigan.",
        ],
      ),
      APA_PB,
    );
    const run = await runEngine({
      rules: M_AND_A_RULES,
      ctx,
      executed_at: "2026-05-12T00:00:00Z",
      source_file: SRC,
    });
    const fired = new Set(run.findings.map((f) => f.rule_id));
    expect(fired.has("MNA-019"), "MNA-019 should accept 'governed by the laws of'").toBe(false);
    expect(fired.has("MNA-026"), "MNA-026 should accept a named third-party consent").toBe(false);
  });

  it("still reports both when genuinely absent", async () => {
    const ctx = withPb(
      buildContext(["APA", "Seller sells the purchased assets to Buyer at the closing."]),
      APA_PB,
    );
    const run = await runEngine({
      rules: M_AND_A_RULES,
      ctx,
      executed_at: "2026-05-12T00:00:00Z",
      source_file: SRC,
    });
    const fired = new Set(run.findings.map((f) => f.rule_id));
    expect(fired.has("MNA-019")).toBe(true);
    expect(fired.has("MNA-026")).toBe(true);
  });
});

describe("MNA-042 — the no-admission materiality disclaimer (v1.1.0)", () => {
  const DS_PB_LOCAL: Playbook = { id: "disclosure-schedules", version: "1.0.0" };

  it("reads 'not an admission that such item is material'", async () => {
    const ctx = withPb(
      buildContext([
        "General Notes",
        "The inclusion of any item in these Disclosure Schedules is not an admission that such item is material, and no disclosure shall be deemed to enlarge or establish any standard of materiality or dollar threshold beyond that set forth in the Agreement.",
      ]),
      DS_PB_LOCAL,
    );
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    expect(run.findings.map((f) => f.rule_id)).not.toContain("MNA-042");
  });

  it("still fires when no materiality disclaimer exists", async () => {
    const ctx = withPb(
      buildContext(["Schedules", "The following contracts are disclosed."]),
      DS_PB_LOCAL,
    );
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    expect(run.findings.map((f) => f.rule_id)).toContain("MNA-042");
  });
});

describe("MNA-040 — blanket data-room deemed-disclosure in its real wording (v1.1.0)", () => {
  const run1 = async (body: string) => {
    const ctx = withPb(buildContext(["Disclosure", body]), DS_PB);
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    return new Set(run.findings.map((f) => f.rule_id));
  };

  it("fires on 'any matter disclosed in the data room shall be deemed disclosed'", async () => {
    expect(
      (
        await run1(
          "Any matter disclosed in the data room shall be deemed disclosed for all purposes.",
        )
      ).has("MNA-040"),
    ).toBe(true);
  });

  it("fires on reps 'qualified by all documents made available in the data room'", async () => {
    expect(
      (
        await run1(
          "The representations are qualified by all documents made available in the data room.",
        )
      ).has("MNA-040"),
    ).toBe(true);
  });

  it("stays silent on a clean numbered-schedule disclosure", async () => {
    expect(
      (
        await run1(
          "The matters set forth on Schedule 3.7 are disclosed in response to Section 3.7 of the Agreement.",
        )
      ).has("MNA-040"),
    ).toBe(false);
  });
});

describe("Escrow release & termination in their real wording (v1.1.0)", () => {
  const ESCROW_PB: Playbook = { id: "escrow-agreement", version: "1.0.0" };
  const run1 = async (body: string) => {
    const ctx = withPb(buildContext(["Escrow", body]), ESCROW_PB);
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    return new Set(run.findings.map((f) => f.rule_id));
  };

  it("MNA-048 reads 'disburse … upon joint written instructions signed by the parties'", async () => {
    expect(
      (
        await run1(
          "The Escrow Agent shall disburse the Escrow Funds upon receipt of joint written instructions signed by the Buyer and the Seller.",
        )
      ).has("MNA-048"),
    ).toBe(false);
    expect((await run1("The Escrow Agent shall hold the Escrow Funds.")).has("MNA-048")).toBe(true);
  });

  it("MNA-053 reads 'This Agreement terminates when all Escrow Funds have been disbursed'", async () => {
    expect(
      (
        await run1("This Agreement terminates when all Escrow Funds have been disbursed.")
      ).has("MNA-053"),
    ).toBe(false);
    expect(
      (await run1("The Escrow Agent shall disburse per instructions.")).has("MNA-053"),
    ).toBe(true);
  });
});

describe("Earnout conduct covenant & CoC acceleration in real wording (v1.1.0)", () => {
  const EARNOUT_PB: Playbook = { id: "earnout-agreement", version: "1.0.0" };
  const run1 = async (body: string) => {
    const ctx = withPb(buildContext(["Earnout", body]), EARNOUT_PB);
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    return new Set(run.findings.map((f) => f.rule_id));
  };

  it("MNA-065 reads a period-first 'operate the business in good faith' covenant", async () => {
    expect(
      (
        await run1(
          "During the Earnout Period, the Buyer shall operate the acquired business in good faith and shall not take any action for the primary purpose of reducing the Earnout Payments.",
        )
      ).has("MNA-065"),
    ).toBe(false);
    expect(
      (await run1("The Buyer shall pay the Sellers based on revenue milestones.")).has("MNA-065"),
    ).toBe(true);
  });

  it("MNA-070 reads acceleration stated as the event ('sells the business … immediately due')", async () => {
    expect(
      (
        await run1(
          "If the Buyer sells the acquired business during the Earnout Period, all unpaid Earnout Payments become immediately due.",
        )
      ).has("MNA-070"),
    ).toBe(false);
    expect(
      (await run1("The Buyer shall pay each Earnout Payment within 10 days.")).has("MNA-070"),
    ).toBe(true);
  });
});

describe("MNA-012 reads the verb-form reps-and-warranties article (v1.1.0)", () => {
  const run1 = async (body: string) => {
    const ctx = withPb(buildContext(["Representations", body]), SPA_PB);
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    return new Set(run.findings.map((f) => f.rule_id));
  };

  it("reads 'The Seller represents and warrants that …'", async () => {
    expect(
      (
        await run1("The Seller represents and warrants that the Company is duly organized.")
      ).has("MNA-012"),
    ).toBe(false);
  });

  it("still fires when the agreement contains no representations", async () => {
    expect(
      (await run1("The Buyer shall pay $9,000,000 at the Closing for the Shares.")).has("MNA-012"),
    ).toBe(true);
  });
});
