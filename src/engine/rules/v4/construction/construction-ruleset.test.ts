import { describe, expect, it } from "vitest";

import { CONSTRUCTION_RULES } from "./rules.js";
import { CON_PLAYBOOK_IDS } from "./_helpers.js";
import { buildContext } from "../../../_test-fixtures.js";
import { runEngine } from "../../../runner.js";
import type { Playbook, RuleContext } from "../../../finding.js";

const CONTRACT_PB: Playbook = { id: "construction-contract", version: "1.0.0" };
const SUBK_PB: Playbook = { id: "subcontractor-agreement", version: "1.0.0" };
const LW_PB: Playbook = { id: "construction-lien-waiver", version: "1.0.0" };
const BOND_PB: Playbook = { id: "payment-performance-bond", version: "1.0.0" };
const CO_PB: Playbook = { id: "change-order", version: "1.0.0" };

const SRC = { name: "test.docx", sha256: "0".repeat(64), size_bytes: 100 };

function withPb(ctx: RuleContext, pb: Playbook): RuleContext {
  return { ...ctx, playbook: pb };
}

describe("v4 Construction ruleset — registry contract", () => {
  it("exports exactly 30 rules with stable CON-NNN ids", () => {
    expect(CONSTRUCTION_RULES.length).toBe(30);
    const ids = CONSTRUCTION_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(30);
    for (const r of CONSTRUCTION_RULES) {
      expect(r.id, r.id).toMatch(/^CON-\d{3}$/);
      expect(r.version, r.id).toMatch(/^\d+\.\d+\.\d+$/);
      expect(r.category, r.id).toBe("construction");
      expect(r.applies_to_playbooks, r.id).toBeDefined();
    }
  });

  it("scopes every rule to one or more construction playbooks", () => {
    const allowed = new Set<string>(CON_PLAYBOOK_IDS);
    for (const r of CONSTRUCTION_RULES) {
      for (const pb of r.applies_to_playbooks ?? []) {
        expect(allowed.has(pb), `${r.id} → ${pb}`).toBe(true);
      }
    }
  });

  it("does not fire under a non-construction playbook", async () => {
    const ctx = buildContext(["Some other doc", "No construction content."]);
    const run = await runEngine({ rules: CONSTRUCTION_RULES, ctx, source_file: SRC });
    expect(run.findings.length).toBe(0);
    expect(run.execution_log.every((e) => !e.fired)).toBe(true);
  });
});

const COMPLIANT_CONTRACT: [string, ...string[]][] = [
  [
    "Construction Contract",
    "Owner: Acme. Contractor: BuildCo. Architect: Design LLP. Scope of work per Contract Documents including drawings, specifications, and addenda. Contract Sum: $5,000,000 stipulated sum. Progress payments monthly with 10% retainage. Substantial completion: 2027-06-01. Final completion: 2027-09-01. Liquidated damages of $5,000 per day. Concealed or unknown conditions per A201 § 3.7.4. Indemnification carves out indemnitee's sole negligence; insurance per A201 § 11 with waiver of subrogation. Termination for cause with cure; termination for convenience with overhead and profit.",
  ],
];

describe("v4 Construction — compliant contract fixture", () => {
  it("emits no critical findings against the compliant contract fixture", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_CONTRACT), CONTRACT_PB);
    const run = await runEngine({ rules: CONSTRUCTION_RULES, ctx, source_file: SRC });
    const criticals = run.findings.filter((f) => f.severity === "critical");
    expect(criticals.map((f) => f.rule_id)).toEqual([]);
  });

  it("is deterministic across runs", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_CONTRACT), CONTRACT_PB);
    const a = await runEngine({ rules: CONSTRUCTION_RULES, ctx, source_file: SRC });
    const b = await runEngine({ rules: CONSTRUCTION_RULES, ctx, source_file: SRC });
    expect(a.result_hash).toEqual(b.result_hash);
  });
});

describe("v4 Construction — failure cases", () => {
  it("CON-006 fires when contract omits indemnification / insurance / waiver", async () => {
    const ctx = withPb(
      buildContext([
        "Construction Contract",
        "Owner BuildIt; contractor BuildCo; architect Design LLP. Scope per Contract Documents and specifications. Contract Sum: $1M stipulated sum, progress payments monthly. Substantial completion 2027-01-01. Termination provisions apply.",
      ]),
      CONTRACT_PB,
    );
    const run = await runEngine({ rules: CONSTRUCTION_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "CON-006")).toBe(true);
  });

  it("CON-009 fires when subcontract omits flow-down", async () => {
    const ctx = withPb(
      buildContext([
        "Subcontractor Agreement",
        "General contractor GC and subcontractor SubCo on the project. Pay-when-paid timing applies. Daily cleanup required. Coordination per GC schedule. One-year warranty on workmanship and materials. Mediation then arbitration; New York venue and governing law.",
      ]),
      SUBK_PB,
    );
    const run = await runEngine({ rules: CONSTRUCTION_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "CON-009")).toBe(true);
  });

  it("CON-014 fires when lien waiver omits waiver type", async () => {
    const ctx = withPb(
      buildContext([
        "Release",
        "Claimant releases Acme Owner for the Property at 100 Main St through 2026-03-01. Amount: $50,000. Signed by claimant.",
      ]),
      LW_PB,
    );
    const run = await runEngine({ rules: CONSTRUCTION_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "CON-014")).toBe(true);
  });

  it("CON-022 fires when bond omits penal sum", async () => {
    const ctx = withPb(
      buildContext([
        "Performance Bond",
        "Principal: BuildCo. Surety: Big Surety Co. Obligee: Acme Owner. AIA A312 Performance Bond. Underlying contract dated 2026-01-01 incorporated by reference. Default declaration triggers surety options to complete, tender, pay, or deny.",
      ]),
      BOND_PB,
    );
    const run = await runEngine({ rules: CONSTRUCTION_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "CON-022")).toBe(true);
  });

  it("CON-028 fires when change order omits time adjustment", async () => {
    const ctx = withPb(
      buildContext([
        "Change Order",
        "Original contract sum: $5,000,000. Revised contract sum: $5,150,000. Description of change in work: added stairwell railings on floors 2-5. Owner, architect, and contractor signatures below. Waiver of further claims for the changed work.",
      ]),
      CO_PB,
    );
    const run = await runEngine({ rules: CONSTRUCTION_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "CON-028")).toBe(true);
  });
});
