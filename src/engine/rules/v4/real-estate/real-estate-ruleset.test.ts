import { describe, expect, it } from "vitest";

import { REAL_ESTATE_RULES } from "./rules.js";
import { RE_PLAYBOOK_IDS } from "./_helpers.js";
import { buildContext } from "../../../_test-fixtures.js";
import { runEngine } from "../../../runner.js";
import type { Playbook, RuleContext } from "../../../finding.js";

const NET_LEASE_PB: Playbook = { id: "net-lease", version: "1.0.0" };
const PSA_PB: Playbook = { id: "real-estate-psa", version: "1.0.0" };
const CCR_PB: Playbook = { id: "ccrs", version: "1.0.0" };
const SNDA_PB: Playbook = { id: "snda", version: "1.0.0" };
const ESTOPPEL_PB: Playbook = { id: "estoppel-certificate", version: "1.0.0" };

const SRC = { name: "test.docx", sha256: "0".repeat(64), size_bytes: 100 };

function withPb(ctx: RuleContext, pb: Playbook): RuleContext {
  return { ...ctx, playbook: pb };
}

describe("v4 Real-estate ruleset — registry contract", () => {
  it("exports exactly 60 rules with stable RE-NNN ids", () => {
    expect(REAL_ESTATE_RULES.length).toBe(60);
    const ids = REAL_ESTATE_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(60);
    for (const r of REAL_ESTATE_RULES) {
      expect(r.id, r.id).toMatch(/^RE-\d{3}$/);
      expect(r.version, r.id).toMatch(/^\d+\.\d+\.\d+$/);
      expect(r.category, r.id).toBe("real-estate");
      expect(r.applies_to_playbooks, r.id).toBeDefined();
    }
  });

  it("scopes every rule to one or more real-estate playbooks", () => {
    const allowed = new Set<string>(RE_PLAYBOOK_IDS);
    for (const r of REAL_ESTATE_RULES) {
      for (const pb of r.applies_to_playbooks ?? []) {
        expect(allowed.has(pb), `${r.id} → ${pb}`).toBe(true);
      }
    }
  });

  it("does not fire under a non-real-estate playbook", async () => {
    const ctx = buildContext(["Some other doc", "No real-estate content here."]);
    const run = await runEngine({ rules: REAL_ESTATE_RULES, ctx, source_file: SRC });
    expect(run.findings.length).toBe(0);
    expect(run.execution_log.every((e) => !e.fired)).toBe(true);
  });
});

const COMPLIANT_NET_LEASE: [string, ...string[]][] = [
  [
    "Triple Net Lease",
    "This NNN lease provides: Tenant shall pay all real estate taxes, property insurance, and common area maintenance and operating expenses. Tenant Insurance: Tenant shall maintain commercial general liability insurance with limits of $2,000,000 and property insurance. Waiver of subrogation applies. Maintenance and Repair: Landlord is responsible for roof and structural; tenant for everything else. Tenant has an audit right for 12 months. Damage and Destruction: covered. Condemnation: covered. Default Remedies: relet and mitigation. Holdover: 150% of base rent. Surrender clause included.",
  ],
];

describe("v4 Real-estate — compliant NNN lease fixture", () => {
  it("emits no critical findings against the compliant NNN fixture", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_NET_LEASE), NET_LEASE_PB);
    const run = await runEngine({ rules: REAL_ESTATE_RULES, ctx, source_file: SRC });
    const criticals = run.findings.filter((f) => f.severity === "critical");
    expect(criticals.map((f) => f.rule_id)).toEqual([]);
  });

  it("is deterministic across runs", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_NET_LEASE), NET_LEASE_PB);
    const a = await runEngine({ rules: REAL_ESTATE_RULES, ctx, source_file: SRC });
    const b = await runEngine({ rules: REAL_ESTATE_RULES, ctx, source_file: SRC });
    expect(a.result_hash).toEqual(b.result_hash);
  });
});

describe("v4 Real-estate — failure cases", () => {
  it("RE-001 fires when NNN lease omits cost allocation", async () => {
    const ctx = withPb(
      buildContext(["Lease", "This is a long-term lease of the premises."]),
      NET_LEASE_PB,
    );
    const run = await runEngine({ rules: REAL_ESTATE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "RE-001")).toBe(true);
  });

  it("RE-009 fires when PSA omits legal description", async () => {
    const ctx = withPb(
      buildContext([
        "Purchase and Sale Agreement",
        "Purchase price is $5,000,000. Earnest money deposit of $100,000. Due-diligence period of 30 days. Title commitment to be ordered. Conditions to closing apply. Risk of loss before closing covered. Seller represents authority. Brokers covered.",
      ]),
      PSA_PB,
    );
    const run = await runEngine({ rules: REAL_ESTATE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "RE-009")).toBe(true);
  });

  it("RE-038 fires on a discriminatory CC&Rs covenant", async () => {
    const ctx = withPb(
      buildContext([
        "Declaration of Covenants",
        "This property shall be restricted to persons of the Caucasian race only.",
      ]),
      CCR_PB,
    );
    const run = await runEngine({ rules: REAL_ESTATE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "RE-038")).toBe(true);
  });

  it("RE-047 fires when SNDA omits non-disturbance covenant", async () => {
    const ctx = withPb(
      buildContext([
        "Subordination Agreement",
        "Tenant subordinates this Lease to the lien of the Mortgage. Tenant agrees to attorn to any successor landlord. Tenant shall not prepay rent.",
      ]),
      SNDA_PB,
    );
    const run = await runEngine({ rules: REAL_ESTATE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "RE-047")).toBe(true);
  });

  it("RE-042 fires when estoppel omits no-default rep", async () => {
    const ctx = withPb(
      buildContext([
        "Estoppel Certificate",
        "The Lease dated January 1, 2020 between Acme and Tenant is in full force and effect. Current monthly rent is $10,000. Security deposit is $20,000.",
      ]),
      ESTOPPEL_PB,
    );
    const run = await runEngine({ rules: REAL_ESTATE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "RE-042")).toBe(true);
  });
});
