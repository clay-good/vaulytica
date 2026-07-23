import { describe, expect, it } from "vitest";

import { SETTLEMENT_RULES } from "./rules.js";
import { SETTLE_PLAYBOOK_IDS } from "./_helpers.js";
import { buildContext } from "../../../_test-fixtures.js";
import { runEngine } from "../../../runner.js";
import type { Playbook, RuleContext } from "../../../finding.js";

const RELEASE_PB: Playbook = { id: "mutual-release", version: "1.0.0" };
const SETTLEMENT_PB: Playbook = { id: "confidential-settlement", version: "1.0.0" };
const DEMAND_PB: Playbook = { id: "demand-letter", version: "1.0.0" };
const CD_PB: Playbook = { id: "cease-and-desist", version: "1.0.0" };
const TOLLING_PB: Playbook = { id: "tolling-agreement", version: "1.0.0" };
const LITHOLD_PB: Playbook = { id: "litigation-hold", version: "1.0.0" };

const SRC = { name: "test.docx", sha256: "0".repeat(64), size_bytes: 100 };

function withPb(ctx: RuleContext, pb: Playbook): RuleContext {
  return { ...ctx, playbook: pb };
}

describe("v4 Settlement ruleset — registry contract", () => {
  it("exports exactly 30 rules with stable SET-NNN ids", () => {
    expect(SETTLEMENT_RULES.length).toBe(30);
    const ids = SETTLEMENT_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(30);
    for (const r of SETTLEMENT_RULES) {
      expect(r.id, r.id).toMatch(/^SET-\d{3}$/);
      expect(r.version, r.id).toMatch(/^\d+\.\d+\.\d+$/);
      expect(r.category, r.id).toBe("settlement");
      expect(r.applies_to_playbooks, r.id).toBeDefined();
    }
  });

  it("scopes every rule to one or more settlement playbooks", () => {
    const allowed = new Set<string>(SETTLE_PLAYBOOK_IDS);
    for (const r of SETTLEMENT_RULES) {
      for (const pb of r.applies_to_playbooks ?? []) {
        expect(allowed.has(pb), `${r.id} → ${pb}`).toBe(true);
      }
    }
  });

  it("does not fire under a non-settlement playbook", async () => {
    const ctx = buildContext(["Some other doc", "No settlement content."]);
    const run = await runEngine({ rules: SETTLEMENT_RULES, ctx, source_file: SRC });
    expect(run.findings.length).toBe(0);
    expect(run.execution_log.every((e) => !e.fired)).toBe(true);
  });
});

const COMPLIANT_RELEASE: [string, ...string[]][] = [
  [
    "Mutual General Release",
    "Releasor and Releasee, including their respective parents, subsidiaries, affiliates, officers, directors, employees, and agents, hereby release any and all claims, known or unknown, arising out of the dispute. This is a compromise of disputed claims and is not an admission of liability or wrongdoing. California Civil Code § 1542 is expressly waived: Releasor acknowledges that a general release does not extend to unknown claims and waives that protection.",
  ],
];

describe("v4 Settlement — compliant release fixture", () => {
  it("emits no critical findings against the compliant release fixture", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_RELEASE), RELEASE_PB);
    const run = await runEngine({ rules: SETTLEMENT_RULES, ctx, source_file: SRC });
    const criticals = run.findings.filter((f) => f.severity === "critical");
    expect(criticals.map((f) => f.rule_id)).toEqual([]);
  });

  it("is deterministic across runs", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_RELEASE), RELEASE_PB);
    const a = await runEngine({ rules: SETTLEMENT_RULES, ctx, source_file: SRC });
    const b = await runEngine({ rules: SETTLEMENT_RULES, ctx, source_file: SRC });
    expect(a.result_hash).toEqual(b.result_hash);
  });
});

describe("v4 Settlement — failure cases", () => {
  it("SET-001 fires when release omits party identification", async () => {
    const ctx = withPb(
      buildContext([
        "Release",
        "All claims are released. Section 1542 is waived as to known or unknown claims.",
      ]),
      RELEASE_PB,
    );
    const run = await runEngine({ rules: SETTLEMENT_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "SET-001")).toBe(true);
  });

  it("SET-007 fires on overbroad confidentiality / non-disparagement in settlement", async () => {
    const ctx = withPb(
      buildContext([
        "Confidential Settlement Agreement",
        "Settlement payment: $50,000. Employee shall not disclose any terms of this Agreement to any person. Employee shall not disparage any individual associated with the Company.",
      ]),
      SETTLEMENT_PB,
    );
    const run = await runEngine({ rules: SETTLEMENT_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "SET-007")).toBe(true);
  });

  it("SET-013 fires on FDCPA-violative threats in a demand letter", async () => {
    const ctx = withPb(
      buildContext([
        "Demand Letter",
        "Please respond within 14 days. If you fail to pay, we will arrange your arrest and criminal prosecution.",
      ]),
      DEMAND_PB,
    );
    const run = await runEngine({ rules: SETTLEMENT_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "SET-013")).toBe(true);
  });

  it("SET-016 fires when cease-and-desist lacks IP identification", async () => {
    const ctx = withPb(
      buildContext([
        "Cease and Desist",
        "You must stop your activities and respond within 7 days.",
      ]),
      CD_PB,
    );
    const run = await runEngine({ rules: SETTLEMENT_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "SET-016")).toBe(true);
  });

  it("SET-021 fires when tolling agreement does not identify tolled claims", async () => {
    const ctx = withPb(
      buildContext([
        "Pause Agreement",
        "The parties agree to pause litigation while they discuss resolution. This agreement terminates on 30 days written notice.",
      ]),
      TOLLING_PB,
    );
    const run = await runEngine({ rules: SETTLEMENT_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "SET-021")).toBe(true);
  });

  it("SET-027 fires when litigation hold does not suspend routine deletion", async () => {
    const ctx = withPb(
      buildContext([
        "Litigation Hold Notice",
        "Preserve email, text, and ESI relating to the anticipated litigation. Confidential — attorney work product. Questions: contact counsel by email. Custodians, please acknowledge.",
      ]),
      LITHOLD_PB,
    );
    const run = await runEngine({ rules: SETTLEMENT_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "SET-027")).toBe(true);
  });
});

describe("SET-003 / SET-010 — '(if applicable)' absences require the nexus (v1.1.0)", () => {
  const NY_SETTLEMENT: [string, ...string[]][] = [
    [
      "Confidential Settlement Agreement",
      "The Parties settle all claims arising from a freight-services dispute. Defendant shall pay Plaintiff $425,000 as full consideration. The Parties shall keep the terms of this Agreement confidential.",
      "This Agreement is governed by the laws of the State of New York.",
    ],
  ];

  it("neither fires on a New York commercial settlement with no California or harassment nexus", async () => {
    const ctx = withPb(buildContext(...NY_SETTLEMENT), SETTLEMENT_PB);
    const run = await runEngine({ rules: SETTLEMENT_RULES, ctx, source_file: SRC });
    const ids = run.findings.map((f) => f.rule_id);
    expect(ids).not.toContain("SET-003");
    expect(ids).not.toContain("SET-010");
  });

  it("SET-003 still fires when California law applies and no § 1542 waiver appears", async () => {
    const ctx = withPb(
      buildContext([
        "Settlement Agreement",
        "The Parties settle all claims. This Agreement is governed by the laws of the State of California. The Parties shall keep this Agreement confidential.",
      ]),
      SETTLEMENT_PB,
    );
    const run = await runEngine({ rules: SETTLEMENT_RULES, ctx, source_file: SRC });
    expect(run.findings.map((f) => f.rule_id)).toContain("SET-003");
  });

  it("SET-010 still fires when the settlement covers harassment claims without the recital", async () => {
    const ctx = withPb(
      buildContext([
        "Settlement Agreement",
        "The Parties settle all claims of workplace harassment asserted in the charge. Employer shall pay Claimant $100,000. The Parties shall keep the terms of this Agreement confidential.",
      ]),
      SETTLEMENT_PB,
    );
    const run = await runEngine({ rules: SETTLEMENT_RULES, ctx, source_file: SRC });
    expect(run.findings.map((f) => f.rule_id)).toContain("SET-010");
  });
});
