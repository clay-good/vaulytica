import { describe, expect, it } from "vitest";

import { EMPLOYMENT_RULES } from "./rules.js";
import { EMP_PLAYBOOK_IDS } from "./_helpers.js";
import { buildContext } from "../../../_test-fixtures.js";
import { runEngine } from "../../../runner.js";
import type { Playbook, RuleContext } from "../../../finding.js";

const EXEC_PB: Playbook = { id: "executive-employment", version: "1.0.0" };
const SEPARATION_PB: Playbook = { id: "separation-agreement", version: "1.0.0" };
const RC_PB: Playbook = { id: "employment-restrictive-covenant", version: "1.0.0" };
const PIIA_PB: Playbook = { id: "piia", version: "1.0.0" };
const HANDBOOK_PB: Playbook = { id: "employee-handbook", version: "1.0.0" };

const SRC = { name: "test.docx", sha256: "0".repeat(64), size_bytes: 100 };

function withPb(ctx: RuleContext, pb: Playbook): RuleContext {
  return { ...ctx, playbook: pb };
}

describe("v4 Employment ruleset — registry contract", () => {
  it("exports exactly 50 rules with stable EMP-NNN ids", () => {
    expect(EMPLOYMENT_RULES.length).toBe(50);
    const ids = EMPLOYMENT_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(50);
    for (const r of EMPLOYMENT_RULES) {
      expect(r.id, r.id).toMatch(/^EMP-\d{3}$/);
      expect(r.version, r.id).toMatch(/^\d+\.\d+\.\d+$/);
      expect(r.category, r.id).toBe("employment");
      expect(r.applies_to_playbooks, r.id).toBeDefined();
    }
  });

  it("scopes every rule to one or more employment playbooks", () => {
    const allowed = new Set<string>(EMP_PLAYBOOK_IDS);
    for (const r of EMPLOYMENT_RULES) {
      for (const pb of r.applies_to_playbooks ?? []) {
        expect(allowed.has(pb), `${r.id} → ${pb}`).toBe(true);
      }
    }
  });

  it("does not fire under a non-employment playbook", async () => {
    const ctx = buildContext(["Some other doc", "No employment content."]);
    const run = await runEngine({ rules: EMPLOYMENT_RULES, ctx, source_file: SRC });
    expect(run.findings.length).toBe(0);
    expect(run.execution_log.every((e) => !e.fired)).toBe(true);
  });
});

const COMPLIANT_SEPARATION: [string, ...string[]][] = [
  [
    "Separation Agreement",
    "Employee is over 40 years of age. The Company offers severance over and above any amounts to which the Employee would otherwise be entitled. The Employee shall have 21 days to consider this Agreement. The Employee may revoke the Agreement within 7 days after signing. You are advised to consult with an attorney before signing. The release includes claims under the Age Discrimination in Employment Act (ADEA) and other applicable law. Protected Rights: nothing in this Agreement prevents Employee from communicating with the SEC, EEOC, NLRB, or other government agency, or from receiving any whistleblower bounty. California § 1542 waiver applies as to known and unknown claims.",
  ],
];

describe("v4 Employment — compliant separation fixture", () => {
  it("emits no critical findings against the compliant separation fixture", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_SEPARATION), SEPARATION_PB);
    const run = await runEngine({ rules: EMPLOYMENT_RULES, ctx, source_file: SRC });
    const criticals = run.findings.filter((f) => f.severity === "critical");
    expect(criticals.map((f) => f.rule_id)).toEqual([]);
  });

  it("is deterministic across runs", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_SEPARATION), SEPARATION_PB);
    const a = await runEngine({ rules: EMPLOYMENT_RULES, ctx, source_file: SRC });
    const b = await runEngine({ rules: EMPLOYMENT_RULES, ctx, source_file: SRC });
    expect(a.result_hash).toEqual(b.result_hash);
  });
});

describe("v4 Employment — failure cases", () => {
  it("EMP-015 fires when separation omits 21/45-day consideration period", async () => {
    const ctx = withPb(
      buildContext([
        "Separation Agreement",
        "Employee releases all claims. You may revoke within 7 days. Advised to consult attorney. ADEA included.",
      ]),
      SEPARATION_PB,
    );
    const run = await runEngine({ rules: EMPLOYMENT_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "EMP-015")).toBe(true);
  });

  it("EMP-020 fires on overbroad confidentiality / non-disparagement", async () => {
    const ctx = withPb(
      buildContext([
        "Separation",
        "Employee shall not disclose any terms of this Agreement to any person. Employee shall not disparage any individual associated with the Company.",
      ]),
      SEPARATION_PB,
    );
    const run = await runEngine({ rules: EMPLOYMENT_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "EMP-020")).toBe(true);
  });

  it("EMP-003 fires when executive agreement omits § 409A compliance", async () => {
    const ctx = withPb(
      buildContext([
        "Executive Employment Agreement",
        "Title: Chief Executive Officer. Reports to Board. Base salary: $500,000. Annual bonus: target 100%. Cause and Good Reason defined. Severance: 24 months. Clawback: per company policy. Restrictive covenants included.",
      ]),
      EXEC_PB,
    );
    const run = await runEngine({ rules: EMPLOYMENT_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "EMP-003")).toBe(true);
  });

  it("EMP-024 fires when restrictive covenant agreement contains worker non-compete", async () => {
    const ctx = withPb(
      buildContext([
        "Restrictive Covenant Agreement",
        "Employee shall not compete with the Company for 12 months after termination of employment.",
      ]),
      RC_PB,
    );
    const run = await runEngine({ rules: EMPLOYMENT_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "EMP-024")).toBe(true);
  });

  it("EMP-035 fires when PIIA lacks the California § 2870 carve-out", async () => {
    const ctx = withPb(
      buildContext([
        "Proprietary Information and Inventions Agreement",
        "Employee assigns all inventions to Employer. Confidentiality applies. DTSA notice under 18 U.S.C. § 1833 attached. Return of materials on termination.",
      ]),
      PIIA_PB,
    );
    const run = await runEngine({ rules: EMPLOYMENT_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "EMP-035")).toBe(true);
  });

  it("EMP-049 fires on overbroad NLRA § 7 confidentiality / wage-discussion ban", async () => {
    const ctx = withPb(
      buildContext([
        "Employee Handbook",
        "Employees shall not discuss wages or working conditions with each other.",
      ]),
      HANDBOOK_PB,
    );
    const run = await runEngine({ rules: EMPLOYMENT_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "EMP-049")).toBe(true);
  });
});
