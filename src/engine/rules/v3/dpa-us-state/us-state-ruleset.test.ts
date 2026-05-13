import { describe, expect, it } from "vitest";

import { DPA_US_STATE_RULES } from "./rules.js";
import { buildContext } from "../../../_test-fixtures.js";
import { runEngine } from "../../../runner.js";
import type { Playbook, RuleContext } from "../../../finding.js";

const CCPA: Playbook = { id: "dpa-ccpa-service-provider", version: "1.0.0" };
const MULTI: Playbook = { id: "dpa-multi-state-us", version: "1.0.0" };
const SRC = { name: "test.docx", sha256: "0".repeat(64), size_bytes: 1 };

const withPb = (ctx: RuleContext, p: Playbook): RuleContext => ({ ...ctx, playbook: p });

const COMPLIANT_US_DPA: [string, ...string[]][] = [
  [
    "CCPA Service Provider Agreement",
    "Effective Date: January 1, 2026. This Agreement is between Business and Service Provider.",
  ],
  [
    "1. Personal Information",
    "Service Provider processes Personal Information on behalf of Business pursuant to this Agreement. Sensitive Personal Information categories include account credentials.",
  ],
  [
    "2. Purpose Limitation",
    "Service Provider shall not retain, use, or disclose Personal Information for any purpose other than the specific business purpose enumerated in this Agreement. Service Provider shall not combine Personal Information with personal information from other sources, except as permitted by 11 CCR § 7050(c).",
  ],
  [
    "3. Prohibitions",
    "Service Provider is prohibited from selling Personal Information. Service Provider is prohibited from sharing Personal Information, including for cross-context behavioral advertising.",
  ],
  [
    "4. Same Level of Privacy Protection",
    "Service Provider shall comply with all applicable obligations under the CCPA and provide the same level of privacy protection as required by the CCPA. Service Provider certifies that it understands the restrictions in this Agreement and the CCPA and will comply with them.",
  ],
  [
    "5. Monitoring and Assistance",
    "Business may take reasonable and appropriate steps to ensure that Service Provider uses Personal Information in a manner consistent with Business's obligations under the CCPA. Service Provider shall assist Business in responding to verifiable consumer requests under the CCPA (access, deletion, opt-out, correction).",
  ],
  [
    "6. Notification of Inability",
    "Service Provider shall notify Business if it makes a determination that it can no longer meet its obligations under the CCPA.",
  ],
  [
    "7. Subcontractor Flow-Down",
    "Service Provider shall engage any subcontractor only pursuant to a written contract requiring the subcontractor to meet the same restrictions and obligations.",
  ],
  [
    "8. Processing Instructions and Scope",
    "Service Provider shall process Personal Information only pursuant to documented instructions. The nature and purpose of the processing, the type of personal data, the duration of processing, and the categories of data subjects are set out in Annex I.",
  ],
  [
    "9. Deletion or Return; Confidentiality; Audit",
    "At Business's direction, Service Provider shall delete or return all Personal Information at the end of the provision of services. Service Provider shall ensure that each person processing Personal Information is subject to a duty of confidentiality. Service Provider shall allow and cooperate with reasonable assessments by Business. Service Provider shall make available to Business information necessary to demonstrate compliance.",
  ],
  [
    "10. Data Minimization",
    "Personal Information collected and processed shall be limited to what is reasonably necessary and proportionate to the disclosed purpose.",
  ],
];

describe("DPA-US-state ruleset — registry contract", () => {
  it("exports exactly 25 rules with stable USDPA-NNN ids", () => {
    expect(DPA_US_STATE_RULES.length).toBe(25);
    const ids = DPA_US_STATE_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(25);
    for (const r of DPA_US_STATE_RULES) {
      expect(r.id).toMatch(/^USDPA-\d{3}$/);
      expect(r.category).toBe("dpa-us-state");
      expect(r.applies_to_playbooks).toContain("dpa-ccpa-service-provider");
    }
  });

  it("does not run when the playbook is not a US-state DPA playbook", async () => {
    const ctx = buildContext(["Agreement", "Generic services agreement."]);
    const run = await runEngine({
      rules: DPA_US_STATE_RULES,
      ctx,
      executed_at: "2026-05-13T00:00:00Z",
      source_file: SRC,
    });
    expect(run.findings).toHaveLength(0);
  });
});

describe("DPA-US-state ruleset — compliant fixture (CCPA Service Provider)", () => {
  it("produces zero critical findings", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_US_DPA), CCPA);
    const run = await runEngine({
      rules: DPA_US_STATE_RULES,
      ctx,
      executed_at: "2026-05-13T00:00:00Z",
      source_file: SRC,
    });
    const criticals = run.findings.filter((f) => f.severity === "critical");
    expect(criticals).toHaveLength(0);
    expect(run.execution_log.filter((e) => e.fired).length).toBeLessThanOrEqual(3);
  });
});

describe("DPA-US-state ruleset — failure modes", () => {
  it("missing no-sale clause fires USDPA-002", async () => {
    const ctx = withPb(buildContext([
      "Agreement",
      "Service Provider processes Personal Information for the specific business purpose enumerated.",
    ]), CCPA);
    const run = await runEngine({ rules: DPA_US_STATE_RULES, ctx, executed_at: "2026-05-13T00:00:00Z", source_file: SRC });
    expect(run.findings.find((f) => f.rule_id === "USDPA-002")).toBeTruthy();
  });

  it("claimed Service Provider without required elements fires USDPA-020", async () => {
    const ctx = withPb(buildContext([
      "Agreement",
      "Vendor has Service Provider status under the CCPA.",
    ]), CCPA);
    const run = await runEngine({ rules: DPA_US_STATE_RULES, ctx, executed_at: "2026-05-13T00:00:00Z", source_file: SRC });
    expect(run.findings.find((f) => f.rule_id === "USDPA-020")).toBeTruthy();
  });

  it("multi-state contract triggers USDPA-021 informational flag", async () => {
    const ctx = withPb(buildContext([
      "Agreement",
      "This Agreement covers several US states with personal data processing.",
    ]), MULTI);
    const run = await runEngine({ rules: DPA_US_STATE_RULES, ctx, executed_at: "2026-05-13T00:00:00Z", source_file: SRC });
    expect(run.findings.find((f) => f.rule_id === "USDPA-021")).toBeTruthy();
  });

  it("document with no personal info reference fires USDPA-025", async () => {
    const ctx = withPb(buildContext([
      "Agreement",
      "Generic services agreement with no privacy terminology.",
    ]), MULTI);
    const run = await runEngine({ rules: DPA_US_STATE_RULES, ctx, executed_at: "2026-05-13T00:00:00Z", source_file: SRC });
    expect(run.findings.find((f) => f.rule_id === "USDPA-025")).toBeTruthy();
  });
});

describe("DPA-US-state ruleset — determinism", () => {
  it("two runs over the same input produce the same result_hash", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_US_DPA), CCPA);
    const a = await runEngine({ rules: DPA_US_STATE_RULES, ctx, executed_at: "2026-05-13T00:00:00Z", source_file: SRC });
    const b = await runEngine({ rules: DPA_US_STATE_RULES, ctx, executed_at: "2026-05-13T00:00:00Z", source_file: SRC });
    expect(a.result_hash).toBe(b.result_hash);
  });
});
