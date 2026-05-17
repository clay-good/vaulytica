import { describe, expect, it } from "vitest";

import { PRIVACY_EXTENDED_RULES } from "./rules.js";
import { PRV_PLAYBOOK_IDS } from "./_helpers.js";
import { buildContext } from "../../../_test-fixtures.js";
import { runEngine } from "../../../runner.js";
import type { Playbook, RuleContext } from "../../../finding.js";

const COOKIE_PB: Playbook = { id: "cookie-notice", version: "1.0.0" };
const NPP_PB: Playbook = { id: "hipaa-npp", version: "1.0.0" };
const ROPA_PB: Playbook = { id: "ropa-art-30", version: "1.0.0" };
const DPIA_PB: Playbook = { id: "dpia-art-35", version: "1.0.0" };
const VSQ_PB: Playbook = { id: "vendor-security-questionnaire", version: "1.0.0" };
const INCIDENT_PB: Playbook = { id: "incident-notification", version: "1.0.0" };

const SRC = { name: "test.docx", sha256: "0".repeat(64), size_bytes: 100 };

function withPb(ctx: RuleContext, pb: Playbook): RuleContext {
  return { ...ctx, playbook: pb };
}

describe("v4 Privacy-extended ruleset — registry contract", () => {
  it("exports exactly 40 rules with stable PRV-NNN ids", () => {
    expect(PRIVACY_EXTENDED_RULES.length).toBe(40);
    const ids = PRIVACY_EXTENDED_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(40);
    for (const r of PRIVACY_EXTENDED_RULES) {
      expect(r.id, r.id).toMatch(/^PRV-\d{3}$/);
      expect(r.version, r.id).toMatch(/^\d+\.\d+\.\d+$/);
      expect(r.category, r.id).toBe("privacy-extended");
      expect(r.applies_to_playbooks, r.id).toBeDefined();
    }
  });

  it("scopes every rule to one or more privacy-extended playbooks", () => {
    const allowed = new Set<string>(PRV_PLAYBOOK_IDS);
    for (const r of PRIVACY_EXTENDED_RULES) {
      for (const pb of r.applies_to_playbooks ?? []) {
        expect(allowed.has(pb), `${r.id} → ${pb}`).toBe(true);
      }
    }
  });

  it("does not fire under a non-privacy-extended playbook", async () => {
    const ctx = buildContext(["Some other doc", "No privacy content."]);
    const run = await runEngine({ rules: PRIVACY_EXTENDED_RULES, ctx, source_file: SRC });
    expect(run.findings.length).toBe(0);
    expect(run.execution_log.every((e) => !e.fired)).toBe(true);
  });
});

const COMPLIANT_NPP: [string, ...string[]][] = [
  [
    "Notice of Privacy Practices",
    "THIS NOTICE DESCRIBES HOW MEDICAL INFORMATION ABOUT YOU MAY BE USED AND DISCLOSED AND HOW YOU CAN GET ACCESS TO THIS INFORMATION. PLEASE REVIEW IT CAREFULLY. Uses and Disclosures: We may use your protected health information for Treatment, Payment, and Health Care Operations (TPO). Your Rights include the right to access and inspect, the right to amend records, an accounting of disclosures, and breach notification. Our Duties: we are required by law to maintain the privacy of your information and to abide by the terms of this notice. Complaints may be filed with us or with the HHS Office for Civil Rights (OCR); no retaliation will occur. Effective Date: 2026-01-01. Privacy Officer: Jane Smith, phone 555-1212, email privacy@example.com. Substance use (42 C.F.R. Part 2), mental health, HIV / AIDS, and genetic (GINA) information have additional protections.",
  ],
];

describe("v4 Privacy-extended — compliant NPP fixture", () => {
  it("emits no critical findings against the compliant NPP fixture", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_NPP), NPP_PB);
    const run = await runEngine({ rules: PRIVACY_EXTENDED_RULES, ctx, source_file: SRC });
    const criticals = run.findings.filter((f) => f.severity === "critical");
    expect(criticals.map((f) => f.rule_id)).toEqual([]);
  });

  it("is deterministic across runs", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_NPP), NPP_PB);
    const a = await runEngine({ rules: PRIVACY_EXTENDED_RULES, ctx, source_file: SRC });
    const b = await runEngine({ rules: PRIVACY_EXTENDED_RULES, ctx, source_file: SRC });
    expect(a.result_hash).toEqual(b.result_hash);
  });
});

describe("v4 Privacy-extended — failure cases", () => {
  it("PRV-001 fires when cookie notice omits categories", async () => {
    const ctx = withPb(
      buildContext([
        "Cookie Notice",
        "We use cookies on our site. You consent by clicking accept.",
      ]),
      COOKIE_PB,
    );
    const run = await runEngine({ rules: PRIVACY_EXTENDED_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "PRV-001")).toBe(true);
  });

  it("PRV-007 fires when NPP omits the prescribed header statement", async () => {
    const ctx = withPb(
      buildContext([
        "Privacy Notice",
        "We may use your health information for treatment, payment, and health care operations. You have rights to access, amend, and accounting. We are required by law to maintain privacy.",
      ]),
      NPP_PB,
    );
    const run = await runEngine({ rules: PRIVACY_EXTENDED_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "PRV-007")).toBe(true);
  });

  it("PRV-015 fires when ROPA omits controller / DPO identification", async () => {
    const ctx = withPb(
      buildContext([
        "ROPA",
        "Purposes of processing: HR / payroll. Categories of data subjects: employees. Categories of personal data: identification only. Recipients: payroll vendor. International transfers: none.",
      ]),
      ROPA_PB,
    );
    const run = await runEngine({ rules: PRIVACY_EXTENDED_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "PRV-015")).toBe(true);
  });

  it("PRV-023 fires when DPIA omits risk assessment", async () => {
    const ctx = withPb(
      buildContext([
        "Assessment Document",
        "Description of the processing: customer analytics. Necessity and proportionality were assessed. Mitigations and safeguards: encryption.",
      ]),
      DPIA_PB,
    );
    const run = await runEngine({ rules: PRIVACY_EXTENDED_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "PRV-023")).toBe(true);
  });

  it("PRV-029 fires when VSQ omits encryption at-rest / in-transit", async () => {
    const ctx = withPb(
      buildContext([
        "Vendor Security Questionnaire",
        "Information security policy approved by management. Access control: RBAC with MFA and quarterly access reviews. SOC 2 Type II. Vulnerability management with critical 7d patch SLA and annual penetration test. Incident response within 72 hours.",
      ]),
      VSQ_PB,
    );
    const run = await runEngine({ rules: PRIVACY_EXTENDED_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "PRV-029")).toBe(true);
  });

  it("PRV-039 fires when incident-notification template omits timing", async () => {
    const ctx = withPb(
      buildContext([
        "Incident Notification",
        "Nature of the incident: unauthorized access on 2026-04-01. Categories of data subjects: customers. DPO contact: privacy@example.com. Likely consequences: identity theft. Measures taken: containment, credit monitoring.",
      ]),
      INCIDENT_PB,
    );
    const run = await runEngine({ rules: PRIVACY_EXTENDED_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "PRV-039")).toBe(true);
  });
});
