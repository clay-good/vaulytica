import { describe, expect, it } from "vitest";

import { HEALTHCARE_RULES } from "./rules.js";
import { HC_PLAYBOOK_IDS } from "./_helpers.js";
import { buildContext } from "../../../_test-fixtures.js";
import { runEngine } from "../../../runner.js";
import type { Playbook, RuleContext } from "../../../finding.js";

const IC_PB: Playbook = { id: "informed-consent", version: "1.0.0" };
const PHI_PB: Playbook = { id: "phi-authorization", version: "1.0.0" };
const ACK_PB: Playbook = { id: "npp-acknowledgment", version: "1.0.0" };

const SRC = { name: "test.docx", sha256: "0".repeat(64), size_bytes: 100 };

function withPb(ctx: RuleContext, pb: Playbook): RuleContext {
  return { ...ctx, playbook: pb };
}

describe("v4 Healthcare ruleset — registry contract", () => {
  it("exports exactly 25 rules with stable HC-NNN ids", () => {
    expect(HEALTHCARE_RULES.length).toBe(25);
    const ids = HEALTHCARE_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(25);
    for (const r of HEALTHCARE_RULES) {
      expect(r.id, r.id).toMatch(/^HC-\d{3}$/);
      expect(r.version, r.id).toMatch(/^\d+\.\d+\.\d+$/);
      expect(r.category, r.id).toBe("healthcare");
      expect(r.applies_to_playbooks, r.id).toBeDefined();
    }
  });

  it("scopes every rule to one or more healthcare playbooks", () => {
    const allowed = new Set<string>(HC_PLAYBOOK_IDS);
    for (const r of HEALTHCARE_RULES) {
      for (const pb of r.applies_to_playbooks ?? []) {
        expect(allowed.has(pb), `${r.id} → ${pb}`).toBe(true);
      }
    }
  });

  it("does not fire under a non-healthcare playbook", async () => {
    const ctx = buildContext(["Some other doc", "No healthcare content."]);
    const run = await runEngine({ rules: HEALTHCARE_RULES, ctx, source_file: SRC });
    expect(run.findings.length).toBe(0);
    expect(run.execution_log.every((e) => !e.fired)).toBe(true);
  });
});

const COMPLIANT_IC: [string, ...string[]][] = [
  [
    "Informed Consent Form",
    "This study involves research. Purpose: evaluate new therapy; expected duration of participation: 12 months. Risks and Discomforts: reasonably foreseeable side effects include nausea. Benefits: there may be no direct benefit to you; others may benefit. Alternatives: standard-of-care treatments are available. Confidentiality: records are protected; the FDA, sponsor, and IRB may inspect records. Voluntary Participation: participation is voluntary; you may withdraw at any time without penalty or loss of benefits. Contacts: principal investigator Dr. Smith, research-related injury contact phone 555-1212, IRB for subject rights at 555-3434. The trial is registered on clinicaltrials.gov; FDA may inspect records. Research-Related Injury: medical treatment available; questions to 555-5555.",
  ],
];

describe("v4 Healthcare — compliant informed-consent fixture", () => {
  it("emits no critical findings against the compliant IC fixture", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_IC), IC_PB);
    const run = await runEngine({ rules: HEALTHCARE_RULES, ctx, source_file: SRC });
    const criticals = run.findings.filter((f) => f.severity === "critical");
    expect(criticals.map((f) => f.rule_id)).toEqual([]);
  });

  it("is deterministic across runs", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_IC), IC_PB);
    const a = await runEngine({ rules: HEALTHCARE_RULES, ctx, source_file: SRC });
    const b = await runEngine({ rules: HEALTHCARE_RULES, ctx, source_file: SRC });
    expect(a.result_hash).toEqual(b.result_hash);
  });
});

describe("v4 Healthcare — failure cases", () => {
  it("HC-006 fires when IC omits voluntary / withdrawal language", async () => {
    const ctx = withPb(
      buildContext([
        "Informed Consent",
        "This study involves research; purpose is X; duration 6 months. Risks include nausea. Benefits: none direct. Alternatives available. Confidentiality protected; FDA may inspect.",
      ]),
      IC_PB,
    );
    const run = await runEngine({ rules: HEALTHCARE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "HC-006")).toBe(true);
  });

  it("HC-014 fires when PHI authorization omits expiration", async () => {
    const ctx = withPb(
      buildContext([
        "Authorization for Release of PHI",
        "Specific information: medical records dated Jan–Dec 2026 may be used and disclosed. Authorized: Dr. Jane Smith. To: attorney John Doe. Purpose: for litigation. Right to Revoke: in writing, except where actions have been taken in reliance. Treatment, payment, and benefits not conditioned on this authorization. Re-disclosure: information may be further disclosed and no longer protected by HIPAA. Signature and date below; if signed by personal representative, authority described.",
      ]),
      PHI_PB,
    );
    const run = await runEngine({ rules: HEALTHCARE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "HC-014")).toBe(true);
  });

  it("HC-019 fires when NPP acknowledgment omits receipt language", async () => {
    const ctx = withPb(
      buildContext([
        "Patient Form",
        "Patient name: Jane Doe. Date: 2026-04-01. Signature: ____. Covered entity: Acme Clinic. Right to copy on request. Retain for 6 years per 164.530.",
      ]),
      ACK_PB,
    );
    const run = await runEngine({ rules: HEALTHCARE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "HC-019")).toBe(true);
  });
});
