import { describe, expect, it } from "vitest";

import { COMPLIANCE_POLICY_RULES } from "./rules.js";
import { POL_PLAYBOOK_IDS } from "./_helpers.js";
import { buildContext } from "../../../_test-fixtures.js";
import { runEngine } from "../../../runner.js";
import type { Playbook, RuleContext } from "../../../finding.js";

const CODE_PB: Playbook = { id: "code-of-conduct", version: "1.0.0" };
const FCPA_PB: Playbook = { id: "anti-bribery-policy", version: "1.0.0" };
const AML_PB: Playbook = { id: "aml-policy", version: "1.0.0" };
const INSIDER_PB: Playbook = { id: "insider-trading-policy", version: "1.0.0" };
const WB_PB: Playbook = { id: "whistleblower-policy", version: "1.0.0" };
const RET_PB: Playbook = { id: "document-retention-policy", version: "1.0.0" };
const COI_PB: Playbook = { id: "coi-policy", version: "1.0.0" };
const AI_PB: Playbook = { id: "ai-aup-policy", version: "1.0.0" };
const SM_PB: Playbook = { id: "social-media-policy", version: "1.0.0" };
const LOB_PB: Playbook = { id: "lobbying-policy", version: "1.0.0" };

const SRC = { name: "test.docx", sha256: "0".repeat(64), size_bytes: 100 };

function withPb(ctx: RuleContext, pb: Playbook): RuleContext {
  return { ...ctx, playbook: pb };
}

describe("v4 Compliance-policy ruleset — registry contract", () => {
  it("exports exactly 50 rules with stable POL-NNN ids", () => {
    expect(COMPLIANCE_POLICY_RULES.length).toBe(50);
    const ids = COMPLIANCE_POLICY_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(50);
    for (const r of COMPLIANCE_POLICY_RULES) {
      expect(r.id, r.id).toMatch(/^POL-\d{3}$/);
      expect(r.version, r.id).toMatch(/^\d+\.\d+\.\d+$/);
      expect(r.category, r.id).toBe("compliance-policy");
      expect(r.applies_to_playbooks, r.id).toBeDefined();
    }
  });

  it("scopes every rule to one or more compliance-policy playbooks", () => {
    const allowed = new Set<string>(POL_PLAYBOOK_IDS);
    for (const r of COMPLIANCE_POLICY_RULES) {
      for (const pb of r.applies_to_playbooks ?? []) {
        expect(allowed.has(pb), `${r.id} → ${pb}`).toBe(true);
      }
    }
  });

  it("does not fire under a non-compliance-policy playbook", async () => {
    const ctx = buildContext(["Some other doc", "No policy content."]);
    const run = await runEngine({ rules: COMPLIANCE_POLICY_RULES, ctx, source_file: SRC });
    expect(run.findings.length).toBe(0);
    expect(run.execution_log.every((e) => !e.fired)).toBe(true);
  });
});

const COMPLIANT_CODE: [string, ...string[]][] = [
  [
    "Code of Conduct",
    "This Code of Conduct applies to all directors, officers, and employees. Senior financial officers shall maintain honest and ethical conduct, ensure full, fair, accurate disclosures in SEC filings, and ensure compliance with laws, rules, and regulations. Waivers may only be granted by the audit committee and will be disclosed within 4 business days on Form 8-K. Reporting Violations: hotline operated by independent third party, anonymous reporting available; non-retaliation enforced. Compliance with all applicable laws and regulations is mandatory.",
  ],
];

describe("v4 Compliance-policy — compliant code-of-conduct fixture", () => {
  it("emits no critical findings against the compliant code fixture", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_CODE), CODE_PB);
    const run = await runEngine({ rules: COMPLIANCE_POLICY_RULES, ctx, source_file: SRC });
    const criticals = run.findings.filter((f) => f.severity === "critical");
    expect(criticals.map((f) => f.rule_id)).toEqual([]);
  });

  it("is deterministic across runs", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_CODE), CODE_PB);
    const a = await runEngine({ rules: COMPLIANCE_POLICY_RULES, ctx, source_file: SRC });
    const b = await runEngine({ rules: COMPLIANCE_POLICY_RULES, ctx, source_file: SRC });
    expect(a.result_hash).toEqual(b.result_hash);
  });
});

describe("v4 Compliance-policy — failure cases", () => {
  it("POL-006 fires when anti-bribery policy omits FCPA prohibition", async () => {
    const ctx = withPb(
      buildContext([
        "Policy",
        "All third-party intermediaries undergo due diligence screening. Books and records must be accurate; internal accounting controls apply. No facilitating payments. UK statute compliance required. Gifts and hospitality subject to pre-approval thresholds.",
      ]),
      FCPA_PB,
    );
    const run = await runEngine({ rules: COMPLIANCE_POLICY_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "POL-006")).toBe(true);
  });

  it("POL-013 fires when AML policy omits OFAC screening", async () => {
    const ctx = withPb(
      buildContext([
        "AML Policy",
        "Anti-money-laundering program includes designated compliance officer, training, independent testing, and customer due diligence. SARs filed within 30 days via FinCEN. CIP includes beneficial-ownership identification at 25% threshold. CTRs filed for cash over $10,000. Records retained 5 years.",
      ]),
      AML_PB,
    );
    const run = await runEngine({ rules: COMPLIANCE_POLICY_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "POL-013")).toBe(true);
  });

  it("POL-025 fires when whistleblower policy omits Rule 21F-17 carve-out", async () => {
    const ctx = withPb(
      buildContext([
        "Whistleblower Policy",
        "Reporting channels: hotline, audit committee, DOL and CFTC. Non-retaliation per SOX § 806 and Dodd-Frank § 922. Confidential and anonymous reporting via third-party hotline. Investigation: timeline, independent investigator, corrective action where warranted.",
      ]),
      WB_PB,
    );
    const run = await runEngine({ rules: COMPLIANCE_POLICY_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "POL-025")).toBe(true);
  });

  it("POL-029 fires when retention policy omits legal-hold override", async () => {
    const ctx = withPb(
      buildContext([
        "Document Retention Policy",
        "Retention schedule by category: tax records 7 years; HR records 7 years; contracts 6 years. ESI including email, IM, cloud, and mobile retained per schedule. SEC Rule 17a-4 and ERISA § 107 apply where relevant. Secure destruction via NAID-AAA shred + certificate of destruction.",
      ]),
      RET_PB,
    );
    const run = await runEngine({ rules: COMPLIANCE_POLICY_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "POL-029")).toBe(true);
  });

  it("POL-038 fires when AI AUP omits prohibited inputs", async () => {
    const ctx = withPb(
      buildContext([
        "AI Acceptable Use Policy",
        "Approved AI tools listed in Schedule A. Procurement gate for new tools includes security review. Human review required for hiring, lending, legal, medical outputs. Hallucinations require verification before reliance. Attribution and IP considerations apply. Annual training and incident reporting via hotline.",
      ]),
      AI_PB,
    );
    const run = await runEngine({ rules: COMPLIANCE_POLICY_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "POL-038")).toBe(true);
  });

  it("POL-042 fires on overbroad social-media wage-discussion ban", async () => {
    const ctx = withPb(
      buildContext([
        "Social Media Policy",
        "Employees may not discuss wages or working conditions on social media. Endorsements require #ad disclosure per FTC. Reg FD prohibits selective material disclosures.",
      ]),
      SM_PB,
    );
    const run = await runEngine({ rules: COMPLIANCE_POLICY_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "POL-042")).toBe(true);
  });

  it("POL-046 fires when lobbying policy omits LDA registration / reporting", async () => {
    const ctx = withPb(
      buildContext([
        "Lobbying Policy",
        "Pre-approval required for lobbying activities and contacts with covered officials. Corporate political contributions prohibited under FECA. State / local lobbying compliance per matrix. Gifts to government officials strictly limited per 5 CFR 2635 and state ethics codes.",
      ]),
      LOB_PB,
    );
    const run = await runEngine({ rules: COMPLIANCE_POLICY_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "POL-046")).toBe(true);
  });

  it("POL-033 fires when COI policy omits definition", async () => {
    const ctx = withPb(
      buildContext([
        "Disclosure Policy",
        "Annual disclosure and ongoing duty to disclose new matters. Affected member recuses; disinterested directors approve transactions. Sanctions for violations include board removal and discipline up to termination.",
      ]),
      COI_PB,
    );
    const run = await runEngine({ rules: COMPLIANCE_POLICY_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "POL-033")).toBe(true);
  });

  it("POL-019 fires when insider trading policy omits blackout / pre-clearance", async () => {
    const ctx = withPb(
      buildContext([
        "Trading Policy",
        "Material non-public information must not be the basis for any trade. Tipping prohibited including to family and friends. Short sales, hedging, and pledging by employees prohibited. Rule 10b5-1 plans permitted with cooling-off and good faith certification.",
      ]),
      INSIDER_PB,
    );
    const run = await runEngine({ rules: COMPLIANCE_POLICY_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "POL-019")).toBe(true);
  });
});
