import { describe, expect, it } from "vitest";

import { BAA_RULES } from "./rules.js";
import { buildContext } from "../../../_test-fixtures.js";
import { runEngine } from "../../../runner.js";
import type { Playbook, RuleContext } from "../../../finding.js";

const BAA_PLAYBOOK: Playbook = { id: "baa", version: "1.0.0" };
const SRC = { name: "test.docx", sha256: "0".repeat(64), size_bytes: 1 };

/** Withe BAA playbook so v3 BAA rules actually run. */
function withBaa(ctx: RuleContext): RuleContext {
  return { ...ctx, playbook: BAA_PLAYBOOK };
}

/**
 * A near-fully-compliant BAA fixture. Every §164.504(e) clause is
 * represented in plain language and the breach-notification clause uses
 * the HIPAA-canonical "no case later than 60 calendar days" phrasing
 * with the 'discovery' trigger and 'without unreasonable delay' inner
 * bound.
 */
const COMPLIANT_BAA_SECTIONS: [string, ...string[]][] = [
  [
    "Business Associate Agreement",
    "Effective Date: January 1, 2026. This Business Associate Agreement is entered into between Covered Entity and Business Associate.",
  ],
  [
    "1. Definitions",
    "Protected Health Information, PHI, and ePHI shall have the meaning given in 45 CFR § 160.103. Breach and Unsecured PHI shall have the meaning given in 45 CFR § 164.402. Security Incident shall mean the attempted or successful unauthorized access, use, disclosure, modification, or destruction of information or interference with system operations in an information system.",
  ],
  [
    "2. Permitted Uses and Disclosures",
    "Business Associate may only use or disclose Protected Health Information as permitted by this Agreement or as required by law. Business Associate shall not use or disclose PHI other than as permitted hereunder.",
  ],
  [
    "3. Appropriate Safeguards",
    "Business Associate shall implement appropriate administrative, physical, and technical safeguards in accordance with the Security Rule (45 CFR §§ 164.308, 164.310, 164.312) to prevent unauthorized use or disclosure of PHI. Business Associate shall comply with the Security Rule with respect to electronic PHI.",
  ],
  [
    "4. Reporting and Mitigation",
    "Business Associate shall report to Covered Entity any use or disclosure of PHI not provided for by this Agreement of which it becomes aware. Business Associate shall report to Covered Entity any security incident of which it becomes aware. Business Associate shall mitigate, to the extent practicable, any harmful effect of a use or disclosure of PHI in violation of this Agreement.",
  ],
  [
    "5. Subcontractors",
    "Business Associate shall ensure that any subcontractor that creates, receives, maintains, or transmits PHI on its behalf agrees in writing to the same restrictions and conditions that apply to Business Associate, including applicable Security Rule requirements. Business Associate shall maintain and make available to Covered Entity a current list of subprocessors that handle PHI.",
  ],
  [
    "6. Individual Rights",
    "Business Associate shall make PHI available as necessary to comply with 45 CFR 164.524 (access to PHI). Business Associate shall make amendment of PHI in accordance with 45 CFR 164.526. Business Associate shall provide an accounting of disclosures as required by 45 CFR 164.528. Minimum necessary use of PHI shall apply.",
  ],
  [
    "7. Books and Records",
    "Business Associate shall make its internal practices, books, and records relating to the use and disclosure of PHI available to the Secretary of HHS for purposes of determining Covered Entity's compliance. Covered Entity shall have reasonable audit rights to verify compliance.",
  ],
  [
    "8. Breach Notification",
    "Following discovery of a breach of unsecured PHI, Business Associate shall notify Covered Entity without unreasonable delay and in no case later than 60 calendar days after discovery of the breach.",
  ],
  [
    "9. Termination",
    "Either party may terminate this Agreement for material breach if the other party fails to cure within thirty (30) days, or if cure is not feasible. Upon termination, Business Associate shall return or destroy all PHI within 30 days of termination, including PHI held by subcontractors. The obligations of this Agreement shall survive termination with respect to PHI retained by Business Associate.",
  ],
  [
    "10. Training and Risk Assessment",
    "Business Associate maintains workforce training on HIPAA / PHI obligations and a sanctions policy for workforce members who violate HIPAA. Business Associate conducts periodic risk assessment under 45 CFR § 164.308(a)(1). Encryption of ePHI at rest and in transit is implemented in accordance with NIST 800-111 and NIST 800-52.",
  ],
  [
    "11. Miscellaneous",
    "Notice shall be given in writing to the addresses listed below. This Agreement shall be governed by the laws of the State of Delaware (subject to HIPAA preemption). Authorized representative signature: By: ____________ Name: Jane Doe Title: Chief Privacy Officer Date: 2026-01-01.",
  ],
];

describe("BAA ruleset — registry contract", () => {
  it("exports exactly 45 rules with stable BAA-NNN ids", () => {
    expect(BAA_RULES.length).toBe(45);
    const ids = BAA_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(45);
    for (const r of BAA_RULES) {
      expect(r.id).toMatch(/^BAA-\d{3}$/);
      expect(r.applies_to_playbooks).toContain("baa");
      expect(r.category).toBe("baa");
      expect(r.dkb_citations.length).toBeGreaterThan(0);
    }
  });

  it("does not run when the playbook is not BAA", async () => {
    const ctx = buildContext(["Agreement", "A totally unrelated document."]);
    const run = await runEngine({
      rules: BAA_RULES,
      ctx,
      executed_at: "2026-05-12T00:00:00Z",
      source_file: SRC,
    });
    expect(run.findings).toHaveLength(0);
    expect(run.execution_log.every((e) => e.fired === false)).toBe(true);
  });
});

describe("BAA ruleset — compliant fixture", () => {
  it("produces few findings against the canonical compliant BAA", async () => {
    const ctx = withBaa(buildContext(...COMPLIANT_BAA_SECTIONS));
    const run = await runEngine({
      rules: BAA_RULES,
      ctx,
      executed_at: "2026-05-12T00:00:00Z",
      source_file: SRC,
    });
    // The fixture is intentionally exhaustive — we expect at most a small
    // number of warnings (e.g., HIPAA-current-terminology, if the
    // detector misses an edge case). Critical findings must be zero.
    const criticals = run.findings.filter((f) => f.severity === "critical");
    expect(criticals).toHaveLength(0);
    // Spot-check: 40+ rules should not fire.
    expect(run.execution_log.filter((e) => e.fired).length).toBeLessThanOrEqual(5);
  });
});

describe("BAA ruleset — failure modes", () => {
  it("missing breach notification clause fires BAA-019", async () => {
    const ctx = withBaa(buildContext([
      "BAA",
      "This is a BAA referencing PHI and Covered Entity and Business Associate but with no breach notice.",
    ]));
    const run = await runEngine({ rules: BAA_RULES, ctx, executed_at: "2026-05-12T00:00:00Z", source_file: SRC });
    expect(run.findings.find((f) => f.rule_id === "BAA-019")).toBeTruthy();
  });

  it("breach notification of 90 days fires BAA-020", async () => {
    const ctx = withBaa(buildContext([
      "BAA",
      "Business Associate shall notify Covered Entity of any breach of unsecured PHI within 90 calendar days after discovery.",
    ]));
    const run = await runEngine({ rules: BAA_RULES, ctx, executed_at: "2026-05-12T00:00:00Z", source_file: SRC });
    expect(run.findings.find((f) => f.rule_id === "BAA-020")).toBeTruthy();
  });

  it("Security Incident narrowed to 'successful' fires BAA-023", async () => {
    const ctx = withBaa(buildContext([
      "BAA",
      "Security Incident means only the successful unauthorized access to ePHI by an unauthorized person.",
      "Business Associate shall notify Covered Entity of any breach of unsecured PHI within 60 calendar days after discovery without unreasonable delay.",
    ]));
    const run = await runEngine({ rules: BAA_RULES, ctx, executed_at: "2026-05-12T00:00:00Z", source_file: SRC });
    expect(run.findings.find((f) => f.rule_id === "BAA-023")).toBeTruthy();
  });

  it("CE indemnifies BA for HIPAA violations fires BAA-027", async () => {
    const ctx = withBaa(buildContext([
      "BAA",
      "Covered Entity shall indemnify Business Associate for any claims arising under HIPAA including breach of unsecured PHI.",
    ]));
    const run = await runEngine({ rules: BAA_RULES, ctx, executed_at: "2026-05-12T00:00:00Z", source_file: SRC });
    expect(run.findings.find((f) => f.rule_id === "BAA-027")).toBeTruthy();
  });

  it("'as soon as practicable' return language fires BAA-024", async () => {
    const ctx = withBaa(buildContext([
      "BAA",
      "Upon termination, Business Associate shall return or destroy all PHI as soon as practicable.",
    ]));
    const run = await runEngine({ rules: BAA_RULES, ctx, executed_at: "2026-05-12T00:00:00Z", source_file: SRC });
    expect(run.findings.find((f) => f.rule_id === "BAA-024")).toBeTruthy();
  });

  it("a document with no PHI reference fires BAA-041", async () => {
    const ctx = withBaa(buildContext([
      "Agreement",
      "This is a generic services agreement with no health-related terminology.",
    ]));
    const run = await runEngine({ rules: BAA_RULES, ctx, executed_at: "2026-05-12T00:00:00Z", source_file: SRC });
    expect(run.findings.find((f) => f.rule_id === "BAA-041")).toBeTruthy();
  });
});

describe("BAA ruleset — determinism", () => {
  it("two runs over the same input produce the same result_hash", async () => {
    const ctx = withBaa(buildContext(...COMPLIANT_BAA_SECTIONS));
    const a = await runEngine({ rules: BAA_RULES, ctx, executed_at: "2026-05-12T00:00:00Z", source_file: SRC });
    const b = await runEngine({ rules: BAA_RULES, ctx, executed_at: "2026-05-12T00:00:00Z", source_file: SRC });
    expect(a.result_hash).toBe(b.result_hash);
  });
});
