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
const PIP_PB: Playbook = { id: "pip", version: "1.0.0" };

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

  it("EMP-035 fires when a California PIIA lacks the § 2870 carve-out", async () => {
    const ctx = withPb(
      buildContext([
        "Proprietary Information and Inventions Agreement",
        "This Agreement is governed by California law. Employee assigns all inventions to Employer. Confidentiality applies. DTSA notice under 18 U.S.C. § 1833 attached. Return of materials on termination.",
      ]),
      PIIA_PB,
    );
    const run = await runEngine({ rules: EMPLOYMENT_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "EMP-035")).toBe(true);
  });

  it("EMP-035 does not fire on a non-California PIIA (§ 2870 is a California statute) (v1.1.0)", async () => {
    const ctx = withPb(
      buildContext([
        "Proprietary Information and Inventions Agreement",
        "This Agreement is governed by Delaware law. Employee assigns all inventions to Employer.",
      ]),
      PIIA_PB,
    );
    const run = await runEngine({ rules: EMPLOYMENT_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "EMP-035")).toBe(false);
  });

  it("EMP-023 fires on a California separation missing the § 1542 waiver, silent elsewhere (v1.1.0)", async () => {
    const caCtx = withPb(
      buildContext([
        "Separation Agreement",
        "This Agreement is governed by California law. Employee, a California resident, releases all claims against Employer.",
      ]),
      SEPARATION_PB,
    );
    const nyCtx = withPb(
      buildContext([
        "Separation Agreement",
        "This Agreement is governed by New York law. Employee releases all claims against Employer.",
      ]),
      SEPARATION_PB,
    );
    const caRun = await runEngine({ rules: EMPLOYMENT_RULES, ctx: caCtx, source_file: SRC });
    const nyRun = await runEngine({ rules: EMPLOYMENT_RULES, ctx: nyCtx, source_file: SRC });
    expect(caRun.findings.some((f) => f.rule_id === "EMP-023")).toBe(true);
    expect(nyRun.findings.some((f) => f.rule_id === "EMP-023")).toBe(false);
  });

  it("EMP-015 / EMP-016 read the 'twenty-one (21) days' / 'seven (7) days' OWBPA form (v1.1.0)", async () => {
    const ctx = withPb(
      buildContext([
        "ADEA Waiver",
        "The Employee has been given twenty-one (21) days to consider this Agreement and may revoke it within seven (7) days after signing.",
      ]),
      SEPARATION_PB,
    );
    const run = await runEngine({ rules: EMPLOYMENT_RULES, ctx, source_file: SRC });
    const ids = new Set(run.findings.map((f) => f.rule_id));
    expect(ids.has("EMP-015")).toBe(false);
    expect(ids.has("EMP-016")).toBe(false);
    // A release with neither window still fires both.
    const bare = withPb(
      buildContext(["Release", "The Employee releases all claims against the Company."]),
      SEPARATION_PB,
    );
    const bareIds = new Set(
      (await runEngine({ rules: EMPLOYMENT_RULES, ctx: bare, source_file: SRC })).findings.map(
        (f) => f.rule_id,
      ),
    );
    expect(bareIds.has("EMP-015")).toBe(true);
    expect(bareIds.has("EMP-016")).toBe(true);
  });

  it("EMP-041 reads a 'ninety (90) days' PIP duration with a biweekly check-in (v1.1.0)", async () => {
    const ctx = withPb(
      buildContext([
        "Duration and Review Schedule",
        "This PIP will remain in effect for a period of ninety (90) days from the date above. The Employee and Manager will meet for a check-in every two weeks to review progress.",
      ]),
      PIP_PB,
    );
    const run = await runEngine({ rules: EMPLOYMENT_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "EMP-041")).toBe(false);
    // A PIP with no duration or review cadence still fires.
    const bare = withPb(
      buildContext(["Plan", "The Employee must improve performance in the identified areas."]),
      PIP_PB,
    );
    const bareRun = await runEngine({ rules: EMPLOYMENT_RULES, ctx: bare, source_file: SRC });
    expect(bareRun.findings.some((f) => f.rule_id === "EMP-041")).toBe(true);
  });

  it("EMP-014 reads an 'Accepted:' block and 'by signing below' instruction (v1.1.0)", async () => {
    const OFFER_PB: Playbook = { id: "offer-letter", version: "1.0.0" };
    const ctx = withPb(
      buildContext([
        "Acceptance",
        "Please indicate your acceptance of this offer by signing below and returning this letter. Accepted: Taylor Kim. Date: __________",
      ]),
      OFFER_PB,
    );
    const run = await runEngine({ rules: EMPLOYMENT_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "EMP-014")).toBe(false);
    // An offer letter with no acceptance mechanism still fires; a "signing
    // bonus" mention is not an acceptance line.
    const bare = withPb(
      buildContext(["Offer", "You will receive a signing bonus of $10,000. The role is full-time."]),
      OFFER_PB,
    );
    const bareRun = await runEngine({ rules: EMPLOYMENT_RULES, ctx: bare, source_file: SRC });
    expect(bareRun.findings.some((f) => f.rule_id === "EMP-014")).toBe(true);
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

describe("EMP-025 / EMP-029 — restrictive-covenant formulas and nexus (v1.1.0)", () => {
  const RC_PB_LOCAL: Playbook = { id: "employment-restrictive-covenant", version: "1.0.0" };

  it("reads 'Non-Competition … twelve (12) months' and skips garden leave without an MA/WA nexus", async () => {
    const ctx = withPb(
      buildContext([
        "Covenants",
        "1. Non-Competition. During employment and for twelve (12) months after the termination of employment, the Employee shall not perform competing services in the Restricted Territory.",
        "9. Governing Law. This Agreement is governed by the laws of the State of Vermont.",
      ]),
      RC_PB_LOCAL,
    );
    const run = await runEngine({ rules: EMPLOYMENT_RULES, ctx, source_file: SRC });
    const ids = run.findings.map((f) => f.rule_id);
    expect(ids).not.toContain("EMP-025");
    expect(ids).not.toContain("EMP-029");
  });

  it("EMP-029 still fires on a Massachusetts non-compete without garden leave", async () => {
    const ctx = withPb(
      buildContext([
        "Covenants",
        "The Employee shall not compete for twelve (12) months after termination. This Agreement is governed by the laws of the Commonwealth of Massachusetts.",
      ]),
      RC_PB_LOCAL,
    );
    const run = await runEngine({ rules: EMPLOYMENT_RULES, ctx, source_file: SRC });
    expect(run.findings.map((f) => f.rule_id)).toContain("EMP-029");
  });

  it("EMP-025 still fires when no duration is stated", async () => {
    const ctx = withPb(
      buildContext([
        "Covenants",
        "The Employee shall not compete with the Company after termination.",
      ]),
      RC_PB_LOCAL,
    );
    const run = await runEngine({ rules: EMPLOYMENT_RULES, ctx, source_file: SRC });
    expect(run.findings.map((f) => f.rule_id)).toContain("EMP-025");
  });
});

describe("EMP-020/021 — McLaren Macomb overbreadth and its carve-out (v1.1.0)", () => {
  const run1 = async (body: string) => {
    const ctx = withPb(buildContext(["Separation", body]), SEPARATION_PB);
    const run = await runEngine({ rules: EMPLOYMENT_RULES, ctx, source_file: SRC });
    return new Set(run.findings.map((f) => f.rule_id));
  };

  it("EMP-020 fires on 'shall not make any disparaging statement' and confidential-terms overbreadth", async () => {
    expect(
      (
        await run1(
          "Employee shall not make any disparaging statement about the Company in any forum.",
        )
      ).has("EMP-020"),
    ).toBe(true);
    expect(
      (
        await run1(
          "Employee shall keep the terms and existence of this Agreement strictly confidential.",
        )
      ).has("EMP-020"),
    ).toBe(true);
  });

  it("EMP-021 fires when a government-agency mention is a PROHIBITION, not a carve-out", async () => {
    expect(
      (
        await run1(
          "Employee shall not disclose the terms of this Agreement to any government agency.",
        )
      ).has("EMP-021"),
    ).toBe(true);
  });

  it("EMP-021 is silent when the protected-rights carve-out genuinely preserves the right", async () => {
    expect(
      (
        await run1(
          "Nothing in this Agreement prevents Employee from filing a charge with or communicating with any government agency, including the EEOC.",
        )
      ).has("EMP-021"),
    ).toBe(false);
  });
});
