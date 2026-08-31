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
      buildContext([
        "Offer",
        "You will receive a signing bonus of $10,000. The role is full-time.",
      ]),
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

describe("EMP-025 — non-compete duration reads the parenthesized 'non-compete … (2) years' (v1.2.0)", () => {
  const run1 = async (body: string) => {
    const ctx = withPb(buildContext(["Restrictive Covenants", body]), RC_PB);
    const run = await runEngine({ rules: EMPLOYMENT_RULES, ctx, source_file: SRC });
    return new Set(run.findings.map((f) => f.rule_id));
  };

  it("does not report the duration missing when stated as 'non-compete … two (2) years'", async () => {
    expect(
      (
        await run1(
          "The Employee's non-compete covenant shall last for two (2) years following termination, within the United States.",
        )
      ).has("EMP-025"),
    ).toBe(false);
  });

  it("still reports the duration missing when no duration is stated", async () => {
    expect(
      (await run1("The Employee agrees to a non-compete covenant within the United States.")).has(
        "EMP-025",
      ),
    ).toBe(true);
  });
});

describe("EMP-030 — blue-pencil/reformation reads the verb 'reform/modify … enforceable' (v1.1.0)", () => {
  const has = async (body: string) =>
    new Set(
      (
        await runEngine({
          rules: EMPLOYMENT_RULES,
          ctx: withPb(buildContext(["Restrictive Covenants", body]), RC_PB),
          source_file: SRC,
        })
      ).findings.map((f) => f.rule_id),
    );

  it("does not report the clause missing when the court is empowered to 'reform … enforceable'", async () => {
    for (const clause of [
      "A court may reform the covenant to the extent necessary to make it enforceable.",
      "The court may modify or reduce the scope of this covenant to render it enforceable.",
      "If overbroad, this covenant shall be judicially modified to the maximum enforceable extent.",
    ]) {
      expect((await has(clause)).has("EMP-030"), clause).toBe(false);
    }
  });

  it("still fires when a general amendment clause is the only 'modify' language", async () => {
    expect(
      (await has("The parties may modify this Agreement only by a signed writing.")).has("EMP-030"),
    ).toBe(true);
  });
});

describe("EMP-024 — non-compete detection recognizes 'agrees/covenants/will not' (v1.1.0)", () => {
  const fires = async (b: string) =>
    (
      await runEngine({
        rules: EMPLOYMENT_RULES,
        ctx: withPb(buildContext(["Restrictive Covenant", b]), RC_PB),
        source_file: SRC,
      })
    ).findings.some((f) => f.rule_id === "EMP-024");

  it.each([
    "Employee shall not compete with the Company for two years.",
    "Employee agrees not to compete with the Company during the restricted period.",
    "Employee will not, directly or indirectly, engage in any competing business.",
    "The Employee shall not, directly or indirectly, engage in any business that competes with the Company.",
    "Employee covenants not to compete with the Company within the territory.",
    // v1.2.0 — senior restrictive-covenant / executive agreements define the
    // party as "Executive" (or address the reader as "you").
    "Executive shall not, directly or indirectly, compete with the Company during the Restricted Period.",
    "Executive agrees not to engage in any competing business within the Territory.",
    "You shall not compete with the Company for twelve months following termination.",
  ])("fires on a worker non-compete: %s", async (b) => {
    expect(await fires(b)).toBe(true);
  });

  it.each([
    "Employee shall not be subject to any covenant not to compete.",
    "This agreement contains no non-compete covenant.",
    "Employee will not solicit any employee of a competing business to leave the Company.",
    "Employee shall not disclose confidential information to any competitor.",
  ])("stays silent on a disclaimed non-compete / non-solicit / NDA: %s", async (b) => {
    expect(await fires(b)).toBe(false);
  });
});

describe("EMP-049 — handbook § 7 detection recognizes passive & fronted forms (v1.1.0)", () => {
  const fires = async (b: string) =>
    (
      await runEngine({
        rules: EMPLOYMENT_RULES,
        ctx: withPb(buildContext(["Employee Handbook", b]), HANDBOOK_PB),
        source_file: SRC,
      })
    ).findings.some((f) => f.rule_id === "EMP-049");

  it.each([
    "Employees may not discuss their wages on company premises.",
    "Employees are prohibited from discussing their salary with coworkers.",
    "No employee shall disclose their compensation to others.",
    "Employees may not post about their working conditions on social media.",
  ])("fires on an overbroad wage-discussion rule: %s", async (b) => {
    expect(await fires(b)).toBe(true);
  });

  it.each([
    "Employees are not prohibited from discussing their wages or working conditions.",
    "This handbook does not restrict employees' rights to discuss compensation.",
    "Employees may freely discuss their wages and working conditions.",
  ])("stays silent on the compliant § 7 carve-out: %s", async (b) => {
    expect(await fires(b)).toBe(false);
  });
});

describe("EMP-020 — in-sentence § 7 carve-outs (v1.2.0)", () => {
  const PB: Playbook = { id: "separation-agreement", version: "1.0.0" };
  const fires = async (b: string) =>
    (
      await runEngine({
        rules: EMPLOYMENT_RULES,
        ctx: { ...buildContext(["Separation Agreement", b]), playbook: PB },
        source_file: SRC,
      })
    ).findings.some((f) => f.rule_id === "EMP-020");

  it("stays silent when the carve-out preserves § 7 rights in the same sentence", async () => {
    // Both guards expected the carve-out as its own "Nothing in this Section…"
    // sentence; the "except that …" form carries the same protection.
    expect(
      await fires(
        "Employee shall keep the terms of this Agreement confidential, except that Employee may discuss the existence and terms of this Agreement with the SEC, EEOC, NLRB, or other government agency, or as otherwise protected under Section 7 of the NLRA.",
      ),
    ).toBe(false);
  });

  it("still fires on an unqualified confidentiality clause", async () => {
    expect(
      await fires(
        "Employee shall keep the terms of this Agreement confidential and shall not disclose them to any person.",
      ),
    ).toBe(true);
  });

  it("still fires when the carve-out does not reach § 7 activity", async () => {
    // A subpoena-only carve-out is not a McLaren Macomb carve-out.
    expect(
      await fires(
        "Employee shall keep the terms of this Agreement confidential, except that Employee may respond to a subpoena.",
      ),
    ).toBe(true);
  });
});

/**
 * Express-denial guard. "Employee does not assign any inventions" contains the
 * assignment phrasing EMP-033 looks for, so the one document that definitively
 * leaves invention ownership with the employee scored clean, while a PIIA
 * merely silent on assignment fired.
 */
describe("EMP-033 — invention assignment expressly refused", () => {
  const run = async (text: string) => {
    const res = await runEngine({
      rules: EMPLOYMENT_RULES,
      ctx: withPb(buildContext(["Inventions", text]), PIIA_PB),
      source_file: SRC,
    });
    return res.findings.filter((f) => f.rule_id === "EMP-033").map((f) => f.title);
  };

  it.each([
    ["Employee does not assign any inventions to the Company."],
    ["Employee retains ownership of all inventions conceived during employment."],
  ])("reports %j as a denial", async (text) => {
    expect(await run(text)).toEqual(["Invention assignment expressly refused"]);
  });

  it("still reports the clause missing on silence", async () => {
    expect(await run("Employee agrees to protect Company confidential information.")).toEqual([
      "Invention-assignment clause missing",
    ]);
  });

  it("stays silent on the compliant assignment", async () => {
    expect(
      await run(
        "Employee hereby assigns all inventions conceived during employment to the Company.",
      ),
    ).toEqual([]);
  });
});

/**
 * California Labor Code § 2870 (and its analogues in WA, MN, IL, DE) REQUIRES
 * an invention-assignment agreement to state that it does not assign
 * inventions the employee developed entirely on their own time without company
 * equipment. That mandated sentence contains "does not assign any invention",
 * and the denial frame accused it until a carve-out lookahead was added —
 * the rule would have flagged the very language the statute compels.
 */
describe("EMP-033 — the § 2870 statutory carve-out is not accused", () => {
  const run = async (text: string) => {
    const res = await runEngine({
      rules: EMPLOYMENT_RULES,
      ctx: withPb(buildContext(["Inventions", text]), PIIA_PB),
      source_file: SRC,
    });
    return res.findings.filter((f) => f.rule_id === "EMP-033").map((f) => f.title);
  };

  it("stays silent on a compliant assignment carrying the § 2870 carve-out", async () => {
    expect(
      await run(
        "Employee hereby assigns all inventions to the Company. This assignment does not assign any invention that Employee developed entirely on Employee's own time without using Company equipment, as provided by California Labor Code Section 2870.",
      ),
    ).toEqual([]);
  });

  it("still reports a blanket refusal to assign", async () => {
    expect(await run("Employee does not assign any inventions to the Company.")).toEqual([
      "Invention assignment expressly refused",
    ]);
  });
});

describe("a performance improvement plan as one is actually written", () => {
  const run = async (id: string, ...paragraphs: string[]) => {
    const res = await runEngine({
      rules: EMPLOYMENT_RULES,
      ctx: withPb(buildContext(["Performance Improvement Plan", ...paragraphs]), PIP_PB),
      source_file: SRC,
    });
    return res.findings.filter((f) => f.rule_id === id).map((f) => f.title);
  };

  // "Expected Standards" is the third heading the measurable-targets section is
  // written under, beside "Performance Goals" and "Performance Expectations".
  it("EMP-040 reads targets under an 'Expected Standards' heading", async () => {
    expect(
      await run(
        "EMP-040",
        "EXPECTED STANDARDS. By the plan end date you are expected to submit forecasts within 15% accuracy for two consecutive months and to log contact activity for every active opportunity at least weekly.",
      ),
    ).toEqual([]);
  });

  // The acknowledgment window was forty characters and the sentence is longer
  // than that; and the receipt-not-agreement disclaimer's subject is as often
  // "it" as "my signature".
  it("EMP-044 reads the ordinary acknowledgment sentence", async () => {
    expect(
      await run(
        "EMP-044",
        "ACKNOWLEDGMENT. My signature below acknowledges that this plan was discussed with me and that I received a copy. It does not indicate that I agree with its contents.",
      ),
    ).toEqual([]);
  });

  it("EMP-044 still reports a plan with no acknowledgment at all", async () => {
    expect(
      await run(
        "EMP-044",
        "Progress will be reviewed at each review date. Failure to meet the expected standards may result in further action.",
      ),
    ).toEqual(["Acknowledgment / signature clause missing"]);
  });
});

describe("an individual separation agreement is not a group termination", () => {
  const run = async (id: string, ...paragraphs: string[]) => {
    const res = await runEngine({
      rules: EMPLOYMENT_RULES,
      ctx: withPb(
        buildContext(["Separation Agreement and General Release", ...paragraphs]),
        SEPARATION_PB,
      ),
      source_file: SRC,
    });
    return res.findings.filter((f) => f.rule_id === id).map((f) => f.title);
  };

  // § 626(f)(1)(H) applies ONLY to a group termination program, and demanding
  // the decisional-unit disclosure of an ordinary release accused every one of
  // omitting a disclosure the statute does not ask it for.
  it("EMP-019 is never asked of an individual release", async () => {
    expect(
      await run(
        "EMP-019",
        "The Employee has twenty-one (21) days from receipt to consider this Agreement and seven (7) days after signing to revoke it.",
      ),
    ).toEqual([]);
  });

  it("EMP-019 still fires on a group termination program that discloses nothing", async () => {
    expect(
      await run(
        "EMP-019",
        "This Agreement is offered as part of a reduction in force affecting the Company's Charlotte operations.",
      ),
    ).toEqual(["Group-termination disclosure clause missing"]);
  });

  // The consideration statement is as often made STRUCTURALLY as in the words
  // "over and above".
  it("EMP-022 reads the structural consideration statement", async () => {
    expect(
      await run(
        "EMP-022",
        "The Employee will be paid all wages earned through the Separation Date and all accrued, unused vacation, whether or not the Employee signs this Agreement.",
        "If the Employee signs this Agreement and does not revoke it, the Company will pay severance of twenty-six weeks of base salary.",
      ),
    ).toEqual([]);
  });
});

describe("a proprietary-information and inventions agreement", () => {
  const run = async (id: string, ...paragraphs: string[]) => {
    const res = await runEngine({
      rules: EMPLOYMENT_RULES,
      ctx: withPb(
        buildContext(["Employee Proprietary Information and Inventions Agreement", ...paragraphs]),
        PIIA_PB,
      ),
      source_file: SRC,
    });
    return res.findings.filter((f) => f.rule_id === id).map((f) => f.title);
  };

  // EMP-032 conjoined "proprietary information" — this family's own TITLE, so
  // it could never fail — with "non-disclosure", which the agreement never
  // uses. It states the obligation instead.
  it("EMP-032 reads the obligation rather than the label", async () => {
    expect(
      await run(
        "EMP-032",
        "I will hold Proprietary Information in confidence, use it only for the Company's benefit, and not disclose it to anyone outside the Company without authorization.",
      ),
    ).toEqual([]);
  });

  it("EMP-032 still fires on an agreement that imposes no confidence at all", async () => {
    expect(
      await run(
        "EMP-032",
        "I assign to the Company every invention I conceive during my employment.",
      ),
    ).toEqual(["Confidentiality / proprietary-information clause missing"]);
  });

  // "I appoint the Company as my ATTORNEY-IN-FACT for that limited purpose" is
  // how the power is granted.
  it("EMP-036 reads the attorney-in-fact appointment", async () => {
    expect(
      await run(
        "EMP-036",
        "If the Company cannot obtain my signature, I appoint the Company as my attorney-in-fact for that limited purpose.",
      ),
    ).toEqual([]);
  });
});

describe("EMP-025 / EMP-027 v1.3.0 / v1.1.0 — the covenant's own drafting", () => {
  const covenant = (...body: string[]) =>
    withPb(
      buildContext(["NON-COMPETITION AND NON-SOLICITATION AGREEMENT", ...body] as [
        string,
        ...string[],
      ]),
      RC_PB,
    );
  const ruleById = (id: string) => EMPLOYMENT_RULES.find((r) => r.id === id)!;

  it("reads a duration stated in the restriction sentence", () => {
    // Every duration pattern wanted the word "non-compete" within 80
    // characters, and a covenant agreement writes that word in its TITLE and
    // nowhere else — so a three-year worldwide non-compete was reported at
    // CRITICAL as having no duration at all.
    const ctx = covenant(
      "During the three (3) years following the termination of Employee's employment for any reason, Employee shall not, anywhere in the world, be employed by any business that competes with the Company.",
    );
    expect(ruleById("EMP-025").check(ctx)).toBeNull();
  });

  it("does not accept a WORLDWIDE restriction as a geographic scope", () => {
    // `worldwide` was a PRESENT pattern on a rule whose own explanation reads
    // "open-ended geographic scope is unenforceable", so the paradigm case of
    // the abuse satisfied the check. The bare `scope` and `state` alternatives
    // it stood beside are in "the scope of this Agreement" and in the State of
    // Delaware in every governing-law clause.
    const ctx = covenant(
      "Employee shall not, anywhere in the world, be employed by any business that competes with the Company. This Agreement is governed by the laws of the State of Delaware and the scope of this Agreement is as stated.",
    );
    expect(ruleById("EMP-027").check(ctx)).not.toBeNull();
  });

  it("still reads a bounded territory", () => {
    const ctx = covenant(
      'Employee shall not perform services within the Restricted Territory. "Restricted Territory" means each state in which the Company sold a product during the last twelve (12) months.',
    );
    expect(ruleById("EMP-027").check(ctx)).toBeNull();
  });
});
