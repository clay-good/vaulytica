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

  it("POL-042 does not fire on a compliant 'policy may not restrict … company' carve-out (v1.1.0)", async () => {
    // Inverse-FP regression: "may not" is a bad_pattern trigger, but a policy
    // that says it MAY NOT restrict discussion of the company is compliant.
    const ctx = withPb(
      buildContext([
        "Social Media Policy",
        "This social media policy may not restrict employees' discussion of the company, its wages, or its working conditions.",
      ]),
      SM_PB,
    );
    const run = await runEngine({ rules: COMPLIANCE_POLICY_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "POL-042")).toBe(false);
  });

  it("POL-042 still fires on a 'posts may not mention the company' restriction (v1.1.0)", async () => {
    const ctx = withPb(
      buildContext([
        "Social Media Policy",
        "Employees' social media posts may not mention the company, the employer, or any business matter.",
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

describe("POL-004 — a denied whistleblower protection is absence, not presence (v1.1.0)", () => {
  const run1 = async (body: string) => {
    const ctx = withPb(buildContext(["Reporting", body]), CODE_PB);
    const run = await runEngine({ rules: COMPLIANCE_POLICY_RULES, ctx, source_file: SRC });
    return new Set(run.findings.map((f) => f.rule_id));
  };

  it("fires when the Code denies reporting and whistleblower protection", async () => {
    expect(
      (
        await run1(
          "This Code prohibits reporting to any agency and provides no whistleblower protection.",
        )
      ).has("POL-004"),
    ).toBe(true);
  });

  it("is silent on a genuine hotline + non-retaliation mechanism", async () => {
    expect(
      (
        await run1(
          "The Company maintains a whistleblower hotline and prohibits retaliation against any employee who reports a concern.",
        )
      ).has("POL-004"),
    ).toBe(false);
  });
});

describe("POL-042 — social-media restriction recognizes passive & fronted-negation forms (v1.2.0)", () => {
  const fires = async (b: string) =>
    (
      await runEngine({
        rules: COMPLIANCE_POLICY_RULES,
        ctx: withPb(buildContext(["Social Media Policy", b]), SM_PB),
        source_file: SRC,
      })
    ).findings.some((f) => f.rule_id === "POL-042");

  it.each([
    "Employees may not discuss their wages or working conditions on social media.",
    "Employees are prohibited from posting about their salary online.",
    "No employee shall comment on compensation matters via social media.",
    "Employees are forbidden from discussing their pay on any online forum.",
  ])("fires on an overbroad wage-discussion restriction: %s", async (b) => {
    expect(await fires(b)).toBe(true);
  });

  it.each([
    "Employees are not prohibited from discussing their wages or working conditions.",
    "This policy does not restrict employees' rights to discuss compensation.",
    "Nothing in this policy prohibits protected concerted activity regarding wages.",
    "Employees may discuss their wages and working conditions freely.",
  ])("stays silent on the compliant § 7 carve-out: %s", async (b) => {
    expect(await fires(b)).toBe(false);
  });
});

describe("POL-042 — lawful confidentiality restrictions (v1.3.0)", () => {
  const fires = async (b: string) =>
    (
      await runEngine({
        rules: COMPLIANCE_POLICY_RULES,
        ctx: withPb(buildContext(["Social Media Policy", b]), SM_PB),
        source_file: SRC,
      })
    ).findings.some((f) => f.rule_id === "POL-042");

  // The fourth bad_pattern carried no wage / working-conditions term, so any
  // trade-secret rule read as an NLRA § 7 violation.
  it.each([
    "This social media policy prohibits employees from disclosing confidential company trade secrets online.",
    "On social media, employees may not disclose the company's proprietary product roadmap.",
  ])("stays silent on a confidentiality-scoped restriction: %s", async (b) => {
    expect(await fires(b)).toBe(false);
  });

  it("still fires on a blanket ban on discussing the employer", async () => {
    expect(await fires("Social media posts may not mention the company in any way.")).toBe(true);
  });

  it("still fires on the wage-discussion ban", async () => {
    expect(
      await fires("Employees may not discuss wages or working conditions on social media."),
    ).toBe(true);
  });
});

// ────────────────────────────────────────────────────────────────────
// Express denial (POL-012..POL-017, v1.1.0).
//
// A presence rule reads the document for the words the required clause
// would use, so a policy that AFFIRMATIVELY DISCLAIMS the clause ("the
// Company performs no OFAC screening") scored as compliant while a policy
// that merely omitted the topic was flagged. That is backwards: the
// disclaimer is the worse document, and — for OFAC, where liability is
// strict — the one the rule must not miss.
// ────────────────────────────────────────────────────────────────────

describe("v4 Compliance-policy — express denial of an AML/BSA clause", () => {
  const COMPLIANT_AML =
    "AML Program. The Company maintains an anti-money-laundering program with written policies and procedures, a designated AML compliance officer, ongoing employee training, independent testing, and customer due diligence (CDD). " +
    "OFAC Sanctions Screening. No customer shall be onboarded without OFAC screening against the SDN list and other sanctions lists; matches are blocked and reported. " +
    "Suspicious Activity Reports. SARs are filed with FinCEN within 30 days of detection and are treated as confidential; tipping-off is prohibited. " +
    "Customer Identification Program. The CIP collects name, date of birth, address, and ID number, and identifies each beneficial owner holding 25% or more under the Corporate Transparency Act. " +
    "Currency Transaction Reports. CTRs are filed for currency transactions above $10,000 with same-day aggregation; structuring is prohibited. " +
    "Recordkeeping. AML records are retained for 5 years.";

  const amlFindings = async (tail: string): Promise<string[]> => {
    const run = await runEngine({
      rules: COMPLIANCE_POLICY_RULES,
      ctx: withPb(buildContext(["AML Policy", `${COMPLIANT_AML} ${tail}`]), AML_PB),
      source_file: SRC,
    });
    return run.findings.map((f) => f.rule_id).filter((id) => /^POL-01[2-7]$/.test(id));
  };

  it.each([
    ["POL-012", "The Company does not maintain an anti-money-laundering program."],
    ["POL-013", "The Company performs no OFAC sanctions screening of customers."],
    ["POL-013", "The Company does not conduct OFAC screening against the SDN list."],
    ["POL-013", "OFAC screening is not required under this policy."],
    ["POL-014", "Suspicious activity reports are not filed by the Company."],
    ["POL-015", "The Company performs no customer identification program checks."],
    ["POL-016", "Currency transaction reports will not be filed."],
    ["POL-017", "AML records are not retained."],
  ])("%s fires on an express disclaimer: %s", async (id, tail) => {
    expect(await amlFindings(tail)).toContain(id);
  });

  // The denial frames must not read a COMPLIANT sentence that happens to
  // pair a negation with the topic as a disclaimer.
  it.each([
    ["nothing added", ""],
    ["conditional 'unless'", "No transaction is processed unless OFAC screening is performed."],
    ["conditional 'without'", "The Company shall not onboard any customer without OFAC screening."],
    ["scope carve-out", "This policy does not apply to OFAC screening performed by third parties."],
    ["non-limitation", "Nothing herein limits the SAR obligations of any employee."],
    ["non-waiver", "The Company does not waive any OFAC screening requirement."],
    ["prohibition", "Failure to file a suspicious activity report is not permitted."],
  ])("stays silent on a compliant AML policy — %s", async (_label, tail) => {
    expect(await amlFindings(tail)).toEqual([]);
  });

  it("reports the denying sentence rather than '(clause absent)'", async () => {
    const run = await runEngine({
      rules: COMPLIANCE_POLICY_RULES,
      ctx: withPb(
        buildContext([
          "AML Policy",
          `${COMPLIANT_AML} The Company performs no OFAC sanctions screening of customers.`,
        ]),
        AML_PB,
      ),
      source_file: SRC,
    });
    const f = run.findings.find((x) => x.rule_id === "POL-013");
    expect(f?.title).toBe("OFAC sanctions screening expressly disclaimed");
    expect(f?.excerpt.text).toContain("performs no OFAC sanctions screening");
  });

  it("still reports a plain omission as a missing clause", async () => {
    const run = await runEngine({
      rules: COMPLIANCE_POLICY_RULES,
      ctx: withPb(buildContext(["AML Policy", "The Company has an AML program."]), AML_PB),
      source_file: SRC,
    });
    const f = run.findings.find((x) => x.rule_id === "POL-013");
    expect(f?.title).toBe("OFAC sanctions screening clause missing");
    expect(f?.excerpt.text).toBe("(clause absent from the document)");
  });
});

describe("v4 Compliance-policy — express denial beyond the AML pack", () => {
  const CLEAN_WB =
    "Reporting Channels. The Company maintains a 24-hour hotline and an ombudsperson, and reports may also be made to the audit committee. Nothing in this policy restricts the right to report to the SEC, CFTC, or DOL. " +
    "Non-Retaliation. The Company prohibits retaliation and will not retaliate against any whistleblower; SOX § 806 and Dodd-Frank § 922 protections apply. " +
    "Nothing in this policy limits Rule 21F-17 rights. Anonymous reporting is available. Investigations are conducted promptly and confidentially.";

  const CLEAN_RET =
    "Retention Schedule. Tax, HR, contracts, corporate, and financial records are retained for the periods listed, in years. " +
    "Legal Hold. On issuance of a litigation hold, routine destruction is suspended and custodians cooperate with counsel to preserve records. " +
    "ESI including email, cloud, and mobile data is preserved. SEC, IRS, DOL, ERISA, and HIPAA minimums apply. Secure destruction by shredding follows NAID sanitization standards.";

  const CLEAN_AI =
    "Approved Tools. Only authorized tools on the allowlist may be used. Prohibited Inputs. PHI, protected health information, PII, trade secret, and privileged material may not be entered. " +
    "Human Review. Human-in-the-loop review is required for high-impact outputs; human oversight applies to all decisions affecting individuals. " +
    "Accuracy. Users must verify output and fact-check for hallucination. Training is provided to all trained users.";

  const findings = async (pb: Playbook, base: string, tail: string): Promise<string[]> =>
    (
      await runEngine({
        rules: COMPLIANCE_POLICY_RULES,
        ctx: withPb(buildContext(["Policy", `${base} ${tail}`]), pb),
        source_file: SRC,
      })
    ).findings.map((f) => f.rule_id);

  it.each([
    ["POL-023", WB_PB, CLEAN_WB, "The Company maintains no hotline or reporting channels."],
    ["POL-023", WB_PB, CLEAN_WB, "Anonymous reporting is not provided."],
    ["POL-029", RET_PB, CLEAN_RET, "The Company does not issue litigation holds."],
    ["POL-029", RET_PB, CLEAN_RET, "A legal hold is not required before destruction proceeds."],
    ["POL-039", AI_PB, CLEAN_AI, "Human review is not required for AI output."],
    ["POL-039", AI_PB, CLEAN_AI, "The Company provides no human oversight of model output."],
  ])("%s fires on an express disclaimer: %s", async (id, pb, base, tail) => {
    expect(await findings(pb, base, tail)).toContain(id);
  });

  it.each([
    ["whistleblower — nothing added", WB_PB, CLEAN_WB, ""],
    [
      "whistleblower — confidentiality, not absence",
      WB_PB,
      CLEAN_WB,
      "Hotline reports are not disclosed to the subject of the report.",
    ],
    [
      "whistleblower — non-limitation",
      WB_PB,
      CLEAN_WB,
      "Nothing herein limits the reporting channels available to employees.",
    ],
    ["retention — nothing added", RET_PB, CLEAN_RET, ""],
    [
      "retention — conditional 'without'",
      RET_PB,
      CLEAN_RET,
      "Records may not be destroyed without a legal hold release.",
    ],
    [
      "retention — hold duration",
      RET_PB,
      CLEAN_RET,
      "A legal hold does not expire until counsel releases it.",
    ],
    ["ai — nothing added", AI_PB, CLEAN_AI, ""],
    [
      "ai — conditional 'without'",
      AI_PB,
      CLEAN_AI,
      "AI output may not be published without human review.",
    ],
    [
      "ai — non-relief",
      AI_PB,
      CLEAN_AI,
      "Human review does not relieve the user of accuracy obligations.",
    ],
  ])("stays silent on a compliant policy — %s", async (_label, pb, base, tail) => {
    expect(await findings(pb, base, tail)).toEqual([]);
  });
});
