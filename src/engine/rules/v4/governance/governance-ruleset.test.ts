import { describe, expect, it } from "vitest";

import { GOVERNANCE_RULES } from "./rules.js";
import { GOV_PLAYBOOK_IDS } from "./_helpers.js";
import { buildContext } from "../../../_test-fixtures.js";
import { runEngine } from "../../../runner.js";
import type { Playbook, RuleContext } from "../../../finding.js";

const BYLAWS_PB: Playbook = { id: "bylaws-corporation", version: "1.0.0" };
const OP_AGREEMENT_PB: Playbook = { id: "operating-agreement-llc", version: "1.0.0" };
const NONPROFIT_PB: Playbook = { id: "nonprofit-bylaws", version: "1.0.0" };

const SRC = { name: "test.docx", sha256: "0".repeat(64), size_bytes: 100 };

function withPb(ctx: RuleContext, pb: Playbook): RuleContext {
  return { ...ctx, playbook: pb };
}

describe("v4 Governance ruleset — registry contract", () => {
  it("exports exactly 80 rules with stable GOV-NNN ids", () => {
    expect(GOVERNANCE_RULES.length).toBe(80);
    const ids = GOVERNANCE_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(80);
    for (const r of GOVERNANCE_RULES) {
      expect(r.id, r.id).toMatch(/^GOV-\d{3}$/);
      expect(r.version, r.id).toMatch(/^\d+\.\d+\.\d+$/);
      expect(r.category, r.id).toBe("governance");
      expect(r.applies_to_playbooks, r.id).toBeDefined();
    }
  });

  it("scopes every rule to one or more governance playbooks", () => {
    const allowed = new Set<string>(GOV_PLAYBOOK_IDS);
    for (const r of GOVERNANCE_RULES) {
      for (const pb of r.applies_to_playbooks ?? []) {
        expect(allowed.has(pb), `${r.id} → ${pb}`).toBe(true);
      }
    }
  });

  it("does not fire any rule when no governance playbook is active", async () => {
    const ctx = buildContext(["Some other doc", "This document has no governance content."]);
    const run = await runEngine({
      rules: GOVERNANCE_RULES,
      ctx,
      source_file: SRC,
    });
    expect(run.findings.length).toBe(0);
    expect(run.execution_log.every((e) => !e.fired)).toBe(true);
  });
});

/**
 * A near-compliant bylaws fixture covering all GOV-001..GOV-012 pillars.
 */
const COMPLIANT_BYLAWS_SECTIONS: [string, ...string[]][] = [
  [
    "Bylaws of Acme Corp.",
    "These Bylaws of Acme Corp., a Delaware corporation, govern the affairs of the Corporation.",
  ],
  [
    "Article I — Stockholders",
    "Annual Meeting of Stockholders. The annual meeting of the stockholders shall be held each year at the time and place determined by the Board of Directors. A special meeting of the stockholders may be called by the Board or by stockholders holding at least 25% of the voting power. Notice of the annual or special meeting of the stockholders shall be given in writing not less than 10 nor more than 60 days before the meeting. A quorum shall consist of the holders of a majority of the voting power, present in person or by proxy.",
  ],
  [
    "Article II — Board of Directors",
    "The Board of Directors shall consist of not fewer than three directors. Directors shall be elected at the annual meeting of stockholders and shall serve one-year terms. Removal of any director and the filling of vacancies on the Board shall be governed by DGCL § 141(k) and DGCL § 223 respectively.",
  ],
  [
    "Article III — Officers",
    "The Board shall elect officers of the Corporation, including a Chief Executive Officer, President, Treasurer, and Secretary. The Chief Executive Officer shall have general charge of the business of the Corporation.",
  ],
  [
    "Article IV — Indemnification",
    "Each director and officer of the Corporation shall be indemnified to the fullest extent permitted by DGCL § 145, including advancement of expenses.",
  ],
  [
    "Article V — Stock",
    "Shares of the Corporation shall be uncertificated, provided that the Board may by resolution authorize the issuance of certificated shares, in which case the form of certificate shall comply with DGCL § 158.",
  ],
  [
    "Article VI — Books and Records",
    "Stockholders shall have the right to inspect the books and records of the Corporation in accordance with DGCL § 220 subject to compliance with the proper-purpose and procedural requirements thereof.",
  ],
  [
    "Article VII — Amendment of Bylaws",
    "These Bylaws may be amended or repealed by the stockholders or, to the extent permitted by the Certificate of Incorporation, by the Board of Directors.",
  ],
];

describe("v4 Governance — bylaws compliant fixture", () => {
  it("emits no critical findings against the compliant bylaws fixture", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_BYLAWS_SECTIONS), BYLAWS_PB);
    const run = await runEngine({
      rules: GOVERNANCE_RULES,
      ctx,
      source_file: SRC,
    });
    const criticals = run.findings.filter((f) => f.severity === "critical");
    expect(criticals.map((f) => f.rule_id)).toEqual([]);
  });

  it("is deterministic across runs", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_BYLAWS_SECTIONS), BYLAWS_PB);
    const a = await runEngine({ rules: GOVERNANCE_RULES, ctx, source_file: SRC });
    const b = await runEngine({ rules: GOVERNANCE_RULES, ctx, source_file: SRC });
    expect(a.result_hash).toEqual(b.result_hash);
  });
});

describe("v4 Governance — failure cases", () => {
  it("GOV-001 fires when the bylaws are silent on amendment authority", async () => {
    const ctx = withPb(
      buildContext([
        "Bylaws",
        "Annual meeting of stockholders shall be held annually. Notice of meeting given 30 days in advance. Quorum is a majority. Board of Directors elected annually. Officers elected by the Board. Indemnification provided to fullest extent. Books and records may be inspected.",
      ]),
      BYLAWS_PB,
    );
    const run = await runEngine({ rules: GOVERNANCE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "GOV-001")).toBe(true);
  });

  it("GOV-022 fires when an operating agreement waives the implied covenant", async () => {
    const ctx = withPb(
      buildContext([
        "Operating Agreement",
        "The Members hereby waive the implied covenant of good faith and fair dealing to the fullest extent permitted by law.",
      ]),
      OP_AGREEMENT_PB,
    );
    const run = await runEngine({ rules: GOVERNANCE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "GOV-022")).toBe(true);
  });

  it("GOV-080 fires when nonprofit bylaws miss the three organizational pillars", async () => {
    const ctx = withPb(
      buildContext(["Nonprofit Bylaws", "The corporation is organized to do good things."]),
      NONPROFIT_PB,
    );
    const run = await runEngine({ rules: GOVERNANCE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "GOV-080")).toBe(true);
  });

  it("GOV-013 reads the descriptive 'managed by its Members' structure (v1.1.0)", async () => {
    const ctx = withPb(
      buildContext([
        "Management",
        "The Company is managed by its Members. Each Member has voting power in proportion to its percentage interest.",
      ]),
      OP_AGREEMENT_PB,
    );
    const run = await runEngine({ rules: GOVERNANCE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "GOV-013")).toBe(false);
  });

  it("GOV-015 reads a verb-form 'shall distribute available cash' clause (v1.1.0)", async () => {
    const ctx = withPb(
      buildContext([
        "Distributions",
        "The Company shall distribute available cash to the Members in proportion to their percentage interests.",
      ]),
      OP_AGREEMENT_PB,
    );
    const run = await runEngine({ rules: GOVERNANCE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "GOV-015")).toBe(false);
  });
});

describe("GOV-028/031/032 — the charter formulas drafting actually uses (v1.1.0)", () => {
  const CHARTER_PB_LOCAL: Playbook = { id: "charter-incorporation", version: "1.0.0" };
  const CLEAN_CHARTER: [string, ...string[]][] = [
    [
      "Certificate of Incorporation",
      "FOURTH: The Board of Directors is authorized, by resolution and without stockholder approval, to provide for the issuance of the Preferred Stock in one or more series, and to fix the designations, powers, preferences, and rights of the shares of each such series.",
      "SIXTH: To the fullest extent permitted by the General Corporation Law of the State of Delaware, no director or officer of the Corporation shall be personally liable to the Corporation or its stockholders for monetary damages for breach of fiduciary duty.",
      "NINTH: The Corporation reserves the right to amend, alter, change, or repeal any provision contained in this Certificate of Incorporation in the manner now or hereafter prescribed by statute.",
    ],
  ];

  it("none of the three absence findings fire on the standard formulas", async () => {
    const ctx = withPb(buildContext(...CLEAN_CHARTER), CHARTER_PB_LOCAL);
    const run = await runEngine({ rules: GOVERNANCE_RULES, ctx, source_file: SRC });
    const ids = run.findings.map((f) => f.rule_id);
    expect(ids).not.toContain("GOV-028");
    expect(ids).not.toContain("GOV-031");
    expect(ids).not.toContain("GOV-032");
  });

  it("all three still fire on a charter that omits the clauses", async () => {
    const ctx = withPb(
      buildContext([
        "Certificate of Incorporation",
        "FIRST: The name of the corporation is Bare Charter Corp.",
        "SECOND: The registered office is in Wilmington, Delaware.",
      ]),
      CHARTER_PB_LOCAL,
    );
    const run = await runEngine({ rules: GOVERNANCE_RULES, ctx, source_file: SRC });
    const ids = run.findings.map((f) => f.rule_id);
    expect(ids).toContain("GOV-028");
    expect(ids).toContain("GOV-031");
    expect(ids).toContain("GOV-032");
  });
});

describe("GOV-058 — 'report regularly to the Board' is the reporting clause (v1.1.0)", () => {
  const COMMITTEE_PB_LOCAL: Playbook = { id: "committee-charter", version: "1.0.0" };

  it("does not fire when the clause carries an adverb", async () => {
    const ctx = withPb(
      buildContext([
        "Reports",
        "The Committee shall report regularly to the Board on its activities, findings, and recommendations.",
      ]),
      COMMITTEE_PB_LOCAL,
    );
    const run = await runEngine({ rules: GOVERNANCE_RULES, ctx, source_file: SRC });
    expect(run.findings.map((f) => f.rule_id)).not.toContain("GOV-058");
  });

  it("still fires when no reporting clause exists", async () => {
    const ctx = withPb(
      buildContext(["Purpose", "The Committee oversees the audit function."]),
      COMMITTEE_PB_LOCAL,
    );
    const run = await runEngine({ rules: GOVERNANCE_RULES, ctx, source_file: SRC });
    expect(run.findings.map((f) => f.rule_id)).toContain("GOV-058");
  });
});

describe("GOV-054 — a denied whistleblower procedure is absence, not presence (v1.1.0)", () => {
  const COMMITTEE_PB2: Playbook = { id: "committee-charter", version: "1.0.0" };
  const run1 = async (body: string) => {
    const ctx = withPb(buildContext(["Charter", body]), COMMITTEE_PB2);
    const run = await runEngine({ rules: GOVERNANCE_RULES, ctx, source_file: SRC });
    return new Set(run.findings.map((f) => f.rule_id));
  };
  it("fires when the charter denies whistleblower procedures", async () => {
    expect((await run1("This charter includes no whistleblower procedures.")).has("GOV-054")).toBe(
      true,
    );
  });
  it("is silent when the charter establishes them", async () => {
    expect(
      (
        await run1(
          "The Committee shall establish whistleblower and complaint procedures for accounting concerns.",
        )
      ).has("GOV-054"),
    ).toBe(false);
  });
});
