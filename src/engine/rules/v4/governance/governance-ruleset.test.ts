import { describe, expect, it } from "vitest";

import { GOVERNANCE_RULES } from "./rules.js";
import { GOV_PLAYBOOK_IDS } from "./_helpers.js";
import { buildContext } from "../../../_test-fixtures.js";
import { runEngine } from "../../../runner.js";
import type { Playbook, RuleContext } from "../../../finding.js";

const BYLAWS_PB: Playbook = { id: "bylaws-corporation", version: "1.0.0" };
const OP_AGREEMENT_PB: Playbook = { id: "operating-agreement-llc", version: "1.0.0" };
const NONPROFIT_PB: Playbook = { id: "nonprofit-bylaws", version: "1.0.0" };
const CHARTER_PB: Playbook = { id: "charter-incorporation", version: "1.0.0" };
const PARTNERSHIP_PB: Playbook = { id: "partnership-agreement", version: "1.0.0" };

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

  it("GOV-041 reads a 'firm-commitment underwritten public offering' termination (v1.1.0)", async () => {
    const SHA_PB: Playbook = { id: "stockholders-agreement", version: "1.0.0" };
    const ctx = withPb(
      buildContext([
        "Termination",
        "This Agreement terminates upon the closing of a firm-commitment underwritten public offering.",
      ]),
      SHA_PB,
    );
    const run = await runEngine({ rules: GOVERNANCE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "GOV-041")).toBe(false);
    const noIpo = withPb(
      buildContext([
        "Termination",
        "This Agreement terminates upon the written consent of the parties.",
      ]),
      SHA_PB,
    );
    expect(
      (await runEngine({ rules: GOVERNANCE_RULES, ctx: noIpo, source_file: SRC })).findings.some(
        (f) => f.rule_id === "GOV-041",
      ),
    ).toBe(true);
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
  it("GOV-053 reads the verb-form auditor authority ('sole authority to appoint, compensate, retain')", async () => {
    expect(
      (
        await run1(
          "The Committee has the sole authority to appoint, compensate, retain, and oversee the independent auditor.",
        )
      ).has("GOV-053"),
    ).toBe(false);
    expect((await run1("The Committee shall meet at least quarterly.")).has("GOV-053")).toBe(true);
  });
});

describe("Nonprofit COI & no-members in real wording (v1.1.0)", () => {
  const NP_PB: Playbook = { id: "nonprofit-bylaws", version: "1.0.0" };
  const run1 = async (body: string) => {
    const ctx = withPb(buildContext(["Nonprofit Bylaws", body]), NP_PB);
    const run = await runEngine({ rules: GOVERNANCE_RULES, ctx, source_file: SRC });
    return new Set(run.findings.map((f) => f.rule_id));
  };

  it("GOV-075 reads 'Conflicts of Interest' / 'conflict-of-interest policy'", async () => {
    expect(
      (
        await run1(
          "Conflicts of Interest. The Corporation shall follow a conflict-of-interest policy.",
        )
      ).has("GOV-075"),
    ).toBe(false);
    expect((await run1("The Board manages the affairs of the Corporation.")).has("GOV-075")).toBe(
      true,
    );
  });

  it("GOV-077 reads 'The Corporation has no members'", async () => {
    expect(
      (await run1("The Corporation has no members. The rights vest in the Board.")).has("GOV-077"),
    ).toBe(false);
    expect((await run1("The Board consists of five directors.")).has("GOV-077")).toBe(true);
  });
});

describe("GOV-045 — 'unanimous written consent' is the unanimity statement (v1.1.0)", () => {
  const WC_PB: Playbook = { id: "written-consent", version: "1.0.0" };
  const run1 = async (body: string) => {
    const ctx = withPb(buildContext(["Action by Written Consent", body]), WC_PB);
    const run = await runEngine({ rules: GOVERNANCE_RULES, ctx, source_file: SRC });
    return new Set(run.findings.map((f) => f.rule_id));
  };

  it("reads 'by unanimous written consent'", async () => {
    expect(
      (
        await run1(
          "The undersigned, being all of the members of the Board, hereby adopt these resolutions by unanimous written consent.",
        )
      ).has("GOV-045"),
    ).toBe(false);
    expect(
      (
        await run1(
          "The undersigned directors, acting by written consent of the Board of Directors, hereby adopt the following resolutions.",
        )
      ).has("GOV-045"),
    ).toBe(true);
  });

  it("GOV-045 (unanimity, board consents only) does not fire on a stockholder consent", async () => {
    const holders =
      "The undersigned stockholders, acting by written consent of the stockholders pursuant to Section 228, hereby adopt the following resolution.";
    expect((await run1(holders)).has("GOV-045")).toBe(false);
    // A board consent that omits the unanimity statement still fires.
    const board =
      "The undersigned directors, acting by written consent of the Board of Directors pursuant to Section 141(f), hereby adopt the following resolution.";
    expect((await run1(board)).has("GOV-045")).toBe(true);
  });

  it("GOV-046/048 (stockholder § 228 rules) do not fire on a board consent", async () => {
    const board =
      "The undersigned, being all of the members of the Board of Directors, acting by unanimous written consent pursuant to Section 141(f), adopt these resolutions. The Board finds it in the best interests of the Corporation and its stockholders.";
    expect((await run1(board)).has("GOV-046")).toBe(false);
    expect((await run1(board)).has("GOV-048")).toBe(false);
  });

  it("GOV-046/048 still fire on a stockholder consent missing the § 228 recital / notice", async () => {
    const holders =
      "The undersigned stockholders, acting by written consent of the stockholders pursuant to the General Corporation Law, hereby adopt the following resolution amending the Certificate of Incorporation.";
    expect((await run1(holders)).has("GOV-046")).toBe(true);
    expect((await run1(holders)).has("GOV-048")).toBe(true);
  });
});

describe("Certificate of incorporation — charter clause phrasings", () => {
  const CHARTER_PB: Playbook = { id: "charter-incorporation", version: "1.0.0" };
  const run1 = async (body: string) => {
    const ctx = withPb(buildContext(["Certificate of Incorporation", body]), CHARTER_PB);
    const run = await runEngine({ rules: GOVERNANCE_RULES, ctx, source_file: SRC });
    return new Set(run.findings.map((f) => f.rule_id));
  };

  it("GOV-028 reads exculpation with a qualifier ('director of the Corporation shall not be personally liable')", async () => {
    expect(
      (
        await run1(
          "To the fullest extent permitted by the DGCL, a director of the Corporation shall not be personally liable to the Corporation for monetary damages for breach of fiduciary duty.",
        )
      ).has("GOV-028"),
    ).toBe(false);
    expect((await run1("The Corporation shall have perpetual existence.")).has("GOV-028")).toBe(
      true,
    );
  });

  it("GOV-030 reads the 'consent in writing' opt-out as addressing § 228", async () => {
    expect(
      (
        await run1(
          "Any action by the stockholders of the Corporation may not be effected by any consent in writing by such stockholders.",
        )
      ).has("GOV-030"),
    ).toBe(false);
    expect((await run1("The Corporation shall have perpetual existence.")).has("GOV-030")).toBe(
      true,
    );
  });
});

describe("GOV-008 — D&O indemnification reads the 'indemnity' / 'Indemnitee' noun forms (v1.1.0)", () => {
  const run1 = async (body: string) => {
    const ctx = withPb(buildContext(["Bylaws", body]), BYLAWS_PB);
    const run = await runEngine({ rules: GOVERNANCE_RULES, ctx, source_file: SRC });
    return new Set(run.findings.map((f) => f.rule_id));
  };
  it("does not report the article missing when drafted around 'Indemnitee' / 'indemnity'", async () => {
    expect(
      (
        await run1(
          "Indemnity. Each Indemnitee shall be held harmless to the fullest extent permitted by law.",
        )
      ).has("GOV-008"),
    ).toBe(false);
  });
  it("still reports the article missing when no indemnification is provided", async () => {
    expect(
      (await run1("The board shall consist of five directors elected annually.")).has("GOV-008"),
    ).toBe(true);
  });

  // v1.2.0 — a bylaw that DISCLAIMS D&O indemnity matched the bare label and
  // was misread as providing it; a director who loses indemnification is
  // exactly what this rule must flag.
  it("reports the article missing when the bylaws DISCLAIM D&O indemnity", async () => {
    expect(
      (
        await run1(
          "The Corporation shall not indemnify its directors or officers under any circumstances.",
        )
      ).has("GOV-008"),
    ).toBe(true);
    expect(
      (
        await run1("No indemnity or advancement of expenses shall be provided to any director.")
      ).has("GOV-008"),
    ).toBe(true);
  });

  it("still does not fire on a standard 'shall indemnify … to the fullest extent' bylaw", async () => {
    expect(
      (
        await run1(
          "The Corporation shall indemnify its directors and officers to the fullest extent permitted by law.",
        )
      ).has("GOV-008"),
    ).toBe(false);
  });
});

describe("GOV-029 / GOV-068 / GOV-079 — indemnity presence flags a disclaimer (v1.1.0)", () => {
  const fired = async (pb: Playbook, body: string) => {
    const run = await runEngine({
      rules: GOVERNANCE_RULES,
      ctx: withPb(buildContext(["Doc", body]), pb),
      source_file: SRC,
    });
    return new Set(run.findings.map((f) => f.rule_id));
  };

  it("GOV-029 fires when a charter DISCLAIMS indemnification, stays silent when it grants it", async () => {
    expect(
      (
        await fired(
          CHARTER_PB,
          "The Corporation shall not indemnify any director for any liability.",
        )
      ).has("GOV-029"),
    ).toBe(true);
    expect(
      (
        await fired(
          CHARTER_PB,
          "The Corporation shall indemnify each director to the fullest extent permitted by law.",
        )
      ).has("GOV-029"),
    ).toBe(false);
  });

  it("GOV-068 fires when an LP agreement DISCLAIMS GP indemnity", async () => {
    expect(
      (await fired(PARTNERSHIP_PB, "The Partnership shall not indemnify the General Partner.")).has(
        "GOV-068",
      ),
    ).toBe(true);
    expect(
      (
        await fired(
          PARTNERSHIP_PB,
          "The Partnership shall indemnify the General Partner to the fullest extent permitted.",
        )
      ).has("GOV-068"),
    ).toBe(false);
  });

  it("GOV-079 fires when nonprofit bylaws DISCLAIM D&O indemnity", async () => {
    expect(
      (
        await fired(NONPROFIT_PB, "The Corporation shall not indemnify its directors or officers.")
      ).has("GOV-079"),
    ).toBe(true);
    expect(
      (
        await fired(
          NONPROFIT_PB,
          "The Corporation shall indemnify its directors and officers as permitted by law.",
        )
      ).has("GOV-079"),
    ).toBe(false);
  });
});

describe("GOV-033 — drag-along provision recognizes the 'bring-along' synonym (v1.1.0)", () => {
  const STOCKHOLDERS_PB: Playbook = { id: "stockholders-agreement", version: "1.0.0" };
  const run = async (body: string) => {
    const r = await runEngine({
      rules: GOVERNANCE_RULES,
      ctx: withPb(buildContext(["Stockholders Agreement", body]), STOCKHOLDERS_PB),
      source_file: SRC,
    });
    return new Set(r.findings.map((f) => f.rule_id));
  };

  it("does not report the provision missing when drafted as 'bring-along'", async () => {
    expect(
      (await run("The majority may exercise bring-along rights to compel a sale.")).has("GOV-033"),
    ).toBe(false);
  });

  it("still fires when no drag/bring-along provision is present", async () => {
    expect(
      (await run("The board shall consist of five directors elected annually.")).has("GOV-033"),
    ).toBe(true);
  });
});

describe("GOV-011 — exclusive-forum overreach detected regardless of clause order (v1.1.0)", () => {
  const BYLAWS: Playbook = { id: "bylaws-corporation", version: "1.0.0" };
  const fires = async (b: string) =>
    (
      await runEngine({
        rules: GOVERNANCE_RULES,
        ctx: withPb(buildContext(["Bylaws", b]), BYLAWS),
        source_file: SRC,
      })
    ).findings.some((f) => f.rule_id === "GOV-011");

  it.each([
    "The Court of Chancery of the State of Delaware shall be the exclusive forum for any claim arising under the Securities Exchange Act of 1934.",
    "The sole and exclusive forum for any action, including claims under the Exchange Act, shall be the Delaware Court of Chancery.",
  ])("fires on an Exchange-Act forum overreach: %s", async (b) => {
    expect(await fires(b)).toBe(true);
  });

  it.each([
    "The federal district courts shall be the exclusive forum for claims arising under the Securities Act of 1933; the Court of Chancery of the State of Delaware is the exclusive forum for internal corporate claims.",
    "The Court of Chancery is the exclusive forum for internal claims; this provision shall not apply to any claim under the Exchange Act.",
  ])("stays silent on the permissible 1933-Act split / carve-out: %s", async (b) => {
    expect(await fires(b)).toBe(false);
  });
});

describe("GOV-022 — implied-covenant waiver recognizes eliminate/disclaim & passive (v1.1.0)", () => {
  const OA: Playbook = { id: "operating-agreement-llc", version: "1.0.0" };
  const fires = async (b: string) =>
    (
      await runEngine({
        rules: GOVERNANCE_RULES,
        ctx: withPb(buildContext(["Operating Agreement", b]), OA),
        source_file: SRC,
      })
    ).findings.some((f) => f.rule_id === "GOV-022");

  it.each([
    "The Members hereby waive the implied covenant of good faith and fair dealing.",
    "The implied contractual covenant of good faith and fair dealing is hereby eliminated.",
    "The Members disclaim any implied covenant of good faith.",
  ])("fires on an implied-covenant waiver/elimination: %s", async (b) => {
    expect(await fires(b)).toBe(true);
  });

  it.each([
    "Nothing in this Agreement shall waive or eliminate the implied covenant of good faith and fair dealing.",
    "No provision of this Agreement eliminates the implied covenant of good faith.",
  ])("stays silent on a preservation clause: %s", async (b) => {
    expect(await fires(b)).toBe(false);
  });
});

describe("GOV-060 — audit-committee independence override recognizes 'need not be independent' (v1.1.0)", () => {
  const CC: Playbook = { id: "committee-charter", version: "1.0.0" };
  const fires = async (b: string) =>
    (
      await runEngine({
        rules: GOVERNANCE_RULES,
        ctx: withPb(buildContext(["Committee Charter", b]), CC),
        source_file: SRC,
      })
    ).findings.some((f) => f.rule_id === "GOV-060");

  it.each([
    "A non-independent director may serve on the audit committee.",
    "Members of the audit committee need not be independent.",
    "A director who is not independent may serve on the audit committee.",
  ])("fires on an independence override: %s", async (b) => {
    expect(await fires(b)).toBe(true);
  });

  it.each([
    "Each member of the audit committee must be independent.",
    "A non-independent director may serve during the phase-in period under the Rule 10A-3 exception.",
  ])("stays silent on a compliant / phase-in charter: %s", async (b) => {
    expect(await fires(b)).toBe(false);
  });
});

describe("GOV-070 — implied-covenant elimination recognizes passive form (v1.1.0)", () => {
  const PA: Playbook = { id: "partnership-agreement", version: "1.0.0" };
  const fires = async (b: string) =>
    (
      await runEngine({
        rules: GOVERNANCE_RULES,
        ctx: withPb(buildContext(["Partnership Agreement", b]), PA),
        source_file: SRC,
      })
    ).findings.some((f) => f.rule_id === "GOV-070");

  it.each([
    "The partners hereby eliminate the implied covenant of good faith and fair dealing.",
    "Any implied covenant of good faith and fair dealing is hereby disclaimed.",
  ])("fires on an implied-covenant elimination: %s", async (b) => {
    expect(await fires(b)).toBe(true);
  });

  it("stays silent on a preservation clause", async () => {
    expect(
      await fires(
        "Nothing herein shall eliminate the implied covenant of good faith and fair dealing.",
      ),
    ).toBe(false);
  });
});

describe("GOV-022 / GOV-070 — the compliant anti-waiver form (v1.2.0)", () => {
  const fires = async (id: string, pb: Playbook, b: string) =>
    (
      await runEngine({
        rules: GOVERNANCE_RULES,
        ctx: withPb(buildContext(["Agreement", b]), pb),
        source_file: SRC,
      })
    ).findings.some((f) => f.rule_id === id);

  // Both rules recommend exactly this drafting, and both then reported it as a
  // critical statutory violation: v1.1.0's guards required the negation to sit
  // directly on the verb, while the passive "may not be eliminated" satisfied
  // the bad pattern's bare `be`.
  it.each([
    "Notwithstanding anything herein, the implied covenant of good faith and fair dealing may not be eliminated or waived by the Members.",
    "The implied covenant of good faith and fair dealing cannot be waived.",
    "The implied covenant of good faith and fair dealing shall never be disclaimed.",
  ])("GOV-022 stays silent on: %s", async (b) => {
    expect(await fires("GOV-022", OP_AGREEMENT_PB, b)).toBe(false);
  });

  it("GOV-022 still fires on an actual waiver", async () => {
    expect(
      await fires(
        "GOV-022",
        OP_AGREEMENT_PB,
        "The implied covenant of good faith and fair dealing is hereby waived by the Members.",
      ),
    ).toBe(true);
  });

  it("GOV-070 stays silent on the partnership form of the same covenant", async () => {
    expect(
      await fires(
        "GOV-070",
        PARTNERSHIP_PB,
        "The implied covenant of good faith and fair dealing may not be eliminated or waived.",
      ),
    ).toBe(false);
  });

  it("GOV-070 still fires on an actual elimination", async () => {
    expect(
      await fires(
        "GOV-070",
        PARTNERSHIP_PB,
        "The implied covenant of good faith and fair dealing is hereby eliminated.",
      ),
    ).toBe(true);
  });
});
