import { describe, expect, it } from "vitest";

import { M_AND_A_RULES } from "./rules.js";
import { MA_PLAYBOOK_IDS } from "./_helpers.js";
import { buildContext } from "../../../_test-fixtures.js";
import { runEngine } from "../../../runner.js";
import type { Playbook, RuleContext } from "../../../finding.js";

const LOI_PB: Playbook = { id: "loi-term-sheet", version: "1.0.0" };
const SPA_PB: Playbook = { id: "stock-purchase-agreement", version: "1.0.0" };
const APA_PB: Playbook = { id: "asset-purchase-agreement", version: "1.0.0" };
const EARNOUT_PB: Playbook = { id: "earnout-agreement", version: "1.0.0" };
const DS_PB: Playbook = { id: "disclosure-schedules", version: "1.0.0" };

const SRC = { name: "test.docx", sha256: "0".repeat(64), size_bytes: 100 };

function withPb(ctx: RuleContext, pb: Playbook): RuleContext {
  return { ...ctx, playbook: pb };
}

describe("v4 M&A ruleset — registry contract", () => {
  it("exports exactly 80 rules with stable MNA-NNN ids", () => {
    expect(M_AND_A_RULES.length).toBe(80);
    const ids = M_AND_A_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(80);
    for (const r of M_AND_A_RULES) {
      expect(r.id, r.id).toMatch(/^MNA-\d{3}$/);
      expect(r.version, r.id).toMatch(/^\d+\.\d+\.\d+$/);
      expect(r.category, r.id).toBe("m-and-a");
      expect(r.applies_to_playbooks, r.id).toBeDefined();
    }
  });

  it("scopes every rule to one or more M&A playbooks", () => {
    const allowed = new Set<string>(MA_PLAYBOOK_IDS);
    for (const r of M_AND_A_RULES) {
      for (const pb of r.applies_to_playbooks ?? []) {
        expect(allowed.has(pb), `${r.id} → ${pb}`).toBe(true);
      }
    }
  });

  it("does not fire any rule under a non-M&A playbook", async () => {
    const ctx = buildContext(["Some other doc", "No M&A content here."]);
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    expect(run.findings.length).toBe(0);
    expect(run.execution_log.every((e) => !e.fired)).toBe(true);
  });
});

const COMPLIANT_LOI: [string, ...string[]][] = [
  [
    "Letter of Intent",
    "This Letter of Intent reflects the parties' good-faith outline. Binding provisions: confidentiality, exclusivity (45 days), expenses, governing law, and forum. Non-Binding: purchase price ($50M aggregate consideration), structure (stock purchase), and definitive-agreement terms. Confidentiality: each party shall hold the other's information in confidence. Exclusivity: seller will not solicit competing offers during the no-shop period. Purchase Price: $50,000,000 aggregate consideration, cash. Structure: stock purchase of all outstanding shares. Conditions: due diligence, financing, HSR clearance. Expenses: each party shall bear its own expenses. Termination: this LOI expires on the drop-dead date. Governing Law: Delaware. Forum: Delaware Chancery.",
  ],
];

describe("v4 M&A — compliant LOI fixture", () => {
  it("emits no critical findings against the compliant LOI fixture", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_LOI), LOI_PB);
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    const criticals = run.findings.filter((f) => f.severity === "critical");
    expect(criticals.map((f) => f.rule_id)).toEqual([]);
  });

  it("is deterministic across runs", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_LOI), LOI_PB);
    const a = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    const b = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    expect(a.result_hash).toEqual(b.result_hash);
  });
});

describe("MNA-001 — non-binding phrasings a real LOI writes (v1.1.0)", () => {
  // Regression: the demarcation check required the non-binding half to read
  // "non-binding" / "not binding" (adjacent) / "except as|for". A compliant LOI
  // that states its non-binding intent as "not intended to be binding" or "does
  // not create a binding obligation", and carves out with "save for" / "other
  // than", scored 2/3 and drew a false "demarcation incomplete" finding.
  const COMPLIANT: [string, string][] = [
    [
      "other-than + does-not-create",
      "This letter of intent does not create a binding obligation, other than the provisions regarding confidentiality and the no-shop covenant, which the parties intend to be binding.",
    ],
    [
      "save-for + not-intended-to-be",
      "Save for the confidentiality and expense-reimbursement clauses, which are legally binding, this term sheet is not intended to be binding.",
    ],
  ];
  for (const [label, clause] of COMPLIANT) {
    it(`does not fire on a demarcated LOI: ${label}`, async () => {
      const ctx = withPb(buildContext(["Letter of Intent", clause]), LOI_PB);
      const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
      expect(run.findings.some((f) => f.rule_id === "MNA-001")).toBe(false);
    });
  }

  it("still fires when the LOI states no non-binding intent at all", async () => {
    const ctx = withPb(
      buildContext([
        "Letter of Intent",
        "This Letter of Intent sets out the proposed purchase price and the confidentiality obligations of the parties, both of which are binding.",
      ]),
      LOI_PB,
    );
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "MNA-001")).toBe(true);
  });
});

describe("v4 M&A — failure cases", () => {
  it("MNA-001 fires when LOI omits binding / non-binding demarcation", async () => {
    const ctx = withPb(
      buildContext([
        "LOI",
        "The parties intend to consummate the transaction at $50M with no further detail provided.",
      ]),
      LOI_PB,
    );
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "MNA-001")).toBe(true);
  });

  it("MNA-015 reads a 'Material Adverse Change' / MAC definition, not just MAE (v1.1.0)", async () => {
    // A merger agreement drafted around MAC rather than MAE was reported as
    // missing the definition entirely.
    const mac = withPb(
      buildContext([
        "Definitions",
        "'Material Adverse Change' means any change that is materially adverse to the business, subject to customary carve-outs (a MAC).",
      ]),
      SPA_PB,
    );
    expect(
      (await runEngine({ rules: M_AND_A_RULES, ctx: mac, source_file: SRC })).findings.some(
        (f) => f.rule_id === "MNA-015",
      ),
    ).toBe(false);
    // A document with no MAE/MAC definition still fires.
    const none = withPb(
      buildContext(["Definitions", "'Company' means Acme Corp., a Delaware corporation."]),
      SPA_PB,
    );
    expect(
      (await runEngine({ rules: M_AND_A_RULES, ctx: none, source_file: SRC })).findings.some(
        (f) => f.rule_id === "MNA-015",
      ),
    ).toBe(true);
  });

  it("MNA-005 reads a verb-form transaction structure ('acquire all … capital stock')", async () => {
    const has = withPb(
      buildContext([
        "Proposed Transaction",
        "The Buyer proposes to acquire all of the issued and outstanding capital stock of the Company for $40,000,000.",
      ]),
      LOI_PB,
    );
    expect(
      (await runEngine({ rules: M_AND_A_RULES, ctx: has, source_file: SRC })).findings.some(
        (f) => f.rule_id === "MNA-005",
      ),
    ).toBe(false);
    // "acquire new equipment" is not a transaction structure.
    const noStructure = withPb(
      buildContext(["Intent", "The parties shall negotiate a definitive agreement in good faith."]),
      LOI_PB,
    );
    expect(
      (await runEngine({ rules: M_AND_A_RULES, ctx: noStructure, source_file: SRC })).findings.some(
        (f) => f.rule_id === "MNA-005",
      ),
    ).toBe(true);
  });

  it("MNA-010 fires when SPA omits the operative purchase-and-sale clause", async () => {
    const ctx = withPb(
      buildContext([
        "Stock Purchase Agreement",
        "Definitions: the Company, the Buyer, the Sellers. Representations and warranties of the Company. Indemnification and survival. Closing conditions including bring-down. Material Adverse Effect carve-outs. Governing Law is Delaware.",
      ]),
      SPA_PB,
    );
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "MNA-010")).toBe(true);
  });

  it("MNA-040 fires on disclosure-schedule data-room reference", async () => {
    const ctx = withPb(
      buildContext([
        "Disclosure Schedule",
        "Section 3.10 Material Contracts: see the data room folder Contracts/.",
      ]),
      DS_PB,
    );
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "MNA-040")).toBe(true);
  });

  it("MNA-067 fires when earnout disclaims duty to maximize", async () => {
    const ctx = withPb(
      buildContext([
        "Earnout Agreement",
        "Buyer has no duty to maximize the earnout and may operate the business in its sole discretion notwithstanding any effect on the earnout.",
      ]),
      EARNOUT_PB,
    );
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "MNA-067")).toBe(true);
  });

  it("MNA-024 fires when APA omits bulk-sales-law clause", async () => {
    const ctx = withPb(
      buildContext([
        "Asset Purchase Agreement",
        "Purchased Assets: equipment and inventory. Excluded Assets: cash. Assumed Liabilities: trade payables. Excluded Liabilities: tax. Purchase Price Allocation per IRC § 1060. Required Consents listed in Schedule. Bill of Sale and Assignment and Assumption Agreement are attached.",
      ]),
      APA_PB,
    );
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "MNA-024")).toBe(true);
  });
});

describe("MNA earnout / set-off spelling variants — hyphenated & closed forms", () => {
  // The detectors were anchored on the closed literal "earnout" / "set.off",
  // missing the hyphenated "earn-out" (the dominant drafting form), the spaced
  // "earn out", and the closed "setoff".
  it("MNA-067 fires on a hyphenated 'Earn-Out' maximization disclaimer", async () => {
    const ctx = withPb(
      buildContext([
        "Earn-Out Agreement",
        "Buyer has no obligation to maximize the Earn-Out and may operate the business in its sole discretion notwithstanding any effect on the Earn-Out.",
      ]),
      EARNOUT_PB,
    );
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "MNA-067")).toBe(true);
  });

  it("MNA-065 accepts a hyphenated 'Earn-Out Period' good-faith conduct covenant", async () => {
    const ctx = withPb(
      buildContext([
        "Conduct of Business",
        "During the Earn-Out Period, Buyer shall operate the acquired business in good faith consistent with achieving the Earn-Out.",
      ]),
      EARNOUT_PB,
    );
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "MNA-065")).toBe(false);
  });

  it("MNA-069 accepts a closed-spelling 'Setoff' clause", async () => {
    const ctx = withPb(
      buildContext([
        "Right of Setoff",
        "The Buyer may setoff any indemnifiable claim against the Earn-Out payments in good faith.",
      ]),
      EARNOUT_PB,
    );
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "MNA-069")).toBe(false);
  });
});

describe("MNA presence forms an APA actually writes (v1.1.0)", () => {
  it("accepts 'governed by the laws of' and a named third-party consent", async () => {
    const ctx = withPb(
      buildContext(
        [
          "8. Conditions to Closing",
          "Buyer's obligation to close is conditioned on assignment of the lease for the premises with the landlord's written consent.",
        ],
        [
          "11. General",
          "This Agreement is governed by the laws of the State of Michigan, and any dispute arising out of this Agreement shall be resolved in the state courts located in Grand Traverse County, Michigan.",
        ],
      ),
      APA_PB,
    );
    const run = await runEngine({
      rules: M_AND_A_RULES,
      ctx,
      executed_at: "2026-05-12T00:00:00Z",
      source_file: SRC,
    });
    const fired = new Set(run.findings.map((f) => f.rule_id));
    expect(fired.has("MNA-019"), "MNA-019 should accept 'governed by the laws of'").toBe(false);
    expect(fired.has("MNA-026"), "MNA-026 should accept a named third-party consent").toBe(false);
  });

  it("still reports both when genuinely absent", async () => {
    const ctx = withPb(
      buildContext(["APA", "Seller sells the purchased assets to Buyer at the closing."]),
      APA_PB,
    );
    const run = await runEngine({
      rules: M_AND_A_RULES,
      ctx,
      executed_at: "2026-05-12T00:00:00Z",
      source_file: SRC,
    });
    const fired = new Set(run.findings.map((f) => f.rule_id));
    expect(fired.has("MNA-019")).toBe(true);
    expect(fired.has("MNA-026")).toBe(true);
  });
});

describe("MNA-042 — the no-admission materiality disclaimer (v1.1.0)", () => {
  const DS_PB_LOCAL: Playbook = { id: "disclosure-schedules", version: "1.0.0" };

  it("reads 'not an admission that such item is material'", async () => {
    const ctx = withPb(
      buildContext([
        "General Notes",
        "The inclusion of any item in these Disclosure Schedules is not an admission that such item is material, and no disclosure shall be deemed to enlarge or establish any standard of materiality or dollar threshold beyond that set forth in the Agreement.",
      ]),
      DS_PB_LOCAL,
    );
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    expect(run.findings.map((f) => f.rule_id)).not.toContain("MNA-042");
  });

  it("still fires when no materiality disclaimer exists", async () => {
    const ctx = withPb(
      buildContext(["Schedules", "The following contracts are disclosed."]),
      DS_PB_LOCAL,
    );
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    expect(run.findings.map((f) => f.rule_id)).toContain("MNA-042");
  });

  it("reads the verbose 'shall not be deemed to be an admission … that … is material' form", async () => {
    const ctx = withPb(
      buildContext([
        "Materiality",
        "The inclusion of any item in these Schedules shall not be deemed to be an admission or acknowledgment that such item is material to the Seller or falls within any dollar threshold set forth in the Purchase Agreement.",
      ]),
      DS_PB_LOCAL,
    );
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    expect(run.findings.map((f) => f.rule_id)).not.toContain("MNA-042");
  });

  it("MNA-044 reads a 'supplement or amend these Schedules' update mechanic", async () => {
    const ctx = withPb(
      buildContext([
        "Update Mechanic",
        "The Seller may supplement or amend these Schedules by written notice to the Buyer prior to the Closing.",
      ]),
      DS_PB_LOCAL,
    );
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    expect(run.findings.map((f) => f.rule_id)).not.toContain("MNA-044");
    const noUpdate = withPb(
      buildContext(["Schedules", "The following contracts are disclosed."]),
      DS_PB_LOCAL,
    );
    expect(
      (await runEngine({ rules: M_AND_A_RULES, ctx: noUpdate, source_file: SRC })).findings.map(
        (f) => f.rule_id,
      ),
    ).toContain("MNA-044");
  });
});

describe("MNA-040 — blanket data-room deemed-disclosure in its real wording (v1.1.0)", () => {
  const run1 = async (body: string) => {
    const ctx = withPb(buildContext(["Disclosure", body]), DS_PB);
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    return new Set(run.findings.map((f) => f.rule_id));
  };

  it("fires on 'any matter disclosed in the data room shall be deemed disclosed'", async () => {
    expect(
      (
        await run1(
          "Any matter disclosed in the data room shall be deemed disclosed for all purposes.",
        )
      ).has("MNA-040"),
    ).toBe(true);
  });

  it("fires on reps 'qualified by all documents made available in the data room'", async () => {
    expect(
      (
        await run1(
          "The representations are qualified by all documents made available in the data room.",
        )
      ).has("MNA-040"),
    ).toBe(true);
  });

  it("stays silent on a clean numbered-schedule disclosure", async () => {
    expect(
      (
        await run1(
          "The matters set forth on Schedule 3.7 are disclosed in response to Section 3.7 of the Agreement.",
        )
      ).has("MNA-040"),
    ).toBe(false);
  });

  // v1.2.0 — the INVERSE clause (good anti-sandbagging drafting: an item is NOT
  // deemed disclosed merely by sitting in the data room) trips the same
  // "deemed disclosed … data room" window and must not be flagged as the defect.
  it("stays silent on a protective 'not deemed disclosed' anti-sandbagging clause", async () => {
    expect(
      (
        await run1(
          "Materials in the data room are not deemed disclosed unless expressly cross-referenced in the Disclosure Schedules.",
        )
      ).has("MNA-040"),
    ).toBe(false);
    expect(
      (
        await run1(
          "No item shall be deemed disclosed solely by virtue of being posted to the data room; specific reference in a Schedule is required.",
        )
      ).has("MNA-040"),
    ).toBe(false);
  });

  it("still fires on blanket disclosure even when a 'no limit' phrase is present", async () => {
    expect(
      (await run1("There is no limit; all data-room materials are deemed disclosed to Buyer.")).has(
        "MNA-040",
      ),
    ).toBe(true);
  });
});

describe("Escrow release & termination in their real wording (v1.1.0)", () => {
  const ESCROW_PB: Playbook = { id: "escrow-agreement", version: "1.0.0" };
  const run1 = async (body: string) => {
    const ctx = withPb(buildContext(["Escrow", body]), ESCROW_PB);
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    return new Set(run.findings.map((f) => f.rule_id));
  };

  it("MNA-048 reads 'disburse … upon joint written instructions signed by the parties'", async () => {
    expect(
      (
        await run1(
          "The Escrow Agent shall disburse the Escrow Funds upon receipt of joint written instructions signed by the Buyer and the Seller.",
        )
      ).has("MNA-048"),
    ).toBe(false);
    expect((await run1("The Escrow Agent shall hold the Escrow Funds.")).has("MNA-048")).toBe(true);
  });

  it("MNA-053 reads 'This Agreement terminates when all Escrow Funds have been disbursed'", async () => {
    expect(
      (await run1("This Agreement terminates when all Escrow Funds have been disbursed.")).has(
        "MNA-053",
      ),
    ).toBe(false);
    expect((await run1("The Escrow Agent shall disburse per instructions.")).has("MNA-053")).toBe(
      true,
    );
  });

  it("MNA-053 reads a date-certain 'Release Date … release … balance of the Escrow Fund'", async () => {
    expect(
      (
        await run1(
          "On the Release Date, the Escrow Agent shall release to the Seller the balance of the Escrow Fund less any pending claims.",
        )
      ).has("MNA-053"),
    ).toBe(false);
  });

  it("MNA-049 reads a 'joint written instructions … or … final order of a court' dispute scheme", async () => {
    expect(
      (
        await run1(
          "The Escrow Agent shall release the Escrow Fund only upon joint written instructions of both parties, or upon a final, non-appealable order of a court of competent jurisdiction.",
        )
      ).has("MNA-049"),
    ).toBe(false);
    expect(
      (
        await run1("The Escrow Agent shall hold the funds and release them after twelve months.")
      ).has("MNA-049"),
    ).toBe(true);
  });
});

describe("Earnout conduct covenant & CoC acceleration in real wording (v1.1.0)", () => {
  const EARNOUT_PB: Playbook = { id: "earnout-agreement", version: "1.0.0" };
  const run1 = async (body: string) => {
    const ctx = withPb(buildContext(["Earnout", body]), EARNOUT_PB);
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    return new Set(run.findings.map((f) => f.rule_id));
  };

  it("MNA-065 reads a period-first 'operate the business in good faith' covenant", async () => {
    expect(
      (
        await run1(
          "During the Earnout Period, the Buyer shall operate the acquired business in good faith and shall not take any action for the primary purpose of reducing the Earnout Payments.",
        )
      ).has("MNA-065"),
    ).toBe(false);
    expect(
      (await run1("The Buyer shall pay the Sellers based on revenue milestones.")).has("MNA-065"),
    ).toBe(true);
  });

  it("MNA-070 reads acceleration stated as the event ('sells the business … immediately due')", async () => {
    expect(
      (
        await run1(
          "If the Buyer sells the acquired business during the Earnout Period, all unpaid Earnout Payments become immediately due.",
        )
      ).has("MNA-070"),
    ).toBe(false);
    expect(
      (await run1("The Buyer shall pay each Earnout Payment within 10 days.")).has("MNA-070"),
    ).toBe(true);
  });
});

describe("MNA-012 reads the verb-form reps-and-warranties article (v1.1.0)", () => {
  const run1 = async (body: string) => {
    const ctx = withPb(buildContext(["Representations", body]), SPA_PB);
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    return new Set(run.findings.map((f) => f.rule_id));
  };

  it("reads 'The Seller represents and warrants that …'", async () => {
    expect(
      (await run1("The Seller represents and warrants that the Company is duly organized.")).has(
        "MNA-012",
      ),
    ).toBe(false);
  });

  it("still fires when the agreement contains no representations", async () => {
    expect(
      (await run1("The Buyer shall pay $9,000,000 at the Closing for the Shares.")).has("MNA-012"),
    ).toBe(true);
  });
});

describe("MNA-032 reads 'approval by the stockholders' order (v1.1.0)", () => {
  const MERGER_PB: Playbook = { id: "merger-agreement", version: "1.0.0" };
  const run1 = async (body: string) => {
    const ctx = withPb(buildContext(["Conditions", body]), MERGER_PB);
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    return new Set(run.findings.map((f) => f.rule_id));
  };

  it("reads 'subject to approval by the Company's stockholders'", async () => {
    expect(
      (await run1("The merger is subject to approval by the Company's stockholders.")).has(
        "MNA-032",
      ),
    ).toBe(false);
  });

  it("still fires when no stockholder approval condition is present", async () => {
    expect(
      (await run1("The merger is subject to the expiration of the antitrust waiting period.")).has(
        "MNA-032",
      ),
    ).toBe(true);
  });
});

describe("MNA-073/074 read the parenthesized non-compete duration (v1.1.0)", () => {
  const RC_PB: Playbook = { id: "ma-restrictive-covenant", version: "1.0.0" };
  const run1 = async (body: string) => {
    const ctx = withPb(buildContext(["Restrictive Covenants", body]), RC_PB);
    const run = await runEngine({ rules: M_AND_A_RULES, ctx, source_file: SRC });
    return new Set(run.findings.map((f) => f.rule_id));
  };

  it("does not report the duration missing when it is stated as 'three (3) years'", async () => {
    // Both "non-compete" and "non-competition" spellings are read (v1.2.0).
    for (const noun of ["non-compete", "non-competition"]) {
      const ids = await run1(
        `The ${noun} covenant shall have a duration of three (3) years following the Closing, within the United States.`,
      );
      expect(ids.has("MNA-073"), noun).toBe(false); // duration present → no "missing"
      expect(ids.has("MNA-074"), noun).toBe(false); // 3 years within the 5-year norm
    }
  });

  it("still reports the duration missing when no duration is stated", async () => {
    const ids = await run1(
      "The Seller's non-competition covenant applies within the United States and to the Business.",
    );
    expect(ids.has("MNA-073")).toBe(true); // no duration → missing finding
  });

  it("flags a parenthesized non-compete longer than five years", async () => {
    const ids = await run1(
      "The non-competition covenant shall be for a period of seven (7) years following the Closing, within the United States.",
    );
    expect(ids.has("MNA-074")).toBe(true); // 7 > 5
  });
});

describe("MNA-067 — earnout-disclaimer detection allows an intervening verb (v1.2.0)", () => {
  const EARNOUT: Playbook = { id: "earnout-agreement", version: "1.0.0" };
  const fires = async (b: string) =>
    (
      await runEngine({
        rules: M_AND_A_RULES,
        ctx: withPb(buildContext(["Earnout", b]), EARNOUT),
        source_file: SRC,
      })
    ).findings.some((f) => f.rule_id === "MNA-067");

  it.each([
    "Buyer has no obligation to maximize the earnout.",
    "Buyer has no obligation to operate the Business so as to maximize the Earnout.",
    "Buyer is under no duty to take any action to increase the earn-out.",
  ])("fires on a maximization disclaimer: %s", async (b) => {
    expect(await fires(b)).toBe(true);
  });

  it.each([
    "Buyer shall use commercially reasonable efforts to maximize the earnout.",
    "Buyer's obligation to maximize the Earnout shall not be diminished.",
  ])("stays silent on an affirmative efforts standard: %s", async (b) => {
    expect(await fires(b)).toBe(false);
  });
});

describe("MNA-074 — >5yr non-compete recognizes 'shall not compete for … years' (v1.2.0)", () => {
  const RC: Playbook = { id: "ma-restrictive-covenant", version: "1.0.0" };
  const fires = async (b: string) =>
    (
      await runEngine({
        rules: M_AND_A_RULES,
        ctx: withPb(buildContext(["Restrictive Covenant", b]), RC),
        source_file: SRC,
      })
    ).findings.some((f) => f.rule_id === "MNA-074");

  it.each([
    "The non-compete period shall be seven (7) years.",
    "Seller shall not compete for a period of ten (10) years.",
    "The restricted period is 8 years from Closing.",
  ])("fires on a >5-year covenant: %s", async (b) => {
    expect(await fires(b)).toBe(true);
  });

  it.each([
    "Seller shall not compete for a period of three (3) years.",
    "The non-compete period shall be four (4) years.",
  ])("stays silent on a <=5-year covenant: %s", async (b) => {
    expect(await fires(b)).toBe(false);
  });
});

describe("MNA-074 — non-compete durations of 20 years and up (v1.3.0)", () => {
  const RC_PB: Playbook = { id: "ma-restrictive-covenant", version: "1.0.0" };
  const fires = async (b: string) =>
    (
      await runEngine({
        rules: M_AND_A_RULES,
        ctx: withPb(buildContext(["Agreement", b]), RC_PB),
        source_file: SRC,
      })
    ).findings.some((f) => f.rule_id === "MNA-074");

  // The year class stopped at 19, so the least enforceable covenants were the
  // ones that escaped the check.
  it.each([
    "Seller shall not compete with the Business for a period of twenty (20) years following the Closing.",
    "The restricted period is twenty-five (25) years.",
    "Seller agrees to a 30-year non-compete.",
  ])("fires on: %s", async (b) => {
    expect(await fires(b)).toBe(true);
  });

  it.each([
    "Seller shall not compete with the Business for a period of three (3) years following the Closing.",
    "The restricted period is five (5) years.",
  ])("stays silent on a compliant duration: %s", async (b) => {
    expect(await fires(b)).toBe(false);
  });
});

describe("MNA-004 — a financing term sheet states its price too", () => {
  /**
   * The commonest term sheet in the world is a venture financing round, and it
   * never says "purchase price". It states the amount, the pre-money
   * valuation, and the per-share price. On the M&A vocabulary alone this check
   * reported, at `critical`, that a Series B term sheet stating its price
   * three separate ways stated no price at all.
   */
  const mna004 = M_AND_A_RULES.find((r) => r.id === "MNA-004")!;

  it("is silent on the financing round's own price vocabulary", () => {
    for (const clause of [
      "Amount: $28,000,000, of which $20,000,000 is to be purchased by the Lead Investor.\nPre-Money Valuation: $112,000,000, calculated on a fully diluted basis.",
      "Price Per Share: the Original Issue Price, determined by dividing the valuation by the fully diluted capitalization.",
      "Investment Amount: $5,000,000 in a single closing.",
    ]) {
      expect(
        mna004.check(withPb(buildContext(["Summary of Terms", clause]), LOI_PB)),
        clause,
      ).toBeNull();
    }
  });

  it("still fires on a term sheet that names no price at all", () => {
    expect(
      mna004.check(
        withPb(
          buildContext([
            "Letter of Intent",
            "Buyer proposes to acquire the Company. Exclusivity runs for 45 days. The parties will negotiate definitive documentation.",
          ]),
          LOI_PB,
        ),
      ),
    ).not.toBeNull();
  });
});

describe("MNA-010 / MNA-019 — the operative clause and the law, in a short agreement", () => {
  const spa = (...body: string[]) =>
    withPb(buildContext(["STOCK PURCHASE AGREEMENT", ...body] as [string, ...string[]]), SPA_PB);
  const ruleById = (id: string) => M_AND_A_RULES.find((r) => r.id === id)!;

  it("MNA-010 reads the sale stated buyer-first", () => {
    // "Seller sells to Buyer all of the outstanding shares of the Company for
    // $42,000,000" is the plainest statement of the sale there is, and both
    // sentence branches read only the seller-shares-buyer order.
    expect(
      ruleById("MNA-010").check(
        spa(
          "Seller sells to Buyer all of the outstanding shares of Sablefield Software, Inc. for $42,000,000 in cash at closing.",
        ),
      ),
    ).toBeNull();
  });

  it("MNA-019 reads 'Delaware law governs'", () => {
    // The adjectival form the jurisdictions extractor has read since v1; this
    // is the third ruleset found carrying its own narrower copy.
    expect(ruleById("MNA-019").check(spa("Delaware law governs this Agreement."))).toBeNull();
  });
});
