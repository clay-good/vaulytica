import { describe, expect, it } from "vitest";

import { EQUITY_RULES } from "./rules.js";
import { EQT_PLAYBOOK_IDS } from "./_helpers.js";
import { buildContext } from "../../../_test-fixtures.js";
import { runEngine } from "../../../runner.js";
import type { Playbook, RuleContext } from "../../../finding.js";

const SAFE_PB: Playbook = { id: "safe-yc", version: "1.0.0" };
const CONV_NOTE_PB: Playbook = { id: "convertible-note", version: "1.0.0" };
const OPTION_PB: Playbook = { id: "stock-option-grant", version: "1.0.0" };
const E83B_PB: Playbook = { id: "section-83b-election", version: "1.0.0" };

const SRC = { name: "test.docx", sha256: "0".repeat(64), size_bytes: 100 };

function withPb(ctx: RuleContext, pb: Playbook): RuleContext {
  return { ...ctx, playbook: pb };
}

describe("v4 Equity ruleset — registry contract", () => {
  it("exports exactly 70 rules with stable EQT-NNN ids", () => {
    expect(EQUITY_RULES.length).toBe(70);
    const ids = EQUITY_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(70);
    for (const r of EQUITY_RULES) {
      expect(r.id, r.id).toMatch(/^EQT-\d{3}$/);
      expect(r.version, r.id).toMatch(/^\d+\.\d+\.\d+$/);
      expect(r.category, r.id).toBe("equity");
      expect(r.applies_to_playbooks, r.id).toBeDefined();
    }
  });

  it("scopes every rule to one or more equity playbooks", () => {
    const allowed = new Set<string>(EQT_PLAYBOOK_IDS);
    for (const r of EQUITY_RULES) {
      for (const pb of r.applies_to_playbooks ?? []) {
        expect(allowed.has(pb), `${r.id} → ${pb}`).toBe(true);
      }
    }
  });

  it("does not fire any rule under a non-equity playbook", async () => {
    const ctx = buildContext(["Some other doc", "No equity content here."]);
    const run = await runEngine({ rules: EQUITY_RULES, ctx, source_file: SRC });
    expect(run.findings.length).toBe(0);
    expect(run.execution_log.every((e) => !e.fired)).toBe(true);
  });
});

const COMPLIANT_SAFE: [string, ...string[]][] = [
  [
    "SAFE",
    "This Post-Money SAFE is entered into between Acme Inc. and the Investor. Definitions include Equity Financing, Liquidity Event, and Dissolution Event. Post-Money Valuation Cap: $20,000,000. Discount Rate: 80%. Most Favored Nation applies to any subsequent convertible instrument issued before the Equity Financing. Investor represents it is an accredited investor. This SAFE shall be governed by the laws of the State of Delaware. Upon a Liquidity Event the Investor shall receive the greater of cash-back or as-converted. Upon Dissolution the Investor has priority over Common Stock.",
  ],
];

describe("v4 Equity — compliant SAFE fixture", () => {
  it("emits no critical findings against the compliant SAFE fixture", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_SAFE), SAFE_PB);
    const run = await runEngine({ rules: EQUITY_RULES, ctx, source_file: SRC });
    const criticals = run.findings.filter((f) => f.severity === "critical");
    expect(criticals.map((f) => f.rule_id)).toEqual([]);
  });

  it("is deterministic across runs", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_SAFE), SAFE_PB);
    const a = await runEngine({ rules: EQUITY_RULES, ctx, source_file: SRC });
    const b = await runEngine({ rules: EQUITY_RULES, ctx, source_file: SRC });
    expect(a.result_hash).toEqual(b.result_hash);
  });
});

describe("v4 Equity — failure cases", () => {
  it("EQT-008 fires when a SAFE carries interest-accrual language", async () => {
    const ctx = withPb(
      buildContext([
        "SAFE",
        "This SAFE shall bear interest at the rate of 5% per annum until conversion.",
      ]),
      SAFE_PB,
    );
    const run = await runEngine({ rules: EQUITY_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "EQT-008")).toBe(true);
  });

  it("EQT-012 fires when a convertible note carries an interest rate at 30% per annum", async () => {
    const ctx = withPb(
      buildContext([
        "Convertible Note",
        "Interest shall accrue at the rate of 30% per annum, compounded annually.",
      ]),
      CONV_NOTE_PB,
    );
    const run = await runEngine({ rules: EQUITY_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "EQT-012")).toBe(true);
  });

  it("EQT-020 fires when an option grant omits exercise price", async () => {
    const ctx = withPb(
      buildContext([
        "Stock Option Grant",
        "Grant Date: January 1, 2026. Number of Shares Subject to the Option: 10,000. Vesting Schedule: 4-year monthly with 1-year cliff. The Option is an Incentive Stock Option under section 422.",
      ]),
      OPTION_PB,
    );
    const run = await runEngine({ rules: EQUITY_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "EQT-020")).toBe(true);
  });

  it("EQT-048 fires when a § 83(b) election omits the procedural recitals", async () => {
    const ctx = withPb(
      buildContext([
        "Section 83(b) Election",
        "The undersigned hereby makes an election under section 83(b) of the Internal Revenue Code with respect to restricted stock.",
      ]),
      E83B_PB,
    );
    const run = await runEngine({ rules: EQUITY_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "EQT-048")).toBe(true);
  });
});

describe("EQT-048 — 83(b) filing recitals in IRS-model wording (v1.1.0)", () => {
  // Regression: the deadline pattern required the word "thirty", and the IRS
  // pattern required the abbreviated "IRS Service Center". A compliant election
  // written the way the IRS model statement is — digits-only "30 days" and the
  // spelled-out "Internal Revenue Service Center" — matched neither and drew a
  // false "recitals incomplete" finding.
  it("does not fire on 'within 30 days … Internal Revenue Service Center … copy to the employer'", async () => {
    const ctx = withPb(
      buildContext([
        "Section 83(b) Election",
        "This statement is filed within 30 days of the transfer with the Internal Revenue Service Center where the taxpayer files their return, and a copy has been furnished to the employer.",
      ]),
      E83B_PB,
    );
    const run = await runEngine({ rules: EQUITY_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "EQT-048")).toBe(false);
  });

  it("still fires on an election that states none of the procedural recitals", async () => {
    const ctx = withPb(
      buildContext([
        "Section 83(b) Election",
        "The recipient acknowledges receipt of restricted shares subject to vesting over four years.",
      ]),
      E83B_PB,
    );
    const run = await runEngine({ rules: EQUITY_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "EQT-048")).toBe(true);
  });
});

describe("Voting agreement — election covenant & termination in real wording", () => {
  const VOTING_PB: Playbook = { id: "voting-agreement", version: "1.0.0" };
  const run1 = async (body: string) => {
    const ctx = withPb(buildContext(["Voting Agreement", body]), VOTING_PB);
    const run = await runEngine({ rules: EQUITY_RULES, ctx, source_file: SRC });
    return new Set(run.findings.map((f) => f.rule_id));
  };

  it("EQT-057 reads 'vote all shares … so as to elect to the Board … directors designated'", async () => {
    expect(
      (
        await run1(
          "Each Stockholder agrees to vote all of its shares so as to elect to the Board of Directors two directors designated by the holders of a majority of the Preferred Stock.",
        )
      ).has("EQT-057"),
    ).toBe(false);
    expect(
      (await run1("Each Stockholder shall keep the terms of this Agreement confidential.")).has(
        "EQT-057",
      ),
    ).toBe(true);
  });

  it("EQT-062 reads a 'terminate on … public offering … or Sale of the Company' clause", async () => {
    expect(
      (
        await run1(
          "This Agreement shall terminate upon the earliest of: (a) the closing of a firm-commitment underwritten public offering; or (b) the closing of a Sale of the Company.",
        )
      ).has("EQT-062"),
    ).toBe(false);
    expect(
      (await run1("Each Stockholder agrees to vote its shares as provided herein.")).has("EQT-062"),
    ).toBe(true);
  });
});

describe("EQT-068 — election window reads the parenthesized 'fifteen (15) days to elect' (v1.1.0)", () => {
  const ROFR_PB: Playbook = { id: "rofr-co-sale", version: "1.0.0" };
  const run1 = async (body: string) => {
    const ctx = withPb(buildContext(["ROFR", body]), ROFR_PB);
    const run = await runEngine({ rules: EQUITY_RULES, ctx, source_file: SRC });
    return new Set(run.findings.map((f) => f.rule_id));
  };
  it("does not report the election window missing when stated as '(15) days to elect'", async () => {
    expect(
      (
        await run1(
          "The Company shall have fifteen (15) days to elect to purchase the offered shares.",
        )
      ).has("EQT-068"),
    ).toBe(false);
  });
  it("still reports the mechanics missing when none is stated", async () => {
    expect(
      (await run1("The shares are subject to certain transfer restrictions only.")).has("EQT-068"),
    ).toBe(true);
  });
});

describe("EQT lock-up spelling — closed 'lockup' form (v1.1.0)", () => {
  // /lock.up/ matched "lock-up" / "lock up" but not the closed "lockup",
  // so a lockup clause with a non-180-day period and no "market stand-off"
  // term falsely tripped the missing-clause finding.
  const RSPA_PB: Playbook = { id: "rspa", version: "1.0.0" };
  const IRA_PB: Playbook = { id: "investor-rights-agreement", version: "1.0.0" };

  it("EQT-041 accepts a closed-spelling '90-day lockup' clause", async () => {
    const ctx = withPb(
      buildContext([
        "Lockup",
        "Each holder agrees to a 90-day lockup following the Company's initial public offering.",
      ]),
      RSPA_PB,
    );
    const run = await runEngine({ rules: EQUITY_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "EQT-041")).toBe(false);
  });

  it("EQT-055 accepts a closed-spelling '90-day lockup' clause", async () => {
    const ctx = withPb(
      buildContext([
        "Lockup",
        "Each Investor agrees to a 90-day lockup following the Company's initial public offering.",
      ]),
      IRA_PB,
    );
    const run = await runEngine({ rules: EQUITY_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "EQT-055")).toBe(false);
  });
});

describe("EQT-028 — anti-repricing covenant in its passive/negated forms (v1.1.0)", () => {
  const run1 = async (body: string) => {
    const ctx = withPb(buildContext(["Repricing", body]), OPTION_PB);
    const run = await runEngine({ rules: EQUITY_RULES, ctx, source_file: SRC });
    return new Set(run.findings.map((f) => f.rule_id));
  };

  // The exchange-required anti-repricing covenant is the GOOD governance this
  // rule wants; its standard passive/negated wording ("No option may be
  // repriced …", "Options shall not be repriced …") tripped the pattern.
  it("stays silent on 'No option may be repriced without stockholder approval'", async () => {
    expect(
      (await run1("No option may be repriced without stockholder approval.")).has("EQT-028"),
    ).toBe(false);
  });

  it("stays silent on 'Options shall not be repriced without stockholder approval'", async () => {
    expect(
      (await run1("Options shall not be repriced without stockholder approval.")).has("EQT-028"),
    ).toBe(false);
  });

  it("still fires when repricing without approval is affirmatively permitted", async () => {
    expect(
      (
        await run1("The Committee may reprice outstanding options without stockholder approval.")
      ).has("EQT-028"),
    ).toBe(true);
  });
});

describe("EQT-058 — drag-along covenant recognizes the 'bring-along' synonym (v1.1.0)", () => {
  const VOTING_PB: Playbook = { id: "voting-agreement", version: "1.0.0" };
  const run = async (body: string) => {
    const r = await runEngine({
      rules: EQUITY_RULES,
      ctx: withPb(buildContext(["Voting Agreement", body]), VOTING_PB),
      source_file: SRC,
    });
    return new Set(r.findings.map((f) => f.rule_id));
  };

  it("does not report the covenant missing when drafted as 'bring-along'", async () => {
    expect(
      (await run("The majority may exercise bring-along rights to compel a sale.")).has("EQT-058"),
    ).toBe(false);
  });

  it("still fires when no drag/bring-along covenant is present", async () => {
    expect(
      (await run("The parties shall vote their shares as directed by the Board.")).has("EQT-058"),
    ).toBe(true);
  });
});

describe("EQT-052 — pro-rata rights presence handles the hyphenated spelling (v1.1.0)", () => {
  const IRA_PB: Playbook = { id: "investor-rights-agreement", version: "1.0.0" };
  const run = async (body: string) =>
    new Set(
      (
        await runEngine({
          rules: EQUITY_RULES,
          ctx: withPb(buildContext(["Investor Rights Agreement", body]), IRA_PB),
          source_file: SRC,
        })
      ).findings.map((f) => f.rule_id),
    );

  it("does not report the clause missing when written 'pro-rata'", async () => {
    expect(
      (await run("Each Major Investor shall have pro-rata rights in subsequent issuances.")).has(
        "EQT-052",
      ),
    ).toBe(false);
  });

  it("still fires when no pro-rata / preemptive / maintain right is present", async () => {
    expect(
      (await run("The Company shall deliver annual financial statements.")).has("EQT-052"),
    ).toBe(true);
  });
});

describe("EQT-021 — FMV rep reads 'fair value … per § 1.409A' (v1.1.0)", () => {
  const PB: Playbook = { id: "stock-option-grant", version: "1.0.0" };
  const has = async (b: string) =>
    new Set(
      (
        await runEngine({
          rules: EQUITY_RULES,
          ctx: withPb(buildContext(["Option Grant", b]), PB),
          source_file: SRC,
        })
      ).findings.map((f) => f.rule_id),
    );
  it("does not fire when FMV is stated as 'fair value … per Treas. Reg. § 1.409A'", async () => {
    expect(
      (
        await has(
          "The Board determined the fair value of each share on the Grant Date per Treasury Regulation Section 1.409A-1(b)(5)(iv).",
        )
      ).has("EQT-021"),
    ).toBe(false);
  });
  it("still fires on a bare ASC-820 'fair value' with no 409A reference", async () => {
    expect(
      (await has("Shares are recorded at fair value under ASC 820 for accounting purposes.")).has(
        "EQT-021",
      ),
    ).toBe(true);
  });
});

describe("EQT-008 — interest-bearing SAFE detection (v1.1.0)", () => {
  const fires = async (b: string) =>
    (
      await runEngine({
        rules: EQUITY_RULES,
        ctx: withPb(buildContext(["SAFE", b]), SAFE_PB),
        source_file: SRC,
      })
    ).findings.some((f) => f.rule_id === "EQT-008");

  it.each([
    "The Purchase Amount shall accrue interest at a rate of 5% per annum until conversion.",
    "Interest shall accrue on the outstanding balance of this instrument at 6% per year.",
    "This SAFE bears interest at 4% per annum.",
    "The Investor is entitled to interest accruing at eight percent (8%).",
    "Simple interest of 5% per annum accrues on the Purchase Amount.",
  ])("fires on interest-accrual phrasing: %s", async (b) => {
    expect(await fires(b)).toBe(true);
  });

  it.each([
    "This SAFE shall not bear interest.",
    "No interest shall accrue on the Purchase Amount.",
    "This instrument is non-interest-bearing.",
    "The Purchase Amount bears no interest.",
    "The Company acts in the best interest of investors.",
  ])("stays silent on compliant / negated phrasing: %s", async (b) => {
    expect(await fires(b)).toBe(false);
  });
});

describe("EQT-012 — usury threshold recognizes 'per year' and parenthesized rates (v1.1.0)", () => {
  const fires = async (b: string) =>
    (
      await runEngine({
        rules: EQUITY_RULES,
        ctx: withPb(buildContext(["Convertible Note", b]), CONV_NOTE_PB),
        source_file: SRC,
      })
    ).findings.some((f) => f.rule_id === "EQT-012");

  it.each([
    "This note bears interest at 30% per annum.",
    "The interest rate is 30% per year.",
    "Interest accrues at a rate of thirty percent (30%) per annum.",
    "The note carries interest of 28%/yr.",
  ])("fires on a usurious annualized rate: %s", async (b) => {
    expect(await fires(b)).toBe(true);
  });

  it.each([
    "This note bears interest at 8% per annum.",
    "Interest accrues at 30% per annum, not to exceed the highest lawful rate.",
    "Ownership is 30% of the fully diluted capitalization.",
  ])("stays silent on a lawful rate / savings clause / non-rate percentage: %s", async (b) => {
    expect(await fires(b)).toBe(false);
  });
});

describe("EQT-028 — repricing detection recognizes 'reduce price' and reversed order (v1.2.0)", () => {
  const fires = async (b: string) =>
    (
      await runEngine({
        rules: EQUITY_RULES,
        ctx: withPb(buildContext(["Option Grant", b]), OPTION_PB),
        source_file: SRC,
      })
    ).findings.some((f) => f.rule_id === "EQT-028");

  it.each([
    "The Board may reprice this option without stockholder approval.",
    "The Committee may reduce the exercise price of outstanding options without obtaining shareholder approval.",
    "Options may be repriced by the Administrator without approval of stockholders.",
    "The Administrator may lower the strike price without shareholder approval.",
  ])("fires on a repricing override: %s", async (b) => {
    expect(await fires(b)).toBe(true);
  });

  it.each([
    "No option may be repriced without stockholder approval.",
    "The Company shall not reprice options without shareholder approval.",
    "The Administrator may not reduce the exercise price without stockholder approval.",
    "Options shall not be repriced without approval of the stockholders.",
  ])("stays silent on the anti-repricing covenant: %s", async (b) => {
    expect(await fires(b)).toBe(false);
  });
});

describe("EQT-008 / EQT-028 — adverbial negation and the 'consent' synonym", () => {
  const fires = async (id: string, pb: Playbook, b: string) =>
    (
      await runEngine({
        rules: EQUITY_RULES,
        ctx: withPb(buildContext(["Agreement", b]), pb),
        source_file: SRC,
      })
    ).findings.some((f) => f.rule_id === id);

  it("EQT-008 (v1.2.0) stays silent on 'shall never bear interest'", async () => {
    // The guard only knew "not"; "never" is the same disclaimer.
    expect(await fires("EQT-008", SAFE_PB, "This SAFE shall never bear interest.")).toBe(false);
  });

  it("EQT-008 still fires on an actual interest grant", async () => {
    expect(await fires("EQT-008", SAFE_PB, "The Purchase Amount shall bear interest at 6%.")).toBe(
      true,
    );
  });

  it("EQT-028 (v1.3.0) stays silent on an emphatic anti-repricing covenant", async () => {
    // "under no circumstances" separates the negation from the verb, so every
    // v1.2.0 guard missed it and the covenant was read as the violation.
    expect(
      await fires(
        "EQT-028",
        OPTION_PB,
        "Options shall, under no circumstances, be repriced without stockholder approval.",
      ),
    ).toBe(false);
  });

  it("EQT-028 fires when the carve-out says 'consent' rather than 'approval'", async () => {
    expect(
      await fires(
        "EQT-028",
        OPTION_PB,
        "The board may unilaterally reduce the strike price without shareholder consent.",
      ),
    ).toBe(true);
  });
});
