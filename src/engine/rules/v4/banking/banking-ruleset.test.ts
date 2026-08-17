import { describe, expect, it } from "vitest";

import { BANKING_RULES } from "./rules.js";
import { BNK_PLAYBOOK_IDS } from "./_helpers.js";
import { buildContext } from "../../../_test-fixtures.js";
import { runEngine } from "../../../runner.js";
import type { Playbook, RuleContext } from "../../../finding.js";

const NOTE_PB: Playbook = { id: "promissory-note", version: "1.0.0" };
const LOAN_PB: Playbook = { id: "loan-agreement", version: "1.0.0" };
const SEC_PB: Playbook = { id: "security-agreement", version: "1.0.0" };
const GTY_PB: Playbook = { id: "guaranty", version: "1.0.0" };
const IC_PB: Playbook = { id: "intercreditor-agreement", version: "1.0.0" };
const SUB_PB: Playbook = { id: "subordination-agreement", version: "1.0.0" };
const DOT_PB: Playbook = { id: "deed-of-trust", version: "1.0.0" };
const UCC1_PB: Playbook = { id: "ucc-1-financing-statement", version: "1.0.0" };

const SRC = { name: "test.docx", sha256: "0".repeat(64), size_bytes: 100 };

function withPb(ctx: RuleContext, pb: Playbook): RuleContext {
  return { ...ctx, playbook: pb };
}

describe("v4 Banking ruleset — registry contract", () => {
  it("exports exactly 51 rules with stable BNK-NNN ids", () => {
    expect(BANKING_RULES.length).toBe(51);
    const ids = BANKING_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(51);
    for (const r of BANKING_RULES) {
      expect(r.id, r.id).toMatch(/^BNK-\d{3}$/);
      expect(r.version, r.id).toMatch(/^\d+\.\d+\.\d+$/);
      expect(r.category, r.id).toBe("banking");
      expect(r.applies_to_playbooks, r.id).toBeDefined();
    }
  });

  it("scopes every rule to one or more banking playbooks", () => {
    const allowed = new Set<string>(BNK_PLAYBOOK_IDS);
    for (const r of BANKING_RULES) {
      for (const pb of r.applies_to_playbooks ?? []) {
        expect(allowed.has(pb), `${r.id} → ${pb}`).toBe(true);
      }
    }
  });

  it("does not fire under a non-banking playbook", async () => {
    const ctx = buildContext(["Some other doc", "No banking content."]);
    const run = await runEngine({ rules: BANKING_RULES, ctx, source_file: SRC });
    expect(run.findings.length).toBe(0);
    expect(run.execution_log.every((e) => !e.fired)).toBe(true);
  });
});

const COMPLIANT_NOTE: [string, ...string[]][] = [
  [
    "Promissory Note",
    "Maker: Acme Corp. Payee: BigBank. Principal Amount: $1,000,000. Maker absolutely and unconditionally promises to pay to the order of Payee. Interest rate: 8.0% per annum, not to exceed the highest lawful rate. Maturity date: 2031-01-01. Events of Default: payment default, insolvency, bankruptcy. Acceleration: holder may declare full principal and accrued interest immediately due. Waivers: maker waives presentment, demand, notice of dishonor, and protest.",
  ],
];

describe("v4 Banking — compliant promissory-note fixture", () => {
  it("emits no critical findings against the compliant note fixture", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_NOTE), NOTE_PB);
    const run = await runEngine({ rules: BANKING_RULES, ctx, source_file: SRC });
    const criticals = run.findings.filter((f) => f.severity === "critical");
    expect(criticals.map((f) => f.rule_id)).toEqual([]);
  });

  it("is deterministic across runs", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_NOTE), NOTE_PB);
    const a = await runEngine({ rules: BANKING_RULES, ctx, source_file: SRC });
    const b = await runEngine({ rules: BANKING_RULES, ctx, source_file: SRC });
    expect(a.result_hash).toEqual(b.result_hash);
  });
});

describe("v4 Banking — failure cases", () => {
  it("BNK-002 fires when note omits unconditional-promise language", async () => {
    const ctx = withPb(
      buildContext([
        "Note",
        "Maker Acme owes Payee BigBank $1,000,000 due 2031-01-01 with interest at 8% per annum, not to exceed the highest lawful rate. Maker waives presentment.",
      ]),
      NOTE_PB,
    );
    const run = await runEngine({ rules: BANKING_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "BNK-002")).toBe(true);
  });

  it("BNK-010 fires when loan agreement omits negative covenants", async () => {
    const ctx = withPb(
      buildContext([
        "Loan Agreement",
        "Loan amount: $50,000,000 term loan; use of proceeds: working capital. Interest: SOFR + 350 bps spread, 1.00% floor. Affirmative covenants: financial statements quarterly, maintenance of existence. Financial covenants: minimum liquidity $5M. Events of Default: payment default, cross-default, insolvency, 30-day cure period.",
      ]),
      LOAN_PB,
    );
    const run = await runEngine({ rules: BANKING_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "BNK-010")).toBe(true);
  });

  it("BNK-015 fires when security agreement omits granting clause", async () => {
    const ctx = withPb(
      buildContext([
        "Security Agreement",
        "Debtor Acme. Secured Party BigBank. Collateral: all accounts, inventory, equipment, and general intangibles. Representations: Debtor owns the collateral free of liens. Authorization to file UCC-1 financing statements. Remedies on default per UCC Article 9 — commercially reasonable disposition, repossession, deficiency.",
      ]),
      SEC_PB,
    );
    const run = await runEngine({ rules: BANKING_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "BNK-015")).toBe(true);
  });

  it("BNK-023 fires when guaranty omits suretyship-defenses waiver", async () => {
    const ctx = withPb(
      buildContext([
        "Guaranty",
        "Guarantor: Jane Smith. Obligee: BigBank. Underlying obligation: Note dated 2026-01-01. Type: continuing guaranty of payment, absolute. Cap: $1,000,000. Subrogation deferred until paid in full. Reinstatement clause for preferences applies.",
      ]),
      GTY_PB,
    );
    const run = await runEngine({ rules: BANKING_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "BNK-023")).toBe(true);
  });

  it("BNK-035 fires when subordination omits payment subordination / blockage", async () => {
    const ctx = withPb(
      buildContext([
        "Subordination Agreement",
        "Subordinated Debt: Junior Note dated 2026-01-01. Senior Debt: Senior facility including refinancings. Permitted payments: scheduled interest absent senior default. Section 510(a) of the Bankruptcy Code applies.",
      ]),
      SUB_PB,
    );
    const run = await runEngine({ rules: BANKING_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "BNK-035")).toBe(true);
  });

  it("BNK-040 fires when deed of trust omits legal description", async () => {
    const ctx = withPb(
      buildContext([
        "Deed of Trust",
        "Grantor: Acme. Trustee: First American Title. Beneficiary: BigBank. Property at 100 Main Street. Grants and conveys the property in trust to have and to hold. Power of sale with state notice procedure. Due on sale applies under Garn-St Germain. Notarized below.",
      ]),
      DOT_PB,
    );
    const run = await runEngine({ rules: BANKING_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "BNK-040")).toBe(true);
  });

  it("BNK-047 fires when UCC-1 prose omits collateral indication", async () => {
    const ctx = withPb(
      buildContext([
        "Financing Statement",
        "Debtor: Acme Corp (exact legal name from Delaware Secretary of State public organic record). Secured Party: BigBank, 1 Main St, mailing address. Filing office: Delaware Secretary of State, UCC Division. Lapse: 5 years; continuation 6 months before lapse. Authorized by Security Agreement of 2026-01-01.",
      ]),
      UCC1_PB,
    );
    const run = await runEngine({ rules: BANKING_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "BNK-047")).toBe(true);
  });

  it("BNK-027 fires when intercreditor omits priorities", async () => {
    const ctx = withPb(
      buildContext([
        "Intercreditor",
        "Payment blockage applies during default. Turnover required. 180-day enforcement standstill. Bankruptcy: DIP financing, 363 sale, plan support. Buy-out option at par plus accrued. Amendments require consent of each creditor party.",
      ]),
      IC_PB,
    );
    const run = await runEngine({ rules: BANKING_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "BNK-027")).toBe(true);
  });
});

describe("BNK-051 — confession of judgment / cognovit clause", () => {
  const run1 = async (body: string) => {
    const ctx = withPb(buildContext(["Note", body]), NOTE_PB);
    const run = await runEngine({ rules: BANKING_RULES, ctx, source_file: SRC });
    return run.findings.find((f) => f.rule_id === "BNK-051");
  };

  it("fires (critical) on a cognovit / attorney-to-confess clause", async () => {
    const f = await run1(
      "Maker irrevocably authorizes any attorney to appear and confess judgment against Maker for the unpaid balance, without prior notice or a hearing.",
    );
    expect(f).toBeDefined();
    expect(f?.severity).toBe("critical");
  });

  it("fires on the phrase 'confession of judgment'", async () => {
    expect(
      await run1("Maker consents to the entry of a confession of judgment upon default."),
    ).toBeDefined();
  });

  it("is silent when the clause is expressly disclaimed", async () => {
    expect(
      await run1("This Note contains no confession of judgment and no warrant of attorney."),
    ).toBeUndefined();
  });

  it("is silent on a clean note", async () => {
    expect(
      await run1(
        "Maker promises to pay Payee $50,000 with interest at 8% per annum, due on demand.",
      ),
    ).toBeUndefined();
  });
});

describe("BNK-013 — Reg Z / TILA disclosures apply to consumer credit only (v1.1.0)", () => {
  const findBnk013 = async (paras: [string, ...string[]][]) => {
    const ctx = withPb(buildContext(...paras), LOAN_PB);
    const run = await runEngine({ rules: BANKING_RULES, ctx, source_file: SRC });
    return run.findings.find((f) => f.rule_id === "BNK-013");
  };

  it("does not fire on a commercial term loan with no consumer-purpose signal", async () => {
    expect(
      await findBnk013([
        [
          "Term Loan Agreement",
          "The Lender agrees to make a term loan to the Borrower, a Delaware corporation, in the principal amount of $5,000,000. Interest at 7.5% per annum, payable quarterly. The Borrower shall maintain a fixed-charge coverage ratio of not less than 1.20 to 1.00.",
        ],
      ]),
    ).toBeUndefined();
  });

  it("fires on a consumer-purpose loan that omits the TILA disclosures", async () => {
    expect(
      await findBnk013([
        [
          "Consumer Loan Agreement",
          "This is a consumer loan for personal, family, or household purposes. Lender lends Borrower $15,000 at 12% per annum, repaid in 36 monthly installments.",
        ],
      ]),
    ).toBeDefined();
  });

  it("is silent on a consumer loan that includes the TILA disclosure block", async () => {
    expect(
      await findBnk013([
        [
          "Consumer Loan Agreement",
          "This consumer loan for personal, family, or household purposes states the Annual Percentage Rate (APR), the finance charge, the amount financed, and the total of payments as required by the Truth in Lending Act.",
        ],
      ]),
    ).toBeUndefined();
  });
});

describe("BNK-022 — guaranty reads 'unconditional' (v1.1.0)", () => {
  const GUAR: Playbook = { id: "guaranty", version: "1.0.0" };
  const has = async (b: string) =>
    new Set(
      (
        await runEngine({
          rules: BANKING_RULES,
          ctx: withPb(buildContext(["Guaranty", b]), GUAR),
          source_file: SRC,
        })
      ).findings.map((f) => f.rule_id),
    );
  it("does not fire on an 'unconditional guaranty'", async () => {
    expect(
      (
        await has("Guarantor provides an unconditional guaranty of the Borrower's obligations.")
      ).has("BNK-022"),
    ).toBe(false);
  });
});

describe("BNK-051 — cognovit detection recognizes 'judgment by confession' (v1.1.0)", () => {
  const NOTE: Playbook = { id: "promissory-note", version: "1.0.0" };
  const fires = async (b: string) =>
    (
      await runEngine({
        rules: BANKING_RULES,
        ctx: withPb(buildContext(["Promissory Note", b]), NOTE),
        source_file: SRC,
      })
    ).findings.some((f) => f.rule_id === "BNK-051");

  it.each([
    "The Borrower authorizes any attorney to confess judgment against the Borrower.",
    "Borrower waives the right to notice and hearing and authorizes entry of judgment by confession.",
    "This note contains a warrant of attorney to confess judgment.",
  ])("fires on a confession-of-judgment clause: %s", async (b) => {
    expect(await fires(b)).toBe(true);
  });

  it.each([
    "No confession of judgment is authorized under this note.",
    "Judgment by confession is prohibited and void under this note.",
  ])("stays silent on a disclaimed clause: %s", async (b) => {
    expect(await fires(b)).toBe(false);
  });
});

describe("BNK-051 — notes that disclaim a cognovit clause (v1.2.0)", () => {
  const PB: Playbook = { id: "promissory-note", version: "1.0.0" };
  const fires = async (b: string) =>
    (
      await runEngine({
        rules: BANKING_RULES,
        ctx: { ...buildContext(["Note", b]), playbook: PB },
        source_file: SRC,
      })
    ).findings.some((f) => f.rule_id === "BNK-051");

  // "cognovit" and "warrant of attorney" had no exclude coverage at all, so
  // naming either in order to disclaim it fired the rule.
  it.each([
    "This Note does not contain a cognovit clause. No attorney is authorized to confess judgment against Maker.",
    "The Note shall not include any confession of judgment provision, warrant of attorney, or judgment by confession against Maker.",
  ])("stays silent on: %s", async (b) => {
    expect(await fires(b)).toBe(false);
  });

  it("still fires on a genuine cognovit clause", async () => {
    expect(
      await fires(
        "Maker authorizes any attorney to confess judgment against Maker for the unpaid balance.",
      ),
    ).toBe(true);
  });
});

/**
 * Express-denial guard (same class as INS-012 / CON-030 / IPL-005). BNK-023's
 * bare "waive" pattern also matches inside a sentence refusing the waiver, and
 * one present-pattern match short-circuits a presence rule — so a guaranty in
 * which the guarantor KEEPS its suretyship defenses scored clean, while one
 * merely silent on the point fired. Preserved defences are what let a release,
 * modification, or impairment of collateral discharge the guarantor, which is
 * the whole risk the waiver removes.
 */
describe("BNK-023 — suretyship defenses expressly preserved", () => {
  const run = async (text: string) => {
    const res = await runEngine({
      rules: BANKING_RULES,
      ctx: withPb(buildContext(["Guaranty", text]), GTY_PB),
      source_file: SRC,
    });
    return res.findings.filter((f) => f.rule_id === "BNK-023").map((f) => f.title);
  };

  it.each([
    [
      "does not waive",
      "Guarantor does not waive any suretyship defenses, including release, modification, or impairment of collateral.",
    ],
    [
      "reserves",
      "Guarantor reserves all suretyship defenses notwithstanding any release or modification of the collateral.",
    ],
  ])("%s is reported as a denial, not as compliance", async (_form, text) => {
    expect(await run(text)).toEqual(["Suretyship defenses expressly preserved"]);
  });

  it("mere silence still reports the waiver as missing", async () => {
    expect(await run("Guarantor guarantees payment of the Obligations when due.")).toEqual([
      "Suretyship-defenses waiver missing",
    ]);
  });

  it("the compliant waiver stays silent", async () => {
    expect(
      await run(
        "Guarantor waives all suretyship defenses, including release, modification, and impairment of collateral.",
      ),
    ).toEqual([]);
  });
});

/**
 * Two more express-denial guards in this pack, same class as BNK-023. In each
 * the bare waive/defer pattern also matches a sentence REFUSING the waiver,
 * and one present match short-circuits a presence rule.
 */
describe("BNK-006 / BNK-025 — waivers expressly refused", () => {
  const run = async (id: string, pb: Playbook, heading: string, text: string) => {
    const res = await runEngine({
      rules: BANKING_RULES,
      ctx: withPb(buildContext([heading, text]), pb),
      source_file: SRC,
    });
    return res.findings.filter((f) => f.rule_id === id).map((f) => f.title);
  };

  it.each([
    ["Maker does not waive presentment, demand, notice of dishonor, or protest."],
    ["Maker reserves presentment and notice of dishonor."],
  ])("BNK-006 reports %j as a denial", async (text) => {
    expect(await run("BNK-006", NOTE_PB, "Note", text)).toEqual([
      "Maker waivers expressly refused",
    ]);
  });

  it("BNK-006 still reports the clause missing on silence", async () => {
    expect(
      await run(
        "BNK-006",
        NOTE_PB,
        "Note",
        "Maker promises to pay the principal sum with interest.",
      ),
    ).toEqual(["Maker waivers clause missing"]);
  });

  it("BNK-006 stays silent on the compliant waiver", async () => {
    expect(
      await run(
        "BNK-006",
        NOTE_PB,
        "Note",
        "Maker waives presentment, demand, notice of dishonor, and protest.",
      ),
    ).toEqual([]);
  });

  it("BNK-025 reports preserved subrogation rights as a denial", async () => {
    expect(
      await run(
        "BNK-025",
        GTY_PB,
        "Guaranty",
        "Guarantor does not waive its subrogation, contribution, or reimbursement rights.",
      ),
    ).toEqual(["Subrogation / contribution rights expressly preserved"]);
  });

  it("BNK-025 stays silent on the compliant waiver", async () => {
    expect(
      await run(
        "BNK-025",
        GTY_PB,
        "Guaranty",
        "Guarantor waives all subrogation and contribution rights until paid in full.",
      ),
    ).toEqual([]);
  });
});
