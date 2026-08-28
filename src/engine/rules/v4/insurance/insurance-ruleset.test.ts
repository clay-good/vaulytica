import { describe, expect, it } from "vitest";

import { INSURANCE_RULES } from "./rules.js";
import { INS_PLAYBOOK_IDS } from "./_helpers.js";
import { buildContext } from "../../../_test-fixtures.js";
import { runEngine } from "../../../runner.js";
import type { Playbook, RuleContext } from "../../../finding.js";

const POLICY_PB: Playbook = { id: "insurance-policy-summary", version: "1.0.0" };
const ENDORSEMENT_PB: Playbook = { id: "insurance-endorsement", version: "1.0.0" };
const IND_PB: Playbook = { id: "indemnification-agreement", version: "1.0.0" };
const HH_PB: Playbook = { id: "hold-harmless-agreement", version: "1.0.0" };

const SRC = { name: "test.docx", sha256: "0".repeat(64), size_bytes: 100 };

function withPb(ctx: RuleContext, pb: Playbook): RuleContext {
  return { ...ctx, playbook: pb };
}

describe("v4 Insurance ruleset — registry contract", () => {
  it("exports exactly 25 rules with stable INS-NNN ids", () => {
    expect(INSURANCE_RULES.length).toBe(25);
    const ids = INSURANCE_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(25);
    for (const r of INSURANCE_RULES) {
      expect(r.id, r.id).toMatch(/^INS-\d{3}$/);
      expect(r.version, r.id).toMatch(/^\d+\.\d+\.\d+$/);
      expect(r.category, r.id).toBe("insurance");
      expect(r.applies_to_playbooks, r.id).toBeDefined();
    }
  });

  it("scopes every rule to one or more insurance playbooks", () => {
    const allowed = new Set<string>(INS_PLAYBOOK_IDS);
    for (const r of INSURANCE_RULES) {
      for (const pb of r.applies_to_playbooks ?? []) {
        expect(allowed.has(pb), `${r.id} → ${pb}`).toBe(true);
      }
    }
  });

  it("does not fire under a non-insurance playbook", async () => {
    const ctx = buildContext(["Some other doc", "No insurance content."]);
    const run = await runEngine({ rules: INSURANCE_RULES, ctx, source_file: SRC });
    expect(run.findings.length).toBe(0);
    expect(run.execution_log.every((e) => !e.fired)).toBe(true);
  });
});

const COMPLIANT_POLICY: [string, ...string[]][] = [
  [
    "Declarations Page",
    "Named Insured: Acme Corp. Producer / Broker: Best Insurance Agency, license 12345. Policy Period: inception 2026-01-01 to expiration 2027-01-01, 12:01 a.m. Limits of liability: each occurrence $1,000,000; general aggregate $2,000,000. Premium: $25,000. Deductible: $5,000 per occurrence; SIR $10,000. Forms Schedule: CG 00 01 04 13 Commercial General Liability (edition 04/13). Coverage Trigger: occurrence; retroactive date n/a; ERP n/a.",
  ],
];

describe("v4 Insurance — compliant policy fixture", () => {
  it("emits no critical findings against the compliant policy fixture", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_POLICY), POLICY_PB);
    const run = await runEngine({ rules: INSURANCE_RULES, ctx, source_file: SRC });
    const criticals = run.findings.filter((f) => f.severity === "critical");
    expect(criticals.map((f) => f.rule_id)).toEqual([]);
  });

  it("is deterministic across runs", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_POLICY), POLICY_PB);
    const a = await runEngine({ rules: INSURANCE_RULES, ctx, source_file: SRC });
    const b = await runEngine({ rules: INSURANCE_RULES, ctx, source_file: SRC });
    expect(a.result_hash).toEqual(b.result_hash);
  });
});

describe("v4 Insurance — failure cases", () => {
  it("INS-003 fires when declarations omit limits", async () => {
    const ctx = withPb(
      buildContext([
        "Declarations",
        "Named Insured: Acme. Policy period: 2026-01-01 to 2027-01-01. Premium $25,000. Deductible $5,000.",
      ]),
      POLICY_PB,
    );
    const run = await runEngine({ rules: INSURANCE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "INS-003")).toBe(true);
  });

  it("INS-010 fires on absolute coverage-restricting endorsement", async () => {
    const ctx = withPb(
      buildContext([
        "Endorsement",
        "Form CG 21 67 12 04 (edition 12/04). This endorsement modifies coverage. Effective date: at policy inception. Absolute exclusion of communicable disease coverage applies.",
      ]),
      ENDORSEMENT_PB,
    );
    const run = await runEngine({ rules: INSURANCE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "INS-010")).toBe(true);
  });

  it("INS-015 fires on Type I broad-form indemnity", async () => {
    const ctx = withPb(
      buildContext([
        "Indemnification Agreement",
        "Indemnitor: Acme. Indemnitee: BigCo and its officers and agents. Indemnitor shall indemnify and hold harmless Indemnitee from any and all claims, including claims caused by indemnitee's sole negligence. Insurance: CGL with additional insured CG 20 10 and waiver of subrogation CG 24 04.",
      ]),
      IND_PB,
    );
    const run = await runEngine({ rules: INSURANCE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "INS-015")).toBe(true);
  });

  it("INS-022 fires on pre-dispute release of gross negligence", async () => {
    const ctx = withPb(
      buildContext([
        "Hold Harmless Agreement",
        "Acme shall be held harmless and released from any and all future claims, including those arising from gross negligence or willful misconduct, during the activity at the gym premises.",
      ]),
      HH_PB,
    );
    const run = await runEngine({ rules: INSURANCE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "INS-022")).toBe(true);
  });
});

describe("INS-015 — the canonical 'in whole or in part' broad-form indemnity (v1.1.0)", () => {
  const run1 = async (body: string) => {
    const ctx = withPb(buildContext(["Indemnity", body]), IND_PB);
    const run = await runEngine({ rules: INSURANCE_RULES, ctx, source_file: SRC });
    return new Set(run.findings.map((f) => f.rule_id));
  };

  it("fires on 'caused in whole or in part by the negligence of the Owner' (Type I)", async () => {
    expect(
      (
        await run1(
          "Contractor shall indemnify Owner from all liability caused in whole or in part by the negligence of the Owner.",
        )
      ).has("INS-015"),
    ).toBe(true);
  });

  it("stays silent on a Type III limited indemnity", async () => {
    expect(
      (
        await run1(
          "Subcontractor shall indemnify Owner only to the extent of Subcontractor's own negligence.",
        )
      ).has("INS-015"),
    ).toBe(false);
  });

  it("stays silent when a benign 'including [fees]' precedes a Type II carve-out", async () => {
    // The "including reasonable attorneys' fees" list plus the carve-out's
    // "own negligence" must not read as a broad-form grant.
    expect(
      (
        await run1(
          "Indemnitor shall indemnify Indemnitee from any and all claims, including reasonable attorneys' fees, except to the extent caused by the Indemnitee's own negligence.",
        )
      ).has("INS-015"),
    ).toBe(false);
  });

  it("stays silent on a self-declared Type II (comparative fault) indemnity", async () => {
    expect(
      (
        await run1(
          "This is a Type II (comparative fault) indemnity. Indemnitor shall indemnify Indemnitee, but excludes any claims caused by the sole negligence of the Indemnitee.",
        )
      ).has("INS-015"),
    ).toBe(false);
  });
});

describe("INS-012 — subrogation waiver reads 'waives rights of recovery' (v1.1.0)", () => {
  const END: Playbook = { id: "insurance-endorsement", version: "1.0.0" };
  const has = async (b: string) =>
    new Set(
      (
        await runEngine({
          rules: INSURANCE_RULES,
          ctx: withPb(buildContext(["Endorsement", b]), END),
          source_file: SRC,
        })
      ).findings.map((f) => f.rule_id),
    );
  it("does not fire when the waiver is stated as 'waives its rights of recovery'", async () => {
    expect(
      (await has("Each party waives its rights of recovery against the other party.")).has(
        "INS-012",
      ),
    ).toBe(false);
  });
});

describe("INS-010 — coverage-restricting endorsement detection (v1.1.0)", () => {
  const END: Playbook = { id: "insurance-endorsement", version: "1.0.0" };
  const fires = async (b: string) =>
    (
      await runEngine({
        rules: INSURANCE_RULES,
        ctx: withPb(buildContext(["Endorsement", b]), END),
        source_file: SRC,
      })
    ).findings.some((f) => f.rule_id === "INS-010");

  it.each([
    "Exclusion of Communicable Disease. We will not pay for any loss arising from a communicable disease.",
    "A sublimit of $25,000 applies to all cyber claims.",
    "The policy is amended to add an Asbestos Exclusion; we will not pay for any claim arising out of asbestos.",
    "Pollution Exclusion. This endorsement adds an absolute pollution exclusion.",
  ])("fires on a titled exclusion / dollar sublimit: %s", async (b) => {
    expect(await fires(b)).toBe(true);
  });

  it.each([
    "This endorsement does not exclude pollution; coverage is preserved.",
    "This policy contains no asbestos exclusion.",
    "A general aggregate limit of $2,000,000 applies to this coverage part.",
    "The sublimit for this coverage is $5,000,000 per occurrence.",
  ])("stays silent on preserved coverage / million-dollar sublimit: %s", async (b) => {
    expect(await fires(b)).toBe(false);
  });
});

describe("INS-022 — release overreach recognizes 'waive' verb (v1.1.0)", () => {
  const HH: Playbook = { id: "hold-harmless-agreement", version: "1.0.0" };
  const fires = async (b: string) =>
    (
      await runEngine({
        rules: INSURANCE_RULES,
        ctx: withPb(buildContext(["Hold Harmless", b]), HH),
        source_file: SRC,
      })
    ).findings.some((f) => f.rule_id === "INS-022");

  it.each([
    "Releasor waives all claims, including those for the Operator's gross negligence.",
    "The undersigned waives any and all future claims against the facility.",
  ])("fires on a waiver-verb overreach: %s", async (b) => {
    expect(await fires(b)).toBe(true);
  });

  it.each([
    "Participant waives claims for ordinary negligence. Nothing herein waives liability for gross negligence or willful misconduct.",
    "Releasor waives claims except for the Operator's gross negligence or willful misconduct.",
    "The waiver does not extend to intentional misconduct.",
  ])("stays silent on a carve-out for gross negligence / intentional acts: %s", async (b) => {
    expect(await fires(b)).toBe(false);
  });
});

describe("INS-015 / INS-022 — bare and fronted negation (v1.3.0 / v1.2.0)", () => {
  const IND: Playbook = { id: "indemnification-agreement", version: "1.0.0" };
  const HH: Playbook = { id: "hold-harmless-agreement", version: "1.0.0" };
  const fires = async (id: string, pb: Playbook, b: string) =>
    (
      await runEngine({
        rules: INSURANCE_RULES,
        ctx: withPb(buildContext(["Agreement", b]), pb),
        source_file: SRC,
      })
    ).findings.some((f) => f.rule_id === id);

  it("INS-015 stays silent on a refusal to indemnify with no 'obligated to' filler", async () => {
    // Every v1.2.0 guard required "not be obligated / required / liable to
    // indemnify", so the blunt refusal tripped the "in whole or in part"
    // pattern and was reported as the broad-form grant it declines.
    expect(
      await fires(
        "INS-015",
        IND,
        "Indemnitor shall not indemnify Owner for loss caused in whole or in part by Owner's own negligence.",
      ),
    ).toBe(false);
  });

  it("INS-015 still fires on the same clause without the negation", async () => {
    expect(
      await fires(
        "INS-015",
        IND,
        "Indemnitor shall indemnify Owner for loss caused in whole or in part by Owner's own negligence.",
      ),
    ).toBe(true);
  });

  it("INS-022 stays silent on a fronted 'No waiver of …' disclaimer", async () => {
    expect(
      await fires(
        "INS-022",
        HH,
        "No waiver of claims arising from gross negligence is intended by this agreement.",
      ),
    ).toBe(false);
  });
});

/**
 * INS-012 used to read an express refusal of the waiver as compliance: its
 * "waive … rights of recovery" pattern matched inside a negated sentence, and
 * a single present-pattern match short-circuits a presence rule. So an
 * endorsement stating the insurer KEEPS its subrogation rights — the exact
 * condition the rule exists to surface — scored clean, while a document merely
 * silent on the topic fired. Same express-denial class fixed across the other
 * v4 packs; this rule had been missed.
 */
describe("INS-012 — express denial of the subrogation waiver", () => {
  const run = async (text: string) => {
    const ctx = buildContext(["Endorsement", text]);
    const res = await runEngine({
      rules: INSURANCE_RULES,
      ctx: withPb(ctx, ENDORSEMENT_PB),
      source_file: SRC,
    });
    return res.findings.filter((f) => f.rule_id === "INS-012").map((f) => f.title);
  };

  it.each([
    [
      "shall not waive",
      "Contractor's insurer shall not waive its rights of recovery against Owner.",
    ],
    ["no waiver of", "No waiver of subrogation is granted under this endorsement."],
    [
      "reserves subrogation",
      "The insurer reserves all rights of subrogation against any responsible third party.",
    ],
    ["retains recovery", "The company retains its rights of recovery against the Owner."],
  ])("%s is reported as a denial, not as compliance", async (_form, text) => {
    expect(await run(text)).toEqual(["Waiver of subrogation expressly denied"]);
  });

  it("mere silence still reports the endorsement as missing", async () => {
    expect(
      await run(
        "This endorsement modifies coverage under the commercial general liability policy.",
      ),
    ).toEqual(["Waiver-of-subrogation endorsement missing"]);
  });

  it.each([
    [
      "waives rights of recovery",
      "The insurer waives its rights of recovery against the Owner under CG 24 04.",
    ],
    [
      "waiver of subrogation",
      "A waiver of subrogation in favor of the Owner is included per CG 24 04.",
    ],
    [
      "transfer of rights",
      "This endorsement addresses transfer of rights of recovery against others to us.",
    ],
  ])("%s stays silent (the compliant drafting must not be accused)", async (_form, text) => {
    expect(await run(text)).toEqual([]);
  });
});

describe("INS-017 — the settlement-consent clause as drafters write it", () => {
  /**
   * The third pillar wanted the NOUN PHRASE "consent to settle" or "right to
   * control", and no drafter writes either. The clause is written as an
   * operative prohibition — "shall not settle any Proceeding … without the
   * other party's prior written consent" — or as the mirror election, "is
   * entitled to assume the defense". A document carrying the strongest
   * settlement-consent provision available was told it established no
   * procedure at all.
   */
  const ins017 = INSURANCE_RULES.find((r) => r.id === "INS-017")!;
  const doc = (...paras: string[]) =>
    withPb(buildContext(["Indemnification Agreement", ...paras]), IND_PB);

  it("is silent on a complete procedure written operatively", () => {
    expect(
      ins017.check(
        doc(
          "Indemnitee shall notify the Company in writing of any Proceeding as soon as reasonably practicable.",
          "Indemnitee shall cooperate with the Company in the defense of any Proceeding.",
          "The Company shall not settle any Proceeding in a manner that imposes any liability on Indemnitee without Indemnitee's prior written consent.",
        ),
      ),
    ).toBeNull();
    expect(
      ins017.check(
        doc(
          "The Indemnitee shall give prompt written notice and tender the claim.",
          "The parties shall cooperate in the defense.",
          "The Indemnitor is entitled to assume the defense with counsel reasonably satisfactory to the Indemnitee.",
        ),
      ),
    ).toBeNull();
  });

  it("still fires when the procedure states no settlement or defense mechanics", () => {
    expect(
      ins017.check(
        doc(
          "Indemnitee shall give the Company notice of any Proceeding and shall cooperate in good faith.",
        ),
      ),
    ).not.toBeNull();
  });
});
