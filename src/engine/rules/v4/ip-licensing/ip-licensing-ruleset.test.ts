import { describe, expect, it } from "vitest";

import { IP_LICENSING_RULES } from "./rules.js";
import { IPL_PLAYBOOK_IDS } from "./_helpers.js";
import { buildContext } from "../../../_test-fixtures.js";
import { runEngine } from "../../../runner.js";
import type { Playbook, RuleContext } from "../../../finding.js";

const ASSIGN_PB: Playbook = { id: "ip-assignment", version: "1.0.0" };
const PATENT_PB: Playbook = { id: "patent-license", version: "1.0.0" };
const TM_PB: Playbook = { id: "trademark-license", version: "1.0.0" };
const COPY_PB: Playbook = { id: "copyright-license", version: "1.0.0" };
const CLA_PB: Playbook = { id: "contributor-license-agreement", version: "1.0.0" };
const OSS_PB: Playbook = { id: "oss-compliance", version: "1.0.0" };
const WFH_PB: Playbook = { id: "work-for-hire-agreement", version: "1.0.0" };

const SRC = { name: "test.docx", sha256: "0".repeat(64), size_bytes: 100 };

function withPb(ctx: RuleContext, pb: Playbook): RuleContext {
  return { ...ctx, playbook: pb };
}

describe("v4 IP & licensing ruleset — registry contract", () => {
  it("exports exactly 40 rules with stable IPL-NNN ids", () => {
    expect(IP_LICENSING_RULES.length).toBe(40);
    const ids = IP_LICENSING_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(40);
    for (const r of IP_LICENSING_RULES) {
      expect(r.id, r.id).toMatch(/^IPL-\d{3}$/);
      expect(r.version, r.id).toMatch(/^\d+\.\d+\.\d+$/);
      expect(r.category, r.id).toBe("ip-licensing");
      expect(r.applies_to_playbooks, r.id).toBeDefined();
    }
  });

  it("scopes every rule to one or more ip-licensing playbooks", () => {
    const allowed = new Set<string>(IPL_PLAYBOOK_IDS);
    for (const r of IP_LICENSING_RULES) {
      for (const pb of r.applies_to_playbooks ?? []) {
        expect(allowed.has(pb), `${r.id} → ${pb}`).toBe(true);
      }
    }
  });

  it("does not fire under a non-ip-licensing playbook", async () => {
    const ctx = buildContext(["Some other doc", "No IP content."]);
    const run = await runEngine({ rules: IP_LICENSING_RULES, ctx, source_file: SRC });
    expect(run.findings.length).toBe(0);
    expect(run.execution_log.every((e) => !e.fired)).toBe(true);
  });
});

const COMPLIANT_ASSIGNMENT: [string, ...string[]][] = [
  [
    "IP Assignment Agreement",
    "Assignor and Assignee are the parties hereto. Assigned IP: U.S. Patent No. 8,000,000; trademark Reg. No. 5,000,000. Right to Sue for past, present, and future infringement is assigned. Further Assurances: Assignor will cooperate with USPTO recordation. Power of Attorney granted to Assignee. Representations and Warranties: Assignor owns the IP, no prior conveyance, free of encumbrances and liens.",
  ],
];

describe("v4 IP & licensing — compliant assignment fixture", () => {
  it("emits no critical findings against the compliant fixture", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_ASSIGNMENT), ASSIGN_PB);
    const run = await runEngine({ rules: IP_LICENSING_RULES, ctx, source_file: SRC });
    const criticals = run.findings.filter((f) => f.severity === "critical");
    expect(criticals.map((f) => f.rule_id)).toEqual([]);
  });

  it("is deterministic across runs", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_ASSIGNMENT), ASSIGN_PB);
    const a = await runEngine({ rules: IP_LICENSING_RULES, ctx, source_file: SRC });
    const b = await runEngine({ rules: IP_LICENSING_RULES, ctx, source_file: SRC });
    expect(a.result_hash).toEqual(b.result_hash);
  });
});

describe("v4 IP & licensing — failure cases", () => {
  it("IPL-001 fires when assignment omits parties", async () => {
    const ctx = withPb(
      buildContext(["Assignment", "All rights are conveyed. Patent No. 8,000,000 transfers."]),
      ASSIGN_PB,
    );
    const run = await runEngine({ rules: IP_LICENSING_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "IPL-001")).toBe(true);
  });

  it("IPL-009 fires on royalty extending beyond patent expiration", async () => {
    const ctx = withPb(
      buildContext([
        "Patent License",
        "Licensed Patents: U.S. Pat. No. 8,000,000. Exclusive worldwide license, sublicensable. Royalties continue after expiration of the licensed patent in perpetuity at 5% of Net Sales.",
      ]),
      PATENT_PB,
    );
    const run = await runEngine({ rules: IP_LICENSING_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "IPL-009")).toBe(true);
  });

  it("IPL-011 does not falsely fire when marking uses 'the applicable patent numbers'", async () => {
    // Regression: "mark … with the APPLICABLE patent numbers" (adjective before
    // "patent") slipped past the old bare-article pattern and drew a false
    // "Patent-marking clause missing" warning.
    const ctx = withPb(
      buildContext([
        "Patent License",
        "Licensed Patents: U.S. Pat. No. 8,000,000. Licensee shall mark the Licensed Products with the applicable patent numbers.",
      ]),
      PATENT_PB,
    );
    const run = await runEngine({ rules: IP_LICENSING_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "IPL-011")).toBe(false);
  });

  it("IPL-011 still fires when a patent license omits any marking clause", async () => {
    const ctx = withPb(
      buildContext([
        "Patent License",
        "Licensed Patents: U.S. Pat. No. 8,000,000. Exclusive worldwide license. Royalty 5% of Net Sales, stepping down after expiration.",
      ]),
      PATENT_PB,
    );
    const run = await runEngine({ rules: IP_LICENSING_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "IPL-011")).toBe(true);
  });

  it("IPL-014 fires when trademark license omits quality control", async () => {
    const ctx = withPb(
      buildContext([
        "Trademark License",
        "Licensed Marks: ACME® (Reg. No. 5,000,000). Territory: US. Channels of trade: retail. Field of use: footwear.",
      ]),
      TM_PB,
    );
    const run = await runEngine({ rules: IP_LICENSING_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "IPL-014")).toBe(true);
  });

  it("IPL-020 fires when copyright license omits exclusivity / writing", async () => {
    const ctx = withPb(
      buildContext([
        "Copyright License",
        "Licensed Works: 'My Book' (Reg. No. TX 1234567). Rights granted: reproduction and distribution under section 106. Term: 5 years. Territory: US. Media: print.",
      ]),
      COPY_PB,
    );
    const run = await runEngine({ rules: IP_LICENSING_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "IPL-020")).toBe(true);
  });

  it("IPL-032 fires when OSS compliance does not address GPL / AGPL source", async () => {
    const ctx = withPb(
      buildContext([
        "OSS Compliance",
        "Third-party software inventory: lodash MIT; libfoo Apache-2.0; libbar BSD-3-Clause. Components are tracked in SBOM (SPDX). NOTICE file generated automatically.",
      ]),
      OSS_PB,
    );
    const run = await runEngine({ rules: IP_LICENSING_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "IPL-032")).toBe(true);
  });

  it("IPL-036 fires when WFH omits § 101 specially-commissioned recital", async () => {
    const ctx = withPb(
      buildContext([
        "Contractor Engagement",
        "Contractor will deliver some Work Product to Client. Independent contractor relationship; contractor pays taxes and receives no benefits. DTSA notice attached. To the extent any portion fails to qualify, contractor hereby assigns all rights.",
      ]),
      WFH_PB,
    );
    const run = await runEngine({ rules: IP_LICENSING_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "IPL-036")).toBe(true);
  });

  it("IPL-027 fires when CLA omits patent license / defensive termination", async () => {
    const ctx = withPb(
      buildContext([
        "Contributor License Agreement",
        "You, the individual Contributor, grant a perpetual, worldwide, royalty-free copyright license to reproduce, distribute, and sublicense your contributions. You represent the contribution is your original creation.",
      ]),
      CLA_PB,
    );
    const run = await runEngine({ rules: IP_LICENSING_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "IPL-027")).toBe(true);
  });
});

describe("IPL-038 — a denied DTSA notice is absence, not presence (v1.1.0)", () => {
  const run1 = async (body: string) => {
    const ctx = withPb(buildContext(["IP", body]), WFH_PB);
    const run = await runEngine({ rules: IP_LICENSING_RULES, ctx, source_file: SRC });
    return new Set(run.findings.map((f) => f.rule_id));
  };
  it("fires when the agreement denies whistleblower immunity", async () => {
    expect((await run1("This Agreement includes no whistleblower immunity.")).has("IPL-038")).toBe(
      true,
    );
  });
  it("is silent on a genuine DTSA § 1833(b) immunity notice", async () => {
    expect(
      (
        await run1(
          "Pursuant to the Defend Trade Secrets Act, Contributor is provided immunity for whistleblower disclosures made in confidence to a government official.",
        )
      ).has("IPL-038"),
    ).toBe(false);
  });
});

describe("IPL-009 — Kimble-compliant post-expiration royalty structures (v1.1.0)", () => {
  const PATENT_PB_LOCAL: Playbook = { id: "patent-license", version: "1.0.0" };
  const run1 = async (body: string) => {
    const ctx = withPb(buildContext(["Royalties", body]), PATENT_PB_LOCAL);
    const run = await runEngine({ rules: IP_LICENSING_RULES, ctx, source_file: SRC });
    return new Set(run.findings.map((f) => f.rule_id));
  };

  // Kimble expressly permits post-expiration royalties structured as a
  // step-down, an allocation to non-patent rights, or an amortized lump sum —
  // exactly the workarounds this rule's own recommendation endorses. Flagging
  // them is a false positive.
  it("stays silent on a step-down to a reduced know-how rate", async () => {
    expect(
      (
        await run1(
          "Royalties shall continue after patent expiration at a reduced rate of 2% reflecting the licensed know-how.",
        )
      ).has("IPL-009"),
    ).toBe(false);
  });

  it("stays silent on royalties expressly allocated to know-how / trade secrets", async () => {
    expect(
      (
        await run1(
          "Post-expiration royalties are attributable to the retained know-how and trade secrets and accrue separately.",
        )
      ).has("IPL-009"),
    ).toBe(false);
  });

  it("stays silent on an amortized lump sum spanning the patent term", async () => {
    expect(
      (
        await run1(
          "The lump-sum consideration is amortized as royalties over 20 years, notwithstanding expiration of the patent.",
        )
      ).has("IPL-009"),
    ).toBe(false);
  });

  it("still fires on a flat patent + know-how rate with no step-down (classic Brulotte)", async () => {
    expect(
      (
        await run1(
          "Royalties for the patent and know-how continue after expiration of the patent at the same 5% rate.",
        )
      ).has("IPL-009"),
    ).toBe(true);
  });
});

describe("IPL-012 — grant-back reads the 'license back' synonym (v1.1.0)", () => {
  const PB: Playbook = { id: "patent-license", version: "1.0.0" };
  const has = async (b: string) =>
    new Set(
      (
        await runEngine({
          rules: IP_LICENSING_RULES,
          ctx: withPb(buildContext(["Patent License", b]), PB),
          source_file: SRC,
        })
      ).findings.map((f) => f.rule_id),
    );
  it("does not fire when improvements are 'licensed back'", async () => {
    expect(
      (
        await has(
          "All improvements developed by Licensee shall be licensed back to Licensor royalty-free.",
        )
      ).has("IPL-012"),
    ).toBe(false);
  });
});

describe("IPL-009 — Brulotte royalty detection recognizes reversed & 'survive' forms (v1.2.0)", () => {
  const PATENT: Playbook = { id: "patent-license", version: "1.0.0" };
  const fires = async (b: string) =>
    (
      await runEngine({
        rules: IP_LICENSING_RULES,
        ctx: withPb(buildContext(["Patent License", b]), PATENT),
        source_file: SRC,
      })
    ).findings.some((f) => f.rule_id === "IPL-009");

  it.each([
    "Royalties shall continue after the expiration of the patent.",
    "Licensee shall pay royalties in perpetuity.",
    "The obligation to pay royalties survives expiration of the licensed patents.",
  ])("fires on royalties running past patent expiration: %s", async (b) => {
    expect(await fires(b)).toBe(true);
  });

  it.each([
    "Royalties shall not survive expiration of the licensed patent.",
    "Royalties shall not be perpetual and terminate upon patent expiration.",
    "Reduced royalties allocated to know-how shall survive expiration of the patent.",
  ])("stays silent on a compliant / hybrid-license royalty: %s", async (b) => {
    expect(await fires(b)).toBe(false);
  });
});

describe("IPL-009 — the Brulotte-compliant step-down (v1.3.0)", () => {
  const PB: Playbook = { id: "patent-license", version: "1.0.0" };
  const fires = async (b: string) =>
    (
      await runEngine({
        rules: IP_LICENSING_RULES,
        ctx: { ...buildContext(["License", b]), playbook: PB },
        source_file: SRC,
      })
    ).findings.some((f) => f.rule_id === "IPL-009");

  it("stays silent when royalties are barred after expiration", async () => {
    // The guard listed "payable / owed / due / owing" but not "paid", so the
    // textbook compliant clause was reported as the Brulotte violation.
    expect(
      await fires("Royalties shall not be paid after expiration of the Licensed Patents."),
    ).toBe(false);
  });

  it("still fires on a royalty that outlives the patent", async () => {
    expect(
      await fires(
        "Royalties shall be paid for twenty years after expiration of the Licensed Patents.",
      ),
    ).toBe(true);
  });
});

/**
 * Third instance of the INS-012 / CON-030 express-denial trap. IPL-005's
 * appoint/authorize pattern also matches inside a sentence that REFUSES the
 * appointment, and one present-pattern match short-circuits a presence rule —
 * so an assignment expressly withholding the power of attorney (leaving the
 * assignee unable to record or prosecute the IP it just bought) scored clean,
 * while one merely silent on the point fired.
 */
describe("IPL-005 — express denial of the power of attorney", () => {
  const run = async (text: string) => {
    const ctx = buildContext(["Assignment", text]);
    const res = await runEngine({
      rules: IP_LICENSING_RULES,
      ctx: withPb(ctx, ASSIGN_PB),
      source_file: SRC,
    });
    return res.findings.filter((f) => f.rule_id === "IPL-005").map((f) => f.title);
  };

  it.each([
    [
      "does not appoint",
      "Assignor does not appoint Assignee as attorney-in-fact for any IP-office filing.",
    ],
    ["no power of attorney", "No power of attorney is granted under this Assignment."],
    [
      "nothing creates",
      "Nothing in this Assignment creates a power of attorney in favor of Assignee.",
    ],
  ])("%s is reported as a denial, not as compliance", async (_form, text) => {
    expect(await run(text)).toEqual(["Power of attorney expressly withheld"]);
  });

  it("mere silence still reports the clause as missing", async () => {
    expect(
      await run(
        "Assignor hereby assigns all right, title and interest in the Patents to Assignee.",
      ),
    ).toEqual(["POA clause missing"]);
  });

  it("the compliant appointment stays silent", async () => {
    expect(
      await run(
        "Assignor irrevocably appoints Assignee as its attorney-in-fact to execute IP-office filings, and grants a power of attorney for that purpose.",
      ),
    ).toEqual([]);
  });
});

/**
 * Express-denial guards for the two CLA grant rules. "Contributor grants NO
 * copyright license" contains the very phrase the rule looks for, and one
 * present-pattern match short-circuits a presence rule — so a CLA that grants
 * nothing scored clean while a CLA merely silent on the grant fired. A CLA
 * without the grant defeats its purpose: the project cannot ship the
 * contribution, and downstream users stay exposed to the contributor's patents.
 */
describe("IPL-026 / IPL-027 — CLA grants expressly withheld", () => {
  const run = async (id: string, text: string) => {
    const res = await runEngine({
      rules: IP_LICENSING_RULES,
      ctx: withPb(buildContext(["Contribution", text]), CLA_PB),
      source_file: SRC,
    });
    return res.findings.filter((f) => f.rule_id === id).map((f) => f.title);
  };

  it.each([
    [
      "IPL-026",
      "Contributor grants no copyright license to the Project, and no perpetual or royalty-free rights are conveyed.",
      "Copyright license grant expressly withheld",
    ],
    [
      "IPL-026",
      "No copyright license is granted under this Agreement, whether perpetual or royalty-free.",
      "Copyright license grant expressly withheld",
    ],
    [
      "IPL-027",
      "No patent license is granted by Contributor, and defensive termination does not apply to any patent litigation.",
      "Patent license grant expressly withheld",
    ],
  ])("%s reports a withheld grant as a denial", async (id, text, title) => {
    expect(await run(id, text)).toEqual([title]);
  });

  it.each([
    ["IPL-026", "Copyright license grant clause missing"],
    ["IPL-027", "Patent license / defensive termination clause missing"],
  ])("%s still reports the clause missing on silence", async (id, title) => {
    expect(await run(id, "Contributor submits the Contribution to the Project.")).toEqual([title]);
  });

  it.each([
    [
      "IPL-026",
      "Contributor grants a perpetual, worldwide, royalty-free copyright license to the Project.",
    ],
    [
      "IPL-027",
      "Contributor grants a patent license to the Project, subject to defensive termination upon patent litigation.",
    ],
  ])("%s stays silent on the compliant grant", async (id, text) => {
    expect(await run(id, text)).toEqual([]);
  });
});

/**
 * Express-denial guard for the grant-back rule: "No grant-back license is
 * granted" contains the phrasing IPL-012 looks for, so a licence expressly
 * refusing the grant-back — locking the licensor out of improvements to its
 * own technology — scored clean.
 */
describe("IPL-012 — grant-back expressly refused", () => {
  const run = async (text: string) => {
    const res = await runEngine({
      rules: IP_LICENSING_RULES,
      // Heading must be neutral: "Improvements" alone satisfies the rule's
      // first present_pattern, which would make the omission case unfireable.
      ctx: withPb(buildContext(["Terms", text]), PATENT_PB),
      source_file: SRC,
    });
    return res.findings.filter((f) => f.rule_id === "IPL-012").map((f) => f.title);
  };

  it("reports a refused grant-back as a denial", async () => {
    expect(
      await run("No grant-back license to improvements is granted under this Agreement."),
    ).toEqual(["Grant-back expressly refused"]);
  });

  it("still reports the clause missing on silence", async () => {
    expect(await run("Licensor grants a license under the Licensed Patents.")).toEqual([
      "Improvements / grant-back clause missing",
    ]);
  });

  it("stays silent on the compliant grant-back", async () => {
    expect(
      await run(
        "Licensee grants a non-exclusive royalty-free grant-back license to improvements and enhancements.",
      ),
    ).toEqual([]);
  });
});

/**
 * IPL-037's "to the extent … not a work for hire" framing appears in a refusal
 * too, so a contract declining the backup assignment scored clean. That refusal
 * is the whole failure mode: work-for-hire is unavailable for most commissioned
 * work under 17 U.S.C. § 101, so without the backup assignment the client can
 * end up owning nothing it paid for.
 */
describe("IPL-037 — backup assignment expressly refused", () => {
  const run = async (text: string) => {
    const res = await runEngine({
      rules: IP_LICENSING_RULES,
      ctx: withPb(buildContext(["Terms", text]), WFH_PB),
      source_file: SRC,
    });
    return res.findings.filter((f) => f.rule_id === "IPL-037").map((f) => f.title);
  };

  it("reports a refused backup assignment as a denial", async () => {
    expect(
      await run(
        "To the extent the deliverable is not a work for hire, Contractor does not assign it to Company.",
      ),
    ).toEqual(["Backup assignment expressly refused"]);
  });

  it("still reports the clause missing on silence", async () => {
    expect(await run("Contractor shall deliver the artwork by March 1.")).toEqual([
      "Backup-assignment clause missing",
    ]);
  });

  it("stays silent on the compliant backup assignment", async () => {
    expect(
      await run(
        "To the extent any deliverable is not a work for hire, Contractor hereby assigns all right, title and interest to Company.",
      ),
    ).toEqual([]);
  });
});

/**
 * IPL-028: a disclaimer names the same concepts the representation does
 * ("makes NO representation that the Contribution is an original work"), so a
 * CLA giving the project no assurance of provenance scored clean.
 */
describe("IPL-028 — original-work representation expressly disclaimed", () => {
  const run = async (text: string) => {
    const res = await runEngine({
      rules: IP_LICENSING_RULES,
      ctx: withPb(buildContext(["Terms", text]), CLA_PB),
      source_file: SRC,
    });
    return res.findings.filter((f) => f.rule_id === "IPL-028").map((f) => f.title);
  };

  it("reports a disclaimed representation as a denial", async () => {
    expect(
      await run(
        "Contributor makes no representation that the Contribution is an original work or that it has the right to grant the license.",
      ),
    ).toEqual(["Original-work representation expressly disclaimed"]);
  });

  it("still reports the clause missing on silence", async () => {
    expect(await run("Contributor submits the Contribution to the Project.")).toEqual([
      "Original-work representation clause missing",
    ]);
  });

  it("stays silent on the compliant representation", async () => {
    expect(
      await run(
        "Contributor represents that the Contribution is an original creation and that it has the right to grant the license, free of third-party claims.",
      ),
    ).toEqual([]);
  });
});
