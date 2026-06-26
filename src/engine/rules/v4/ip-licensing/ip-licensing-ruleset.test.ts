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
