import { describe, expect, it } from "vitest";

import { NDA_DEEP_RULES } from "./rules.js";
import { buildContext } from "../../../_test-fixtures.js";
import { runEngine } from "../../../runner.js";
import type { Playbook, RuleContext } from "../../../finding.js";

const MUTUAL: Playbook = { id: "mutual-nda-deep", version: "1.0.0" };
const UNILATERAL: Playbook = { id: "unilateral-nda-deep", version: "1.0.0" };

function withPb(ctx: RuleContext, pb: Playbook): RuleContext {
  return { ...ctx, playbook: pb };
}

/**
 * A near-fully-compliant mutual NDA fixture. Includes the DTSA notice
 * (three pillars: immunity, government, sealed filing), all four
 * Confidential-Information exclusions, definite term + perpetual trade
 * secret carve-out, attestation-of-destruction, injunctive relief with
 * bond waiver, viable governing law, and bilateral framing.
 */
const COMPLIANT_MUTUAL_SECTIONS: [string, ...string[]][] = [
  [
    "Mutual Non-Disclosure Agreement",
    "This Mutual Non-Disclosure Agreement is entered into by Acme Inc. and Globex LLC. Each party has full power and authority to enter into this Agreement and signing does not create any conflicting obligation with any other agreement.",
  ],
  [
    "1. Definitions",
    "\"Confidential Information\" means any non-public information disclosed by either party. \"Purpose\" means evaluating a potential business relationship between the parties. Confidential Information does not include information that (a) is or becomes generally available to the public other than as a result of a breach; (b) was already known to the receiving party prior to disclosure; (c) was received from a third party without breach of any obligation of confidentiality; or (d) was independently developed by the receiving party without reference to the Confidential Information.",
  ],
  [
    "2. Permitted Use",
    "Each party shall use the other party's Confidential Information solely for the Purpose. No license is granted to either party in or to the Confidential Information except as expressly set forth in this Agreement.",
  ],
  [
    "3. Term",
    "The obligations of confidentiality shall continue for a period of five (5) years from the date of disclosure. With respect to trade secrets, the obligations of confidentiality shall continue for as long as the information qualifies as a trade secret under applicable law.",
  ],
  [
    "4. Return or Destruction",
    "Upon termination or written request, each party shall return or destroy all Confidential Information of the other party and shall provide a written certification, signed by an officer, attesting to such destruction within thirty (30) days.",
  ],
  [
    "5. Equitable Relief",
    "The parties acknowledge that breach would cause irreparable harm and that the non-breaching party shall be entitled to seek injunctive and other equitable relief, without the need to post a bond or other security, in addition to any other available remedies.",
  ],
  [
    "6. Non-Solicitation",
    "Each party agrees that it shall not solicit employees of the other party for twelve (12) months; provided that nothing in this clause shall restrict general solicitations of employment not specifically directed at employees of the other party.",
  ],
  [
    "7. DTSA Notice",
    "Pursuant to 18 U.S.C. § 1833(b), each party is hereby notified that an individual shall not be held criminally or civilly liable under any federal or state trade secret law for the disclosure of a trade secret that is made (i) in confidence to a federal, state, or local government official, either directly or indirectly, or to an attorney; and (ii) solely for the purpose of reporting or investigating a suspected violation of law; or (iii) in a complaint or other document filed in a lawsuit or other proceeding, if such filing is made under seal.",
  ],
  [
    "8. Miscellaneous",
    "This Agreement shall be governed by the laws of the State of Delaware. Each party may not assign this Agreement without the prior written consent of the other party; this Agreement shall bind and inure to the benefit of the parties and their successors and assigns. This Agreement is not intended to create a precedent for any future agreement.",
  ],
];

describe("NDA-deep ruleset — registry contract", () => {
  it("exports exactly 25 rules with stable NDA-D-NNN ids", () => {
    expect(NDA_DEEP_RULES.length).toBe(25);
    const ids = NDA_DEEP_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(25);
    for (const r of NDA_DEEP_RULES) {
      expect(r.id, r.id).toMatch(/^NDA-D-\d{3}$/);
      expect(r.version, r.id).toMatch(/^\d+\.\d+\.\d+$/);
      expect(r.category, r.id).toBe("nda");
      expect(r.applies_to_playbooks, r.id).toBeDefined();
    }
  });

  it("scopes to NDA-deep playbooks only", () => {
    const allowed = new Set(["mutual-nda-deep", "unilateral-nda-deep"]);
    for (const r of NDA_DEEP_RULES) {
      for (const pb of r.applies_to_playbooks ?? []) {
        expect(allowed.has(pb), `${r.id} → ${pb}`).toBe(true);
      }
    }
  });
});

describe("NDA-deep ruleset — compliant mutual NDA fixture", () => {
  it("emits no critical findings against the compliant fixture", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_MUTUAL_SECTIONS), MUTUAL);
    const run = await runEngine({
      rules: NDA_DEEP_RULES,
      ctx,
      source_file: { name: "nda.docx", sha256: "0".repeat(64), size_bytes: 100 },
    });
    const criticals = run.findings.filter((f) => f.severity === "critical");
    expect(criticals.map((f) => f.rule_id)).toEqual([]);
  });

  it("is deterministic across runs", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_MUTUAL_SECTIONS), MUTUAL);
    const sf = { name: "nda.docx", sha256: "0".repeat(64), size_bytes: 100 };
    const a = await runEngine({ rules: NDA_DEEP_RULES, ctx, source_file: sf });
    const b = await runEngine({ rules: NDA_DEEP_RULES, ctx, source_file: sf });
    expect(a.result_hash).toEqual(b.result_hash);
  });
});

describe("NDA-deep ruleset — failure cases", () => {
  it("NDA-D-001 fires when DTSA notice is absent", async () => {
    const ctx = withPb(
      buildContext(["NDA", "Standard mutual NDA without any DTSA notice text."]),
      MUTUAL,
    );
    const run = await runEngine({
      rules: NDA_DEEP_RULES,
      ctx,
      source_file: { name: "nda.docx", sha256: "0".repeat(64), size_bytes: 1 },
    });
    expect(run.findings.some((f) => f.rule_id === "NDA-D-001")).toBe(true);
  });

  it("NDA-D-011 fires on 'any business purpose' permitted use", async () => {
    const ctx = withPb(
      buildContext([
        "NDA",
        "Receiving Party may use Confidential Information for any business purpose at its discretion.",
      ]),
      MUTUAL,
    );
    const run = await runEngine({
      rules: NDA_DEEP_RULES,
      ctx,
      source_file: { name: "nda.docx", sha256: "0".repeat(64), size_bytes: 1 },
    });
    expect(run.findings.some((f) => f.rule_id === "NDA-D-011")).toBe(true);
  });

  it("rules do not fire when no NDA playbook is active", async () => {
    const ctx = buildContext([
      "Some other doc",
      "This document has no DTSA notice and no Confidential Information definition.",
    ]);
    const run = await runEngine({
      rules: NDA_DEEP_RULES,
      ctx,
      source_file: { name: "x.docx", sha256: "0".repeat(64), size_bytes: 1 },
    });
    expect(run.findings.length).toBe(0);
    expect(run.execution_log.every((e) => !e.fired)).toBe(true);
  });

  it("NDA-D-025 fires on a unilateral NDA missing role framing", async () => {
    const ctx = withPb(
      buildContext(["NDA", "Acme Inc. agrees not to disclose information of Globex LLC."]),
      UNILATERAL,
    );
    const run = await runEngine({
      rules: NDA_DEEP_RULES,
      ctx,
      source_file: { name: "nda.docx", sha256: "0".repeat(64), size_bytes: 1 },
    });
    expect(run.findings.some((f) => f.rule_id === "NDA-D-025")).toBe(true);
  });
});
