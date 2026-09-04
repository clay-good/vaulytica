import { describe, expect, it } from "vitest";
import { runEngine } from "../../runner.js";
import { buildContext } from "../../_test-fixtures.js";
import { V5_RULES } from "./index.js";
import type { Playbook, RuleContext } from "../../finding.js";

const DO_POLICY: Playbook = { id: "do-policy", version: "1.0.0" };
const withPb = (ctx: RuleContext, p: Playbook): RuleContext => ({ ...ctx, playbook: p });

/**
 * INS-103 promises, in its own name and its own fix text, to check that the
 * insured-versus-insured exclusion carries its standard CARVE-BACKS — "Without
 * carve-backs, the IvI exclusion defeats derivative suits, trustee claims in
 * bankruptcy, and whistleblower retaliation claims — exactly the claims D&O is
 * bought for."
 *
 * It did not check that. `pack()` builds a presence rule whose patterns are
 * satisfied by ANY match unless the spec sets `all: true`, and INS-103 did not
 * set it — so naming the exclusion satisfied the rule and the carve-back
 * pattern could never change the outcome. A critical-severity rule was silent
 * on the exact thing it exists to catch. `all: true` is used 83 times elsewhere
 * in the v5 packs and was used nowhere in the insurance pack.
 */
async function fires(id: string, text: string): Promise<boolean> {
  const run = await runEngine({
    rules: V5_RULES,
    ctx: withPb(
      buildContext(["Directors and Officers Liability Insurance Policy", text]),
      DO_POLICY,
    ),
    source_file: { name: "policy.docx", sha256: "0".repeat(64), size_bytes: 100 },
  });
  return run.findings.some((f) => f.rule_id === id);
}

const EXCLUSION =
  "Exclusion 4. Insured versus Insured. The Insurer shall not be liable for Loss on account of any Claim brought or maintained by or on behalf of any Insured.";

describe("INS-103 — the IvI exclusion and its carve-backs", () => {
  it("fires when the exclusion is stated with no carve-back at all", async () => {
    expect(await fires("INS-103", EXCLUSION)).toBe(true);
  });

  it("is silent when a carve-back names a derivative action", async () => {
    expect(
      await fires(
        "INS-103",
        `${EXCLUSION} This exclusion does not apply to a derivative action brought without the assistance of any Insured Person.`,
      ),
    ).toBe(false);
  });

  it("is silent when a carve-back names a bankruptcy trustee or a whistleblower", async () => {
    expect(
      await fires(
        "INS-103",
        `${EXCLUSION} This exclusion does not apply to a Claim brought by a bankruptcy trustee, or to a whistleblower Claim.`,
      ),
    ).toBe(false);
  });
});

/**
 * GOV-116 is the same defect found by the same reading: its name joins a topic
 * and a REQUIREMENT ("Adjournment and secretary signature"), its explanation is
 * "Unsigned, unapproved minutes are a draft", and its fix asks for the
 * secretary's signature block — yet recording the adjournment alone satisfied
 * it. Both pillars are now required.
 */
const MINUTES: Playbook = { id: "meeting-minutes", version: "1.0.0" };

async function firesOnMinutes(id: string, text: string): Promise<boolean> {
  const run = await runEngine({
    rules: V5_RULES,
    ctx: withPb(buildContext(["Minutes of the Meeting of the Board of Directors", text]), MINUTES),
    source_file: { name: "minutes.docx", sha256: "0".repeat(64), size_bytes: 100 },
  });
  return run.findings.some((f) => f.rule_id === id);
}

describe("GOV-116 — adjournment AND the secretary's signature", () => {
  it("fires on minutes that adjourn but carry no signature or approval", async () => {
    expect(
      await firesOnMinutes(
        "GOV-116",
        "There being no further business, the meeting was adjourned at 4:15 p.m.",
      ),
    ).toBe(true);
  });

  it("is silent when the secretary signs them", async () => {
    expect(
      await firesOnMinutes(
        "GOV-116",
        "There being no further business, the meeting was adjourned at 4:15 p.m. Respectfully submitted, Adaeze Whitfield-Moreau, Secretary.",
      ),
    ).toBe(false);
  });
});
