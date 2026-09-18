/**
 * A rule whose description states a precondition must TEST it.
 *
 * "Where international transfers occur, the DPA must name a Chapter V
 * mechanism." A presence rule reports an ABSENCE, so if it never checks the
 * "where", it accuses every document that lacks the clause — including every
 * document the clause does not belong in. The class was closed once for
 * TRANSFER-018 (9.637.0) and found again eleven times: MSA-016 told a services
 * MSA to add an uptime SLA; MSA-030 asked for an exclusive-remedy escape in
 * MSAs that state no exclusive remedy; DPA-032 told a DPA with no international
 * transfer, at CRITICAL, that it names no Chapter V mechanism; EMP-025 reported
 * a missing non-compete DURATION in agreements with no non-compete.
 *
 * So: a rule whose description opens with "Where", "When" or "If" is either
 * gated (its builder recorded an `applicable_if` / `when`) or listed below with
 * the reason it need not be. A new conditional rule cannot ship ungated
 * without someone writing that reason down.
 */
import { describe, expect, it } from "vitest";
import { LAUNCH_RULES } from "../../src/engine/rules/index.js";
import { V3_RULES } from "../../src/engine/rules/v3/index.js";
import { V4_RULES } from "../../src/engine/rules/v4/index.js";
import { V5_RULES } from "../../src/engine/rules/v5/index.js";
import { V6_RULES } from "../../src/engine/rules/v6/index.js";
import { V3_GATED_PRESENCE_RULE_IDS } from "../../src/engine/rules/v3/_regulated-rule.js";
import { V4_GATED_PRESENCE_RULE_IDS } from "../../src/engine/rules/v4/_helpers.js";
import { GATED_PACK_RULE_IDS } from "../../src/engine/rules/v5/_pack.js";

/** Conditional rules that are correct without a gate, and why. */
const REVIEWED: Record<string, string> = {
  "STRUCT-019":
    "custom reconciliation: fires only when the document itself recites notarization or witnessing",
  "NDA-D-020": "a language rule: its match IS the non-solicitation clause the condition names",
  "DPA-016":
    "Art. 28(3)(d) requires every DPA to state its Art. 28(2) conditions; the rule stands down for prior specific authorisation (9.637.0), and a DPA silent on sub-processors must still answer it",
  "DPA-031":
    "whether Art. 37 requires a DPO turns on the controller's activities, which no DPA states; a warning to check",
  "EMP-109": "'When a commission is earned' names the topic, not a condition",
  "PRV-026":
    "a DPIA must record its residual-risk conclusion either way; any residual-risk or prior-consultation statement satisfies it",
  "HC-022":
    "an acknowledgment form must provide for the case where acknowledgment is not obtained (45 C.F.R. § 164.520(c)(2)(ii))",
  "INS-012":
    "what the underlying contract requires is not in the endorsement; the finding is phrased as the question to ask",
};

const rules = [...LAUNCH_RULES, ...V3_RULES, ...V4_RULES, ...V5_RULES, ...V6_RULES];
const gated = (id: string): boolean =>
  V3_GATED_PRESENCE_RULE_IDS.has(id) ||
  V4_GATED_PRESENCE_RULE_IDS.has(id) ||
  GATED_PACK_RULE_IDS.has(id);
const conditional = rules.filter((r) => /^(?:where|when|if)\b/i.test(r.description));

describe("stated preconditions", () => {
  it("finds the conditional rules (guards the filter itself)", () => {
    expect(conditional.length).toBeGreaterThan(15);
    expect(conditional.map((r) => r.id)).toContain("DPA-032");
  });

  it("every conditional rule tests its condition, or says why it need not", () => {
    const open = conditional.filter((r) => !gated(r.id) && !(r.id in REVIEWED));
    expect(
      open.map((r) => `${r.id}: ${r.description}`),
      "gate these with applicable_if, or add a reviewed reason",
    ).toEqual([]);
  });

  it("the reviewed list names only rules that still need it", () => {
    const ids = new Set(conditional.map((r) => r.id));
    const stale = Object.keys(REVIEWED).filter((id) => !ids.has(id) || gated(id));
    expect(stale, "remove these from REVIEWED").toEqual([]);
  });
});
