/**
 * The guard against over-suppression.
 *
 * A long campaign of false-positive fixes teaches every rule to stay quiet on
 * a clause that only LOOKS like a defect. The risk that campaign creates is the
 * opposite and worse error: a rule taught to ignore the compliant form that
 * also stops seeing the real one. A linter that misses a genuine defect is more
 * dangerous than one that over-reports, because silence reads as a clean bill.
 *
 * This document is adversarial by construction. Every clause in it is the
 * GENUINE version of something a guard elsewhere in the engine suppresses:
 *
 *   - a California settlement with no § 1542 waiver (SET-003's gate is
 *     satisfied — California law governs and the release covers unknown claims)
 *   - a settlement of a sexual-harassment charge with no § 162(q) recital
 *     (SET-010's nexus is present)
 *   - a one-sided, uncapped commercial indemnity (RISK-002, RISK-015 — not the
 *     statutory D&O or neutral-agent forms those rules learned to skip)
 *   - a real class-action waiver (DARK-005 — not "nothing herein waives")
 *   - a lowercase use of an expressly defined term (STRUCT-009 / STRUCT-014 —
 *     not a statutory idiom, entity type, or parenthetical noun)
 *   - a dangling internal cross-reference (STRUCT-007 — not a statutory cite,
 *     an ARTICLE heading, or another instrument's numbering)
 *   - a genuine cross-border transfer with no Article 46 safeguard (IPDATA-008
 *     — not "no transfers occur")
 *   - a truly unidentified obligor and a bare ambiguous trigger (OBLI-001,
 *     OBLI-003 — not a named passive agent or a stated statutory mechanism)
 *   - no signature block at all (STRUCT-003 — no conformed signature,
 *     certification, adoption recital, delivery recital, or publication stamp)
 *
 * If a future guard is written too broadly, one of these assertions fails and
 * says exactly which defect went blind.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../_test-fixtures.js";
import { runEngine } from "../runner.js";
import { LAUNCH_RULES } from "./index.js";
import { V3_RULES } from "./v3/index.js";
import { V4_RULES } from "./v4/index.js";
import type { Playbook, RuleContext } from "../finding.js";

const SRC = { name: "adversarial.docx", sha256: "0".repeat(64), size_bytes: 100 };
const SETTLEMENT_PB: Playbook = { id: "confidential-settlement", version: "1.0.0" };
const ALL_RULES = [...LAUNCH_RULES, ...V3_RULES, ...V4_RULES];

const ADVERSARIAL: [string, ...string[]][] = [
  [
    "Confidential Settlement Agreement and Release",
    'This Confidential Settlement Agreement (this "Agreement") is entered into as of May 4, 2027, between Sablecrest Media LLC, a California limited liability company ("Company"), and Dana Whitfield ("Claimant"), resolving Claimant\'s charge of workplace sexual harassment filed with the DFEH.',
  ],
  [
    "Definitions",
    '"Confidential Information" means all non-public information of the Company disclosed to Claimant during employment.',
  ],
  [
    "Settlement Payment",
    "Company shall pay Claimant $250,000. Claimant shall protect the confidential information of the Company at all times.",
  ],
  [
    "Release",
    "Claimant releases the Company from all claims, known and unknown, arising from Claimant's employment and the harassment charge.",
  ],
  [
    "Indemnification",
    "Claimant shall indemnify and hold harmless the Company from any and all claims, damages, losses, and expenses arising out of any breach of this Agreement by Claimant. Claimant shall indemnify the Company against any third-party claim relating to Claimant's statements. Claimant shall indemnify the Company for any tax liability arising from the settlement payment.",
  ],
  [
    "Class-Action Waiver",
    "Claimant waives any right to participate in a class action, collective action, or representative action against the Company.",
  ],
  [
    "Data Transfer",
    "Company may transfer Claimant's personnel data to its processing affiliate outside the EEA for administration.",
  ],
  [
    "Administration",
    "The appropriate party shall provide notice from time to time as needed. Any dispute shall be resolved as set forth in Section 19 of this Agreement.",
  ],
  ["Governing Law", "This Agreement is governed by the laws of the State of California."],
];

function withPb(ctx: RuleContext, pb: Playbook): RuleContext {
  return { ...ctx, playbook: pb };
}

/** Each planted defect, with the clause that plants it. */
const PLANTED: [string, string][] = [
  ["SET-003", "California release of unknown claims with no § 1542 waiver"],
  ["SET-010", "sexual-harassment settlement with no § 162(q) recital"],
  ["RISK-002", "indemnity borne by one party only"],
  ["RISK-015", "commercial indemnity with no aggregate cap"],
  ["DARK-005", "an actual class-action waiver"],
  ["STRUCT-003", "no signature block of any form"],
  ["STRUCT-007", "a reference to a Section 19 that does not exist"],
  ["STRUCT-009", "lowercase use of the defined Confidential Information"],
  ["STRUCT-014", "lowercase use of the defined Confidential Information"],
  ["IPDATA-008", "transfer outside the EEA with no Article 46 safeguard"],
  ["OBLI-001", "'the appropriate party' as obligor"],
  ["OBLI-003", "'from time to time as needed' as a trigger"],
];

describe("suppression regression — every guarded rule still sees the real defect", () => {
  it.each(PLANTED)("%s still fires on %s", async (ruleId) => {
    const ctx = withPb(buildContext(...ADVERSARIAL), SETTLEMENT_PB);
    const run = await runEngine({ rules: ALL_RULES, ctx, source_file: SRC });
    expect(run.findings.map((f) => f.rule_id)).toContain(ruleId);
  });
});
