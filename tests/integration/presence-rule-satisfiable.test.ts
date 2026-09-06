/**
 * A presence rule must be able to report the absence it exists to report.
 *
 * 899 rules in the catalog are built through the `presence()` helper: they
 * carry `present_patterns`, and they fire when the document does not satisfy
 * them. The failure mode this guards is the quietest one in the tree — a
 * pattern broad enough to match anything makes its rule satisfied by every
 * document, so the rule runs on every specimen, produces nothing, and is
 * indistinguishable from a rule whose clause is always present. It is the same
 * shape as the unsatisfiable `required_clauses` session 22 found, seen from
 * the other side: there a rule could never PASS, here it can never FIRE.
 *
 * The test is the simplest possible: a document with no legal content at all.
 * Every presence rule must fire on it, because nothing it is looking for is
 * there.
 *
 * The exceptions are not hand-written, which is the point. A rule that
 * declares `applicable_if` is CONDITIONAL — Reg Z governs consumer credit
 * only, the OWBPA disclosure applies to group terminations, DGCL § 141(f)
 * governs board consents — and standing down on a document that is not of that
 * kind is the rule working. `buildV4PresenceRule` already records exactly
 * those ids in `V4_GATED_PRESENCE_RULE_IDS` as it builds them, so the
 * exception list cannot drift from the rules it describes.
 *
 * Note on the probe itself: `present_patterns` are satisfied by ANY ONE match
 * unless the rule sets `require_all_present`. So the fixture text has to be
 * genuinely contentless — an earlier version said "This document is
 * intentionally minimal" and CON-019 went silent on the words "this document"
 * alone, which looked exactly like the defect this file hunts and was not one.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { LAUNCH_RULES } from "../../src/engine/rules/index.js";
import { V3_RULES } from "../../src/engine/rules/v3/index.js";
import { V4_RULES } from "../../src/engine/rules/v4/index.js";
import { V5_RULES } from "../../src/engine/rules/v5/index.js";
import { V6_RULES } from "../../src/engine/rules/v6/index.js";
import { V4_GATED_PRESENCE_RULE_IDS } from "../../src/engine/rules/v4/_helpers.js";
import { buildContext } from "../../src/engine/_test-fixtures.js";
import type { Rule, RuleContext } from "../../src/engine/finding.js";

/** Every id declared through `presence({ ... })`, read from the source. */
function presenceRuleIds(): Set<string> {
  const files = execFileSync("git", ["ls-files", "src/engine/rules/**/*.ts"], {
    encoding: "utf8",
  })
    .trim()
    .split("\n")
    .filter((f) => f && !f.endsWith(".test.ts"));
  const ids = new Set<string>();
  for (const file of files) {
    const src = readFileSync(file, "utf8");
    const re = /presence\(\{\s*[\s\S]{0,200}?id:\s*"([A-Z0-9-]+)"/g;
    for (let m = re.exec(src); m; m = re.exec(src)) ids.add(m[1]!);
  }
  return ids;
}

/**
 * The live catalog. Imported STATICALLY: a computed `import()` path resolves
 * under tsx and not under vite, so a dynamic version of this passes in a
 * scratch probe and throws "Unknown variable dynamic import" in the suite.
 */
function liveRules(): Map<string, Rule> {
  const all: Rule[] = [...LAUNCH_RULES, ...V3_RULES, ...V4_RULES, ...V5_RULES, ...V6_RULES];
  return new Map(all.map((r) => [r.id, r]));
}

describe("every presence rule can report its own absence", () => {
  it("fires on a document with no legal content, unless it is conditional", () => {
    const ids = presenceRuleIds();
    expect(ids.size, "the source scan found no presence rules — it is broken").toBeGreaterThan(800);
    const rules = liveRules();

    // Deliberately meaningless: no legal vocabulary for any pattern to match.
    const base = buildContext(["XQZ", "Wvbk qrfl."]);
    const silent: string[] = [];
    let probed = 0;
    for (const id of [...ids].sort()) {
      const rule = rules.get(id);
      if (!rule) continue;
      if (V4_GATED_PRESENCE_RULE_IDS.has(id)) continue;
      const playbooks = (rule as Rule & { playbooks?: string[] }).playbooks ?? [];
      const ctx: RuleContext = {
        ...base,
        playbook: { id: playbooks[0] ?? "generic-fallback", version: "1.0.0" },
      };
      probed++;
      if (rule.check(ctx) === null) silent.push(id);
    }
    expect(probed, "no presence rule was actually exercised").toBeGreaterThan(800);
    expect(
      silent,
      "these presence rules cannot report their own absence — a pattern matches everything, " +
        "or the rule is conditional and should declare `applicable_if`",
    ).toEqual([]);
  }, 120_000);

  it("the conditional set is populated, so the exemption is not vacuous", () => {
    // The set fills as `buildV4PresenceRule` runs, so the catalog has to be
    // loaded before it is read — which importing the rule modules above does.
    liveRules();
    // If `V4_GATED_PRESENCE_RULE_IDS` were empty the assertion above would
    // still pass today and would stop exempting anything the moment a
    // conditional rule was added.
    expect(V4_GATED_PRESENCE_RULE_IDS.size).toBeGreaterThan(20);
  });
});
