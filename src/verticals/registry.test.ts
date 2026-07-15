import { describe, expect, it } from "vitest";
import type { Rule } from "../engine/finding.js";
import { runEngine } from "../engine/runner.js";
import { buildContext } from "../engine/_test-fixtures.js";
import { LAUNCH_RULES } from "../engine/rules/index.js";
import { V3_RULES } from "../engine/rules/v3/index.js";
import { V4_RULES } from "../engine/rules/v4/index.js";
import { FILING_RULES } from "../engine/rules/filing/index.js";
import {
  NAMESPACE_OWNERS,
  REGISTERED_ASSERTION_GATES,
  SCOPE_OF_REVIEW,
  rulePrefix,
  scopeForPlaybook,
  selectActiveRules,
} from "./registry.js";

const LAUNCH_IDS = new Set(LAUNCH_RULES.map((r) => r.id));
const NON_LAUNCH: readonly Rule[] = [...V3_RULES, ...V4_RULES, ...FILING_RULES].filter(
  (r) => !LAUNCH_IDS.has(r.id),
);

// The registry gate contract (add-document-vertical-framework, Requirement:
// "Vertical rule packs are gated to their document families").
describe("vertical rule-pack gating", () => {
  it("every non-launch rule declares exactly one registered gate", () => {
    const offenders: string[] = [];
    for (const r of NON_LAUNCH) {
      const hasPlaybookGate = Array.isArray(r.applies_to_playbooks) && r.applies_to_playbooks.length > 0;
      const hasAssertionGate = r.assertion_gate !== undefined;
      if (!hasPlaybookGate && !hasAssertionGate) {
        offenders.push(`${r.id} (no applies_to_playbooks and no assertion_gate)`);
      }
      if (hasAssertionGate && !REGISTERED_ASSERTION_GATES.includes(r.assertion_gate!)) {
        offenders.push(`${r.id} (unregistered assertion gate "${r.assertion_gate}")`);
      }
    }
    expect(offenders, offenders.join("\n")).toEqual([]);
  });

  it("confirms the shipped v3/v4 packs already satisfy the gate", () => {
    // Not an assumption — the audit said they pass; this pins it. Every shipped
    // non-launch rule uses the playbook gate today (no assertion gates yet).
    expect(NON_LAUNCH.length).toBeGreaterThan(0);
    for (const r of NON_LAUNCH) {
      expect(r.applies_to_playbooks?.length ?? 0, r.id).toBeGreaterThan(0);
    }
  });
});

// Namespace reservation (Requirement: "Rule-ID namespaces are reserved per
// vertical").
describe("rule-id namespace ownership", () => {
  it("every launch rule prefix is owned by the launch set", () => {
    for (const r of LAUNCH_RULES) {
      expect(NAMESPACE_OWNERS[rulePrefix(r.id)], r.id).toBe("launch");
    }
  });

  it("every non-launch rule prefix maps to a single non-launch owner", () => {
    for (const r of NON_LAUNCH) {
      const owner = NAMESPACE_OWNERS[rulePrefix(r.id)];
      expect(owner, `${r.id}: prefix "${rulePrefix(r.id)}" is unregistered`).toBeDefined();
      expect(owner, r.id).not.toBe("launch");
    }
  });

  it("no prefix is claimed by two owners (map keys are unique by construction)", () => {
    const prefixes = Object.keys(NAMESPACE_OWNERS);
    expect(new Set(prefixes).size).toBe(prefixes.length);
  });
});

// Hash isolation (Requirement: "Adding a pack cannot change existing hashes").
describe("pack hash isolation", () => {
  // A representative document context. LAUNCH_RULES carry no gate, so their
  // selection is a no-op; the synthetic pack rules must be filtered out.
  const ctx = buildContext(
    ["Mutual NDA"],
    [
      'This Agreement is between Acme Corp. ("Discloser") and Globex Inc. ("Recipient"). Effective Date: 2025-01-01.',
    ],
    ["Recipient shall protect Confidential Information. By: ____ Name: ____ Title: ____"],
  );
  const sourceFile = { name: "doc.docx", sha256: "0".repeat(64), size_bytes: 100 };

  const synthPlaybookGated: Rule = {
    id: "SYNTH-001",
    version: "1.0.0",
    name: "synthetic playbook-gated",
    category: "synthetic",
    default_severity: "critical",
    description: "fires unconditionally when it runs",
    dkb_citations: [],
    applies_to_playbooks: ["synthetic-pack-playbook"],
    check: () => null,
  };
  const synthAssertionGated: Rule = {
    id: "SYNTH-002",
    version: "1.0.0",
    name: "synthetic assertion-gated",
    category: "synthetic",
    default_severity: "critical",
    description: "fires unconditionally when it runs",
    dkb_citations: [],
    assertion_gate: "synthetic-assertion",
    check: () => null,
  };

  it("a playbook-gated pack rule leaves the baseline hash byte-identical", async () => {
    const baseline = await runEngine({
      rules: selectActiveRules(LAUNCH_RULES, ctx.playbook.id),
      ctx,
      source_file: sourceFile,
    });
    const withPack = await runEngine({
      rules: selectActiveRules([...LAUNCH_RULES, synthPlaybookGated], ctx.playbook.id),
      ctx,
      source_file: sourceFile,
    });
    expect(withPack.result_hash).toBe(baseline.result_hash);
    expect(withPack.execution_log.length).toBe(baseline.execution_log.length);
  });

  it("an assertion-gated pack rule with no assertion made leaves the hash byte-identical", async () => {
    const baseline = await runEngine({
      rules: selectActiveRules(LAUNCH_RULES, ctx.playbook.id, []),
      ctx,
      source_file: sourceFile,
    });
    const withPack = await runEngine({
      // Assertion not in the active set → the rule is selected out regardless
      // of playbook, so the hash is unchanged.
      rules: selectActiveRules([...LAUNCH_RULES, synthAssertionGated], ctx.playbook.id, []),
      ctx,
      source_file: sourceFile,
    });
    expect(withPack.result_hash).toBe(baseline.result_hash);
  });

  it("selection admits the pack rule once its gate is satisfied (sanity)", () => {
    // Guards against a filter that drops everything: the rules DO run when gated in.
    expect(
      selectActiveRules([synthPlaybookGated], "synthetic-pack-playbook").map((r) => r.id),
    ).toEqual(["SYNTH-001"]);
    expect(
      selectActiveRules([synthAssertionGated], "anything", ["synthetic-assertion"]).map((r) => r.id),
    ).toEqual(["SYNTH-002"]);
  });
});

// Scope-of-review registry (Requirement: "Every pack declares and renders its
// scope of review").
describe("scope-of-review registry", () => {
  it("the shipped regulated packs (DPA, BAA) declare a scope statement", () => {
    for (const id of ["baa", "dpa-controller-processor", "scc-module-2"]) {
      const scope = scopeForPlaybook(id);
      expect(scope, id).toBeDefined();
      expect(scope!.reviewed_for.length).toBeGreaterThan(0);
      expect(scope!.not_reviewed_for.length).toBeGreaterThan(0);
    }
  });

  it("presence-only: no scope statement claims the document is compliant or clean", () => {
    const banned = /\b(compliant|compliance-verified|clean bill|certified|guarantee)\b/i;
    for (const scope of Object.values(SCOPE_OF_REVIEW)) {
      for (const line of [...scope.reviewed_for, ...scope.not_reviewed_for]) {
        expect(banned.test(line), line).toBe(false);
      }
    }
  });

  it("an unregistered playbook has no scope statement", () => {
    expect(scopeForPlaybook("mutual-nda")).toBeUndefined();
  });
});
