import { describe, expect, it } from "vitest";
import {
  MODEL_CLAUSES,
  MODEL_CLAUSE_COVERAGE,
  ModelClauseSchema,
  modelClauseForRule,
} from "./model-clauses.js";
import { LAUNCH_RULES } from "../engine/rules/index.js";

describe("model-clause catalog (spec-v6 Part IV)", () => {
  it("every entry validates against the schema", () => {
    for (const mc of MODEL_CLAUSES) {
      expect(() => ModelClauseSchema.parse(mc)).not.toThrow();
    }
  });

  it("clause ids are unique", () => {
    const ids = MODEL_CLAUSES.map((m) => m.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("each rule maps to at most one model clause (no ambiguous coverage)", () => {
    const seen = new Set<string>();
    for (const mc of MODEL_CLAUSES) {
      for (const ruleId of mc.applies_to_rules) {
        expect(seen.has(ruleId)).toBe(false);
        seen.add(ruleId);
      }
    }
  });

  it("every referenced rule id exists in the launch catalog", () => {
    const known = new Set(LAUNCH_RULES.map((r) => r.id));
    for (const mc of MODEL_CLAUSES) {
      for (const ruleId of mc.applies_to_rules) {
        expect(known.has(ruleId), `${ruleId} (from ${mc.id}) is not a known rule`).toBe(true);
      }
    }
  });

  it("coverage count is honest (matches the distinct rule mappings)", () => {
    const distinctRules = new Set(MODEL_CLAUSES.flatMap((m) => m.applies_to_rules));
    expect(MODEL_CLAUSE_COVERAGE.rules_with_reference).toBe(distinctRules.size);
    expect(MODEL_CLAUSE_COVERAGE.model_clauses).toBe(MODEL_CLAUSES.length);
  });

  it("modelClauseForRule resolves mapped rules and returns undefined otherwise", () => {
    expect(modelClauseForRule("RISK-005")?.id).toBe("cp-csa-limitation-of-liability");
    expect(modelClauseForRule("STRUCT-001")).toBeUndefined();
    expect(modelClauseForRule("does-not-exist")).toBeUndefined();
  });

  it("the catalog is a frozen, deterministic projection (two reads identical)", () => {
    const a = JSON.stringify(MODEL_CLAUSES);
    const b = JSON.stringify(MODEL_CLAUSES);
    expect(a).toBe(b);
  });
});
