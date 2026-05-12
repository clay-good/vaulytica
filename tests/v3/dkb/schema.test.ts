import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  ConsistencyCheckSchema,
  InsuranceNormSchema,
  RegulatorModelFormSchema,
  StatutoryClauseRequirementSchema,
  SubprocessorRequirementSchema,
  TransferMechanismSchema,
  V3DkbNodeSchema,
  parseV3Node,
} from "../../../src/dkb/v3/schema.js";
import { validateV3Nodes } from "../../../src/dkb/loader.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(__dirname, "..", "..", "..", "dkb", "fixtures", "v3", "nodes");

const loadJson = (name: string): unknown =>
  JSON.parse(readFileSync(join(FIXTURES, name), "utf8")) as unknown;

describe("v3 DKB node schemas", () => {
  it("accepts the regulator_model_form fixture", () => {
    expect(() => RegulatorModelFormSchema.parse(loadJson("regulator_model_form.sample.json"))).not.toThrow();
  });

  it("accepts the statutory_clause_requirement fixture", () => {
    expect(() =>
      StatutoryClauseRequirementSchema.parse(loadJson("statutory_clause_requirement.sample.json")),
    ).not.toThrow();
  });

  it("accepts the transfer_mechanism fixture", () => {
    expect(() => TransferMechanismSchema.parse(loadJson("transfer_mechanism.sample.json"))).not.toThrow();
  });

  it("accepts the subprocessor_requirement fixture", () => {
    expect(() =>
      SubprocessorRequirementSchema.parse(loadJson("subprocessor_requirement.sample.json")),
    ).not.toThrow();
  });

  it("accepts the insurance_norm fixture", () => {
    expect(() => InsuranceNormSchema.parse(loadJson("insurance_norm.sample.json"))).not.toThrow();
  });

  it("accepts the consistency_check fixture", () => {
    expect(() => ConsistencyCheckSchema.parse(loadJson("consistency_check.sample.json"))).not.toThrow();
  });

  it("discriminated-union parseV3Node accepts every fixture", () => {
    const files = readdirSync(FIXTURES).filter((f) => f.endsWith(".sample.json"));
    expect(files.length).toBeGreaterThanOrEqual(6);
    for (const f of files) {
      const node = parseV3Node(loadJson(f));
      expect(node.node_type).toBeTypeOf("string");
      expect(node.cites.length).toBeGreaterThan(0);
    }
  });

  it("validateV3Nodes accepts an array of fixtures", () => {
    const files = readdirSync(FIXTURES).filter((f) => f.endsWith(".sample.json"));
    const arr = files.map((f) => loadJson(f));
    expect(() => validateV3Nodes(arr)).not.toThrow();
  });

  it("rejects a malformed node (missing required field)", () => {
    const valid = loadJson("statutory_clause_requirement.sample.json") as Record<string, unknown>;
    const broken = { ...valid };
    delete broken.requirement;
    expect(() => V3DkbNodeSchema.parse(broken)).toThrow();
  });

  it("rejects a malformed node (bad content_hash_at_pin)", () => {
    const valid = JSON.parse(
      readFileSync(join(FIXTURES, "regulator_model_form.sample.json"), "utf8"),
    ) as { cites: Array<{ content_hash_at_pin: string }> };
    valid.cites[0]!.content_hash_at_pin = "not-a-sha256";
    expect(() => V3DkbNodeSchema.parse(valid)).toThrow();
  });

  it("rejects a node with an unknown node_type", () => {
    expect(() =>
      V3DkbNodeSchema.parse({
        id: "x",
        node_type: "not_a_real_type",
        dkb_node_version: 1,
        dkb_node_last_validated_at: "2026-05-12T00:00:00Z",
        cites: [],
      }),
    ).toThrow();
  });
});
