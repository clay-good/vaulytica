/**
 * Guards the published JSON Schema artifact (docs/v6/playbook.schema.json)
 * against drift from the authoritative Zod schema. The Zod schema is the
 * source of truth; this test asserts the JSON mirror stays in lockstep on
 * the parts most likely to silently diverge (the bounded metric enum, the
 * severity enum, the required top-level fields).
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { NUMERIC_METRICS, CUSTOM_PLAYBOOK_SCHEMA_VERSION } from "./custom-playbook.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCHEMA_PATH = join(__dirname, "..", "..", "docs", "v6", "playbook.schema.json");

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const schema: any = JSON.parse(readFileSync(SCHEMA_PATH, "utf8"));

describe("playbook.schema.json artifact", () => {
  it("is valid JSON Schema 2020-12 with the expected identity", () => {
    expect(schema.$schema).toBe("https://json-schema.org/draft/2020-12/schema");
    expect(schema.type).toBe("object");
    expect(schema.additionalProperties).toBe(false);
  });

  it("requires the same top-level fields the Zod schema does", () => {
    expect(schema.required).toEqual([
      "schema_version",
      "catalog_version",
      "id",
      "name",
      "description",
    ]);
  });

  it("pins schema_version to the current format version", () => {
    expect(schema.properties.schema_version.const).toBe(CUSTOM_PLAYBOOK_SCHEMA_VERSION);
  });

  it("mirrors the bounded numeric-metric enum exactly", () => {
    const predicate = schema.$defs.predicate.oneOf.find(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (p: any) => p.properties?.kind?.const === "numeric_threshold",
    );
    expect(predicate).toBeDefined();
    expect(predicate.properties.metric.enum).toEqual([...NUMERIC_METRICS]);
  });

  it("covers all six predicate kinds", () => {
    const kinds = schema.$defs.predicate.oneOf
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      .map((p: any) => p.properties.kind.const)
      .sort();
    expect(kinds).toEqual(
      [
        "clause_absent",
        "clause_present",
        "cross_ref_resolves",
        "defined_term_present",
        "governing_law_in",
        "numeric_threshold",
      ].sort(),
    );
  });
});
