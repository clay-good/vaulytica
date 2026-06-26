import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { ZodTypeAny } from "zod";
import {
  ClassifierPatternSchema,
  ClassifierVocabSchema,
  ClauseLibrarySchema,
  DarkPatternSchema,
  DefinitionTemplateSchema,
  DkbManifestSchema,
  JurisdictionSchema,
  StatutorySchema,
} from "./schema.js";

/**
 * spec-v7 Part XIII (Step 121) — schema fuzz + round-trip.
 *
 * A schema's job is to *reject* malformed input; the existing schema test only
 * proved it *accepts* the (valid) starter files. These close the other half:
 *
 *  - round-trip identity — `parse → serialize → parse` is the identity on every
 *    valid artifact, so the validated DKB is stable under serialization (the same
 *    canonicalization discipline the engine's result_hash honors);
 *  - mutation-of-valid — take a valid artifact, break exactly one field (wrong
 *    type, missing-required, out-of-range, malformed-URL/hash), and assert the
 *    schema rejects it. This is fuzzing with a known oracle: every mutation is a
 *    real corruption the loader must catch before it can poison the rule engine.
 */

const __dirname = dirname(fileURLToPath(import.meta.url));
const STARTER = join(__dirname, "..", "..", "dkb", "dist", "v0.0.1-starter");
const load = (name: string): unknown => JSON.parse(readFileSync(join(STARTER, name), "utf8"));
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;

const FILES: { name: string; schema: ZodTypeAny; file: string; array: boolean }[] = [
  { name: "manifest", schema: DkbManifestSchema, file: "dkb-manifest.json", array: false },
  { name: "clauses", schema: ClauseLibrarySchema, file: "dkb-clauses.json", array: true },
  {
    name: "jurisdictions",
    schema: JurisdictionSchema,
    file: "dkb-jurisdictions.json",
    array: true,
  },
  {
    name: "definitions",
    schema: DefinitionTemplateSchema,
    file: "dkb-definitions.json",
    array: true,
  },
  { name: "dark patterns", schema: DarkPatternSchema, file: "dkb-dark-patterns.json", array: true },
  { name: "statutes", schema: StatutorySchema, file: "dkb-statutes.json", array: true },
  {
    name: "classifier vocab",
    schema: ClassifierVocabSchema,
    file: "dkb-classifier-vocab.json",
    array: true,
  },
  {
    name: "classifier patterns",
    schema: ClassifierPatternSchema,
    file: "dkb-classifier-patterns.json",
    array: true,
  },
];

describe("DKB schema — round-trip identity (spec-v7 Step 121)", () => {
  for (const { name, schema, file } of FILES) {
    it(`${name}: parse → serialize → parse is the identity`, () => {
      const parsed = schema.parse(load(file));
      const round = schema.parse(JSON.parse(JSON.stringify(parsed)));
      expect(round).toEqual(parsed);
    });
  }
});

describe("DKB schema — rejects the wrong top-level type (spec-v7 Step 121)", () => {
  for (const { name, schema, array } of FILES) {
    it(`${name}: rejects a ${array ? "non-array" : "non-object"}, null, and a number`, () => {
      expect(schema.safeParse(array ? { not: "an array" } : [1, 2, 3]).success).toBe(false);
      expect(schema.safeParse(null).success).toBe(false);
      expect(schema.safeParse(42).success).toBe(false);
    });
  }
});

// A valid first element of an array artifact, deep-cloned so the mutation can't
// leak between cases.
const firstOf = (file: string): Record<string, unknown> =>
  clone((load(file) as Record<string, unknown>[])[0]!);

describe("DKB schema — mutation-of-valid is rejected (spec-v7 Step 121)", () => {
  it("clauses: an invalid `position` enum value", () => {
    const c = firstOf("dkb-clauses.json");
    c.position = "sideways";
    expect(ClauseLibrarySchema.safeParse([c]).success).toBe(false);
  });

  it("clauses: a missing required `normalized_text`", () => {
    const c = firstOf("dkb-clauses.json");
    delete c.normalized_text;
    expect(ClauseLibrarySchema.safeParse([c]).success).toBe(false);
  });

  it("clauses: a non-URL `source.source_url`", () => {
    const c = firstOf("dkb-clauses.json");
    (c.source as Record<string, unknown>).source_url = "not-a-url";
    expect(ClauseLibrarySchema.safeParse([c]).success).toBe(false);
  });

  it("jurisdictions: an invalid `non_compete_enforceability` enum value", () => {
    const j = firstOf("dkb-jurisdictions.json");
    j.non_compete_enforceability = "maybe";
    expect(JurisdictionSchema.safeParse([j]).success).toBe(false);
  });

  it("jurisdictions: a non-positive statute-of-limitations year count", () => {
    const j = firstOf("dkb-jurisdictions.json");
    j.statute_of_limitations_contract_years = -1;
    expect(JurisdictionSchema.safeParse([j]).success).toBe(false);
  });

  it("definitions: a missing required `variants.balanced`", () => {
    const d = firstOf("dkb-definitions.json");
    delete (d.variants as Record<string, unknown>).balanced;
    expect(DefinitionTemplateSchema.safeParse([d]).success).toBe(false);
  });

  it("dark patterns: an empty `authorities` array (min 1 required)", () => {
    const p = firstOf("dkb-dark-patterns.json");
    p.authorities = [];
    expect(DarkPatternSchema.safeParse([p]).success).toBe(false);
  });

  it("statutes: a `retrieved_at` that is a date, not an ISO datetime", () => {
    const s = firstOf("dkb-statutes.json");
    s.retrieved_at = "2026-01-01";
    expect(StatutorySchema.safeParse([s]).success).toBe(false);
  });

  it("classifier patterns: a `confidence` outside [0, 1]", () => {
    const p = firstOf("dkb-classifier-patterns.json");
    p.confidence = 2;
    expect(ClassifierPatternSchema.safeParse([p]).success).toBe(false);
  });

  it("classifier vocab: `terms` that is not a record of numbers", () => {
    // The starter vocab is empty, so synthesize a valid entry and break it.
    const valid = { category: "contract", terms: { shall: 0.5 } };
    expect(ClassifierVocabSchema.safeParse([valid]).success).toBe(true);
    expect(ClassifierVocabSchema.safeParse([{ category: "contract", terms: "nope" }]).success).toBe(
      false,
    );
    expect(
      ClassifierVocabSchema.safeParse([{ category: "contract", terms: { shall: "high" } }]).success,
    ).toBe(false);
  });

  it("manifest: a malformed file `sha256` (not 64 hex chars)", () => {
    const m = clone(load("dkb-manifest.json")) as { files: { clauses: { sha256: string } } };
    m.files.clauses.sha256 = "xyz";
    expect(DkbManifestSchema.safeParse(m).success).toBe(false);
  });

  it("manifest: a missing required `version`", () => {
    const m = clone(load("dkb-manifest.json")) as Record<string, unknown>;
    delete m.version;
    expect(DkbManifestSchema.safeParse(m).success).toBe(false);
  });

  it("manifest: a `built_at` that is not an ISO datetime", () => {
    const m = clone(load("dkb-manifest.json")) as Record<string, unknown>;
    m.built_at = "yesterday";
    expect(DkbManifestSchema.safeParse(m).success).toBe(false);
  });
});
