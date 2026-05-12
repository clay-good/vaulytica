import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const __dirname = dirname(fileURLToPath(import.meta.url));
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

const STARTER = join(__dirname, "..", "..", "dkb", "dist", "v0.0.1-starter");

const loadJson = (name: string): unknown =>
  JSON.parse(readFileSync(join(STARTER, name), "utf8")) as unknown;

describe("starter DKB conforms to the published schemas", () => {
  it("manifest", () => {
    expect(() => DkbManifestSchema.parse(loadJson("dkb-manifest.json"))).not.toThrow();
  });
  it("clauses", () => {
    expect(() => ClauseLibrarySchema.parse(loadJson("dkb-clauses.json"))).not.toThrow();
  });
  it("jurisdictions", () => {
    expect(() => JurisdictionSchema.parse(loadJson("dkb-jurisdictions.json"))).not.toThrow();
  });
  it("definitions", () => {
    expect(() => DefinitionTemplateSchema.parse(loadJson("dkb-definitions.json"))).not.toThrow();
  });
  it("dark patterns", () => {
    expect(() => DarkPatternSchema.parse(loadJson("dkb-dark-patterns.json"))).not.toThrow();
  });
  it("statutes", () => {
    expect(() => StatutorySchema.parse(loadJson("dkb-statutes.json"))).not.toThrow();
  });
  it("classifier vocab", () => {
    expect(() => ClassifierVocabSchema.parse(loadJson("dkb-classifier-vocab.json"))).not.toThrow();
  });
  it("classifier patterns", () => {
    expect(() => ClassifierPatternSchema.parse(loadJson("dkb-classifier-patterns.json"))).not.toThrow();
  });

  it("rejects entries missing a license", () => {
    const broken = {
      version: "v0.0.0-test",
      schema_version: "1.0.0",
      built_at: "2026-05-11T00:00:00Z",
      files: {
        clauses: { filename: "c.json", sha256: "a".repeat(64) },
        jurisdictions: { filename: "j.json", sha256: "a".repeat(64) },
        definitions: { filename: "d.json", sha256: "a".repeat(64) },
        dark_patterns: { filename: "dp.json", sha256: "a".repeat(64) },
        statutes: { filename: "s.json", sha256: "a".repeat(64) },
        classifier_vocab: { filename: "cv.json", sha256: "a".repeat(64) },
        classifier_patterns: { filename: "cp.json", sha256: "a".repeat(64) },
      },
      sources: [
        {
          id: "x",
          source: "X",
          source_url: "https://example.com",
          retrieved_at: "2026-05-11T00:00:00Z",
          // license intentionally missing
          license_url: "https://example.com/license",
        },
      ],
    };
    expect(() => DkbManifestSchema.parse(broken)).toThrow();
  });
});
