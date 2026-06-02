import { describe, expect, it } from "vitest";
import {
  parseProvenance,
  parseGoldAnnotation,
  parseCorpusManifest,
  ProvenanceSchema,
} from "./schema.js";

describe("corpus & annotation schemas (spec-v5 §4, §6)", () => {
  it("accepts a valid provenance record", () => {
    const p = parseProvenance({
      corpus_doc_id: "edgar-10k-ex10-2021-acme-msa-redacted",
      origin: "SEC EDGAR",
      source_ref: "0001193125-21-000000",
      license: "US-Gov-PD",
      retrieved_at: "2026-06-01",
      redacted_sha256: "a".repeat(64),
      redaction_log: [{ kind: "party-name", count: 4, replacement: "[PARTY-1]" }],
    });
    expect(p.corpus_doc_id).toContain("acme-msa");
    expect(p.bootstrap).toBeUndefined();
  });

  it("rejects a bad retrieved_at and a short sha", () => {
    expect(() =>
      ProvenanceSchema.parse({
        corpus_doc_id: "x",
        origin: "SEC EDGAR",
        source_ref: "y",
        license: "PD",
        retrieved_at: "June 1 2026",
        redacted_sha256: "abc",
        redaction_log: [],
      }),
    ).toThrow();
  });

  it("rejects an unknown origin", () => {
    expect(() =>
      ProvenanceSchema.parse({
        corpus_doc_id: "x",
        origin: "Random Blog",
        source_ref: "y",
        license: "PD",
        retrieved_at: "2026-06-01",
        redacted_sha256: "a".repeat(64),
        redaction_log: [],
      }),
    ).toThrow();
  });

  it("accepts a valid gold annotation with verdicts", () => {
    const a = parseGoldAnnotation({
      corpus_doc_id: "edgar-acme-msa",
      playbook_id: "msa-general",
      annotator_a: "att-014",
      annotator_b: "att-022",
      kappa_input: true,
      dkb_version_at_annotation: "v0.0.1-starter",
      expected_findings: [
        { rule_id: "MSA-006", verdict: "should_fire", severity_expected: "critical" },
        { rule_id: "MSA-024", verdict: "should_not_fire", note: "law and venue consistent" },
      ],
      uncovered_defects: [{ description: "one-sided audit right", no_rule_yet: true }],
    });
    expect(a.expected_findings).toHaveLength(2);
    expect(a.kappa_input).toBe(true);
  });

  it("rejects an invalid verdict", () => {
    expect(() =>
      parseGoldAnnotation({
        corpus_doc_id: "x",
        playbook_id: "pb",
        annotator_a: "a",
        kappa_input: false,
        dkb_version_at_annotation: "v",
        expected_findings: [{ rule_id: "R1", verdict: "maybe" }],
      }),
    ).toThrow();
  });

  it("accepts an empty corpus manifest (seed state)", () => {
    const m = parseCorpusManifest({ corpus_version: "v0.0.0-seed", splits: {} });
    expect(Object.keys(m.splits)).toHaveLength(0);
  });
});
