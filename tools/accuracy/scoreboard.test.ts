import { describe, expect, it } from "vitest";
import { assembleScoreboard, renderScoreboardMarkdown, scoreboardHash } from "./scoreboard.js";
import { gradeAnnotation } from "./grade.js";
import { loadAccuracyDeps, runDocument } from "./pipeline.js";
import type { GradedDocument } from "./metrics.js";
import type { GoldAnnotation, Provenance } from "./schema.js";

const baseInput = {
  corpus_version: "v0.0.0-test",
  dkb_version: "v0.0.1-starter",
  engine_version: "0.1.0",
  catalog: { rules: 1062, playbooks: 135 },
  kappa_pairs: [],
};

function gd(over: Partial<GradedDocument> = {}): GradedDocument {
  return {
    corpus_doc_id: "d1",
    playbook_id: "pb",
    fired_rule_ids: new Set(["R1"]),
    gold: new Map([["R1", "should_fire"]]),
    high_confidence: true,
    bootstrap: false,
    ...over,
  };
}

describe("scoreboard assembly (spec-v5 §10)", () => {
  it("reports the empty state honestly with no graded docs", () => {
    const a = assembleScoreboard({ ...baseInput, graded: [] });
    expect(a.corpus_status).toBe("empty");
    expect(a.headline.micro.precision).toBeNull();
    expect(a.doc_counts.real_graded_pairs).toBe(0);
    expect(a.notes.join(" ")).toContain("No real annotated documents yet");
  });

  it("computes a populated headline and stamps the versions", () => {
    const a = assembleScoreboard({
      ...baseInput,
      thin_floor: 1,
      graded: [gd(), gd({ corpus_doc_id: "d2", fired_rule_ids: new Set(["R1"]) })],
    });
    expect(a.corpus_status).toBe("populated");
    expect(a.headline.micro.precision).toBeCloseTo(1, 10);
    expect(a.corpus_version).toBe("v0.0.0-test");
    expect(a.dkb_version).toBe("v0.0.1-starter");
  });

  it("excludes bootstrap pairs and notes them", () => {
    const a = assembleScoreboard({
      ...baseInput,
      graded: [gd({ bootstrap: true })],
    });
    expect(a.doc_counts.real_graded_pairs).toBe(0);
    expect(a.doc_counts.bootstrap_pairs).toBe(1);
    expect(a.notes.join(" ")).toContain("bootstrap placeholder");
  });

  it("hash is reproducible and excludes itself", () => {
    const a = assembleScoreboard({ ...baseInput, graded: [gd()] });
    const b = assembleScoreboard({ ...baseInput, graded: [gd()] });
    expect(a.scoreboard_hash).toBe(b.scoreboard_hash);
    expect(a.scoreboard_hash).toMatch(/^[0-9a-f]{64}$/);
    // Recomputing over the artifact (with hash blanked) reproduces the hash.
    expect(scoreboardHash(a)).toBe(a.scoreboard_hash);
  });

  it("a different graded result changes the hash", () => {
    const a = assembleScoreboard({ ...baseInput, graded: [gd()] });
    const b = assembleScoreboard({
      ...baseInput,
      graded: [gd({ fired_rule_ids: new Set([]), gold: new Map([["R1", "should_fire"]]) })],
    });
    expect(a.scoreboard_hash).not.toBe(b.scoreboard_hash);
  });

  it("renders deterministic markdown", () => {
    const a = assembleScoreboard({ ...baseInput, graded: [gd()] });
    const md1 = renderScoreboardMarkdown(a);
    const md2 = renderScoreboardMarkdown(a);
    expect(md1).toBe(md2);
    expect(md1).toContain("# Vaulytica accuracy scoreboard");
    expect(md1).toContain(a.scoreboard_hash);
  });
});

describe("end-to-end: real pipeline → grade → scoreboard (spec-v5 §9)", () => {
  it("runs the full engine over an in-memory document and grades it", async () => {
    const deps = await loadAccuracyDeps();
    // A short NDA-shaped document; we don't assert specific rule ids (those
    // are the engine's job, covered by golden tests) — only that the pipeline
    // reuse runs end to end and produces a gradable EngineRun.
    const text = [
      "MUTUAL NONDISCLOSURE AGREEMENT",
      'This Agreement is between [PARTY-1] and [PARTY-2]. "Confidential Information" means any information disclosed.',
      "The receiving party shall protect Confidential Information. This Agreement is governed by the laws of the State of Delaware.",
    ].join("\n\n");

    const { run, playbook_id } = await runDocument(text, "d-nda.txt", "mutual-nda", deps);
    expect(playbook_id).toBe("mutual-nda");
    expect(run.result_hash).toMatch(/^[0-9a-f]{64}$/);

    const provenance: Provenance = {
      corpus_doc_id: "e2e-nda",
      origin: "Common Paper",
      source_ref: "in-memory test",
      license: "CC0",
      retrieved_at: "2026-06-01",
      redacted_sha256: "0".repeat(64),
      redaction_log: [],
      bootstrap: true, // never counts toward a real number
    };
    const annotation: GoldAnnotation = {
      corpus_doc_id: "e2e-nda",
      playbook_id: "mutual-nda",
      annotator_a: "test",
      kappa_input: false,
      dkb_version_at_annotation: "v0.0.1-starter",
      expected_findings: [{ rule_id: run.findings[0]?.rule_id ?? "STRUCT-001", verdict: "should_fire" }],
    };
    const graded = gradeAnnotation(
      provenance,
      annotation,
      run.findings.map((f) => f.rule_id),
    );
    expect(graded.bootstrap).toBe(true);

    const board = assembleScoreboard({ ...baseInput, graded: [graded] });
    // Bootstrap doc → excluded from real counts, honest empty headline.
    expect(board.doc_counts.bootstrap_pairs).toBe(1);
    expect(board.doc_counts.real_graded_pairs).toBe(0);
  });

  it("runs the same document twice to byte-identical findings (determinism)", async () => {
    const deps = await loadAccuracyDeps();
    const text = "SERVICES AGREEMENT\n\nThe parties agree to the following terms and conditions.";
    const a = await runDocument(text, "d.txt", undefined, deps);
    const b = await runDocument(text, "d.txt", undefined, deps);
    expect(a.run.result_hash).toBe(b.run.result_hash);
  });
});
