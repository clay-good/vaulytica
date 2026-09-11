/**
 * The thirty coherence reads take a posture-coherence artifact — and the
 * commonest `.json` this tool writes is an analysis report.
 *
 * So `analyze --format json` followed by `coherence-trend` on the results is
 * the natural wrong guess, and what it printed described the shape mismatch
 * without ever naming the mistake:
 *
 *     ✗ round 1: schema must be one of "vaulytica.posture-coherence.v1", … (got undefined)
 *       round 1: coherence_hash must be a string
 *       round 1: dimensions must be an array
 *
 * Every line is true and none of them says "you passed a report" — the same
 * defect `cli-diff-wrong-input.test.ts` names for `diff`, on **thirty commands
 * at once**: every `coherence-*` read and `posture-review` come through
 * `verifyCoherenceSequence`, and `compare-coherence` through its own pair
 * parse. Both now go through one `wrongKindOfJson`.
 *
 * 🚨 The schema errors are NOT replaced in general — for a file this tool did
 * not write they are the most useful thing to show. They are replaced only
 * when the input is recognisably one of ours, which is when a name is
 * available and more useful than a shape.
 */
import { describe, expect, it } from "vitest";
import { verifyCoherenceSequence } from "../../tools/cli/coherence-sequence.js";
import { jsonKindOf } from "../../tools/cli/json-kind.js";
import { compareCoherenceArtifacts } from "../../tools/cli/compare-coherence.js";

const REPORT = JSON.stringify({ run: { result_hash: "x", findings: [] }, ingest: {} });
const PLAYBOOK = JSON.stringify({ id: "team", catalog_version: "1", rules: [] });
/** Valid JSON this tool did not write — the schema errors must survive. */
const STRANGER = JSON.stringify({ hello: "world" });

describe("a coherence read, handed the wrong kind of JSON", () => {
  it("names an analysis report and says how to produce a coherence artifact", async () => {
    const out = await verifyCoherenceSequence([REPORT, REPORT]);
    expect(out.ok).toBe(false);
    const errs = out.ok ? [] : out.errors;
    expect(errs.join("\n")).toContain("looks like an analysis report");
    expect(errs.join("\n"), "it must say which command writes one").toContain("--emit-coherence");
    // 🚨 The defect, as an assertion: the shape list must not be the answer.
    expect(errs.join("\n")).not.toContain("coherence_hash must be a string");
  });

  it("names a custom playbook too", async () => {
    const out = await verifyCoherenceSequence([PLAYBOOK, PLAYBOOK]);
    expect(out.ok).toBe(false);
    expect((out.ok ? [] : out.errors).join("\n")).toContain("looks like a custom playbook");
  });

  it("compare-coherence says it, and points at the command that diffs analyses", async () => {
    const out = await compareCoherenceArtifacts(REPORT, REPORT);
    expect(out.ok).toBe(false);
    const text = (out.ok ? [] : out.errors).join("\n");
    expect(text).toContain("looks like an analysis report");
    expect(text).toContain("vaulytica compare");
  });

  it("keeps the schema errors for JSON this tool did not write", async () => {
    // The load-bearing negative. "Not one of ours" has no name to give, so the
    // shape mismatch is the most useful answer and must survive.
    const out = await verifyCoherenceSequence([STRANGER, STRANGER]);
    expect(out.ok).toBe(false);
    const text = (out.ok ? [] : out.errors).join("\n");
    expect(text).toContain("coherence_hash must be a string");
    expect(text).not.toContain("looks like");
  });

  it("recognises each kind by the fields that distinguish it", () => {
    expect(jsonKindOf(REPORT)).toBe("report");
    expect(jsonKindOf(PLAYBOOK)).toBe("playbook");
    expect(jsonKindOf(STRANGER)).toBeNull();
    expect(jsonKindOf("not json at all")).toBeNull();
  });
});
