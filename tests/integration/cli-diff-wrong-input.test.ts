/**
 * `diff` compares two CUSTOM PLAYBOOKS — and every other `.json` this tool
 * writes is an analysis report.
 *
 * So `analyze --format json` followed by `diff` on the results is the natural
 * wrong guess, and the schema errors it used to print described the shape
 * mismatch without ever naming the mistake:
 *
 *     ✗ invalid playbook:
 *       a: (root): Unrecognized keys: "run", "ingest", "provenance", …
 *       a: catalog_version: Invalid input: expected string, received undefined
 *       …twelve more lines…
 *
 * Every line is true and none of them says "you passed a report". The CLI's own
 * usage line said only `diff <a.json> <b.json>`, which does not distinguish the
 * two kinds of JSON it emits either — the README did, but a user reading
 * `--help` did not.
 */
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";

async function stderrOf(argv: string[]): Promise<string> {
  const chunks: string[] = [];
  const spy = vi.spyOn(process.stderr, "write").mockImplementation((c: unknown) => {
    chunks.push(String(c));
    return true;
  });
  const prevCode = process.exitCode;
  try {
    const { runDiff } = await import("../../tools/cli/diff.js");
    await runDiff(argv);
  } finally {
    spy.mockRestore();
    process.exitCode = prevCode;
  }
  return chunks.join("");
}

describe("diff, handed an analysis report by mistake", () => {
  it("names the mistake instead of printing a schema dump", async () => {
    const tmp = mkdtempSync(join(tmpdir(), "vaul-diff-"));
    // The shape `analyze --format json` writes: a `run` key at the root.
    const report = { run: { result_hash: "abc", findings: [] }, ingest: { warnings: [] } };
    const a = join(tmp, "report-a.json");
    const b = join(tmp, "report-b.json");
    writeFileSync(a, JSON.stringify(report), "utf8");
    writeFileSync(b, JSON.stringify(report), "utf8");

    const err = await stderrOf([a, b]);
    expect(err).toContain("looks like an analysis report");
    expect(err, "it must point at the command that does do this").toContain("vaulytica compare");
    // And it must NOT bury the reader in the schema mismatch.
    expect(err).not.toContain("Unrecognized keys");
  });

  it("names the other two shapes this tool writes, too", async () => {
    // 🚨 The original repair recognised ONE of the three sibling shapes. A
    // verification certificate and a posture-coherence artifact still got the
    // shape dump this test exists to end — "Unrecognized keys: schema, tool,
    // input, playbook_id, …". `json-kind.ts` is the single owner that names
    // all four kinds (9.703.0).
    const tmp = mkdtempSync(join(tmpdir(), "vaul-diff3-"));
    const cases: [name: string, body: unknown, expected: string][] = [
      [
        "cert",
        { schema: "vaulytica.verification-certificate.v1", tool: {}, input: {} },
        "verification certificate",
      ],
      [
        "coh",
        { schema: "vaulytica.posture-coherence.v2", coherence_hash: "x", dimensions: [] },
        "posture-coherence artifact",
      ],
    ];
    for (const [name, body, expected] of cases) {
      const a = join(tmp, `${name}-a.json`);
      const b = join(tmp, `${name}-b.json`);
      writeFileSync(a, JSON.stringify(body), "utf8");
      writeFileSync(b, JSON.stringify(body), "utf8");
      const err = await stderrOf([a, b]);
      expect(err, `${name}: not named`).toContain(`looks like a ${expected}`);
      expect(err, `${name}: still a schema dump`).not.toContain("Unrecognized keys");
    }
  });

  it("still reports a genuine playbook schema error as one", async () => {
    // A file that is neither a report nor a valid playbook keeps the detailed
    // errors — those are the useful output when the input really is meant to
    // be a playbook.
    const tmp = mkdtempSync(join(tmpdir(), "vaul-diff2-"));
    const a = join(tmp, "pb-a.json");
    const b = join(tmp, "pb-b.json");
    writeFileSync(a, JSON.stringify({ schema_version: "9.9", id: 1 }), "utf8");
    writeFileSync(b, JSON.stringify({ schema_version: "9.9", id: 1 }), "utf8");

    const err = await stderrOf([a, b]);
    expect(err).toContain("invalid playbook");
    expect(err).not.toContain("looks like an analysis report");
  });
});
