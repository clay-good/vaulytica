/**
 * CLI stream contract (fix-cli-json-purity): when a machine-readable
 * format (`json`, `sarif`, `csv`) is selected, stdout carries exactly one
 * serialized artifact — every human summary, note, and progress line goes
 * to stderr. Before this fix, `analyze x.docx --format json | jq .` failed
 * at line 1 because the per-file summary line printed to stdout ahead of
 * the JSON document (and `--format csv > out.csv` shipped the summary as
 * row 1 of the CSV).
 *
 * The sweep is self-maintaining: the subcommand list is parsed from
 * `run.ts`'s own dispatch switch, so a new subcommand that ships without
 * an entry here fails the coverage assertion by name.
 */

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

import {
  bundlePostureCoherence,
  buildPostureCoherenceJson,
  type CoherenceInput,
} from "../../src/report/posture-coherence.js";
import type {
  NegotiationPosture,
  NegotiationTier,
} from "../../src/playbooks/custom-interpreter.js";

const REPO_ROOT = process.cwd();
const RUN_TS = join(REPO_ROOT, "tools", "cli", "run.ts");
const TXT_FIXTURE = join(REPO_ROOT, "tests", "fixtures", "contracts", "pasted-mutual-nda.txt");

const tmp = mkdtempSync(join(tmpdir(), "vaul-stream-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

// --- capture helpers -------------------------------------------------------

type Captured = { stdout: string; stderr: string };

/** Run a CLI handler in-process, capturing the two streams separately. */
async function capture(fn: () => Promise<void>): Promise<Captured> {
  const out: string[] = [];
  const err: string[] = [];
  const realOut = process.stdout.write.bind(process.stdout);
  const realErr = process.stderr.write.bind(process.stderr);
  const realExit = process.exitCode;
  process.stdout.write = ((s: string | Uint8Array) => {
    out.push(String(s));
    return true;
  }) as typeof process.stdout.write;
  process.stderr.write = ((s: string | Uint8Array) => {
    err.push(String(s));
    return true;
  }) as typeof process.stderr.write;
  try {
    await fn();
  } finally {
    process.stdout.write = realOut;
    process.stderr.write = realErr;
    process.exitCode = realExit; // gates may set it; never leak into vitest
  }
  return { stdout: out.join(""), stderr: err.join("") };
}

function expectPureJson(cmd: string, c: Captured): void {
  expect(
    () => JSON.parse(c.stdout) as unknown,
    `${cmd}: stdout is not a single JSON document:\n${c.stdout.slice(0, 200)}`,
  ).not.toThrow();
}

// --- coherence artifact fixtures (unpinned v1 → every command emits the note)

function posture(map: Record<string, NegotiationTier>): NegotiationPosture {
  return {
    positions: Object.entries(map).map(([dimension, tier]) => ({ dimension, tier })),
    counts: { ideal: 0, acceptable: 0, below_acceptable: 0, unevaluable: 0 },
    posture_hash: "test",
  };
}
const bundle = (...docs: Array<[string, Record<string, NegotiationTier>]>): CoherenceInput[] =>
  docs.map(([document, map]) => ({ document, posture: posture(map) }));

async function writeCoherenceArtifacts(): Promise<string[]> {
  const tiers: NegotiationTier[][] = [
    ["acceptable", "acceptable"],
    ["below-acceptable", "acceptable"],
    ["acceptable", "below-acceptable"],
  ];
  const paths: string[] = [];
  for (let i = 0; i < tiers.length; i++) {
    const c = await bundlePostureCoherence(
      bundle(
        ["msa.docx", { Cap: tiers[i]![0]!, Term: tiers[i]![1]! }],
        ["order.docx", { Cap: "ideal", Term: "ideal" }],
      ),
    );
    const p = join(tmp, `round-${i + 1}.coherence.json`);
    // Unpinned (v1) artifact: every consumer proceeds with an advisory
    // ladder note — which must land on stderr, never inside the JSON.
    writeFileSync(p, buildPostureCoherenceJson(c, null), "utf8");
    paths.push(p);
  }
  return paths;
}

// --- the sweep --------------------------------------------------------------

/**
 * Every subcommand in run.ts's dispatch switch (parsed from source). The
 * dispatch cases are uniquely `case "<cmd>": return run<Handler>(rest)`,
 * which distinguishes them from format/flag switches elsewhere in the file.
 */
function dispatchedCommands(): string[] {
  const source = readFileSync(RUN_TS, "utf8");
  const cmds = [...source.matchAll(/case "([a-z][a-z-]*)":\s*\n\s*return run/g)].map((m) => m[1]!);
  return [...new Set(cmds)];
}

// Static import map (vite forbids variable dynamic imports). Completeness is
// enforced below: every command in run.ts's dispatch switch must appear here
// (or in the non-artifact set), so a new subcommand fails the sweep by name.
const COHERENCE_IMPORTS: Record<string, () => Promise<Record<string, unknown>>> = {
  "compare-coherence": () => import("../../tools/cli/compare-coherence.js"),
  "coherence-trend": () => import("../../tools/cli/coherence-trend.js"),
  "coherence-shift-trend": () => import("../../tools/cli/coherence-shift-trend.js"),
  "coherence-arc": () => import("../../tools/cli/coherence-arc.js"),
  "coherence-exposure": () => import("../../tools/cli/coherence-exposure.js"),
  "coherence-persistence": () => import("../../tools/cli/coherence-persistence.js"),
  "coherence-breadth": () => import("../../tools/cli/coherence-breadth.js"),
  "coherence-recurrence": () => import("../../tools/cli/coherence-recurrence.js"),
  "coherence-volatility": () => import("../../tools/cli/coherence-volatility.js"),
  "coherence-synchrony": () => import("../../tools/cli/coherence-synchrony.js"),
  "coherence-settling": () => import("../../tools/cli/coherence-settling.js"),
  "coherence-onset": () => import("../../tools/cli/coherence-onset.js"),
  "coherence-latency": () => import("../../tools/cli/coherence-latency.js"),
  "coherence-concurrency": () => import("../../tools/cli/coherence-concurrency.js"),
  "coherence-relapse": () => import("../../tools/cli/coherence-relapse.js"),
  "coherence-tenure": () => import("../../tools/cli/coherence-tenure.js"),
  "coherence-affinity": () => import("../../tools/cli/coherence-affinity.js"),
  "coherence-recovery-affinity": () => import("../../tools/cli/coherence-recovery-affinity.js"),
  "coherence-opposition": () => import("../../tools/cli/coherence-opposition.js"),
  "coherence-precedence": () => import("../../tools/cli/coherence-precedence.js"),
  "coherence-concession": () => import("../../tools/cli/coherence-concession.js"),
  "coherence-recovery-order": () => import("../../tools/cli/coherence-recovery-order.js"),
  "coherence-weak-front": () => import("../../tools/cli/coherence-weak-front.js"),
  "coherence-cadence": () => import("../../tools/cli/coherence-cadence.js"),
  "coherence-duration": () => import("../../tools/cli/coherence-duration.js"),
  "coherence-durability": () => import("../../tools/cli/coherence-durability.js"),
  "coherence-chain": () => import("../../tools/cli/coherence-chain.js"),
  "coherence-recovery-chain": () => import("../../tools/cli/coherence-recovery-chain.js"),
  "coherence-matrix": () => import("../../tools/cli/coherence-matrix.js"),
};

describe("CLI stream contract (machine formats own stdout)", () => {
  it("covers every dispatched subcommand", () => {
    const covered = new Set([
      "analyze",
      "diff",
      "compare",
      "verify", // no machine format: human receipt text only
      ...Object.keys(COHERENCE_IMPORTS),
    ]);
    const missing = dispatchedCommands().filter((c) => !covered.has(c));
    expect(missing, `new subcommand(s) not covered by the stream-contract sweep`).toEqual([]);
  });

  it("every coherence subcommand emits pure JSON on stdout, notes on stderr", async () => {
    const artifacts = await writeCoherenceArtifacts();
    const commands = Object.keys(COHERENCE_IMPORTS);
    expect(commands.length).toBeGreaterThanOrEqual(29);
    for (const cmd of commands) {
      // Handler naming convention: coherence-weak-front → runCoherenceWeakFront
      // in tools/cli/coherence-weak-front.ts (same for compare-coherence).
      const handlerName =
        "run" + cmd.replace(/(^|-)([a-z])/g, (_m, _d, ch: string) => ch.toUpperCase());
      const mod = (await COHERENCE_IMPORTS[cmd]!()) as Record<
        string,
        (argv: string[]) => Promise<void>
      >;
      const handler = mod[handlerName];
      expect(handler, `${cmd}: expected export ${handlerName}`).toBeTypeOf("function");
      const argv =
        cmd === "compare-coherence"
          ? [artifacts[0]!, artifacts[1]!, "--format", "json"]
          : [...artifacts, "--format", "json"];
      const c = await capture(() => handler!(argv));
      expectPureJson(cmd, c);
      expect(c.stderr, `${cmd}: unpinned-artifact ladder note must go to stderr`).toContain(
        "note:",
      );
    }
  });

  it("analyze --format json: stdout parses, summary line on stderr", async () => {
    const { runAnalyze } = await import("../../tools/cli/run.js");
    const c = await capture(() => runAnalyze([TXT_FIXTURE, "--format", "json"]));
    expectPureJson("analyze json", c);
    expect(c.stderr).toMatch(/\[mutual-nda\]\s+\d+C \d+W \d+I/);
    expect(c.stdout).not.toContain("[mutual-nda]");
  });

  it("analyze --format csv: stdout begins with the CSV header row", async () => {
    const { runAnalyze } = await import("../../tools/cli/run.js");
    const c = await capture(() => runAnalyze([TXT_FIXTURE, "--format", "csv"]));
    expect(c.stdout.startsWith("severity,rule_id,")).toBe(true);
    expect(c.stderr).toContain("[mutual-nda]");
  });

  it("analyze --format sarif: stdout parses as SARIF JSON", async () => {
    const { runAnalyze } = await import("../../tools/cli/run.js");
    const c = await capture(() => runAnalyze([TXT_FIXTURE, "--format", "sarif"]));
    expectPureJson("analyze sarif", c);
    expect((JSON.parse(c.stdout) as { version?: string }).version).toBeDefined();
  });

  it("analyze --format md (human format): summary stays on stdout", async () => {
    const { runAnalyze } = await import("../../tools/cli/run.js");
    const c = await capture(() => runAnalyze([TXT_FIXTURE, "--format", "md"]));
    expect(c.stdout).toContain("[mutual-nda]");
  });

  it("compare --format json emits pure JSON on stdout", async () => {
    const { runCompare } = await import("../../tools/cli/compare.js");
    const c = await capture(() => runCompare([TXT_FIXTURE, TXT_FIXTURE, "--format", "json"]));
    expectPureJson("compare", c);
  });

  it("diff --format json emits pure JSON on stdout", async () => {
    const playbook = {
      schema_version: "1.0",
      catalog_version: "1.0.0",
      id: "stream-test",
      name: "Stream Test",
      description: "Stream contract fixture",
      custom_rules: [
        {
          id: "c1",
          title: "Indemnity present",
          description: "An indemnification clause must be present.",
          severity: "warning",
          assert: { kind: "clause_present", pattern: "indemnification" },
        },
      ],
    };
    const a = join(tmp, "pb-a.json");
    const b = join(tmp, "pb-b.json");
    writeFileSync(a, JSON.stringify(playbook), "utf8");
    writeFileSync(b, JSON.stringify({ ...playbook, name: "Stream Test B" }), "utf8");
    const { runDiff } = await import("../../tools/cli/diff.js");
    const c = await capture(() => runDiff([a, b, "--format", "json"]));
    expectPureJson("diff", c);
  });
});
