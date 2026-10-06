import { afterAll, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expandRoundArchives, isSequenceCommand, roundFiles } from "./round-archive.js";
import { compareCoherenceTrendArtifacts } from "./coherence-trend.js";
import {
  bundlePostureCoherence,
  buildPostureCoherenceJson,
} from "../../src/report/posture-coherence.js";
import type { NegotiationTier } from "../../src/playbooks/custom-interpreter.js";

const dirs: string[] = [];
afterAll(async () => Promise.all(dirs.map((d) => rm(d, { recursive: true, force: true }))));

async function archive(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "vaulytica-rounds-"));
  dirs.push(dir);
  for (const [name, body] of Object.entries(files)) await writeFile(join(dir, name), body);
  return dir;
}

const LADDER = "a".repeat(64);
const round = async (cap: NegotiationTier) =>
  buildPostureCoherenceJson(
    await bundlePostureCoherence([
      {
        document: "order.docx",
        posture: {
          positions: [{ dimension: "Cap", tier: cap }],
          counts: { ideal: 0, acceptable: 0, below_acceptable: 0, unevaluable: 0 },
          posture_hash: "test",
        },
      },
    ]),
    LADDER,
  );

describe("roundFiles — round order read from the file names", () => {
  it("orders round2 before round10, where a lexical sort would not", async () => {
    const dir = await archive({
      "round10.coherence.json": "",
      "round2.coherence.json": "",
      "round1.coherence.json": "",
      "notes.txt": "",
    });
    expect((await roundFiles(dir)).map((f) => f.slice(dir.length + 1))).toEqual([
      "round1.coherence.json",
      "round2.coherence.json",
      "round10.coherence.json",
    ]);
  });

  it("refuses a name that carries no round number", async () => {
    const dir = await archive({ "round1.coherence.json": "", "final.coherence.json": "" });
    await expect(roundFiles(dir)).rejects.toThrow(/final\.coherence\.json carries no round number/);
  });

  it("refuses two names that carry the same round number", async () => {
    const dir = await archive({ "round-1.coherence.json": "", "round-01.coherence.json": "" });
    await expect(roundFiles(dir)).rejects.toThrow(/carry the same round number/);
  });

  it("refuses a directory with no artifacts", async () => {
    const dir = await archive({ "notes.txt": "" });
    await expect(roundFiles(dir)).rejects.toThrow(/no \*\.coherence\.json files/);
  });
});

describe("expandRoundArchives — a directory on a sequence command's argv", () => {
  it("expands in place, keeps flags and a --format value, and reports the order", async () => {
    const dir = await archive({ "r2.coherence.json": "", "r1.coherence.json": "" });
    const reported: string[][] = [];
    const argv = await expandRoundArchives(["--format", "json", dir, "--fail-on-x"], (_d, f) =>
      reported.push(f),
    );
    expect(argv).toEqual([
      "--format",
      "json",
      join(dir, "r1.coherence.json"),
      join(dir, "r2.coherence.json"),
      "--fail-on-x",
    ]);
    expect(reported).toEqual([[join(dir, "r1.coherence.json"), join(dir, "r2.coherence.json")]]);
  });

  it("gives the trend the same answer as the files listed in order", async () => {
    // A below-floor dip in round 2 that recovers by round 10: a whipsaw. Sorted
    // lexically (1, 10, 2) the same archive would read as a different deal.
    const texts = {
      "round1.coherence.json": await round("acceptable"),
      "round2.coherence.json": await round("below-acceptable"),
      "round10.coherence.json": await round("ideal"),
    };
    const dir = await archive(texts);
    const files = await expandRoundArchives([dir]);
    const fromDir = await compareCoherenceTrendArtifacts(
      await Promise.all(files.map((f) => readFile(f, "utf8"))),
      "json",
    );
    const listed = await compareCoherenceTrendArtifacts(
      [
        texts["round1.coherence.json"],
        texts["round2.coherence.json"],
        texts["round10.coherence.json"],
      ],
      "json",
    );
    expect(fromDir).toEqual(listed);
    expect(fromDir.ok && fromDir.regressed).toBe(true);
  });
});

describe("isSequenceCommand — every command that walks a round archive", () => {
  it("covers each command the usage lists over <r1.coherence.json> <r2.coherence.json>", () => {
    // Derived from the help text so a new walker cannot be added without the
    // directory form reaching it.
    const usage = readFileSync(join(process.cwd(), "tools", "cli", "run.ts"), "utf8");
    const commands = [
      ...usage.matchAll(/^\s{2}([a-z-]+) <r1\.coherence\.json> <r2\.coherence\.json>/gm),
    ].map((m) => m[1]!);
    expect(commands.length).toBeGreaterThanOrEqual(25);
    expect(commands.filter((c) => !isSequenceCommand(c))).toEqual([]);
    expect(isSequenceCommand("analyze")).toBe(false);
    expect(isSequenceCommand("compare-coherence")).toBe(false);
  });
});

describe("runRoundTrend — the browser reads a round archive as the CLI does", () => {
  const LADDER_B = "b".repeat(64);

  it("orders by file name and returns the JSON coherence-trend prints", async () => {
    const { runRoundTrend } = await import("../../src/ui/pipeline.js");
    const texts = {
      "round1.coherence.json": await round("acceptable"),
      "round2.coherence.json": await round("below-acceptable"),
      "round10.coherence.json": await round("ideal"),
    };
    // Dropped in any order — a browser hands files over as the user picked them.
    const trend = await runRoundTrend(
      ["round10.coherence.json", "round1.coherence.json", "round2.coherence.json"].map((name) => ({
        name,
        text: texts[name as keyof typeof texts],
      })),
    );
    const cli = await compareCoherenceTrendArtifacts(Object.values(texts), "json");
    expect(trend.ok && cli.ok).toBe(true);
    if (!trend.ok || !cli.ok) return;
    expect(trend.names).toEqual(Object.keys(texts));
    expect(trend.json).toBe(cli.output);
    expect(trend.trajectory.fronts[0]!.trajectory).toBe("whipsaw");
    expect(trend.ladderNote).toBeNull();
  });

  it("refuses rounds scored against different playbooks, naming both files", async () => {
    const { runRoundTrend } = await import("../../src/ui/pipeline.js");
    const other = buildPostureCoherenceJson(
      await bundlePostureCoherence([
        {
          document: "order.docx",
          posture: {
            positions: [{ dimension: "Cap", tier: "ideal" }],
            counts: { ideal: 1, acceptable: 0, below_acceptable: 0, unevaluable: 0 },
            posture_hash: "t",
          },
        },
      ]),
      LADDER_B,
    );
    const trend = await runRoundTrend([
      { name: "r1.coherence.json", text: await round("acceptable") },
      { name: "r2.coherence.json", text: other },
    ]);
    expect(!trend.ok && trend.errors.join(" ")).toMatch(
      /r1\.coherence\.json and r2\.coherence\.json were scored against different playbooks/,
    );
  });

  it("refuses a tampered round, an unordered archive, and a single round", async () => {
    const { runRoundTrend } = await import("../../src/ui/pipeline.js");
    const good = await round("acceptable");
    const tampered = good.replace('"acceptable"', '"ideal"');
    const t = await runRoundTrend([
      { name: "r1.coherence.json", text: good },
      { name: "r2.coherence.json", text: tampered },
    ]);
    expect(!t.ok && t.errors[0]).toMatch(/^r2\.coherence\.json: /);
    const u = await runRoundTrend([
      { name: "r1.coherence.json", text: good },
      { name: "final.coherence.json", text: good },
    ]);
    expect(!u.ok && u.errors[0]).toMatch(/final\.coherence\.json carries no round number/);
    const one = await runRoundTrend([{ name: "r1.coherence.json", text: good }]);
    expect(one.ok).toBe(false);
  });
});
