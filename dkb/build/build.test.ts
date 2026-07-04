/**
 * Integrity gates on the DKB build orchestrator (fix-dkb-build-integrity).
 *
 * The v2026-06-28-local incident: every fetcher failed (warn-and-continue),
 * the build wrote a content-empty artifact with a valid manifest, and the
 * site shipped it. These tests pin the three guarantees that prevent a
 * recurrence: builds refuse empty content sections, refuse unacknowledged
 * shrinkage vs. the prior version, and write manifests whose refs describe
 * the exact bytes on disk.
 */

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { copyFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { runBuild } from "./build.js";
import type { ParsedRecord } from "./types.js";

const STARTER = join(process.cwd(), "dkb", "dist", "v0.0.1-starter");
const NOW = "2026-07-04T00:00:00.000Z";

const STARTER_COUNTS = {
  clauses: 30,
  jurisdictions: 12,
  definitions: 10,
  dark_patterns: 8,
  statutes: 30,
} as const;

const tmp = mkdtempSync(join(tmpdir(), "vaul-dkb-build-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

function sha256Hex(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex");
}

/** Copy the starter's five content files, optionally overriding one. */
function makeCuratedDir(name: string, override?: { file: string; contents: unknown }): string {
  const dir = join(tmp, name);
  mkdirSync(dir, { recursive: true });
  const files = [
    "dkb-clauses.json",
    "dkb-jurisdictions.json",
    "dkb-definitions.json",
    "dkb-dark-patterns.json",
    "dkb-statutes.json",
  ];
  for (const f of files) copyFileSync(join(STARTER, f), join(dir, f));
  if (override) {
    writeFileSync(join(dir, override.file), JSON.stringify(override.contents, null, 2), "utf8");
  }
  return dir;
}

describe("empty-section floor", () => {
  it("refuses to write an artifact with empty content sections, naming them", async () => {
    const outRoot = join(tmp, "out-floor");
    await expect(
      runBuild({
        records: [],
        curated_root: join(tmp, "does-not-exist"),
        out_root: outRoot,
        version: "v0001-test",
        now_iso: NOW,
      }),
    ).rejects.toThrow(/empty content section\(s\).*statutes/s);
    expect(existsSync(join(outRoot, "v0001-test"))).toBe(false);
  });
});

describe("offline build from curated sources", () => {
  const outRoot = join(tmp, "out-curated");

  it("emits the full curated content set with an honest manifest", async () => {
    const result = await runBuild({
      records: [],
      curated_root: STARTER,
      out_root: outRoot,
      version: "v0001-test",
      now_iso: NOW,
    });

    for (const [section, count] of Object.entries(STARTER_COUNTS)) {
      expect(result.manifest.files[section as keyof typeof STARTER_COUNTS].entries).toBe(count);
    }

    // Every manifest ref must describe the exact bytes written to disk —
    // the shipped incident manifest recorded sha256("[]") for files that
    // held real content.
    const outDir = join(outRoot, "v0001-test");
    for (const ref of Object.values(result.manifest.files)) {
      const bytes = readFileSync(join(outDir, ref.filename));
      expect(sha256Hex(bytes)).toBe(ref.sha256);
      expect((JSON.parse(bytes.toString("utf8")) as unknown[]).length).toBe(ref.entries);
    }

    // Curated provenance survives: the starter's source citations carry over.
    expect(result.manifest.sources.length).toBeGreaterThan(0);
  });

  it("merges fetched records into the curated baseline by id", async () => {
    const source = {
      id: "test-source",
      source: "Test Source",
      source_url: "https://example.com/",
      retrieved_at: NOW,
      license: "CC0-1.0",
      license_url: "https://creativecommons.org/publicdomain/zero/1.0/",
    };
    const records: ParsedRecord[] = [
      {
        kind: "clause",
        data: {
          id: "test-clause-fetched-1",
          category: "confidentiality",
          text: "Test clause text.",
          position: "balanced",
          deal_types: ["nda"],
          source,
        },
      },
    ];
    const result = await runBuild({
      records,
      curated_root: STARTER,
      out_root: join(tmp, "out-merge"),
      version: "v0001-test",
      now_iso: NOW,
      dry_run: true,
    });
    expect(result.clauses.length).toBe(STARTER_COUNTS.clauses + 1);
    expect(result.clauses.some((c) => c.id === "test-clause-fetched-1")).toBe(true);
    expect(result.manifest.sources.some((s) => s.id === "test-source")).toBe(true);
  });
});

describe("shrinkage gate", () => {
  const outRoot = join(tmp, "out-shrink");
  const reducedClauses = JSON.parse(
    readFileSync(join(STARTER, "dkb-clauses.json"), "utf8"),
  ) as unknown[];
  const reduced = makeCuratedDir("curated-reduced", {
    file: "dkb-clauses.json",
    contents: reducedClauses.slice(0, 12),
  });

  it("refuses an unacknowledged drop, naming section and counts", async () => {
    await runBuild({
      records: [],
      curated_root: STARTER,
      out_root: outRoot,
      version: "v0001-prior",
      now_iso: NOW,
    });
    await expect(
      runBuild({
        records: [],
        curated_root: reduced,
        out_root: outRoot,
        version: "v0002-next",
        now_iso: NOW,
        ack_path: join(tmp, "no-such-ack.yml"),
      }),
    ).rejects.toThrow(/unacknowledged shrinkage.*clauses 30 → 12/s);
    expect(existsSync(join(outRoot, "v0002-next"))).toBe(false);
  });

  it("accepts an acknowledged drop and records it in the manifest", async () => {
    const ackPath = join(tmp, "ack.yml");
    writeFileSync(
      ackPath,
      [
        "acknowledgments:",
        "  - section: clauses",
        "    new_count: 12",
        '    reason: "test: intentional reduction"',
      ].join("\n"),
      "utf8",
    );
    const result = await runBuild({
      records: [],
      curated_root: reduced,
      out_root: outRoot,
      version: "v0002-next",
      now_iso: NOW,
      ack_path: ackPath,
    });
    expect(result.manifest.shrinkage_acknowledgments).toEqual([
      {
        section: "clauses",
        prior_count: 30,
        new_count: 12,
        reason: "test: intentional reduction",
      },
    ]);
  });
});

describe("classifier vocab carry-forward", () => {
  it("reuses the prior version's trained vocab when no examples were fetched", async () => {
    const outRoot = join(tmp, "out-vocab");
    const priorDir = join(outRoot, "v0001-prior");
    mkdirSync(priorDir, { recursive: true });
    writeFileSync(
      join(priorDir, "dkb-classifier-vocab.json"),
      JSON.stringify([{ category: "confidentiality", terms: { disclose: 0.5 } }]),
      "utf8",
    );
    const result = await runBuild({
      records: [],
      curated_root: STARTER,
      out_root: outRoot,
      version: "v0002-next",
      now_iso: NOW,
      dry_run: true,
    });
    expect(result.vocab).toEqual([{ category: "confidentiality", terms: { disclose: 0.5 } }]);
    expect(result.manifest.files.classifier_vocab.entries).toBe(1);
  });
});
