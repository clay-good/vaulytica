/**
 * v4 multi-document bundle golden test (spec-v4.md §§10–11 / Step 61).
 *
 * Each subdirectory under `tests/golden/v4/bundles/<bundle-name>/`
 * holds 2+ fixture files (`.txt` or `.docx`) plus optional
 * `<file>.playbook` sidecars. The harness ingests every file, runs
 * the full v4 per-doc pipeline (LAUNCH + V3 + V4 rules), then runs
 * the cross-document consistency engine (`runEngineMulti`).
 *
 * The bundle golden at `tests/golden/v4/bundle-expected/<name>.json`
 * records:
 *   - per-document `result_hash` + finding count
 *   - the consistency `result_hash`, finding count, rule_ids fired,
 *     and total execution-log entry count.
 *
 * We do NOT inline the full per-document EngineRun in the bundle
 * golden — those are already covered by the per-doc fixtures under
 * `fixtures/`. The bundle golden's job is to lock down the
 * cross-document semantics + the bundle fingerprint.
 *
 * Sanity guards (per bundle):
 *   - At least 2 documents.
 *   - The consistency run must emit at least one CROSS-* finding OR
 *     log every shipped CROSS rule as "no-op" (we lock down which).
 *
 * Regeneration: set `VAULYTICA_REGEN_GOLDEN=1`.
 */

import { describe, expect, it } from "vitest";
import { existsSync } from "node:fs";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  LAUNCH_RULES,
  V3_RULES,
  V4_RULES,
  type Rule,
} from "../../../src/engine/index.js";
import { runEngineMulti, stableStringify } from "../../../src/engine/runner.js";
import {
  ALL_CONSISTENCY_RULES,
  type ConsistencyFinding,
  type ConsistencyRun,
} from "../../../src/engine/consistency/index.js";
import { loadStarterDkbSync } from "../../../src/engine/_test-fixtures.js";
import { extractAll } from "../../../src/extract/index.js";
import { matchPlaybook } from "../../../src/playbooks/index.js";

import { ingestFixture, listV4Bundles, loadAllPlaybooks } from "./_pipeline.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const BUNDLES = join(__dirname, "bundles");
const EXPECTED = join(__dirname, "bundle-expected");
const REGEN = process.env.VAULYTICA_REGEN_GOLDEN === "1";

const bundles = await listV4Bundles(BUNDLES);

describe("v4 bundle golden-output", () => {
  it("at least one v4 bundle is present", () => {
    expect(
      bundles.length,
      "drop a folder under tests/golden/v4/bundles/<name>/ with 2+ fixtures",
    ).toBeGreaterThan(0);
  });

  if (REGEN) {
    it("regenerates every v4 bundle golden", async () => {
      await mkdir(EXPECTED, { recursive: true });
      for (const name of bundles) {
        const result = await runBundle(name);
        await writeFile(
          join(EXPECTED, `${name}.json`),
          stableStringify(summarize(result)),
        );
      }
      for (const name of bundles) {
        expect(existsSync(join(EXPECTED, `${name}.json`)), name).toBe(true);
      }
    });
    return;
  }

  for (const name of bundles) {
    it(`bundle ${name} matches its golden`, async () => {
      const expectedPath = join(EXPECTED, `${name}.json`);
      if (!existsSync(expectedPath)) {
        throw new Error(
          `Missing golden for bundle ${name}. Run with VAULYTICA_REGEN_GOLDEN=1 to create it.`,
        );
      }
      const expected = JSON.parse(await readFile(expectedPath, "utf8"));
      const got = summarize(await runBundle(name));
      expect(stableStringify(got)).toBe(stableStringify(expected));
    });

    it(`bundle ${name} is deterministic across two in-process runs`, async () => {
      const a = summarize(await runBundle(name));
      const b = summarize(await runBundle(name));
      expect(stableStringify(b)).toBe(stableStringify(a));
    });

    it(`bundle ${name} satisfies the sanity guard (>=2 docs)`, async () => {
      const result = await runBundle(name);
      expect(result.per_document.length, name).toBeGreaterThanOrEqual(2);
    });
  }
});

type BundleResult = {
  per_document: Array<{ doc_id: string; source_file_name: string; run: { result_hash: string; findings: unknown[] } }>;
  consistency: ConsistencyRun;
};

async function runBundle(name: string): Promise<BundleResult> {
  const dir = join(BUNDLES, name);
  const entries = (await readdir(dir))
    .filter((n) => n.endsWith(".txt") || n.endsWith(".docx"))
    .sort();
  if (entries.length < 2) {
    throw new Error(`bundle ${name} has < 2 documents`);
  }
  const dkb = loadStarterDkbSync();
  const playbooks = await loadAllPlaybooks();

  const documents: Parameters<typeof runEngineMulti>[0]["documents"] = [];
  for (const entry of entries) {
    const fixturePath = join(dir, entry);
    const ingest = await ingestFixture(fixturePath);
    const extracted = extractAll(ingest.tree, {
      classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
    });
    const titleSource = ingest.tree.sections[0]?.heading ?? entry;
    const bodyParts: string[] = [];
    const walk = (sections: import("../../../src/ingest/types.js").Section[]): void => {
      for (const s of sections) {
        for (const p of s.paragraphs) for (const r of p.runs) bodyParts.push(r.text);
        walk(s.children);
      }
    };
    walk(ingest.tree.sections);
    const sidecar = `${fixturePath}.playbook`;
    const forced = existsSync(sidecar)
      ? (await readFile(sidecar, "utf8")).trim()
      : null;
    const match = matchPlaybook(extracted, extracted.classified, playbooks, {
      title: titleSource,
      body_text: bodyParts.join(" "),
    });
    const playbookId = forced ?? match.playbook_id;
    const playbook = playbooks.find((p) => p.id === playbookId) ?? playbooks[0]!;

    documents.push({
      doc_id: stripExt(entry),
      source_file_name: entry,
      run: {
        rules: [...LAUNCH_RULES, ...V3_RULES, ...V4_RULES] as readonly Rule[],
        ctx: { tree: ingest.tree, extracted, dkb, playbook },
        source_file: {
          name: entry,
          sha256: ingest.sha256,
          size_bytes: ingest.tree.sections.length,
        },
        playbook_match_confidence: forced ? 1 : match.confidence,
        playbook_match_reasoning: forced
          ? `forced via sidecar to ${forced}`
          : match.reasoning,
        executed_at: "",
      },
    });
  }

  const { per_document, consistency } = await runEngineMulti({
    documents,
    dkb,
    consistencyRules: ALL_CONSISTENCY_RULES,
    executed_at: "",
  });
  return {
    per_document: per_document.map((d) => ({
      doc_id: d.doc_id,
      source_file_name: d.source_file_name,
      run: { result_hash: d.run.result_hash, findings: d.run.findings },
    })),
    consistency,
  };
}

function summarize(result: BundleResult) {
  const consistency_finding_ids = result.consistency.findings
    .map((f: ConsistencyFinding) => f.rule_id)
    .slice()
    .sort();
  return {
    per_document: result.per_document.map((d) => ({
      doc_id: d.doc_id,
      source_file_name: d.source_file_name,
      result_hash: d.run.result_hash,
      finding_count: d.run.findings.length,
    })),
    consistency: {
      result_hash: result.consistency.result_hash,
      finding_count: result.consistency.findings.length,
      execution_log_count: result.consistency.execution_log.length,
      finding_rule_ids: consistency_finding_ids,
    },
  };
}

function stripExt(name: string): string {
  const i = name.lastIndexOf(".");
  return i > 0 ? name.slice(0, i) : name;
}
