/**
 * v4 golden-test pipeline harness (spec-v4.md Part VI / Step 61).
 *
 * Mirrors `tests/golden/v3/_pipeline.ts` but additionally loads every
 * v4 playbook under `src/playbooks/v4/` and runs the union of
 * `LAUNCH_RULES + V3_RULES + V4_RULES` so v4 sub-domain rule outputs
 * appear in the golden snapshots.
 *
 * Multi-document bundles (the consistency-engine side of v4 §10) are
 * handled in `./bundle.test.ts` via `runEngineMulti` over a folder of
 * fixtures under `bundles/<bundle-name>/`.
 */

import { readFile, readdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { basename as pathBasename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { parseDocxHtml } from "../../../src/ingest/docx.js";
import { normalize, countWords } from "../../../src/ingest/normalize.js";
import { sha256Hex } from "../../../src/ingest/hash.js";
import { ingestPaste } from "../../../src/ingest/paste.js";
import type { IngestResult } from "../../../src/ingest/types.js";
import { extractAll } from "../../../src/extract/index.js";
import { loadStarterDkbSync } from "../../../src/engine/_test-fixtures.js";
import {
  LAUNCH_RULES,
  V3_RULES,
  V4_RULES,
  runEngine,
  type EngineRun,
  type Rule,
} from "../../../src/engine/index.js";
import {
  matchPlaybook,
  parsePlaybook,
  LAUNCH_PLAYBOOK_IDS,
  type Playbook,
} from "../../../src/playbooks/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..", "..", "..");
const PLAYBOOK_DIR = join(REPO_ROOT, "playbooks");
const V3_PLAYBOOK_DIR = join(REPO_ROOT, "src", "playbooks", "v3");
const V4_PLAYBOOK_DIR = join(REPO_ROOT, "src", "playbooks", "v4");

let cachedPlaybooks: Playbook[] | null = null;

export async function loadAllPlaybooks(): Promise<Playbook[]> {
  if (cachedPlaybooks) return cachedPlaybooks;
  const playbooks: Playbook[] = [];
  for (const id of LAUNCH_PLAYBOOK_IDS) {
    const text = await readFile(join(PLAYBOOK_DIR, `${id}.json`), "utf8");
    playbooks.push(parsePlaybook(JSON.parse(text)));
  }
  // Schema-validation failures are surfaced loudly. The
  // "every v3 / v4 playbook validates" tests in
  // tests/integration/playbook-matching.test.ts pin the contract;
  // this loader matches it so a regression doesn't silently shrink
  // the candidate set for the v4 bundle pipeline.
  for (const dir of [V3_PLAYBOOK_DIR, V4_PLAYBOOK_DIR]) {
    if (!existsSync(dir)) continue;
    const names = (await readdir(dir)).filter((n) => n.endsWith(".json"));
    for (const name of names) {
      const text = await readFile(join(dir, name), "utf8");
      try {
        playbooks.push(parsePlaybook(JSON.parse(text)));
      } catch (e) {
        throw new Error(
          `playbook ${name} (under ${dir}) failed PlaybookSchema validation: ${e instanceof Error ? e.message : String(e)}`,
          { cause: e },
        );
      }
    }
  }
  cachedPlaybooks = playbooks;
  return playbooks;
}

export type RunFixtureResult = {
  ingest: IngestResult;
  run: EngineRun;
  playbook: Playbook;
};

export async function ingestFixture(path: string): Promise<IngestResult> {
  if (path.endsWith(".docx")) {
    const buf = await readFile(path);
    const ab = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
    const mammoth = (await import("mammoth")) as unknown as {
      convertToHtml: (input: { buffer: Buffer }) => Promise<{
        value: string;
        messages: Array<{ type: string; message: string }>;
      }>;
    };
    const result = await mammoth.convertToHtml({ buffer: buf });
    const warnings = result.messages
      .filter((m) => m.type === "warning" || m.type === "error")
      .map((m) => `mammoth: ${m.message}`);
    const tree = normalize(parseDocxHtml(result.value));
    return {
      tree,
      source: "docx",
      word_count: countWords(tree),
      sha256: await sha256Hex(ab),
      warnings,
    };
  }
  if (path.endsWith(".txt")) {
    const text = await readFile(path, "utf8");
    return ingestPaste(text);
  }
  throw new Error(`unsupported fixture type: ${path}`);
}

export async function runV4Fixture(path: string, fileName?: string): Promise<RunFixtureResult> {
  const name = fileName ?? basename(path);
  const ingest = await ingestFixture(path);

  const dkb = loadStarterDkbSync();
  const extracted = extractAll(ingest.tree, {
    classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
  });
  const playbooks = await loadAllPlaybooks();

  const forced = await readForcedPlaybook(path);
  const { titleSource, bodyText } = collectTitleAndBody(ingest, name);
  const match = matchPlaybook(extracted, extracted.classified, playbooks, {
    title: titleSource,
    body_text: bodyText,
  });
  const playbookId = forced ?? match.playbook_id;
  const playbook = playbooks.find((p) => p.id === playbookId) ?? playbooks[0]!;

  const run = await runEngine({
    rules: [...LAUNCH_RULES, ...V3_RULES, ...V4_RULES] as readonly Rule[],
    ctx: { tree: ingest.tree, extracted, dkb, playbook },
    source_file: { name, sha256: ingest.sha256, size_bytes: ingest.tree.sections.length },
    playbook_match_confidence: forced ? 1 : match.confidence,
    playbook_match_reasoning: forced
      ? `forced via sidecar to ${forced}`
      : match.reasoning,
    executed_at: "",
  });

  return { ingest, run, playbook };
}

function collectTitleAndBody(
  ingest: IngestResult,
  name: string,
): { titleSource: string; bodyText: string } {
  const titleSource = ingest.tree.sections[0]?.heading ?? name;
  const bodyParts: string[] = [];
  const walk = (sections: import("../../../src/ingest/types.js").Section[]): void => {
    for (const s of sections) {
      for (const p of s.paragraphs) for (const r of p.runs) bodyParts.push(r.text);
      walk(s.children);
    }
  };
  walk(ingest.tree.sections);
  return { titleSource, bodyText: bodyParts.join(" ") };
}

async function readForcedPlaybook(fixturePath: string): Promise<string | null> {
  const sidecar = `${fixturePath}.playbook`;
  if (!existsSync(sidecar)) return null;
  return (await readFile(sidecar, "utf8")).trim();
}

export async function listV4Fixtures(dir: string): Promise<string[]> {
  if (!existsSync(dir)) return [];
  const entries = await readdir(dir);
  return entries.filter((n) => n.endsWith(".docx") || n.endsWith(".txt")).sort();
}

export async function listV4Bundles(dir: string): Promise<string[]> {
  if (!existsSync(dir)) return [];
  const entries = await readdir(dir, { withFileTypes: true });
  return entries.filter((e) => e.isDirectory()).map((e) => e.name).sort();
}

function basename(p: string): string {
  // Use node's path.basename so Windows backslash separators don't leak
  // the full path into `source_file.name` (breaks cross-OS result_hash).
  return pathBasename(p);
}

/**
 * Normalize an EngineRun for golden comparison: drop the per-execution
 * elapsed times. The runner already blanks them for the hash, but the
 * stored golden should never record them either.
 */
export function normalizeForGolden(run: EngineRun): EngineRun {
  return {
    ...run,
    executed_at: "",
    execution_log: run.execution_log.map((e) => ({ ...e, elapsed_ms: 0 })),
  };
}
