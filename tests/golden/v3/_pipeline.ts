/**
 * v3 golden-test pipeline harness.
 *
 * Mirrors `tests/integration/_pipeline-helpers.ts` but runs the union
 * of `LAUNCH_RULES` and `V3_RULES` so v3-specific rule outputs are
 * captured in the golden snapshots.
 *
 * Inputs: `.txt` paste fixtures and `.docx` binaries under
 * `tests/golden/v3/fixtures/`. Each fixture has an optional sidecar
 * `tests/golden/v3/fixtures/<name>.playbook` containing the playbook id
 * to force — used when the auto-detector picks a v2 playbook that
 * doesn't exercise the v3 rule we are baselining.
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
const PLAYBOOK_DIR = join(__dirname, "..", "..", "..", "playbooks");
const V3_PLAYBOOK_DIR = join(__dirname, "..", "..", "..", "src", "playbooks", "v3");

let cachedPlaybooks: Playbook[] | null = null;

export async function loadAllPlaybooks(): Promise<Playbook[]> {
  if (cachedPlaybooks) return cachedPlaybooks;
  const playbooks: Playbook[] = [];
  for (const id of LAUNCH_PLAYBOOK_IDS) {
    const text = await readFile(join(PLAYBOOK_DIR, `${id}.json`), "utf8");
    playbooks.push(parsePlaybook(JSON.parse(text)));
  }
  // v3 playbooks live in a separate directory and are loaded greedily
  // so the auto-detect surface sees them. Schema-validation failures
  // are surfaced loudly — the silent-skip pattern from the early-build
  // placeholder days masked real regressions; the
  // "every v3 playbook validates" test in
  // tests/integration/playbook-matching.test.ts pins the contract,
  // and this loader now matches it.
  if (existsSync(V3_PLAYBOOK_DIR)) {
    const v3Names = (await readdir(V3_PLAYBOOK_DIR)).filter((n) => n.endsWith(".json"));
    for (const name of v3Names) {
      const text = await readFile(join(V3_PLAYBOOK_DIR, name), "utf8");
      try {
        playbooks.push(parsePlaybook(JSON.parse(text)));
      } catch (e) {
        throw new Error(
          `v3 playbook ${name} failed PlaybookSchema validation: ${e instanceof Error ? e.message : String(e)}`,
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

export async function runV3Fixture(path: string, fileName?: string): Promise<RunFixtureResult> {
  const name = fileName ?? basename(path);
  let ingest: IngestResult;
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
    ingest = {
      tree,
      source: "docx",
      word_count: countWords(tree),
      sha256: await sha256Hex(ab),
      warnings,
    };
  } else if (path.endsWith(".txt")) {
    const text = await readFile(path, "utf8");
    ingest = await ingestPaste(text);
  } else {
    throw new Error(`unsupported fixture type: ${path}`);
  }

  const dkb = loadStarterDkbSync();
  const extracted = extractAll(ingest.tree, {
    classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
  });
  const playbooks = await loadAllPlaybooks();

  // Optional sidecar overrides the auto-detector — useful when a fixture
  // is contrived to exercise one v3 ruleset and the auto-detect would
  // pick a v2 fallback.
  const forced = await readForcedPlaybook(path);

  const titleSource = ingest.tree.sections[0]?.heading ?? name;
  const bodyParts: string[] = [];
  const walkSections = (sections: import("../../../src/ingest/types.js").Section[]): void => {
    for (const s of sections) {
      for (const p of s.paragraphs) {
        for (const r of p.runs) bodyParts.push(r.text);
      }
      walkSections(s.children);
    }
  };
  walkSections(ingest.tree.sections);
  const bodyText = bodyParts.join(" ");
  const match = matchPlaybook(extracted, extracted.classified, playbooks, {
    title: titleSource,
    body_text: bodyText,
  });
  const playbookId = forced ?? match.playbook_id;
  const playbook = playbooks.find((p) => p.id === playbookId) ?? playbooks[0]!;

  const run = await runEngine({
    rules: [...LAUNCH_RULES, ...V3_RULES] as readonly Rule[],
    ctx: { tree: ingest.tree, extracted, dkb, playbook },
    source_file: { name, sha256: ingest.sha256, size_bytes: ingest.tree.sections.length },
    playbook_match_confidence: forced ? 1 : match.confidence,
    playbook_match_reasoning: forced ? `forced via sidecar to ${forced}` : match.reasoning,
    executed_at: "",
  });

  return { ingest, run, playbook };
}

async function readForcedPlaybook(fixturePath: string): Promise<string | null> {
  const sidecar = `${fixturePath}.playbook`;
  if (!existsSync(sidecar)) return null;
  return (await readFile(sidecar, "utf8")).trim();
}

export async function listV3Fixtures(dir: string): Promise<string[]> {
  if (!existsSync(dir)) return [];
  const entries = await readdir(dir);
  return entries.filter((n) => n.endsWith(".docx") || n.endsWith(".txt")).sort();
}

function basename(p: string): string {
  // Use node's path.basename to handle Windows backslash separators —
  // otherwise `source_file.name` ends up as the full Windows path and
  // poisons `result_hash` on cross-OS runs.
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
