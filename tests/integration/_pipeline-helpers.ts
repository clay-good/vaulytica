/**
 * Shared helpers for the full-pipeline integration tests. Replicates
 * what `src/ui/main.ts` does in the browser but Node-side, so the
 * golden-output test exercises the same code path the live UI does.
 */

import { readFile, readdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { basename as pathBasename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { parseDocxHtml } from "../../src/ingest/docx.js";
import { normalize, countWords } from "../../src/ingest/normalize.js";
import { sha256Hex } from "../../src/ingest/hash.js";
import { ingestPaste } from "../../src/ingest/paste.js";
import type { IngestResult } from "../../src/ingest/types.js";
import { extractAll } from "../../src/extract/index.js";
import { loadStarterDkbSync } from "../../src/engine/_test-fixtures.js";
import { LAUNCH_RULES, runEngine, type EngineRun } from "../../src/engine/index.js";
import {
  matchPlaybook,
  parsePlaybook,
  LAUNCH_PLAYBOOK_IDS,
  type Playbook,
} from "../../src/playbooks/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PLAYBOOK_DIR = join(__dirname, "..", "..", "playbooks");

let cachedPlaybooks: Playbook[] | null = null;

export async function loadAllPlaybooks(): Promise<Playbook[]> {
  if (cachedPlaybooks) return cachedPlaybooks;
  const playbooks: Playbook[] = [];
  for (const id of LAUNCH_PLAYBOOK_IDS) {
    const text = await readFile(join(PLAYBOOK_DIR, `${id}.json`), "utf8");
    playbooks.push(parsePlaybook(JSON.parse(text)));
  }
  cachedPlaybooks = playbooks;
  return playbooks;
}

export type RunFixtureResult = {
  ingest: IngestResult;
  run: EngineRun;
  playbook: Playbook;
  dkb: ReturnType<typeof loadStarterDkbSync>;
};

/**
 * Run the full pipeline against a fixture file. `.docx` goes through
 * `ingestDocxBuffer`; `.txt` through `ingestPaste`. Returns both the
 * ingest result and the engine run so callers can serialize / diff
 * them.
 */
export async function runFixture(path: string, fileName?: string): Promise<RunFixtureResult> {
  const name = fileName ?? basename(path);
  let ingest: IngestResult;
  let sizeBytes: number;
  if (path.endsWith(".docx")) {
    // Node mammoth doesn't accept `arrayBuffer`; pass the Node Buffer
    // directly. Then funnel through the same `parseDocxHtml` →
    // `normalize` path the browser ingest uses.
    const buf = await readFile(path);
    sizeBytes = buf.byteLength;
    const ab = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
    const mammoth = (await import("mammoth")) as unknown as {
      convertToHtml: (input: {
        buffer: Buffer;
      }) => Promise<{ value: string; messages: Array<{ type: string; message: string }> }>;
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
    sizeBytes = Buffer.byteLength(text);
    ingest = await ingestPaste(text);
  } else {
    throw new Error(`unsupported fixture type: ${path}`);
  }

  const dkb = loadStarterDkbSync();
  const extracted = extractAll(ingest.tree, {
    classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
  });
  const playbooks = await loadAllPlaybooks();

  const titleSource = ingest.tree.sections[0]?.heading ?? name;
  // Walk every section + child for the body text so distinguishing-phrase
  // matching sees the whole document, not just section[0]. Matches what
  // the browser pipeline does in src/ui/pipeline.ts.
  const bodyParts: string[] = [];
  const walkSections = (sections: import("../../src/ingest/types.js").Section[]): void => {
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
  const playbook = playbooks.find((p) => p.id === match.playbook_id) ?? playbooks[0]!;

  const run = await runEngine({
    rules: LAUNCH_RULES,
    ctx: { tree: ingest.tree, extracted, dkb, playbook },
    // The input's byte length — the same basis every product surface stamps
    // (fix-cli-browser-parity); `source_file` is inside the hashed run.
    source_file: { name, sha256: ingest.sha256, size_bytes: sizeBytes },
    playbook_match_confidence: match.confidence,
    playbook_match_reasoning: match.reasoning,
    // Empty string keeps `executed_at` out of the hash and out of the
    // golden file. The runner already blanks it for the hash but the
    // golden JSON should reflect the deterministic surface.
    executed_at: "",
  });

  return { ingest, run, playbook, dkb };
}

export async function listFixtures(contractsDir: string): Promise<string[]> {
  if (!existsSync(contractsDir)) return [];
  const entries = await readdir(contractsDir);
  return entries
    .filter((n) => n.endsWith(".docx") || n.endsWith(".txt") || n.endsWith(".pdf"))
    .sort();
}

function basename(p: string): string {
  // Use node's path.basename so Windows backslash separators don't leak
  // the full path into `source_file.name` (breaks cross-OS result_hash).
  return pathBasename(p);
}
