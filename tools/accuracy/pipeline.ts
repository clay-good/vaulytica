/**
 * Node-side full-catalog pipeline for the accuracy harness (spec-v5 §9, Step 71).
 *
 * "The harness must call the exact ingest → extract → classify → engine path
 * the browser uses, so a measured number reflects shipped behavior, not a
 * test-only shortcut." This module composes the same `src/` functions
 * `src/ui/pipeline.ts` does (no logic is re-implemented here — only the
 * orchestration is mirrored), but synchronously and over the local
 * filesystem, with no network and no DOM.
 *
 * Build-and-CI-only. Imported by the harness and its tests; never by `src/`.
 */

import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ingestPaste } from "../../src/ingest/paste.js";
import { extractAll } from "../../src/extract/index.js";
import { loadStarterDkbSync } from "../../src/engine/_test-fixtures.js";
import {
  LAUNCH_RULES,
  V3_RULES,
  V4_RULES,
  runEngine,
  type EngineRun,
  type Rule,
} from "../../src/engine/index.js";
import {
  matchPlaybook,
  parsePlaybook,
  LAUNCH_PLAYBOOK_IDS,
  type Playbook,
} from "../../src/playbooks/index.js";
import { selectMatchCandidates } from "../../src/ui/playbook-candidates.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..", "..");
const PLAYBOOK_DIR = join(REPO_ROOT, "playbooks");

export type AccuracyDeps = {
  dkb: ReturnType<typeof loadStarterDkbSync>;
  launchPlaybooks: Playbook[];
  extendedPlaybooks: Playbook[];
  /** The full live rule catalog (LAUNCH + V3 + V4), exactly as the UI runs it. */
  rules: readonly Rule[];
};

let cached: AccuracyDeps | null = null;

/** Load the engine dependencies once. The DKB is the committed starter (the
 * same load path the engine's integration tests use); the scoreboard stamps
 * `dkb.manifest.version` so a published number is always reproducible. */
export async function loadAccuracyDeps(): Promise<AccuracyDeps> {
  if (cached) return cached;
  const dkb = loadStarterDkbSync();
  const launchPlaybooks: Playbook[] = [];
  for (const id of LAUNCH_PLAYBOOK_IDS) {
    const text = await readFile(join(PLAYBOOK_DIR, `${id}.json`), "utf8");
    launchPlaybooks.push(parsePlaybook(JSON.parse(text)));
  }
  let extendedPlaybooks: Playbook[] = [];
  try {
    const ext = JSON.parse(await readFile(join(PLAYBOOK_DIR, "extended.json"), "utf8"));
    extendedPlaybooks = (ext as unknown[]).map((p) => parsePlaybook(p));
  } catch {
    extendedPlaybooks = [];
  }
  cached = {
    dkb,
    launchPlaybooks,
    extendedPlaybooks,
    rules: [...LAUNCH_RULES, ...V3_RULES, ...V4_RULES] as readonly Rule[],
  };
  return cached;
}

export type DocumentRun = {
  /** EngineRun for the (document × requested playbook). */
  run: EngineRun;
  /** The playbook the engine ran under. */
  playbook_id: string;
  /** The playbook `matchPlaybook` would auto-select (for classifier measurement). */
  auto_matched_playbook_id: string;
};

function bodyTextOf(tree: import("../../src/ingest/types.js").DocumentTree): string {
  const parts: string[] = [];
  const walk = (sections: import("../../src/ingest/types.js").Section[]): void => {
    for (const s of sections) {
      for (const p of s.paragraphs) for (const r of p.runs) parts.push(r.text);
      walk(s.children);
    }
  };
  walk(tree.sections);
  return parts.join(" ");
}

/**
 * Run the full pipeline on a corpus document's redacted text. When
 * `playbookId` is supplied (the gold annotation is per document × playbook),
 * the engine runs under *that* playbook so the rule grading is apples-to-
 * apples; the auto-matched id is returned alongside for classifier metrics.
 */
export async function runDocument(
  text: string,
  filename: string,
  playbookId: string | undefined,
  deps: AccuracyDeps,
): Promise<DocumentRun> {
  const ingest = await ingestPaste(text);
  const extracted = extractAll(ingest.tree, {
    classifier: { vocab: { vocab: {} }, patterns: deps.dkb.classifier.patterns },
  });
  const titleSource = ingest.tree.sections[0]?.heading ?? filename;
  const body = bodyTextOf(ingest.tree);
  const candidates = selectMatchCandidates(deps.launchPlaybooks, deps.extendedPlaybooks, {
    title: titleSource,
    body,
    classified: extracted.classified,
    extracted,
  });
  const match = matchPlaybook(extracted, extracted.classified, candidates, {
    title: titleSource,
    body_text: body,
  });

  const allPlaybooks = [...deps.launchPlaybooks, ...deps.extendedPlaybooks];
  const playbook =
    (playbookId && allPlaybooks.find((p) => p.id === playbookId)) ||
    candidates.find((p) => p.id === match.playbook_id) ||
    deps.launchPlaybooks[0]!;

  const run = await runEngine({
    rules: deps.rules,
    ctx: { tree: ingest.tree, extracted, dkb: deps.dkb, playbook },
    source_file: { name: filename, sha256: ingest.sha256, size_bytes: ingest.tree.sections.length },
    playbook_match_confidence: match.confidence,
    playbook_match_reasoning: match.reasoning,
    executed_at: "",
  });

  return {
    run,
    playbook_id: playbook.id,
    auto_matched_playbook_id: match.playbook_id,
  };
}
