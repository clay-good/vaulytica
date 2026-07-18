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
import type { DKB } from "../../src/dkb/types.js";
import { loadDkbDirSync, resolveDkbDir } from "../dkb/resolve.js";
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
import { activateFiling } from "../../src/filing/activate.js";
import type { CourtProfile } from "../../src/filing/court-profile.js";
import type { BriefKind } from "../../src/filing/run-options.js";
import { activatePrivacyNotice } from "../../src/privacy/activate.js";
import type { RegimeId } from "../../src/privacy/regime-data.js";
import { activateEstateChecks } from "../../src/estate/activate.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..", "..");
const PLAYBOOK_DIR = join(REPO_ROOT, "playbooks");

export type AccuracyDeps = {
  dkb: DKB;
  launchPlaybooks: Playbook[];
  extendedPlaybooks: Playbook[];
  /** The full live rule catalog (LAUNCH + V3 + V4), exactly as the UI runs it. */
  rules: readonly Rule[];
};

const cachedByDir = new Map<string, AccuracyDeps>();

/** Load the engine dependencies once per DKB directory. The default DKB is
 * the latest `dkb/dist/` artifact — the SAME one the site build ships
 * (`dkb_version` is inside `result_hash`, so anything else makes browser
 * reports unverifiable headless); `--dkb` pins an explicit artifact. The
 * scoreboard stamps `dkb.manifest.version` so a published number is always
 * reproducible. */
export async function loadAccuracyDeps(opts: { dkbDir?: string } = {}): Promise<AccuracyDeps> {
  const dkbDir = resolveDkbDir({ explicit: opts.dkbDir });
  const hit = cachedByDir.get(dkbDir);
  if (hit) return hit;
  const dkb = loadDkbDirSync(dkbDir);
  const launchPlaybooks: Playbook[] = [];
  for (const id of LAUNCH_PLAYBOOK_IDS) {
    const text = await readFile(join(PLAYBOOK_DIR, `${id}.json`), "utf8");
    launchPlaybooks.push(parsePlaybook(JSON.parse(text)));
  }
  // Both branches assign, so no initializer is needed (ESLint 10
  // `no-useless-assignment`); the catch supplies the empty-on-missing default.
  let extendedPlaybooks: Playbook[];
  try {
    const ext = JSON.parse(await readFile(join(PLAYBOOK_DIR, "extended.json"), "utf8"));
    extendedPlaybooks = (ext as unknown[]).map((p) => parsePlaybook(p));
  } catch {
    extendedPlaybooks = [];
  }
  const deps: AccuracyDeps = {
    dkb,
    launchPlaybooks,
    extendedPlaybooks,
    rules: [...LAUNCH_RULES, ...V3_RULES, ...V4_RULES] as readonly Rule[],
  };
  cachedByDir.set(dkbDir, deps);
  return deps;
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
  // UTF-8 byte length — what the browser stamps for the same text input.
  return runIngested(await ingestPaste(text), filename, playbookId, deps, Buffer.byteLength(text));
}

/**
 * The post-ingest half of the pipeline: extract → classify → playbook
 * match → engine. Factored out of {@link runDocument} so a caller that
 * ingested a *binary* document (the CLI, Step 143, reading `.docx`/`.pdf`)
 * runs the identical downstream the parity test pins for text — no logic
 * is re-implemented, only the ingest front-end differs.
 */
export async function runIngested(
  ingest: import("../../src/ingest/types.js").IngestResult,
  filename: string,
  playbookId: string | undefined,
  deps: AccuracyDeps,
  /**
   * Byte length of the ingested input — file bytes for binary inputs,
   * UTF-8 byte length for text — matching what the browser stamps
   * (`src/ui/pipeline.ts` uses `buffer.byteLength`). `source_file` is
   * inside the hashed run, so any other basis breaks cross-surface
   * verification.
   */
  sizeBytes: number,
  /**
   * Filing-format-lint activation (add-filing-format-lint). Present only when
   * the user selected a `--court` profile. The pack fires only when the matched
   * playbook is a filing playbook; otherwise this is ignored, so a non-filing
   * document's hash is unchanged even with `--court` set.
   */
  filing?: { profile: CourtProfile; brief_kind: BriefKind },
  /**
   * Privacy-notice regimes the user asserted (`--regime`). Present only when
   * the user opts in; the PNOT pack fires only for a notice playbook.
   */
  regimes?: readonly RegimeId[],
  /** Estate-checks assertion (`--estate-checks`). Fires the pack on will/trust/codicil. */
  estateChecks?: boolean,
  /** Normalized `us-xx` state (`--state`) — selects the formalities overlay and implies the pack. */
  estateState?: string,
): Promise<DocumentRun> {
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

  const activation = activateFiling(filing, playbook.id, ingest, deps.rules);
  const privacy = activatePrivacyNotice(regimes ?? [], playbook.id, activation.rules);
  const estate = activateEstateChecks(
    estateChecks ?? false,
    playbook.id,
    privacy.rules,
    estateState,
  );

  const run = await runEngine({
    rules: estate.rules,
    ctx: {
      tree: ingest.tree,
      extracted,
      dkb: deps.dkb,
      playbook,
      ...(activation.options ? { options: activation.options } : {}),
    },
    source_file: { name: filename, sha256: ingest.sha256, size_bytes: sizeBytes },
    playbook_match_confidence: match.confidence,
    playbook_match_reasoning: match.reasoning,
    ...(activation.filing_profile ? { filing_profile: activation.filing_profile } : {}),
    ...(privacy.asserted_regimes ? { asserted_regimes: privacy.asserted_regimes } : {}),
    ...(estate.estate_checks_asserted ? { estate_checks_asserted: true } : {}),
    ...(estate.asserted_state ? { asserted_state: estate.asserted_state } : {}),
    executed_at: "",
  });

  return {
    run,
    playbook_id: playbook.id,
    auto_matched_playbook_id: match.playbook_id,
  };
}
