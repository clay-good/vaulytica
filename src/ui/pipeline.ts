/**
 * The full analysis pipeline (ingest → extract → DKB → playbook →
 * engine → report). Split out of `main.ts` so the main UI bundle
 * does not eagerly pull pdfjs / mammoth / docx / decimal / zod /
 * tesseract — those weigh several hundred KB and are only needed
 * once the user drops a file.
 *
 * `main.ts` dynamic-imports this module on first file drop. Network
 * fetches for the DKB and playbooks are intentionally kicked off
 * concurrently with the module load.
 */

import { ingestPdfBuffer, ingestDocxBuffer } from "../ingest/index.js";
import {
  classifyExtension,
  extractZipEntries,
  filesToCandidates,
  planBundle,
  BUNDLE_CAP_MESSAGE,
  type MultiIngestEntry,
} from "../ingest/multi.js";
import type { IngestResult } from "../ingest/types.js";
import { extractAll } from "../extract/index.js";
import { loadDkb } from "../dkb/index.js";
import type { DKB } from "../dkb/types.js";
import { matchPlaybook, parsePlaybook, LAUNCH_PLAYBOOK_IDS } from "../playbooks/index.js";
import type { Playbook } from "../playbooks/types.js";
import {
  ALL_CONSISTENCY_RULES,
  LAUNCH_RULES,
  V3_RULES,
  runEngine,
  runConsistency,
  type ConsistencyDocument,
  type ConsistencyRun,
  type EngineRun,
  type Rule,
} from "../engine/index.js";
import { buildDocxReport, buildJsonReport } from "../report/index.js";
import {
  buildBundleDocxReport,
  buildBundleJsonBlob,
  type BundleDocument,
} from "../report/bundle.js";
import {
  detectV3Family,
  defaultFramesForPlaybook,
  type ComplianceFrame,
  type V3Detection,
  type FrameDefaults,
} from "./v3/index.js";
import { familyDisplayLabel } from "./v3-labels.js";
import { filterRulesByFrames } from "./frame-filter.js";

export type PipelineProgress = {
  /** Fraction in [0, 1] after each rule completes. */
  onProgress?: (fraction: number) => void;
  /** Fired once for each rule executed, with the rule and outcome. */
  onRule?: (rule: Rule, fired: boolean) => void;
  /** Fired once after the DKB loads so the UI can surface the version. */
  onDkbLoaded?: (version: string) => void;
};

/**
 * Cached per-document state from the expensive pre-engine phase
 * (ingest + extract + DKB load + playbook match). The complete-state
 * UI retains a `PreparedDocument` so the chip-toggle re-run can call
 * straight into `runReport` without re-parsing the PDF or re-loading
 * the DKB. Spec-v3 §61 / LAUNCH row v3-o follow-up.
 */
export type PreparedDocument = {
  ingest: IngestResult;
  /** ExtractedData — `unknown` here so we can avoid importing the extract barrel just for the type. */
  extracted: import("../extract/types.js").ExtractedData;
  body_text: string;
  dkb: DKB;
  playbook: Playbook;
  source_file: { name: string; sha256: string; size_bytes: number };
  match: { playbook_id: string; confidence: number; reasoning: string };
};

export type PipelineResult = {
  ingest: IngestResult;
  run: EngineRun;
  playbook: Playbook;
  match_reasoning: string;
  docx_blob: Blob;
  json_blob: Blob;
  /**
   * v3 family auto-detection (spec-v3.md §60, LAUNCH row v3-o). Always
   * computed alongside the v2 playbook match so the UI can surface
   * "we detected: BAA" as a suggestion. `family === "unknown"` when
   * no detector fired with confidence ≥ 1.
   */
  v3_detection: V3Detection;
  /**
   * Default compliance-frame chip-row state for the matched playbook
   * (spec-v3.md §61). The UI renders one chip per `available` frame
   * with `aria-checked` mirroring membership in `on`. Toggling is
   * presentational at this hookup level — engine-side filtering is a
   * follow-up.
   */
  v3_frames: FrameDefaults;
};

export type PipelineConfig = {
  dkb_base?: string;
  playbook_base?: string;
};

export type PipelineOptions = {
  /**
   * Active compliance frames (spec-v3 §61, LAUNCH row v3-o follow-up).
   * When provided, the engine rule set is filtered via
   * `filterRulesByFrames` before the run: any frame-gated rule whose
   * frames don't intersect this list is excluded. Unframed rules (the
   * V1 launch rules + the V3 deep-rule families like NDA-D / MSA) are
   * always kept regardless. Omit or pass `undefined` to disable
   * frame filtering (default — matches v1/v3/v4 behavior to date).
   */
  active_frames?: ReadonlyArray<ComplianceFrame>;
  /**
   * Cross-document consistency toggle (spec-v3 §62). Default `true`.
   * When set to `false`, `runBundlePipeline` skips the consistency
   * pass: it still constructs an empty `ConsistencyRun` (so the
   * bundle DOCX/JSON renderer's contract is preserved) but with an
   * empty rules list, so no findings are emitted and the cross-doc
   * appendix renders as "0 cross-document findings".
   */
  cross_doc_consistency?: boolean;
};

const DEFAULT_DKB_BASE = "/dkb";
const DEFAULT_PLAYBOOK_BASE = "/playbooks";

let cachedDkb: DKB | null = null;
let cachedPlaybooks: Playbook[] | null = null;

/**
 * Phase 1: ingest + extract + DKB load + playbook match. Slow on
 * first run (PDF parsing, mammoth, DKB fetch); idempotent and pure
 * relative to its inputs. The output is reused across compliance-
 * frame toggle re-runs.
 */
export async function prepareDocument(
  file: File,
  kind: "pdf" | "docx",
  config: PipelineConfig = {},
  hooks: PipelineProgress = {},
): Promise<PreparedDocument> {
  const buffer = await file.arrayBuffer();
  const dkbPromise = ensureDkb(config.dkb_base ?? DEFAULT_DKB_BASE);
  const ingest: IngestResult =
    kind === "pdf"
      ? await ingestPdfBuffer(buffer, { allowOcr: true })
      : await ingestDocxBuffer(buffer);

  const dkb = await dkbPromise;
  hooks.onDkbLoaded?.(dkb.manifest.version);

  const extracted = extractAll(ingest.tree, {
    classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
  });

  const playbooks = await ensurePlaybooks(config.playbook_base ?? DEFAULT_PLAYBOOK_BASE);
  const titleSource = ingest.tree.sections[0]?.heading ?? file.name;
  // Walk every section + child paragraph for distinguishing-phrase
  // matching. The classifier categories alone are a poor proxy for
  // body text — a unilateral NDA's `the Disclosing Party` phrasing
  // doesn't show up in the categories but is dispositive for the
  // playbook match.
  const bodyParts: string[] = [];
  const walkSections = (
    sections: ReadonlyArray<{
      paragraphs: ReadonlyArray<{ runs: ReadonlyArray<{ text: string }> }>;
      children: ReadonlyArray<unknown>;
    }>,
  ): void => {
    for (const s of sections) {
      for (const p of s.paragraphs) for (const r of p.runs) bodyParts.push(r.text);
      walkSections(s.children as typeof sections);
    }
  };
  walkSections(
    ingest.tree.sections as unknown as Parameters<typeof walkSections>[0],
  );
  const bodyText = bodyParts.join(" ");
  const match = matchPlaybook(extracted, extracted.classified, playbooks, {
    title: titleSource,
    body_text: bodyText,
  });
  const playbook = playbooks.find((p) => p.id === match.playbook_id) ?? playbooks[0]!;

  return {
    ingest,
    extracted,
    body_text: bodyText,
    dkb,
    playbook,
    source_file: { name: file.name, sha256: ingest.sha256, size_bytes: buffer.byteLength },
    match: {
      playbook_id: match.playbook_id,
      confidence: match.confidence,
      reasoning: match.reasoning,
    },
  };
}

/**
 * Phase 2: run engine (optionally frame-filtered) + build reports +
 * detect v3 family + compute frame defaults. Idempotent given a
 * `PreparedDocument`; expected to be called multiple times for a
 * given prepared payload as the user toggles compliance-frame chips.
 */
export async function runReport(
  prepared: PreparedDocument,
  hooks: PipelineProgress = {},
  options: PipelineOptions = {},
): Promise<PipelineResult> {
  const ruleSet = filterRulesByFrames(
    [...LAUNCH_RULES, ...V3_RULES] as readonly Rule[],
    options.active_frames,
  );
  const run = await runEngine({
    rules: ruleSet as readonly Rule[],
    ctx: {
      tree: prepared.ingest.tree,
      extracted: prepared.extracted,
      dkb: prepared.dkb,
      playbook: prepared.playbook,
    },
    source_file: prepared.source_file,
    playbook_match_confidence: prepared.match.confidence,
    playbook_match_reasoning: prepared.match.reasoning,
    executed_at: new Date().toISOString(),
    onRule: ({ rule, index, total, fired }) => {
      hooks.onProgress?.((index + 1) / total);
      hooks.onRule?.(rule, fired);
    },
  });

  const docx_blob = await buildDocxReport(
    run,
    prepared.ingest,
    prepared.dkb,
    prepared.playbook,
    undefined,
    prepared.extracted,
  );
  const json_blob = buildJsonReport(run, prepared.ingest);

  const v3_detection = detectV3Family(prepared.extracted, prepared.body_text);
  const v3_frames = defaultFramesForPlaybook(prepared.playbook.id);

  return {
    ingest: prepared.ingest,
    run,
    playbook: prepared.playbook,
    match_reasoning: prepared.match.reasoning,
    docx_blob,
    json_blob,
    v3_detection,
    v3_frames,
  };
}

/**
 * Run the full pipeline end-to-end. Returns the `PreparedDocument`
 * alongside the `PipelineResult` so the UI can retain it for a
 * later `runReport` call when compliance-frame chips toggle.
 */
export async function runPipeline(
  file: File,
  kind: "pdf" | "docx",
  hooks: PipelineProgress = {},
  config: PipelineConfig = {},
  options: PipelineOptions = {},
): Promise<PipelineResult & { prepared: PreparedDocument }> {
  const prepared = await prepareDocument(file, kind, config, hooks);
  const report = await runReport(prepared, hooks, options);
  return { ...report, prepared };
}

async function ensureDkb(base: string): Promise<DKB> {
  if (cachedDkb) return cachedDkb;
  cachedDkb = await loadDkb({ base });
  return cachedDkb;
}

async function ensurePlaybooks(base: string): Promise<Playbook[]> {
  if (cachedPlaybooks) return cachedPlaybooks;
  // Parallel fetch — the service worker pre-caches `/playbooks/*` so
  // these are all the same network round-trip in practice, and on
  // a cold load the HTTP/2 multiplexing handles them fine. Order in
  // the result array still mirrors `LAUNCH_PLAYBOOK_IDS` because
  // `Promise.all` preserves index.
  const responses = await Promise.all(
    LAUNCH_PLAYBOOK_IDS.map(async (id) => {
      const res = await fetch(`${base}/${id}.json`);
      if (!res.ok) throw new Error(`failed to load playbook ${id}: ${res.status}`);
      return parsePlaybook(await res.json());
    }),
  );
  cachedPlaybooks = responses;
  return cachedPlaybooks;
}

export function countsBySeverity(run: EngineRun): {
  critical: number;
  warning: number;
  info: number;
} {
  const out = { critical: 0, warning: 0, info: 0 };
  for (const f of run.findings) out[f.severity]++;
  return out;
}

/* -------------------------------------------------------------------------- */
/* Multi-document bundle pipeline (spec-v4.md §8 / §11, LAUNCH row v4-d)      */
/* -------------------------------------------------------------------------- */

export type BundlePipelineHooks = {
  /** Fraction in [0, 1] across the whole bundle (per-doc progress merged). */
  onProgress?: (fraction: number) => void;
  /** Fired as documents finish ingest, before engine runs. */
  onDocumentReady?: (filename: string, index: number, total: number) => void;
  /** Fired once after the DKB loads. */
  onDkbLoaded?: (version: string) => void;
};

export type BundlePerDocument = {
  filename: string;
  run: EngineRun;
  playbook: Playbook;
  match_reasoning: string;
  docx_blob: Blob;
  json_blob: Blob;
  /** v3 family auto-detection (spec-v3 §60), computed per-doc. */
  v3_detection: V3Detection;
};

export type BundlePipelineResult = {
  documents: BundlePerDocument[];
  rejected: Array<{ filename: string; reason: string }>;
  consistency: ConsistencyRun;
  bundle_docx_blob: Blob;
  bundle_json_blob: Blob;
};

/**
 * Cached output from the expensive bundle-pre-engine phase
 * (ingest + extract + per-doc engine + per-doc reports + consistency
 * doc shapes). The bundle-complete UI retains a `PreparedBundle` so
 * the spec-v3 §62 cross-doc consistency toggle can re-run via
 * `runBundleReport` without re-ingesting every document.
 */
export type PreparedBundle = {
  documents: BundlePerDocument[];
  rejected: Array<{ filename: string; reason: string }>;
  /**
   * Per-document tree + extracted payloads needed to re-run the
   * cross-doc consistency engine. Held alongside the per-doc engine
   * runs so a toggle only re-runs the cheap consistency pass.
   */
  consistency_docs: ConsistencyDocument[];
  dkb: DKB;
};

/**
 * Resolve the dropped file list into the raw candidate-bundle shape
 * consumed by `planBundle`. Handles the v4 §8 zip-bundle case: a single
 * `.zip` drop is unpacked client-side and its accepted entries are
 * promoted to the candidate list.
 */
export async function expandBundleInputs(
  files: ReadonlyArray<File>,
): Promise<Array<{ filename: string; bytes: ArrayBuffer; size_bytes: number }>> {
  if (files.length === 1 && files[0]!.name.toLowerCase().endsWith(".zip")) {
    const bytes = await files[0]!.arrayBuffer();
    return extractZipEntries(bytes);
  }
  // Defensive: ignore unsupported extensions up-front; `planBundle`
  // would reject them with per-file messages, but for the UI we want a
  // tighter, deterministic list to feed the engine.
  const accepted = files.filter((f) => classifyExtension(f.name) !== null);
  return filesToCandidates(accepted);
}

/**
 * Phase 1 (bundle path): ingest + extract + per-doc engine + per-doc
 * reports for every accepted file in the dropped bundle. Mirrors
 * `prepareDocument` for the single-doc path. The output is reused
 * across cross-doc-consistency toggle re-runs (spec-v3 §62) so the
 * toggle costs one consistency pass + one bundle-report rebuild, not
 * a full re-ingest of every document.
 */
export async function prepareBundle(
  files: ReadonlyArray<File>,
  hooks: BundlePipelineHooks = {},
  config: PipelineConfig = {},
  options: PipelineOptions = {},
): Promise<PreparedBundle> {
  if (files.length === 0) throw new Error(BUNDLE_CAP_MESSAGE);

  // 1. Resolve raw bytes (handles single-zip and multi-file).
  const candidates = await expandBundleInputs(files);
  const plan = planBundle(candidates);
  if (!plan.ok) throw new Error(plan.reason);

  // 2. Load DKB + playbooks in parallel.
  const dkbPromise = ensureDkb(config.dkb_base ?? DEFAULT_DKB_BASE);
  const playbooksPromise = ensurePlaybooks(config.playbook_base ?? DEFAULT_PLAYBOOK_BASE);

  const accepted = plan.entries.filter((e): e is Extract<MultiIngestEntry, { ok: true }> => e.ok);
  const rejected: Array<{ filename: string; reason: string }> = plan.entries
    .filter((e): e is Extract<MultiIngestEntry, { ok: false }> => !e.ok)
    .map((e) => ({ filename: e.filename, reason: e.reason }));

  if (accepted.length < 2) {
    // Spec-v4 §8: the bundle path is for ≥ 2 ingestable documents.
    // Smaller bundles are routed through the single-doc pipeline by the
    // UI; this error is the defensive fallback if a caller bypasses it.
    throw new Error(
      `Bundle requires at least 2 ingestable documents; got ${accepted.length}.`,
    );
  }

  // 3. Ingest each accepted entry (parallel). Reuse the cached DKB.
  const dkb = await dkbPromise;
  hooks.onDkbLoaded?.(dkb.manifest.version);
  const playbooks = await playbooksPromise;

  const total = accepted.length;
  const perDoc: BundlePerDocument[] = [];
  // Parallel array keeping each doc's tree + extracted so the
  // consistency pass can re-use them without re-ingesting.
  const consistencyDocs: ConsistencyDocument[] = [];

  // Per-doc progress accumulator: each doc contributes 1/total of the
  // overall bar; within a doc, progress runs 0 → 1 as rules fire.
  const perDocProgress = new Array<number>(total).fill(0);
  const reportTotal = (): void => {
    if (!hooks.onProgress) return;
    const sum = perDocProgress.reduce((a, b) => a + b, 0);
    hooks.onProgress(sum / total);
  };

  for (let i = 0; i < accepted.length; i++) {
    const entry = accepted[i]!;
    const ingest: IngestResult =
      entry.kind === "pdf"
        ? await ingestPdfBuffer(entry.bytes, { allowOcr: true })
        : await ingestDocxBuffer(entry.bytes);

    hooks.onDocumentReady?.(entry.filename, i, total);

    const extracted = extractAll(ingest.tree, {
      classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
    });

    // Walk body text the same way the single-doc pipeline does so the
    // playbook matcher sees comparable surface area.
    const bodyParts: string[] = [];
    const walkSections = (
      sections: ReadonlyArray<{
        paragraphs: ReadonlyArray<{ runs: ReadonlyArray<{ text: string }> }>;
        children: ReadonlyArray<unknown>;
      }>,
    ): void => {
      for (const s of sections) {
        for (const p of s.paragraphs) for (const r of p.runs) bodyParts.push(r.text);
        walkSections(s.children as typeof sections);
      }
    };
    walkSections(
      ingest.tree.sections as unknown as Parameters<typeof walkSections>[0],
    );

    const titleSource = ingest.tree.sections[0]?.heading ?? entry.filename;
    const match = matchPlaybook(extracted, extracted.classified, playbooks, {
      title: titleSource,
      body_text: bodyParts.join(" "),
    });
    const playbook = playbooks.find((p) => p.id === match.playbook_id) ?? playbooks[0]!;

    const docIndex = i;
    // Frame-filtered rule set (spec-v3 §61). When `options.active_frames`
    // is omitted, this returns the full LAUNCH+V3 set unchanged.
    const ruleSet = filterRulesByFrames(
      [...LAUNCH_RULES, ...V3_RULES] as readonly Rule[],
      options.active_frames,
    );
    const run = await runEngine({
      rules: ruleSet as readonly Rule[],
      ctx: { tree: ingest.tree, extracted, dkb, playbook },
      source_file: {
        name: entry.filename,
        sha256: ingest.sha256,
        size_bytes: entry.size_bytes,
      },
      playbook_match_confidence: match.confidence,
      playbook_match_reasoning: match.reasoning,
      executed_at: new Date().toISOString(),
      onRule: ({ index, total: ruleTotal }) => {
        perDocProgress[docIndex] = (index + 1) / ruleTotal;
        reportTotal();
      },
    });

    const docx_blob = await buildDocxReport(run, ingest, dkb, playbook, undefined, extracted);
    const json_blob = buildJsonReport(run, ingest);

    const v3_detection = detectV3Family(extracted, bodyParts.join(" "));

    perDoc.push({
      filename: entry.filename,
      run,
      playbook,
      match_reasoning: match.reasoning,
      docx_blob,
      json_blob,
      v3_detection,
    });
    consistencyDocs.push({
      doc_id: `doc-${i + 1}-${entry.filename}`,
      source_file_name: entry.filename,
      playbook_id: playbook.id,
      tree: ingest.tree,
      extracted,
    });
  }

  return {
    documents: perDoc,
    rejected,
    consistency_docs: consistencyDocs,
    dkb,
  };
}

/**
 * Phase 2 (bundle path): run the cross-doc consistency engine and
 * build the consolidated bundle DOCX + JSON. Cheap relative to
 * `prepareBundle` — the per-doc engine runs are already in the
 * `PreparedBundle`. Called both as part of the full pipeline and
 * standalone when the user flips the spec-v3 §62 consistency toggle
 * in the bundle-complete state.
 */
export async function runBundleReport(
  prepared: PreparedBundle,
  options: PipelineOptions = {},
): Promise<BundlePipelineResult> {
  // Cross-document consistency. When the user has toggled the §62
  // consistency switch off, the rules list collapses to an empty
  // array — the runner still produces a valid `ConsistencyRun`, but
  // findings + execution_log are empty so the cross-doc appendix
  // renders as "0 cross-document findings".
  const consistencyEnabled = options.cross_doc_consistency !== false;
  const consistency = await runConsistency({
    rules: consistencyEnabled ? ALL_CONSISTENCY_RULES : [],
    documents: prepared.consistency_docs,
    dkb: prepared.dkb,
    executed_at: new Date().toISOString(),
  });

  const bundleInput: {
    documents: BundleDocument[];
    consistency: typeof consistency;
    dkb: DKB;
    rejected?: ReadonlyArray<{ filename: string; reason: string }>;
    consistency_enabled?: boolean;
  } = {
    documents: prepared.documents.map((d) => ({
      doc_id: `doc-${d.filename}`,
      source_file_name: d.filename,
      // Prefer the v3 family label when the detector fired with non-
      // "unknown"; fall back to the playbook name (e.g. "Mutual NDA",
      // "SaaS — Vendor") for v2-launch families that the v3 detector
      // doesn't cover.
      detected_family: familyDisplayLabel(d.v3_detection.family, d.playbook.name),
      detection_confidence: d.v3_detection.confidence,
      playbook_deprecated: d.playbook.deprecated === true ? true : undefined,
      playbook_superseded_by: d.playbook.deprecated === true ? d.playbook.superseded_by : undefined,
      run: d.run,
    })),
    consistency,
    dkb: prepared.dkb,
    rejected: prepared.rejected.length > 0 ? prepared.rejected : undefined,
    consistency_enabled: consistencyEnabled,
  };
  const bundle_docx_blob = await buildBundleDocxReport(bundleInput);
  const bundle_json_blob = await buildBundleJsonBlob(bundleInput);

  return {
    documents: prepared.documents,
    rejected: prepared.rejected,
    consistency,
    bundle_docx_blob,
    bundle_json_blob,
  };
}

/**
 * Run the full multi-document analysis pipeline. Mirrors `runPipeline`
 * for the single-doc path but fans out across N documents and folds in
 * the cross-document consistency engine.
 *
 * The bundle DOCX / JSON cover all per-doc engine runs plus the
 * cross-doc findings. Each document's own per-doc DOCX / JSON are
 * returned alongside so the UI can surface them as secondary
 * downloads. The returned `prepared` field gives the UI everything
 * it needs to call `runBundleReport` directly on a consistency
 * toggle without re-ingesting (spec-v3 §62 follow-up).
 */
export async function runBundlePipeline(
  files: ReadonlyArray<File>,
  hooks: BundlePipelineHooks = {},
  config: PipelineConfig = {},
  options: PipelineOptions = {},
): Promise<BundlePipelineResult & { prepared: PreparedBundle }> {
  const prepared = await prepareBundle(files, hooks, config, options);
  const report = await runBundleReport(prepared, options);
  hooks.onProgress?.(1);
  return { ...report, prepared };
}
