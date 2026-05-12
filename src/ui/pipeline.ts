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
import type { IngestResult } from "../ingest/types.js";
import { extractAll } from "../extract/index.js";
import { loadDkb } from "../dkb/index.js";
import type { DKB } from "../dkb/types.js";
import { matchPlaybook, parsePlaybook, LAUNCH_PLAYBOOK_IDS } from "../playbooks/index.js";
import type { Playbook } from "../playbooks/types.js";
import { LAUNCH_RULES, runEngine, type EngineRun, type Rule } from "../engine/index.js";
import { buildDocxReport, buildJsonReport } from "../report/index.js";

export type PipelineProgress = {
  /** Fraction in [0, 1] after each rule completes. */
  onProgress?: (fraction: number) => void;
  /** Fired once for each rule executed, with the rule and outcome. */
  onRule?: (rule: Rule, fired: boolean) => void;
  /** Fired once after the DKB loads so the UI can surface the version. */
  onDkbLoaded?: (version: string) => void;
};

export type PipelineResult = {
  ingest: IngestResult;
  run: EngineRun;
  playbook: Playbook;
  match_reasoning: string;
  docx_blob: Blob;
  json_blob: Blob;
};

export type PipelineConfig = {
  dkb_base?: string;
  playbook_base?: string;
};

const DEFAULT_DKB_BASE = "/dkb";
const DEFAULT_PLAYBOOK_BASE = "/playbooks";

let cachedDkb: DKB | null = null;
let cachedPlaybooks: Playbook[] | null = null;

export async function runPipeline(
  file: File,
  kind: "pdf" | "docx",
  hooks: PipelineProgress = {},
  config: PipelineConfig = {},
): Promise<PipelineResult> {
  // 1. Ingest. DKB load runs in parallel.
  const buffer = await file.arrayBuffer();
  const dkbPromise = ensureDkb(config.dkb_base ?? DEFAULT_DKB_BASE);
  const ingest: IngestResult =
    kind === "pdf"
      ? await ingestPdfBuffer(buffer, { allowOcr: true })
      : await ingestDocxBuffer(buffer);

  // 2. Wait for DKB.
  const dkb = await dkbPromise;
  hooks.onDkbLoaded?.(dkb.manifest.version);

  // 3. Extract.
  const extracted = extractAll(ingest.tree, {
    classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
  });

  // 4. Match playbook.
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

  // 5. Run engine with live progress.
  const run = await runEngine({
    rules: LAUNCH_RULES,
    ctx: { tree: ingest.tree, extracted, dkb, playbook },
    source_file: { name: file.name, sha256: ingest.sha256, size_bytes: buffer.byteLength },
    playbook_match_confidence: match.confidence,
    playbook_match_reasoning: match.reasoning,
    executed_at: new Date().toISOString(),
    onRule: ({ rule, index, total, fired }) => {
      hooks.onProgress?.((index + 1) / total);
      hooks.onRule?.(rule, fired);
    },
  });

  // 6. Build report Blobs.
  const docx_blob = await buildDocxReport(run, ingest, dkb, playbook);
  const json_blob = buildJsonReport(run, ingest);

  return {
    ingest,
    run,
    playbook,
    match_reasoning: match.reasoning,
    docx_blob,
    json_blob,
  };
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
