/**
 * Corpus loader (spec-v5 §4, §7, Step 67/71).
 *
 * Reads the ground-truth corpus from `corpus/`: the version stamp, the
 * split manifest, the per-document provenance records, the redacted document
 * text, and the gold annotations. Validates every artifact against the zod
 * schemas. Returns a structured, in-memory corpus the harness grades against.
 *
 * Tolerant of an empty corpus: before the human-gated sourcing (Step 68) and
 * annotation (Step 70) land, `corpus/` carries only scaffolding, and the
 * loader returns zero documents rather than throwing — the harness then
 * reports the honest empty state.
 */

import { readFile, readdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  parseProvenance,
  parseGoldAnnotation,
  parseCorpusManifest,
  type Provenance,
  type GoldAnnotation,
  type CorpusManifest,
} from "./schema.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
export const CORPUS_DIR = join(__dirname, "..", "..", "corpus");

export type CorpusDocument = {
  provenance: Provenance;
  /** Redacted document text. */
  text: string;
  /** All gold annotations for this document, one per applicable playbook. */
  annotations: GoldAnnotation[];
  split: "regression" | "development";
};

export type Corpus = {
  version: string;
  manifest: CorpusManifest | null;
  documents: CorpusDocument[];
};

async function readJsonFilesIn(dir: string): Promise<Array<{ name: string; value: unknown }>> {
  if (!existsSync(dir)) return [];
  const entries = (await readdir(dir)).filter((n) => n.endsWith(".json")).sort();
  const out: Array<{ name: string; value: unknown }> = [];
  for (const name of entries) {
    out.push({ name, value: JSON.parse(await readFile(join(dir, name), "utf8")) });
  }
  return out;
}

export async function loadCorpus(corpusDir: string = CORPUS_DIR): Promise<Corpus> {
  const versionPath = join(corpusDir, "CORPUS_VERSION");
  const version = existsSync(versionPath)
    ? (await readFile(versionPath, "utf8")).trim()
    : "v0.0.0-unscaffolded";

  const manifestPath = join(corpusDir, "manifest.json");
  const manifest = existsSync(manifestPath)
    ? parseCorpusManifest(JSON.parse(await readFile(manifestPath, "utf8")))
    : null;

  const provenanceRecords = (await readJsonFilesIn(join(corpusDir, "provenance"))).map((f) =>
    parseProvenance(f.value),
  );
  const annotationRecords = (await readJsonFilesIn(join(corpusDir, "annotations"))).map((f) =>
    parseGoldAnnotation(f.value),
  );

  const annotationsByDoc = new Map<string, GoldAnnotation[]>();
  for (const a of annotationRecords) {
    const list = annotationsByDoc.get(a.corpus_doc_id) ?? [];
    list.push(a);
    annotationsByDoc.set(a.corpus_doc_id, list);
  }

  const documents: CorpusDocument[] = [];
  for (const provenance of provenanceRecords) {
    const id = provenance.corpus_doc_id;
    const textPath = join(corpusDir, "documents", `${id}.txt`);
    if (!existsSync(textPath)) {
      throw new Error(`corpus document text missing for provenance ${id}: ${textPath}`);
    }
    const text = await readFile(textPath, "utf8");
    const split = manifest?.splits[id] ?? "development";
    documents.push({
      provenance,
      text,
      annotations: (annotationsByDoc.get(id) ?? []).sort((x, y) =>
        x.playbook_id < y.playbook_id ? -1 : x.playbook_id > y.playbook_id ? 1 : 0,
      ),
      split,
    });
  }

  documents.sort((a, b) =>
    a.provenance.corpus_doc_id < b.provenance.corpus_doc_id
      ? -1
      : a.provenance.corpus_doc_id > b.provenance.corpus_doc_id
        ? 1
        : 0,
  );

  return { version, manifest, documents };
}
