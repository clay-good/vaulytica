/**
 * Accuracy harness CLI (spec-v5 §9–§10, Step 71). `npm run accuracy`.
 *
 * Loads the ground-truth corpus, runs the real full-catalog engine pipeline
 * over each (document × annotated playbook) in the regression split, grades
 * the output against gold, assembles the scoreboard, and writes
 * `tools/accuracy/SCOREBOARD.md` + `scoreboard.json`. Deterministic and
 * offline; the scoreboard hash is stable across machines.
 *
 * Build-and-CI-only — never imported by `src/`.
 */

import { writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ENGINE_VERSION } from "../../src/engine/index.js";
import { loadCorpus } from "./corpus.js";
import { loadAccuracyDeps, runDocument } from "./pipeline.js";
import { gradeAnnotation } from "./grade.js";
import type { GradedDocument } from "./metrics.js";
import { assembleScoreboard, renderScoreboardMarkdown } from "./scoreboard.js";
import type { VerdictPair } from "./kappa.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = __dirname;

export async function runAccuracy(): Promise<{ markdown: string; json: string }> {
  const [corpus, deps] = await Promise.all([loadCorpus(), loadAccuracyDeps()]);

  // Score the regression split (the CI-gated set, spec-v5 §11). With an empty
  // corpus this is simply zero documents and the scoreboard reports it.
  const regression = corpus.documents.filter((d) => d.split === "regression");

  const graded: GradedDocument[] = [];
  for (const doc of regression) {
    for (const annotation of doc.annotations) {
      const { run } = await runDocument(
        doc.text,
        `${doc.provenance.corpus_doc_id}.txt`,
        annotation.playbook_id,
        deps,
      );
      graded.push(
        gradeAnnotation(
          doc.provenance,
          annotation,
          run.findings.map((f) => f.rule_id),
        ),
      );
    }
  }

  // Inter-annotator κ pairs: derivable only from raw dual-annotator verdicts,
  // which the human annotation step (Step 70) produces. None exist yet, so κ
  // is reported as "none" honestly rather than fabricated.
  const kappaPairs: VerdictPair[] = [];

  const artifact = assembleScoreboard({
    corpus_version: corpus.version,
    dkb_version: deps.dkb.manifest.version,
    engine_version: ENGINE_VERSION,
    catalog: {
      rules: deps.rules.length,
      playbooks: deps.launchPlaybooks.length + deps.extendedPlaybooks.length,
    },
    graded,
    kappa_pairs: kappaPairs,
  });

  const markdown = renderScoreboardMarkdown(artifact);
  const json = JSON.stringify(artifact, null, 2);
  return { markdown, json };
}

async function main(): Promise<void> {
  const { markdown, json } = await runAccuracy();
  await writeFile(join(OUT_DIR, "SCOREBOARD.md"), markdown + "\n");
  await writeFile(join(OUT_DIR, "scoreboard.json"), json + "\n");
  console.log("Wrote tools/accuracy/SCOREBOARD.md and scoreboard.json");
}

// Run when invoked directly (npm run accuracy), not when imported by a test.
const invokedDirectly = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (invokedDirectly) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
