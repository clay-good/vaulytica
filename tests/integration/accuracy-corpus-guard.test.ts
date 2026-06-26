/**
 * v5 corpus privacy + disjointness guards (spec-v5 §4 disjoint-from-fixtures,
 * §VIII / Step 83 bundle-excludes-corpus).
 *
 * Three invariants protect the v5 surface:
 *   1. **`src/` never imports the harness or the corpus.** The accuracy
 *      harness (`tools/accuracy/`) and corpus (`corpus/`) are build-and-CI-
 *      only; if `src/` imported them, corpus bytes could reach the deployed
 *      bundle. This is the load-bearing privacy guard.
 *   2. **Corpus ⟂ fixtures.** The accuracy corpus and the synthetic unit
 *      fixtures are disjoint (spec-v5 §4) so the engine is never graded on the
 *      documents it was authored against.
 *   3. **No corpus text in the bundle.** When a build exists, no corpus
 *      document's text appears in any shipped asset.
 */

import { describe, expect, it } from "vitest";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "..", "..");
const SRC = join(REPO_ROOT, "src");
const CORPUS = join(REPO_ROOT, "corpus");
const FIXTURES = join(REPO_ROOT, "tests", "fixtures", "contracts");
const DIST_ASSETS = join(REPO_ROOT, "dist", "assets");

function walk(dir: string, pred: (p: string) => boolean): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...walk(full, pred));
    else if (pred(full)) out.push(full);
  }
  return out;
}

describe("v5 corpus privacy guard (spec-v5 §VIII, Step 83)", () => {
  it("no src/ file imports the accuracy harness or the corpus", () => {
    const tsFiles = walk(SRC, (p) => p.endsWith(".ts"));
    const offenders: string[] = [];
    for (const file of tsFiles) {
      const text = readFileSync(file, "utf8");
      if (
        /from\s+["'][^"']*tools\/accuracy/.test(text) ||
        /from\s+["'][^"']*\/corpus\//.test(text)
      ) {
        offenders.push(file.replace(REPO_ROOT + "/", ""));
      }
    }
    expect(offenders, "src/ must never import the corpus or accuracy harness").toEqual([]);
  });

  it("no src/ file imports the citation-check tool (spec-v8 §19 posture guard)", () => {
    // The citation-check tool has a network reachability path; if src/
    // imported it the no-server posture would be at risk, so it stays
    // build/CI-only in tools/, exactly like the accuracy harness.
    const tsFiles = walk(SRC, (p) => p.endsWith(".ts"));
    const offenders: string[] = [];
    for (const file of tsFiles) {
      const text = readFileSync(file, "utf8");
      if (/from\s+["'][^"']*tools\/citation-check/.test(text)) {
        offenders.push(file.replace(REPO_ROOT + "/", ""));
      }
    }
    expect(offenders, "src/ must never import the citation-check tool").toEqual([]);
  });

  it("no built asset contains any corpus document's text", () => {
    if (!existsSync(DIST_ASSETS)) return; // build-gated; runs in CI where dist exists
    const docsDir = join(CORPUS, "documents");
    const corpusDocs = walk(docsDir, (p) => p.endsWith(".txt")).map((p) => readFileSync(p, "utf8"));
    if (corpusDocs.length === 0) return; // vacuously true for the seed corpus
    const assets = walk(DIST_ASSETS, (p) => p.endsWith(".js") || p.endsWith(".html")).map((p) =>
      readFileSync(p, "utf8"),
    );
    for (const doc of corpusDocs) {
      // Probe with a distinctive 60-char slice to avoid trivial substrings.
      const probe = doc.replace(/\s+/g, " ").trim().slice(0, 60);
      if (probe.length < 20) continue;
      for (const asset of assets) {
        expect(asset.includes(probe), "corpus text must not appear in any shipped asset").toBe(
          false,
        );
      }
    }
  });
});

describe("corpus ⟂ unit fixtures (spec-v5 §4)", () => {
  it("no corpus document id collides with a unit fixture name", () => {
    const corpusIds = new Set(
      walk(join(CORPUS, "provenance"), (p) => p.endsWith(".json")).map((p) =>
        p
          .split("/")
          .pop()!
          .replace(/\.json$/, ""),
      ),
    );
    const fixtureStems = new Set(
      walk(FIXTURES, (p) => p.endsWith(".txt") || p.endsWith(".docx") || p.endsWith(".pdf")).map(
        (p) =>
          p
            .split("/")
            .pop()!
            .replace(/\.(txt|docx|pdf)$/, ""),
      ),
    );
    const overlap = [...corpusIds].filter((id) => fixtureStems.has(id));
    expect(overlap, "accuracy corpus and unit fixtures must be disjoint").toEqual([]);
  });
});
