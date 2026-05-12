/**
 * Shared tokenizer for the classifier training pipeline and the
 * inference-time classifier in `src/extract/classifier.ts`. Determinism
 * is achieved by:
 *   - Pure ASCII-folding lowercasing
 *   - Splitting on `/[^a-z0-9]+/` after lowercasing
 *   - Removing stopwords from the contract-specific list
 *   - No stemming (legal vocabulary penalizes stemming per spec §13)
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";

const TOKEN_SPLIT = /[^a-z0-9]+/g;

export function tokenize(text: string, stopwords: ReadonlySet<string>): string[] {
  const out: string[] = [];
  const lowered = text.toLowerCase();
  for (const tok of lowered.split(TOKEN_SPLIT)) {
    if (!tok) continue;
    if (tok.length < 2) continue;
    if (stopwords.has(tok)) continue;
    if (/^\d+$/.test(tok)) continue;
    out.push(tok);
  }
  return out;
}

export function parseStopwordList(text: string): Set<string> {
  const out = new Set<string>();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    out.add(line.toLowerCase());
  }
  return out;
}

export async function loadStopwords(path?: string): Promise<Set<string>> {
  const p = path ?? join(process.cwd(), "dkb", "build", "stopwords.txt");
  const text = await readFile(p, "utf8");
  return parseStopwordList(text);
}
