/**
 * Deterministic TF-IDF trainer for the clause classifier (spec §13,
 * build step 11).
 *
 * Training input: a flat list of `{category, text}` examples, where
 * `category` has already been reconciled against the unified taxonomy.
 *
 * Output: a `ClassifierVocabFile` shape compatible with
 * `dkb-classifier-vocab.json` — one row per category with up to
 * {@link TOP_K} terms and their TF-IDF weights.
 *
 * Determinism: the standard formula `tf(t,c) * log(N / df(t))` with
 * raw term frequency. Tokenization comes from the same `tokenize()`
 * used at inference time. Ties (in weight) are broken alphabetically
 * by term so the output JSON is byte-stable across re-runs.
 */

import { tokenize } from "./tokenize.js";

export const TOP_K = 1000;

export type ClassifierExample = { category: string; text: string };

export type CategoryVocab = {
  category: string;
  /** term → weight, JSON-serializable. */
  terms: Record<string, number>;
};

export type TfIdfTrainOptions = {
  stopwords: ReadonlySet<string>;
  /** Cap on terms kept per category (default 1000). */
  top_k?: number;
  /** Optional explicit category list — if omitted, derived from examples. */
  categories?: string[];
};

export function trainTfIdf(
  examples: readonly ClassifierExample[],
  opts: TfIdfTrainOptions,
): CategoryVocab[] {
  const topK = opts.top_k ?? TOP_K;

  // 1) Group tokens per category. categoryTermPresence is local to
  // this call so repeated training runs stay deterministic.
  const perCategoryTf = new Map<string, Map<string, number>>();
  const categoryTermPresence = new Map<string, Set<string>>();
  const docCounts = new Map<string, number>();

  for (const ex of examples) {
    const cat = ex.category;
    const tokens = tokenize(ex.text, opts.stopwords);
    let tf = perCategoryTf.get(cat);
    if (!tf) {
      tf = new Map();
      perCategoryTf.set(cat, tf);
    }
    for (const t of tokens) tf.set(t, (tf.get(t) ?? 0) + 1);
    // For IDF: count how many distinct categories contain this term.
    const seen = new Set(tokens);
    for (const t of seen) {
      let cats = categoryTermPresence.get(t);
      if (!cats) {
        cats = new Set();
        categoryTermPresence.set(t, cats);
      }
      cats.add(cat);
    }
  }

  for (const [term, cats] of categoryTermPresence) {
    docCounts.set(term, cats.size);
  }

  const N = perCategoryTf.size || 1;

  // 3) For each category, compute weights and pick top-K.
  const cats = (opts.categories ?? [...perCategoryTf.keys()]).slice().sort();
  const out: CategoryVocab[] = [];
  for (const cat of cats) {
    const tf = perCategoryTf.get(cat);
    if (!tf) {
      out.push({ category: cat, terms: {} });
      continue;
    }
    const weighted: Array<[string, number]> = [];
    for (const [term, count] of tf) {
      const df = docCounts.get(term) ?? 1;
      const idf = Math.log(N / df);
      // Standard `tf * idf`, no normalization. We export the raw weight
      // and cosine-normalize at inference time.
      const weight = count * idf;
      if (weight <= 0) continue;
      weighted.push([term, weight]);
    }
    weighted.sort((a, b) => {
      if (b[1] !== a[1]) return b[1] - a[1];
      return a[0].localeCompare(b[0]);
    });
    const top = weighted.slice(0, topK);
    const terms: Record<string, number> = {};
    for (const [t, w] of top) terms[t] = round6(w);
    out.push({ category: cat, terms });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Internal helpers

function round6(n: number): number {
  return Math.round(n * 1_000_000) / 1_000_000;
}

/** Cosine similarity between an input token bag and a category vocabulary. */
export function cosineScore(
  inputTokens: readonly string[],
  vocab: CategoryVocab,
): number {
  // Build the input vector with raw term counts.
  const input = new Map<string, number>();
  for (const t of inputTokens) input.set(t, (input.get(t) ?? 0) + 1);

  let dot = 0;
  let inputNorm2 = 0;
  let vocabNorm2 = 0;
  for (const v of Object.values(vocab.terms)) vocabNorm2 += v * v;
  for (const [, c] of input) inputNorm2 += c * c;
  for (const [t, c] of input) {
    const w = vocab.terms[t];
    if (w) dot += c * w;
  }
  if (inputNorm2 === 0 || vocabNorm2 === 0) return 0;
  return dot / Math.sqrt(inputNorm2 * vocabNorm2);
}

/**
 * Classify a single text against a vocabulary set. Returns the
 * highest-scoring `{category, confidence}`. Ties broken
 * alphabetically by category name for determinism.
 */
export function classify(
  text: string,
  vocabs: readonly CategoryVocab[],
  stopwords: ReadonlySet<string>,
): { category: string; confidence: number } | undefined {
  const toks = tokenize(text, stopwords);
  if (toks.length === 0) return undefined;
  let best: { category: string; confidence: number } | undefined;
  for (const v of vocabs) {
    const score = cosineScore(toks, v);
    if (!best || score > best.confidence || (score === best.confidence && v.category < best.category)) {
      best = { category: v.category, confidence: score };
    }
  }
  return best;
}
