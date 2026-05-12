import type { DocumentTree } from "../ingest/types.js";
import type { ClassifiedParagraph } from "./types.js";
import { forEachParagraph } from "./walk.js";

/**
 * Deterministic clause classifier: TF-IDF cosine similarity with a regex
 * pattern overlay. The full classifier data lives in the DKB
 * (`dkb-classifier-vocab.json`, `dkb-classifier-patterns.json`); this
 * module is the inference-time engine that consumes that data.
 *
 * Until Step 5 lands the DKB, callers may pass an empty
 * {@link ClassifierData} and every paragraph is labeled `"unclassified"`
 * with method `"unclassified"`. This keeps the type-level wiring stable
 * across the build steps.
 *
 * Determinism: tie-breaks are alphabetical by category. The tokenizer is
 * a single regex with no locale dependence.
 */

export type ClassifierVocab = {
  /** Category → term → TF-IDF weight. */
  vocab: Record<string, Record<string, number>>;
  /** Optional stopword list to filter from incoming paragraphs. */
  stopwords?: string[];
  /** Cosine threshold below which we report `"unclassified"`. Default 0.10. */
  threshold?: number;
};

export type ClassifierPattern = {
  category: string;
  /** Regex source. */
  pattern: string;
  /** Regex flags (always parsed case-insensitive if no `i` is set). */
  flags?: string;
  /** Confidence emitted on match. Defaults to 0.95. */
  confidence?: number;
};

export type ClassifierData = {
  vocab?: ClassifierVocab;
  patterns?: ClassifierPattern[];
};

export function classifyClauses(
  tree: DocumentTree,
  data: ClassifierData = {},
): ClassifiedParagraph[] {
  const out: ClassifiedParagraph[] = [];
  const patterns = compilePatterns(data.patterns ?? []);
  const vocab = data.vocab;
  const stopwords = new Set(vocab?.stopwords ?? DEFAULT_STOPWORDS);
  const threshold = vocab?.threshold ?? 0.1;

  forEachParagraph(tree, (ctx) => {
    // 1) pattern overlay
    const patternHit = patterns.find((p) => p.re.test(ctx.text));
    if (patternHit) {
      out.push({
        paragraph_id: ctx.paragraph.id,
        section_id: ctx.section.id,
        category: patternHit.category,
        confidence: patternHit.confidence,
        method: "pattern",
      });
      return;
    }

    // 2) TF-IDF fallback
    if (vocab && Object.keys(vocab.vocab).length > 0) {
      const tokens = tokenize(ctx.text, stopwords);
      const tf = termFrequency(tokens);
      let best: { category: string; score: number } | null = null;
      const cats = Object.keys(vocab.vocab).sort();
      for (const cat of cats) {
        const score = cosineSimilarity(tf, vocab.vocab[cat]!);
        if (!best || score > best.score) best = { category: cat, score };
      }
      if (best && best.score >= threshold) {
        out.push({
          paragraph_id: ctx.paragraph.id,
          section_id: ctx.section.id,
          category: best.category,
          confidence: best.score,
          method: "tfidf",
        });
        return;
      }
    }

    out.push({
      paragraph_id: ctx.paragraph.id,
      section_id: ctx.section.id,
      category: "unclassified",
      confidence: 0,
      method: "unclassified",
    });
  });

  return out;
}

function compilePatterns(raw: ClassifierPattern[]): {
  category: string;
  re: RegExp;
  confidence: number;
}[] {
  return raw.map((p) => {
    let flags = p.flags ?? "";
    if (!flags.includes("i")) flags += "i";
    return {
      category: p.category,
      re: new RegExp(p.pattern, flags),
      confidence: p.confidence ?? 0.95,
    };
  });
}

function tokenize(text: string, stopwords: Set<string>): string[] {
  return text
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t.length >= 2 && !stopwords.has(t));
}

function termFrequency(tokens: string[]): Record<string, number> {
  const tf: Record<string, number> = {};
  for (const t of tokens) tf[t] = (tf[t] ?? 0) + 1;
  const total = tokens.length || 1;
  for (const k of Object.keys(tf)) tf[k] = tf[k]! / total;
  return tf;
}

function cosineSimilarity(
  a: Record<string, number>,
  b: Record<string, number>,
): number {
  let dot = 0;
  let magA = 0;
  let magB = 0;
  for (const k of Object.keys(a)) {
    const av = a[k]!;
    magA += av * av;
    const bv = b[k];
    if (bv !== undefined) dot += av * bv;
  }
  for (const k of Object.keys(b)) {
    const bv = b[k]!;
    magB += bv * bv;
  }
  if (magA === 0 || magB === 0) return 0;
  return dot / (Math.sqrt(magA) * Math.sqrt(magB));
}

const DEFAULT_STOPWORDS = [
  "the", "a", "an", "and", "or", "of", "to", "in", "on", "at", "by", "for",
  "with", "as", "is", "it", "be", "this", "that", "these", "those",
  "shall", "party", "agreement", "section", "hereof", "hereunder",
  "thereof", "thereto", "herein", "therein", "such", "any", "all", "each",
  "no", "not", "but", "if", "then", "so", "may", "will", "would", "could",
  "should", "do", "does", "did", "has", "have", "had",
];
