/**
 * Classifier barrel for the build pipeline.
 */
export { tokenize, parseStopwordList, loadStopwords } from "./tokenize.js";
export {
  parseTaxonomy,
  loadTaxonomy,
  buildAliasMap,
  reconcileCategory,
  slugify,
  type Taxonomy,
} from "./taxonomy.js";
export {
  trainTfIdf,
  cosineScore,
  classify,
  TOP_K,
  type ClassifierExample,
  type CategoryVocab,
  type TfIdfTrainOptions,
} from "./tfidf.js";
export { PATTERNS } from "./patterns.js";
