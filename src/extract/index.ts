/**
 * Extractor layer barrel. Each extractor is a pure function from the
 * normalized {@link DocumentTree} (plus dependencies it needs) to its
 * typed output. The composite {@link ExtractedData} is what the rule
 * engine consumes.
 *
 * Determinism contract: every extractor is referentially transparent. No
 * time, no randomness, no network, no environment.
 */

import type { DocumentTree } from "../ingest/types.js";
import { extractParties } from "./parties.js";
import { extractDates } from "./dates.js";
import { extractAmounts } from "./amounts.js";
import { extractDefinitions } from "./definitions.js";
import { extractSections } from "./sections.js";
import { extractCrossRefs } from "./crossrefs.js";
import { extractObligations } from "./obligations.js";
import { extractJurisdictions, type DkbLookup } from "./jurisdictions.js";
import { classifyClauses, type ClassifierData } from "./classifier.js";
import type { ExtractedData } from "./types.js";

export type {
  Party,
  DateReference,
  DateReferenceType,
  MoneyReference,
  DefinitionMap,
  DefinitionEntry,
  SectionOutline,
  SectionOutlineNode,
  CrossRef,
  Obligation,
  JurisdictionReference,
  ClassifiedParagraph,
  ExtractedData,
  DocPosition,
} from "./types.js";

export { extractParties } from "./parties.js";
export { extractDates } from "./dates.js";
export { extractAmounts } from "./amounts.js";
export { extractDefinitions } from "./definitions.js";
export { extractSections, flattenOutline } from "./sections.js";
export { extractCrossRefs } from "./crossrefs.js";
export { extractObligations } from "./obligations.js";
export { extractJurisdictions } from "./jurisdictions.js";
export type { DkbLookup } from "./jurisdictions.js";
export { classifyClauses } from "./classifier.js";
export type { ClassifierData, ClassifierVocab, ClassifierPattern } from "./classifier.js";

/**
 * Convenience: run every extractor in dependency order against a tree.
 * Useful for tests and for the UI hookup in build step 12.
 */
export function extractAll(
  tree: DocumentTree,
  options: { classifier?: ClassifierData; jurisdictionLookup?: DkbLookup } = {},
): ExtractedData {
  const parties = extractParties(tree);
  const dates = extractDates(tree);
  const amounts = extractAmounts(tree);
  const definitions = extractDefinitions(tree);
  const outline = extractSections(tree);
  const crossrefs = extractCrossRefs(tree, outline);
  const obligations = extractObligations(tree, parties);
  const jurisdictions = extractJurisdictions(tree, options.jurisdictionLookup);
  const classified = classifyClauses(tree, options.classifier);
  return {
    parties,
    dates,
    amounts,
    definitions,
    outline,
    crossrefs,
    obligations,
    jurisdictions,
    classified,
  };
}
