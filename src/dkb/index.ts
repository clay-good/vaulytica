/**
 * Deterministic Knowledge Base — public surface.
 *
 * Consumers (rule engine, playbook matcher, report builder) import the
 * loaded {@link DKB} from this barrel. The classifier extractor consumes
 * `dkb.classifier.{vocab,patterns}` directly.
 */
export type {
  ClauseLibraryEntry,
  ClausePosition,
  ClauseSide,
  DKB,
  DarkPatternEntry,
  DefinitionTemplate,
  DefinitionVariant,
  DkbFileRef,
  DkbManifest,
  ElectronicSignatureStandard,
  JurisdictionRecord,
  NonCompeteEnforceability,
  SourceCitation,
  StatutoryIndexEntry,
  ClassifierVocabEntry,
  ClassifierPatternEntry,
} from "./types.js";

export {
  ClassifierPatternSchema,
  ClassifierVocabSchema,
  ClauseLibrarySchema,
  DarkPatternSchema,
  DefinitionTemplateSchema,
  DkbManifestSchema,
  JurisdictionSchema,
  SourceCitationSchema,
  StatutorySchema,
} from "./schema.js";

export { loadDkb, DkbLoadError, validateV3Nodes } from "./loader.js";
export type { LoadDkbOptions } from "./loader.js";

export {
  compareDkbVersions,
  isValidDkbVersion,
  parseDkbVersion,
} from "./version.js";
export type { ParsedDkbVersion } from "./version.js";
