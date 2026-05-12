import { z } from "zod";
import type {
  ClauseLibraryEntry,
  DKB,
  DarkPatternEntry,
  DefinitionTemplate,
  DkbManifest,
  JurisdictionRecord,
  StatutoryIndexEntry,
} from "./types.js";

/**
 * Zod schemas for every DKB artifact. The DKB build pipeline validates
 * every file against the matching schema before publishing; the loader
 * validates again at fetch time so a corrupted CDN cache cannot poison
 * the rule engine silently.
 */

const isoString = z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/, {
  message: "must be ISO 8601 UTC ('YYYY-MM-DDTHH:MM:SSZ')",
});

const isoDate = z.string().regex(/^\d{4}-\d{2}-\d{2}/, {
  message: "must start with ISO 8601 date 'YYYY-MM-DD'",
});

const url = z.string().url();
const hex64 = z.string().regex(/^[0-9a-f]{64}$/);

export const SourceCitationSchema = z.object({
  id: z.string().min(1),
  source: z.string().min(1),
  source_url: url,
  retrieved_at: isoString,
  source_published_at: isoDate.optional(),
  license: z.string().min(1),
  license_url: url,
  attribution: z.string().optional(),
});

export const ClauseLibrarySchema = z.array(
  z.object({
    id: z.string().min(1),
    version: z.string().min(1),
    category: z.string().min(1),
    position: z.enum(["restrictive", "balanced", "permissive"]),
    normalized_text: z.string().min(1),
    jurisdiction: z.string().optional(),
    deal_types: z.array(z.string()),
    side: z
      .enum([
        "provider",
        "customer",
        "employer",
        "employee",
        "discloser",
        "recipient",
        "neutral",
      ])
      .optional(),
    source: SourceCitationSchema,
  }),
);

export const JurisdictionSchema = z.array(
  z.object({
    id: z.string().min(1),
    name: z.string().min(1),
    abbreviation: z.string().min(1),
    jurisdiction_type: z.enum([
      "us-state",
      "us-federal",
      "us-territory",
      "foreign-country",
      "foreign-subdivision",
    ]),
    court_structure: z.string().min(1),
    choice_of_law_citation: SourceCitationSchema.optional(),
    statute_of_frauds_citation: SourceCitationSchema.optional(),
    electronic_signature_law: z.object({
      standard: z.enum(["UETA", "ESIGN", "ESRA", "other"]),
      citation: SourceCitationSchema,
    }),
    arbitration_act_citation: SourceCitationSchema.optional(),
    non_compete_enforceability: z.enum(["enforced", "limited", "narrow", "void", "varies"]),
    statute_of_limitations_contract_years: z.number().positive(),
  }),
);

export const DefinitionTemplateSchema = z.array(
  z.object({
    id: z.string().min(1),
    version: z.string().min(1),
    term: z.string().min(1),
    variants: z.object({
      restrictive: z.object({ text: z.string().min(1), source: SourceCitationSchema }),
      balanced: z.object({ text: z.string().min(1), source: SourceCitationSchema }),
      permissive: z.object({ text: z.string().min(1), source: SourceCitationSchema }),
    }),
    notes: z.string().optional(),
  }),
);

export const DarkPatternSchema = z.array(
  z.object({
    id: z.string().min(1),
    version: z.string().min(1),
    pattern_description: z.string().min(1),
    detection: z.object({
      regex: z.array(z.string()).optional(),
      structural_check: z.string().optional(),
    }),
    plain_language_explanation: z.string().min(1),
    harm_pattern: z.string().min(1),
    authorities: z.array(SourceCitationSchema).min(1),
  }),
);

export const StatutorySchema = z.array(
  z.object({
    id: z.string().min(1),
    citation: z.string().min(1),
    canonical_url: url,
    jurisdiction: z.string().min(1),
    excerpt: z.string().min(1),
    retrieved_at: isoString,
    source_published_at: isoDate.optional(),
  }),
);

export const ClassifierVocabSchema = z.array(
  z.object({
    category: z.string().min(1),
    terms: z.record(z.string(), z.number()),
  }),
);

export const ClassifierPatternSchema = z.array(
  z.object({
    category: z.string().min(1),
    pattern: z.string().min(1),
    flags: z.string().optional(),
    confidence: z.number().min(0).max(1),
  }),
);

const FileRef = z.object({
  filename: z.string().min(1),
  sha256: hex64,
  entries: z.number().int().nonnegative().optional(),
});

export const DkbManifestSchema = z.object({
  version: z.string().min(1),
  schema_version: z.string().min(1),
  built_at: isoString,
  files: z.object({
    clauses: FileRef,
    jurisdictions: FileRef,
    definitions: FileRef,
    dark_patterns: FileRef,
    statutes: FileRef,
    classifier_vocab: FileRef,
    classifier_patterns: FileRef,
  }),
  sources: z.array(SourceCitationSchema),
});

/**
 * Compile-time check that the inferred Zod types match the hand-written
 * types in `./types.ts`. If a schema drifts from the types, TypeScript
 * surfaces the divergence here.
 */
type _CheckManifest = z.infer<typeof DkbManifestSchema> extends DkbManifest ? true : false;
type _CheckClauses = z.infer<typeof ClauseLibrarySchema> extends ClauseLibraryEntry[] ? true : false;
type _CheckJurisdictions =
  z.infer<typeof JurisdictionSchema> extends JurisdictionRecord[] ? true : false;
type _CheckDefinitions =
  z.infer<typeof DefinitionTemplateSchema> extends DefinitionTemplate[] ? true : false;
type _CheckDarkPatterns = z.infer<typeof DarkPatternSchema> extends DarkPatternEntry[] ? true : false;
type _CheckStatutes = z.infer<typeof StatutorySchema> extends StatutoryIndexEntry[] ? true : false;
type _CheckDkb = DKB extends DKB ? true : false;
// References silenced so TS treats them as used.
const _checks: [
  _CheckManifest,
  _CheckClauses,
  _CheckJurisdictions,
  _CheckDefinitions,
  _CheckDarkPatterns,
  _CheckStatutes,
  _CheckDkb,
] = [true, true, true, true, true, true, true];
void _checks;
