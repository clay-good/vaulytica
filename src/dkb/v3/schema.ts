import { z } from "zod";
import type {
  ConsistencyCheck,
  InsuranceNorm,
  PinnedCitation,
  RegulatorModelForm,
  StatutoryClauseRequirement,
  SubprocessorRequirement,
  TransferMechanism,
  V3DkbNode,
} from "./types.js";

/**
 * Zod schemas for v3 DKB node types. See `./types.ts` and spec-v3.md §13.
 * The build pipeline validates every node before publishing; the loader
 * re-validates so a corrupted asset cannot poison the rule engine.
 */

const iso = z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/, {
  message: "must be ISO 8601 UTC ('YYYY-MM-DDTHH:MM:SSZ')",
});
const isoDate = z.string().regex(/^\d{4}-\d{2}-\d{2}$/, {
  message: "must be ISO 8601 date 'YYYY-MM-DD'",
});
const hex64 = z.string().regex(/^[0-9a-f]{64}$/);
const url = z.string().url();

export const PinnedCitationSchema = z.object({
  authority: z.string().min(1),
  citation: z.string().min(1),
  source_url: url,
  content_hash_at_pin: hex64,
  fetched_at: iso,
});

const baseFields = {
  id: z.string().min(1),
  dkb_node_version: z.number().int().nonnegative(),
  dkb_node_last_validated_at: iso,
  cites: z.array(PinnedCitationSchema).min(1),
};

export const RegulatorModelFormSchema = z.object({
  ...baseFields,
  node_type: z.literal("regulator_model_form"),
  name: z.string().min(1),
  regulator: z.string().min(1),
  jurisdiction: z.string().min(1),
  authoritative_url: url,
  vendored_path: z.string().min(1),
  vendored_content_hash: hex64,
  clauses: z
    .array(
      z.object({
        clause_id: z.string().min(1),
        heading: z.string().optional(),
        required_by_citation: z.string().min(1),
        normalized_text: z.string().min(1),
      }),
    )
    .min(1),
});

export const StatutoryClauseRequirementSchema = z.object({
  ...baseFields,
  node_type: z.literal("statutory_clause_requirement"),
  regulator: z.string().min(1),
  jurisdiction: z.string().min(1),
  authority: z.string().min(1),
  citation: z.string().min(1),
  effective_date: isoDate,
  requirement: z.string().min(1),
  minimum_compliant_text: z.string().min(1),
  applies_to_document_types: z.array(z.string().min(1)).min(1),
});

export const TransferMechanismSchema = z.object({
  ...baseFields,
  node_type: z.literal("transfer_mechanism"),
  kind: z.enum([
    "adequacy_decision",
    "scc_module_1",
    "scc_module_2",
    "scc_module_3",
    "scc_module_4",
    "uk_idta",
    "uk_addendum",
    "swiss_addendum",
    "bcr",
    "art_49_derogation",
  ]),
  name: z.string().min(1),
  scope: z.string().min(1),
  required_ancillary_documents: z.array(z.string()),
  status_note: z.string().optional(),
});

export const SubprocessorRequirementSchema = z.object({
  ...baseFields,
  node_type: z.literal("subprocessor_requirement"),
  regulator: z.string().min(1),
  jurisdiction: z.string().min(1),
  notice_period_days: z.number().int().nonnegative().optional(),
  objection_rights: z.enum(["general", "specific", "none"]),
  flow_down_required: z.boolean(),
  list_publication_required: z.boolean(),
  notes: z.string().optional(),
});

export const InsuranceNormSchema = z.object({
  ...baseFields,
  node_type: z.literal("insurance_norm"),
  vertical: z.string().min(1),
  coverage_type: z.enum([
    "general_liability",
    "professional_liability",
    "cyber",
    "workers_compensation",
    "umbrella",
    "auto",
    "errors_and_omissions",
  ]),
  minimum_per_occurrence_usd: z.number().nonnegative(),
  minimum_aggregate_usd: z.number().nonnegative(),
  required_endorsements: z.array(z.string()),
  minimum_carrier_rating: z.string().min(1),
});

export const ConsistencyCheckSchema = z.object({
  ...baseFields,
  node_type: z.literal("consistency_check"),
  name: z.string().min(1),
  document_pair: z.tuple([z.string().min(1), z.string().min(1)]),
  description: z.string().min(1),
  implementing_rule_id: z.string().min(1),
});

export const V3DkbNodeSchema = z.discriminatedUnion("node_type", [
  RegulatorModelFormSchema,
  StatutoryClauseRequirementSchema,
  TransferMechanismSchema,
  SubprocessorRequirementSchema,
  InsuranceNormSchema,
  ConsistencyCheckSchema,
]);

/** Validate an unknown JSON value as a v3 node, throwing on failure. */
export const parseV3Node = (value: unknown): V3DkbNode => V3DkbNodeSchema.parse(value);

/** Validate an array of mixed v3 nodes. */
export const V3DkbNodeListSchema = z.array(V3DkbNodeSchema);

// Compile-time check that the Zod inference matches the hand-written types.
type _Pinned = z.infer<typeof PinnedCitationSchema> extends PinnedCitation ? true : false;
type _Rmf = z.infer<typeof RegulatorModelFormSchema> extends RegulatorModelForm ? true : false;
type _Scr =
  z.infer<typeof StatutoryClauseRequirementSchema> extends StatutoryClauseRequirement
    ? true
    : false;
type _Tm = z.infer<typeof TransferMechanismSchema> extends TransferMechanism ? true : false;
type _Sub =
  z.infer<typeof SubprocessorRequirementSchema> extends SubprocessorRequirement ? true : false;
type _Ins = z.infer<typeof InsuranceNormSchema> extends InsuranceNorm ? true : false;
type _Cc = z.infer<typeof ConsistencyCheckSchema> extends ConsistencyCheck ? true : false;
const _checks: [_Pinned, _Rmf, _Scr, _Tm, _Sub, _Ins, _Cc] = [
  true,
  true,
  true,
  true,
  true,
  true,
  true,
];
void _checks;
