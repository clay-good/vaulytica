/**
 * Court profiles — versioned, cited data behind the filing-format-lint pack
 * (add-filing-format-lint). Each profile carries a court's numeric filing
 * limits and required blocks, and — for every limit and block — the rule
 * citation, source URL, and retrieval date. The FILE-### rules read the
 * selected profile from `ctx.options.filing`; nothing is inferred, so a limit
 * without cited authority fails schema validation rather than shipping.
 *
 * Profiles are data, not code: content changes are releases (a new `version`),
 * never silent edits. The Zod schema below is the CI gate.
 */

import { z } from "zod";
import FRAP_DEFAULT from "./profiles/frap-default.json";
import CA9_APPELLATE from "./profiles/ca9-appellate.json";
import CAL_RULES_8204 from "./profiles/cal-rules-8.204.json";

/** The filing blocks a profile may require, and that FILE rules presence-check. */
export const FILING_BLOCKS = [
  "caption",
  "table-of-contents",
  "table-of-authorities",
  "certificate-of-compliance",
  "certificate-of-service",
  "signature-block",
] as const;
export type FilingBlock = (typeof FILING_BLOCKS)[number];

/**
 * Blocks a profile may exclude from the type-volume word count (e.g. the FRAP
 * 32(f) items: cover, disclosure statement, tables, certificates, signature
 * blocks). Named separately from {@link FILING_BLOCKS} because "cover" and
 * "disclosure-statement" are excludable but not presence-required.
 */
export const COUNT_EXCLUSIONS = [
  "cover",
  "disclosure-statement",
  "table-of-contents",
  "table-of-authorities",
  "certificate-of-compliance",
  "certificate-of-service",
  "signature-block",
] as const;
export type CountExclusion = (typeof COUNT_EXCLUSIONS)[number];

const citation = z
  .object({
    cite: z.string().min(1),
    url: z.string().url(),
    retrieved_at: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "retrieved_at must be YYYY-MM-DD"),
  })
  .strict();

/** A numeric limit with its cited authority. */
const limit = z
  .object({
    value: z.number().int().positive(),
    cite: z.string().min(1),
    url: z.string().url(),
    retrieved_at: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  })
  .strict();

const requiredBlock = z
  .object({
    block: z.enum(FILING_BLOCKS),
    cite: z.string().min(1),
    url: z.string().url(),
    retrieved_at: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  })
  .strict();

export const CourtProfileSchema = z
  .object({
    id: z.string().min(1),
    court_name: z.string().min(1),
    version: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "version is a release date YYYY-MM-DD"),
    authority: z.array(citation).min(1),
    limits: z
      .object({
        principal_words: limit.optional(),
        reply_words: limit.optional(),
        principal_pages: limit.optional(),
        reply_pages: limit.optional(),
      })
      .strict(),
    required_blocks: z.array(requiredBlock),
    count_exclusions: z.array(z.enum(COUNT_EXCLUSIONS)),
  })
  .strict();

export type CourtProfile = z.infer<typeof CourtProfileSchema>;

/** Parse and validate a court profile. Throws a ZodError naming the field on failure. */
export function parseCourtProfile(data: unknown): CourtProfile {
  return CourtProfileSchema.parse(data);
}

/** All shipped court profiles, keyed by id. Validated at module load. */
export const COURT_PROFILES: Readonly<Record<string, CourtProfile>> = Object.freeze(
  Object.fromEntries(
    [FRAP_DEFAULT, CA9_APPELLATE, CAL_RULES_8204].map((p) => {
      const profile = parseCourtProfile(p);
      return [profile.id, profile];
    }),
  ),
);

/** The ids a `--court` flag / tab picker accepts, sorted for stable display. */
export const COURT_PROFILE_IDS: readonly string[] = Object.keys(COURT_PROFILES).sort();

/** Look up a shipped profile by id, or `undefined` if unknown. */
export function getCourtProfile(id: string): CourtProfile | undefined {
  return COURT_PROFILES[id];
}
