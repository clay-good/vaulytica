/**
 * Court-deadline computation — computation profiles.
 *
 * Cited, versioned data (mirrors `src/filing/court-profile.ts`'s
 * cited-data + Zod pattern). A profile is the rule set
 * {@link import("./compute.js").computeDeadline} applies against a
 * trigger date: whether the trigger day itself counts, whether a
 * non-court-day landing rolls forward, and the Rule 6(d)-style service
 * add-on. All values are cited; nothing is inferred.
 */

import { z } from "zod";

export const SERVICE_METHODS = [
  "electronic",
  "mail",
  "clerk",
  "other-consented",
  "personal",
] as const;
export type ServiceMethod = (typeof SERVICE_METHODS)[number];

const citation = z
  .object({
    cite: z.string().min(1),
    url: z.string().url(),
    retrieved_at: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "retrieved_at must be YYYY-MM-DD"),
  })
  .strict();

export const DeadlineProfileSchema = z
  .object({
    id: z.string().min(1),
    name: z.string().min(1),
    version: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "version is a release date YYYY-MM-DD"),
    exclude_trigger_day: z.boolean(),
    count_basis: z.literal("calendar-days"),
    roll_forward: z.boolean(),
    calendar_id: z.string().min(1),
    service_adjustment_days: z.number().int().nonnegative(),
    service_methods_adjusted: z.array(z.enum(SERVICE_METHODS)),
    authority: z.array(citation).min(1),
  })
  .strict();

export type DeadlineProfile = z.infer<typeof DeadlineProfileSchema>;

const FRCP_6: DeadlineProfile = {
  id: "frcp-6",
  name: "Federal Rules of Civil Procedure — Rule 6",
  version: "2026-07-15",
  exclude_trigger_day: true,
  count_basis: "calendar-days",
  roll_forward: true,
  calendar_id: "us-federal",
  service_adjustment_days: 3,
  service_methods_adjusted: ["mail", "clerk", "other-consented"],
  authority: [
    {
      cite: "Fed. R. Civ. P. 6(a), (d)",
      url: "https://www.law.cornell.edu/rules/frcp/rule_6",
      retrieved_at: "2026-07-15",
    },
  ],
};

const CAL_CCP_12: DeadlineProfile = {
  id: "cal-ccp-12",
  name: "California Code of Civil Procedure §§ 12, 12a",
  version: "2026-07-15",
  exclude_trigger_day: true,
  count_basis: "calendar-days",
  roll_forward: true,
  calendar_id: "california",
  // Cal. Civ. Proc. Code § 1013(a): service by mail within California extends
  // the deadline by 5 calendar days (not the federal 3). Electronic and
  // personal service earn no extension here (v1 scope).
  service_adjustment_days: 5,
  service_methods_adjusted: ["mail"],
  authority: [
    {
      cite: "Cal. Civ. Proc. Code §§ 12, 12a",
      url: "https://leginfo.legislature.ca.gov/",
      retrieved_at: "2026-07-15",
    },
    {
      cite: "Cal. Civ. Proc. Code § 1013(a)",
      url: "https://leginfo.legislature.ca.gov/",
      retrieved_at: "2026-07-15",
    },
  ],
};

/** Parse and validate a deadline profile. Throws a ZodError on failure. */
export function parseDeadlineProfile(data: unknown): DeadlineProfile {
  return DeadlineProfileSchema.parse(data);
}

/** All shipped deadline profiles, keyed by id. Validated at module load. */
export const DEADLINE_PROFILES: Readonly<Record<string, DeadlineProfile>> = Object.freeze(
  Object.fromEntries(
    [FRCP_6, CAL_CCP_12].map((p) => {
      const profile = parseDeadlineProfile(p);
      return [profile.id, profile];
    }),
  ),
);

/** The ids a `--profile` flag / picker accepts, sorted for stable display. */
export const DEADLINE_PROFILE_IDS: readonly string[] = Object.keys(DEADLINE_PROFILES).sort();

/** Look up a shipped profile by id, or `undefined` if unknown. */
export function getDeadlineProfile(id: string): DeadlineProfile | undefined {
  return DEADLINE_PROFILES[id];
}
