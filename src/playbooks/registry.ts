/**
 * The list of every launch playbook id, in the order they appear in
 * spec §20. Used by the loader and by tests that enumerate the full
 * registry. Generic fallback is last by convention.
 */
export const LAUNCH_PLAYBOOK_IDS = [
  "mutual-nda",
  "unilateral-nda",
  "employment-at-will-us",
  "independent-contractor",
  "saas-customer",
  "saas-vendor",
  "msa-general",
  "sow",
  "lease-commercial-multitenant",
  "lease-residential-us",
  "consulting-agreement",
  "generic-fallback",
] as const;

export type LaunchPlaybookId = (typeof LAUNCH_PLAYBOOK_IDS)[number];
