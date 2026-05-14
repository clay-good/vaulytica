/**
 * v3 extractor shared types.
 *
 * Spec: spec-v3.md §17. Each v3 extractor is a pure function from a normalized
 * DocumentTree (plus, optionally, the v2 ExtractedData) to a deterministic,
 * JSON-serializable output. The aggregate {@link V3ExtractedData} is what the
 * v3 rule engine and the v3 report renderer consume.
 */

import type { DocPosition, Party } from "../types.js";

/* ---------------- §18 role classification ---------------- */

/** Controlled vocabulary of regulated-agreement legal roles. */
export type Role =
  | "covered-entity"
  | "business-associate"
  | "subcontractor"
  | "controller"
  | "processor"
  | "sub-processor"
  | "joint-controller"
  | "third-party"
  | "service-provider-ccpa"
  | "contractor-ccpa"
  | "service-recipient"
  | "service-supplier";

export type RoleEvidence =
  | "definition"
  | "recital"
  | "clause-usage"
  | "classifier";

export type RoleAssignment = {
  /** Party id from the v2 Party extractor when matched; else a synthetic id. */
  party_id: string;
  /** Party display name as it appears in the document. */
  party_name: string;
  role: Role;
  /** 0..1; 1.0 for definitional/explicit matches, lower for inference. */
  confidence: number;
  evidence: RoleEvidence;
  /** Where in the document the role was inferred. */
  position: DocPosition;
  /** The exact text span that triggered the match. */
  raw_text: string;
};

/* ---------------- §19 PHI / personal-data categories ---------------- */

export type DataCategoryGroup =
  | "hipaa-identifier"
  | "gdpr-special"
  | "gdpr-criminal"
  | "ccpa-sensitive"
  | "other";

export type DataCategory = {
  /** Slug; matches the normalized controlled vocabulary. */
  slug: string;
  /** Human label as detected. */
  label: string;
  group: DataCategoryGroup;
  position: DocPosition;
  raw_text: string;
};

/* ---------------- §20 cross-border transfer mechanism ---------------- */

export type TransferMechanismKind =
  | "scc-module-1"
  | "scc-module-2"
  | "scc-module-3"
  | "scc-module-4"
  | "scc-unspecified"
  | "uk-idta"
  | "uk-addendum"
  | "swiss-addendum"
  | "adequacy-decision"
  | "binding-corporate-rules"
  | "article-49-derogation"
  | "data-privacy-framework"
  | "unknown";

export type TransferMechanismLocation =
  | "inline"
  | "annex"
  | "attachment"
  | "by-reference"
  | "hyperlink"
  | "recital-only";

export type TransferMechanismReference = {
  kind: TransferMechanismKind;
  raw_text: string;
  location: TransferMechanismLocation;
  position: DocPosition;
};

/* ---------------- §21 security-measures inventory ---------------- */

export type SecurityMeasureSlug =
  | "encryption-at-rest"
  | "encryption-in-transit"
  | "mfa"
  | "sso"
  | "vulnerability-scanning"
  | "penetration-testing"
  | "security-training"
  | "bcp-dr"
  | "incident-response"
  | "access-controls-rbac"
  | "logging-audit"
  | "network-segmentation"
  | "hardware-tokens"
  | "secure-development-lifecycle"
  | "third-party-audits-soc2-t2"
  | "third-party-audits-iso-27001"
  | "third-party-audits-hitrust";

export type SecurityMeasureCadence =
  | "annual"
  | "biennial"
  | "continuous"
  | "on-incident"
  | "unspecified";

export type SecurityMeasureScope =
  | "production"
  | "all-systems"
  | "in-scope-systems"
  | "unspecified";

export type SecurityMeasure = {
  slug: SecurityMeasureSlug;
  raw_text: string;
  cadence: SecurityMeasureCadence;
  scope: SecurityMeasureScope;
  position: DocPosition;
};

/* ---------------- §22 breach-notification timing ---------------- */

export type BreachTrigger =
  | "discovery"
  | "confirmation"
  | "suspicion"
  | "determination"
  | "unspecified";

export type BreachAddressee =
  | "controller"
  | "regulator"
  | "data-subject"
  | "law-enforcement"
  | "customer-named-contact"
  | "unspecified";

export type BreachChannel =
  | "email"
  | "written-notice"
  | "designated-contact"
  | "phone"
  | "unspecified";

export type BreachTiming = {
  trigger: BreachTrigger;
  addressee: BreachAddressee;
  /** Normalized maximum delay in hours (when numeric). Null if a vague phrase. */
  max_delay_hours: number | null;
  /** Raw phrase if non-numeric: "without unreasonable delay", "promptly", etc. */
  max_delay_phrase: string | null;
  channel: BreachChannel;
  raw_text: string;
  position: DocPosition;
};

/* ---------------- §23 audit-rights / inspection ---------------- */

export type AuditMethod =
  | "onsite"
  | "remote"
  | "questionnaire-only"
  | "soc2-substitution"
  | "third-party-auditor";

export type AuditCostAllocation =
  | "auditee"
  | "auditor"
  | "cost-shift-on-findings"
  | "unspecified";

export type AuditRights = {
  /** Times-per-year frequency when numeric (1, 2, …); null for vague. */
  frequency_per_year: number | null;
  /** Notice period in days when numeric. */
  notice_days: number | null;
  scope_phrase: string;
  methods: AuditMethod[];
  cost_allocation: AuditCostAllocation;
  confidentiality_required: boolean;
  third_party_auditor_permitted: boolean;
  raw_text: string;
  position: DocPosition;
};

/* ---------------- §24 subprocessor inventory ---------------- */

export type SubprocessorConsentForm = "general-written" | "specific-prior" | "silent";

export type SubprocessorListLocation =
  | "annex"
  | "url"
  | "on-request"
  | "absent";

export type SubprocessorObjectionConsequence =
  | "terminate-for-convenience"
  | "terminate-affected-services"
  | "no-right"
  | "unspecified";

export type SubprocessorInventory = {
  permitted: boolean;
  consent_form: SubprocessorConsentForm;
  list_location: SubprocessorListLocation;
  /** Notice period for additions in days when numeric. */
  notice_days: number | null;
  objection_right: boolean;
  objection_consequence: SubprocessorObjectionConsequence;
  flow_down_required: boolean;
  position: DocPosition;
  raw_text: string;
};

/* ---------------- §25 insurance schedule ---------------- */

export type InsuranceLine =
  | "commercial-general-liability"
  | "professional-liability"
  | "cyber-liability"
  | "umbrella-excess"
  | "workers-compensation"
  | "employers-liability"
  | "automobile-liability"
  | "employment-practices-liability"
  | "fiduciary-liability"
  | "other";

export type InsuranceAmount = {
  line: InsuranceLine;
  /** Per-occurrence USD when stated; null if only aggregate. */
  per_occurrence_usd: number | null;
  /** Aggregate USD when stated. */
  aggregate_usd: number | null;
  raw_text: string;
  position: DocPosition;
};

export type InsuranceEndorsement = {
  /** ISO endorsement form (CG 20 10, CG 20 37, CG 20 26, etc.). */
  form_number: string;
  raw_text: string;
  position: DocPosition;
};

export type InsuranceSchedule = {
  amounts: InsuranceAmount[];
  endorsements: InsuranceEndorsement[];
  /** AM Best rating when stated in the contract requirements (e.g., "A-VII"). */
  required_am_best_rating: string | null;
  /** Notice-of-cancellation in days when numeric. */
  notice_of_cancellation_days: number | null;
};

/* ---------------- §26 DTSA / whistleblower notice ---------------- */

export type DtsaNotice = {
  present: boolean;
  /** True when the notice covers § 1833(b)(1) (gov/attorney disclosure immunity). */
  covers_government_disclosure: boolean;
  /** True when the notice covers § 1833(b)(2) (under-seal court filing exception). */
  covers_under_seal: boolean;
  /** True when the notice extends to contractors / consultants in addition to employees. */
  covers_contractors: boolean;
  /** True when all three substantive elements above are present. */
  substantively_complete: boolean;
  raw_text: string | null;
  position: DocPosition | null;
};

/* ---------------- aggregate ---------------- */

export type V3ExtractedData = {
  roles: RoleAssignment[];
  data_categories: DataCategory[];
  transfer_mechanisms: TransferMechanismReference[];
  security_measures: SecurityMeasure[];
  breach_timings: BreachTiming[];
  audit_rights: AuditRights[];
  subprocessor: SubprocessorInventory | null;
  insurance: InsuranceSchedule;
  dtsa_notice: DtsaNotice;
};

export type { Party, DocPosition };
