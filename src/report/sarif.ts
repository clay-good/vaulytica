/**
 * SARIF 2.1.0 export (spec-v8 §20, Step 141).
 *
 * Emits an `EngineRun` as a Static Analysis Results Interchange Format
 * document — the JSON GitHub Code Scanning, VS Code, and the linter
 * ecosystem consume. A "linter for legal documents" that speaks SARIF can
 * annotate a pull request, populate a code-scanning dashboard, and dedupe
 * findings across runs.
 *
 * The mapping is mechanical and deterministic:
 *   - each fired rule → a `reportingDescriptor` (id, name, `helpUri` = the
 *     citation URL, `shortDescription`);
 *   - each finding → a `result` (level from severity, message, a section
 *     `location`, `partialFingerprints` from the deterministic finding id +
 *     `result_hash` so findings dedupe across runs);
 *   - each `SourceCitation` → the rule's `helpUri` + the result's
 *     `properties.citations` (carrying source, URL, and the §17 freshness
 *     signal), so a SARIF result is as citable as the DOCX (spec-v8 §3
 *     corollary: a new format carries no less provenance than the report).
 *
 * Deterministic canonical JSON: rules sorted by id, results in the run's
 * sorted finding order, no wall-clock in the body. Render-side — it reads
 * the `EngineRun` and changes no `result_hash`.
 */

import type { EngineRun, Finding, Severity } from "../engine/finding.js";
import type { SourceCitation } from "../dkb/types.js";
import { ENGINE_VERSION } from "../engine/runner.js";
import {
  currencyLabel,
  formatCitation,
  freshnessSignal,
  type CitationCurrency,
} from "./citations.js";
import type { V9Surfaces } from "./v9-surfaces.js";
import { buildReviewCoverage, reviewCoverageSentence } from "./review-coverage.js";
import { erroredRuleNotice } from "./execution-log.js";
import type { HandoffFinding } from "../delivery/types.js";
import type { IngestResult } from "../ingest/types.js";
import type { CriticalDate, CriticalDateKind } from "./critical-dates.js";
import type { ConsistencyFinding, ConsistencyRun } from "../engine/consistency/types.js";

/**
 * Thrust B (the closing checklist) in SARIF, WITHOUT duplicating a single
 * result.
 *
 * Every checklist item is a re-projection of a rule the SARIF already emits —
 * the `STRUCT-*` readiness findings as engine results, `HANDOFF-001/002` as
 * delivery results — so emitting the checklist as its own results would
 * double-count in exactly the surface where a count is load-bearing: a CI gate
 * that fails on a threshold. That is why the checklist body is deliberately
 * absent here and always will be.
 *
 * What was missing is the ROLL-UP. A pipeline reading the SARIF could see the
 * individual results but had no way to learn that N of them are the
 * execution-readiness set, or which category each belongs to, without
 * hardcoding the rule list — a list that lives in `closing-checklist.ts` and
 * moves. So the checklist arrives as run-level `properties.readiness` (the
 * open count and the per-category counts) plus a `readiness` tag on the
 * results that ARE checklist items. Same facts, no second copy.
 *
 * Gated on a non-empty checklist, so a run without `--checklist` produces the
 * byte-identical SARIF it did before this existed.
 */
function readinessCategories(v9?: V9Surfaces): Map<string, string> {
  const items = v9?.closingChecklist?.items ?? [];
  return new Map(items.map((i) => [i.rule_id, i.category]));
}

/** Human label per derived-deadline family (Thrust C), for SARIF descriptors. */
const CRITICAL_DATE_KIND_LABEL: Record<CriticalDateKind, string> = {
  "auto-renewal-notice": "Auto-renewal notice deadline",
  "cure-window": "Cure window deadline",
  "opt-out-window": "Opt-out / termination window",
  "survival-end": "Survival-end date",
  "notice-period": "Notice-period deadline",
};

const SARIF_SCHEMA =
  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
const INFORMATION_URI = "https://github.com/clay-good/vaulytica";

/** Synthetic rule id for the unmatched-document banner in SARIF output. */
const CLASSIFICATION_NOTICE_RULE_ID = "VAULYTICA-CLASSIFICATION-NOTICE";

/**
 * Synthetic rule id for "About this input" — what the ingest could and could
 * not read. A note-level result rather than an invocation notification: CI and
 * code scanning annotate on RESULTS, and a notification a dashboard renders
 * nowhere is the same silence this notice exists to break.
 */
const INPUT_NOTICE_RULE_ID = "VAULYTICA-INPUT-NOTICE";

/**
 * Synthetic rule id for "the secondary-family list you are reading is
 * truncated". Same reasoning as the input notice: the terminal has said this
 * since the count existed, and SARIF — the artifact the Action uploads, and the
 * only one a code-scanning dashboard reads — said nothing, so a CI job saw four
 * scanned families and no way to learn that four more were never looked at.
 */
const SECONDARY_CAP_RULE_ID = "VAULYTICA-SECONDARY-FAMILIES-CAPPED";

/**
 * Synthetic rule id for the attorney-review caveat.
 *
 * "0 of N findings cite an attorney-reviewed rule — every rule applied here is
 * author-asserted" is the single most load-bearing sentence this tool emits,
 * and the DOCX and HTML reports were the only surfaces carrying it. SARIF is
 * what a code-scanning dashboard shows a reviewer who never opens the Word
 * file: it annotated N findings and said nothing about what any of them rests
 * on. Always emitted when there are findings, exactly as the report always
 * emits it — a coverage statement you can skip when it is inconvenient is not
 * a coverage statement.
 */
const REVIEW_COVERAGE_RULE_ID = "VAULYTICA-ATTORNEY-REVIEW-COVERAGE";

/**
 * Synthetic rule id for "a rule crashed, so this document was not checked
 * against it."
 *
 * The engine swallows a throwing rule and treats it as silence — correct for a
 * pure-rule contract, and the wrong thing to leave unsaid, because "this check
 * crashed" and "this check passed" are not the same sentence to a lawyer
 * relying on the review. Only the Word reports said it. A CI job gating on
 * SARIF saw a clean run and no way to learn that a check never ran.
 *
 * WARNING level, not note: unlike the other synthetic results here this one
 * reports a hole in the analysis itself.
 */
const ERRORED_RULE_ID = "VAULYTICA-RULE-ERRORED";

/** Severity → SARIF result level. */
const LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  warning: "warning",
  info: "note",
};

type SarifCitationProperty = {
  source: string;
  source_url?: string;
  freshness?: string;
  verify_currency?: string;
  formatted: string;
};

export type SarifLog = {
  $schema: string;
  version: "2.1.0";
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: Array<{
          id: string;
          name: string;
          shortDescription: { text: string };
          helpUri?: string;
          properties?: Record<string, unknown>;
        }>;
      };
    };
    results: Array<{
      ruleId: string;
      ruleIndex: number;
      level: "error" | "warning" | "note";
      message: { text: string };
      locations: Array<{
        physicalLocation: {
          artifactLocation: { uri: string };
          region?: { charOffset: number; charLength: number };
        };
        logicalLocations?: Array<{ name: string; kind: string }>;
      }>;
      partialFingerprints: Record<string, string>;
      properties: Record<string, unknown>;
    }>;
    /** Tool-run provenance: the opt-in packs the user asserted. */
    properties?: Record<string, unknown>;
  }>;
};

function citationProperty(c: SourceCitation, currency?: CitationCurrency): SarifCitationProperty {
  const url = c.source_url?.trim();
  const prop: SarifCitationProperty = { source: c.source, formatted: formatCitation(c) };
  if (url) prop.source_url = url;
  const fresh = freshnessSignal(c);
  if (fresh) prop.freshness = fresh;
  // Deterministic currency label — anchored to the DKB's built_at.
  const stale = currencyLabel(c, currency);
  if (stale) prop.verify_currency = stale;
  return prop;
}

/** The finding's primary resolvable citation URL, if any. */
function primaryHelpUri(f: Finding): string | undefined {
  for (const c of f.source_citations) {
    const url = c.source_url?.trim();
    if (url) return url;
  }
  return undefined;
}

type SarifRule = SarifLog["runs"][0]["tool"]["driver"]["rules"][0];
type SarifResult = SarifLog["runs"][0]["results"][0];

export function buildSarif(
  run: EngineRun,
  v9?: V9Surfaces,
  currency?: CitationCurrency,
  ingest?: Pick<IngestResult, "warnings">,
  consistency?: ConsistencyRun,
): SarifLog {
  // One reportingDescriptor per distinct rule that produced a finding, in
  // sorted rule-id order for determinism. The v9 surfaces extend this with the
  // HANDOFF-* (pre-disclosure) and DATE-* (derived-deadline) rule families, so
  // a SARIF consumer (CI / code scanning) sees the handoff risks and the
  // computed deadlines as first-class results — never silently dropped.
  const handoff = v9?.delivery?.findings ?? [];
  const register = v9?.criticalDates?.register ?? [];
  const engineRuleIds = [...new Set(run.findings.map((f) => f.rule_id))].sort();
  const handoffRuleIds = [...new Set(handoff.map((f) => f.rule_id))].sort();
  const dateRuleIds = [...new Set(register.map((r) => r.rule_id))].sort();
  // add-document-vertical-framework — the unmatched-document banner as a
  // note-level result so a CI/code-scanning consumer sees the caveat too.
  const noticeRuleIds = run.classification_notice ? [CLASSIFICATION_NOTICE_RULE_ID] : [];
  // What the ingest could and could not read. The CI surface carried none of
  // it: a pipeline gating on SARIF never learned that the document it passed
  // was a redline read as all-changes-accepted, or was not in English at all.
  const inputWarnings = ingest?.warnings ?? [];
  const inputRuleIds = inputWarnings.length > 0 ? [INPUT_NOTICE_RULE_ID] : [];
  // Clearly-present families the per-document cap never scanned.
  const secondaryOmitted = v9?.secondaryFamiliesOmitted ?? 0;
  const capRuleIds = secondaryOmitted > 0 ? [SECONDARY_CAP_RULE_ID] : [];
  const reviewCoverage = buildReviewCoverage(run.findings);
  const reviewRuleIds = reviewCoverage.total > 0 ? [REVIEW_COVERAGE_RULE_ID] : [];
  const erroredNotice = erroredRuleNotice(run.execution_log);
  const erroredRuleIds = erroredNotice ? [ERRORED_RULE_ID] : [];
  // Cross-document (CC-* / CROSS-*). A bundle's conflicts had reached the DOCX
  // appendix and the bundle JSON and no CI surface at all — so a job that
  // gated on them annotated nothing, and SARIF is the artifact the Action
  // uploads by default. Each finding is attached to the document its FIRST
  // excerpt names, with the counterpart documents as further locations, so a
  // conflict appears exactly once across the bundle's SARIF files.
  const crossFindings = (consistency?.findings ?? []).filter(
    (f) => f.excerpts[0]?.source_file_name === run.source_file.name,
  );
  const crossRuleIds = [...new Set(crossFindings.map((f) => f.rule_id))].sort();
  // Engine / handoff / date / notice rule-id namespaces are disjoint, so the
  // combined index is collision-free and every result's ruleIndex resolves.
  const allRuleIds = [
    ...engineRuleIds,
    ...handoffRuleIds,
    ...dateRuleIds,
    ...noticeRuleIds,
    ...inputRuleIds,
    ...capRuleIds,
    ...reviewRuleIds,
    ...erroredRuleIds,
    ...crossRuleIds,
  ];
  const ruleIndex = new Map(allRuleIds.map((id, i) => [id, i]));

  const engineRules: SarifRule[] = engineRuleIds.map((id) => {
    // Representative finding for the descriptor's text + helpUri.
    const f = run.findings.find((x) => x.rule_id === id)!;
    const helpUri = primaryHelpUri(f);
    const descriptor: SarifRule = {
      id,
      name: id,
      shortDescription: { text: f.title },
    };
    if (helpUri) descriptor.helpUri = helpUri;
    if (f.source_citations.length > 0) {
      descriptor.properties = {
        citations: f.source_citations.map((c) => citationProperty(c, currency)),
      };
    }
    return descriptor;
  });
  const handoffRules: SarifRule[] = handoffRuleIds.map((id) => {
    const f = handoff.find((x) => x.rule_id === id)!;
    return { id, name: id, shortDescription: { text: f.title } };
  });
  const dateRules: SarifRule[] = dateRuleIds.map((id) => {
    const r = register.find((x) => x.rule_id === id)!;
    return { id, name: id, shortDescription: { text: CRITICAL_DATE_KIND_LABEL[r.kind] } };
  });
  const noticeRules: SarifRule[] = noticeRuleIds.map((id) => ({
    id,
    name: id,
    shortDescription: { text: "Document type not recognized" },
  }));
  const inputRules: SarifRule[] = inputRuleIds.map((id) => ({
    id,
    name: id,
    shortDescription: { text: "About this input — what the analysis could and could not read" },
  }));
  const capRules: SarifRule[] = capRuleIds.map((id) => ({
    id,
    name: id,
    shortDescription: { text: "Additional detected families were not scanned" },
  }));
  const reviewRules: SarifRule[] = reviewRuleIds.map((id) => ({
    id,
    name: id,
    shortDescription: { text: "How many findings rest on an attorney-reviewed rule" },
  }));
  const erroredRules: SarifRule[] = erroredRuleIds.map((id) => ({
    id,
    name: id,
    shortDescription: {
      text: "A rule ended in an error, so this document was not checked against it",
    },
  }));
  const crossRules: SarifRule[] = crossRuleIds.map((id) => {
    const f = crossFindings.find((x) => x.rule_id === id)!;
    const descriptor: SarifRule = { id, name: id, shortDescription: { text: f.title } };
    if (f.source_citations.length > 0) {
      descriptor.properties = {
        citations: f.source_citations.map((c) => citationProperty(c, currency)),
      };
    }
    return descriptor;
  });
  const rules = [
    ...engineRules,
    ...handoffRules,
    ...dateRules,
    ...noticeRules,
    ...inputRules,
    ...capRules,
    ...reviewRules,
    ...erroredRules,
    ...crossRules,
  ];

  // Thrust B: which rule ids are execution-readiness items, so the results
  // that already exist can be tagged instead of duplicated.
  const readiness = readinessCategories(v9);

  const findingResults: SarifResult[] = run.findings.map((f) => {
    const idx = ruleIndex.get(f.rule_id)!;
    const helpUri = primaryHelpUri(f);
    const citations = f.source_citations.map((c) => citationProperty(c, currency));
    return {
      ruleId: f.rule_id,
      ruleIndex: idx,
      level: LEVEL[f.severity],
      message: { text: f.description },
      locations: [
        {
          physicalLocation: {
            // The document is the artifact; the section id is the stable,
            // re-ingest-durable anchor (spec-v8 Open Q #6 — section primary).
            artifactLocation: { uri: run.source_file.name },
            region: {
              charOffset: f.excerpt.start_offset,
              charLength: Math.max(0, f.excerpt.end_offset - f.excerpt.start_offset),
            },
          },
          logicalLocations: [{ name: f.excerpt.section_id ?? "document", kind: "section" }],
        },
      ],
      // Deterministic dedupe key: the finding id is `${rule}-${section}-${offset}`,
      // stable across runs of the same document; the result_hash pins the run.
      partialFingerprints: {
        "vaulyticaFindingId/v1": f.id,
        "vaulyticaResultHash/v1": run.result_hash,
      },
      properties: {
        severity: f.severity,
        section: f.excerpt.section_id ?? "",
        explanation: f.explanation,
        ...(f.recommendation ? { recommendation: f.recommendation } : {}),
        ...(helpUri ? { helpUri } : {}),
        ...(f.tier ? { tier: f.tier } : {}),
        ...(f.source ? { provenance: f.source } : {}),
        ...(readiness.has(f.rule_id) ? { readiness: readiness.get(f.rule_id)! } : {}),
        citations,
      },
    };
  });

  // HANDOFF-* (Thrust A): pre-disclosure facts cited to the container, not a
  // text offset — so no `region`, and the logicalLocation names the container.
  const deliveryHash = v9?.delivery?.delivery_hash ?? "";
  const handoffResults: SarifResult[] = handoff.map((f) =>
    handoffResult(f, ruleIndex, run, deliveryHash, readiness.get(f.rule_id)),
  );

  // DATE-* (Thrust C): computed deadlines, surfaced at "note" level (a date to
  // track, not a violation), anchored to the source section.
  const datesHash = v9?.criticalDates?.critical_dates_hash ?? "";
  const dateResults: SarifResult[] = register.map((r, i) =>
    dateResult(r, ruleIndex, run, datesHash, i),
  );

  // add-document-vertical-framework — the unmatched-document banner, at note
  // level (a caveat to read, not a violation), located to the whole document.
  const noticeResults: SarifResult[] = run.classification_notice
    ? [
        {
          ruleId: CLASSIFICATION_NOTICE_RULE_ID,
          ruleIndex: ruleIndex.get(CLASSIFICATION_NOTICE_RULE_ID)!,
          level: "note",
          message: { text: run.classification_notice.message },
          locations: [
            {
              physicalLocation: { artifactLocation: { uri: run.source_file.name } },
              logicalLocations: [{ name: "document", kind: "container" }],
            },
          ],
          partialFingerprints: {
            "vaulyticaClassificationNotice/v1": run.classification_notice.reason,
            "vaulyticaResultHash/v1": run.result_hash,
          },
          properties: {
            surface: "classification-notice",
            reason: run.classification_notice.reason,
          },
        },
      ]
    : [];

  const inputResults: SarifResult[] = inputWarnings.map((text, i) => ({
    ruleId: INPUT_NOTICE_RULE_ID,
    ruleIndex: ruleIndex.get(INPUT_NOTICE_RULE_ID)!,
    level: "note" as const,
    message: { text },
    locations: [
      {
        physicalLocation: { artifactLocation: { uri: run.source_file.name } },
        logicalLocations: [{ name: "document", kind: "container" }],
      },
    ],
    partialFingerprints: {
      "vaulyticaInputNotice/v1": String(i),
      "vaulyticaResultHash/v1": run.result_hash,
    },
    properties: { surface: "input-notice" },
  }));

  const capResults: SarifResult[] =
    secondaryOmitted > 0
      ? [
          {
            ruleId: SECONDARY_CAP_RULE_ID,
            ruleIndex: ruleIndex.get(SECONDARY_CAP_RULE_ID)!,
            level: "note" as const,
            message: {
              text: `${secondaryOmitted} further clearly-present ${
                secondaryOmitted === 1 ? "family was" : "families were"
              } NOT scanned — the per-document cap stops at the strongest-signal families. Nothing below reports on them, present or absent.`,
            },
            locations: [
              {
                physicalLocation: { artifactLocation: { uri: run.source_file.name } },
                logicalLocations: [{ name: "document", kind: "container" }],
              },
            ],
            partialFingerprints: {
              "vaulyticaSecondaryCap/v1": String(secondaryOmitted),
              "vaulyticaResultHash/v1": run.result_hash,
            },
            properties: { surface: "secondary-families-capped", omitted: secondaryOmitted },
          },
        ]
      : [];

  const reviewResults: SarifResult[] =
    reviewCoverage.total > 0
      ? [
          {
            ruleId: REVIEW_COVERAGE_RULE_ID,
            ruleIndex: ruleIndex.get(REVIEW_COVERAGE_RULE_ID)!,
            level: "note" as const,
            message: { text: reviewCoverageSentence(reviewCoverage) },
            locations: [
              {
                physicalLocation: { artifactLocation: { uri: run.source_file.name } },
                logicalLocations: [{ name: "document", kind: "container" }],
              },
            ],
            partialFingerprints: {
              "vaulyticaReviewCoverage/v1": `${reviewCoverage.attorney_reviewed}/${reviewCoverage.total}`,
              "vaulyticaResultHash/v1": run.result_hash,
            },
            properties: {
              surface: "attorney-review-coverage",
              attorney_reviewed: reviewCoverage.attorney_reviewed,
              total: reviewCoverage.total,
            },
          },
        ]
      : [];

  const erroredResults: SarifResult[] = erroredNotice
    ? [
        {
          ruleId: ERRORED_RULE_ID,
          ruleIndex: ruleIndex.get(ERRORED_RULE_ID)!,
          level: "warning" as const,
          message: { text: erroredNotice },
          locations: [
            {
              physicalLocation: { artifactLocation: { uri: run.source_file.name } },
              logicalLocations: [{ name: "document", kind: "container" }],
            },
          ],
          partialFingerprints: {
            "vaulyticaErroredRules/v1": run.execution_log
              .filter((e) => e.errored)
              .map((e) => e.rule_id)
              .join(","),
            "vaulyticaResultHash/v1": run.result_hash,
          },
          properties: { surface: "rule-errored" },
        },
      ]
    : [];

  const consistencyHash = consistency?.result_hash ?? "";
  const crossResults: SarifResult[] = crossFindings.map((f) =>
    crossDocumentResult(f, ruleIndex, consistencyHash, currency),
  );

  const results = [
    ...findingResults,
    ...handoffResults,
    ...dateResults,
    ...noticeResults,
    ...inputResults,
    ...capResults,
    ...reviewResults,
    ...erroredResults,
    ...crossResults,
  ];

  // Tool-run provenance: which opt-in packs were asserted (each rides in the
  // hashed run). Emitted only when something was asserted, so a plain run's
  // SARIF is unchanged. Lets a CI/code-scanning dashboard record what was checked.
  const provenance: Record<string, unknown> = {};
  if (run.playbook_id) provenance.playbook_id = run.playbook_id;
  if (run.filing_profile) provenance.court_profile = run.filing_profile.id;
  if (run.asserted_regimes && run.asserted_regimes.length > 0)
    provenance.privacy_regimes = run.asserted_regimes;
  if (run.estate_checks_asserted) provenance.estate_checks = true;
  if (run.asserted_state) provenance.estate_state = run.asserted_state;
  // Thrust B roll-up: the readiness count a CI gate would threshold on, and
  // the per-category breakdown, without a second copy of any result. Sorted
  // keys so the block is byte-deterministic.
  const checklist = v9?.closingChecklist;
  if (checklist && checklist.items.length > 0) {
    const byCategory: Record<string, number> = {};
    for (const item of [...checklist.items].sort((a, b) =>
      a.category.localeCompare(b.category, "en"),
    ))
      byCategory[item.category] = (byCategory[item.category] ?? 0) + 1;
    provenance.readiness = { open_count: checklist.open_count, by_category: byCategory };
  }
  // The matched family's normal pairings, as PROVENANCE rather than results —
  // the same call `readiness` makes above, for the same reason. These are not
  // findings: a single document cannot know whether a companion exists, so
  // emitting one as a SARIF result would assert an absence the engine never
  // checked. A code-scanning dashboard gets the ids, and nothing gates on them.
  const related = v9?.relatedDocuments;
  if (related && related.length > 0) {
    provenance.related_documents = related.map((r) => r.playbook_id);
  }
  const hasProvenance =
    run.filing_profile ||
    run.asserted_regimes?.length ||
    run.estate_checks_asserted ||
    provenance.readiness !== undefined ||
    provenance.related_documents !== undefined;

  return {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Vaulytica",
            version: ENGINE_VERSION,
            informationUri: INFORMATION_URI,
            rules,
          },
        },
        results,
        ...(hasProvenance ? { properties: provenance } : {}),
      },
    ],
  };
}

/** Map a HANDOFF finding to a SARIF result (container-located, no text region). */
function handoffResult(
  f: HandoffFinding,
  ruleIndex: Map<string, number>,
  run: EngineRun,
  deliveryHash: string,
  readiness?: string,
): SarifResult {
  return {
    ruleId: f.rule_id,
    ruleIndex: ruleIndex.get(f.rule_id)!,
    level: LEVEL[f.severity],
    message: { text: f.description },
    locations: [
      {
        physicalLocation: { artifactLocation: { uri: run.source_file.name } },
        logicalLocations: [{ name: "pre-disclosure", kind: "container" }],
      },
    ],
    partialFingerprints: {
      "vaulyticaHandoffId/v1": f.rule_id,
      "vaulyticaDeliveryHash/v1": deliveryHash,
    },
    properties: {
      severity: f.severity,
      count: f.count,
      evidence: f.evidence,
      ...(readiness ? { readiness } : {}),
      surface: "delivery",
    },
  };
}

/**
 * Map a cross-document finding to a SARIF result.
 *
 * A conflict is not a fact about one file, so the result carries one location
 * per contributing document — the first excerpt's document leads (it is the one
 * whose SARIF file this result lands in) and the counterparts follow. A code-
 * scanning consumer shows the alert on the leading document and can follow the
 * others; without the extra locations, "your BAA is broader than your MSA" would
 * annotate the BAA and never say what it was compared against.
 */
function crossDocumentResult(
  f: ConsistencyFinding,
  ruleIndex: Map<string, number>,
  consistencyHash: string,
  currency?: CitationCurrency,
): SarifResult {
  return {
    ruleId: f.rule_id,
    ruleIndex: ruleIndex.get(f.rule_id)!,
    level: LEVEL[f.severity],
    message: { text: f.description },
    locations: f.excerpts.map((e) => ({
      physicalLocation: {
        artifactLocation: { uri: e.source_file_name },
        region: {
          charOffset: e.start_offset,
          charLength: Math.max(0, e.end_offset - e.start_offset),
        },
      },
      logicalLocations: [{ name: e.section_id ?? "document", kind: "section" }],
    })),
    partialFingerprints: {
      "vaulyticaConsistencyFindingId/v1": f.id,
      "vaulyticaConsistencyHash/v1": consistencyHash,
    },
    properties: {
      severity: f.severity,
      explanation: f.explanation,
      ...(f.recommendation ? { recommendation: f.recommendation } : {}),
      documents: f.excerpts.map((e) => e.source_file_name),
      surface: "cross-document",
      citations: f.source_citations.map((c) => citationProperty(c, currency)),
    },
  };
}

/** Map a derived critical date to a SARIF result (section-located, note level). */
function dateResult(
  r: CriticalDate,
  ruleIndex: Map<string, number>,
  run: EngineRun,
  datesHash: string,
  index: number,
): SarifResult {
  const when = r.resolved
    ? r.window
      ? `${r.window[0]}–${r.window[1]}`
      : (r.computed_date ?? "unresolved")
    : "verify manually";
  return {
    ruleId: r.rule_id,
    ruleIndex: ruleIndex.get(r.rule_id)!,
    level: "note",
    message: { text: `${CRITICAL_DATE_KIND_LABEL[r.kind]} (${when}): ${r.trigger}` },
    locations: [
      {
        physicalLocation: { artifactLocation: { uri: run.source_file.name } },
        logicalLocations: [{ name: r.section ?? "document", kind: "section" }],
      },
    ],
    partialFingerprints: {
      // Index keeps the key unique when two rows share a rule id + section.
      "vaulyticaCriticalDateId/v1": `${r.rule_id}-${r.section ?? "doc"}-${index}`,
      "vaulyticaCriticalDatesHash/v1": datesHash,
    },
    properties: {
      kind: r.kind,
      resolved: r.resolved,
      computed_date: r.computed_date ?? "",
      anchor: r.anchor,
      responsible: r.responsible,
      ...(r.reason ? { reason: r.reason } : {}),
      surface: "critical-dates",
    },
  };
}

/** Canonical, pretty-printed SARIF JSON string (deterministic). */
export function buildSarifJson(
  run: EngineRun,
  v9?: V9Surfaces,
  currency?: CitationCurrency,
  ingest?: Pick<IngestResult, "warnings">,
  consistency?: ConsistencyRun,
): string {
  return JSON.stringify(buildSarif(run, v9, currency, ingest, consistency), null, 2);
}

export function sarifBlob(
  run: EngineRun,
  v9?: V9Surfaces,
  currency?: CitationCurrency,
  ingest?: Pick<IngestResult, "warnings">,
): Blob {
  return new Blob([buildSarifJson(run, v9, currency, ingest)], {
    type: "application/sarif+json",
  });
}

// ---------------------------------------------------------------------------
// Structural conformance (spec-v8 §20)
// ---------------------------------------------------------------------------

/**
 * Assert the **ingestion-critical** structural invariants of SARIF 2.1.0 over
 * a built log — the rules GitHub Code Scanning and the SARIF ecosystem
 * actually enforce when consuming a file. Returns a list of human-readable
 * violations; an empty list means the log conforms.
 *
 * This is a deterministic, dependency-free structural check, not a full
 * validation against the OASIS-published JSON Schema (that schema cannot be
 * fetched in the offline/in-tab posture, and hand-vendoring a copy and
 * calling it "the published schema" would be the dishonesty this project
 * forbids). It pins the object-graph rules `buildSarif` must satisfy: a
 * `level` outside the enum, a dangling `ruleIndex`, a non-string
 * `partialFingerprints` value, a missing `message.text`, or a non-absolute
 * `helpUri` would each break a real consumer, and each is caught here.
 *
 * Exposed (not test-only) so a caller writing SARIF — e.g. the CLI — can
 * self-check its output before handing it to a downstream tool.
 */
export function sarifConformanceViolations(log: SarifLog): string[] {
  const v: string[] = [];
  const isStr = (x: unknown): x is string => typeof x === "string";
  const isNonEmpty = (x: unknown): x is string => isStr(x) && x.length > 0;
  const isInt = (x: unknown): x is number => typeof x === "number" && Number.isInteger(x);
  const isAbsoluteUrl = (x: string): boolean => {
    try {
      return Boolean(new URL(x).href);
    } catch {
      return false;
    }
  };
  const LEVELS = new Set(["error", "warning", "note", "none"]);

  if (log.version !== "2.1.0")
    v.push(`version must be "2.1.0", got ${JSON.stringify(log.version)}`);
  if (!isNonEmpty(log.$schema)) v.push("$schema must be a non-empty string");
  if (!Array.isArray(log.runs) || log.runs.length === 0) {
    v.push("runs must be a non-empty array");
    return v;
  }

  log.runs.forEach((run, ri) => {
    const driver = run.tool?.driver;
    if (!driver) {
      v.push(`runs[${ri}].tool.driver is required`);
      return;
    }
    if (!isNonEmpty(driver.name)) v.push(`runs[${ri}].tool.driver.name must be a non-empty string`);
    const rules = driver.rules ?? [];
    rules.forEach((rule, di) => {
      if (!isNonEmpty(rule.id)) v.push(`runs[${ri}].rules[${di}].id must be a non-empty string`);
      if (rule.shortDescription && !isStr(rule.shortDescription.text)) {
        v.push(`runs[${ri}].rules[${di}].shortDescription.text must be a string`);
      }
      if (rule.helpUri !== undefined && !(isStr(rule.helpUri) && isAbsoluteUrl(rule.helpUri))) {
        v.push(`runs[${ri}].rules[${di}].helpUri must be an absolute URI`);
      }
    });

    if (!Array.isArray(run.results)) {
      v.push(`runs[${ri}].results must be an array`);
      return;
    }
    run.results.forEach((res, si) => {
      const at = `runs[${ri}].results[${si}]`;
      if (!isStr(res.ruleId)) v.push(`${at}.ruleId must be a string`);
      if (!isInt(res.ruleIndex) || res.ruleIndex < 0 || res.ruleIndex >= rules.length) {
        v.push(`${at}.ruleIndex ${res.ruleIndex} out of range [0, ${rules.length - 1}]`);
      } else if (rules[res.ruleIndex]!.id !== res.ruleId) {
        v.push(
          `${at}.ruleIndex points to "${rules[res.ruleIndex]!.id}", not ruleId "${res.ruleId}"`,
        );
      }
      if (!LEVELS.has(res.level)) v.push(`${at}.level "${res.level}" is not a valid SARIF level`);
      if (!isNonEmpty(res.message?.text)) v.push(`${at}.message.text must be a non-empty string`);
      if (!Array.isArray(res.locations) || res.locations.length === 0) {
        v.push(`${at}.locations must be a non-empty array`);
      } else {
        res.locations.forEach((loc, li) => {
          const uri = loc.physicalLocation?.artifactLocation?.uri;
          if (!isNonEmpty(uri))
            v.push(`${at}.locations[${li}] artifactLocation.uri must be non-empty`);
          const region = loc.physicalLocation?.region;
          if (region) {
            if (!isInt(region.charOffset) || region.charOffset < 0) {
              v.push(`${at}.locations[${li}].region.charOffset must be a non-negative integer`);
            }
            if (!isInt(region.charLength) || region.charLength < 0) {
              v.push(`${at}.locations[${li}].region.charLength must be a non-negative integer`);
            }
          }
        });
      }
      for (const [k, val] of Object.entries(res.partialFingerprints ?? {})) {
        if (!isStr(val)) v.push(`${at}.partialFingerprints["${k}"] must be a string`);
      }
    });
  });

  return v;
}
