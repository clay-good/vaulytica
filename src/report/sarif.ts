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
import { formatCitation, freshnessSignal } from "./citations.js";

const SARIF_SCHEMA =
  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
const INFORMATION_URI = "https://github.com/clay-good/vaulytica";

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
  }>;
};

function citationProperty(c: SourceCitation): SarifCitationProperty {
  const url = c.source_url?.trim();
  const prop: SarifCitationProperty = { source: c.source, formatted: formatCitation(c) };
  if (url) prop.source_url = url;
  const fresh = freshnessSignal(c);
  if (fresh) prop.freshness = fresh;
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

export function buildSarif(run: EngineRun): SarifLog {
  // One reportingDescriptor per distinct rule that produced a finding, in
  // sorted rule-id order for determinism.
  const ruleIds = [...new Set(run.findings.map((f) => f.rule_id))].sort();
  const ruleIndex = new Map(ruleIds.map((id, i) => [id, i]));

  const rules = ruleIds.map((id) => {
    // Representative finding for the descriptor's text + helpUri.
    const f = run.findings.find((x) => x.rule_id === id)!;
    const helpUri = primaryHelpUri(f);
    const descriptor: SarifLog["runs"][0]["tool"]["driver"]["rules"][0] = {
      id,
      name: id,
      shortDescription: { text: f.title },
    };
    if (helpUri) descriptor.helpUri = helpUri;
    if (f.source_citations.length > 0) {
      descriptor.properties = { citations: f.source_citations.map(citationProperty) };
    }
    return descriptor;
  });

  const results = run.findings.map((f) => {
    const idx = ruleIndex.get(f.rule_id)!;
    const helpUri = primaryHelpUri(f);
    const citations = f.source_citations.map(citationProperty);
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
          logicalLocations: [
            { name: f.excerpt.section_id ?? "document", kind: "section" },
          ],
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
        citations,
      },
    };
  });

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
      },
    ],
  };
}

/** Canonical, pretty-printed SARIF JSON string (deterministic). */
export function buildSarifJson(run: EngineRun): string {
  return JSON.stringify(buildSarif(run), null, 2);
}

export function sarifBlob(run: EngineRun): Blob {
  return new Blob([buildSarifJson(run)], { type: "application/sarif+json" });
}
