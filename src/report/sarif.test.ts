import { describe, expect, it } from "vitest";
import { buildSarif, buildSarifJson, sarifConformanceViolations } from "./sarif.js";
import type { EngineRun, Finding } from "../engine/finding.js";

function finding(id: string, rule: string, sev: Finding["severity"], withUrl = true): Finding {
  return {
    id,
    rule_id: rule,
    rule_version: "1.0.0",
    severity: sev,
    title: `Title ${rule}`,
    description: `Description for ${rule}`,
    excerpt: { text: "clause text", section_id: "s2", start_offset: 10, end_offset: 30 },
    explanation: "Why this matters.",
    recommendation: "Consider revising.",
    source_citations: withUrl
      ? [
          {
            id: "gdpr-28",
            source: "Regulation (EU) 2016/679 (GDPR), Article 28",
            source_url: "https://eur-lex.europa.eu/eli/reg/2016/679/oj",
            retrieved_at: "2026-05-11T00:00:00Z",
            license: "CC-BY-4.0",
            license_url: "https://creativecommons.org/licenses/by/4.0/",
          },
        ]
      : [
          {
            id: "policy-4-2",
            source: "Policy 4.2",
            source_url: "",
            retrieved_at: "",
            license: "Team policy",
            license_url: "",
          },
        ],
    document_position: 0,
  };
}

function run(findings: Finding[]): EngineRun {
  return {
    version: "0.1.0",
    dkb_version: "v0.0.1-starter",
    playbook_id: "dpa",
    source_file: { name: "dpa.docx", sha256: "a".repeat(64), size_bytes: 2048 },
    executed_at: "2026-06-08T00:00:00Z",
    findings,
    execution_log: [],
    result_hash: "c".repeat(64),
  };
}

describe("buildSarif (spec-v8 §20 — SARIF 2.1.0)", () => {
  it("emits a well-formed SARIF 2.1.0 envelope", () => {
    const log = buildSarif(run([finding("f1", "DPA-001", "critical")]));
    expect(log.version).toBe("2.1.0");
    expect(log.$schema).toContain("sarif-schema-2.1.0");
    expect(log.runs).toHaveLength(1);
    expect(log.runs[0]!.tool.driver.name).toBe("Vaulytica");
  });

  it("maps severity → level (critical=error, warning=warning, info=note)", () => {
    const log = buildSarif(
      run([finding("f1", "A", "critical"), finding("f2", "B", "warning"), finding("f3", "C", "info")]),
    );
    expect(log.runs[0]!.results.map((r) => r.level)).toEqual(["error", "warning", "note"]);
  });

  it("one reportingDescriptor per distinct rule, sorted by id, citation→helpUri", () => {
    const log = buildSarif(run([finding("f1", "ZZZ", "info"), finding("f2", "AAA", "critical")]));
    const rules = log.runs[0]!.tool.driver.rules;
    expect(rules.map((r) => r.id)).toEqual(["AAA", "ZZZ"]);
    expect(rules[0]!.helpUri).toBe("https://eur-lex.europa.eu/eli/reg/2016/679/oj");
  });

  it("each result carries a stable partialFingerprint from finding id + result_hash", () => {
    const log = buildSarif(run([finding("f1", "A", "critical")]));
    const fp = log.runs[0]!.results[0]!.partialFingerprints;
    expect(fp["vaulyticaFindingId/v1"]).toBe("f1");
    expect(fp["vaulyticaResultHash/v1"]).toBe("c".repeat(64));
  });

  it("locates a finding by section (logicalLocation) with the offset in region", () => {
    const log = buildSarif(run([finding("f1", "A", "critical")]));
    const loc = log.runs[0]!.results[0]!.locations[0]!;
    expect(loc.physicalLocation.artifactLocation.uri).toBe("dpa.docx");
    expect(loc.physicalLocation.region).toEqual({ charOffset: 10, charLength: 20 });
    expect(loc.logicalLocations?.[0]).toEqual({ name: "s2", kind: "section" });
  });

  it("every result carries a resolvable citation URL (§18 completeness)", () => {
    const log = buildSarif(run([finding("f1", "A", "critical")]));
    const result = log.runs[0]!.results[0]!;
    expect(result.properties.helpUri).toBe("https://eur-lex.europa.eu/eli/reg/2016/679/oj");
    const cites = result.properties.citations as Array<{ source_url?: string }>;
    expect(cites[0]!.source_url).toBe("https://eur-lex.europa.eu/eli/reg/2016/679/oj");
  });

  it("renders the URL-less custom citation without a helpUri but with a citation property", () => {
    const log = buildSarif(run([finding("f1", "POLICY-1", "warning", false)]));
    const rule = log.runs[0]!.tool.driver.rules[0]!;
    expect(rule.helpUri).toBeUndefined();
    const cites = log.runs[0]!.results[0]!.properties.citations as Array<{ formatted: string }>;
    expect(cites[0]!.formatted).toBe("Policy 4.2");
  });

  it("is deterministic: identical run → identical JSON bytes", () => {
    const r = run([finding("f1", "A", "critical"), finding("f2", "B", "info")]);
    expect(buildSarifJson(r)).toBe(buildSarifJson(r));
  });
});

describe("SARIF 2.1.0 structural conformance (spec-v8 §20)", () => {
  it("real output conforms across fixtures (cited, URL-less, empty, multi-rule)", () => {
    const fixtures = [
      run([finding("f1", "DPA-001", "critical")]),
      run([finding("f1", "POLICY-1", "warning", false)]), // URL-less custom citation
      run([]), // no findings
      run([
        finding("f1", "ZZZ", "info"),
        finding("f2", "AAA", "critical"),
        finding("f3", "AAA", "warning"), // two findings, one rule
      ]),
    ];
    for (const r of fixtures) {
      expect(sarifConformanceViolations(buildSarif(r))).toEqual([]);
    }
  });

  it("has teeth — catches a dangling ruleIndex", () => {
    const log = buildSarif(run([finding("f1", "A", "critical")]));
    log.runs[0]!.results[0]!.ruleIndex = 99;
    expect(sarifConformanceViolations(log).some((s) => s.includes("ruleIndex"))).toBe(true);
  });

  it("has teeth — catches an invalid level, a non-string fingerprint, and a bad helpUri", () => {
    const log = buildSarif(run([finding("f1", "A", "critical")]));
    // @ts-expect-error — deliberately invalid for the negative test.
    log.runs[0]!.results[0]!.level = "fatal";
    // @ts-expect-error — fingerprints must be strings.
    log.runs[0]!.results[0]!.partialFingerprints["bad/v1"] = 42;
    log.runs[0]!.tool.driver.rules[0]!.helpUri = "not-a-url";
    const violations = sarifConformanceViolations(log);
    expect(violations.some((s) => s.includes("level"))).toBe(true);
    expect(violations.some((s) => s.includes("partialFingerprints"))).toBe(true);
    expect(violations.some((s) => s.includes("helpUri"))).toBe(true);
  });

  it("has teeth — catches a missing message text and empty artifact uri", () => {
    const log = buildSarif(run([finding("f1", "A", "critical")]));
    log.runs[0]!.results[0]!.message.text = "";
    log.runs[0]!.results[0]!.locations[0]!.physicalLocation.artifactLocation.uri = "";
    const violations = sarifConformanceViolations(log);
    expect(violations.some((s) => s.includes("message.text"))).toBe(true);
    expect(violations.some((s) => s.includes("artifactLocation.uri"))).toBe(true);
  });
});
