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
      run([
        finding("f1", "A", "critical"),
        finding("f2", "B", "warning"),
        finding("f3", "C", "info"),
      ]),
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

describe("buildSarif — v9 Last Look surfaces (HANDOFF-* + DATE-*)", () => {
  const delivery = {
    source: "docx" as const,
    inspectable: true,
    findings: [
      {
        rule_id: "HANDOFF-001",
        severity: "critical" as const,
        title: "Tracked changes are present",
        description: "3 tracked-change revisions remain in the document's container.",
        count: 3,
        evidence: ["insertion by Opposing Counsel: “indemnify and hold harmless”"],
      },
      {
        rule_id: "HANDOFF-005",
        severity: "warning" as const,
        title: "Sensitive-data patterns are present",
        description: "2 spans match sensitive-data formats.",
        count: 2,
        evidence: ["ssn (high confidence): ***-**-6789"],
      },
    ],
    summary: "Delivery: 3 tracked changes, 2 sensitive-data spans — review before sending.",
    delivery_hash: "d".repeat(64),
  };
  const criticalDates = {
    register: [
      {
        rule_id: "DATE-001",
        kind: "auto-renewal-notice" as const,
        resolved: true,
        computed_date: "2025-11-01",
        trigger: "60 days before the Renewal Date",
        anchor: "Renewal Date",
        responsible: "Acme Corp",
        section: "s8",
      },
      {
        rule_id: "DATE-005",
        kind: "notice-period" as const,
        resolved: false,
        computed_date: null,
        trigger: "15 business days after the Approval Date",
        anchor: "Approval Date",
        responsible: "",
        section: "s9",
        reason: "business-day deadline — no holiday calendar is asserted; verify manually",
      },
    ],
    resolved_count: 1,
    unresolved_count: 1,
    critical_dates_hash: "e".repeat(64),
  };

  it("emits HANDOFF-* and DATE-* as first-class, conformant results", () => {
    const log = buildSarif(run([finding("f1", "STRUCT-001", "warning")]), {
      delivery,
      criticalDates,
    });
    expect(sarifConformanceViolations(log)).toEqual([]);
    const results = log.runs[0]!.results;
    const ids = results.map((r) => r.ruleId);
    expect(ids).toContain("HANDOFF-001");
    expect(ids).toContain("HANDOFF-005");
    expect(ids).toContain("DATE-001");
    expect(ids).toContain("DATE-005");
    // Every result's ruleIndex resolves to its own ruleId in the rule list.
    const rules = log.runs[0]!.tool.driver.rules;
    for (const r of results) expect(rules[r.ruleIndex]!.id).toBe(r.ruleId);
    // HANDOFF carries no text region (container-located); DATE is note level.
    const handoff = results.find((r) => r.ruleId === "HANDOFF-001")!;
    expect(handoff.level).toBe("error");
    expect(handoff.locations[0]!.physicalLocation.region).toBeUndefined();
    expect(handoff.locations[0]!.logicalLocations![0]!.kind).toBe("container");
    const date = results.find((r) => r.ruleId === "DATE-001")!;
    expect(date.level).toBe("note");
    expect(date.partialFingerprints["vaulyticaCriticalDatesHash/v1"]).toBe("e".repeat(64));
  });

  it("is byte-identical to the v8 SARIF when no v9 surface is supplied", () => {
    const findings = [finding("f1", "STRUCT-001", "warning")];
    expect(buildSarifJson(run(findings))).toBe(buildSarifJson(run(findings), {}));
  });
});
