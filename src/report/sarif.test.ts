import { describe, expect, it } from "vitest";
import { buildSarif, buildSarifJson, sarifConformanceViolations } from "./sarif.js";
import type { EngineRun, Finding } from "../engine/finding.js";
import type { ConsistencyRun } from "../engine/consistency/types.js";

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
    // The trailing note is the always-emitted attorney-review coverage result
    // (9.576.0). Filtered out here so this test keeps asserting the severity
    // MAPPING and nothing else; its own coverage is below.
    expect(
      log.runs[0]!.results.filter((r) => !r.ruleId.startsWith("VAULYTICA-")).map((r) => r.level),
    ).toEqual(["error", "warning", "note"]);
  });

  it("one reportingDescriptor per distinct rule, sorted by id, citation→helpUri", () => {
    const log = buildSarif(run([finding("f1", "ZZZ", "info"), finding("f2", "AAA", "critical")]));
    const rules = log.runs[0]!.tool.driver.rules;
    expect(rules.filter((r) => !r.id.startsWith("VAULYTICA-")).map((r) => r.id)).toEqual([
      "AAA",
      "ZZZ",
    ]);
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
    expect(loc.physicalLocation.region).toEqual({
      charOffset: 10,
      charLength: 20,
      // The clause itself, in SARIF's own field for it (9.583.0). Offsets alone
      // make an annotation checkable only by someone holding the extracted text
      // and willing to count characters; a dashboard reader has neither.
      snippet: { text: "clause text" },
    });
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

describe("SARIF run provenance (asserted opt-in packs)", () => {
  function baseRun(): EngineRun {
    return {
      version: "0.1.0",
      dkb_version: "v0.0.1-starter",
      playbook_id: "appellate-brief",
      source_file: { name: "brief.pdf", sha256: "a".repeat(64), size_bytes: 10 },
      executed_at: "",
      findings: [],
      execution_log: [],
      result_hash: "b".repeat(64),
    };
  }

  it("omits run.properties when nothing was asserted", () => {
    const sarif = buildSarif(baseRun());
    expect(sarif.runs[0]!.properties).toBeUndefined();
  });

  it("records the asserted packs when present", () => {
    const run = baseRun();
    run.filing_profile = {
      id: "frap-default",
      version: "2026-07-15",
      court_name: "FRAP",
      brief_kind: "principal",
      authority: [],
    };
    run.asserted_regimes = ["ccpa"];
    run.estate_checks_asserted = true;
    const p = buildSarif(run).runs[0]!.properties!;
    expect(p.court_profile).toBe("frap-default");
    expect(p.privacy_regimes).toEqual(["ccpa"]);
    expect(p.estate_checks).toBe(true);
  });
});

/**
 * "About this input" on the CI surface. A pipeline gating on SARIF never
 * learned that the document it passed was a redline read as
 * all-changes-accepted, carried hidden text nobody can see, or was not in
 * English at all — the one consumer that acts on the result automatically was
 * the one told least.
 *
 * Carried as note-level RESULTS, not invocation notifications: CI and code
 * scanning annotate on results, and a notification a dashboard renders nowhere
 * is the same silence the notice exists to break.
 */
describe("SARIF input notices", () => {
  function baseRun(): EngineRun {
    return {
      version: "0.1.0",
      dkb_version: "v0.0.1-starter",
      playbook_id: "mutual-nda",
      source_file: { name: "nda.docx", sha256: "a".repeat(64), size_bytes: 10 },
      executed_at: "",
      findings: [],
      execution_log: [],
      result_hash: "b".repeat(64),
    };
  }

  const WARNINGS = [
    "This document does not read as English — it appears to be Spanish.",
    "2 tracked changes were read as ACCEPTED.",
  ];

  it("emits one note-level result per warning, verbatim", () => {
    const sarif = buildSarif(baseRun(), undefined, undefined, { warnings: WARNINGS });
    const notices = sarif.runs[0]!.results.filter((r) => r.ruleId === "VAULYTICA-INPUT-NOTICE");
    expect(notices).toHaveLength(2);
    expect(notices.every((n) => n.level === "note")).toBe(true);
    expect(notices.map((n) => n.message.text)).toEqual(WARNINGS);
  });

  it("declares the synthetic rule so every ruleIndex resolves", () => {
    const sarif = buildSarif(baseRun(), undefined, undefined, { warnings: WARNINGS });
    const rules = sarif.runs[0]!.tool.driver.rules;
    const idx = rules.findIndex((r) => r.id === "VAULYTICA-INPUT-NOTICE");
    expect(idx).toBeGreaterThan(-1);
    for (const n of sarif.runs[0]!.results.filter((r) => r.ruleId === "VAULYTICA-INPUT-NOTICE")) {
      expect(n.ruleIndex).toBe(idx);
    }
  });

  it("still conforms structurally with the notices present", () => {
    expect(
      sarifConformanceViolations(
        buildSarif(baseRun(), undefined, undefined, { warnings: WARNINGS }),
      ),
    ).toEqual([]);
  });

  it("changes nothing when the ingest read the document cleanly", () => {
    // A run with nothing to declare produces the bytes it produced before the
    // notices existed — including one where `ingest` is not passed at all.
    const before = buildSarifJson(baseRun());
    expect(buildSarifJson(baseRun(), undefined, undefined, { warnings: [] })).toBe(before);
  });

  it("is deterministic across builds", () => {
    const a = buildSarifJson(baseRun(), undefined, undefined, { warnings: WARNINGS });
    const b = buildSarifJson(baseRun(), undefined, undefined, { warnings: WARNINGS });
    expect(a).toBe(b);
  });
});

/**
 * Thrust B in SARIF: the roll-up, and no second copy of anything.
 *
 * The checklist is a re-projection of results the SARIF already carries, so
 * duplicating it would double-count in the one surface where a count decides
 * whether a build fails. These assert the shape that avoids that: run-level
 * `properties.readiness`, a `readiness` tag on the results that ARE checklist
 * items, and — the load-bearing one — an unchanged result COUNT.
 */
describe("buildSarif — v9 Thrust B (the closing checklist roll-up)", () => {
  const checklist = {
    items: [
      {
        category: "signature" as const,
        rule_id: "STRUCT-003",
        label: "No signature block",
        section: "s9",
      },
      {
        category: "blank" as const,
        rule_id: "STRUCT-011",
        label: "Unfilled placeholder",
        section: "s2",
      },
      {
        category: "handoff" as const,
        rule_id: "HANDOFF-001",
        label: "3 tracked changes still in the document",
      },
    ],
    open_count: 3,
  };
  const r = run([
    finding("f1", "STRUCT-003", "critical"),
    finding("f2", "STRUCT-011", "warning"),
    finding("f3", "GOV-001", "info"),
  ]);

  it("carries the open count and the per-category breakdown at run level", () => {
    const log = buildSarif(r, { closingChecklist: checklist });
    expect(log.runs[0]!.properties).toEqual({
      playbook_id: "dpa",
      readiness: {
        open_count: 3,
        by_category: { blank: 1, handoff: 1, signature: 1 },
      },
    });
  });

  it("tags the results that are checklist items, and only those", () => {
    const log = buildSarif(r, { closingChecklist: checklist });
    const tagged = Object.fromEntries(
      log.runs[0]!.results.map((x) => [
        x.ruleId,
        (x.properties as Record<string, unknown>).readiness,
      ]),
    );
    expect(tagged).toEqual({
      "STRUCT-003": "signature",
      "STRUCT-011": "blank",
      "GOV-001": undefined,
    });
  });

  it("adds no result — the checklist body is a projection, never a second copy", () => {
    const without = buildSarif(r);
    const with_ = buildSarif(r, { closingChecklist: checklist });
    expect(with_.runs[0]!.results.length).toBe(without.runs[0]!.results.length);
    expect(with_.runs[0]!.tool.driver.rules.length).toBe(without.runs[0]!.tool.driver.rules.length);
  });

  it("leaves a run with no checklist byte-identical", () => {
    expect(buildSarifJson(r, {})).toBe(buildSarifJson(r));
    expect(buildSarifJson(r, { closingChecklist: { items: [], open_count: 0 } })).toBe(
      buildSarifJson(r),
    );
  });

  it("stays SARIF 2.1.0 conformant with the roll-up present", () => {
    expect(sarifConformanceViolations(buildSarif(r, { closingChecklist: checklist }))).toEqual([]);
  });
});

/**
 * Cross-document findings on the CI surface.
 *
 * A bundle's conflicts reached the DOCX appendix and the bundle JSON and no CI
 * surface at all. SARIF is the artifact the GitHub Action uploads by default,
 * so a job gating on `--fail-on-consistency` annotated nothing: the check went
 * red and code scanning showed no reason why.
 */
describe("buildSarif — cross-document findings (CC-* / CROSS-*)", () => {
  function crossRun(): ConsistencyRun {
    return {
      version: "0.1.0",
      dkb_version: "v0.0.1-starter",
      documents: [
        { doc_id: "dpa", source_file_name: "dpa.docx", playbook_id: "dpa", kind: "dpa" },
        { doc_id: "msa", source_file_name: "msa.docx", playbook_id: "msa-general", kind: "msa" },
      ],
      executed_at: "",
      findings: [
        {
          id: "CC-002-dpa-10",
          rule_id: "CC-002",
          rule_version: "1.0.0",
          severity: "warning",
          title: "DPA purpose is open-ended relative to the MSA services",
          description: "The DPA permits processing for any purpose the controller directs.",
          explanation: "GDPR Art. 28(3) requires a stated purpose.",
          recommendation: "Tether the purpose to the MSA's services.",
          source_citations: [],
          excerpts: [
            {
              doc_id: "dpa",
              source_file_name: "dpa.docx",
              text: "any purpose the Controller directs",
              section_id: "s3",
              start_offset: 10,
              end_offset: 44,
            },
            {
              doc_id: "msa",
              source_file_name: "msa.docx",
              text: "Scope of Services: payroll processing",
              section_id: "s1",
              start_offset: 0,
              end_offset: 37,
            },
          ],
        },
      ],
      execution_log: [],
      result_hash: "d".repeat(64),
    };
  }

  it("emits the finding on the document its FIRST excerpt names", () => {
    const log = buildSarif(run([]), undefined, undefined, undefined, crossRun());
    const cross = log.runs[0]!.results.filter((r) => r.properties?.surface === "cross-document");
    expect(cross).toHaveLength(1);
    expect(cross[0]!.ruleId).toBe("CC-002");
    expect(cross[0]!.level).toBe("warning");
    // The rule descriptor must resolve, or a consumer renders an unnamed alert.
    const rules = log.runs[0]!.tool.driver.rules!;
    expect(rules[cross[0]!.ruleIndex!]!.id).toBe("CC-002");
  });

  it("does NOT repeat the finding in the counterpart document's SARIF", () => {
    // Once per bundle, not once per document — a conflict cited twice reads as
    // two problems.
    const msaRun: EngineRun = {
      ...run([]),
      source_file: { ...run([]).source_file, name: "msa.docx" },
    };
    const log = buildSarif(msaRun, undefined, undefined, undefined, crossRun());
    expect(log.runs[0]!.results.filter((r) => r.properties?.surface === "cross-document")).toEqual(
      [],
    );
  });

  it("carries every contributing document as a location", () => {
    // "Your DPA is broader than your MSA" annotating only the DPA never says
    // what it was compared against.
    const log = buildSarif(run([]), undefined, undefined, undefined, crossRun());
    const cross = log.runs[0]!.results.find((r) => r.properties?.surface === "cross-document")!;
    expect(cross.locations!.map((l) => l.physicalLocation!.artifactLocation.uri)).toEqual([
      "dpa.docx",
      "msa.docx",
    ]);
    expect(cross.properties!.documents).toEqual(["dpa.docx", "msa.docx"]);
    expect(cross.partialFingerprints!["vaulyticaConsistencyHash/v1"]).toBe("d".repeat(64));
  });

  it("is byte-identical to a run without it when no consistency is passed", () => {
    expect(buildSarifJson(run([finding("f1", "DPA-001", "critical")]))).toBe(
      buildSarifJson(run([finding("f1", "DPA-001", "critical")]), undefined, undefined, undefined),
    );
  });

  it("stays SARIF 2.1.0 conformant with cross-document results present", () => {
    expect(
      sarifConformanceViolations(buildSarif(run([]), undefined, undefined, undefined, crossRun())),
    ).toEqual([]);
  });
});

describe("the attorney-review caveat reaches SARIF", () => {
  it("emits one note-level result saying what the findings rest on", () => {
    // The DOCX and HTML reports have carried this sentence since the ledger
    // existed; SARIF — what a code-scanning dashboard shows a reviewer who
    // never opens the Word file — annotated N findings and said nothing about
    // what any of them rests on.
    const log = buildSarif(run([finding("f1", "A", "critical"), finding("f2", "B", "info")]));
    const notes = log.runs[0]!.results.filter(
      (r) => r.ruleId === "VAULYTICA-ATTORNEY-REVIEW-COVERAGE",
    );
    expect(notes).toHaveLength(1);
    expect(notes[0]!.level).toBe("note");
    expect(notes[0]!.message.text).toContain("0 of 2 findings cite an attorney-reviewed rule");
    expect(notes[0]!.properties!.total).toBe(2);
    expect(notes[0]!.properties!.attorney_reviewed).toBe(0);
    // The descriptor index has to resolve, or a consumer drops the result.
    const rules = log.runs[0]!.tool.driver.rules;
    expect(rules[notes[0]!.ruleIndex!]!.id).toBe("VAULYTICA-ATTORNEY-REVIEW-COVERAGE");
  });

  it("says nothing when there is nothing to say", () => {
    // No findings, no coverage claim — "0 of 0" would read as a warning about
    // a document that produced none.
    const log = buildSarif(run([]));
    expect(
      log.runs[0]!.results.some((r) => r.ruleId === "VAULYTICA-ATTORNEY-REVIEW-COVERAGE"),
    ).toBe(false);
  });
});

describe("the SARIF snippet quotes the clause, and only when there is one", () => {
  it("carries the excerpt for a finding with a span", () => {
    const log = buildSarif(run([finding("f1", "A", "critical")]));
    expect(log.runs[0]!.results[0]!.locations[0]!.physicalLocation.region!.snippet).toEqual({
      text: "clause text",
    });
  });

  it("omits it for a finding about an ABSENCE", () => {
    // `excerpt.text` on a spanless finding is the rule's own marker string.
    // Presenting that as a snippet quotes words the document never contained —
    // the same failure the DOCX comment calls "the worst line in it".
    const absent: Finding = {
      ...finding("f2", "B", "warning"),
      excerpt: { text: "MARKER", section_id: "s2", start_offset: 0, end_offset: 0 },
    };
    const region = buildSarif(run([absent])).runs[0]!.results[0]!.locations[0]!.physicalLocation
      .region!;
    expect(region.charLength).toBe(0);
    expect(region.snippet).toBeUndefined();
    expect(JSON.stringify(region)).not.toContain("MARKER");
  });
});

/**
 * The state-law overlays on the CI surface.
 *
 * The overlays are where the answer changes by jurisdiction — a non-compete
 * governed by California law is void under Bus. & Prof. Code § 16600 — and the
 * DOCX, the HTML and the in-tab card have printed that for releases. SARIF, the
 * artifact the Action uploads and the only one a code-scanning dashboard reads,
 * carried **no overlay of any kind**: a pipeline analyzing that agreement
 * annotated its findings and said nothing about the statute that decides them.
 *
 * Both notes ride at `note` level beside the classification notice and the
 * input notices: a caveat and a citation to read, never a violation, and never
 * something a `--fail-on` gate can trip on.
 */
describe("SARIF carries the jurisdiction overlays", () => {
  const employmentRun = (): EngineRun => ({
    version: "0.1.0",
    dkb_version: "v0.0.1-starter",
    playbook_id: "employment-at-will-us",
    source_file: { name: "employment.docx", sha256: "a".repeat(64), size_bytes: 10 },
    executed_at: "",
    findings: [],
    execution_log: [],
    result_hash: "b".repeat(64),
  });

  const governedBy = (state: string) =>
    ({
      jurisdictions: [
        { clause_kind: "governing-law", jurisdiction_id: state, raw_text: `laws of ${state}` },
      ],
    }) as never;

  it("names the state, what its law does, and the citation", () => {
    const sarif = buildSarif(
      employmentRun(),
      undefined,
      undefined,
      undefined,
      undefined,
      governedBy("us-ca"),
    );
    const notes = sarif.runs[0]!.results.filter(
      (r) => r.ruleId === "VAULYTICA-JURISDICTION-OVERLAY",
    );
    expect(notes.length, "the CI surface carried no overlay").toBeGreaterThan(0);
    expect(notes[0]!.level).toBe("note");
    expect(notes[0]!.message.text).toContain("California");
    expect(notes[0]!.message.text).toMatch(/16600|void|unenforceable/i);
    expect(notes[0]!.properties?.state).toBe("us-ca");
    // The descriptor is registered, so `ruleIndex` resolves for a consumer.
    const rules = sarif.runs[0]!.tool.driver.rules!;
    expect(rules[notes[0]!.ruleIndex]!.id).toBe("VAULYTICA-JURISDICTION-OVERLAY");
  });

  it("says an uncovered state is a gap, not a pass", () => {
    // Alabama has no non-compete overlay; 34 of 50 states do not.
    const sarif = buildSarif(
      employmentRun(),
      undefined,
      undefined,
      undefined,
      undefined,
      governedBy("us-al"),
    );
    const gaps = sarif.runs[0]!.results.filter(
      (r) => r.ruleId === "VAULYTICA-JURISDICTION-OVERLAY-GAP",
    );
    expect(gaps, "an uncovered state reached CI as silence").toHaveLength(1);
    expect(gaps[0]!.level).toBe("note");
    expect(gaps[0]!.message.text).toContain("AL");
    expect(gaps[0]!.message.text).toContain("an honest coverage gap, not a clean pass");
    expect(gaps[0]!.properties?.uncovered_states).toEqual(["us-al"]);
  });

  it("adds nothing at all when no extraction is supplied", () => {
    // Back-compat: every existing caller that does not pass `extracted` gets
    // byte-identical SARIF, so `result_hash` and every golden stay put.
    expect(buildSarifJson(employmentRun())).toBe(
      buildSarifJson(employmentRun(), undefined, undefined, undefined, undefined, undefined),
    );
    const sarif = buildSarif(employmentRun());
    expect(sarif.runs[0]!.results.some((r) => r.ruleId?.includes("OVERLAY"))).toBe(false);
  });

  it("stays structurally conformant with the overlay results present", () => {
    const sarif = buildSarif(
      employmentRun(),
      undefined,
      undefined,
      undefined,
      undefined,
      governedBy("us-ca"),
    );
    expect(sarifConformanceViolations(sarif)).toEqual([]);
  });
});
