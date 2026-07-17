import { describe, expect, it } from "vitest";
import { buildDocxReport } from "./docx.js";
import { buildJsonReport } from "./json.js";
import { loadStarterDkbSync } from "../engine/_test-fixtures.js";
import type { EngineRun, Finding } from "../engine/finding.js";
import type { IngestResult } from "../ingest/types.js";
import type { Playbook } from "../playbooks/types.js";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadMutualNda(): Playbook {
  const p = join(__dirname, "..", "..", "playbooks", "mutual-nda.json");
  return JSON.parse(readFileSync(p, "utf8")) as Playbook;
}

function finding(id: string, severity: Finding["severity"]): Finding {
  return {
    id,
    rule_id: "STRUCT-001",
    rule_version: "1.0.0",
    severity,
    title: `Finding ${id}`,
    description: "Description of the finding",
    excerpt: { text: "excerpt text", section_id: "s1", start_offset: 0, end_offset: 12 },
    explanation: "Plain language explanation of why this matters.",
    recommendation: "Consider revising the clause.",
    source_citations: [
      {
        id: "common-paper-mutual-nda-v1.1",
        source: "Common Paper Mutual NDA, v1.1",
        source_url: "https://github.com/CommonPaper/Mutual-NDA",
        retrieved_at: "2026-05-11T00:00:00Z",
        license: "CC-BY-4.0",
        license_url: "https://creativecommons.org/licenses/by/4.0/",
      },
    ],
    document_position: 0,
  };
}

function makeRun(): EngineRun {
  return {
    version: "0.1.0",
    dkb_version: "v0.0.1-starter",
    playbook_id: "mutual-nda",
    playbook_match_confidence: 0.92,
    playbook_match_reasoning: "Selected mutual-nda.",
    source_file: { name: "test.pdf", sha256: "a".repeat(64), size_bytes: 1024 },
    executed_at: "2026-05-12T12:00:00Z",
    findings: [finding("c1", "critical"), finding("w1", "warning"), finding("i1", "info")],
    execution_log: [
      {
        rule_id: "STRUCT-001",
        rule_version: "1.0.0",
        fired: true,
        finding_id: "c1",
        elapsed_ms: 0.1,
      },
      { rule_id: "STRUCT-002", rule_version: "1.0.0", fired: false, elapsed_ms: 0.05 },
    ],
    result_hash: "b".repeat(64),
  };
}

const ingest: IngestResult = {
  tree: { type: "document", sections: [] },
  source: "pdf",
  word_count: 1000,
  sha256: "a".repeat(64),
  warnings: [],
};

describe("buildDocxReport", () => {
  it("produces a non-empty Blob with the docx MIME type", async () => {
    const blob = await buildDocxReport(makeRun(), ingest, loadStarterDkbSync(), loadMutualNda());
    expect(blob.size).toBeGreaterThan(1000);
    // docx Packer.toBlob assigns the OOXML mime type
    expect(blob.type).toContain("application/vnd.openxmlformats-officedocument");
  });

  it("output bytes start with the ZIP local-file-header magic (PK\\x03\\x04)", async () => {
    const blob = await buildDocxReport(makeRun(), ingest, loadStarterDkbSync(), loadMutualNda());
    const bytes = new Uint8Array(await blob.arrayBuffer());
    expect(bytes[0]).toBe(0x50);
    expect(bytes[1]).toBe(0x4b);
    expect(bytes[2]).toBe(0x03);
    expect(bytes[3]).toBe(0x04);
  });

  it("renders an honest attorney-review-coverage section (0 of N until signed)", async () => {
    const blob = await buildDocxReport(makeRun(), ingest, loadStarterDkbSync(), loadMutualNda());
    const { unzipSync, strFromU8 } = await import("fflate");
    const entries = unzipSync(new Uint8Array(await blob.arrayBuffer()));
    const runText = (
      strFromU8(entries["word/document.xml"]!).match(/<w:t[^>]*>([^<]*)<\/w:t>/g) ?? []
    )
      .map((m) => m.replace(/<[^>]+>/g, ""))
      .join("");
    expect(runText).toContain("Attorney review coverage");
    expect(runText).toContain("findings cite an attorney-reviewed rule");
  });

  it("renders the universal scope-of-review block in the disclaimer", async () => {
    const blob = await buildDocxReport(makeRun(), ingest, loadStarterDkbSync(), loadMutualNda());
    const { unzipSync, strFromU8 } = await import("fflate");
    const entries = unzipSync(new Uint8Array(await blob.arrayBuffer()));
    const runText = (
      strFromU8(entries["word/document.xml"]!).match(/<w:t[^>]*>([^<]*)<\/w:t>/g) ?? []
    )
      .map((m) => m.replace(/<[^>]+>/g, ""))
      .join("");
    expect(runText).toContain("Scope of this review");
    expect(runText).toContain("commercial adequacy");
  });

  it("emits review_coverage in the JSON report (a projection outside result_hash)", () => {
    const run = makeRun();
    const blob = buildJsonReport(run, ingest, loadMutualNda());
    return blob.text().then((text) => {
      const report = JSON.parse(text) as {
        review_coverage: { total: number; attorney_reviewed: number };
        run: { result_hash: string };
      };
      expect(report.review_coverage.total).toBe(run.findings.length);
      expect(report.review_coverage.attorney_reviewed).toBe(0);
      // Outside the hash: the run's own result_hash is untouched.
      expect(report.run.result_hash).toBe(run.result_hash);
    });
  });

  it("renders citations in full and wraps long URLs (spec-v8 §18 never-truncate)", async () => {
    const longUrl =
      "https://www.govinfo.gov/content/pkg/CFR-2024-title45-vol2/xml/CFR-2024-title45-vol2-sec164-410.xml";
    const longSource =
      "45 C.F.R. § 164.410(a)(1) — Notification to the Secretary of a breach of unsecured protected health information";
    const run = makeRun();
    run.findings = [
      {
        ...finding("c1", "critical"),
        source_citations: [
          {
            id: "cfr-164-410",
            source: longSource,
            source_url: longUrl,
            retrieved_at: "2026-05-11T00:00:00Z",
            license: "Public domain (US government work)",
            license_url: "https://www.usa.gov/government-works",
          },
        ],
      },
    ];
    const blob = await buildDocxReport(run, ingest, loadStarterDkbSync(), loadMutualNda());
    const { unzipSync, strFromU8 } = await import("fflate");
    const entries = unzipSync(new Uint8Array(await blob.arrayBuffer()));
    const docXml = strFromU8(entries["word/document.xml"]!);
    // Concatenate every run's visible text: the wrap mechanism splits a URL
    // across adjacent runs, so the contiguous string only re-forms when the
    // run texts are joined — which is exactly what Word renders on the page.
    const runText = (docXml.match(/<w:t[^>]*>([^<]*)<\/w:t>/g) ?? [])
      .map((m) => m.replace(/<[^>]+>/g, ""))
      .join("");
    // Never truncated: the full citation source and the full URL both appear.
    expect(runText).toContain(longSource);
    expect(runText).toContain(longUrl);
    expect(runText).not.toContain("…");
    // Wrapped: the long URL is split into multiple adjacent runs so Word can
    // break it at the margin rather than overflow the page.
    const urlRunCount = (docXml.match(/<w:t[^>]*>[^<]*govinfo[^<]*<\/w:t>/g) ?? []).length;
    expect(urlRunCount).toBeGreaterThan(1);
  });

  it("never emits a javascript:/data: hyperlink relationship (XSS defense, output boundary)", async () => {
    const evil = "javascript:alert(document.domain)";
    const run = makeRun();
    run.findings = [
      {
        ...finding("c1", "critical"),
        source_citations: [
          {
            id: "policy-evil",
            source: "Team Policy 9",
            source_url: evil,
            retrieved_at: "2026-05-11T00:00:00Z",
            license: "Team policy",
            license_url: "",
          },
        ],
      },
    ];
    const blob = await buildDocxReport(run, ingest, loadStarterDkbSync(), loadMutualNda());
    const { unzipSync, strFromU8 } = await import("fflate");
    const entries = unzipSync(new Uint8Array(await blob.arrayBuffer()));
    // The citation-index would otherwise create an ExternalHyperlink whose
    // Target lands in the relationships file. With the scheme guard, no
    // hyperlink relationship is created, so the dangerous scheme never becomes
    // an active link in the shared DOCX.
    const rels = entries["word/_rels/document.xml.rels"]
      ? strFromU8(entries["word/_rels/document.xml.rels"]!)
      : "";
    expect(rels).not.toContain("javascript:");
    // The URL text is still present (citability), just inert.
    const docXml = strFromU8(entries["word/document.xml"]!);
    const runText = (docXml.match(/<w:t[^>]*>([^<]*)<\/w:t>/g) ?? [])
      .map((m) => m.replace(/<[^>]+>/g, ""))
      .join("");
    expect(runText).toContain(evil);
  });

  it("handles a run with zero findings", async () => {
    const run = makeRun();
    run.findings = [];
    const blob = await buildDocxReport(run, ingest, loadStarterDkbSync(), loadMutualNda());
    expect(blob.size).toBeGreaterThan(0);
  });

  it("renders extracted-data appendix tables when ExtractedData is threaded (Step 9 follow-up)", async () => {
    // The DOCX bytes are zip-compressed but vary deterministically by
    // content. Comparing blob sizes with vs without the extracted data
    // is a cheap proof that the new appendix renderers fired.
    const baseline = await buildDocxReport(
      makeRun(),
      ingest,
      loadStarterDkbSync(),
      loadMutualNda(),
    );
    const extracted = {
      parties: [
        {
          id: "p1",
          name: "Acme Inc.",
          role: "Disclosing Party",
          entity_type: "corporation",
          jurisdiction_of_formation: "Delaware",
          positions: [],
        },
        {
          id: "p2",
          name: "Northwind Ltd.",
          role: "Receiving Party",
          entity_type: "limited company",
          positions: [],
        },
      ],
      dates: [
        {
          id: "d1",
          type: "absolute" as const,
          raw_text: "January 1, 2026",
          iso: "2026-01-01",
          position: { start_offset: 0, end_offset: 15 },
        },
        {
          id: "d2",
          type: "relative" as const,
          raw_text: "thirty (30) days after the Effective Date",
          anchor: "Effective Date",
          offset_days: 30,
          position: { start_offset: 0, end_offset: 40 },
        },
      ],
      amounts: [
        {
          id: "m1",
          raw_text: "$50,000",
          amount: "50000",
          currency: "USD",
          word_form: false,
          position: { start_offset: 0, end_offset: 7 },
        },
      ],
      definitions: {
        entries: [
          {
            term: "Confidential Information",
            definition: "Any non-public information disclosed under this Agreement.",
            defined_at: { start_offset: 0, end_offset: 50 },
            used_at: [
              { start_offset: 60, end_offset: 85 },
              { start_offset: 100, end_offset: 125 },
            ],
          },
        ],
        unused_terms: ["Vintage Term"],
        undefined_capitalized: [],
      },
      outline: { nodes: [], by_id: {} },
      crossrefs: [],
      obligations: [
        {
          id: "o1",
          obligor: "Receiving Party",
          action: "treat the Confidential Information as confidential",
          trigger: "upon disclosure",
          qualifier: "for two years",
          modal: "shall",
          raw_text: "...",
          position: { start_offset: 0, end_offset: 0 },
        },
      ],
      jurisdictions: [
        {
          clause_kind: "governing-law" as const,
          jurisdiction_id: "us-de",
          raw_text: "State of Delaware",
          position: { start_offset: 0, end_offset: 18 },
        },
      ],
      classified: [],
    };
    const enriched = await buildDocxReport(
      makeRun(),
      ingest,
      loadStarterDkbSync(),
      loadMutualNda(),
      undefined,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      extracted as any,
    );
    expect(enriched.size).toBeGreaterThan(baseline.size);
  });

  it("falls back to the counts-only appendix when ExtractedData is omitted (legacy path)", async () => {
    // Belt-and-suspenders: the appendix still renders without
    // extracted, so any future caller that doesn't thread the data
    // through still gets a useful report.
    const blob = await buildDocxReport(makeRun(), ingest, loadStarterDkbSync(), loadMutualNda());
    expect(blob.size).toBeGreaterThan(1000);
  });

  it("cover + audit trail surface deprecation when the playbook is marked deprecated (Step 27 follow-up)", async () => {
    // mutual-nda is marked deprecated + superseded_by mutual-nda-deep in
    // its JSON (commit 24f0a8d). The DOCX cover AND the audit-trail
    // Playbook line should both annotate so a reader of either surface
    // sees that they were analyzed against a legacy playbook.
    const blob = await buildDocxReport(makeRun(), ingest, loadStarterDkbSync(), loadMutualNda());
    const { unzipSync, strFromU8 } = await import("fflate");
    const entries = unzipSync(new Uint8Array(await blob.arrayBuffer()));
    const docXml = strFromU8(entries["word/document.xml"]!);
    // The substring appears at least twice: once in the cover Playbook
    // line, once in the audit-trail Playbook line.
    const hits = docXml.match(/legacy; superseded by mutual-nda-deep/g) ?? [];
    expect(hits.length).toBeGreaterThanOrEqual(2);
  });

  it("cover does NOT annotate non-deprecated playbooks", async () => {
    const nonDeprecated = { ...loadMutualNda(), deprecated: false, superseded_by: undefined };
    const blob = await buildDocxReport(makeRun(), ingest, loadStarterDkbSync(), nonDeprecated);
    const { unzipSync, strFromU8 } = await import("fflate");
    const entries = unzipSync(new Uint8Array(await blob.arrayBuffer()));
    const docXml = strFromU8(entries["word/document.xml"]!);
    expect(docXml).not.toContain("legacy");
    expect(docXml).not.toContain("superseded by");
  });

  it("renders the v9 Last Look sections when the surfaces are supplied", async () => {
    const v9 = {
      delivery: {
        source: "docx" as const,
        inspectable: true,
        findings: [
          {
            rule_id: "HANDOFF-001",
            severity: "critical" as const,
            title: "Tracked changes are present",
            description: "2 tracked-change revisions remain.",
            count: 2,
            evidence: [],
          },
        ],
        summary: "Delivery: 2 tracked changes — review before sending.",
        delivery_hash: "d".repeat(64),
      },
      closingChecklist: {
        open_count: 1,
        items: [
          {
            category: "attachment" as const,
            rule_id: "STRUCT-018",
            label: "Referenced attachment not present: Exhibit C",
            section: "s3",
          },
        ],
      },
      criticalDates: {
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
        ],
        resolved_count: 1,
        unresolved_count: 0,
        critical_dates_hash: "e".repeat(64),
      },
    };
    const blob = await buildDocxReport(
      makeRun(),
      ingest,
      loadStarterDkbSync(),
      loadMutualNda(),
      undefined,
      undefined,
      undefined,
      v9,
    );
    const { unzipSync, strFromU8 } = await import("fflate");
    const entries = unzipSync(new Uint8Array(await blob.arrayBuffer()));
    const docXml = strFromU8(entries["word/document.xml"]!);
    const runText = (docXml.match(/<w:t[^>]*>([^<]*)<\/w:t>/g) ?? [])
      .map((m) => m.replace(/<[^>]+>/g, ""))
      .join("");
    expect(runText).toContain("Clean to Send");
    expect(runText).toContain("Ready to Sign");
    expect(runText).toContain("Critical Dates");
    expect(runText).toContain("HANDOFF-001");
    expect(runText).toContain("2025-11-01");
  });

  it("omits the v9 sections when no surface is supplied", async () => {
    const blob = await buildDocxReport(makeRun(), ingest, loadStarterDkbSync(), loadMutualNda());
    const { unzipSync, strFromU8 } = await import("fflate");
    const entries = unzipSync(new Uint8Array(await blob.arrayBuffer()));
    const runText = (
      strFromU8(entries["word/document.xml"]!).match(/<w:t[^>]*>([^<]*)<\/w:t>/g) ?? []
    )
      .map((m) => m.replace(/<[^>]+>/g, ""))
      .join("");
    expect(runText).not.toContain("Clean to Send");
    expect(runText).not.toContain("Critical Dates");
  });

  it("renders the negotiation-posture section when supplied (spec-v10)", async () => {
    const posture = {
      counts: { ideal: 1, acceptable: 1, below_acceptable: 0, unevaluable: 0 },
      positions: [
        { dimension: "Liability cap", tier: "acceptable" as const, detail: "8x", section_id: "s4" },
        { dimension: "Governing law", tier: "ideal" as const, guidance: "Delaware" },
      ],
      posture_hash: "f".repeat(64),
    };
    const blob = await buildDocxReport(
      makeRun(),
      ingest,
      loadStarterDkbSync(),
      loadMutualNda(),
      undefined,
      undefined,
      undefined,
      undefined,
      posture,
    );
    const { unzipSync, strFromU8 } = await import("fflate");
    const entries = unzipSync(new Uint8Array(await blob.arrayBuffer()));
    const runText = (
      strFromU8(entries["word/document.xml"]!).match(/<w:t[^>]*>([^<]*)<\/w:t>/g) ?? []
    )
      .map((m) => m.replace(/<[^>]+>/g, ""))
      .join("");
    expect(runText).toContain("Negotiation Posture");
    expect(runText).toContain("Liability cap");
    expect(runText).toContain("Acceptable");
  });

  it("surfaces the v3 ladder detail (met rung, deal-size band, approved fallback) in the posture table", async () => {
    const posture = {
      counts: { ideal: 0, acceptable: 1, below_acceptable: 1, unevaluable: 0 },
      positions: [
        {
          dimension: "Liability cap",
          tier: "acceptable" as const,
          detail: "8x",
          met_rung: "7x cap",
          size_band: "≥ $1M",
          section_id: "s4",
        },
        {
          dimension: "Indemnity",
          tier: "below-acceptable" as const,
          approved_language: "Indemnity shall be mutual and capped at fees.",
        },
      ],
      posture_hash: "f".repeat(64),
    };
    const blob = await buildDocxReport(
      makeRun(),
      ingest,
      loadStarterDkbSync(),
      loadMutualNda(),
      undefined,
      undefined,
      undefined,
      undefined,
      posture,
    );
    const { unzipSync, strFromU8 } = await import("fflate");
    const entries = unzipSync(new Uint8Array(await blob.arrayBuffer()));
    const runText = (
      strFromU8(entries["word/document.xml"]!).match(/<w:t[^>]*>([^<]*)<\/w:t>/g) ?? []
    )
      .map((m) => m.replace(/<[^>]+>/g, ""))
      .join("");
    expect(runText).toContain("met rung: 7x cap");
    expect(runText).toContain("Deal-size band: ≥ $1M");
    expect(runText).toContain("Your approved fallback: Indemnity shall be mutual");
  });
});

describe("buildJsonReport", () => {
  it("serializes the run plus ingest summary as pretty JSON", async () => {
    const blob = buildJsonReport(makeRun(), ingest);
    expect(blob.type).toBe("application/json");
    const text = await blob.text();
    const parsed = JSON.parse(text);
    expect(parsed.run.playbook_id).toBe("mutual-nda");
    expect(parsed.ingest.sha256).toBe("a".repeat(64));
    expect(text).toContain("\n  "); // pretty-printed
  });

  it("stamps report-level provenance (dkb/engine/rule-taxonomy versions) (spec-v7 §17)", async () => {
    const parsed = JSON.parse(await buildJsonReport(makeRun(), ingest).text());
    expect(parsed.provenance.dkb_version).toBe(parsed.run.dkb_version);
    expect(parsed.provenance.engine_version).toBe(parsed.run.version);
    expect(parsed.provenance.rule_taxonomy_version).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it("surfaces playbook_deprecated + playbook_superseded_by when the playbook is deprecated (Step 27 follow-up)", async () => {
    const blob = buildJsonReport(makeRun(), ingest, loadMutualNda());
    const parsed = JSON.parse(await blob.text());
    expect(parsed.playbook_deprecated).toBe(true);
    expect(parsed.playbook_superseded_by).toBe("mutual-nda-deep");
  });

  it("omits playbook_deprecated when the playbook is not deprecated (back-compat)", async () => {
    const nonDeprecated = { ...loadMutualNda(), deprecated: false, superseded_by: undefined };
    const blob = buildJsonReport(makeRun(), ingest, nonDeprecated);
    const parsed = JSON.parse(await blob.text());
    expect(parsed.playbook_deprecated).toBeUndefined();
    expect(parsed.playbook_superseded_by).toBeUndefined();
  });

  it("omits playbook_deprecated when the playbook arg is omitted entirely (back-compat)", async () => {
    const blob = buildJsonReport(makeRun(), ingest);
    const parsed = JSON.parse(await blob.text());
    expect(parsed.playbook_deprecated).toBeUndefined();
    expect(parsed.playbook_superseded_by).toBeUndefined();
  });

  it("emits secondary_families when multi-family activation supplies them (spec-v6)", async () => {
    const secondary = [
      {
        playbook_id: "dpa-controller-processor",
        playbook_name: "DPA (Controller–Processor)",
        findings: [finding("dpa1", "critical")],
        counts: { critical: 1, warning: 0, info: 0 },
      },
    ];
    const blob = buildJsonReport(makeRun(), ingest, loadMutualNda(), secondary);
    const parsed = JSON.parse(await blob.text());
    expect(parsed.secondary_families).toHaveLength(1);
    expect(parsed.secondary_families[0].playbook_id).toBe("dpa-controller-processor");
    expect(parsed.secondary_families[0].findings).toHaveLength(1);
  });

  it("omits secondary_families for a single-family document (back-compat)", async () => {
    const blob = buildJsonReport(makeRun(), ingest, loadMutualNda(), []);
    const parsed = JSON.parse(await blob.text());
    expect(parsed.secondary_families).toBeUndefined();
  });
});

describe("model-clause references (spec-v6 Part IV)", () => {
  function runWithRule(ruleId: string): EngineRun {
    const run = makeRun();
    run.findings = [{ ...finding("x1", "warning"), rule_id: ruleId }];
    return run;
  }

  it("emits a model_clause_references entry for a fired rule that has one", async () => {
    const blob = buildJsonReport(runWithRule("RISK-005"), ingest);
    const parsed = JSON.parse(await blob.text());
    expect(parsed.model_clause_references).toHaveLength(1);
    expect(parsed.model_clause_references[0].rule_id).toBe("RISK-005");
    expect(parsed.model_clause_references[0].reference.id).toBe("cp-csa-limitation-of-liability");
    expect(parsed.model_clause_references[0].reference.source.license).toBe("CC-BY-4.0");
    expect(parsed.model_clause_coverage.referenced_in_report).toBe(1);
    expect(parsed.model_clause_coverage.rules_with_reference).toBeGreaterThan(0);
  });

  it("omits model_clause_references when no fired rule has one, but still publishes coverage", async () => {
    const blob = buildJsonReport(runWithRule("STRUCT-001"), ingest);
    const parsed = JSON.parse(await blob.text());
    expect(parsed.model_clause_references).toBeUndefined();
    expect(parsed.model_clause_coverage.referenced_in_report).toBe(0);
    expect(parsed.model_clause_coverage.model_clauses).toBeGreaterThan(0);
  });

  it("does not change the run result_hash (references live outside the run)", async () => {
    const run = runWithRule("RISK-005");
    const before = run.result_hash;
    const blob = buildJsonReport(run, ingest);
    const parsed = JSON.parse(await blob.text());
    expect(parsed.run.result_hash).toBe(before);
  });

  it("renders the reference + attribution in the DOCX for a finding that has one", async () => {
    const blob = await buildDocxReport(
      runWithRule("RISK-005"),
      ingest,
      loadStarterDkbSync(),
      loadMutualNda(),
    );
    const { unzipSync, strFromU8 } = await import("fflate");
    const files = unzipSync(new Uint8Array(await blob.arrayBuffer()));
    const docXml = strFromU8(files["word/document.xml"]!);
    expect(docXml).toContain("Reference model clause");
    expect(docXml).toContain("Common Paper");
    expect(docXml).toContain("Vaulytica does not draft");
  });
});

describe("jurisdiction overlays (spec-v6 Part VI §21, Step 101)", () => {
  function empRun(): EngineRun {
    const run = makeRun();
    run.playbook_id = "executive-employment";
    return run;
  }
  function extractedWithGovLaw(raw: string): import("../extract/types.js").ExtractedData {
    return {
      parties: [],
      dates: [],
      amounts: [],
      definitions: { entries: [] } as never,
      outline: { sections: [] } as never,
      crossrefs: [],
      obligations: [],
      jurisdictions: [
        {
          clause_kind: "governing-law",
          raw_text: raw,
          position: { section_id: "s1", start: 0, end: raw.length },
        },
      ],
      classified: [],
    };
  }

  it("emits jurisdiction_overlays in JSON for an employment doc governed by California", async () => {
    const blob = buildJsonReport(
      empRun(),
      ingest,
      undefined,
      undefined,
      extractedWithGovLaw("California"),
    );
    const parsed = JSON.parse(await blob.text());
    expect(parsed.jurisdiction_overlays.family).toBe("employment");
    expect(parsed.jurisdiction_overlays.matched[0].jurisdiction).toBe("us-ca");
    expect(parsed.jurisdiction_overlays.matched[0].posture).toBe("prohibited");
  });

  it("reports an uncovered governing-law state honestly", async () => {
    // Montana: no non-compete overlay node (Wyoming gained one via SF 107).
    const blob = buildJsonReport(
      empRun(),
      ingest,
      undefined,
      undefined,
      extractedWithGovLaw("Montana"),
    );
    const parsed = JSON.parse(await blob.text());
    expect(parsed.jurisdiction_overlays.matched).toHaveLength(0);
    expect(parsed.jurisdiction_overlays.uncovered_states).toEqual(["us-mt"]);
  });

  it("omits jurisdiction_overlays for a family with no overlay catalog", async () => {
    const blob = buildJsonReport(
      makeRun(),
      ingest,
      undefined,
      undefined,
      extractedWithGovLaw("California"),
    );
    const parsed = JSON.parse(await blob.text());
    expect(parsed.jurisdiction_overlays).toBeUndefined();
  });

  it("does not change the run result_hash (overlays live outside the run)", async () => {
    const run = empRun();
    const before = run.result_hash;
    const blob = buildJsonReport(
      run,
      ingest,
      undefined,
      undefined,
      extractedWithGovLaw("California"),
    );
    const parsed = JSON.parse(await blob.text());
    expect(parsed.run.result_hash).toBe(before);
  });

  it("renders the Jurisdiction Overlays section in the DOCX", async () => {
    const blob = await buildDocxReport(
      empRun(),
      ingest,
      loadStarterDkbSync(),
      loadMutualNda(),
      undefined,
      extractedWithGovLaw("California"),
    );
    const { unzipSync, strFromU8 } = await import("fflate");
    const files = unzipSync(new Uint8Array(await blob.arrayBuffer()));
    const docXml = strFromU8(files["word/document.xml"]!);
    expect(docXml).toContain("Jurisdiction Overlays");
    expect(docXml).toContain("California");
  });
});

describe("buildDocxReport multi-family section (spec-v6)", () => {
  it("renders the 'Additional Checks' section when secondary families are supplied", async () => {
    const secondary = [
      {
        playbook_id: "dpa-controller-processor",
        playbook_name: "DPA (Controller–Processor)",
        findings: [finding("dpa1", "critical")],
        counts: { critical: 1, warning: 0, info: 0 },
      },
      {
        playbook_id: "ip-licensing-patent",
        playbook_name: "Patent License",
        findings: [],
        counts: { critical: 0, warning: 0, info: 0 },
      },
    ];
    const blob = await buildDocxReport(
      makeRun(),
      ingest,
      loadStarterDkbSync(),
      loadMutualNda(),
      undefined,
      undefined,
      secondary,
    );
    const { unzipSync, strFromU8 } = await import("fflate");
    const files = unzipSync(new Uint8Array(await blob.arrayBuffer()));
    const docXml = strFromU8(files["word/document.xml"]!);
    expect(docXml).toContain("Additional Checks From Other Detected Families");
    expect(docXml).toContain("DPA (Controller");
    expect(docXml).toContain("Patent License");
  });

  it("renders no 'Additional Checks' section when none are supplied (back-compat)", async () => {
    const blob = await buildDocxReport(makeRun(), ingest, loadStarterDkbSync(), loadMutualNda());
    const { unzipSync, strFromU8 } = await import("fflate");
    const files = unzipSync(new Uint8Array(await blob.arrayBuffer()));
    const docXml = strFromU8(files["word/document.xml"]!);
    expect(docXml).not.toContain("Additional Checks From Other Detected Families");
  });
});

// spec-v7 Part XIV (Step 122) — report-structure validation. The report is
// the product: the thing a user cites. Earlier tests proved it is a valid ZIP
// of the right MIME type; these prove it *says the right things* — that the
// cover/audit-trail carry the proof fields, findings are grouped in severity
// order, citations render, and the verbatim posture block is present. Structure,
// not pixels: every assertion is a deterministic substring/ordering over the
// unzipped OOXML, so it is CI-safe and localizes any regression that drops or
// reorders a load-bearing part of the report.
describe("report-structure validation (spec-v7 Step 122)", () => {
  async function docXmlOf(blob: Blob): Promise<string> {
    const { unzipSync, strFromU8 } = await import("fflate");
    const files = unzipSync(new Uint8Array(await blob.arrayBuffer()));
    return strFromU8(files["word/document.xml"]!);
  }

  it("DOCX carries the title and the proof fields (engine/DKB versions, file fingerprint, result hash)", async () => {
    const run = makeRun();
    const xml = await docXmlOf(
      await buildDocxReport(run, ingest, loadStarterDkbSync(), loadMutualNda()),
    );
    expect(xml).toContain("Vaulytica Report");
    expect(xml).toContain(`Engine version: ${run.version}`);
    expect(xml).toContain(`DKB version: ${run.dkb_version}`);
    expect(xml).toContain(`File fingerprint: ${run.source_file.sha256}`);
    expect(xml).toContain(`Result hash: ${run.result_hash}`);
  });

  it("DOCX groups findings Critical → Warning → Info, in that order", async () => {
    const xml = await docXmlOf(
      await buildDocxReport(makeRun(), ingest, loadStarterDkbSync(), loadMutualNda()),
    );
    // Anchor ordering on the per-finding severity badges, which appear only in
    // the findings sections (the counts tables use the plain words), so the
    // order reflects the findings grouping, not an incidental earlier mention.
    const crit = xml.indexOf("[CRITICAL]");
    const warn = xml.indexOf("[WARNING]");
    const info = xml.indexOf("[INFO]");
    expect(crit).toBeGreaterThan(-1);
    expect(warn).toBeGreaterThan(crit);
    expect(info).toBeGreaterThan(warn);
    expect(xml).toContain("Critical Findings");
    expect(xml).toContain("Warnings");
  });

  it("DOCX renders a Sources line for cited findings plus a Bibliography section", async () => {
    const xml = await docXmlOf(
      await buildDocxReport(makeRun(), ingest, loadStarterDkbSync(), loadMutualNda()),
    );
    expect(xml).toMatch(/Sources: \[\d+\]/);
    expect(xml).toContain("Bibliography");
  });

  it("DOCX carries the verbatim determinism, privacy, and non-advice posture statements", async () => {
    const xml = await docXmlOf(
      await buildDocxReport(makeRun(), ingest, loadStarterDkbSync(), loadMutualNda()),
    );
    expect(xml).toContain("This report was produced by a deterministic process");
    expect(xml).toContain("performed entirely inside the user"); // privacy (apostrophe-free prefix)
    expect(xml).toContain("Vaulytica is a software tool, not a lawyer"); // non-advice disclaimer
  });

  it("JSON report is shape-complete: run + ingest envelopes with well-formed findings", async () => {
    const parsed = JSON.parse(await buildJsonReport(makeRun(), ingest).text());
    for (const k of [
      "version",
      "dkb_version",
      "playbook_id",
      "result_hash",
      "executed_at",
      "findings",
      "execution_log",
      "source_file",
    ]) {
      expect(parsed.run).toHaveProperty(k);
    }
    expect(Array.isArray(parsed.run.findings)).toBe(true);
    expect(Array.isArray(parsed.run.execution_log)).toBe(true);
    for (const k of ["name", "sha256", "size_bytes"]) {
      expect(parsed.run.source_file).toHaveProperty(k);
    }
    // The JSON ingest is an intentional summary Pick (no tree, no warnings).
    for (const k of ["source", "word_count", "sha256"]) {
      expect(parsed.ingest).toHaveProperty(k);
    }
    // Every finding traces to a rule and carries a valid severity + citations array.
    for (const f of parsed.run.findings) {
      for (const k of ["id", "rule_id", "severity", "title", "source_citations"]) {
        expect(f).toHaveProperty(k);
      }
      expect(["critical", "warning", "info"]).toContain(f.severity);
    }
  });
});
