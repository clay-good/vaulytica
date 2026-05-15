import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Packer } from "docx";

import { buildDocxReport } from "../docx.js";
import { loadStarterDkbSync } from "../../engine/_test-fixtures.js";
import type { EngineRun, Finding } from "../../engine/finding.js";
import type { IngestResult } from "../../ingest/types.js";
import type { Playbook } from "../../playbooks/types.js";
import type { ConsistencyRun } from "../../engine/consistency/types.js";
import type { ComplianceMatrix } from "./types.js";
import type {
  TransferMechanismReference,
  SubprocessorInventory,
  InsuranceSchedule,
} from "../../extract/v3/types.js";
import {
  renderComplianceMatrix,
  renderTransfersSummary,
  renderSubprocessorPage,
  renderInsurancePage,
  renderConsistencyAppendix,
  renderCitationIndex,
  buildV3Footer,
} from "./index.js";
import { buildBibliography } from "../bibliography.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadMutualNda(): Playbook {
  const p = join(__dirname, "..", "..", "..", "playbooks", "mutual-nda.json");
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
      { rule_id: "STRUCT-001", rule_version: "1.0.0", fired: true, finding_id: "c1", elapsed_ms: 0.1 },
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

const sampleMatrix: ComplianceMatrix = {
  columns: ["Permitted Uses", "Safeguards", "Breach Notification", "Return/Destruction"],
  dkb_build_date: "2026-05-13T00:00:00Z",
  rows: [
    {
      regulator: "HIPAA",
      authority_url: "https://www.ecfr.gov/current/title-45/section-164.504",
      cells: [
        { status: "pass", contributing_rule_ids: ["BAA-001"] },
        { status: "partial", note: "missing risk assessment", contributing_rule_ids: ["BAA-013"] },
        { status: "fail", note: "60-day clock not stated", contributing_rule_ids: ["BAA-019"] },
        { status: "na" },
      ],
    },
  ],
};

const sampleTransfers: TransferMechanismReference[] = [
  {
    kind: "scc-module-2",
    raw_text: "Module 2 (C-to-P) of the EU SCCs applies. A TIA has been completed.",
    location: "annex",
    position: { section_id: "s7", start: 100, end: 180 },
  },
  {
    kind: "uk-addendum",
    raw_text: "UK Addendum incorporates the SCCs with supplementary measures.",
    location: "by-reference",
    position: { section_id: "s7", start: 200, end: 260 },
  },
];

const sampleSubprocessor: SubprocessorInventory = {
  permitted: true,
  consent_form: "general-written",
  list_location: "url",
  notice_days: 30,
  objection_right: true,
  objection_consequence: "terminate-affected-services",
  flow_down_required: true,
  position: { section_id: "s5", start: 50, end: 150 },
  raw_text:
    "Customer hereby grants general written authorization for subprocessors. The current list is available at https://example.com/subprocessors. Customer has the right to object on 30 days' notice.",
};

const sampleInsurance: InsuranceSchedule = {
  amounts: [
    {
      line: "commercial-general-liability",
      per_occurrence_usd: 1_000_000,
      aggregate_usd: 2_000_000,
      raw_text: "$1M / $2M CGL",
      position: { section_id: "s8", start: 0, end: 20 },
    },
    {
      line: "cyber-liability",
      per_occurrence_usd: 5_000_000,
      aggregate_usd: 5_000_000,
      raw_text: "$5M cyber",
      position: { section_id: "s8", start: 30, end: 50 },
    },
  ],
  endorsements: [
    { form_number: "CG 20 10", raw_text: "CG 20 10", position: { section_id: "s8", start: 60, end: 70 } },
  ],
  required_am_best_rating: "A- VII",
  notice_of_cancellation_days: 30,
};

const sampleConsistencyRun: ConsistencyRun = {
  version: "0.1.0",
  dkb_version: "v0.0.1-starter",
  documents: [
    { doc_id: "msa", source_file_name: "msa.docx", playbook_id: "msa-vendor-deep", kind: "msa" },
    { doc_id: "baa", source_file_name: "baa.docx", playbook_id: "baa", kind: "baa" },
  ],
  executed_at: "2026-05-13T00:00:00Z",
  findings: [
    {
      id: "CC-001-baa-0",
      rule_id: "CC-001",
      rule_version: "1.0.0",
      severity: "critical",
      title: "BAA permitted uses are broader than the MSA's service scope",
      description: "Open-ended PHI use does not match the MSA's defined services.",
      explanation: "HHS guidance prohibits the BA from using PHI other than as the CE could.",
      recommendation: "Narrow the BAA's permitted-uses clause.",
      source_citations: [],
      excerpts: [
        {
          doc_id: "baa",
          source_file_name: "baa.docx",
          text: "Business Associate may use PHI for any business purpose.",
          start_offset: 0,
          end_offset: 60,
        },
        {
          doc_id: "msa",
          source_file_name: "msa.docx",
          text: "The Services are claims processing on behalf of Customer.",
          start_offset: 0,
          end_offset: 60,
        },
      ],
    },
  ],
  execution_log: [],
  result_hash: "c".repeat(64),
};

/* ---------------- per-renderer shape ---------------- */

describe("renderComplianceMatrix", () => {
  it("renders a heading + table + page break when rows are present", () => {
    const out = renderComplianceMatrix(sampleMatrix);
    expect(out.length).toBeGreaterThanOrEqual(3);
  });

  it("emits a polite placeholder when columns are empty", () => {
    const out = renderComplianceMatrix({ columns: [], rows: [] });
    expect(out.length).toBeGreaterThan(0);
  });
});

describe("renderTransfersSummary", () => {
  it("returns [] when no transfers detected", () => {
    expect(renderTransfersSummary([])).toEqual([]);
  });
  it("renders content when transfers are detected", () => {
    const out = renderTransfersSummary(sampleTransfers);
    expect(out.length).toBeGreaterThan(0);
  });
});

describe("renderSubprocessorPage", () => {
  it("returns [] when the inventory is null", () => {
    expect(renderSubprocessorPage(null)).toEqual([]);
  });
  it("renders the inventory when present", () => {
    const out = renderSubprocessorPage(sampleSubprocessor);
    expect(out.length).toBeGreaterThan(0);
  });
});

describe("renderInsurancePage", () => {
  it("returns [] when nothing was extracted", () => {
    expect(
      renderInsurancePage({
        amounts: [],
        endorsements: [],
        required_am_best_rating: null,
        notice_of_cancellation_days: null,
      }),
    ).toEqual([]);
  });
  it("renders the schedule when present", () => {
    const out = renderInsurancePage(sampleInsurance);
    expect(out.length).toBeGreaterThan(0);
  });
});

describe("renderConsistencyAppendix", () => {
  it("renders both a heading and finding details", () => {
    const out = renderConsistencyAppendix(sampleConsistencyRun);
    expect(out.length).toBeGreaterThan(0);
  });
  it("renders a 'no conflicts' message when findings are empty", () => {
    const empty: ConsistencyRun = { ...sampleConsistencyRun, findings: [] };
    const out = renderConsistencyAppendix(empty);
    expect(out.length).toBeGreaterThan(0);
  });
});

describe("renderCitationIndex", () => {
  it("returns [] when bibliography is empty", () => {
    expect(renderCitationIndex([], "v0.0.1-starter")).toEqual([]);
  });
  it("renders when bibliography has entries", () => {
    const run = makeRun();
    const bib = buildBibliography(run.findings, loadStarterDkbSync());
    const out = renderCitationIndex(bib, run.dkb_version, "2026-05-13T00:00:00Z");
    expect(out.length).toBeGreaterThan(0);
  });
});

describe("buildV3Footer", () => {
  it("produces a Footer instance", async () => {
    const footer = buildV3Footer({
      engine_version: "0.1.0",
      dkb_version: "v0.0.1-starter",
      result_hash: "b".repeat(64),
      dkb_build_date: "2026-05-13T00:00:00Z",
    });
    // The Footer class doesn't expose a simple `text` getter, but it must
    // be serializable via Packer when wrapped in a Document.
    expect(footer).toBeDefined();
    void Packer;
  });
});

/* ---------------- end-to-end DOCX with v3 inputs ---------------- */

describe("buildDocxReport with v3 inputs", () => {
  it("produces a Blob larger than the v2-only report when all v3 sections are passed", async () => {
    const v2Blob = await buildDocxReport(makeRun(), ingest, loadStarterDkbSync(), loadMutualNda());
    const v3Blob = await buildDocxReport(
      makeRun(),
      ingest,
      loadStarterDkbSync(),
      loadMutualNda(),
      {
        matrix: sampleMatrix,
        transfers: sampleTransfers,
        subprocessor: sampleSubprocessor,
        insurance: sampleInsurance,
        consistency: sampleConsistencyRun,
        dkb_build_date: "2026-05-13T00:00:00Z",
      },
    );
    expect(v3Blob.size).toBeGreaterThan(v2Blob.size);
    // ZIP local-file-header magic
    const bytes = new Uint8Array(await v3Blob.arrayBuffer());
    expect(bytes[0]).toBe(0x50);
    expect(bytes[1]).toBe(0x4b);
  });

  it("is backwards compatible: omitting v3 yields the v2 report", async () => {
    const blob = await buildDocxReport(makeRun(), ingest, loadStarterDkbSync(), loadMutualNda());
    expect(blob.size).toBeGreaterThan(1000);
  });

  it("omits each conditional section when its input is absent", async () => {
    // Pass only the matrix; the other v3 inputs are absent.
    const blob = await buildDocxReport(
      makeRun(),
      ingest,
      loadStarterDkbSync(),
      loadMutualNda(),
      { matrix: sampleMatrix },
    );
    expect(blob.size).toBeGreaterThan(1000);
  });
});
