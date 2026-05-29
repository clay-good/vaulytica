import { describe, expect, it } from "vitest";
import { runCustomPlaybook } from "./custom-interpreter.js";
import { validateCustomPlaybook, type CustomPlaybook } from "./custom-playbook.js";
import type { DocumentTree } from "../ingest/types.js";
import type { ExtractedData } from "../extract/types.js";

// --- fixtures ---------------------------------------------------------------

/** A one-section tree whose single paragraph holds `body`. */
function tree(heading: string, body: string): DocumentTree {
  return {
    type: "document",
    sections: [
      {
        id: "s1",
        heading,
        level: 1,
        paragraphs: [{ id: "s1.p1", runs: [{ id: "s1.p1.r0", text: body, start: 0, end: body.length }] }],
        children: [],
      },
    ],
  };
}

function emptyExtracted(over: Partial<ExtractedData> = {}): ExtractedData {
  return {
    parties: [],
    dates: [],
    amounts: [],
    definitions: { entries: [], unused_terms: [], undefined_capitalized: [] },
    outline: { nodes: [], by_id: {} },
    crossrefs: [],
    obligations: [],
    jurisdictions: [],
    classified: [],
    ...over,
  };
}

function pb(over: Partial<CustomPlaybook> = {}): CustomPlaybook {
  const raw = {
    schema_version: "1.0",
    catalog_version: "0.1.0",
    id: "test-pb",
    name: "Test",
    description: "Test playbook",
    ...over,
  };
  const v = validateCustomPlaybook(raw);
  if (!v.ok) throw new Error("fixture playbook invalid: " + v.errors.join("; "));
  return v.playbook;
}

// --- predicate behavior -----------------------------------------------------

describe("runCustomPlaybook — predicates", () => {
  it("defined_term_present fires when the term is undefined", async () => {
    const run = await runCustomPlaybook(
      pb({
        custom_rules: [
          { id: "R1", title: "Need CI", description: "Confidential Information must be defined.", severity: "warning", assert: { kind: "defined_term_present", term: "Confidential Information" } },
        ],
      }),
      { tree: tree("Agreement", "no defined terms here"), extracted: emptyExtracted() },
    );
    expect(run.findings).toHaveLength(1);
    expect(run.findings[0]!.rule_id).toBe("R1");
    expect(run.findings[0]!.source).toBe("custom-playbook");
  });

  it("defined_term_present is compliant (no finding) when the term is defined", async () => {
    const run = await runCustomPlaybook(
      pb({
        custom_rules: [
          { id: "R1", title: "Need CI", description: "d", severity: "warning", assert: { kind: "defined_term_present", term: "Confidential Information" } },
        ],
      }),
      {
        tree: tree("Agreement", "x"),
        extracted: emptyExtracted({
          definitions: { entries: [{ term: "Confidential Information", definition: "...", defined_at: { section_id: "s1", start: 0, end: 1 }, used_at: [] }], unused_terms: [], undefined_capitalized: [] },
        }),
      },
    );
    expect(run.findings).toHaveLength(0);
  });

  it("clause_absent fires when the forbidden clause is present", async () => {
    const run = await runCustomPlaybook(
      pb({
        custom_rules: [
          { id: "R1", title: "No arbitration", description: "We strike arbitration.", severity: "warning", assert: { kind: "clause_absent", pattern: "arbitration" } },
        ],
      }),
      { tree: tree("Disputes", "All disputes resolved by binding arbitration."), extracted: emptyExtracted() },
    );
    expect(run.findings).toHaveLength(1);
    expect(run.findings[0]!.excerpt.text.toLowerCase()).toContain("arbitration");
  });

  it("clause_present fires when a required clause is missing", async () => {
    const run = await runCustomPlaybook(
      pb({
        custom_rules: [
          { id: "R1", title: "Need LoL", description: "d", severity: "critical", assert: { kind: "clause_present", section_heading: "Limitation of Liability" } },
        ],
      }),
      { tree: tree("Payment", "fees are due net 30"), extracted: emptyExtracted() },
    );
    expect(run.findings).toHaveLength(1);
  });

  it("governing_law_in fires when the law is outside the allowed set", async () => {
    const run = await runCustomPlaybook(
      pb({
        custom_rules: [
          { id: "R1", title: "Gov law DE/NY", description: "d", severity: "warning", assert: { kind: "governing_law_in", allowed: ["us-de", "us-ny"] } },
        ],
      }),
      {
        tree: tree("Governing Law", "laws of the State of California"),
        extracted: emptyExtracted({
          jurisdictions: [{ clause_kind: "governing-law", jurisdiction_id: "us-ca", raw_text: "State of California", position: { section_id: "s1", start: 0, end: 10 } }],
        }),
      },
    );
    expect(run.findings).toHaveLength(1);
    expect(run.findings[0]!.explanation).toContain("us-ca");
  });

  it("governing_law_in is unevaluable when no governing-law clause resolves", async () => {
    const run = await runCustomPlaybook(
      pb({
        custom_rules: [
          { id: "R1", title: "Gov law", description: "d", severity: "warning", assert: { kind: "governing_law_in", allowed: ["us-de"] } },
        ],
      }),
      { tree: tree("X", "no governing law clause"), extracted: emptyExtracted() },
    );
    expect(run.findings).toHaveLength(0);
    expect(run.unevaluable).toHaveLength(1);
    expect(run.unevaluable[0]!.rule_id).toBe("R1");
  });

  it("cross_ref_resolves fires when an internal reference dangles", async () => {
    const run = await runCustomPlaybook(
      pb({
        custom_rules: [
          { id: "R1", title: "Refs resolve", description: "d", severity: "info", assert: { kind: "cross_ref_resolves" } },
        ],
      }),
      {
        tree: tree("X", "see Section 9.9"),
        extracted: emptyExtracted({
          crossrefs: [{ raw_text: "Section 9.9", unresolved: true, position: { section_id: "s1", start: 4, end: 15 } }],
        }),
      },
    );
    expect(run.findings).toHaveLength(1);
  });

  it("numeric_threshold fires when a stated value breaks the assertion", async () => {
    const run = await runCustomPlaybook(
      pb({
        custom_rules: [
          { id: "R1", title: "Notice <= 30d", description: "d", severity: "warning", assert: { kind: "numeric_threshold", metric: "notice_period_days", comparator: "lte", value: 30 } },
        ],
      }),
      { tree: tree("Term", "Either party may terminate on 60 days written notice."), extracted: emptyExtracted() },
    );
    expect(run.findings).toHaveLength(1);
    expect(run.findings[0]!.explanation).toContain("60");
  });

  it("numeric_threshold is unevaluable when the metric is absent", async () => {
    const run = await runCustomPlaybook(
      pb({
        custom_rules: [
          { id: "R1", title: "Cap >= 12x", description: "d", severity: "warning", assert: { kind: "numeric_threshold", metric: "liability_cap_multiple", comparator: "gte", value: 12 } },
        ],
      }),
      { tree: tree("X", "this document never mentions a cap multiple"), extracted: emptyExtracted() },
    );
    expect(run.findings).toHaveLength(0);
    expect(run.unevaluable[0]!.reason).toContain("liability_cap_multiple");
  });

  it("numeric_threshold is compliant when the stated value satisfies the assertion", async () => {
    const run = await runCustomPlaybook(
      pb({
        custom_rules: [
          { id: "R1", title: "Notice <= 30d", description: "d", severity: "warning", assert: { kind: "numeric_threshold", metric: "notice_period_days", comparator: "lte", value: 30 } },
        ],
      }),
      { tree: tree("Term", "terminate on 30 days written notice"), extracted: emptyExtracted() },
    );
    expect(run.findings).toHaveLength(0);
  });
});

describe("runCustomPlaybook — required_clauses + citation provenance", () => {
  it("required_clauses fires when a required category is not classified", async () => {
    const run = await runCustomPlaybook(
      pb({ required_clauses: [{ category: "limitation-of-liability", severity: "critical" }] }),
      { tree: tree("X", "y"), extracted: emptyExtracted() },
    );
    expect(run.findings).toHaveLength(1);
    expect(run.findings[0]!.rule_id).toBe("required-clause:limitation-of-liability");
  });

  it("marks a citationless rule uncited and a cited rule cited", async () => {
    const run = await runCustomPlaybook(
      pb({
        custom_rules: [
          { id: "CITED", title: "t", description: "d", severity: "warning", assert: { kind: "clause_absent", pattern: "arbitration" }, citation: { reference: "Policy 4.2" } },
          { id: "UNCITED", title: "t", description: "d", severity: "warning", assert: { kind: "clause_absent", pattern: "arbitration" } },
        ],
      }),
      { tree: tree("X", "binding arbitration applies"), extracted: emptyExtracted() },
    );
    const byId = Object.fromEntries(run.findings.map((f) => [f.rule_id, f]));
    expect(byId["CITED"]!.citation_provenance).toBe("cited");
    expect(byId["CITED"]!.source_citations[0]!.source).toBe("Policy 4.2");
    expect(byId["UNCITED"]!.citation_provenance).toBe("uncited (team policy)");
    expect(byId["UNCITED"]!.source_citations).toHaveLength(0);
  });
});

describe("runCustomPlaybook — determinism", () => {
  it("produces a byte-identical result_hash across two runs", async () => {
    const playbook = pb({
      custom_rules: [
        { id: "A", title: "t", description: "d", severity: "critical", assert: { kind: "defined_term_present", term: "Foo" } },
        { id: "B", title: "t", description: "d", severity: "warning", assert: { kind: "clause_absent", pattern: "arbitration" } },
      ],
    });
    const input = { tree: tree("X", "binding arbitration"), extracted: emptyExtracted() };
    const a = await runCustomPlaybook(playbook, input);
    const b = await runCustomPlaybook(playbook, input);
    expect(a.result_hash).toBe(b.result_hash);
    expect(a.result_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("changes the result_hash when findings change", async () => {
    const playbook = pb({
      custom_rules: [
        { id: "A", title: "t", description: "d", severity: "warning", assert: { kind: "clause_absent", pattern: "arbitration" } },
      ],
    });
    const present = await runCustomPlaybook(playbook, { tree: tree("X", "binding arbitration"), extracted: emptyExtracted() });
    const absent = await runCustomPlaybook(playbook, { tree: tree("X", "no such clause"), extracted: emptyExtracted() });
    expect(present.result_hash).not.toBe(absent.result_hash);
  });
});
