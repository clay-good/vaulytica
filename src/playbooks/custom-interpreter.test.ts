import { describe, expect, it } from "vitest";
import { runCustomPlaybook, ladderHash } from "./custom-interpreter.js";
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

// --- spec-v10 Thrust C: dimension breadth (measure-first fixtures) ----------
//
// Each new metric is gated by a fixture proving the extractor locates the
// value on representative clause prose BEFORE it is relied on by a position.
// A metric run against a document that does not state it must be unevaluable,
// never guessed (spec-v10 §3 corollary 2, §XVI).

describe("runCustomPlaybook — Thrust C numeric metrics", () => {
  /** Build a single-rule playbook asserting `metric comparator value`. */
  function metricRule(
    metric: string,
    comparator: "gte" | "lte" | "gt" | "lt" | "eq",
    value: number,
  ): CustomPlaybook {
    return pb({
      custom_rules: [
        {
          id: "R1",
          title: "t",
          description: "d",
          severity: "warning",
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          assert: { kind: "numeric_threshold", metric, comparator, value } as any,
        },
      ],
    });
  }

  const CASES: Array<{ metric: string; body: string; expect: number }> = [
    { metric: "cure_period_days", body: "If a party fails to cure such breach within 30 days of written notice, the other party may terminate.", expect: 30 },
    { metric: "cure_period_days", body: "The breaching party shall have a cure period of 15 days to remedy the default.", expect: 15 },
    { metric: "cure_period_days", body: "Termination is permitted if the default is not remedied within 45 business days to cure the breach.", expect: 45 },
    { metric: "auto_renewal_notice_days", body: "This Agreement will automatically renew for successive one-year terms unless either party gives at least 60 days written notice of non-renewal.", expect: 60 },
    { metric: "auto_renewal_notice_days", body: "Notice of non-renewal must be delivered no fewer than 90 days before the end of the then-current term.", expect: 90 },
    { metric: "indemnity_cap_amount", body: "Vendor's total indemnification liability under this section shall not exceed $500,000 in the aggregate.", expect: 500000 },
    { metric: "indemnity_cap_amount", body: "In no event shall $250,000 be exceeded for the Provider's indemnification obligations.", expect: 250000 },
    { metric: "uptime_sla_percent", body: "Provider guarantees monthly uptime of 99.9% measured per calendar month.", expect: 99.9 },
    { metric: "uptime_sla_percent", body: "The Service shall maintain 99.95% availability during each billing period.", expect: 99.95 },
  ];

  for (const c of CASES) {
    it(`extracts ${c.metric} = ${c.expect} from representative prose`, async () => {
      // eq makes the assertion pass iff the extracted value is exactly c.expect:
      // a clean proof the extractor located the right number (compliant = found
      // and matched; a wrong/absent value would be a finding or unevaluable).
      const run = await runCustomPlaybook(metricRule(c.metric, "eq", c.expect), {
        tree: tree("Clause", c.body),
        extracted: emptyExtracted(),
      });
      expect(run.unevaluable).toHaveLength(0);
      expect(run.findings).toHaveLength(0);
    });
  }

  it("a Thrust C metric is unevaluable when the document never states it", async () => {
    const run = await runCustomPlaybook(metricRule("uptime_sla_percent", "gte", 99), {
      tree: tree("X", "This agreement says nothing about service availability."),
      extracted: emptyExtracted(),
    });
    expect(run.findings).toHaveLength(0);
    expect(run.unevaluable[0]!.reason).toContain("uptime_sla_percent");
  });

  it("a Thrust C metric fires a finding when the stated value breaks the assertion", async () => {
    const run = await runCustomPlaybook(metricRule("uptime_sla_percent", "gte", 99.99), {
      tree: tree("SLA", "Provider guarantees uptime of 99.9% per month."),
      extracted: emptyExtracted(),
    });
    expect(run.findings).toHaveLength(1);
    expect(run.findings[0]!.explanation).toContain("99.9");
  });
});

describe("runCustomPlaybook — clause_mutual predicate", () => {
  it("is compliant when the clause carries mutuality language", async () => {
    const run = await runCustomPlaybook(
      pb({
        custom_rules: [
          { id: "R1", title: "Mutual indemnity", description: "d", severity: "warning", assert: { kind: "clause_mutual", clause: "indemnification" } },
        ],
      }),
      { tree: tree("Indemnification", "Each party shall indemnify and hold harmless the other party from third-party claims."), extracted: emptyExtracted() },
    );
    expect(run.findings).toHaveLength(0);
    expect(run.unevaluable).toHaveLength(0);
  });

  it("fires when the clause is one-way", async () => {
    const run = await runCustomPlaybook(
      pb({
        custom_rules: [
          { id: "R1", title: "Mutual indemnity", description: "d", severity: "warning", assert: { kind: "clause_mutual", clause: "indemnification" } },
        ],
      }),
      { tree: tree("Indemnification", "Customer shall indemnify and defend Vendor against all claims arising from Customer's use of the Service."), extracted: emptyExtracted() },
    );
    expect(run.findings).toHaveLength(1);
    expect(run.findings[0]!.explanation.toLowerCase()).toContain("one-way");
  });

  it("is unevaluable when no clause of that category is present", async () => {
    const run = await runCustomPlaybook(
      pb({
        custom_rules: [
          { id: "R1", title: "Mutual termination", description: "d", severity: "warning", assert: { kind: "clause_mutual", clause: "termination" } },
        ],
      }),
      { tree: tree("Payment", "Fees are due net 30."), extracted: emptyExtracted() },
    );
    expect(run.findings).toHaveLength(0);
    expect(run.unevaluable[0]!.reason).toContain("termination");
  });

  it("honors an explicit pattern override for the clause location", async () => {
    const run = await runCustomPlaybook(
      pb({
        custom_rules: [
          { id: "R1", title: "Mutual confidentiality", description: "d", severity: "warning", assert: { kind: "clause_mutual", clause: "confidentiality", pattern: "non-disclosure" } },
        ],
      }),
      { tree: tree("NDA", "The non-disclosure obligations are mutual and bind both parties equally."), extracted: emptyExtracted() },
    );
    expect(run.findings).toHaveLength(0);
    expect(run.unevaluable).toHaveLength(0);
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

// --- ladder fingerprint (spec-v15) ------------------------------------------

describe("ladderHash — playbook ladder fingerprint", () => {
  const POS = [
    {
      dimension: "Liability cap",
      ideal: { kind: "numeric_threshold", metric: "liability_cap_multiple", comparator: "gte", value: 2 },
      acceptable: { kind: "numeric_threshold", metric: "liability_cap_multiple", comparator: "gte", value: 1 },
      guidance: { ideal: "Push for 2x.", acceptable: "1x floor.", walk_away: "Below 1x, walk." },
    },
    {
      dimension: "Governing law",
      ideal: { kind: "governing_law_in", allowed: ["Delaware"] },
      acceptable: { kind: "governing_law_in", allowed: ["Delaware", "New York"] },
    },
  ] as const;

  it("returns null for a playbook with no negotiation positions", async () => {
    expect(await ladderHash(pb())).toBeNull();
  });

  it("is a stable 64-hex fingerprint, independent of position order", async () => {
    const a = await ladderHash(pb({ negotiation_positions: POS as never }));
    const reordered = await ladderHash(pb({ negotiation_positions: [POS[1], POS[0]] as never }));
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(a).toBe(reordered);
  });

  it("ignores per-tier guidance (advisory text never changes ladder identity)", async () => {
    const withGuidance = await ladderHash(pb({ negotiation_positions: POS as never }));
    const stripped = JSON.parse(JSON.stringify(POS)).map((p: Record<string, unknown>) => {
      delete p.guidance;
      return p;
    });
    const without = await ladderHash(pb({ negotiation_positions: stripped as never }));
    expect(withGuidance).toBe(without);
  });

  it("changes when a tier predicate or a referenced threshold changes", async () => {
    const base = await ladderHash(pb({ negotiation_positions: POS as never }));
    const looser = [
      { ...POS[0], acceptable: { kind: "numeric_threshold", metric: "liability_cap_multiple", comparator: "gte", value: 0.5 } },
      POS[1],
    ];
    expect(await ladderHash(pb({ negotiation_positions: looser as never }))).not.toBe(base);

    const withThresholds = await ladderHash(
      pb({ negotiation_positions: POS as never, thresholds: { liability_cap_multiple: 2 } }),
    );
    expect(withThresholds).not.toBe(base);
  });
});
