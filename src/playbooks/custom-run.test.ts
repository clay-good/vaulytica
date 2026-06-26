import { describe, expect, it } from "vitest";
import {
  previewCustomPlaybook,
  selectBuiltinRuleIds,
  runWithCustomPlaybook,
  RULE_CATALOG_VERSION,
} from "./custom-run.js";
import { validateCustomPlaybook, type CustomPlaybook } from "./custom-playbook.js";
import type { Finding, Rule } from "../engine/finding.js";
import type { DocumentTree } from "../ingest/types.js";
import type { ExtractedData } from "../extract/types.js";
import { loadStarterDkbSync, GENERIC_PLAYBOOK } from "../engine/_test-fixtures.js";

// --- fixtures ---------------------------------------------------------------

const CATALOG = ["AAA-001", "BBB-002", "CCC-003"] as const;

function fakeRule(id: string, fires: boolean): Rule {
  const finding: Finding = {
    id: `${id}-f`,
    rule_id: id,
    rule_version: "1.0.0",
    severity: "warning",
    title: `${id} title`,
    description: `${id} desc`,
    excerpt: { text: "", start_offset: 0, end_offset: 0 },
    explanation: `${id} explanation`,
    source_citations: [],
    document_position: 0,
  };
  return {
    id,
    version: "1.0.0",
    name: id,
    category: "test",
    default_severity: "warning",
    description: id,
    dkb_citations: [],
    check: () => (fires ? { ...finding } : null),
  };
}

const RULES: readonly Rule[] = [
  fakeRule("AAA-001", true),
  fakeRule("BBB-002", true),
  fakeRule("CCC-003", false),
];

function tree(heading: string, body: string): DocumentTree {
  return {
    type: "document",
    sections: [
      {
        id: "s1",
        heading,
        level: 1,
        paragraphs: [
          { id: "s1.p1", runs: [{ id: "s1.p1.r0", text: body, start: 0, end: body.length }] },
        ],
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
  const base: CustomPlaybook = {
    schema_version: "1.0",
    catalog_version: RULE_CATALOG_VERSION,
    id: "team-standard",
    name: "Team Standard",
    description: "A team standard.",
    ...over,
  };
  // Round-trip through the validator so tests exercise the same shape the UI does.
  const result = validateCustomPlaybook(base);
  if (!result.ok) throw new Error(`fixture invalid: ${result.errors.join("; ")}`);
  return result.playbook;
}

// --- selectBuiltinRuleIds ---------------------------------------------------

describe("selectBuiltinRuleIds", () => {
  it("augment with no selection keeps the whole catalog", () => {
    expect(selectBuiltinRuleIds(pb(), CATALOG)).toEqual([...CATALOG]);
  });

  it("include narrows to the listed ids (catalog order preserved)", () => {
    const got = selectBuiltinRuleIds(
      pb({ rule_selection: { include: ["CCC-003", "AAA-001"] } }),
      CATALOG,
    );
    expect(got).toEqual(["AAA-001", "CCC-003"]);
  });

  it("exclude drops the listed ids", () => {
    expect(selectBuiltinRuleIds(pb({ rule_selection: { exclude: ["BBB-002"] } }), CATALOG)).toEqual(
      ["AAA-001", "CCC-003"],
    );
  });

  it("rule_overrides skip drops the rule too", () => {
    expect(
      selectBuiltinRuleIds(pb({ rule_overrides: { "AAA-001": { skip: true } } }), CATALOG),
    ).toEqual(["BBB-002", "CCC-003"]);
  });

  it("replace mode selects nothing from the catalog", () => {
    const p = pb({ mode: "replace", required_clauses: [{ category: "x", severity: "info" }] });
    expect(selectBuiltinRuleIds(p, CATALOG)).toEqual([]);
  });
});

// --- previewCustomPlaybook --------------------------------------------------

describe("previewCustomPlaybook", () => {
  it("reports selected + excluded counts for augment mode", () => {
    const preview = previewCustomPlaybook(pb({ rule_selection: { exclude: ["BBB-002"] } }), {
      rule_ids: CATALOG,
    });
    expect(preview.mode).toBe("augment");
    expect(preview.selected_builtin_rule_ids).toEqual(["AAA-001", "CCC-003"]);
    expect(preview.excluded_builtin_count).toBe(1);
  });

  it("excludes the entire catalog in replace mode", () => {
    const p = pb({ mode: "replace", required_clauses: [{ category: "x", severity: "info" }] });
    const preview = previewCustomPlaybook(p, { rule_ids: CATALOG });
    expect(preview.selected_builtin_rule_ids).toEqual([]);
    expect(preview.excluded_builtin_count).toBe(CATALOG.length);
  });

  it("flags unknown selection + override ids", () => {
    const preview = previewCustomPlaybook(
      pb({
        rule_selection: { include: ["AAA-001", "NOPE-999"] },
        rule_overrides: { "ALSO-MISSING": { severity: "info" } },
      }),
      { rule_ids: CATALOG },
    );
    expect(preview.unknown_selection_rule_ids).toEqual(["NOPE-999"]);
    expect(preview.unknown_override_rule_ids).toEqual(["ALSO-MISSING"]);
  });

  it("lists uncited custom rules and a catalog-version mismatch", () => {
    const preview = previewCustomPlaybook(
      pb({
        catalog_version: "0.0.1-ancient",
        custom_rules: [
          {
            id: "T-1",
            title: "t1",
            description: "d1",
            severity: "warning",
            assert: { kind: "clause_absent", pattern: "arbitration" },
          },
          {
            id: "T-2",
            title: "t2",
            description: "d2",
            severity: "info",
            assert: { kind: "defined_term_present", term: "Confidential Information" },
            citation: { reference: "Policy §1" },
          },
        ],
      }),
      { rule_ids: CATALOG, version: RULE_CATALOG_VERSION },
    );
    expect(preview.custom_rule_count).toBe(2);
    expect(preview.uncited_custom_rule_ids).toEqual(["T-1"]);
    expect(preview.catalog_version_mismatch).toBe(true);
  });
});

// --- runWithCustomPlaybook --------------------------------------------------

const dkb = loadStarterDkbSync();
const sourceFile = { name: "doc.pdf", sha256: "abc", size_bytes: 10 };

function baseInput(custom: CustomPlaybook): Parameters<typeof runWithCustomPlaybook>[0] {
  return {
    rules: RULES,
    matched_playbook: GENERIC_PLAYBOOK,
    custom_playbook: custom,
    tree: tree("Agreement", "This agreement contains an arbitration clause."),
    extracted: emptyExtracted(),
    dkb,
    source_file: sourceFile,
    executed_at: "",
  };
}

describe("runWithCustomPlaybook", () => {
  it("augment merges built-in (catalog) and custom (custom-playbook) findings", async () => {
    const custom = pb({
      custom_rules: [
        {
          id: "TEAM-NO-ARB",
          title: "No arbitration",
          description: "We strike arbitration.",
          severity: "critical",
          assert: { kind: "clause_absent", pattern: "arbitration" },
        },
      ],
    });
    const result = await runWithCustomPlaybook(baseInput(custom));

    // Built-ins AAA-001 + BBB-002 fire (CCC-003 does not); custom rule fires.
    expect(result.builtin_finding_count).toBe(2);
    expect(result.custom_finding_count).toBe(1);

    const sources = result.run.findings.map((f) => f.source);
    expect(sources.filter((s) => s === "catalog")).toHaveLength(2);
    expect(sources.filter((s) => s === "custom-playbook")).toHaveLength(1);

    // The custom critical sorts ahead of the built-in warnings.
    expect(result.run.findings[0]!.rule_id).toBe("TEAM-NO-ARB");
  });

  it("replace mode drops the built-in catalog entirely", async () => {
    const custom = pb({
      mode: "replace",
      custom_rules: [
        {
          id: "TEAM-NO-ARB",
          title: "No arbitration",
          description: "We strike arbitration.",
          severity: "critical",
          assert: { kind: "clause_absent", pattern: "arbitration" },
        },
      ],
    });
    const result = await runWithCustomPlaybook(baseInput(custom));
    expect(result.builtin_finding_count).toBe(0);
    expect(result.custom_finding_count).toBe(1);
    expect(result.run.findings).toHaveLength(1);
    expect(result.run.findings[0]!.source).toBe("custom-playbook");
  });

  it("is deterministic — two runs produce the same result_hash", async () => {
    const custom = pb({
      custom_rules: [
        {
          id: "TEAM-NO-ARB",
          title: "No arbitration",
          description: "We strike arbitration.",
          severity: "critical",
          assert: { kind: "clause_absent", pattern: "arbitration" },
        },
      ],
    });
    const a = await runWithCustomPlaybook(baseInput(custom));
    const b = await runWithCustomPlaybook(baseInput(custom));
    expect(a.run.result_hash).toBe(b.run.result_hash);
    expect(a.run.result_hash).not.toBe("");
  });

  it("a severity override changes the built-in finding severity", async () => {
    const custom = pb({ rule_overrides: { "AAA-001": { severity: "critical" } } });
    const result = await runWithCustomPlaybook(baseInput(custom));
    const aaa = result.run.findings.find((f) => f.rule_id === "AAA-001");
    expect(aaa?.severity).toBe("critical");
  });
});
