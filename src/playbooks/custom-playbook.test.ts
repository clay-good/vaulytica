import { describe, expect, it } from "vitest";
import {
  validateCustomPlaybook,
  parseCustomPlaybookJson,
  CUSTOM_PLAYBOOK_SCHEMA_VERSION,
  type CustomPlaybook,
} from "./custom-playbook.js";

/** A minimal, valid augment-mode playbook. */
function minimal(overrides: Partial<CustomPlaybook> = {}): unknown {
  return {
    schema_version: CUSTOM_PLAYBOOK_SCHEMA_VERSION,
    catalog_version: "0.1.0",
    id: "acme-saas-buyer",
    name: "Acme SaaS Buyer Standard",
    description: "Acme's negotiation positions for inbound SaaS agreements.",
    ...overrides,
  };
}

describe("validateCustomPlaybook — happy path", () => {
  it("accepts a minimal playbook", () => {
    const r = validateCustomPlaybook(minimal());
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.playbook.id).toBe("acme-saas-buyer");
  });

  it("accepts the full surface: selection, overrides, thresholds, required clauses, custom rules", () => {
    const r = validateCustomPlaybook(
      minimal({
        mode: "augment",
        rule_selection: { include: ["LIMIT-001"], exclude: ["INFO-009"] },
        rule_overrides: { "LIMIT-001": { severity: "critical" }, "INFO-009": { skip: true } },
        thresholds: { min_cap_multiple: 12, max_notice_days: 30 },
        required_clauses: [{ category: "limitation-of-liability", severity: "critical" }],
        custom_rules: [
          {
            id: "ACME-1",
            title: "Liability cap must be at least 12x fees",
            description: "We do not accept a cap below 12x trailing fees.",
            severity: "critical",
            assert: { kind: "numeric_threshold", metric: "liability_cap_multiple", comparator: "gte", value: 12 },
            citation: { reference: "Acme Contracting Policy §4.2", url: "https://example.com/policy" },
          },
          {
            id: "ACME-2",
            title: "Must define Confidential Information",
            description: "A defined Confidential Information term is required.",
            severity: "warning",
            assert: { kind: "defined_term_present", term: "Confidential Information" },
          },
          {
            id: "ACME-3",
            title: "No arbitration clause",
            description: "We strike mandatory arbitration.",
            severity: "warning",
            assert: { kind: "clause_absent", pattern: "arbitration" },
          },
          {
            id: "ACME-4",
            title: "Governing law must be DE or NY",
            description: "We accept only Delaware or New York governing law.",
            severity: "warning",
            assert: { kind: "governing_law_in", allowed: ["us-de", "us-ny"] },
          },
        ],
      }),
    );
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.playbook.custom_rules).toHaveLength(4);
  });

  it("accepts a citationless custom rule (marked uncited downstream, not rejected)", () => {
    const r = validateCustomPlaybook(
      minimal({
        custom_rules: [
          {
            id: "ACME-1",
            title: "Require a DPA",
            description: "Inbound contracts touching personal data need a DPA.",
            severity: "critical",
            assert: { kind: "clause_present", section_heading: "Data Processing" },
          },
        ],
      }),
    );
    expect(r.ok).toBe(true);
  });
});

describe("validateCustomPlaybook — rejections with readable errors", () => {
  it("rejects a wrong schema_version", () => {
    const r = validateCustomPlaybook(minimal({ schema_version: "9.9" as never }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.errors.join("\n")).toContain("schema_version");
  });

  it("rejects an unknown top-level key (strict)", () => {
    const r = validateCustomPlaybook({ ...(minimal() as object), surprise: true });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.errors.join("\n")).toMatch(/Unrecognized key|surprise/);
  });

  it("rejects an unknown numeric metric (bounded DSL)", () => {
    const r = validateCustomPlaybook(
      minimal({
        custom_rules: [
          {
            id: "X",
            title: "t",
            description: "d",
            severity: "info",
            // @ts-expect-error — exercising the runtime guard
            assert: { kind: "numeric_threshold", metric: "moon_phase", comparator: "gte", value: 1 },
          },
        ],
      }),
    );
    expect(r.ok).toBe(false);
  });

  it("rejects a clause predicate with neither pattern nor section_heading", () => {
    const r = validateCustomPlaybook(
      minimal({
        custom_rules: [
          {
            id: "X",
            title: "t",
            description: "d",
            severity: "info",
            assert: { kind: "clause_present" },
          },
        ],
      }),
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.errors.join("\n")).toContain("pattern");
  });

  it("rejects duplicate custom_rule ids", () => {
    const dup = {
      id: "DUP",
      title: "t",
      description: "d",
      severity: "info" as const,
      assert: { kind: "defined_term_present" as const, term: "Foo" },
    };
    const r = validateCustomPlaybook(minimal({ custom_rules: [dup, { ...dup }] }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.errors.join("\n")).toContain('duplicate custom_rule id "DUP"');
  });

  it("rejects a replace-mode playbook that checks nothing", () => {
    const r = validateCustomPlaybook(minimal({ mode: "replace" }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.errors.join("\n")).toContain("replace-mode");
  });

  it("accepts a replace-mode playbook that defines positions", () => {
    const r = validateCustomPlaybook(
      minimal({
        mode: "replace",
        required_clauses: [{ category: "limitation-of-liability", severity: "critical" }],
      }),
    );
    expect(r.ok).toBe(true);
  });

  it("rejects a missing required field with a pathed message", () => {
    const r = validateCustomPlaybook({ schema_version: CUSTOM_PLAYBOOK_SCHEMA_VERSION });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.errors.some((e) => e.startsWith("catalog_version:"))).toBe(true);
      expect(r.errors.some((e) => e.startsWith("id:"))).toBe(true);
      // errors are sorted for stable display
      expect([...r.errors]).toEqual([...r.errors].sort((a, b) => a.localeCompare(b)));
    }
  });
});

describe("parseCustomPlaybookJson", () => {
  it("parses a valid JSON string", () => {
    const r = parseCustomPlaybookJson(JSON.stringify(minimal()));
    expect(r.ok).toBe(true);
  });

  it("reports a JSON syntax error as a readable validation error, not a throw", () => {
    const r = parseCustomPlaybookJson("{ not valid json ");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.errors[0]).toContain("not valid JSON");
  });
});
