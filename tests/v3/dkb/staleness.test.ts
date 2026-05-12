import { describe, expect, it } from "vitest";

import {
  applyStalenessToRules,
  detectStaleness,
  normalizeForHash,
  sha256Hex,
  statusFromReport,
  unacknowledgedRows,
  type RuleNode,
} from "../../../dkb/build/v3/staleness.js";
import type { V3DkbNode } from "../../../src/dkb/v3/types.js";

const NOW = "2026-05-12T00:00:00Z";

const sampleAuthorityText = "Business Associate shall report any use or disclosure...";
const pinnedHash = sha256Hex(sampleAuthorityText);

const node = (over: Partial<V3DkbNode> = {}): V3DkbNode =>
  ({
    id: "hipaa-test-node",
    node_type: "statutory_clause_requirement",
    dkb_node_version: 1,
    dkb_node_last_validated_at: NOW,
    regulator: "HHS OCR",
    jurisdiction: "us-federal",
    authority: "45 C.F.R. § 164.504(e)(2)(ii)(C)",
    citation: "45 C.F.R. § 164.504(e)(2)(ii)(C)",
    effective_date: "2013-09-23",
    requirement: "BA must report unauthorized uses/disclosures.",
    minimum_compliant_text: "Business Associate shall report...",
    applies_to_document_types: ["BAA"],
    cites: [
      {
        authority: "45 C.F.R. § 164.504(e)(2)(ii)(C)",
        citation: "45 C.F.R. § 164.504(e)(2)(ii)(C)",
        source_url: "https://www.ecfr.gov/test",
        content_hash_at_pin: pinnedHash,
        fetched_at: NOW,
      },
    ],
    ...over,
  }) as V3DkbNode;

describe("normalizeForHash", () => {
  it("collapses whitespace and normalizes line endings", () => {
    expect(sha256Hex("a  b\r\nc")).toBe(sha256Hex("a b\nc"));
  });
  it("trims leading and trailing whitespace", () => {
    expect(normalizeForHash("   hello world   ")).toBe("hello world");
  });
});

describe("detectStaleness", () => {
  it("reports zero stale citations when hashes match", async () => {
    const report = await detectStaleness({
      nodes: [node()],
      fetchAuthority: async () => ({ text: sampleAuthorityText, fetched_at: NOW }),
      nowIso: NOW,
    });
    expect(report.stale_citations).toBe(0);
    expect(report.stale_nodes).toBe(0);
    expect(report.total_nodes).toBe(1);
  });

  it("flags a node when the authority text drifts", async () => {
    const report = await detectStaleness({
      nodes: [node()],
      fetchAuthority: async () => ({ text: `${sampleAuthorityText} (amended 2026)`, fetched_at: NOW }),
      nowIso: NOW,
    });
    expect(report.stale_citations).toBe(1);
    expect(report.stale_nodes).toBe(1);
    expect(report.rows[0]!.node_id).toBe("hipaa-test-node");
    expect(report.rows[0]!.fetched_hash).not.toBe(pinnedHash);
  });
});

describe("applyStalenessToRules", () => {
  it("disables rules that depend on a stale node", async () => {
    const report = await detectStaleness({
      nodes: [node()],
      fetchAuthority: async () => ({ text: "different content", fetched_at: NOW }),
      nowIso: NOW,
    });
    const rules: RuleNode[] = [
      { id: "BAA-001", enabled: true, depends_on_dkb_nodes: ["hipaa-test-node"] },
      { id: "BAA-002", enabled: true, depends_on_dkb_nodes: ["other-node"] },
    ];
    const { rules: next, disabled } = applyStalenessToRules(rules, report);
    expect(disabled).toEqual(["BAA-001"]);
    expect(next.find((r) => r.id === "BAA-001")!.enabled).toBe(false);
    expect(next.find((r) => r.id === "BAA-002")!.enabled).toBe(true);
  });
});

describe("unacknowledgedRows", () => {
  it("returns rows not present in the ack list", async () => {
    const report = await detectStaleness({
      nodes: [node()],
      fetchAuthority: async () => ({ text: "different content", fetched_at: NOW }),
      nowIso: NOW,
    });
    expect(unacknowledgedRows(report, [])).toHaveLength(1);
    expect(
      unacknowledgedRows(report, [
        {
          node_id: "hipaa-test-node",
          citation: "45 C.F.R. § 164.504(e)(2)(ii)(C)",
          ack: "renumbered, no substantive change",
        },
      ]),
    ).toHaveLength(0);
  });
});

describe("statusFromReport", () => {
  it("produces the UI footer payload", () => {
    const status = statusFromReport({
      generated_at: NOW,
      total_nodes: 5,
      stale_nodes: 1,
      stale_citations: 2,
      rows: [],
    });
    expect(status).toEqual({
      dkb_last_validated_at: NOW,
      stale_citations_pending_review: 2,
    });
  });
});
