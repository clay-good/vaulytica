/**
 * v4 fetcher framework tests (spec-v4.md §13 / Step 60).
 *
 * Three layers of coverage:
 *   1. Catalog — every Step-60 fetcher is registered.
 *   2. Parsers — each `parse*` helper extracts the expected nodes from
 *      a representative vendored snapshot.
 *   3. Staleness gate — the v3 detector accepts v4-emitted nodes and
 *      flags drift when the snapshot diverges from the pinned hash.
 */

import { describe, expect, it } from "vitest";

import {
  AIA_CONTRACTS_URL,
  DGCL_URL,
  FRCP_URL,
  FRE_URL,
  MBCA_URL,
  NVCA_MODEL_DOCS_URL,
  PROCEDURAL_SOURCES,
  STATE_LANDLORD_TENANT_SOURCES,
  STATE_TRUST_WILL_SOURCES,
  UCC_ARTICLE_2_URL,
  UCC_ARTICLE_3_URL,
  UCC_ARTICLE_9_URL,
  UCC_SOURCES,
  V4_FETCHERS,
  V4_FETCHER_IDS,
  V4_SOURCE_URLS,
  createV4FsReader,
  parseAiaCatalog,
  parseDgcl,
  parseMbca,
  parseNvcaIndex,
  parseProceduralRule,
  parseStateLandlordTenant,
  parseStateTrustWill,
  parseUccArticle,
} from "../../../../dkb/build/v4/fetchers/index.js";
import { detectStaleness, sha256Hex } from "../../../../dkb/build/v3/staleness.js";
import { V3DkbNodeListSchema } from "../../../../src/dkb/v3/schema.js";

const REPO_ROOT = process.cwd();
const NOW = "2026-05-17T00:00:00Z";

describe("v4 fetcher catalog", () => {
  it("registers every Step-60 fetcher under its source_id", () => {
    expect(V4_FETCHER_IDS).toEqual(
      [
        "aia",
        "ca-landlord-tenant",
        "ca-trust-will",
        "dgcl",
        "fl-landlord-tenant",
        "fl-trust-will",
        "frcp",
        "fre",
        "il-landlord-tenant",
        "il-trust-will",
        "mbca",
        "nvca",
        "ny-landlord-tenant",
        "ny-trust-will",
        "tx-landlord-tenant",
        "tx-trust-will",
        "ucc-article-2",
        "ucc-article-3",
        "ucc-article-9",
      ].sort(),
    );
  });

  it("exposes a URL for every registered fetcher", () => {
    for (const id of V4_FETCHER_IDS) {
      expect(V4_SOURCE_URLS[id], `missing URL for ${id}`).toBeTruthy();
    }
  });
});

describe("parsers", () => {
  it("parseNvcaIndex emits one model-form node per NVCA template", () => {
    const nodes = parseNvcaIndex("NVCA Model Legal Documents catalog page", NOW);
    expect(nodes.length).toBe(6);
    expect(nodes.every((n) => n.node_type === "regulator_model_form")).toBe(true);
    expect(nodes.every((n) => n.cites[0]!.source_url === NVCA_MODEL_DOCS_URL)).toBe(true);
  });

  it("parseDgcl extracts every requirement when the snapshot includes all anchors", () => {
    const snapshot = `certificate of incorporation registered office authorized stock
      bylaws adopt amend repeal
      board of directors managed by or under the direction
      annual meeting of stockholders
      agreement of merger plan of merger § 251
      appraisal rights § 262`;
    const nodes = parseDgcl(snapshot, NOW);
    expect(nodes.map((n) => n.id)).toContain("dgcl-251-merger-consolidation");
    expect(nodes.length).toBeGreaterThanOrEqual(5);
    expect(nodes.every((n) => n.cites[0]!.source_url === DGCL_URL)).toBe(true);
  });

  it("parseMbca emits zero nodes when the snapshot is unrelated text", () => {
    expect(parseMbca("unrelated marketing copy", NOW)).toEqual([]);
  });

  it("parseUccArticle is article-scoped (does not over-fire across articles)", () => {
    const article2 = UCC_SOURCES["ucc-article-2"]!;
    const nodes = parseUccArticle(
      // @ts-expect-error narrow shape OK for the test
      article2,
      "statute of frauds writing signed merchantability disclaim",
      NOW,
    );
    expect(nodes.length).toBeGreaterThan(0);
    expect(nodes.every((n) => n.citation.startsWith("U.C.C. § 2-"))).toBe(true);
  });

  it("parseAiaCatalog requires the AIA index keyword to fire", () => {
    expect(parseAiaCatalog("unrelated text", NOW)).toEqual([]);
    expect(parseAiaCatalog("AIA Contract Documents A201", NOW).length).toBe(6);
  });

  it("parseProceduralRule covers FRCP 37(e) and FRE 408", () => {
    const frcp = PROCEDURAL_SOURCES["frcp"]!;
    const fre = PROCEDURAL_SOURCES["fre"]!;
    expect(
      parseProceduralRule(
        // @ts-expect-error narrow shape OK
        frcp,
        "rule 37(e) spoliation litigation hold rule 41 voluntary dismissal",
        NOW,
      ).length,
    ).toBe(2);
    expect(
      // @ts-expect-error narrow shape OK
      parseProceduralRule(fre, "rule 408 settlement negotiation rule 502 privilege waiver", NOW)
        .length,
    ).toBe(2);
  });

  it("parseStateLandlordTenant fires CA-specific requirements", () => {
    const ca = STATE_LANDLORD_TENANT_SOURCES["ca"]!;
    const nodes = parseStateLandlordTenant(
      ca,
      "security deposit Cal. Civ. § 1950.5 return 21 days warranty of habitability repair and deduct",
      NOW,
    );
    expect(nodes.map((n) => n.id)).toEqual(
      expect.arrayContaining(["ca-civ-1950.5-security-deposit", "ca-civ-1942-habitability"]),
    );
  });

  it("parseStateTrustWill enforces witness-formality requirements", () => {
    const tx = STATE_TRUST_WILL_SOURCES["tx"]!;
    const nodes = parseStateTrustWill(
      tx,
      "§ 251.051 credible witnesses at least 14 subscribe their names",
      NOW,
    );
    expect(nodes.length).toBe(1);
    expect(nodes[0]!.applies_to_document_types).toContain("will");
  });
});

describe("end-to-end fetcher runs against vendored snapshots", () => {
  const reader = createV4FsReader(REPO_ROOT);

  it.each(Object.keys(V4_FETCHERS).sort())(
    "%s — runs from snapshot and emits schema-valid v3 nodes",
    async (id) => {
      const fetcher = V4_FETCHERS[id]!;
      const result = await fetcher({
        source_id: id,
        nowIso: NOW,
        reader,
        repoRoot: REPO_ROOT,
      });
      expect(result.source_id).toBe(id);
      expect(result.nodes.length).toBeGreaterThan(0);
      // Each fetcher's nodes must validate against the v3 schema (spec-v4.md §12).
      expect(() => V3DkbNodeListSchema.parse(result.nodes)).not.toThrow();
    },
  );
});

describe("staleness gate covers v4 nodes", () => {
  const reader = createV4FsReader(REPO_ROOT);

  it("clean run reports zero stale citations when the snapshot matches the pin", async () => {
    const result = await V4_FETCHERS["dgcl"]!({
      source_id: "dgcl",
      nowIso: NOW,
      reader,
      repoRoot: REPO_ROOT,
    });
    const snapshot = reader.read(DGCL_URL)!;
    const report = await detectStaleness({
      nodes: result.nodes,
      fetchAuthority: async () => ({ text: snapshot, fetched_at: NOW }),
      nowIso: NOW,
    });
    expect(report.stale_citations).toBe(0);
    expect(report.stale_nodes).toBe(0);
    expect(report.total_nodes).toBe(result.nodes.length);
  });

  it("drifted authority text fires the staleness gate", async () => {
    const result = await V4_FETCHERS["ucc-article-2"]!({
      source_id: "ucc-article-2",
      nowIso: NOW,
      reader,
      repoRoot: REPO_ROOT,
    });
    const drifted =
      (reader.read(UCC_ARTICLE_2_URL) ?? "") + "\nDRIFT — Amendment adopted 2026-05-17.";
    const report = await detectStaleness({
      nodes: result.nodes,
      fetchAuthority: async () => ({ text: drifted, fetched_at: NOW }),
      nowIso: NOW,
    });
    expect(report.stale_citations).toBeGreaterThan(0);
    expect(report.stale_nodes).toBe(result.nodes.length);
    expect(sha256Hex(drifted)).not.toBe(result.nodes[0]!.cites[0]!.content_hash_at_pin);
  });
});

// Confirm every URL constant is referenced (guards against accidental drift).
void [UCC_ARTICLE_3_URL, UCC_ARTICLE_9_URL, MBCA_URL, FRCP_URL, FRE_URL, AIA_CONTRACTS_URL];
