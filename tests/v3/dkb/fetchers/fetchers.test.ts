import { describe, expect, it } from "vitest";

import {
  HHS_OCR_INDEX_URL,
  HHS_SAMPLE_BAA_URL,
  HIPAA_TITLE_45_URL,
  STATE_PRIVACY_SOURCES,
  V3_FETCHERS,
  V3_FETCHER_IDS,
  createFsReader,
  parseHipaaSnapshot,
  parseHhsSampleBaa,
  parseOcrIndex,
  parseStatePrivacy,
} from "../../../../dkb/build/v3/fetchers/index.js";
import { V3DkbNodeListSchema } from "../../../../src/dkb/v3/schema.js";

const REPO_ROOT = process.cwd();
const NOW = "2026-05-12T00:00:00Z";

describe("v3 fetcher catalog", () => {
  it("registers every Step-21 fetcher", () => {
    expect(V3_FETCHER_IDS).toEqual(
      [
        "ccpa-civ-code",
        "ccpa-regulations-11ccr",
        "cpa",
        "ctdpa",
        "dpdpa",
        "hhs-ocr-resolutions",
        "hhs-sample-baa",
        "hipaa-ecfr-title-45",
        "ocpa",
        "tdpsa",
        "ucpa",
        "vcdpa",
      ].sort(),
    );
  });
});

describe("parseHipaaSnapshot", () => {
  it("extracts the §164.504(e)(2) BAA requirements from a representative excerpt", () => {
    const text = `establish the permitted and required uses and disclosures
      Business Associate shall report to Covered Entity any use or disclosure not provided for
      Business Associate shall ensure that any subcontractor agrees to the same restrictions
      in no case later than 60 calendar days after discovery
      satisfactory assurances that the business associate will appropriately safeguard
      shall comply, where applicable, with the Security Rule`;
    const nodes = parseHipaaSnapshot(text, NOW);
    expect(nodes).toHaveLength(6);
    expect(nodes.every((n) => n.node_type === "statutory_clause_requirement")).toBe(true);
    expect(nodes.every((n) => n.cites[0]!.source_url === HIPAA_TITLE_45_URL)).toBe(true);
  });

  it("returns nothing when text has no matches", () => {
    expect(parseHipaaSnapshot("some unrelated paragraph", NOW)).toEqual([]);
  });
});

describe("parseHhsSampleBaa", () => {
  it("emits a regulator_model_form node with one clause per heading", () => {
    const html =
      "<html><h2>Permitted Uses and Disclosures</h2><h2>Reporting of Improper Use or Disclosure</h2><h2>Subcontractors</h2></html>";
    const node = parseHhsSampleBaa(html, NOW);
    expect(node.node_type).toBe("regulator_model_form");
    expect(node.clauses.length).toBeGreaterThanOrEqual(3);
    expect(node.cites[0]!.source_url).toBe(HHS_SAMPLE_BAA_URL);
  });
});

describe("parseOcrIndex", () => {
  it("extracts year-prefixed entries as clauses", () => {
    const html = `<a href="x">2024 Settlement</a><a href="y">2023 Resolution Agreement</a>`;
    const node = parseOcrIndex(html, NOW);
    expect(node.clauses.length).toBeGreaterThanOrEqual(2);
    expect(node.cites[0]!.source_url).toBe(HHS_OCR_INDEX_URL);
  });
});

describe("parseStatePrivacy", () => {
  it("emits processor-contract nodes for VCDPA when the text matches", () => {
    const va = STATE_PRIVACY_SOURCES.va!;
    const text =
      "A contract between a controller and a processor shall govern... duty of confidentiality... delete or return... subcontractor pursuant to a written contract.";
    const nodes = parseStatePrivacy(va, text, NOW);
    expect(nodes.length).toBeGreaterThan(0);
    expect(nodes[0]!.applies_to_document_types).toEqual(["DPA"]);
    expect(nodes[0]!.cites[0]!.source_url).toBe(va.source_url);
  });

  it("returns nothing when none of the requirement regexes match", () => {
    const va = STATE_PRIVACY_SOURCES.va!;
    expect(parseStatePrivacy(va, "completely unrelated text", NOW)).toEqual([]);
  });
});

describe("integration: every fetcher runs offline against vendored snapshots", () => {
  const reader = createFsReader(REPO_ROOT);

  for (const id of V3_FETCHER_IDS) {
    it(`fetcher ${id} produces v3-schema-valid nodes`, async () => {
      const fetcher = V3_FETCHERS[id]!;
      const result = await fetcher({
        source_id: id,
        nowIso: NOW,
        reader,
        repoRoot: REPO_ROOT,
      });
      expect(result.source_id).toBe(id);
      expect(result.nodes.length).toBeGreaterThan(0);
      expect(() => V3DkbNodeListSchema.parse(result.nodes)).not.toThrow();
      for (const n of result.nodes) {
        expect(n.cites.length).toBeGreaterThan(0);
        expect(n.cites[0]!.content_hash_at_pin).toMatch(/^[0-9a-f]{64}$/);
      }
    });
  }
});

describe("offline-mode safety", () => {
  it("throws a helpful error when the snapshot is missing", async () => {
    const fetcher = V3_FETCHERS["hipaa-ecfr-title-45"]!;
    await expect(
      fetcher({
        source_id: "hipaa-ecfr-title-45",
        nowIso: NOW,
        reader: { read: () => undefined },
        repoRoot: REPO_ROOT,
      }),
    ).rejects.toThrow(/missing snapshot/);
  });
});
