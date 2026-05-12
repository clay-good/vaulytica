import { describe, expect, it } from "vitest";

import {
  GDPR_URL,
  HHS_OCR_INDEX_URL,
  HHS_SAMPLE_BAA_URL,
  HIPAA_TITLE_45_URL,
  INTL_SOURCES,
  STATE_PRIVACY_SOURCES,
  UK_ADDENDUM_URL,
  V3_FETCHERS,
  V3_FETCHER_IDS,
  createFsReader,
  parseEdpbGuidelines,
  parseEuScc,
  parseGdpr,
  parseHipaaSnapshot,
  parseHhsSampleBaa,
  parseIntl,
  parseOcrIndex,
  parseStatePrivacy,
  parseSwissAddendum,
  parseSwissFadp,
  parseUkAddendum,
  parseUkGdpr,
  parseUkIdta,
} from "../../../../dkb/build/v3/fetchers/index.js";
import { V3DkbNodeListSchema } from "../../../../src/dkb/v3/schema.js";

const REPO_ROOT = process.cwd();
const NOW = "2026-05-12T00:00:00Z";

describe("v3 fetcher catalog", () => {
  it("registers every Step-21 and Step-22 fetcher", () => {
    expect(V3_FETCHER_IDS).toEqual(
      [
        "appi",
        "ccpa-civ-code",
        "ccpa-regulations-11ccr",
        "cpa",
        "ctdpa",
        "dpdpa",
        "edpb-guidelines",
        "eu-scc-2021-914",
        "gdpr",
        "hhs-ocr-resolutions",
        "hhs-sample-baa",
        "hipaa-ecfr-title-45",
        "lgpd",
        "ocpa",
        "pipeda",
        "pipl",
        "swiss-addendum",
        "swiss-fadp",
        "tdpsa",
        "ucpa",
        "uk-addendum",
        "uk-gdpr",
        "uk-idta",
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

describe("parseGdpr", () => {
  it("emits the major DPA-relevant articles when the text references them", () => {
    const text =
      "Article 28 processor shall process; Article 32 technical and organisational measures; not later than 72 hours after; Article 44 third country; Article 46 appropriate safeguards; processor notify controller without undue delay.";
    const nodes = parseGdpr(text, "2026-05-12T00:00:00Z");
    expect(nodes.length).toBeGreaterThanOrEqual(5);
    expect(nodes.every((n) => n.cites[0]!.source_url === GDPR_URL)).toBe(true);
  });
});

describe("parseEuScc", () => {
  it("emits four module forms + four transfer-mechanism nodes when all four modules are present", () => {
    const text =
      "Module 1 Controller to Controller; Module 2 Controller to Processor; Module 3 Processor to Processor; Module 4 Processor to Controller.";
    const nodes = parseEuScc(text, "2026-05-12T00:00:00Z");
    expect(nodes.filter((n) => n.node_type === "regulator_model_form")).toHaveLength(4);
    expect(nodes.filter((n) => n.node_type === "transfer_mechanism")).toHaveLength(4);
    const m2 = nodes.find((n) => n.node_type === "transfer_mechanism" && n.id === "transfer-scc-module-2");
    expect(m2?.node_type).toBe("transfer_mechanism");
    if (m2 && m2.node_type === "transfer_mechanism") {
      expect(m2.required_ancillary_documents).toContain("Annex III (List of Sub-processors)");
    }
  });

  it("emits nothing when no module is mentioned", () => {
    expect(parseEuScc("unrelated text", "2026-05-12T00:00:00Z")).toEqual([]);
  });
});

describe("parseUkIdta and parseUkAddendum", () => {
  it("UK IDTA snapshot produces a regulator_model_form + transfer_mechanism", () => {
    const nodes = parseUkIdta(
      "Part 1 — Parties; Part 2 — Transfer Details; Part 3 — Security Measures; Part 4 — Mandatory Clauses.",
      "2026-05-12T00:00:00Z",
    );
    expect(nodes).toHaveLength(2);
    expect(nodes.find((n) => n.node_type === "transfer_mechanism")?.id).toBe("transfer-uk-idta");
  });

  it("UK Addendum snapshot produces a regulator_model_form + transfer_mechanism", () => {
    const nodes = parseUkAddendum(
      "Table 1 — Parties; Table 2 — Selected SCC Modules; Table 3 — Appendix Information; Table 4 — Ending This Addendum.",
      "2026-05-12T00:00:00Z",
    );
    expect(nodes.length).toBeGreaterThanOrEqual(2);
    expect(nodes[0]!.cites[0]!.source_url).toBe(UK_ADDENDUM_URL);
  });
});

describe("parseUkGdpr / parseSwissFadp / parseSwissAddendum / parseEdpbGuidelines", () => {
  it("emits a UK-GDPR Article-28 node", () => {
    const nodes = parseUkGdpr("Article 28 processor binding contract", "2026-05-12T00:00:00Z");
    expect(nodes).toHaveLength(1);
    expect(nodes[0]!.jurisdiction).toBe("uk");
  });

  it("emits a Swiss FADP Art. 9 node", () => {
    const nodes = parseSwissFadp("processor shall process FADP Article 7", "2026-05-12T00:00:00Z");
    expect(nodes).toHaveLength(1);
  });

  it("emits a Swiss Addendum form + transfer-mechanism", () => {
    const nodes = parseSwissAddendum(
      "Swiss FDPIC Addendum to the EU SCCs",
      "2026-05-12T00:00:00Z",
    );
    expect(nodes).toHaveLength(2);
  });

  it("EDPB index parses Guidelines NN/YYYY entries", () => {
    const node = parseEdpbGuidelines(
      "Guidelines 07/2020 on processors. Guidelines 05/2021 on Article 3.",
      "2026-05-12T00:00:00Z",
    );
    expect(node.clauses.length).toBeGreaterThanOrEqual(2);
  });
});

describe("parseIntl (PIPEDA / LGPD / APPI / PIPL)", () => {
  it("PIPL parser carries the translation provenance in the authority field", () => {
    const pipl = INTL_SOURCES.pipl!;
    const text = "Article 21 personal information handler entrusted; Article 38 cross-border outbound";
    const nodes = parseIntl(pipl, text, "2026-05-12T00:00:00Z");
    expect(nodes.length).toBeGreaterThanOrEqual(2);
    expect(nodes[0]!.authority).toContain("National People's Congress");
  });

  it("LGPD parser recognises operator language", () => {
    const lgpd = INTL_SOURCES.lgpd!;
    const nodes = parseIntl(lgpd, "Art. 39 operador tratamento instructions controller", "2026-05-12T00:00:00Z");
    expect(nodes).toHaveLength(1);
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
