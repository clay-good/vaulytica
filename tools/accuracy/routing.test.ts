/**
 * Routing on public filings (spec-v53 §8): the record holds no text, the label
 * table names real types, and the five shares and their caveats are printed
 * whether or not there is a sample.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  loadRoutingSample,
  measureRouting,
  ROUTING_OUTCOMES,
  RoutingLabelTableSchema,
  RoutingRecordSchema,
  routingCaveats,
  routingOutcome,
  unknownLabelTargets,
  type RoutingLabel,
  type RoutingRecord,
} from "./routing.js";
import { CORPUS_DIR } from "./corpus.js";
import { parseCorpusManifest } from "./schema.js";
import { loadAccuracyDeps } from "./pipeline.js";
import { assembleScoreboard, renderScoreboardMarkdown } from "./scoreboard.js";

const rec = (over: Partial<RoutingRecord> = {}): RoutingRecord => ({
  accession: "0001193125-24-123456",
  exhibit_url: "https://www.sec.gov/Archives/edgar/data/1/000119312524123456/d1ex101.htm",
  retrieved_at: "2026-10-11",
  text_sha256: "a".repeat(64),
  title: "Master Services Agreement",
  label: "master services agreement",
  observed_route: "msa-general",
  ...over,
});
const LABELS: RoutingLabel[] = RoutingLabelTableSchema.parse([
  { label: "master services agreement", exact: "msa-general", acceptable: ["msa-customer-deep"] },
  { label: "indenture", no_family: true },
]);

describe("a routing record", () => {
  it("validates, and has nowhere to put the document's text", () => {
    expect(RoutingRecordSchema.parse(rec())).toEqual(rec());
    expect(() => RoutingRecordSchema.parse({ ...rec(), text: "WHEREAS…" })).toThrow();
    expect(() => RoutingRecordSchema.parse({ ...rec(), excerpt: "…" })).toThrow();
    expect(() => RoutingRecordSchema.parse({ ...rec(), title: "x".repeat(201) })).toThrow();
  });

  it("is read from sec.gov, by accession number and hash", () => {
    expect(() =>
      RoutingRecordSchema.parse(rec({ exhibit_url: "https://example.com/ex101.htm" })),
    ).toThrow();
    expect(() => RoutingRecordSchema.parse(rec({ accession: "123" }))).toThrow();
    expect(() => RoutingRecordSchema.parse(rec({ text_sha256: "abc" }))).toThrow();
  });
});

describe("the five shares", () => {
  it("classifies each record once", () => {
    const [msa, indenture] = LABELS as [RoutingLabel, RoutingLabel];
    expect(routingOutcome(rec(), msa)).toBe("exact");
    expect(routingOutcome(rec({ observed_route: "msa-customer-deep" }), msa)).toBe("acceptable");
    expect(routingOutcome(rec({ observed_route: "saas-customer" }), msa)).toBe("wrong");
    expect(routingOutcome(rec({ observed_route: "generic-fallback" }), msa)).toBe("fallback");
    // No type exists for the title: counted as that, wherever it went.
    expect(routingOutcome(rec({ observed_route: "generic-fallback" }), indenture)).toBe(
      "no_family",
    );
    expect(routingOutcome(rec({ observed_route: "loan-agreement" }), indenture)).toBe("no_family");
  });

  it("sums to the sample, keeps the no-type share, and counts per type", () => {
    const m = measureRouting(
      [
        rec(),
        rec({ observed_route: "msa-customer-deep" }),
        rec({ observed_route: "saas-customer" }),
        rec({ observed_route: "generic-fallback" }),
        rec({ label: "indenture", title: "Indenture", observed_route: "generic-fallback" }),
      ],
      LABELS,
      ["msa-general", "msa-customer-deep", "saas-customer", "loan-agreement"],
    );
    expect(m.n).toBe(5);
    expect(m.counts).toEqual({ exact: 1, acceptable: 1, wrong: 1, fallback: 1, no_family: 1 });
    expect(ROUTING_OUTCOMES.reduce((sum, o) => sum + (m.shares[o] ?? 0), 0)).toBeCloseTo(1, 10);
    expect(m.per_family).toEqual([
      {
        family: "msa-general",
        n: 4,
        counts: { exact: 1, acceptable: 1, wrong: 1, fallback: 1, no_family: 0 },
      },
    ]);
    expect(m.families_with_documents).toBe(1);
    expect(m.caveats[2]).toBe("Document types with zero real documents: 3 of 4.");
  });

  it("refuses a record whose label is not in the table", () => {
    expect(() => measureRouting([rec({ label: "nope" })], LABELS, [])).toThrow(/unknown label/);
  });

  it("prints all three caveats with no sample at all", () => {
    const m = measureRouting([], [], ["a", "b"]);
    expect(m.n).toBe(0);
    expect(m.shares.exact).toBeNull();
    expect(m.caveats).toEqual(routingCaveats(2, 2));
    expect(m.caveats[0]).toMatch(/upper bound/);
    expect(m.caveats[1]).toMatch(/says nothing about residential leases/);
  });
});

describe("the label table", () => {
  it("rejects a row that is both a type and no type, and duplicate keys", () => {
    expect(() =>
      RoutingLabelTableSchema.parse([{ label: "x", exact: "msa-general", no_family: true }]),
    ).toThrow();
    expect(() => RoutingLabelTableSchema.parse([{ label: "x" }])).toThrow();
    expect(() =>
      RoutingLabelTableSchema.parse([
        { label: "x", no_family: true },
        { label: "x", no_family: true },
      ]),
    ).toThrow();
  });

  it("as committed, names only types the catalog has", async () => {
    const deps = await loadAccuracyDeps();
    const catalog = [...deps.launchPlaybooks, ...deps.extendedPlaybooks].map((p) => p.id);
    const sample = await loadRoutingSample(CORPUS_DIR);
    expect(sample.labels.length).toBeGreaterThan(10);
    expect(unknownLabelTargets(sample.labels, catalog)).toEqual([]);
    // It reuses the tie the suite declares for a master services agreement.
    const msa = sample.labels.find((l) => l.label === "master services agreement")!;
    expect(msa.exact).toBe("msa-general");
    expect(msa.acceptable).toEqual(["msa-customer-deep", "msa-vendor-deep"]);
    // And every committed record, if any, is a valid one with a known label.
    const keys = new Set(sample.labels.map((l) => l.label));
    for (const r of sample.records) expect(keys.has(r.label), r.accession).toBe(true);
  });
});

describe("the manifest and the scoreboard", () => {
  it("accepts a routing split", () => {
    expect(
      parseCorpusManifest({ corpus_version: "v1", splits: { "edgar-0001": "routing" } }).splits,
    ).toEqual({ "edgar-0001": "routing" });
    expect(() => parseCorpusManifest({ corpus_version: "v1", splits: { x: "holdout" } })).toThrow();
  });

  it("prints the five shares and the caveats, sample or no sample", () => {
    const base = {
      corpus_version: "v0",
      dkb_version: "d",
      engine_version: "e",
      catalog: { rules: 1, playbooks: 2 },
      graded: [],
      kappa_pairs: [],
    };
    const empty = renderScoreboardMarkdown(assembleScoreboard(base));
    expect(empty).toContain("## Routing on public filings");
    expect(empty).toContain("No exhibits sampled yet");
    for (const row of [
      "The type its title names",
      "Another type accepted for that title",
      "A different type",
      "No type matched",
      "The catalog has no type for this title",
    ]) {
      expect(empty, row).toContain(`| ${row} |`);
    }
    expect(empty).toContain("upper bound");
    expect(empty).toContain("Document types with zero real documents");

    const some = renderScoreboardMarkdown(
      assembleScoreboard({
        ...base,
        routing: measureRouting([rec(), rec({ observed_route: "saas-customer" })], LABELS, [
          "msa-general",
          "saas-customer",
        ]),
      }),
    );
    expect(some).toContain("Of 2 EDGAR exhibits");
    expect(some).toContain("| The type its title names | 1 | 50.0% |");
    expect(some).toContain("| msa-general | 2 | 1 | 0 | 1 | 0 |");
    expect(some).not.toContain("No exhibits sampled yet");
  });

  it("the committed scoreboard carries the section", () => {
    const md = readFileSync(join(process.cwd(), "tools", "accuracy", "SCOREBOARD.md"), "utf8");
    expect(md).toContain("## Routing on public filings");
    expect(md).toMatch(/Document types with zero real documents: \d+ of \d+\./);
  });
});
