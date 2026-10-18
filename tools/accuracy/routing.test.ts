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

describe("the label table, against the router", () => {
  /**
   * Each labelled title, as the title of a document with almost no body. Not
   * the measurement — a real exhibit has a body — but the cheapest check that
   * a label names a type the router can reach from that title at all.
   *
   * Measured on 9.886.0: 14 of 21 route to the labelled type. The other seven
   * fall to the fallback, for two reasons, both deliberate:
   *
   *   - FIVE are titles two types both claim ("employment agreement",
   *     "separation agreement", "indemnification agreement", "credit
   *     agreement") or that only a shorter keyword reaches ("stock option
   *     agreement"). A shared name earns nobody the title credit — the body is
   *     meant to break the tie (`longestOpeningKeyword`) — so a body-less
   *     document stays unmatched, and the fallback names the closest type.
   *   - TWO are bare nouns no type claims alone ("lease", "license
   *     agreement"): which lease, which license, is in the body.
   *
   * The first EDGAR sample (9.939.0) added six more, for a third reason: the
   * name EDGAR filers use is not one the type lists. A bare "WARRANT", a
   * "SECURITIES PURCHASE AGREEMENT", a "Restricted Stock Award", a "Cash Award
   * Notice", a "CO-DEVELOPMENT AND LICENSE AGREEMENT", and — though the type
   * lists it — a "SUBSCRIPTION AGREEMENT", which a second type also claims.
   * These are router gaps the sample found, pinned here rather than tuned
   * away before the measurement that found them was published.
   *
   * Pinned so a label that stops reaching its type shows up here, and so a
   * title that starts reaching it is noticed and the list shortened.
   */
  const UNREACHED_WITHOUT_A_BODY = [
    "cash incentive award",
    "credit agreement",
    "development and license agreement",
    "employment agreement",
    "indemnification agreement",
    "lease",
    "license agreement",
    "restricted stock award agreement",
    "securities purchase agreement",
    "separation agreement",
    "stock option agreement",
    "subscription agreement",
    "warrant",
  ];

  /**
   * A title a type shares by NAME but not by substance. A "Federal Assignment
   * of Claims Agreement" assigns a government contract's payments to a lender
   * under the Assignment of Claims Act; `assignment-of-claim` reviews the
   * assignment of a legal claim or judgment (champerty, notice to the
   * obligor). On the title alone the router takes the name. Pinned so the
   * collision is visible; the measurement reports what the body does.
   */
  const NAMED_LIKE_ANOTHER_TYPE: Readonly<Record<string, string>> = {
    "assignment of claims agreement": "assignment-of-claim",
  };

  it("reaches the labelled type from the title alone, except where the title is shared or bare", async () => {
    const deps = await loadAccuracyDeps();
    const { analyzeText } = await import("../cli/api.js");
    const sample = await loadRoutingSample(CORPUS_DIR);
    const unreached: string[] = [];
    const wrong: string[] = [];
    for (const l of sample.labels.filter((x) => !x.no_family)) {
      const named = l.label.replace(/\b\w/g, (c) => c.toUpperCase());
      const text = `${l.label.toUpperCase()}\n\nThis ${named} is entered into as of March 2, 2026 between Alder Corporation, a Delaware corporation, and Birch Holdings LLC, a Delaware limited liability company.\n\n1. General. The parties agree to the terms set out below.\n`;
      const r = await analyzeText(text, "stub.txt", { deps });
      if (r.playbook_id === l.exact || l.acceptable.includes(r.playbook_id)) continue;
      if (r.playbook_id === "generic-fallback") unreached.push(l.label);
      else wrong.push(`${l.label} → ${r.playbook_id}`);
    }
    // A title never routes to a type the label does not accept.
    expect(wrong).toEqual([]);
    expect(unreached.sort()).toEqual(UNREACHED_WITHOUT_A_BODY);
  }, 120_000);

  it("gives a title with no type of its own no type", async () => {
    const deps = await loadAccuracyDeps();
    const { analyzeText } = await import("../cli/api.js");
    const sample = await loadRoutingSample(CORPUS_DIR);
    const none = sample.labels.filter((x) => x.no_family).map((x) => x.label);
    expect(none).toContain("registration rights agreement");
    for (const label of none) {
      const r = await analyzeText(
        `${label.toUpperCase()}\n\nThis document is entered into as of March 2, 2026 between Alder Corporation and Birch Holdings LLC.\n`,
        "stub.txt",
        { deps },
      );
      expect(r.playbook_id, label).toBe(NAMED_LIKE_ANOTHER_TYPE[label] ?? "generic-fallback");
    }
  }, 120_000);
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
