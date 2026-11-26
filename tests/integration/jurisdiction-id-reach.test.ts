/**
 * `wire-jurisdiction-id-resolution` tasks 3–4, extended by `pin-the-docx-report` task 3 — the product fills
 * `jurisdiction_id`.
 *
 * 🚨 Why this guard exists at all. `extractAll` has always accepted a
 * `jurisdictionLookup`, and until this change NO caller in the product passed
 * one. `lookup` was the default `() => undefined`, so `jurisdiction_id` was
 * absent on every entry the product had ever produced: a DOCX column that
 * always printed "—", a `governing_law_in` playbook condition that compared
 * `allowed` ids against `undefined` and reported a compliant document
 * violated, and three separate re-implementations of the same normalization in
 * modules that gave up on reading the field.
 *
 * Nothing could notice, because an optional parameter left out compiles, runs,
 * and produces a plausible answer — "unknown" — for every document. That is
 * the shape this file guards: not whether the resolver is correct (its own
 * tests do that), but whether the product still ASKS it.
 *
 * Two halves, because either alone is weak. The static half reads the product's
 * `extractAll` call sites, so a THIRD pipeline added later without the lookup
 * fails even if the two existing ones stay wired. The runtime half drives the
 * real `prepareDocument` on a document naming a US state, so a call site that
 * passes a lookup which resolves nothing still fails.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

import {
  callSites,
  callSitesIn,
  committedOutputHelpers,
  harnessReasons,
  sourcesUnder,
  type CallSite,
} from "./_extract-all-sites.js";
import { prepareDocument, runReport } from "../../src/ui/pipeline.js";
import { runCustomPlaybook } from "../../src/playbooks/custom-interpreter.js";
import { validateCustomPlaybook } from "../../src/playbooks/custom-playbook.js";
import { buildDocxReport } from "../../src/report/docx.js";
import { resolveDkbDir } from "../../tools/dkb/resolve.js";

const ROOT = process.cwd();
const DKB_DIR = resolveDkbDir();
const PLAYBOOK_DIR = join(ROOT, "playbooks");

// Serve the browser pipeline's same-origin fetches from the artifact bytes on
// disk, the way `cross-surface-parity` does.
const realFetch = globalThis.fetch;
globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
  const url = String(input);
  const serve = (dir: string, name: string): Response => {
    try {
      return new Response(readFileSync(join(dir, name)), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    } catch {
      return new Response("not found", { status: 404 });
    }
  };
  if (url.startsWith("/x-dkb/"))
    return Promise.resolve(serve(DKB_DIR, url.slice("/x-dkb/".length)));
  if (url.startsWith("/x-playbooks/"))
    return Promise.resolve(serve(PLAYBOOK_DIR, url.slice("/x-playbooks/".length)));
  return realFetch(input, init);
}) as typeof fetch;
afterAll(() => {
  globalThis.fetch = realFetch;
});

/**
 * The walk and the scan live in `_extract-all-sites.ts`, shared with the
 * harness sweep below. One scanner, one answer.
 *
 * 🚨 `tools/` is in the product walk because leaving it out is the mistake this
 * guard was written to prevent, and it made it anyway. The first version scoped
 * to `src/`, went green on two wired call sites, and was reported as done —
 * while `tools/cli/artifacts.ts` built its own `extracted` with a bare
 * `extractAll` and handed it to `buildDocxReport`, so the CLI's report, the
 * surface agents and scripts use, still printed a dash in every id cell.
 *
 * The lesson is the s34 one: ask WHO can reach a surface. A guard that sweeps
 * the directory where you happened to make the fix proves you made the fix.
 */
const PRODUCT_ROOTS = ["src", "tools"] as const;
const HARNESS_ROOTS = ["tests", "tools"] as const;

function productCallSites(): CallSite[] {
  return callSites(
    ROOT,
    PRODUCT_ROOTS.flatMap((r) => sourcesUnder(ROOT, r, { includeTests: false })),
  );
}

describe("jurisdiction_id reach", () => {
  it("has product call sites to check (the guard is not vacuous)", () => {
    const sites = productCallSites();
    expect(sites.length).toBeGreaterThan(0);
    // Both of the browser pipelines, single-document and bundle...
    expect(sites.filter((s) => s.file === "src/ui/pipeline.ts").length).toBe(2);
    // ...and the headless surface, which the first version of this guard could
    // not see. A floor rather than an exact count: `tools/` call sites come and
    // go with the CLI's subcommands, and pinning the number would make this
    // fail for reasons that have nothing to do with the lookup.
    expect(sites.filter((s) => s.file.startsWith("tools/")).length).toBeGreaterThanOrEqual(10);
  });

  it("passes a jurisdiction lookup at every product extractAll call site", () => {
    const unwired = productCallSites()
      .filter((s) => !s.wired)
      .map((s) => s.file);
    expect(unwired).toEqual([]);
  });

  it("populates jurisdiction_id through the real pipeline", async () => {
    const text = [
      "SERVICES AGREEMENT",
      "",
      "1. Governing Law",
      "",
      "1.1 This Agreement is governed by and construed in accordance with the laws of the State of Delaware.",
      "",
      "2. Venue",
      "",
      "2.1 The parties submit to the exclusive jurisdiction of the courts located in Wilmington, Delaware.",
      "",
    ].join("\n");
    const file = new File([new TextEncoder().encode(text)], "services.txt");
    const prepared = await prepareDocument(file, "text", {
      dkb_base: "/x-dkb",
      playbook_base: "/x-playbooks",
    });

    const gov = prepared.extracted.jurisdictions.find((j) => j.clause_kind === "governing-law");
    expect(gov).toBeDefined();
    expect(gov!.jurisdiction_id).toBe("us-de");

    // 🚨 The venue entry resolves too, and that is worth pinning: the venue
    // capture does NOT keep the courthouse city. "the courts located in
    // Wilmington, Delaware" is extracted as the STATE, so the venue and the
    // governing law arrive already identical in raw text. That is the measured
    // reason CHOICE-004's id branch suppresses nothing on 149 corpus documents
    // with both clauses — 147 are raw-equal before the ids are consulted.
    const venue = prepared.extracted.jurisdictions.find((j) => j.clause_kind === "venue");
    expect(venue).toBeDefined();
    expect(venue!.jurisdiction_id).toBe("us-de");
  }, 120000);

  /**
   * The two consumers that were broken by the empty field, asserted against
   * the REAL pipeline's extraction rather than a hand-built reference.
   *
   * 🚨 This distinction is the whole reason the defects survived. The existing
   * unit tests for both consumers construct their own `jurisdictions` entries
   * and set `jurisdiction_id` by hand — so the suite tested a field shape the
   * product had never once produced. A test that supplies the input the
   * product cannot supply proves the consumer, and hides the pipeline.
   */
  describe("the consumers the empty field broke", () => {
    const delawareDoc = (): File =>
      new File(
        [
          new TextEncoder().encode(
            [
              "SERVICES AGREEMENT",
              "",
              "1. Governing Law",
              "",
              "1.1 This Agreement is governed by the laws of the State of Delaware.",
              "",
            ].join("\n"),
          ),
        ],
        "services.txt",
      );

    it("accepts a custom playbook that allows a jurisdiction by DKB id", async () => {
      const prepared = await prepareDocument(delawareDoc(), "text", {
        dkb_base: "/x-dkb",
        playbook_base: "/x-playbooks",
      });

      // `governing_law_in` documents that an author may write DKB ids in
      // `allowed`, and compares them against `jurisdiction_id`. With the field
      // empty that comparison could never match, so this playbook reported a
      // Delaware-law document VIOLATED — a false positive on a compliant
      // document, in the one surface a user writes themselves.
      const pb = validateCustomPlaybook({
        schema_version: "1.0",
        catalog_version: "0.1.0",
        id: "custom-gov-law",
        name: "Delaware only",
        description: "Allows Delaware governing law, by DKB id.",
        custom_rules: [
          {
            id: "R1",
            title: "Governing law must be Delaware",
            description: "d",
            severity: "warning",
            assert: { kind: "governing_law_in", allowed: ["us-de"] },
          },
        ],
      });
      if (!pb.ok) throw new Error(`playbook invalid: ${JSON.stringify(pb.errors)}`);

      const run = await runCustomPlaybook(pb.playbook, {
        tree: prepared.ingest.tree,
        extracted: prepared.extracted,
      });
      expect(run.findings).toEqual([]);
    }, 120000);

    it("prints a resolved id in the report's jurisdiction table", async () => {
      const prepared = await prepareDocument(delawareDoc(), "text", {
        dkb_base: "/x-dkb",
        playbook_base: "/x-playbooks",
      });
      const report = await runReport(prepared);
      const blob = await buildDocxReport(
        report.run,
        prepared.ingest,
        prepared.dkb,
        prepared.playbook,
        undefined,
        prepared.extracted,
      );

      // 🚨 Read the rendered TEXT, not the blob size. `docx.test.ts` asserts
      // `blob.size` and nothing else, which is exactly why a column that
      // printed "—" for every row of every report was invisible to the suite:
      // a dash is the same number of bytes as an id.
      const buf = Buffer.from(await blob.arrayBuffer());
      const mammoth = (await import("mammoth")) as unknown as {
        convertToHtml: (input: { buffer: Buffer }) => Promise<{ value: string }>;
      };
      const html = (await mammoth.convertToHtml({ buffer: buf })).value;

      expect(html).toContain("Jurisdictions");
      expect(html).toContain("us-de");
    }, 180000);
  });
});

/**
 * The harness half — `guard-harness-extraction-parity`.
 *
 * 🥇 Three times in one session a TEST HARNESS built `extracted` differently
 * from the product, and each time something else found it: `_test-fixtures.ts`
 * (the shared rule-test context builder) turned up in a static sweep, the
 * digest harness by inspection, and `cli-docx-report`'s parity check by going
 * red in the gate. Nothing was looking for the class. That is a bad detection
 * story for a defect that has now recurred three times, so this looks for it.
 *
 * ⚠️ Deliberately NOT every harness. `tests/` holds ~90 `extractAll` calls and
 * most are unit fixtures asserting things jurisdictions have nothing to do
 * with; requiring the option there would be churn with no reader, and a guard
 * that flags 40 files nobody will fix becomes an exceptions table. The three
 * reasons in `harnessReasons` are the ones where the omission changes what the
 * harness PROVES — committed output, a rendered report, or an assertion that
 * reads the field.
 *
 * 🚨 The third reason is the sharpest and the easiest to miss:
 * `extraction-format-invariance` projects `jurisdiction_id ?? ""` to assert the
 * id survives a format transform, and for its whole life every value in that
 * projection was the empty string. It compared "" to "" on every document and
 * passed. An assertion over a field the harness never populates does not fail
 * — it quietly stops being a test.
 */
describe("jurisdiction_id reach — the harnesses that must match the product", () => {
  const swept = (): { file: string; reasons: string[]; src: string }[] => {
    const files = HARNESS_ROOTS.flatMap((r) => sourcesUnder(ROOT, r, { includeTests: true }));
    const inherited = committedOutputHelpers(ROOT, files);
    return files
      .map((file) => {
        const src = readFileSync(join(ROOT, file), "utf8");
        return { file, src, reasons: harnessReasons(src, inherited.has(file)) };
      })
      .filter((f) => f.reasons.length > 0);
  };

  it("has a non-trivial class to check, for each reason", () => {
    const files = swept();
    expect(files.length).toBeGreaterThan(15);
    // Every reason must actually select something. A reason that matches no
    // file is a rule nobody is held to, and it would read as compliance.
    for (const reason of [
      "committed output",
      "renders a report artifact",
      "asserts on jurisdiction_id",
    ]) {
      expect(
        files.filter((f) => f.reasons.includes(reason)).length,
        `no file selected by "${reason}" — the rule matches nothing`,
      ).toBeGreaterThan(0);
    }
  });

  it("finds real call sites in that class (the sweep is not vacuous)", () => {
    const sites = swept().flatMap((f) => callSitesIn(f.file, f.src));
    expect(sites.length).toBeGreaterThan(10);
    expect(sites.filter((s) => s.wired).length).toBeGreaterThan(5);
  });

  it("passes the lookup in every harness that renders, pins, or reads the field", () => {
    const unwired = swept().flatMap((f) =>
      callSitesIn(f.file, f.src)
        .filter((s) => !s.wired)
        .map(() => `${f.file} (${f.reasons.join("; ")})`),
    );
    expect([...new Set(unwired)].sort()).toEqual([]);
  });
});
