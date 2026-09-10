/**
 * A statute's recorded jurisdiction, against where it is actually published.
 *
 * 🚨 The DKB's statutory index records **Regulation (EU) 2016/679 — the
 * GDPR — as `us-federal`**, alongside the UETA and the Uniform Trade Secrets
 * Act. The GDPR is not United States federal law, and a uniform act is a model
 * statute a state may or may not have enacted, not federal law either.
 *
 * 🥇 **Nothing reads the field today**, which is the only reason this is a
 * latent defect rather than a live one: `StatutoryIndexEntry.jurisdiction` has
 * no consumer anywhere in `src/` or `tools/` — the `.jurisdiction` reads in the
 * tree belong to `STATE_OVERLAYS` and `ESTATE_FORMALITIES`, different types
 * entirely. So no routing, no overlay selection and no report line depends on
 * it being wrong.
 *
 * It is not fixed here, and the reason is worth stating: `dkb/dist/` is a
 * **content-hashed** artifact and `dkb_version` sits inside `result_hash`, so
 * correcting three rows churns every golden in the repo. That is its own
 * change, made deliberately, not a tail. See BUILD_PROGRESS and the frontier.
 *
 * What this file does instead is make the wrongness **visible and bounded**: it
 * names the three entries, so a fourth cannot join them quietly, and it gives
 * whoever does the DKB pass an exact checklist. The day someone starts reading
 * `jurisdiction`, this is the file that says the data is not yet trustworthy.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const DIST = join(process.cwd(), "dkb", "dist");

type Statute = { citation: string; canonical_url: string; jurisdiction: string };

/** Where US federal and state law is actually published. */
const US_PUBLIC =
  /\.gov(\/|$)|\.gov\.|law\.cornell\.edu|leginfo\.legislature|legislature\.|\.us(\/|$)/;

/**
 * Known-wrong, declared with the reason. Keyed by citation so the entry is
 * identified by WHAT it is, not by where it sits in a generated file.
 */
const DECLARED: ReadonlyMap<string, string> = new Map([
  [
    "Regulation (EU) 2016/679 (GDPR), Article 28 — Processor",
    "an EU regulation recorded as us-federal; fixing it churns every golden",
  ],
  [
    "UETA § 7 (Legal recognition of electronic records and signatures)",
    "a Uniform Law Commission act, not federal law; states enact it individually",
  ],
  [
    "Uniform Trade Secrets Act (1985)",
    "a Uniform Law Commission act, not federal law; states enact it individually",
  ],
]);

function newestDist(): string {
  const versions = readdirSync(DIST, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort();
  return versions[versions.length - 1]!;
}

function statutes(): Statute[] {
  const raw = readFileSync(join(DIST, newestDist(), "dkb-statutes.json"), "utf8");
  const parsed = JSON.parse(raw) as Statute[] | { statutes: Statute[] };
  return Array.isArray(parsed) ? parsed : parsed.statutes;
}

describe("DKB statutory index — jurisdiction against publisher", () => {
  it("no statute claims a US jurisdiction it is not published under, beyond the declared three", () => {
    const rows = statutes();
    // Anti-vacuity: an index that failed to load reports no mismatches at all.
    expect(rows.length, "the statutory index did not load").toBeGreaterThan(20);

    const mismatched = rows
      .filter((s) => s.jurisdiction.startsWith("us-") && !US_PUBLIC.test(s.canonical_url))
      .map((s) => s.citation)
      .filter((c) => !DECLARED.has(c))
      .sort();

    expect(
      mismatched,
      "a statute records a US jurisdiction but is published elsewhere — either the " +
        "jurisdiction is wrong or the URL is. Fix it, or declare it here with the reason.",
    ).toEqual([]);
  });

  it("every declared exception is still there, so a fixed one cannot linger", () => {
    // The same rule the recognizer sweeps follow: a stale exception is a lie
    // about the tree, and the DKB pass that fixes these must delete them here.
    const citations = new Set(statutes().map((s) => s.citation));
    const gone = [...DECLARED.keys()].filter((c) => !citations.has(c)).sort();
    expect(gone, "a declared exception names a statute the index no longer holds").toEqual([]);
  });

  it("the field still has no consumer, which is why the above is latent", () => {
    // If this fails, someone started routing on `jurisdiction` and the three
    // declared rows stopped being harmless. Read this file's header first.
    const src = [
      ...readdirSync(join(process.cwd(), "src", "dkb")).map((f) => join("src", "dkb", f)),
    ]
      .filter((f) => f.endsWith(".ts") && !f.includes(".test."))
      .map((f) => readFileSync(join(process.cwd(), f), "utf8"))
      .join("\n");
    expect(src).toContain("jurisdiction");
    // Named in the TYPE, never read off a statute.
    expect(/stat(?:ute)?\.jurisdiction/.test(src)).toBe(false);
  });
});
