/**
 * The cross-document engine must not change its mind because a document was
 * re-wrapped.
 *
 * Every other second surface in the tree has a metamorphic relation now — the
 * findings, the extracted data, the critical-dates register, the negotiation
 * posture, the delivery scan. The `ConsistencyRun` had none, and it is the
 * surface with the most to lose from a format change, because a cross-document
 * rule reads TWO documents and compares what it found in each. A transform that
 * moves one side and not the other manufactures a disagreement out of nothing:
 * `CC-005` reports the governing law of two documents as different,
 * `CROSS-DEFTERM-001` reports a defined term as drifting, `CROSS-DATE-001`
 * reports an impossible chronology. Those are confident accusations about a
 * pair of contracts, and a false one is expensive to dismiss.
 *
 * It went un-relationed for a simple reason: until 9.528.0 the engine ran only
 * in the browser, so there was no headless caller to point a relation at. There
 * is now.
 *
 * The comparison is `rule_id` plus the doc_id of each cited document — the
 * identity of the conflict and who it is between. Never the excerpt text, which
 * is the clause the transform rewrites.
 */
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { ingestPaste } from "../../src/ingest/paste.js";
import { extractAll } from "../../src/extract/index.js";
import { loadStarterDkbSync } from "../../src/engine/_test-fixtures.js";
import { runConsistency } from "../../src/engine/consistency/runner.js";
import { ALL_CONSISTENCY_RULES } from "../../src/engine/consistency/rules/index.js";
import type { ConsistencyDocument } from "../../src/engine/consistency/types.js";

const BUNDLES = join(process.cwd(), "tests", "golden", "v4", "bundles");
const dkb = loadStarterDkbSync();

const bundleNames = readdirSync(BUNDLES, { withFileTypes: true })
  .filter((e) => e.isDirectory())
  .map((e) => e.name)
  .sort();

function membersOf(bundle: string): string[] {
  return readdirSync(join(BUNDLES, bundle))
    .filter((f) => f.endsWith(".txt"))
    .sort();
}

/** Same routing the bundle golden uses: the sidecar, or the generic fallback. */
function playbookOf(bundle: string, file: string): string {
  const sidecar = join(BUNDLES, bundle, `${file}.playbook`);
  return existsSync(sidecar) ? readFileSync(sidecar, "utf8").trim() : "generic-fallback";
}

async function docsFor(
  bundle: string,
  transform: (t: string) => string,
): Promise<ConsistencyDocument[]> {
  const out: ConsistencyDocument[] = [];
  for (const file of membersOf(bundle)) {
    const ingest = await ingestPaste(transform(readFileSync(join(BUNDLES, bundle, file), "utf8")));
    out.push({
      doc_id: file,
      source_file_name: file,
      playbook_id: playbookOf(bundle, file),
      tree: ingest.tree,
      extracted: extractAll(ingest.tree),
    });
  }
  return out;
}

/** The conflict's identity and who it is between — never the quoted clause. */
async function conflicts(bundle: string, transform: (t: string) => string): Promise<string> {
  const documents = await docsFor(bundle, transform);
  const run = await runConsistency({ rules: ALL_CONSISTENCY_RULES, documents, dkb });
  return run.findings
    .map((f) => `${f.rule_id}[${[...new Set(f.excerpts.map((e) => e.doc_id))].sort().join("+")}]`)
    .sort()
    .join("|");
}

const identity = (t: string): string => t;
const stripBlankLines = (t: string): string =>
  t
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .join("\n");
const crlf = (t: string): string => t.replace(/\n/g, "\r\n");
const doubleSpaced = (t: string): string => t.split("\n").join("\n\n");
const smartQuotes = (t: string): string => t.replace(/'/g, "’").replace(/"([^"]*)"/g, "“$1”");

const TRANSFORMS: Array<[string, (t: string) => string]> = [
  ["blank lines stripped", stripBlankLines],
  ["CRLF line endings", crlf],
  ["double-spaced", doubleSpaced],
  ["smart quotes", smartQuotes],
];

/** What `after` lost from `base` and gained over it, counting duplicates. */
function multisetDiff(
  base: readonly string[],
  after: readonly string[],
): { lost: string[]; gained: string[] } {
  const counts = new Map<string, number>();
  for (const k of base) counts.set(k, (counts.get(k) ?? 0) + 1);
  const gained: string[] = [];
  for (const k of after) {
    const n = counts.get(k) ?? 0;
    if (n > 0) counts.set(k, n - 1);
    else gained.push(k);
  }
  const lost: string[] = [];
  for (const [k, n] of counts) for (let i = 0; i < n; i++) lost.push(k);
  return { lost: lost.sort(), gained: gained.sort() };
}

describe("the cross-document run is not a function of the format", () => {
  it("the corpus of bundles actually exercises the engine (anti-vacuity)", async () => {
    // A relation over a baseline of nothing proves nothing. Both halves matter:
    // enough bundles, and enough of them producing a conflict to compare.
    expect(bundleNames.length).toBeGreaterThanOrEqual(10);
    let withFindings = 0;
    let total = 0;
    for (const b of bundleNames) {
      const base = await conflicts(b, identity);
      if (base !== "") {
        withFindings++;
        total += base.split("|").length;
      }
    }
    expect(withFindings, "no bundle produces a cross-document finding").toBeGreaterThanOrEqual(10);
    expect(total, "the baseline is too thin to constrain anything").toBeGreaterThan(15);
  }, 600_000);

  /**
   * The debt, held by equality.
   *
   * Every mover is the SAME transform — blank lines stripped — and the same
   * root cause: `ingestPaste` joins a short line to the one beneath it, so
   * removing blank lines changes what the party and defined-term extractors
   * read. That debt is already measured and ratcheted at its source
   * (`extraction-format-invariance.test.ts`, `defined-terms-format.test.ts`).
   *
   * 🥇 What is NEW here is the COST. At the extraction layer a mover is a
   * divergent record in a table. At this layer the same movement becomes a
   * confident accusation about a PAIR OF CONTRACTS — and it runs in both
   * directions. `termination-mismatch` GAINS "Acme Inc / Acme appears to be the
   * same entity under different legal names" purely because the layout changed;
   * nothing in either document is inconsistent. `privacy-notice-vs-dpa` LOSES
   * the same kind of finding for the same reason. A finding that appears and
   * disappears with blank lines is worse than a finding that is merely absent.
   *
   * 🥇 THE THREE `CROSS-PARTY-001` MOVERS ARE GONE, and the measurement is why.
   * All five such findings the bundle corpus produced differed only by a
   * corporate suffix, which made "stand down on any suffix-only difference"
   * look like the fix — and it was wrong: `party-name-conflict`, the bundle
   * named for this rule, is "Acme Corp" / "Acme Corporation", a real drafting
   * inconsistency. The line that separates the artifacts from the finding
   * EXACTLY is PRESENCE versus ABSENCE of a corporate form ("Acme Inc" /
   * "Acme"), and that is what `findPartyNameMismatches` now skips. What remains
   * below is a different root cause, in the defined-term extractor: a CLAUSE
   * HEADING ("Governing Law:", written at the start of a line in one document
   * and mid-paragraph in the others) read as a definition, diagnosed in
   * 9.538.0.
   *
   * 🚨 The analogue of the party repair does NOT work here, and it was measured
   * before being declined. "Stand down when the term has no uses in its own
   * defining document" splits 4 of the corpus's 6 `CROSS-DEFTERM-002` findings
   * — but one of those 4 is `defterm-usage-drift`'s "Authorized Users", the
   * flagship case of the bundle NAMED for this rule, where a definitions
   * section legitimately defines a term the rest of the DEAL uses. Unlike the
   * corporate-suffix split, this one does not separate the artifacts from the
   * findings. Do not ship it.
   */
  it("holds the known movers by equality — every one an ingest-join artifact", async () => {
    const OWED: ReadonlyArray<string> = [
      // Two defined-term conflicts lost: joining lines changes which document
      // the extractor believes defines "Governing Law".
      "governing-law-mismatch [blank lines stripped]: -CROSS-DEFTERM-002[dpa.txt+sow.txt] -CROSS-DEFTERM-002[msa.txt+sow.txt]",
    ];

    const owed: string[] = [];
    for (const bundle of bundleNames) {
      const base = (await conflicts(bundle, identity)).split("|").filter(Boolean);
      for (const [label, fn] of TRANSFORMS) {
        const after = (await conflicts(bundle, fn)).split("|").filter(Boolean);
        // A MULTISET diff. Two of the manufactured findings share a rule id and
        // a document pair and differ only in which party they name, so a Set
        // collapses them and the list under-reports the damage by one.
        const { lost, gained } = multisetDiff(base, after);
        if (lost.length === 0 && gained.length === 0) continue;
        owed.push(
          `${bundle} [${label}]: ${[...lost.map((k) => `-${k}`), ...gained.map((k) => `+${k}`)].join(" ")}`,
        );
      }
    }
    // Equality, not a ceiling: a NEW mover fails here, and so does a repair
    // whose line was not removed from the list.
    expect(owed.sort()).toEqual([...OWED].sort());
  }, 600_000);

  it("only the blank-line transform moves anything", async () => {
    // The load-bearing claim of the whole file: three of the four transforms
    // are inert, so a green is about the ENGINE, not about transforms too weak
    // to disturb it.
    const movers = new Set<string>();
    for (const bundle of bundleNames) {
      const base = await conflicts(bundle, identity);
      for (const [label, fn] of TRANSFORMS) {
        if ((await conflicts(bundle, fn)) !== base) movers.add(label);
      }
    }
    expect([...movers]).toEqual(["blank lines stripped"]);
  }, 600_000);
});
