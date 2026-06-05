/**
 * v4 sub-domain classifier — top-1 accuracy on the labeled golden corpus
 * (spec-v6.md §19, Step 99).
 *
 * The threshold-calibration test (classifier-calibration.test.ts) locks in
 * the *acceptance floor*; this test locks in *correctness*: of the labeled
 * single-doc fixtures, how many does the stage-1 scorer rank #1 correctly,
 * and are the four named confusions (spec-v6 §19) resolved?
 *
 *   healthcare → privacy        (J should not lose to I)
 *   ip-licensing → equity       (H should not lose to C)
 *   settlement → commercial     (G should not lose to A)
 *   compliance → employment     (O should not lose to F)
 *
 * Re-engineering target: lift top-1 above the ~70% baseline (53/75 measured
 * 2026-05-28, 22 misclassifications) by tuning the hand-authored feature
 * table in `dkb/v4/sub-domain-features.json`. No model; the table stays
 * inspectable. See BUILD_PROGRESS for the before/after.
 */

import { describe, expect, it, beforeAll } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ingestFixture } from "../../golden/v4/_pipeline.js";
import { extractAll } from "../../../src/extract/index.js";
import { loadStarterDkbSync } from "../../../src/engine/_test-fixtures.js";
import { scoreSubDomains, type SubDomainFeatures } from "../../../src/extract/v4/classifier.js";
import type { V4SubDomain } from "../../../src/extract/v4/index.js";
import type { Section } from "../../../src/ingest/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..", "..", "..");
const FIXTURE_DIR = join(REPO_ROOT, "tests", "golden", "v4", "fixtures");

const FEATURES = JSON.parse(
  readFileSync(join(REPO_ROOT, "dkb", "v4", "sub-domain-features.json"), "utf8"),
) as SubDomainFeatures;

const PREFIX_TO_SUBDOMAIN: ReadonlyArray<readonly [string, V4SubDomain]> = [
  ["governance-", "B-governance"],
  ["equity-", "C-equity"],
  ["m-and-a-", "D-m-and-a"],
  ["real-estate-", "E-real-estate"],
  ["employment-", "F-employment"],
  ["settlement-", "G-settlement"],
  ["ip-licensing-", "H-ip-licensing"],
  ["privacy-", "I-privacy"],
  ["healthcare-", "J-healthcare"],
  ["insurance-", "K-insurance"],
  ["banking-", "L-banking"],
  ["construction-", "M-construction"],
  ["trust-", "N-trust-estate"],
  ["compliance-", "O-compliance-policy"],
  ["regulatory-", "P-regulatory-prose"],
];

function expectedSubDomain(name: string): V4SubDomain | null {
  for (const [prefix, sd] of PREFIX_TO_SUBDOMAIN) if (name.startsWith(prefix)) return sd;
  return null;
}

function collectBody(sections: readonly Section[]): string {
  const parts: string[] = [];
  const walk = (ss: readonly Section[]): void => {
    for (const s of ss) {
      for (const p of s.paragraphs) for (const r of p.runs) parts.push(r.text);
      walk(s.children);
    }
  };
  walk(sections);
  return parts.join(" ");
}

type Row = { name: string; expected: V4SubDomain; predicted: V4SubDomain; confidence: number; runnerUp: V4SubDomain };

let rows: Row[] = [];

beforeAll(async () => {
  const dkb = loadStarterDkbSync();
  const files = readdirSync(FIXTURE_DIR)
    .filter((n) => n.endsWith(".txt"))
    .sort();
  const out: Row[] = [];
  for (const name of files) {
    const expected = expectedSubDomain(name);
    if (!expected) continue;
    const ingest = await ingestFixture(join(FIXTURE_DIR, name));
    const extracted = extractAll(ingest.tree, {
      classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
    });
    const scores = scoreSubDomains({
      extracted,
      body_text: collectBody(ingest.tree.sections),
      features: FEATURES,
    });
    out.push({
      name,
      expected,
      predicted: scores[0]!.sub_domain,
      confidence: scores[0]!.normalized,
      runnerUp: scores[1]!.sub_domain,
    });
  }
  rows = out;
});

describe("v4 sub-domain classifier — top-1 accuracy (Step 99)", () => {
  it("classifies a non-trivial labeled corpus", () => {
    expect(rows.length).toBeGreaterThanOrEqual(70);
  });

  it("achieves the re-engineered top-1 accuracy target (≥ 85%)", () => {
    const correct = rows.filter((r) => r.predicted === r.expected).length;
    const wrong = rows.filter((r) => r.predicted !== r.expected);
    // Diagnostic — printed only when the suite runs with reporter output.
    if (wrong.length > 0) {
      console.log(
        `top-1 ${correct}/${rows.length} = ${((100 * correct) / rows.length).toFixed(1)}%; misses:\n` +
          wrong
            .map((w) => `  ${w.name}: exp ${w.expected} got ${w.predicted} (${w.confidence.toFixed(3)})`)
            .join("\n"),
      );
    }
    expect(correct / rows.length).toBeGreaterThanOrEqual(0.85);
  });

  it("resolves the four named confusions (spec-v6 §19)", () => {
    // Every fixture for the confused-from domain must NOT be predicted as
    // the confused-to domain.
    const confusions: Array<[V4SubDomain, V4SubDomain]> = [
      ["J-healthcare", "I-privacy"],
      ["H-ip-licensing", "C-equity"],
      ["G-settlement", "A-commercial"],
      ["O-compliance-policy", "F-employment"],
    ];
    for (const [from, to] of confusions) {
      const leaked = rows.filter((r) => r.expected === from && r.predicted === to);
      expect(leaked, `${from} leaking to ${to}: ${leaked.map((l) => l.name).join(", ")}`).toHaveLength(0);
    }
  });

  it("every sub-domain with fixtures classifies at least one correctly", () => {
    const byDomain = new Map<V4SubDomain, Row[]>();
    for (const r of rows) {
      const list = byDomain.get(r.expected) ?? [];
      list.push(r);
      byDomain.set(r.expected, list);
    }
    for (const [sd, list] of byDomain) {
      const correct = list.filter((r) => r.predicted === r.expected).length;
      expect(correct, `${sd} has zero correct of ${list.length}`).toBeGreaterThan(0);
    }
  });
});
