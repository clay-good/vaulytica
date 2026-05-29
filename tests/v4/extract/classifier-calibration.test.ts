/**
 * v4 sub-domain classifier — threshold calibration regression
 * (spec-v4.md Part VII open question #8).
 *
 * Open question #8 flagged the 0.5 / 0.5 sub-domain / family confidence
 * thresholds as "a starting point ... may need calibration once a
 * fixture corpus exists." The labeled golden corpus now exists
 * (tests/golden/v4/fixtures/ — one passing + several failing fixtures
 * per sub-domain B–P, each filename-prefixed with its sub-domain), so
 * this test runs the stage-1 scorer over the whole corpus and locks in
 * the calibrated floor.
 *
 * Methodology (reproduced here so the calibration is auditable):
 *
 *   For each labeled fixture we ingest → extract → `scoreSubDomains`,
 *   take the top-1 sub-domain, and classify the outcome at a candidate
 *   threshold t as:
 *     - true-accept   : predicted === expected AND winner.normalized ≥ t
 *     - false-accept  : predicted !== expected AND winner.normalized ≥ t
 *     - false-reject  : predicted === expected AND winner.normalized < t
 *
 *   Threshold sweep over the corpus (measured 2026-05-28):
 *
 *     t      true-accept  false-accept  false-reject
 *     0.30        38            0            15
 *     0.40        38            0            15
 *     0.45        28            0            25
 *     0.50        28            0            25   ← original spec floor
 *     0.60        13            0            40
 *
 *   false-accept is 0 at every threshold — no wrong top-1 prediction in
 *   the corpus scores above 0.286, so lowering the floor never admits a
 *   misclassification. Dropping 0.5 → 0.4 recovers 10 correct detections
 *   (28 → 38) that the 0.5 floor was sending to `generic-fallback`. 0.4
 *   is the robust point in the [0.30, 0.40] plateau: it clears the 0.286
 *   false-positive ceiling by a comfortable 0.114 margin yet still
 *   captures the 0.429 correct tier.
 *
 * This test asserts the live invariants behind that table so a feature
 * edit or a corpus change that breaks the calibration fails loudly.
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

// Fixture filename prefix → expected sub-domain. The golden corpus names
// every single-doc fixture `<sub-domain-slug>-...`.
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

type Row = { name: string; expected: V4SubDomain; predicted: V4SubDomain; confidence: number };

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
    const winner = scores[0]!;
    out.push({ name, expected, predicted: winner.sub_domain, confidence: winner.normalized });
  }
  rows = out;
});

function tally(t: number): { trueAccept: number; falseAccept: number; falseReject: number } {
  let trueAccept = 0;
  let falseAccept = 0;
  let falseReject = 0;
  for (const r of rows) {
    const accepted = r.confidence >= t;
    const correct = r.predicted === r.expected;
    if (accepted && correct) trueAccept++;
    else if (accepted && !correct) falseAccept++;
    else if (!accepted && correct) falseReject++;
  }
  return { trueAccept, falseAccept, falseReject };
}

describe("v4 sub-domain classifier — threshold calibration (open question #8)", () => {
  it("has a non-trivial labeled corpus to calibrate against", () => {
    expect(rows.length).toBeGreaterThanOrEqual(60);
  });

  it("admits zero misclassifications at the calibrated floor", () => {
    const floor = FEATURES.thresholds.sub_domain_min_confidence;
    expect(tally(floor).falseAccept).toBe(0);
  });

  it("accepts the bulk of correct detections at the calibrated floor", () => {
    const floor = FEATURES.thresholds.sub_domain_min_confidence;
    // Measured 38; floor with margin so a small corpus shuffle doesn't flap.
    expect(tally(floor).trueAccept).toBeGreaterThanOrEqual(35);
  });

  it("recovers correct detections the original 0.5 spec floor was rejecting", () => {
    // The lower floor is strictly more permissive, so it can only add
    // accepts — and with false-accept pinned at 0 (test above), every
    // recovered detection is a correct one the 0.5 floor was sending to
    // generic-fallback.
    const calibrated = tally(FEATURES.thresholds.sub_domain_min_confidence);
    const original = tally(0.5);
    expect(calibrated.trueAccept).toBeGreaterThan(original.trueAccept);
  });

  it("keeps a safety margin: dropping below the false-positive ceiling would admit errors", () => {
    // Every wrong top-1 prediction scores ≤ 0.286, so a floor at or below
    // that ceiling starts admitting misclassifications. This pins the
    // reason the floor is 0.4 and not lower.
    const ceilingProbe = tally(0.25);
    expect(ceilingProbe.falseAccept).toBeGreaterThan(0);
    expect(FEATURES.thresholds.sub_domain_min_confidence).toBeGreaterThan(0.286);
  });
});
