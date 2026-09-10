/**
 * Every numeric ladder metric must actually READ the corpus.
 *
 * `custom-interpreter.ts` computes the negotiation ladder from the document
 * text, and each numeric dimension resolves through one `extractMetricValues`
 * case: a small set of regexes over the folded document. When those regexes
 * miss the way contracts ordinarily write the thing, the position is reported
 * **unevaluable** — and that is the failure this file exists for, because an
 * unevaluable dimension does not read as a wrong answer. It drops off the
 * ladder the negotiator reads, silently, and no relation over `run.findings`
 * can see it: the posture is not a finding.
 *
 * Two metrics were shipping DEAD when this guard was written (9.651.0), and
 * neither was visible from any other surface:
 *
 *   - `liability_cap_multiple` read only an explicit multiplier ("12x fees").
 *     The ordinary cap writes none — "limited to the fees paid in the twelve
 *     (12) months before the event giving rise to the claim" — so the metric
 *     located a value in **1 of 327 specimens**, and the dimension the shipped
 *     `saas-buyer` example ladder leads with (severity `critical`) rested on a
 *     single document. (My first probe said zero. It hand-rolled the multiplier
 *     regex without `PERIOD_COUNT`, so "capped at **three** times the fees" was
 *     invisible to the probe and not to the engine. Feed a metric what its real
 *     caller feeds it, or measure the wrong thing confidently.)
 *   - `notice_period_days` spelled the plural possessive `days's`. Every
 *     contract writes `days'`. 14 specimens, where 108 state a notice period.
 *
 * The reach numbers are committed by EQUALITY, so widening a pattern means
 * raising one on purpose and narrowing one means lowering it on purpose.
 * A number that moves without a line in the CHANGELOG is a regression.
 *
 * A LOW number is not automatically a defect — some of these are honest. Only
 * two specimens cap an indemnity by a stated figure, and ten carry an uptime
 * percentage at all. What is never honest is **zero**.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ingestPaste } from "../../src/ingest/paste.js";
import { extractAll } from "../../src/extract/index.js";
import { evaluateNegotiationPosture } from "../../src/playbooks/custom-interpreter.js";
import type { NegotiationPosition } from "../../src/playbooks/custom-playbook.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");
const SPECIMENS = readdirSync(DIR)
  .filter((f) => f.endsWith(".txt"))
  .sort();

/**
 * How many specimens each metric locates a value in. Measured 2026-09-10 over
 * the 327-specimen corpus. Adding a specimen moves these; say so in the
 * CHANGELOG when it does.
 */
const REACH: Record<string, number> = {
  notice_period_days: 109,
  term_length_days: 40,
  payment_term_days: 56,
  liability_cap_multiple: 21,
  liability_cap_amount: 65,
  cure_period_days: 60,
  auto_renewal_notice_days: 26,
  indemnity_cap_amount: 2,
  uptime_sla_percent: 8,
};

/**
 * A ladder of one position per metric, each with a threshold no real value can
 * fail (`gte -1`). We are asking only whether the metric LOCATED a number, so
 * the comparison must never be what decides the tier.
 */
const POSITIONS = Object.keys(REACH).map(
  (metric) =>
    ({
      dimension: metric,
      ideal: { kind: "numeric_threshold", metric, comparator: "gte", value: -1 },
      acceptable: { kind: "numeric_threshold", metric, comparator: "gte", value: -1 },
      guidance: { ideal: "i", acceptable: "a", walk_away: "w" },
    }) as NegotiationPosition,
);

describe("ladder metric reach over the specimen corpus", () => {
  it("locates the number of documents each metric is committed to", async () => {
    const hits: Record<string, number> = Object.fromEntries(Object.keys(REACH).map((m) => [m, 0]));
    for (const file of SPECIMENS) {
      const ingest = await ingestPaste(readFileSync(join(DIR, file), "utf8"));
      const posture = await evaluateNegotiationPosture(POSITIONS, {
        tree: ingest.tree,
        extracted: extractAll(ingest.tree),
      });
      for (const p of posture.positions) {
        if (p.tier !== "unevaluable") hits[p.dimension] = (hits[p.dimension] ?? 0) + 1;
      }
    }

    // Anti-vacuity. A harness that ingested nothing, or a ladder whose
    // positions failed to resolve, reports every metric at zero — which is
    // indistinguishable from nine dead metrics unless we say otherwise here.
    expect(SPECIMENS.length).toBeGreaterThan(300);
    expect(Object.values(hits).reduce((a, b) => a + b, 0)).toBeGreaterThan(300);

    // The headline: a metric no document in a 327-document corpus exercises is
    // not a strict metric, it is an unreachable one.
    for (const [metric, n] of Object.entries(hits)) {
      expect(n, `${metric} reads no document in the corpus`).toBeGreaterThan(0);
    }

    expect(hits).toEqual(REACH);
  }, 240_000);
});
