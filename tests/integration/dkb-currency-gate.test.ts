/**
 * Citation-currency CI gate (fix-legal-authority-currency).
 *
 * The fastest way to lose an attorney is to be confidently wrong about
 * current law — the shipped DKB cited the vacated FTC non-compete rule as
 * "pending" for over a year. This gate makes silent aging impossible:
 * every statute node in the LATEST artifact must have been retrieved
 * within the manifest's currency horizon (default 12 months) of *now*,
 * or carry an explicit `currency_acknowledgments` entry in
 * `dkb-staleness-ack.yml`. Deliberately wall-clock: the whole point is
 * that CI goes red when the knowledge base ages out in real time.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import * as YAML from "js-yaml";
import { describe, expect, it } from "vitest";
import { loadDkbDirSync, resolveDkbDir } from "../../tools/dkb/resolve.js";
import { DEFAULT_CURRENCY_HORIZON_MONTHS } from "../../src/report/citations.js";

type AckFile = { currency_acknowledgments?: Array<{ node_id: string; ack: string }> };

describe("DKB citation-currency gate (latest artifact)", () => {
  it("every statute node is within the horizon or explicitly acknowledged", () => {
    const dkb = loadDkbDirSync(resolveDkbDir());
    const horizon = dkb.manifest.currency_horizon_months ?? DEFAULT_CURRENCY_HORIZON_MONTHS;
    const ackRaw = YAML.load(
      readFileSync(join(process.cwd(), "dkb-staleness-ack.yml"), "utf8"),
    ) as AckFile;
    const acked = new Set((ackRaw.currency_acknowledgments ?? []).map((a) => a.node_id));

    const now = Date.now(); // wall-clock BY DESIGN — this is the aging gate
    const stale: string[] = [];
    for (const node of dkb.statutes) {
      const m = node.retrieved_at.match(/^(\d{4})-(\d{2})-(\d{2})/);
      expect(m, `${node.id}: unparseable retrieved_at "${node.retrieved_at}"`).not.toBeNull();
      const [, y, mo, d] = m!;
      const threshold = Date.UTC(Number(y), Number(mo) - 1 + horizon, Number(d));
      if (now > threshold && !acked.has(node.id)) {
        stale.push(`${node.id} (retrieved ${y}-${mo}-${d})`);
      }
    }
    expect(
      stale,
      `statute node(s) older than ${horizon} months — re-verify and bump retrieved_at, ` +
        `or acknowledge in dkb-staleness-ack.yml under currency_acknowledgments`,
    ).toEqual([]);
  });
});
