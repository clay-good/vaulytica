#!/usr/bin/env node
/**
 * Source-pinning staleness gate (spec-v3.md §14 / Step 20).
 *
 * Run as part of the DKB build. Loads every v3 node from
 * `dkb/dist/<version>/v3/*.json`, re-fetches each pinned citation, and
 * compares the normalized SHA-256 against `content_hash_at_pin`. Writes
 * `dkb/dist/<version>/v3/staleness-report.json` and exits non-zero if
 * any drift is not explicitly acknowledged in `dkb-staleness-ack.yml`.
 *
 * In offline mode (`--offline`, the default for CI without network),
 * authority text is replayed from cached snapshots under
 * `dkb/fixtures/v3/snapshots/{sha256(source_url)}.txt`. The cache hash
 * is the same content-addressed scheme v2's fetcher framework uses.
 */

import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import * as YAML from "js-yaml";

import { V3DkbNodeListSchema } from "../../../src/dkb/v3/schema.js";
import type { PinnedCitation, V3DkbNode } from "../../../src/dkb/v3/types.js";
import {
  detectStaleness,
  type AcknowledgmentEntry,
  type AuthorityFetcher,
  type StalenessReport,
  unacknowledgedRows,
} from "./staleness.js";

export type RunOptions = {
  nodesDir: string;
  snapshotsDir: string;
  reportPath: string;
  ackPath: string;
  fetchAuthority?: AuthorityFetcher;
  nowIso?: string;
};

const urlKey = (url: string): string => createHash("sha256").update(url).digest("hex");

const snapshotFetcher = (snapshotsDir: string, nowIso: string): AuthorityFetcher => async (
  cite: PinnedCitation,
) => {
  const path = join(snapshotsDir, `${urlKey(cite.source_url)}.txt`);
  if (!existsSync(path)) {
    throw new Error(
      `staleness check: snapshot missing for ${cite.source_url} at ${path}; vendor a snapshot or run with --online`,
    );
  }
  return { text: readFileSync(path, "utf8"), fetched_at: nowIso };
};

export function loadNodes(nodesDir: string): V3DkbNode[] {
  if (!existsSync(nodesDir)) return [];
  const out: V3DkbNode[] = [];
  for (const f of readdirSync(nodesDir)) {
    if (!f.endsWith(".json")) continue;
    const raw = JSON.parse(readFileSync(join(nodesDir, f), "utf8")) as unknown;
    if (Array.isArray(raw)) {
      out.push(...V3DkbNodeListSchema.parse(raw));
    } else {
      out.push(...V3DkbNodeListSchema.parse([raw]));
    }
  }
  return out;
}

export function loadAcks(path: string): AcknowledgmentEntry[] {
  if (!existsSync(path)) return [];
  const parsed = YAML.load(readFileSync(path, "utf8"), { schema: YAML.FAILSAFE_SCHEMA });
  const list = (parsed as { acknowledgments?: unknown } | null)?.acknowledgments;
  if (!Array.isArray(list)) return [];
  return list
    .filter(
      (e): e is AcknowledgmentEntry =>
        typeof e === "object" &&
        e !== null &&
        typeof (e as Record<string, unknown>).node_id === "string" &&
        typeof (e as Record<string, unknown>).citation === "string" &&
        typeof (e as Record<string, unknown>).ack === "string",
    )
    .map((e) => ({ node_id: e.node_id, citation: e.citation, ack: e.ack }));
}

export async function runStalenessCheck(
  opts: RunOptions,
): Promise<{ report: StalenessReport; unacknowledged: ReturnType<typeof unacknowledgedRows> }> {
  const nowIso = opts.nowIso ?? new Date().toISOString();
  const nodes = loadNodes(opts.nodesDir);
  const fetchAuthority = opts.fetchAuthority ?? snapshotFetcher(opts.snapshotsDir, nowIso);
  const report = await detectStaleness({ nodes, fetchAuthority, nowIso });
  writeFileSync(opts.reportPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  const acks = loadAcks(opts.ackPath);
  const unacknowledged = unacknowledgedRows(report, acks);
  return { report, unacknowledged };
}

// CLI entrypoint
const isMain = (): boolean => {
  const argv1 = process.argv[1];
  if (!argv1) return false;
  return argv1.endsWith("check-staleness.ts") || argv1.endsWith("check-staleness.js");
};

if (isMain()) {
  const repoRoot = process.cwd();
  const opts: RunOptions = {
    nodesDir: process.env.V3_NODES_DIR ?? join(repoRoot, "dkb", "fixtures", "v3", "nodes"),
    snapshotsDir:
      process.env.V3_SNAPSHOTS_DIR ?? join(repoRoot, "dkb", "fixtures", "v3", "snapshots"),
    reportPath:
      process.env.V3_STALENESS_REPORT ?? join(repoRoot, "dkb", "fixtures", "v3", "staleness-report.json"),
    ackPath: process.env.V3_STALENESS_ACK ?? join(repoRoot, "dkb-staleness-ack.yml"),
  };

  runStalenessCheck(opts)
    .then(({ report, unacknowledged }) => {
      process.stdout.write(
        `staleness: ${report.stale_citations} stale citations across ${report.stale_nodes} nodes; ` +
          `${unacknowledged.length} unacknowledged\n`,
      );
      if (unacknowledged.length > 0) {
        for (const r of unacknowledged) {
          process.stderr.write(`UNACK ${r.node_id} :: ${r.citation} :: ${r.diff_url}\n`);
        }
        process.exit(1);
      }
    })
    .catch((err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(`staleness check failed: ${msg}\n`);
      process.exit(2);
    });
}
