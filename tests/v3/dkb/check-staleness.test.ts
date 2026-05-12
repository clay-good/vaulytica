import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  loadAcks,
  runStalenessCheck,
} from "../../../dkb/build/v3/check-staleness.js";
import { sha256Hex } from "../../../dkb/build/v3/staleness.js";

const NOW = "2026-05-12T00:00:00Z";

let dir: string;
let nodesDir: string;
let reportPath: string;
let ackPath: string;

const sampleText = "Authority text 1";
const pinnedHash = sha256Hex(sampleText);

const node = {
  id: "test-node",
  node_type: "statutory_clause_requirement" as const,
  dkb_node_version: 1,
  dkb_node_last_validated_at: NOW,
  regulator: "Reg",
  jurisdiction: "us-federal",
  authority: "auth",
  citation: "Cite 1",
  effective_date: "2024-01-01",
  requirement: "must",
  minimum_compliant_text: "shall",
  applies_to_document_types: ["BAA"],
  cites: [
    {
      authority: "auth",
      citation: "Cite 1",
      source_url: "https://example.gov/x",
      content_hash_at_pin: pinnedHash,
      fetched_at: NOW,
    },
  ],
};

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "vaul-stale-"));
  nodesDir = join(dir, "nodes");
  reportPath = join(dir, "report.json");
  ackPath = join(dir, "ack.yml");
  mkdirSync(nodesDir, { recursive: true });
  writeFileSync(join(nodesDir, "node.json"), JSON.stringify(node), "utf8");
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("runStalenessCheck", () => {
  it("writes a clean report when hashes match", async () => {
    writeFileSync(ackPath, "acknowledgments: []\n", "utf8");
    const { report, unacknowledged } = await runStalenessCheck({
      nodesDir,
      snapshotsDir: dir,
      reportPath,
      ackPath,
      fetchAuthority: async () => ({ text: sampleText, fetched_at: NOW }),
      nowIso: NOW,
    });
    expect(report.stale_citations).toBe(0);
    expect(unacknowledged).toHaveLength(0);
    const onDisk = JSON.parse(readFileSync(reportPath, "utf8")) as { stale_citations: number };
    expect(onDisk.stale_citations).toBe(0);
  });

  it("flags unacknowledged drift", async () => {
    writeFileSync(ackPath, "acknowledgments: []\n", "utf8");
    const { report, unacknowledged } = await runStalenessCheck({
      nodesDir,
      snapshotsDir: dir,
      reportPath,
      ackPath,
      fetchAuthority: async () => ({ text: "DIFFERENT", fetched_at: NOW }),
      nowIso: NOW,
    });
    expect(report.stale_citations).toBe(1);
    expect(unacknowledged).toHaveLength(1);
  });

  it("respects acknowledgments in the yml file", async () => {
    writeFileSync(
      ackPath,
      `acknowledgments:
  - node_id: "test-node"
    citation: "Cite 1"
    ack: "renumbered, no substantive change"
`,
      "utf8",
    );
    const { unacknowledged } = await runStalenessCheck({
      nodesDir,
      snapshotsDir: dir,
      reportPath,
      ackPath,
      fetchAuthority: async () => ({ text: "DIFFERENT", fetched_at: NOW }),
      nowIso: NOW,
    });
    expect(unacknowledged).toHaveLength(0);
  });
});

describe("loadAcks", () => {
  it("returns an empty list when file is missing", () => {
    expect(loadAcks(join(dir, "missing.yml"))).toEqual([]);
  });

  it("ignores malformed entries", () => {
    writeFileSync(
      ackPath,
      `acknowledgments:
  - node_id: "x"
    citation: "y"
    ack: "z"
  - notACK: true
`,
      "utf8",
    );
    expect(loadAcks(ackPath)).toHaveLength(1);
  });
});
