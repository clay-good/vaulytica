/**
 * CC-008 / CC-009 false-positive ratchet.
 *
 * The two paired privacy-notice ↔ DPA rules accuse a controller of telling
 * data subjects something its own contract contradicts. That is the loudest
 * kind of finding the cross-document engine can emit, so the standing
 * requirement is that it never fires on a well-drafted pair.
 *
 * This sweep crosses EVERY notice-family specimen in the golden corpora with
 * EVERY DPA-family specimen — every pair a user could plausibly drop together
 * — and holds the finding count at zero. All of those specimens are compliant
 * documents: they disclose their recipients and their transfers, which is
 * exactly what CC-008/CC-009 test for the absence of.
 *
 * 🚨 A zero over an empty or inert cross-product proves nothing, so the
 * POSITIVE CONTROL below is not optional: the same sweep, with one notice
 * rewritten to make the unqualified promise, must fire both rules. Without it
 * a pattern that had stopped matching anything at all would read as a pass.
 *
 * The closest real near-miss is `privacy-policy-lint-minimal-pass.txt`'s
 * "We do not share your personal information for cross-context behavioral
 * advertising" — a CCPA-specific denial of ad-sharing, not of disclosure as
 * such, and the same paragraph goes on to name the service providers it does
 * share with. CC-008 requires a third-party recipient as the object of the
 * denial, so it correctly stays silent.
 */

import { describe, expect, it } from "vitest";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ingestPaste } from "../../src/ingest/paste.js";
import { extractAll } from "../../src/extract/index.js";
import { loadStarterDkbSync } from "../../src/engine/_test-fixtures.js";
import { runConsistency } from "../../src/engine/consistency/runner.js";
import {
  CC_008_PRIVACY_NOTICE_DISCLOSURE,
  CC_009_PRIVACY_NOTICE_TRANSFERS,
} from "../../src/engine/consistency/rules/index.js";
import { kindOf } from "../../src/engine/consistency/_helpers.js";
import type { ConsistencyDocument } from "../../src/engine/consistency/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..", "..");
const FIXTURE_DIRS = [
  join(ROOT, "tests", "golden", "v3", "fixtures"),
  join(ROOT, "tests", "golden", "v4", "fixtures"),
];

const RULES = [CC_008_PRIVACY_NOTICE_DISCLOSURE, CC_009_PRIVACY_NOTICE_TRANSFERS];

async function loadSpecimen(dir: string, file: string): Promise<ConsistencyDocument> {
  const sidecar = join(dir, `${file}.playbook`);
  const playbook_id = existsSync(sidecar)
    ? readFileSync(sidecar, "utf8").trim()
    : "generic-fallback";
  const ingest = await ingestPaste(readFileSync(join(dir, file), "utf8"));
  return {
    doc_id: file,
    source_file_name: file,
    playbook_id,
    tree: ingest.tree,
    extracted: extractAll(ingest.tree),
  };
}

const specimens: ConsistencyDocument[] = [];
for (const dir of FIXTURE_DIRS) {
  for (const file of readdirSync(dir).sort()) {
    if (!file.endsWith(".txt")) continue;
    specimens.push(await loadSpecimen(dir, file));
  }
}

const notices = specimens.filter((d) => kindOf(d) === "privacy_policy");
const dpas = specimens.filter((d) => kindOf(d) === "dpa");

const dkb = loadStarterDkbSync();

async function sweep(noticeSet: readonly ConsistencyDocument[]): Promise<string[]> {
  const hits: string[] = [];
  for (const notice of noticeSet) {
    for (const dpa of dpas) {
      const run = await runConsistency({
        rules: RULES,
        documents: [
          { ...notice, doc_id: "notice" },
          { ...dpa, doc_id: "dpa" },
        ],
        dkb,
      });
      for (const f of run.findings) {
        hits.push(`${f.rule_id} ${notice.source_file_name} × ${dpa.source_file_name}`);
      }
    }
  }
  return hits;
}

describe("CC-008 / CC-009 across every notice × DPA pair in the corpora", () => {
  it("the cross-product is real (anti-vacuity)", () => {
    expect(notices.length).toBeGreaterThanOrEqual(5);
    expect(dpas.length).toBeGreaterThanOrEqual(50);
  });

  it("fires on no well-drafted pair", async () => {
    const hits = await sweep(notices);
    expect(hits, hits.join("\n")).toEqual([]);
  }, 120_000);

  it("POSITIVE CONTROL: the same sweep fires when a notice makes the unqualified promise", async () => {
    // Take a real notice and replace its disclosure and transfer sections with
    // the promises CC-008/CC-009 exist to catch. If this does not fire, the
    // zero above is a pattern that matches nothing, not a corpus that is clean.
    const base = notices[0]!;
    const contradictory = await ingestPaste(
      [
        "Privacy Notice",
        "",
        "Who We Share Your Data With. We do not share your personal information with third parties.",
        "",
        "International Transfers. We do not transfer your personal data outside the European Economic Area.",
      ].join("\n"),
    );
    const planted: ConsistencyDocument = {
      ...base,
      doc_id: "planted",
      source_file_name: "planted-notice.txt",
      tree: contradictory.tree,
      extracted: extractAll(contradictory.tree),
    };
    const hits = await sweep([planted]);
    expect(hits.some((h) => h.startsWith("CC-008"))).toBe(true);
    expect(hits.some((h) => h.startsWith("CC-009"))).toBe(true);
  }, 120_000);
});
