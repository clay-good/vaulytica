/**
 * The clean-document method, applied to the CROSS-DOCUMENT engine.
 *
 * Fifteen complete, well-drafted single documents have been authored against
 * the per-document rules, and each one paid: a document written to be correct
 * turns every finding it draws into a candidate defect. The cross-document
 * engine had never been given the same test. Its bundles are one-defect
 * fixtures — two documents of a dozen lines each, built to make exactly one
 * CROSS-* rule fire — and the only "clean" one is twenty-four lines long.
 *
 * `tests/golden/v4/bundles/clean-deal-room/` is a deliberately CONSISTENT deal
 * room: a master services agreement, a statement of work and an order form
 * issued under it, a data processing addendum that forms part of it, and the
 * customer's published privacy notice. Same parties, same
 * governing law and venue, same currency, same liability cap and the same
 * carve-outs, the same five-year confidentiality survival in both the MSA and
 * the DPA, the same order of precedence stated identically in all three, and
 * dates in the order a real engagement signs them — the MSA and the DPA on
 * January 15, the SOW on February 1.
 *
 * So the whole bundle must draw NOTHING. Every conflict it reports is a false
 * accusation about a pair of contracts that agree.
 *
 * It found one on its first run. CROSS-DATE-001 called the MSA's reference to
 * "each Statement of Work" a chronology paradox, because the SOW is dated after
 * the master that anticipates it — which is what a master agreement is for.
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

const DIR = join(process.cwd(), "tests", "golden", "v4", "bundles", "clean-deal-room");
const dkb = loadStarterDkbSync();

describe("a deal room that agrees with itself", () => {
  it("reports no cross-document conflict", async () => {
    const files = readdirSync(DIR)
      .filter((f) => f.endsWith(".txt"))
      .sort();
    expect(files, "the clean deal room lost its members").toEqual([
      "dpa.txt",
      "msa.txt",
      "order-form.txt",
      "privacy-notice.txt",
      "sow.txt",
    ]);

    const documents: ConsistencyDocument[] = [];
    for (const file of files) {
      const ingest = await ingestPaste(readFileSync(join(DIR, file), "utf8"));
      const sidecar = join(DIR, `${file}.playbook`);
      documents.push({
        doc_id: file,
        source_file_name: file,
        playbook_id: existsSync(sidecar)
          ? readFileSync(sidecar, "utf8").trim()
          : "generic-fallback",
        tree: ingest.tree,
        extracted: extractAll(ingest.tree),
      });
    }

    const run = await runConsistency({ rules: ALL_CONSISTENCY_RULES, documents, dkb });

    // 🚨 ANTI-VACUITY. A relation whose assertion is "nothing was reported"
    // passes hardest when nothing RAN — the failure this repo has met on a
    // leak-scan invariant and on its own reach guard. The bundle is built to
    // give twenty of the twenty-two cross-document rules something to compare,
    // and the two that stay behind are the BAA pair (CC-001, CC-004): a food
    // distributor's analytics engagement has no protected health information,
    // and `clean-msa-baa` is where that pairing lives.
    const ran = run.execution_log.filter((e) => e.ran).map((e) => e.rule_id);
    expect(
      ran.length,
      `only ${ran.length} cross-document rules had anything to compare — the bundle stopped exercising the engine`,
    ).toBeGreaterThanOrEqual(20);
    expect(
      run.execution_log.filter((e) => !e.ran).map((e) => e.rule_id),
      "a rule stopped running — check whether the bundle still carries the documents it requires",
    ).toEqual(["CC-001", "CC-004"]);
    const conflicts = run.findings.map(
      (f) =>
        `${f.rule_id}[${[...new Set(f.excerpts.map((e) => e.doc_id))].sort().join("+")}]: ${f.title}`,
    );
    expect(
      conflicts,
      `these three documents agree — every conflict is a false one:\n  ${conflicts.join("\n  ")}`,
    ).toEqual([]);
  }, 120_000);
});
