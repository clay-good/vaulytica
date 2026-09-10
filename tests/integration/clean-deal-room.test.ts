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
 *
 * `clean-deal-room-phi/` is the second room, and it exists for the two rules the
 * first cannot reach: CC-001 and CC-004 compare a BAA against the MSA it hangs
 * off, and a food distributor's analytics engagement has no protected health
 * information. A clinical-analytics MSA, its SOW, and a HIPAA business associate
 * agreement whose permitted uses are the MSA's purpose word for word, and whose
 * term is the MSA's term. Between the two rooms every one of the twenty-two
 * cross-document rules is exercised by drafting that agrees with itself.
 *
 * It found one too: CROSS-DEFTERM-002 read the "Business Associate" in
 * "the Business Associate Agreement" as a borrowed defined term.
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

const dkb = loadStarterDkbSync();

interface Room {
  readonly dir: string;
  readonly members: readonly string[];
  /** The rules that cannot reach this room, and why the room is right to lack them. */
  readonly unreachable: readonly string[];
}

const ROOMS: readonly Room[] = [
  {
    dir: "clean-deal-room",
    members: ["dpa.txt", "msa.txt", "order-form.txt", "privacy-notice.txt", "sow.txt"],
    // The BAA pair: a food distributor's analytics engagement has no PHI.
    unreachable: ["CC-001", "CC-004"],
  },
  {
    dir: "clean-deal-room-phi",
    members: ["baa.txt", "msa.txt", "sow.txt"],
    // The DPA pair and the privacy-notice pair: this room is HIPAA, not GDPR,
    // and carries no published notice.
    unreachable: ["CC-002", "CC-003", "CC-008", "CC-009"],
  },
];

describe.each(ROOMS)("a deal room that agrees with itself — $dir", (room) => {
  it("reports no cross-document conflict", async () => {
    const dir = join(process.cwd(), "tests", "golden", "v4", "bundles", room.dir);
    const files = readdirSync(dir)
      .filter((f) => f.endsWith(".txt"))
      .sort();
    expect(files, "the clean deal room lost its members").toEqual([...room.members]);

    const documents: ConsistencyDocument[] = [];
    for (const file of files) {
      const ingest = await ingestPaste(readFileSync(join(dir, file), "utf8"));
      const sidecar = join(dir, `${file}.playbook`);
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
    // leak-scan invariant and on its own reach guard. Both halves are pinned:
    // which rules had something to compare, and which could not reach this room.
    expect(
      run.execution_log.filter((e) => !e.ran).map((e) => e.rule_id),
      "a rule stopped running — check whether the room still carries the documents it requires",
    ).toEqual([...room.unreachable]);
    expect(
      run.execution_log.filter((e) => e.ran).length,
      "too few cross-document rules had anything to compare",
    ).toBeGreaterThanOrEqual(ALL_CONSISTENCY_RULES.length - room.unreachable.length);

    const conflicts = run.findings.map(
      (f) =>
        `${f.rule_id}[${[...new Set(f.excerpts.map((e) => e.doc_id))].sort().join("+")}]: ${f.title}`,
    );
    expect(
      conflicts,
      `these documents agree — every conflict is a false one:\n  ${conflicts.join("\n  ")}`,
    ).toEqual([]);
  }, 120_000);
});

// Between the two rooms, every shipped cross-document rule is exercised by
// drafting that agrees with itself. A rule that no clean room can reach has
// never been shown to stay quiet on a correct bundle.
it("between them, the rooms reach every cross-document rule", () => {
  const unreached = ALL_CONSISTENCY_RULES.map((r) => r.id).filter((id) =>
    ROOMS.every((room) => room.unreachable.includes(id)),
  );
  expect(unreached, "no clean deal room exercises these rules").toEqual([]);
});
