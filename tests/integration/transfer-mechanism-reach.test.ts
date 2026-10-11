/**
 * Every transfer mechanism the engine can name, and whether it has ever named it.
 *
 * 🚨 **All four SCC MODULE detectors were dead** — zero firings across the
 * whole specimen corpus, including `scc-module-2.txt` and `scc-module-3.txt`,
 * two specimens named for their module. Every transfer in the corpus was
 * reported as "EU SCC (module unspecified)", so the §56 page told its reader
 * the document had not said which module it adopted while the document said so
 * in its own title. Nothing noticed, because
 * `v3-extractor-base-rate.test.ts` measures how much of the corpus each
 * EXTRACTOR claims, and this extractor's reach was fine — it was the
 * classification inside it that was broken. A detector can be dead inside a
 * healthy extractor.
 *
 * 🥇 **A silent kind is only allowed if the corpus contains none of its
 * vocabulary**, and the vocabulary below is written INDEPENDENTLY of the
 * patterns it guards. Checking a kind's own pattern against the corpus would
 * be circular — a dead pattern matches nothing, which is exactly what it must
 * prove. Writing the words out by hand is what makes this a test: had it
 * existed, `scc-module-2`'s entry would have found "Module Two" in two
 * specimens and demanded to know why the kind never fired.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ingestPaste } from "../../src/ingest/paste.js";
import { extractTransferMechanisms } from "../../src/extract/v3/transfer-mechanism.js";
import type { TransferMechanismKind } from "../../src/extract/v3/types.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

/**
 * Documents each kind is identified in. Committed by EQUALITY: widening a
 * detector means raising a number on purpose, and narrowing one means lowering
 * it on purpose. Measured 2026-10-11 over the specimen corpus.
 */
const REACH: Partial<Record<TransferMechanismKind, number>> = {
  "uk-addendum": 5,
  "scc-module-2": 4,
  "scc-module-3": 3,
  "scc-unspecified": 3,
  "uk-idta": 1,
  "adequacy-decision": 1,
};

/**
 * The kinds the corpus has no transfer of, with the words a drafter would have
 * to write for one — hand-written, not taken from the patterns.
 *
 * Modules One and Four are the controller-to-controller and
 * processor-to-controller transfers; the corpus has neither, which is ordinary
 * (a processor exporting back to its own controller is rare drafting). The
 * other six are mechanisms no specimen invokes.
 */
const ABSENT: Record<string, RegExp> = {
  "scc-module-1": /\bmodule\s+(?:1|one)\b|\bcontroller\s+to\s+controller\b/i,
  "scc-module-4": /\bmodule\s+(?:4|four)\b|\bprocessor\s+to\s+controller\b/i,
  "swiss-addendum": /\bswiss\b/i,
  "binding-corporate-rules": /\bbinding\s+corporate\s+rules\b|\bBCRs?\b/i,
  "article-49-derogation": /\bartic(?:le)?\.?\s*49\b/i,
  "data-privacy-framework": /\bdata\s+privacy\s+framework\b|\bDPF\b/i,
  "privacy-shield": /\bprivacy\s+shield\b/i,
  unknown: /\b(?:^\b)$/,
};

describe("transfer-mechanism reach over the specimen corpus", () => {
  it("names every kind the corpus contains, and only stays silent where the words are absent", async () => {
    const files = readdirSync(DIR)
      .filter((f) => f.endsWith(".txt"))
      .sort();
    const hits = new Map<string, number>();
    const vocabularyFound: string[] = [];

    for (const file of files) {
      const raw = readFileSync(join(DIR, file), "utf8");
      const ingest = await ingestPaste(raw);
      for (const kind of new Set(extractTransferMechanisms(ingest.tree).map((r) => r.kind))) {
        hits.set(kind, (hits.get(kind) ?? 0) + 1);
      }
      // A kind declared absent whose words turn up is the tripwire.
      for (const [kind, rx] of Object.entries(ABSENT)) {
        if (rx.test(raw)) vocabularyFound.push(`${kind} in ${file}`);
      }
    }

    // Anti-vacuity: a harness that ingested nothing reports every kind silent,
    // which is indistinguishable from fourteen dead detectors.
    expect(files.length).toBeGreaterThan(300);
    expect([...hits.values()].reduce((a, b) => a + b, 0)).toBeGreaterThan(10);

    expect(Object.fromEntries([...hits.entries()].sort())).toEqual(
      Object.fromEntries(Object.entries(REACH).sort()),
    );

    // Every silent kind must be silent because the corpus says nothing a
    // drafter would say to invoke it — never because its detector is broken.
    expect(vocabularyFound).toEqual([]);
    for (const kind of Object.keys(ABSENT)) expect(hits.has(kind)).toBe(false);
  }, 300_000);
});
