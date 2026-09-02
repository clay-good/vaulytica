/**
 * A specimen must BEAT its runner-up, not tie it.
 *
 * `specimen-regression.test.ts` asserts the family a document routes to and
 * that it matched at 0.6 or better. Neither says anything about the gap to the
 * next family, and a tie is decided by a lexicographic comparison of the two
 * ids — which is arbitrary, and which is how two real documents went wrong:
 *
 *   - A voting agreement tied `stockholders-agreement` at 0.5, lost the
 *     tiebreak, and was told at `critical` that it had no voting-agreement
 *     clause.
 *   - A Rule 26(f) joint report tied `complaint` at 0.6 and was told it
 *     demanded no relief and no jury trial.
 *
 * A tie means the catalog cannot tell the two apart on this document. That is
 * a defect in the catalog whichever way the tiebreak falls, so it is asserted
 * here rather than left to luck.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ingestPaste } from "../../src/ingest/paste.js";
import { extractAll } from "../../src/extract/index.js";
import { matchPlaybook, titleCorpus } from "../../src/playbooks/matcher.js";
import { parsePlaybook, parsePlaybooks } from "../../src/playbooks/loader.js";
import { loadStarterDkbSync } from "../../src/engine/_test-fixtures.js";

const SPECIMENS = join(process.cwd(), "tests", "fixtures", "specimens");
const PLAYBOOK_DIR = join(process.cwd(), "playbooks");
const launch = readdirSync(PLAYBOOK_DIR)
  .filter((f) => f.endsWith(".json") && f !== "extended.json")
  .map((f) => parsePlaybook(JSON.parse(readFileSync(join(PLAYBOOK_DIR, f), "utf8"))));
const extended = parsePlaybooks(
  JSON.parse(readFileSync(join(PLAYBOOK_DIR, "extended.json"), "utf8")),
);
const ALL = [...launch, ...extended];
const dkb = loadStarterDkbSync();

/**
 * Ties that are a real choice rather than a defect: the same document seen
 * from two sides, or under two regimes. Which one you want is your choice —
 * `--role`, `--playbook` — not the document's, and the catalog is right to
 * score them equally. Each needs its reason.
 */
const DECLARED_TIES = new Map<string, string>([
  [
    "order-form.txt:saas-vendor",
    "the customer and vendor packs read the same order form from two sides",
  ],
  [
    "saas-order-form-fields.txt:saas-vendor",
    "the same two sides, on a field-heavy order form issued under a master agreement",
  ],
  ["saas-tos.txt:saas-vendor", "the same two sides, on a set of published terms"],
  [
    "cloud-services-agreement.txt:saas-vendor",
    "the same two sides again, on a subscription agreement titled CLOUD SERVICES AGREEMENT — which lens you want is --role, not the document's",
  ],
  [
    "privacy-notice.txt:privacy-policy-lint",
    "the lint pack is a second lens on the same notice, not a rival family",
  ],
  [
    "privacy-notice-multistate.txt:privacy-policy-lint",
    "the same second lens; ADDENDA-020 now runs on both families, so which one wins costs the document nothing",
  ],
  [
    "loan-agreement.txt:revolving-credit-agreement",
    "a credit agreement can be a term loan or a revolver; this one is both-shaped and the document does not say which pack you want",
  ],
]);

const NAMES = readdirSync(SPECIMENS)
  .filter((f) => f.endsWith(".txt"))
  .sort();

describe("a specimen beats its runner-up", () => {
  it.each(NAMES)(
    "%s",
    async (name) => {
      const text = readFileSync(join(SPECIMENS, name), "utf8");
      const tree = (await ingestPaste(text)).tree;
      const extracted = extractAll(tree, {
        classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
      });
      const match = matchPlaybook(extracted, extracted.classified, ALL, {
        title: titleCorpus(tree, name),
        body_text: text,
      });
      // A generic-fallback document has nothing to beat.
      if (match.playbook_id === "generic-fallback") return;
      const runnerUp = match.alternatives?.[0];
      if (!runnerUp) return;
      if (DECLARED_TIES.has(`${name}:${runnerUp.playbook_id}`)) {
        expect(
          runnerUp.raw_confidence,
          `${name}: ${runnerUp.playbook_id} is declared a TIE, so it must still be one`,
        ).toBe(match.raw_confidence);
        return;
      }
      // A DEPRECATED runner-up that names the winner as its successor is not a
      // tie and is not luck: the matcher promotes a named successor over its
      // deprecated predecessor whenever the successor clears the threshold on
      // its own merits, so the winner is deterministic and is expected to
      // score LOWER. `mutual-nda` out-scores `mutual-nda-deep` on every NDA —
      // the legacy family carries `required_clauses` and the successor carries
      // none — which is exactly why the tiebreak-only mechanism never fired.
      const runnerUpPb = ALL.find((p) => p.id === runnerUp.playbook_id);
      if (runnerUpPb?.deprecated === true && runnerUpPb.superseded_by === match.playbook_id) return;
      // The RAW score is what decides the ranking. `confidence` is clamped to
      // 1, so two families can both display 1 while one outscores the other by
      // a wide margin — reading the clamped value called a 1.2-vs-1.0 win a
      // coin flip. Compare what the matcher actually sorts on.
      expect(
        runnerUp.raw_confidence,
        `${name} routes to ${match.playbook_id} at ${match.raw_confidence}, tied by ${runnerUp.playbook_id} at ${runnerUp.raw_confidence} — the tiebreak is a lexicographic id comparison, so which one wins is luck`,
      ).toBeLessThan(match.raw_confidence);
    },
    120_000,
  );
});
