/**
 * A distinguishing phrase has to distinguish.
 *
 * `distinguishing_phrases` are worth 0.2 each (capped at three) against a 0.5
 * threshold, so three phrases carry a playbook over the line on their own. A
 * phrase that appears in most documents therefore hands 0.6 to a playbook the
 * document has nothing to do with.
 *
 * cease-and-desist listed "infringement", "trademark", "copyright", and
 * "patent" — every IP document on earth contains them — and an internal IP
 * portfolio memorandum addressed to a board WON that playbook at 0.5. snda
 * listed "attorn", which matches "attorney". internship-agreement listed
 * "intern", which matches "internal" and "Internet". ai-addendum listed
 * "prompt", which matches "promptly".
 *
 * The specimen corpus is the measuring stick: thirty-odd hand-written
 * documents of unrelated kinds. A phrase present in more than a quarter of
 * them is not distinguishing anything, and either belongs in
 * `title_keywords` (where it competes on identity) or does not belong at all.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parsePlaybook, parsePlaybooks } from "../../src/playbooks/loader.js";
import { LAUNCH_PLAYBOOK_IDS } from "../../src/playbooks/registry.js";

const PLAYBOOKS = parsePlaybooks(
  JSON.parse(readFileSync(join(process.cwd(), "playbooks", "extended.json"), "utf8")),
);
const LAUNCH = LAUNCH_PLAYBOOK_IDS.map((id) =>
  parsePlaybook(JSON.parse(readFileSync(join(process.cwd(), "playbooks", `${id}.json`), "utf8"))),
);

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");
const CORPUS = readdirSync(DIR)
  .filter((n) => n.endsWith(".txt"))
  .map((n) => readFileSync(join(DIR, n), "utf8").toLowerCase());

/**
 * More than a seventh of unrelated documents.
 *
 * Was 0.28 — "more than a quarter" — until 9.510.0. The quarter was a
 * defensible line and it left a whole tier underneath it: twelve phrases
 * between a seventh and a quarter of the corpus, every one a bare common word
 * ("warranty", "indemnification", "manager", "owner", "contractor", "grant",
 * "definitions", "commission", "release", "disclosure"). They were invisible
 * to this guard and expensive downstream, because a distinguishing phrase does
 * not only feed the 0.5 routing threshold — it also counts toward
 * `familyIsPresent`'s three-signal bar, which runs a family's WHOLE RULE PACK
 * as a secondary scan. Dropping the twelve removed **100 findings, 49 of them
 * CRITICAL**, from 19 specimens, and moved **zero** routing decisions on the
 * specimen corpus or the golden fixtures.
 */
const MAX_SHARE = 0.15;

/**
 * Broad phrases already in the catalog, each with the reason it stays. These
 * are debt, not design: every one of them is a candidate for replacement by a
 * phrase in the document's own register, and none may be added to.
 */
const KNOWN_BROAD = new Map<string, string>([
  // The party's NAME in the instrument, not a topic word.
  ["principal", "the grantor of a power of attorney and the obligee of a bond are 'the Principal'"],
  // Pleading elements and defined roles, argued in the document that owns them.
  // "jurisdiction" came off `complaint` in 9.149.0, with "plaintiff", "venue",
  // and "jury": all four are the words of every commercial contract's own
  // governing-law and dispute clauses, and a Rule 26(f) joint report routed to
  // `complaint` on them and was told at `critical` that it demanded no relief
  // and no jury.
  ["consent", "the operative act of a cookie notice"],
  ["purpose", "the operative disclosure of a PHI authorization"],
  ["exclusive", "the operative grant word of a copyright license"],
  ["indemnify", "the operative verb of a standalone indemnification agreement"],
  ["authorize", "the operative verb of a background-check disclosure"],
  ["received", "the operative verb of a notice-of-privacy-practices acknowledgment"],
  ["confidential", "the subject of a stipulated protective order"],
  ["assignment", "the operative act of a PIIA"],
  ["schedule", "a disclosure schedule is named for it"],
  // Surfaced by the 0.28 → 0.15 tightening. Unlike the twelve dropped in the
  // same change, each of these IS the family's term of art rather than a
  // common word that happens to appear in it — the test the docs state, and
  // the one frequency alone cannot make.
  [
    "hold harmless",
    "the family's own name; high because many contracts carry the clause it detects",
  ],
  // "agent" was here, on the same reasoning as "principal" — and it was the
  // reasoning that was wrong. A healthcare POA's Agent is named "the health
  // care agent"; the bare noun is the escrow agent, the registered agent and
  // the agent of every commercial party. With "hipaa" beside it, three words
  // of ordinary commercial English put `healthcare-poa` at the full 0.6 on an
  // enterprise software licence with a BAA (9.643.0). Retired in favor of the
  // family's own collocations.
  // 🚨 Broad, and MEASURED AS LOAD-BEARING. Dropping it re-routes
  // `settlement-confidential-minimal` and
  // `settlement-confidential-missing-consideration-fail` to `mutual-release`
  // at 0.70 — a golden fixture landing in the wrong family. Narrowing it to a
  // phrase in the document's own register is the real fix; deleting it is not.
  [
    "confidentiality",
    "load-bearing: without it two confidential-settlement golden fixtures route to mutual-release",
  ],
]);

function contains(corpus: string, feature: string): boolean {
  const needle = feature.toLowerCase();
  if (needle.length > 5 || !/^[a-z0-9][a-z0-9.-]*$/.test(needle)) return corpus.includes(needle);
  const escaped = needle.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(?:^|[^a-z0-9])${escaped}(?![a-z0-9])`, "i").test(corpus);
}

describe("distinguishing phrases against the specimen corpus", () => {
  it("no phrase matches more than a quarter of unrelated documents", () => {
    expect(CORPUS.length, "the specimen corpus is missing").toBeGreaterThan(20);
    const limit = CORPUS.length * MAX_SHARE;
    const broad: string[] = [];
    for (const pb of [...LAUNCH, ...PLAYBOOKS]) {
      for (const phrase of pb.match_features.distinguishing_phrases) {
        const key = phrase.toLowerCase();
        if (KNOWN_BROAD.has(key)) continue;
        const hits = CORPUS.filter((doc) => contains(doc, phrase)).length;
        if (hits > limit) {
          broad.push(`${pb.id}: "${phrase}" matches ${hits}/${CORPUS.length} specimens`);
        }
      }
    }
    expect(
      broad.sort(),
      `these phrases do not distinguish — move them to title_keywords, narrow them, or drop them:\n  ${broad.sort().join("\n  ")}`,
    ).toEqual([]);
  }, 60_000);

  it("every allowlisted phrase is still in the catalog", () => {
    // An allowlist that outlives its phrase silently permits a future
    // reintroduction of the same broad word somewhere else.
    const live = new Set(
      [...LAUNCH, ...PLAYBOOKS].flatMap((pb) =>
        pb.match_features.distinguishing_phrases.map((p) => p.toLowerCase()),
      ),
    );
    const stale = [...KNOWN_BROAD.keys()].filter((k) => !live.has(k));
    expect(stale, `allowlisted phrases no longer in any playbook: ${stale.join(", ")}`).toEqual([]);
  });
});
