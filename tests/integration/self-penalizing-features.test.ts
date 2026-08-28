/**
 * A playbook may not penalize its own vocabulary.
 *
 * `negative_features` are the matcher's counter-signal: −0.1 each, for text
 * that means "this is some OTHER family's document". A negative feature that
 * appears in the family's own name, its own title keywords, or its own
 * distinguishing phrases is therefore self-contradictory — it subtracts from
 * the very documents the playbook exists to win.
 *
 * Four shipped that way, and one of them is the substring bug in its purest
 * form: `irrevocable-trust` listed **"revocable"**, which is inside
 * "irrevocable". Features longer than an acronym are matched as plain
 * substrings, so every irrevocable trust took the penalty on its own name,
 * printed on every page. `loi-term-sheet` listed "definitive agreement" as
 * both a distinguishing phrase (+0.2) and a negative feature (−0.1) — the
 * sentence every term sheet ends on. `trademark-assignment` listed "patent",
 * while its own longest distinguishing phrase is "recordation with the united
 * states patent and trademark office". `deed-of-trust` listed "security
 * agreement", which is inside its own title keyword "mortgage and security
 * agreement", the ordinary title of a commercial deed of trust.
 *
 * The invariant is mechanical and needs no judgment: whatever a playbook
 * offers as evidence FOR itself cannot also be evidence against.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parsePlaybook, parsePlaybooks } from "../../src/playbooks/loader.js";
import { LAUNCH_PLAYBOOK_IDS } from "../../src/playbooks/registry.js";

const PLAYBOOKS = [
  ...parsePlaybooks(
    JSON.parse(readFileSync(join(process.cwd(), "playbooks", "extended.json"), "utf8")),
  ),
  ...LAUNCH_PLAYBOOK_IDS.map((id) =>
    parsePlaybook(JSON.parse(readFileSync(join(process.cwd(), "playbooks", `${id}.json`), "utf8"))),
  ),
];

describe("negative features", () => {
  it("the catalog is loaded", () => {
    expect(PLAYBOOKS.length).toBeGreaterThan(200);
  });

  it.each(PLAYBOOKS.map((p) => [p.id, p] as const))(
    "%s does not list a negative feature drawn from its own vocabulary",
    (_id, playbook) => {
      const f = playbook.match_features;
      const own = [
        playbook.name ?? "",
        ...f.title_keywords,
        ...f.distinguishing_phrases,
        ...f.required_clauses,
      ]
        .map((s) => s.toLowerCase())
        .filter((s) => s.length > 0);

      const offending = f.negative_features
        .map((n) => n.toLowerCase())
        .flatMap((n) => own.filter((o) => o.includes(n)).map((o) => `"${n}" inside "${o}"`));

      expect(offending, `${playbook.id} penalizes itself: ${offending.join("; ")}`).toEqual([]);
    },
  );
});
