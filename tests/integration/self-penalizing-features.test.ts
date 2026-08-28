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
import { EXPECTED } from "./specimen-regression.test.js";

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

/**
 * The second half of the same invariant, and the half the substring test
 * cannot see.
 *
 * Seven of the negative features fixed on 2026-08-28 were not substrings of
 * their own playbook's features — they were phrases from the family's own
 * BOILERPLATE, which no amount of reading the playbook can reveal:
 * `written-consent` listed "bylaws", the recital every DGCL § 141(f) consent
 * opens on; `prenuptial-agreement` listed "during the marriage", which is what
 * a premarital agreement is about (it scored 0.4 and routed to a DIVORCE
 * settlement); `security-agreement`, `escrow-agreement`, and
 * `payment-performance-bond` each listed the instrument they exist to secure
 * or serve; `patent-assignment` listed "trademark", which is inside the name
 * of the office it asks to record it.
 *
 * The specimens are what make this checkable: each is a realistic document of
 * a known family, so a negative feature appearing in one is, by definition, a
 * penalty the family charges itself.
 */
describe("negative features against the family's own specimen", () => {
  const DIR = join(process.cwd(), "tests", "fixtures", "specimens");
  const byId = new Map(PLAYBOOKS.map((p) => [p.id, p]));

  it.each(Object.entries(EXPECTED))("%s", (file, expectation) => {
    const playbook = byId.get(expectation.playbook);
    if (!playbook) return; // a launch playbook not in the extended bundle
    const text = readFileSync(join(DIR, file), "utf8").toLowerCase();
    const offending = playbook.match_features.negative_features.filter((n) =>
      text.includes(n.toLowerCase()),
    );
    expect(
      offending,
      `${expectation.playbook} penalizes its own document for: ${offending.join(", ")}`,
    ).toEqual([]);
  });
});
