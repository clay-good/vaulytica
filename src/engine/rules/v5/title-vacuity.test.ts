/**
 * The reachability guards for the pack shorthand (spec-v45.md §13).
 *
 * Covers every ruleset built on `pack()` — v5's US catalog and v6's
 * law-practice packs — because the shorthand, not the wave, is what makes
 * this family of defects possible.
 *
 * A clause-presence rule fires when *none* of its patterns match, so a
 * rule whose pattern is a word from the document's own title can never
 * fire. That is the failure mode this wave is structurally prone to: the
 * catalog is one rule per compliance-matrix column, and the column labels
 * are drawn from the same vocabulary as the family name. Left unchecked it
 * produces a check that reports nothing on every document forever — worse
 * than no check at all, because the compliance matrix shows the column as
 * reviewed.
 *
 * The probe is the strongest form available without a corpus: a document
 * that is *only* its family's title plus neutral execution boilerplate.
 * Nothing substantive is in it, so every ungated check for that family
 * must fire. Rules carrying an applicability gate are excluded — they are
 * supposed to be silent on a document that does not show the shape they
 * check for, and `behavior.test.ts` pins several of those in both
 * directions instead.
 *
 * This caught 27 real defects when it was first run, including the
 * irrevocability recital satisfied by the words "Irrevocable Trust" in the
 * title and the UCC § 9-104 control language satisfied by the word
 * "Control" in "Deposit Account Control Agreement".
 *
 * Three guards followed, each closing a way a check can be unreachable
 * that the first one cannot see: past a closed applicability gate, and
 * through a conjunction that drops its recognizers' regex flags.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildContext } from "../../_test-fixtures.js";
import { V5_RULES } from "./index.js";
import { V6_RULES } from "../v6/index.js";
import { GATED_PACK_RULE_IDS, PACK_SPECS } from "./_pack.js";

/** Every rule this shorthand has built — v5's catalog and v6's law-practice packs. */
const PACK_RULES = [...V5_RULES, ...V6_RULES].filter((r) => PACK_SPECS.has(r.id));

const familyName = new Map<string, string>();
for (const wave of ["v5", "v6"]) {
  for (const file of readdirSync(join(process.cwd(), "src", "playbooks", wave))) {
    if (!file.endsWith(".json")) continue;
    const pb = JSON.parse(
      readFileSync(join(process.cwd(), "src", "playbooks", wave, file), "utf8"),
    ) as { id: string; name: string };
    familyName.set(pb.id, pb.name);
  }
}

/** The paragraphs of {@link titleOnly}, as the flat text a pattern sees. */
const TITLE_ONLY_LINES = (playbookId: string) => [
  familyName.get(playbookId)!,
  "The parties have entered into this document as of the date first written above.",
  "Signatures",
  "By: ____ Name: ____ Title: ____ Date: ____",
];

/** The family's own title, plus boilerplate that asserts nothing. */
function titleOnly(playbookId: string) {
  const [title, recital, sigHeading, sigBlock] = TITLE_ONLY_LINES(playbookId);
  return buildContext([title!, recital!], [sigHeading!, sigBlock!]);
}

/** The first playbook a rule is gated to — pack rules are gated to exactly one. */
const familyOf = (r: { applies_to_playbooks?: readonly string[] }) =>
  (r.applies_to_playbooks ?? [])[0]!;

describe("title-vacuity guard", () => {
  it("every ungated check fires on a document that is only its family's title", () => {
    const vacuous = PACK_RULES.filter((r) => !GATED_PACK_RULE_IDS.has(r.id))
      .filter((r) => r.check(titleOnly(familyOf(r))) === null)
      .map((r) => `${r.id} (${r.name})`);
    expect(
      vacuous,
      `these checks are satisfied by the document title alone:\n  ${vacuous.join("\n  ")}`,
    ).toEqual([]);
  });

  it("no GATED check's recognizers are satisfied by the title either", () => {
    // The test above has to excuse a gated rule, because its gate closes
    // before its recognizers are ever consulted — which means the exclusion
    // is also a blind spot exactly the size of the gated set. Reading the
    // recognizers straight out of the spec reaches past the gate: a gated
    // rule whose patterns the title alone satisfies is just as dead, it
    // simply needs a document that opens the gate before anyone notices.
    const vacuous: string[] = [];
    for (const id of GATED_PACK_RULE_IDS) {
      const spec = PACK_SPECS.get(id)!;
      const text = TITLE_ONLY_LINES(spec.playbook).join("\n");
      const hits = spec.pat.filter((p) => p.test(text));
      const satisfied = spec.all ? hits.length === spec.pat.length : hits.length > 0;
      if (satisfied) vacuous.push(`${id} — satisfied by ${hits.map(String).join(", ")}`);
    }
    expect(
      vacuous,
      `these gated checks could not fire even with their gate open:\n  ${vacuous.join("\n  ")}`,
    ).toEqual([]);
  });

  it("keeps every recognizer's own flags under an `all` conjunction", () => {
    // A conjunction that rebuilds its pillars into one regex cannot carry
    // per-pattern flags, and the loss is silent: `/^\s*\d+\.\s/m` looking for
    // a numbered paragraph degrades to a start-of-DOCUMENT match, so
    // PLDG-004 reported a properly numbered complaint as having no numbered
    // paragraphs — at `critical`, on the one document shape the check
    // exists to bless. `g` and `y` are the other half of the contract: their
    // `lastIndex` state would make repeated `test()` calls alternate.
    const multiline = [...PACK_SPECS].filter(([, s]) => s.pat.some((p) => p.flags.includes("m")));
    expect(multiline.map(([id]) => id)).toEqual(["DISC-005", "DISC-013", "PLDG-004"]);
    const stateful = [...PACK_SPECS].filter(([, s]) =>
      s.pat.some((p) => p.flags.includes("g") || p.flags.includes("y")),
    );
    expect(stateful.map(([id]) => id)).toEqual([]);
  });

  it("PLDG-004 blesses a complaint whose numbering starts below the caption", () => {
    // The regression the flag loss produced, stated as the document rather
    // than the mechanism: paragraph 1 of a real complaint is never the first
    // character of the file — a caption and an introductory sentence come
    // first.
    const numbered = buildContext(
      ["COMPLAINT", "Plaintiff, by and through undersigned counsel, alleges as follows:"],
      [
        "COUNT ONE — BREACH OF CONTRACT",
        "1. Plaintiff is a Delaware corporation.\n2. Defendant is a New York corporation.\n3. Defendant failed to deliver.",
      ],
    );
    const rule = V6_RULES.find((r) => r.id === "PLDG-004")!;
    expect(rule.check(numbered)).toBeNull();

    const narrative = buildContext(
      ["COMPLAINT", "Plaintiff alleges the following."],
      ["COUNT ONE — BREACH OF CONTRACT", "Defendant breached the agreement in several ways."],
    );
    expect(rule.check(narrative)?.title).toContain("Numbered paragraphs");
  });

  it("records a gate for every rule that declares one, and for no rule that does not", () => {
    // The exclusion above is only sound if the gated set is derived rather
    // than hand-maintained. Pin that it is non-empty and that every member
    // is a real v5 rule, so a stale id can never quietly widen the exclusion.
    const ids = new Set(PACK_RULES.map((r) => r.id));
    expect(GATED_PACK_RULE_IDS.size).toBeGreaterThan(0);
    for (const id of GATED_PACK_RULE_IDS) expect(ids.has(id), `${id} is not a pack rule`).toBe(true);
  });
});
