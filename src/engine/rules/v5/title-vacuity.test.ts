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
 *
 * A fourth followed those, and found 21 more. The boilerplate above is
 * STERILER THAN ANY REAL DOCUMENT — it has no entire-agreement clause, no
 * notices clause, no governing law, and no "IN WITNESS WHEREOF" — so a
 * check satisfied by ordinary execution language passed the vacuity probe
 * and was still dead in the field. `amend` is in every amendment clause,
 * `notice` in every notices clause, `state\s+of\s+\w+` in every
 * governing-law clause; `signed` and `authoriz` and `represent` and
 * `present` and `witness` and `author` are all inside the words a
 * signature block and an execution clause already contain. Every one of
 * the 21 was a rule whose own NAME states a conjunction ("Fee schedule
 * attached AND amendment notice") written as a synonym OR.
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
const NAME_OF = new Map(PACK_RULES.map((r) => [r.id, r.name]));

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
    for (const id of GATED_PACK_RULE_IDS)
      expect(ids.has(id), `${id} is not a pack rule`).toBe(true);
  });

  it("recognizes the hyphenated spelling of a compound its own name hyphenates", () => {
    // A QDRO says "This is a separate-interest order". EST-422's recognizer
    // was `separate\s+interest`, so the hyphen — the ordinary spelling when
    // the compound is used as an adjective, and the spelling the rule's OWN
    // NAME uses — did not match, and the check reported the method missing at
    // `critical` on a document that had stated it.
    //
    // The rule name is the oracle here, and a good one: an author who writes
    // "Separate-interest or shared-payment method" has already decided the
    // compound is hyphenated. Seventy-six distinct compounds across
    // ninety-seven patterns were blind to their own spelling. `[-\s]+` costs
    // nothing — a compound means the same thing hyphenated or spaced — and
    // this guard keeps the next one from shipping.
    const blind: string[] = [];
    for (const [id, spec] of PACK_SPECS) {
      for (const m of (NAME_OF.get(id) ?? "").matchAll(/\b([A-Za-z]{3,})-([A-Za-z]{3,})\b/g)) {
        const spaced = `${m[1]!} ${m[2]!}`;
        const hyphenated = `${m[1]!}-${m[2]!}`;
        for (const p of spec.pat) {
          const re = new RegExp(p.source, "i");
          if (re.test(spaced) && !re.test(hyphenated)) blind.push(`${id} — "${hyphenated}"`);
        }
      }
    }
    expect(blind, `patterns blind to their own name's hyphen:\n  ${blind.join("\n  ")}`).toEqual(
      [],
    );
  });
});

/**
 * Execution language every real document carries, and nothing substantive.
 * A check that goes silent on this cannot fire on a real document that is
 * missing the clause it looks for.
 */
const REAL_BOILERPLATE = [
  "The parties have entered into this document as of the date first written above.",
  "This document constitutes the entire agreement between the parties and supersedes all prior discussions. It may be amended only by a written agreement signed by both parties.",
  "Any notice under this document must be in writing and is effective upon receipt.",
  "This document is governed by the laws of the State of Delaware. If any provision is held invalid, the remainder shall continue in full force and effect.",
  "IN WITNESS WHEREOF, the parties have duly executed and signed this document by their authorized representatives as of the date first written above.",
];

describe("boilerplate-reachability guard", () => {
  it("no ungated check is satisfied by ordinary execution language", () => {
    const dead: string[] = [];
    let checked = 0;
    for (const r of PACK_RULES) {
      if (GATED_PACK_RULE_IDS.has(r.id)) continue;
      const title = familyName.get((r.applies_to_playbooks ?? [])[0]!);
      if (!title) continue;
      checked += 1;
      const ctx = buildContext(
        [title, ...REAL_BOILERPLATE],
        ["Signatures", "By: ____ Name: ____ Title: ____ Date: ____"],
      );
      if (r.check(ctx) === null) dead.push(`${r.id}  ${NAME_OF.get(r.id) ?? ""}`);
    }
    expect(checked, "the sweep found no rules — it is broken").toBeGreaterThan(500);
    expect(
      dead.sort(),
      `satisfied by boilerplate, so unable to fire:\n  ${dead.sort().join("\n  ")}`,
    ).toEqual([]);
  });
});

/**
 * The other direction for the same 21 rules.
 *
 * Turning a synonym OR into a conjunction makes a check STRICTER, and a
 * check that fires on a compliant document is worse than one that never
 * fires at all. Each clause below is written the way that rule's own `fix`
 * text says to write it — which is also the test that the recommendation is
 * actionable.
 */
const COMPLIANT: Array<[string, string, string[]]> = [
  [
    "COMM-145",
    "Franchise Disclosure Document",
    [
      "ITEM 23 RECEIPT. This disclosure document was delivered to you at least 14 calendar days before you signed any binding agreement or made any payment to the franchisor. Both copies of the receipt bear the issuance date and the franchise seller's identity.",
    ],
  ],
  [
    "COMM-202",
    "Website Terms of Use",
    [
      "We may modify these terms at any time. Changes take effect only prospectively after we post the revised terms and state a new effective date, and your continued use after that effective date is acceptance.",
    ],
  ],
  [
    "DISC-026",
    "Privilege Log",
    [
      "Entry 1. Author: Ana Duarte (General Counsel). Recipients: Dermot Halloran. CC: outside counsel. Copied to: none.",
    ],
  ],
  [
    "DISC-037",
    "Notice of Deposition",
    [
      "PLEASE TAKE NOTICE that the deposition of Dermot Halloran will be taken. Name of the deponent: Dermot Halloran, Managing Member.",
    ],
  ],
  [
    "EMP-122",
    "Relocation Agreement",
    [
      "You authorize the Company to deduct the unearned relocation amount from your final paycheck, in writing, only to the extent permitted by applicable state law, and to invoice you for any remainder.",
    ],
  ],
  [
    "EMP-147",
    "WARN Notice",
    [
      "This notice is given under the federal WARN Act and the state plant closing law of California, Labor Code § 1400, whose notice period is longer.",
    ],
  ],
  [
    "ENG-026",
    "Joint Representation Waiver",
    [
      "Each client consents in writing to the joint representation after being informed of the risks. Each client shall sign below and date this waiver.",
    ],
  ],
  [
    "EQT-106",
    "Omnibus Equity Incentive Plan",
    [
      "The Board may amend the Plan at any time, provided that any amendment increasing the share reserve requires stockholder approval, as does any amendment to the extent required by applicable law or listing standards.",
    ],
  ],
  [
    "EQT-124",
    "Warrant Agreement",
    [
      "Upon an acquisition or change of control, this Warrant shall be assumed by the successor or shall terminate upon the closing, and the Company shall give the Holder at least twenty (20) days prior written notice of the closing.",
    ],
  ],
  [
    "EST-408",
    "Special Needs Trust",
    [
      "Distributions are intended to supplement and not supplant, impair, or diminish any public benefits, including SSI and Medicaid, that the beneficiary receives or may become eligible to receive.",
    ],
  ],
  [
    "GOV-112",
    "Meeting Minutes",
    [
      "A quorum of the directors was present at the commencement of the meeting and a quorum was present throughout, including when each vote was taken.",
    ],
  ],
  [
    "HC-108",
    "Medical Director Agreement",
    [
      "The term of this Agreement is three (3) years commencing on the Effective Date, and this Agreement is signed by both parties before the Services begin.",
    ],
  ],
  [
    "HC-121",
    "Payer Provider Agreement",
    [
      "The fee schedule is attached as Exhibit B. Payer shall give Provider at least ninety (90) days' prior notice of any rate change, and Provider may terminate if it does not accept the new rates.",
    ],
  ],
  [
    "HC-132",
    "Telehealth Consent",
    [
      "Your provider is licensed in the state in which the patient is located at the time of the encounter, and you must confirm your physical location at each visit.",
    ],
  ],
  [
    "IPL-103",
    "Patent Assignment",
    [
      "Assignor hereby authorizes and requests the Commissioner for Patents to record this assignment against the applications and patents listed on Schedule A.",
    ],
  ],
  [
    "IPL-109",
    "Trademark Assignment",
    [
      "Assignor authorizes recordation of this assignment with the United States Patent and Trademark Office and with any foreign registries, and Assignee shall bear the recordation costs.",
    ],
  ],
  [
    "IPL-112",
    "Trademark Coexistence Agreement",
    [
      "Each party shall use its mark only in the territory and geographic areas described in Schedule 1 and only in the channels of trade listed there, including online and retail use.",
    ],
  ],
  [
    "IPL-115",
    "Trademark Coexistence Agreement",
    [
      "This agreement is perpetual and its term continues indefinitely. It is binding upon and inures to the benefit of the parties' successors and assigns, and any assignee of the marks must assume it in writing.",
    ],
  ],
  [
    "MNA-123",
    "Subscription Agreement",
    [
      "The Company may accept or reject this subscription in whole or in part. Funds are held in escrow until acceptance and are returned without interest if the subscription is rejected or the minimum offering is not met.",
    ],
  ],
  [
    "MNA-128",
    "Side Letter",
    [
      "This letter may be amended only by a written instrument signed by the Company and the Investor, and an amendment of the principal agreement by the requisite holders does not alter the rights granted here.",
    ],
  ],
  [
    "SET-115",
    "Assignment of Claim",
    [
      "Assignor warrants that it holds title to the claim free and clear of any prior assignment or encumbrance, and makes no warranty as to collectability or outcome.",
    ],
  ],
];

describe("the tightened checks stay silent on a compliant clause", () => {
  it.each(COMPLIANT)("%s", (id, heading, paras) => {
    const rule = PACK_RULES.find((r) => r.id === id);
    expect(rule, `no pack rule ${id}`).toBeDefined();
    const finding = rule!.check(
      buildContext(
        [heading, ...paras],
        ["Signatures", "By: ____ Name: ____ Title: ____ Date: ____"],
      ),
    );
    expect(finding, `${id} flagged a compliant clause: ${finding?.title ?? ""}`).toBeNull();
  });
});
