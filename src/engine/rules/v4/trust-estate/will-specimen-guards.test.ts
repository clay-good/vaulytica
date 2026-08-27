/**
 * Four defects a hand-written Ohio will found.
 *
 * EST-004's second express-denial frame carried no negation guard, unlike its
 * sibling, so the STANDARD bond waiver — "No fiduciary serving under this Will
 * shall be required to post bond in any jurisdiction" — was reported as a will
 * that affirmatively REQUIRES bond, which is the reverse of what it says.
 *
 * EST-104 and EST-105 recognized only ruled signature lines. A will that is
 * pasted, typed, or e-signed carries the conformed signature instead — "/s/
 * Dermot Aloysius Halloran" over "Dermot Aloysius Halloran, Testator", and an
 * attestation clause reciting that the witnesses "subscribed our names as
 * witnesses" — so a properly executed will was told nobody had signed it and
 * that it had no witnesses. STRUCT-003 learned the same lesson in 9.42.
 *
 * And a will names its family throughout — "my wife Priya Raghunathan
 * Halloran", "my son Emil Halloran" — while having no "parties" for the party
 * extractor to find, so every family member was reported as a Title-Case term
 * the will forgot to define.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../../../_test-fixtures.js";
import { extractDefinitions } from "../../../../extract/definitions.js";
import { buildTree } from "../../../../extract/_fixtures.js";
import { V4_RULES } from "../index.js";
import { ESTATE_CHECK_RULES } from "./estate-checks.js";

const rule = (id: string) => {
  const r = [...V4_RULES, ...ESTATE_CHECK_RULES].find((x) => x.id === id);
  if (!r) throw new Error(`no rule ${id}`);
  return r;
};

const will = (...paras: string[]) =>
  buildContext(["Last Will and Testament of Dermot Aloysius Halloran", ...paras]);

describe("EST-004 — the bond waiver whose subject carries the negation", () => {
  it("reads 'No fiduciary shall be required to post bond' as a waiver", () => {
    const finding = rule("EST-004").check(
      will(
        "No fiduciary serving under this Will shall be required to post bond in any jurisdiction.",
      ),
    );
    expect(finding, `flagged a bond waiver: ${finding?.title ?? ""}`).toBeNull();
  });

  it("still reports a will that affirmatively requires bond", () => {
    const finding = rule("EST-004").check(
      will(
        "My Executor shall be required to post bond with corporate surety in the amount of $100,000.",
      ),
    );
    expect(finding).not.toBeNull();
    expect(finding!.title).toBe("Fiduciary bond expressly required");
  });
});

describe("EST-104 / EST-105 — the conformed signature", () => {
  const EXECUTED = [
    "IN WITNESS WHEREOF, I have signed this Will on the 14th day of September, 2026.",
    "/s/ Dermot Aloysius Halloran Dermot Aloysius Halloran, Testator",
    "The foregoing instrument was signed, published, and declared by the testator in our presence, and we, at his request and in his presence and in the presence of each other, have subscribed our names as witnesses.",
    "/s/ Marisol Aguirre Marisol Aguirre, residing at 41 Vinewood Lane, Columbus, Ohio",
  ];

  it("EST-104 reads a conformed testator signature", () => {
    expect(rule("EST-104").check(will(...EXECUTED))).toBeNull();
  });

  it("EST-105 reads an attestation clause and conformed witness signatures", () => {
    expect(rule("EST-105").check(will(...EXECUTED))).toBeNull();
  });

  it("both still fire on an unexecuted draft", () => {
    const draft = will("I give the residue of my estate to my wife if she survives me.");
    expect(rule("EST-104").check(draft)).not.toBeNull();
    expect(rule("EST-105").check(draft)).not.toBeNull();
  });

  it("EST-105 is not satisfied by testator-side boilerplate alone", () => {
    // The pre-existing `witnesseth` / `witness whereof` guard still holds:
    // "IN WITNESS WHEREOF, I have signed" is the testator signing, not a
    // witness.
    expect(
      rule("EST-105").check(
        will(
          "IN WITNESS WHEREOF, I have signed this Will.",
          "/s/ Dermot Aloysius Halloran Dermot Aloysius Halloran, Testator",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("a will's family are people, not defined terms", () => {
  it("does not report a relative introduced by their relationship", () => {
    const map = extractDefinitions(
      buildTree([
        "Last Will and Testament",
        "I give the residue to my wife Priya Raghunathan Halloran. I give my watch to my son Emil Halloran.",
        "My wife Priya Raghunathan Halloran shall serve as Executor, and my son Emil Halloran as successor.",
      ]),
    );
    const terms = map.undefined_capitalized.map((e) => e.term);
    expect(terms).not.toContain("Priya Raghunathan Halloran");
    expect(terms).not.toContain("Emil Halloran");
  });

  it("does not report the front half of the will's own title", () => {
    const map = extractDefinitions(
      buildTree([
        "Will",
        "I declare this to be my Last Will and Testament. I revoke all prior wills.",
        "This is my Last Will and Testament and I sign it freely.",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain("Last Will");
  });
});
