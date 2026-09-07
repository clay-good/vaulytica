/**
 * A family is not "clearly present" because its acronym is inside a word.
 *
 * `familyIsPresent` decides whether to run a whole playbook's rule pack as a
 * SECONDARY family, and one title-keyword hit is enough. It tested that hit
 * with `title.includes(keyword)` — a raw substring — while `matcher.ts` had
 * long since solved the same comparison properly in `matchesIn`: an acronym of
 * five characters or fewer matches only at a word boundary.
 *
 * The catalog has 48 title keywords of four characters or fewer, all
 * acronyms, and several are inside ordinary contract vocabulary:
 *
 *   "co"  ⊂ company, contract, confidential, counsel, corporation
 *   "cla" ⊂ clause, claim, declaration
 *   "sig" ⊂ signature, signed, assign, design
 *   "spa" ⊂ space, transparent
 *   "apa" ⊂ capacity, apart
 *
 * Measured over the 312 specimens before the fix: **145 shed a spurious
 * family, 176 activations, 695 findings, 515 of them CRITICAL** — confident
 * accusations drawn from playbooks for documents the specimen is not.
 * `change-order`, whose keyword is `"co"`, accounted for 114 of the 176. A
 * commercial Master Services Agreement drew four criticals from `family-msa`,
 * the family-law *Marital Settlement* Agreement.
 *
 * This is the "a comparison written twice will disagree with itself" failure
 * in its keyword form. `featureMatcher` is the single owner now, and this
 * guard holds both halves: the substring must not activate, and the genuine
 * acronym still must.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { familyIsPresent, familySignalStrength } from "../../src/ui/playbook-candidates.js";
import { featureMatcher } from "../../src/playbooks/matcher.js";
import { parsePlaybooks } from "../../src/playbooks/loader.js";
import type { Playbook } from "../../src/playbooks/types.js";
import type { ExtractedData } from "../../src/extract/types.js";

const EXTENDED: readonly Playbook[] = parsePlaybooks(
  JSON.parse(readFileSync(join(process.cwd(), "playbooks", "extended.json"), "utf8")),
);

const byId = (id: string): Playbook => {
  const p = EXTENDED.find((x) => x.id === id);
  if (!p) throw new Error(`fixture playbook ${id} is gone; pick another`);
  return p;
};

/** The minimum a selector reads: a title corpus, a body, and empty extraction. */
function signals(title: string, body: string) {
  return {
    title,
    body,
    classified: [],
    extracted: { definitions: { entries: [] } } as unknown as ExtractedData,
  };
}

describe("an acronym inside a word does not activate a family", () => {
  it("catalog check: the short keywords this guard is about are still there", () => {
    // Anti-vacuity, and a canary: if `change-order` stops declaring "co" the
    // examples below stop proving anything, and this test should be re-aimed
    // rather than left green.
    const short = EXTENDED.flatMap((p) =>
      p.match_features.title_keywords.filter((k) => k.length <= 4).map((k) => [p.id, k] as const),
    );
    expect(short.length, "short title keywords in the catalog").toBeGreaterThanOrEqual(30);
    expect(short).toContainEqual(["change-order", "co"]);
    expect(short).toContainEqual(["family-msa", "msa"]);
  });

  it('"co" does not make a Change Order present in ordinary contract prose', () => {
    const changeOrder = byId("change-order");
    for (const title of [
      "MASTER SERVICES AGREEMENT",
      "This Agreement is entered into by Halbrook Company",
      "CONFIDENTIALITY AND NON-DISCLOSURE AGREEMENT",
      "Contract for Professional Services",
      "ACME CORPORATION SHAREHOLDER AGREEMENT",
    ]) {
      expect(familyIsPresent(changeOrder, signals(title, title)), title).toBe(false);
    }
  });

  it("still activates on a document that really is one", () => {
    const changeOrder = byId("change-order");
    expect(familyIsPresent(changeOrder, signals("CHANGE ORDER NO. 4", "change order"))).toBe(true);
    // The bare acronym, standing as its own word, is a real signal.
    expect(familyIsPresent(changeOrder, signals("AIA Document G701 — CO 12", "co 12"))).toBe(true);
  });

  it('"msa" does not route a commercial MSA into the family-law playbook', () => {
    // The motivating case: a commercial Master Services Agreement drew four
    // CRITICAL findings from the Marital Settlement Agreement playbook.
    const familyMsa = byId("family-msa");
    const title = "MASTER SERVICES AGREEMENT between Northwind LLC and Halbrook Company";
    expect(familyIsPresent(familyMsa, signals(title, title))).toBe(false);
    // …but a document that names itself with the acronym still reaches it.
    expect(familyIsPresent(familyMsa, signals("MARITAL SETTLEMENT AGREEMENT (MSA)", ""))).toBe(
      true,
    );
  });

  it("the candidacy score reads the same comparison as the presence bar", () => {
    // Both were written with the raw substring; fixing only one leaves a
    // playbook that scores as a candidate on a signal that cannot activate it.
    const changeOrder = byId("change-order");
    const prose = signals("CONFIDENTIALITY AGREEMENT of Halbrook Company", "confidential");
    const real = signals("CHANGE ORDER NO. 4", "change order");
    expect(familySignalStrength(changeOrder, real)).toBeGreaterThan(
      familySignalStrength(changeOrder, prose),
    );
  });
});

describe("featureMatcher", () => {
  it("folds case, like matchPlaybook's own call does", () => {
    // 🚨 The bug this helper shipped with for one measurement round: the
    // acronym branch of `matchesIn` is a case-insensitive regex but the PHRASE
    // branch is a bare `includes` against a lower-cased needle, so a corpus
    // left in its original case matches no phrase at all. It dropped 65 of 312
    // specimens out of their own family's candidate set into `generic-fallback`
    // — "COMPLAINT" does not contain "complaint".
    const upper = featureMatcher("MASTER SERVICES AGREEMENT");
    expect(upper("master services agreement")).toBe(true);
    const mixed = featureMatcher("Complaint for Breach of Contract");
    expect(mixed("complaint")).toBe(true);
  });

  it("matches a short acronym only at a word boundary", () => {
    const m = featureMatcher("Halbrook Company confidential contract");
    expect(m("co")).toBe(false);
    expect(featureMatcher("CO 12 issued under the contract")("co")).toBe(true);
  });

  it("keeps phrase semantics for anything longer", () => {
    const m = featureMatcher("Conflicts of Interest Policy");
    expect(m("conflicts of interest")).toBe(true);
  });
});

describe("three bare common words do not make a family present", () => {
  /**
   * The guaranty case, pinned. `familyIsPresent` activates a family's WHOLE
   * rule pack on `distHits + reqHits >= 3`, and three words a whole DOMAIN
   * shares cleared that bar: every document in a lending package names the
   * borrower and the lender. Corpus frequency cannot see it — each word is
   * under `distinguishing-base-rate.test.ts`'s ceiling — so the bar now asks
   * for one COLLOCATION (multi-word, or a hyphenated compound) or a structural
   * `required_clauses` hit.
   */
  const loan = byId("loan-agreement");

  it("a guaranty is not a loan agreement", () => {
    // What a real guaranty says: it names the loan's parties, and nothing else
    // about it is a loan agreement.
    const body =
      "GUARANTY. The undersigned Guarantor absolutely and unconditionally guarantees to Lender the prompt payment of all obligations of Borrower under the commitment described above.";
    expect(familyIsPresent(loan, signals("CONTINUING GUARANTY", body))).toBe(false);
  });

  it("but a document carrying a real loan collocation still is", () => {
    const body =
      "The Borrower shall pay interest to the Lender. Events of default include any failure to pay when due. The commitment shall terminate on the maturity date.";
    expect(familyIsPresent(loan, signals("CREDIT AGREEMENT", body))).toBe(true);
  });

  it("a hyphenated compound counts as a collocation", () => {
    // The clause that keeps `net-lease` reaching SNDA terms: "non-disturbance"
    // and "attornment" are terms of art spelled as one hyphenated token, and a
    // word-count-only rule discarded them.
    const snda = byId("snda");
    const body =
      "Tenant shall subordinate this Lease to the lien of any mortgage, and Mortgagee shall grant non-disturbance so long as Tenant is not in default. Tenant shall attorn to Lender.";
    expect(familyIsPresent(snda, signals("SUBORDINATION AGREEMENT", body))).toBe(true);
  });
});
