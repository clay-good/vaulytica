/**
 * An amendment is not held to the checklist of the instrument it amends.
 *
 * The router reads "First Amendment to Credit Agreement" as a credit agreement,
 * and every presence check in that family then reported the instrument's
 * clauses missing from a two-page amendment: six CRITICAL findings on a credit
 * amendment, two on an amendment to a securities purchase agreement. The
 * presence factory now stands down on a document that names itself an
 * amendment AND ratifies its parent (`amendsNamedParent`), and only there.
 */
import { describe, expect, it } from "vitest";
import { BANKING_RULES } from "./banking/rules.js";
import { buildContext } from "../../_test-fixtures.js";
import type { Playbook, RuleContext } from "../../finding.js";

const BNK_008 = BANKING_RULES.find((r) => r.id === "BNK-008")!;
const LOAN: Playbook = { id: "loan-agreement", version: "1.0.0" } as Playbook;

const withPb = (ctx: RuleContext, pb: Playbook): RuleContext => ({ ...ctx, playbook: pb });

const RATIFIES =
  "Except as expressly amended by this Amendment, the Credit Agreement remains in full force and effect and is ratified and confirmed.";

describe("presence rules on an amendment", () => {
  it("stand down on an amendment that ratifies its parent", () => {
    const ctx = withPb(
      buildContext([
        "FIRST AMENDMENT TO CREDIT AGREEMENT",
        "Section 2.1 of the Credit Agreement is amended by replacing $50,000,000 with $75,000,000.",
        RATIFIES,
      ]),
      LOAN,
    );
    expect(BNK_008.check(ctx)).toBeNull();
  });

  it('still check an "Amended and Restated" agreement, which is the whole instrument again', () => {
    for (const title of [
      "AMENDED AND RESTATED CREDIT AGREEMENT",
      "SECOND AMENDED & RESTATED CREDIT AGREEMENT",
      "AMENDMENT AND RESTATEMENT AGREEMENT",
    ]) {
      const ctx = withPb(
        buildContext([title, "The Lenders agree to make Loans to the Borrower.", RATIFIES]),
        LOAN,
      );
      expect(BNK_008.check(ctx), title).not.toBeNull();
    }
  });

  it("still check an agreement whose severability clause says the rest remains in force", () => {
    const ctx = withPb(
      buildContext([
        "CREDIT AGREEMENT",
        "The Lenders agree to make Loans to the Borrower. If any provision is held invalid, all other provisions of this Agreement shall remain in full force and effect.",
      ]),
      LOAN,
    );
    expect(BNK_008.check(ctx)).not.toBeNull();
  });

  it("still check a document titled as an amendment that does not ratify a parent", () => {
    const ctx = withPb(
      buildContext([
        "AMENDMENT TO CREDIT AGREEMENT",
        "Section 2.1 of the Credit Agreement is amended by replacing $50,000,000 with $75,000,000.",
      ]),
      LOAN,
    );
    expect(BNK_008.check(ctx)).not.toBeNull();
  });
});
