import { describe, expect, it } from "vitest";
import { rule as RISK_011 } from "./RISK-011.js";
import { buildContext } from "../../_test-fixtures.js";

describe("RISK-011 — the notice element stated with the verb", () => {
  // "We will notify you of any such claim" is the notice term. The element
  // matched only the NOUN ("prompt notice" / "written notice"), so an
  // indemnity that spells the obligation out was told it states no notice
  // procedure at all.
  it("reads 'we will notify you of any such claim'", () => {
    const f = RISK_011.check(
      buildContext([
        "13. Indemnification",
        "You agree to indemnify and hold harmless Tidemark from any claim arising out of your breach of these Terms. We will notify you of any such claim, will give you sole control of the defense, and will not settle without your prior written consent.",
      ]),
    );
    expect(f).toBeNull();
  });

  it("still reports notice missing when the indemnity states no notice term", () => {
    const f = RISK_011.check(
      buildContext([
        "13. Indemnification",
        "You agree to indemnify and hold harmless Tidemark from any claim arising out of your breach of these Terms.",
      ]),
    );
    expect(f?.title).toContain("notice");
  });
});

describe("RISK-011 v1.6.0 — the British spelling of a defence", () => {
  it("reads 'control of the defence'", () => {
    // A UK or Commonwealth indemnity spells it with a c, and this repo already
    // reads "licence" beside "license" for the same reason. The textbook
    // clause was reported as an indemnity missing its defence-control element.
    const ctx = buildContext([
      "Indemnity",
      "Contractor shall indemnify Client against any third-party claim that the Work infringes a copyright, provided that Client promptly notifies Contractor of the claim, gives Contractor control of the defence, and cooperates at Contractor's expense. Contractor shall not settle a claim that admits fault on Client's part without Client's prior written consent.",
    ]);
    expect(RISK_011.check(ctx)).toBeNull();
  });
});

describe("RISK-011 v1.7.0 — 'indemnify, defend, and hold harmless the Escrow Agent'", () => {
  it("stays silent on the stakeholder's own protection", () => {
    // The carve-out for a neutral agent's fiduciary indemnity wanted
    // "indemnify and hold harmless the Escrow Agent" adjacently, and the
    // three-verb form is at least as common. An M&A escrow agreement was told
    // that the clause protecting its escrow agent controls no defense and
    // requires no settlement consent.
    const ctx = buildContext([
      "9. Indemnification of the Escrow Agent",
      "Buyer and the Sellers, jointly and severally, shall indemnify, defend, and hold harmless the Escrow Agent and its officers, directors, employees, and agents from and against all claims, losses, liabilities, and reasonable out-of-pocket expenses arising out of this Escrow Agreement, except to the extent caused by the Escrow Agent's gross negligence or willful misconduct.",
    ]);
    expect(RISK_011.check(ctx)).toBeNull();
  });

  it("still audits a commercial indemnity that names a party, not an agent", () => {
    const ctx = buildContext([
      "9. Indemnification",
      "Supplier shall indemnify, defend, and hold harmless Buyer and its officers, directors, employees, and agents from and against all claims arising out of the Products.",
    ]);
    expect(RISK_011.check(ctx)).not.toBeNull();
  });
});

/**
 * Approval IS consent.
 *
 * "amounts paid in settlement approved by Provider" and "no settlement without
 * the indemnitor's prior written approval" are the ordinary way half of
 * technology indemnities write the settlement-consent term, and the element
 * read only the word "consent" — so an indemnity that plainly contains the
 * term was told it was missing it.
 *
 * That is the failure direction that matters for a presence rule: its false
 * NEGATIVE is a missed absence, its false POSITIVE is a confident accusation
 * about a clause the document has. Found by the clean-document method on a
 * complete SaaS agreement; the specimen corpus does not move (35 findings
 * before, 35 after), because every specimen happens to write "consent".
 */
describe("RISK-011 — settlement consent written as approval", () => {
  const INDEMNITY = (settlement: string) =>
    RISK_011.check(
      buildContext([
        "9. Indemnification",
        `Provider shall defend Customer against any third-party claim that the Service infringes a patent, and shall indemnify Customer for damages finally awarded or ${settlement} The indemnified party shall give prompt written notice of the claim and allow the indemnifying party sole control of the defense.`,
      ]),
    );

  it("reads 'amounts paid in settlement approved by' as the consent term", () => {
    expect(INDEMNITY("amounts paid in settlement approved by Provider.")).toBeNull();
  });

  it("reads a prior-written-approval settlement bar the same way", () => {
    expect(
      INDEMNITY(
        "amounts paid in settlement, and shall not settle any claim without Customer's prior written approval.",
      ),
    ).toBeNull();
  });

  it("still reports the element missing when the clause says nothing about settlement", () => {
    const f = INDEMNITY("amounts paid to the claimant.");
    expect(f, "an indemnity with no settlement term went unreported").not.toBeNull();
    expect(f!.description).toContain("settlement consent");
  });
});

describe("RISK-011 — defense control with a possessive determiner", () => {
  it("reads 'allow the indemnifying party to control its defense'", () => {
    const ctx = buildContext([
      "Indemnification",
      "Client shall indemnify, defend and hold harmless Venue from third-party claims arising out of the Event. The indemnified party shall give the indemnifying party prompt written notice of a claim, allow the indemnifying party to control its defense, and cooperate in it. The indemnifying party shall not settle a claim without the indemnified party's consent.",
    ]);
    expect(RISK_011.check(ctx)).toBeNull();
  });
});

describe("RISK-011 — an indemnity in a nested section", () => {
  it("reads the whole section, wherever it sits in the tree", async () => {
    const { buildTree } = await import("../../../extract/_fixtures.js");
    const base = buildContext(["Top", "x"]);
    const tree = buildTree(
      ["AGREEMENT", "The parties agree as follows."],
      [
        "6. INDEMNIFICATION",
        "6.1 Each party shall indemnify, defend and hold harmless the other from third-party claims.",
        "6.3 Procedure. The indemnified party shall give prompt written notice, allow the indemnifying party to control the defense, and not settle without its consent.",
      ],
    );
    // Nest section 2 under section 1, as a DOCX ingest does for a numbered heading.
    const [first, second] = tree.sections;
    first!.children.push(second!);
    tree.sections.splice(1, 1);
    const { extractAll } = await import("../../../extract/index.js");
    const ctx = {
      ...base,
      tree,
      extracted: extractAll(tree, { classifier: { vocab: { vocab: {} }, patterns: [] } }),
    };
    expect(RISK_011.check(ctx)).toBeNull();
  });
});

describe("RISK-011 — claim before the notice verb, and the indemnity's own section", () => {
  it("reads '… any third-party claim …, provided that Client promptly notifies Contractor'", () => {
    const ctx = buildContext([
      "6. Indemnity",
      "6.2 Contractor shall indemnify Client against any third-party claim that the Work infringes a copyright, provided that Client promptly notifies Contractor, gives Contractor control of the defence, and cooperates. Contractor shall not settle a claim without Client's prior written consent.",
    ]);
    expect(RISK_011.check(ctx)).toBeNull();
  });

  it("audits the clause titled Indemnification, not an earlier passing mention", () => {
    const ctx = buildContext(
      [
        "2. Loans",
        "2.8 Breakage. The Borrower shall compensate and indemnify each Lender for breakage costs on a prepayment.",
      ],
      [
        "9. General",
        "9.1 Indemnification. The Borrower shall indemnify each Lender against third-party claims. The Lender shall give prompt notice of any claim, the Borrower shall control the defense, and no claim shall be settled without the Borrower's consent.",
      ],
    );
    expect(RISK_011.check(ctx)).toBeNull();
  });
});

describe("RISK-011 — the procedure in a clause of its own", () => {
  it("reads a sibling section headed 'Defense and Cooperation'", () => {
    const ctx = buildContext(
      [
        "2. Indemnity",
        "Indemnitor shall indemnify, defend, and hold harmless Indemnitee from all third-party claims.",
      ],
      ["3. Insurance", "Indemnitor shall maintain liability insurance."],
      [
        "4. Defense and Cooperation",
        "Indemnitee shall give Indemnitor written notice of any claim, Indemnitor shall control the defense, and Indemnitor shall not settle any claim without Indemnitee's consent.",
      ],
    );
    expect(RISK_011.check(ctx)).toBeNull();
  });
});

describe("RISK-011 — the indemnity clause, not the whole pasted document", () => {
  // Pasted text is often a single section; another clause's "written notice"
  // is not the indemnity's claims notice.
  const INDEMNITY =
    "9.1 Indemnification. The Borrower shall indemnify each Lender against all losses and claims arising from the Loan Documents. The Administrative Agent shall control the defense of any third-party claim, and no indemnified party shall settle any such claim without the Borrower's prior written consent.";

  it("does not borrow another clause's notice", () => {
    const ctx = buildContext([
      "",
      "8.2 Voluntary Termination. The Borrower may terminate the Commitments on three Business Days' prior written notice.",
      INDEMNITY,
      "9.2 Amendments. No amendment is effective without the written consent of each affected Lender.",
    ]);
    expect(RISK_011.check(ctx)?.title).toMatch(/missing: notice$/);
  });

  it("reads a procedure clause titled as one", () => {
    const ctx = buildContext([
      "",
      INDEMNITY,
      "9.2 Notice of Claims. A Lender shall give the Borrower written notice of a claim within thirty (30) days.",
    ]);
    expect(RISK_011.check(ctx)).toBeNull();
  });

  it("reads 'notify … promptly' and 'participate at its own expense'", () => {
    const ctx = buildContext([
      "",
      "8.4 Indemnity. Each Party shall indemnify the other against third-party claims. The indemnified Party shall notify the indemnifying Party promptly, may participate at its own expense, and shall not settle without consent.",
    ]);
    expect(RISK_011.check(ctx)).toBeNull();
  });
});
