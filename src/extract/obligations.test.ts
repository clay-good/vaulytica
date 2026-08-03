import { describe, expect, it } from "vitest";
import { extractObligations } from "./obligations.js";
import { extractParties } from "./parties.js";
import { buildTree } from "./_fixtures.js";

describe("extractObligations", () => {
  it("captures modal sentences with party-named obligor", () => {
    const tree = buildTree([
      "Agreement",
      'This Agreement is between Acme Corp., a Delaware corporation ("Provider"), and Globex Industries, Inc., a New York corporation ("Customer").',
      "Provider shall deliver the Services within thirty (30) days after the Effective Date.",
      "Customer must pay the fees subject to the terms of Section 4.",
    ]);
    const parties = extractParties(tree);
    const oblis = extractObligations(tree, parties);
    expect(oblis.length).toBeGreaterThanOrEqual(2);
    const provider = oblis.find((o) => /Provider/i.test(o.obligor));
    const customer = oblis.find((o) => /Customer/i.test(o.obligor));
    expect(provider?.modal).toBe("shall");
    expect(customer?.modal).toBe("must");
    expect(provider?.trigger ?? "").toMatch(/within\s+thirty/);
    expect(customer?.qualifier ?? "").toMatch(/subject\s+to/);
  });

  it("decomposes a nested trigger into its sub-conditions", () => {
    const tree = buildTree([
      "Notice",
      "The Provider shall refund the fees within 60 days of the date that the Customer provides written notice that it has terminated for cause.",
    ]);
    const obli = extractObligations(tree, []).find((o) => o.nested_triggers);
    expect(obli?.nested_triggers?.length).toBeGreaterThanOrEqual(2);
    expect(obli?.nested_triggers?.join(" ")).toMatch(/written notice/);
  });

  it("captures a scope-narrowing obligor exclusion", () => {
    const tree = buildTree([
      "Confidentiality",
      "Each party except the Provider shall maintain insurance at all times.",
    ]);
    const obli = extractObligations(tree, []).find((o) => o.obligor_exclusion);
    expect(obli?.obligor_exclusion).toMatch(/Provider/);
  });

  it("does not report the excluded party as the obligor", () => {
    // With real parties, the trailing excluded name used to win the obligor
    // `endsWith` match, so "Each party except the Provider" reported obligor
    // "Provider" — the very party the sentence carves out.
    const parties = extractParties(
      buildTree([
        "Parties",
        'This Agreement is between Acme Corp. ("Provider") and Globex Inc. ("Customer").',
      ]),
    );
    const tree = buildTree([
      "Insurance",
      "Each party except the Provider shall maintain insurance at all times.",
    ]);
    const obli = extractObligations(tree, parties).find((o) => o.obligor_exclusion);
    expect(obli?.obligor_exclusion).toMatch(/Provider/);
    // The obligor is the parties (minus the carve-out), never the excluded one.
    expect(obli?.obligor).not.toMatch(/^Provider$/);
    expect(obli?.obligor).toBe("the parties");
  });

  it("splits a coordinated sentence into one obligation per party", () => {
    const parties = extractParties(
      buildTree([
        "Parties",
        'This Agreement is between Acme Corp. ("Provider") and Globex Inc. ("Customer").',
      ]),
    );
    const tree = buildTree([
      "Delivery",
      "The Provider shall deliver the goods, and the Customer shall pay the invoice within thirty (30) days.",
    ]);
    const obs = extractObligations(tree, parties);
    // Both obligations are recovered — the Customer's payment is not dropped
    // nor folded into the Provider's action.
    expect(obs).toHaveLength(2);
    const provider = obs.find((o) => /Provider/.test(o.obligor));
    const customer = obs.find((o) => /Customer/.test(o.obligor));
    expect(provider?.action).toBe("deliver the goods");
    expect(customer?.action).toBe("pay the invoice");
    expect(customer?.trigger).toMatch(/thirty/);
  });

  it("does not over-split a subordinate or elided-subject coordination", () => {
    // "goods and services that the Customer shall inspect" is one obligation
    // (subordinate relative clause), and "shall deliver and shall install" is
    // one obligation (elided shared subject) — neither fabricates a second.
    const tree = buildTree([
      "Scope",
      "The Provider shall deliver goods and services that the Customer shall inspect.",
      "The Provider shall deliver and shall install the equipment.",
    ]);
    const obs = extractObligations(tree, []);
    expect(obs).toHaveLength(2);
    expect(obs.every((o) => o.obligor.trim().length > 0)).toBe(true);
  });

  it("captures prohibitive and permissive boundary modals", () => {
    const tree = buildTree([
      "Restrictions",
      "The Customer may not assign this Agreement without consent.",
      "The Provider is required to maintain the Services.",
      "The Customer cannot sublicense the software.",
    ]);
    const modals = extractObligations(tree, []).map((o) => o.modal);
    expect(modals).toContain("may not");
    expect(modals).toContain("is required to");
    expect(modals).toContain("cannot");
  });

  it("captures plural-subject and covenant modals the singular list missed", () => {
    const tree = buildTree([
      "Covenants",
      "The parties are required to maintain insurance.",
      "The parties are responsible for their own taxes.",
      "The Provider covenants to deliver the software.",
      "The Provider covenants and agrees to defend the Customer.",
    ]);
    const obs = extractObligations(tree, []);
    const modals = obs.map((o) => o.modal);
    expect(modals).toContain("are required to");
    expect(modals).toContain("are responsible for");
    expect(modals).toContain("covenants to");
    expect(modals).toContain("covenants and agrees to");
    // The multi-verb covenant keeps the obligor intact ("Provider", not
    // "Provider covenants and").
    const defend = obs.find((o) => o.modal === "covenants and agrees to");
    expect(defend?.obligor).toBe("The Provider");
  });

  it("does not read the contract-formation 'the parties agree to …' as an obligation", () => {
    // Plural "agree to" is boilerplate (formation), deliberately excluded — the
    // substantive singular "agrees to" still extracts.
    const boilerplate = extractObligations(
      buildTree(["Recitals", "The parties agree to the following terms and conditions."]),
      [],
    );
    expect(boilerplate).toHaveLength(0);
    const substantive = extractObligations(
      buildTree(["Body", "The Provider agrees to indemnify the Customer."]),
      [],
    );
    expect(substantive.map((o) => o.modal)).toContain("agrees to");
  });
});
