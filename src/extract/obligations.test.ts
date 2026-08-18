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

  it("attributes a two-party compound subject to 'the parties', not the last one", () => {
    // "The Provider and the Customer shall each …" is a mutual obligation. The
    // obligor's endsWith match keys on the tail of the subject, so it used to
    // return whichever party sat last ("Customer") — making OBLI-002 read the
    // shared duty as one-sided.
    const tree = buildTree([
      "Agreement",
      'This Agreement is between Acme Corp., a Delaware corporation ("Provider"), and Globex Industries, Inc., a New York corporation ("Customer").',
      "The Provider and the Customer shall each bear their own costs and expenses.",
    ]);
    const parties = extractParties(tree);
    const oblis = extractObligations(tree, parties);
    const shared = oblis.find((o) => /bear their own costs/.test(o.action));
    expect(shared?.obligor).toBe("the parties");
  });

  it("does not read a party-plus-non-party compound subject as mutual", () => {
    // Only ONE side of the "and" is a party, so this is not a mutual obligation
    // and must not collapse to "the parties".
    const tree = buildTree([
      "Agreement",
      'This Agreement is between Acme Corp., a Delaware corporation ("Provider"), and Globex Industries, Inc., a New York corporation ("Customer").',
      "The Provider and its subcontractors shall comply with the security policy.",
    ]);
    const parties = extractParties(tree);
    const oblis = extractObligations(tree, parties);
    const o = oblis.find((x) => /comply with the security policy/.test(x.action));
    expect(o?.obligor).not.toBe("the parties");
  });

  it("captures an hours-based deadline as an obligation trigger", () => {
    // Breach- and incident-notice duties are commonly stated in hours ("within
    // 24 hours", "within seventy-two (72) hours"); hours was missing from the
    // trigger's time-unit list, so those deadlines never surfaced.
    const tree = buildTree([
      "Notice",
      "Provider shall notify Customer within 24 hours of discovering a breach.",
      "Provider shall report the incident within seventy-two (72) hours.",
    ]);
    const oblis = extractObligations(tree, []);
    const triggers = oblis.map((o) => o.trigger ?? "");
    expect(triggers.some((t) => /within\s+24\s+hours/.test(t))).toBe(true);
    expect(triggers.some((t) => /seventy-two\s+\(72\)\s+hours/.test(t))).toBe(true);
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

  it("leaves no stranded punctuation when both a trigger and a qualifier are excised", () => {
    // Cutting the trigger clause out of the predicate leaves behind the comma
    // that separated it from the main clause, so the action for a sentence
    // carrying BOTH a trigger and a qualifier — a routine drafting shape —
    // came out as "deliver the Deliverables ,": the cleanup stripped only one
    // trailing character, taking the period and leaving the comma exposed.
    const obs = extractObligations(
      buildTree([
        "Delivery",
        "Provider shall deliver the Deliverables within thirty (30) days of the Effective Date, subject to Customer's timely provision of specifications.",
      ]),
      [],
    );
    expect(obs).toHaveLength(1);
    expect(obs[0]!.action).toBe("deliver the Deliverables");
  });

  it("leaves no doubled separator when the excised clause sat between two others", () => {
    // Same excision seam, mid-string rather than at the end: cutting the
    // qualifier out of the middle left "deliver the Deliverables, , no later
    // than 30 days after execution".
    const obs = extractObligations(
      buildTree([
        "Delivery",
        "The Contractor shall deliver the Deliverables, provided that the Client has paid the Deposit, no later than 30 days after execution.",
      ]),
      [],
    );
    expect(obs).toHaveLength(1);
    expect(obs[0]!.action).toBe("deliver the Deliverables, no later than 30 days after execution");
  });

  it("does not end a sentence at an abbreviation period", () => {
    // splitSentences treated EVERY "." as a terminator, so a clock time cut the
    // sentence in half: the action recorded was "deliver notice no later than
    // 5:00 p" and the rest of the clause was dropped as an unterminated
    // remainder — a silently truncated obligation.
    const obs = extractObligations(
      buildTree([
        "Notices",
        "Provider shall deliver notice no later than 5:00 p.m. Eastern Time on the Delivery Date.",
      ]),
      [],
    );
    expect(obs).toHaveLength(1);
    expect(obs[0]!.action).toBe(
      "deliver notice no later than 5:00 p.m. Eastern Time on the Delivery Date",
    );
  });

  it("does not resolve an obligor from an address fragment left by an abbreviation split", () => {
    // The truncation's worse half: splitting at "St." in a street address made
    // the NEXT "sentence" start mid-clause, so the following modal's subject
    // was the fragment "Suite 400, and" — a phantom obligor no reader would
    // recognize, attached to a real duty.
    const obs = extractObligations(
      buildTree([
        "Delivery",
        "Provider shall, no later than 5:00 p.m. Eastern Time on the Delivery Date, deliver the Deliverables to Customer at 123 Main St., Suite 400, and shall provide a written notice of delivery.",
      ]),
      [],
    );
    expect(obs.map((o) => o.obligor)).toEqual(["Provider"]);
    // And no stranded separator from the fronted clause: the predicate starts
    // at the comma after "shall", which used to lead the action text.
    expect(obs[0]!.action.startsWith("no later than")).toBe(true);
  });

  it("keeps a proviso as the qualifier rather than splitting it into an obligation", () => {
    // "; provided that … shall not …" carries its own modal, so the semicolon
    // boundary split it into a second obligation — with the literal words
    // "provided that any such inspection" as the obligor and, with the negation
    // stripped by the split, an action that read as an affirmative duty TO
    // interfere. The clause says the exact opposite.
    const obs = extractObligations(
      buildTree([
        "Audit",
        "Customer shall have the right to inspect Provider's records; provided that any such inspection shall not unreasonably interfere with Provider's business operations.",
      ]),
      [],
    );
    expect(obs).toHaveLength(1);
    expect(obs[0]!.obligor).toBe("Customer");
    expect(obs[0]!.action).toBe("have the right to inspect Provider's records");
    expect(obs[0]!.qualifier).toBe(
      "provided that any such inspection shall not unreasonably interfere with Provider's business operations",
    );
  });

  it("still ends a sentence at an uppercase initialism before a new subject", () => {
    // The abbreviation guard has to tell "5:00 p.m. Eastern Time" (one
    // sentence) from "…in the U.S. Vendor shall comply…" (two). An
    // unrestricted guard swallowed both, and reported this obligor as
    // "business is in the U.S. Vendor" — an adversarial pass caught it.
    const obs = extractObligations(
      buildTree([
        "Compliance",
        "Vendor represents that its principal place of business is in the U.S. Vendor shall comply with all applicable export control laws.",
      ]),
      [],
    );
    expect(obs.map((o) => o.obligor)).toEqual(["Vendor"]);
    expect(obs[0]!.action).toBe("comply with all applicable export control laws");
  });

  it("keeps an uppercase initialism inside its own sentence", () => {
    // The other direction: "U.S." mid-sentence is followed by a lowercase word,
    // so the start-of-sentence test correctly declines to split there.
    const obs = extractObligations(
      buildTree([
        "Compliance",
        "The Provider shall comply with all U.S. federal export regulations.",
      ]),
      [],
    );
    expect(obs).toHaveLength(1);
    expect(obs[0]!.action).toBe("comply with all U.S. federal export regulations");
  });

  it("splits an affirmative proviso into its own obligation, without the lead-in", () => {
    // A negated proviso restricts the clause before it; an affirmative one is a
    // real second duty, and suppressing it would lose an obligation. Both keep
    // the lead-in off the obligor, which the pre-existing split corrupted into
    // "provided that Customer".
    const obs = extractObligations(
      buildTree([
        "Invoices",
        "Customer shall have the right to dispute any invoice in writing within ten days; provided that Customer shall pay all undisputed fees within thirty days of invoice.",
      ]),
      [],
    );
    expect(obs.map((o) => o.obligor)).toEqual(["Customer", "Customer"]);
    expect(obs[1]!.action).toBe("pay all undisputed fees");
    expect(obs[1]!.trigger).toBe("within thirty days of invoice");
  });

  it("still splits a genuine coordinated second clause", () => {
    // The proviso guard is anchored, so an ordinary semicolon-coordinated
    // second obligation must still yield two records.
    const obs = extractObligations(
      buildTree([
        "Duties",
        "Provider shall deliver the Services; Customer shall pay the fees within thirty (30) days.",
      ]),
      [],
    );
    expect(obs.map((o) => o.obligor)).toEqual(["Provider", "Customer"]);
  });
});
