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

  it("does not read a modal inside the protasis as the duty", () => {
    // "If Supplier cannot meet accepted orders, it shall allocate available
    // Products …" has its duty in the apodosis; `cannot` states when the duty
    // arises. CONJ has no boundary at ", it ", so the whole sentence became
    // ONE obligation with modal `cannot` and action "meet accepted orders, it
    // shall allocate …" — the condition read as the duty, the duty swallowed.
    const tree = buildTree([
      "Allocation",
      "If Supplier cannot meet accepted orders, it shall allocate available Products " +
        "among its distributors and its own account.",
    ]);
    // Parties are supplied because only a PARTY is an improvement on a
    // pronoun: a protasis subject that resolves to nothing better is left
    // alone rather than traded for a fragment.
    const parties = extractParties(
      buildTree([
        "Parties",
        'This Agreement is between Acme Corp. ("Supplier") and Globex Inc. ("Distributor").',
      ]),
    );
    const oblis = extractObligations(tree, parties);
    expect(oblis.length).toBe(1);
    expect(oblis[0]?.modal).toBe("shall");
    expect(oblis[0]?.trigger).toBe("If Supplier cannot meet accepted orders");
    expect(oblis[0]?.action).toBe(
      "allocate available Products among its distributors and its own account",
    );
    // The apodosis refers back with a pronoun; a ledger column reading "it"
    // names nobody, so the protasis supplies the party.
    expect(oblis[0]?.obligor).toBe("Supplier");
  });

  it("does not take the protasis subject when the apodosis has its own", () => {
    // 🚨 The load-bearing negative. "If Wife cannot refinance …, THE HOMESTEAD
    // shall be listed for sale" is not a duty of the Wife's — the apodosis
    // names its own subject and only a BARE pronoun is resolved back.
    const tree = buildTree([
      "Homestead",
      "If Wife cannot refinance within that period, the homestead shall be listed for sale.",
    ]);
    const [obli] = extractObligations(tree, []);
    expect(obli?.obligor).toBe("the homestead");
    expect(obli?.trigger).toBe("If Wife cannot refinance within that period");
  });

  it("leaves no stranded space where the trigger was cut out", () => {
    // Excising the trigger left the space that preceded it in front of the
    // comma that followed: "…updates , and store Company information…".
    const tree = buildTree([
      "Security",
      "Each user shall install operating system and application updates within " +
        "thirty (30) days, and store Company information only in approved systems.",
    ]);
    for (const o of extractObligations(tree, [])) {
      expect(o.action, "a stranded separator seam").not.toMatch(/\s[,;]/);
      expect(o.action).not.toMatch(/\s{2,}/);
    }
  });

  it("reads a fronted condition as the trigger", () => {
    // `TRIGGER_RE` was run over the predicate only, and a fronted condition
    // lives in the SUBJECT — so the one column a lawyer scans to answer "when
    // does this bite?" was empty on 258 of the corpus's 3,688 obligations.
    const tree = buildTree([
      "Indemnity",
      "If Owner uses the Instruments of Service without retaining Architect, Owner " +
        "shall indemnify Architect from any claim arising out of that use.",
    ]);
    const [obli] = extractObligations(tree, []);
    expect(obli?.obligor).toBe("Owner");
    expect(obli?.trigger).toBe(
      "If Owner uses the Instruments of Service without retaining Architect",
    );
    // The trigger came from the subject, so the action keeps all of itself.
    expect(obli?.action).toBe("indemnify Architect from any claim arising out of that use");
  });

  it("keeps a grouped number whole in the trigger", () => {
    // A comma is not always a clause boundary. "at least $28,000,000" was cut
    // to "at least $28" — the threshold off by six orders of magnitude.
    const tree = buildTree([
      "Earnout",
      "If Net Revenue for the First Earnout Period is at least $28,000,000, Buyer " +
        "shall pay the Earnout Amount.",
    ]);
    const [obli] = extractObligations(tree, []);
    expect(obli?.trigger).toBe(
      "If Net Revenue for the First Earnout Period is at least $28,000,000",
    );
    expect(obli?.action).toBe("pay the Earnout Amount");
  });

  it("still stops at a comma that is punctuation", () => {
    // The load-bearing negative: only a comma followed by exactly three
    // digits is admitted, so an ordinary list still ends the clause.
    const tree = buildTree([
      "Notice",
      "If the Customer objects, the Provider shall respond within ten (10) days, " +
        "and the parties shall confer.",
    ]);
    const oblis = extractObligations(tree, []);
    expect(oblis.length).toBeGreaterThan(0);
    // The predicate's own trigger wins the column (see the test above); what
    // matters here is that NO trigger runs past the comma into the next clause.
    expect(oblis.some((o) => o.trigger === "within ten (10) days")).toBe(true);
    for (const o of oblis) {
      expect(o.trigger ?? "", "a trigger ran through a comma that is punctuation").not.toMatch(
        /,\s+and\b/,
      );
    }
  });

  it("prefers the predicate's own trigger over the fronted one", () => {
    // The fronted clause is a FALLBACK. A predicate that states its own
    // deadline still owns the column, and that trigger is still excised from
    // the action — which the fronted one never is.
    const tree = buildTree([
      "Notice",
      "Upon receipt of an invoice, the Customer shall pay it within thirty (30) days.",
    ]);
    const [obli] = extractObligations(tree, []);
    expect(obli?.trigger).toBe("within thirty (30) days");
    expect(obli?.action).toBe("pay it");
  });

  it("does not split a nested trigger on a DEMONSTRATIVE that", () => {
    // Splitting on the bare word decomposed "if that changes" into
    // ["if", "changes"]. A demonstrative `that` names WHICH ONE and opens no
    // sub-condition, so there is nothing to decompose here.
    const tree = buildTree([
      "Jurisdiction",
      "The Company shall file the action in the Court of Chancery, and if that court lacks " +
        "jurisdiction the Company shall file in the Superior Court.",
    ]);
    for (const o of extractObligations(tree, [])) {
      expect(o.nested_triggers, `decomposed ${JSON.stringify(o.trigger)}`).toBeUndefined();
    }
  });

  it("does not split on a purposive so-that", () => {
    // "so that X can meet the deadline" states a PURPOSE, not a condition the
    // duty waits on — and the clause after it is not a sub-trigger.
    const tree = buildTree([
      "Requests",
      "The Service Provider shall respond within ten (10) business days of the Business's " +
        "request so that the Business can meet the forty-five (45) day statutory deadline.",
    ]);
    const oblis = extractObligations(tree, []);
    expect(oblis.length).toBeGreaterThan(0);
    for (const o of oblis) expect(o.nested_triggers).toBeUndefined();
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

  it("reads a proviso's own subject as the obligor, not the party before it", () => {
    // `except` has two grammars and they name opposite parties.
    //
    // As a PREPOSITION it narrows the subject ("Each party except the
    // Provider shall …"), and the carve-out must come off before the obligor
    // is resolved — the case above.
    //
    // As a SUBORDINATOR it opens a PROVISO that carries its OWN subject and
    // its own duty, and stripping there is the same inversion one step on: it
    // deletes the real obligor and leaves the `endsWith` match to land on
    // whoever the clause BEFORE happened to name. Here that is Supplier, so
    // the obligations ledger printed SUPPLIER as owing a duty not to remove
    // Supplier's own notice — the duty is OEM's, and it is owed TO Supplier.
    //
    // `splitModalClauses` already draws this distinction for `provided that`
    // (PROVISO_LEAD). This is the same repair for `except`.
    const tree = buildTree([
      "Branding",
      "OEM may label the OEM Products under OEM's own brand and need not " +
        "identify Supplier, except that OEM shall not remove or obscure any " +
        "Supplier notice embedded in the firmware.",
    ]);
    const obli = extractObligations(tree, []).find((o) => /remove or obscure/.test(o.action));
    expect(obli, "the proviso's duty is no longer extracted at all").toBeDefined();
    expect(obli?.obligor).toBe("OEM");
    // A proviso subject is not a carve-out: nobody is excluded here.
    expect(obli?.obligor_exclusion).toBeUndefined();
  });

  it("gives an affirmative proviso its own clause, so its duty is not lost", () => {
    // `, except that` was not a boundary in CONJ, so a proviso carrying its
    // own subject and its own modal was merged into the clause before it.
    // QUALIFIER_RE then swallowed the whole proviso as that clause's
    // `qualifier`, and the duty inside it never became a row at all: the
    // ledger said "the parties shall bear their own expenses" and nowhere
    // said that Parent pays the HSR filing fees.
    const tree = buildTree([
      "Expenses",
      "Each party shall bear its own expenses, except that Parent shall pay " +
        "all filing fees under the HSR Act.",
    ]);
    const oblis = extractObligations(tree, []);
    expect(oblis.length).toBe(2);
    expect(oblis[0]?.obligor).toBe("the parties");
    expect(oblis[0]?.action).toBe("bear its own expenses");
    expect(oblis[1]?.obligor).toBe("Parent");
    expect(oblis[1]?.action).toBe("pay all filing fees under the HSR Act");
  });

  it("does not read a cross-reference or a bare preposition as an excluded party", () => {
    // The other three `except` subjects in the corpus. None carves out a
    // party, and each produced a confident non-answer in a field whose whole
    // job is to name the party that does NOT owe the duty.
    const cases: [string, string][] = [
      // "except as provided in …" — a cross-reference. Excluded "as provided
      // in a".
      [
        "Waiver",
        "Each Spouse waives the right to elect against the other's will, to a " +
          "spousal or family allowance, to homestead, and to any statutory " +
          "share, except as provided in a will, revocable trust, or " +
          "beneficiary designation executed after the date of this Agreement.",
      ],
      // "except by will or the laws of descent" — a manner. Excluded "by".
      [
        "Transfer",
        "The Option is not transferable except by will or the laws of descent " +
          "and distribution, and during the Optionee's lifetime is exercisable " +
          "only by the Optionee.",
      ],
      // A shouted warranty disclaimer. Excluded "AS THOSE".
      [
        "Warranty",
        "THIS WARRANTY IS IN LIEU OF ALL OTHER WARRANTIES, EXPRESS OR IMPLIED, " +
          "INCLUDING MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, " +
          "EXCEPT AS THOSE MAY NOT BE EXCLUDED UNDER MANDATORY LAW.",
      ],
    ];
    for (const [heading, text] of cases) {
      const oblis = extractObligations(buildTree([heading, text]), []);
      expect(
        oblis.length,
        `${heading}: nothing extracted, so this asserts nothing`,
      ).toBeGreaterThan(0);
      for (const o of oblis) {
        expect(o.obligor_exclusion, `${heading} excluded ${o.obligor_exclusion}`).toBeUndefined();
      }
    }
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

  it("does not split a clause at a cross-reference abbreviation either", () => {
    // The clause splitter's "." boundary exists to recover a duty stranded
    // behind an ambiguous abbreviation, but it knew nothing about cross
    // references, so it undid the sentence fix one stage later and handed the
    // second duty the obligor "4 of this Agreement and Client".
    const obs = extractObligations(
      buildTree([
        "Reporting",
        "Provider shall submit the report described in Ex. 4 of this Agreement and Client shall pay the invoice within 30 days.",
      ]),
      [],
    );
    expect(obs.map((o) => o.obligor)).toEqual(["Provider"]);
    expect(obs[0]!.action.startsWith("submit the report described in Ex. 4")).toBe(true);
  });

  it("does not end a sentence at a cross-reference or date abbreviation", () => {
    // The obligations splitter and SENTENCE_END in walk.ts had drifted: the
    // shared pattern already kept "Ex. 4" whole, but this hand-rolled scan
    // never got the list, so the action was truncated at "described in Ex" and
    // the rest dropped as an unterminated remainder. Both now read one list.
    const ex = extractObligations(
      buildTree([
        "Reporting",
        "Provider shall submit the quarterly compliance report described in Ex. 4 of this Agreement.",
      ]),
      [],
    );
    expect(ex[0]!.action).toBe(
      "submit the quarterly compliance report described in Ex. 4 of this Agreement",
    );
    const jan = extractObligations(
      buildTree(["Renewal", "Provider shall deliver the renewal notice by Jan. 5 of each year."]),
      [],
    );
    expect(jan[0]!.action).toBe("deliver the renewal notice by Jan. 5 of each year");
  });

  it("recovers a duty stranded behind a clock abbreviation that ends a sentence", () => {
    // "5:00 p.m. Eastern Time" is one sentence and "5:00 p.m. The Provider
    // shall …" is two, and nothing local tells them apart — so the splitter
    // keeps them together and the clause splitter separates them at the period
    // instead. Without that, the Provider's duty was swallowed into the
    // previous sentence's action and the only obligation reported had the
    // obligor "Notice".
    const obs = extractObligations(
      buildTree([
        "Notices",
        "Notice must be delivered no later than 5:00 p.m. The Provider shall then execute the definitive documents.",
      ]),
      [],
    );
    expect(obs.map((o) => o.obligor)).toEqual(["Notice", "The Provider"]);
    expect(obs[1]!.action).toBe("then execute the definitive documents");
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

describe("a sentence that opens with a fronted adverbial", () => {
  const obligorsOf = (text: string) => {
    const tree = buildTree(["Body", text]);
    return extractObligations(tree, extractParties(tree)).map((o) => o.obligor);
  };

  it("takes the subject after the comma, not the whole adverbial", () => {
    // The subject capture reaches back to the start of the clause, so the
    // adverbial came with it and the last-resort branch published "days after
    // the Effective Date, Seller" as the party who owes the duty — in the
    // findings and in the critical-dates register.
    expect(
      obligorsOf(
        "Within five (5) business days after the Effective Date, Seller shall deliver the rent roll to Buyer.",
      ),
    ).toContain("Seller");
    expect(
      obligorsOf(
        "For three (3) years after the Closing, each Seller shall not solicit any employee of the Company.",
      ),
    ).toContain("each Seller");
    expect(
      obligorsOf(
        "Until the expiration of four (4) years after the furnishing of the Services, Medical Director shall make the records available.",
      ),
    ).toContain("Medical Director");
  });

  it("leaves a genuinely comma-bearing subject alone", () => {
    // Keyed on the opening subordinator: a compound subject does not start
    // with one, so its commas are not treated as the end of an adverbial.
    // The subject keeps all three names rather than being cut back to the
    // text after its last comma.
    expect(
      obligorsOf("Seller, Buyer, and the Company shall each bear their own expenses."),
    ).toContain("Seller, Buyer, and the Company");
  });
});

/**
 * "to the extent" was a recognized fronted adverbial and "to the FULLEST
 * extent permitted by law," — the opening of nearly every American indemnity
 * clause — was not, so the obligor read "fullest extent permitted by law,
 * Architect" and matched no party. OBLI-002 then called a mutual indemnity
 * one-sided.
 */
describe("a fronted adverbial does not become the obligor", () => {
  const parties = extractParties(
    buildTree([
      "Doc",
      'This Agreement is between Harrowgate Community Health, a Pennsylvania nonprofit corporation ("Owner"), and Vessel & Roark Architects LLP, a Pennsylvania limited liability partnership ("Architect").',
    ]),
  );

  it.each([
    "To the fullest extent permitted by law, Architect shall indemnify Owner.",
    "To the maximum extent permitted by law, Architect shall indemnify Owner.",
    "Following the Closing, Architect shall indemnify Owner.",
  ])("%s", (sentence) => {
    const got = extractObligations(buildTree(["Indemnity", sentence]), parties);
    expect(got.map((o) => o.obligor)).toContain("Architect");
  });
});

/**
 * "will" is also a noun, and legal documents are where it is one.
 *
 * "employment with the Company is at will", "any trust created under this
 * Will", "by beneficiary designation, or by will" — each matched the modal
 * list, produced an obligor that was a sentence fragment ("employment with the
 * Company is at"), and an ACTION THAT WAS EMPTY. The obligations ledger's whole
 * proposition is "who must do what"; a row with the what missing was printed
 * into the CSV a lawyer reads. Seven across the corpus.
 */
describe("extractObligations — a modal with no verb phrase after it", () => {
  const obl = (tree: ReturnType<typeof buildTree>) => extractObligations(tree, []);
  const actions = (text: string): string[] =>
    obl(buildTree(["Agreement", text])).map((o) => o.action);

  it("does not read at-will employment as an obligation", () => {
    expect(
      actions("Employment with the Company is at will and may be terminated at any time."),
    ).not.toContain("");
    expect(obl(buildTree(["Agreement", "Employment with the Company is at will."]))).toEqual([]);
  });

  it("does not read the testamentary instrument as an obligation", () => {
    expect(
      obl(buildTree(["Last Will", "The residue passes to any trust created under this Will."])),
    ).toEqual([]);
  });

  it("still reads 'will' as a modal when a verb phrase follows it", () => {
    // The whole point of keeping "will" in the modal list.
    const out = actions("Provider will deliver the Deliverables to Customer.");
    expect(out.some((a) => /deliver the Deliverables/.test(a))).toBe(true);
  });

  it("keeps a duty whose action was swallowed by its own trigger", () => {
    // The narrow test is `no action AND no trigger AND no qualifier`. Here the
    // trigger pattern's tail runs to the end of the sentence and takes the verb
    // phrase with it — a real duty, and it must survive.
    const out = obl(
      buildTree([
        "Notice",
        "If you record a notice of completion, you must within 10 days after recording send a copy of the notice to your contractor.",
      ]),
    );
    expect(out.length).toBeGreaterThan(0);
    expect(out[0]!.trigger).toMatch(/within 10 days/);
  });
});

/**
 * The sentence splitter's paths nothing had executed.
 *
 * `splitSentences` came back with twelve **NoCoverage** mutants — lines no test
 * runs at all — and three of them are the difference between finding a duty and
 * silently not:
 *
 *  - the **no-terminator fallback**. A paragraph with no `.`/`!`/`?` yields zero
 *    sentences, and without the fallback yields zero obligations. Numbered list
 *    items, table cells and heading-style clauses routinely have no final
 *    period, so this branch is what keeps their duties in the ledger — and it
 *    could have been deleted with nothing failing.
 *  - `!` and `?` as terminators. Rare in a contract and not absent from one:
 *    "NOTICE!", a question in an intake form.
 *  - a paragraph that **opens** with a terminator, which the leading-terminator
 *    skip exists for.
 */
describe("extractObligations — sentences the splitter had never been given", () => {
  const obl = (text: string) => extractObligations(buildTree(["Agreement", text]), []);

  it("reads a clause with NO sentence terminator at all", () => {
    // The fallback branch: no terminator, so the whole paragraph is one
    // sentence. Without it this duty does not exist.
    const out = obl("Provider shall deliver the Deliverables by Friday");
    expect(out).toHaveLength(1);
    expect(out[0]!.obligor).toBe("Provider");
    expect(out[0]!.action).toContain("deliver the Deliverables");
  });

  it("treats ? and ! as sentence terminators", () => {
    const q = obl("Who bears the cost? Provider shall pay all shipping charges.");
    expect(q).toHaveLength(1);
    // The duty is the second sentence — the question is not swallowed into it.
    expect(q[0]!.action).toBe("pay all shipping charges");

    const bang = obl("NOTICE! Recipient must return all materials within ten days.");
    expect(bang).toHaveLength(1);
    expect(bang[0]!.obligor).toBe("Recipient");
    expect(bang[0]!.action).toContain("return all materials");
  });

  it("skips a terminator that OPENS the paragraph", () => {
    const out = obl(". Provider shall indemnify the Client against third-party claims.");
    expect(out).toHaveLength(1);
    expect(out[0]!.action).toContain("indemnify the Client");
  });
});

/**
 * Who is on the hook — the four answers `resolveObligor` can give, three of
 * which no test reached.
 *
 * The obligor is printed in the obligations ledger and read by OBLI-002 to
 * decide whether a duty is one-sided, so getting it wrong is not a cosmetic
 * error: attributing a MUTUAL obligation to one party manufactures an
 * asymmetry that the document does not contain. Mutation testing reported the
 * role branch of the compound-subject resolver, the direct party-name match
 * and the last-resort fallback as executed by no test at all.
 */
describe("resolveObligor — who the duty lands on", () => {
  const parties = [
    { name: "Vanterra Systems, Inc.", role: "provider" },
    { name: "Halbrook Diagnostics LLC", role: "customer" },
  ] as unknown as Parameters<typeof extractObligations>[1];

  const obligor = (line: string): string | undefined =>
    extractObligations(buildTree(["Agreement", line]), parties)[0]?.obligor;

  it("reads a compound subject of two ROLES as both parties, not the last one", () => {
    // The `endsWith` matches below key on the TAIL of the subject, so without
    // this branch "The Provider and the Customer" resolves to the Customer
    // alone and OBLI-002 reports a shared duty as one-sided.
    expect(obligor("The Provider and the Customer shall each maintain insurance.")).toBe(
      "the parties",
    );
  });

  it("reads a compound subject of two NAMES the same way", () => {
    expect(
      obligor("Vanterra Systems, Inc. and Halbrook Diagnostics LLC shall jointly fund the escrow."),
    ).toBe("the parties");
  });

  it("picks the party name out of a long subject, rather than its last six words", () => {
    // The discriminating case for the direct-name branch: a subject of ELEVEN
    // words ending in the party's name. The last-resort fallback would answer
    // "under this Agreement, Halbrook Diagnostics LLC"; the name match answers
    // the party.
    expect(
      obligor(
        "The party receiving the Services under this Agreement, Halbrook Diagnostics LLC shall pay the fees.",
      ),
    ).toBe("Halbrook Diagnostics LLC");
  });

  it("reports the casing the DOCUMENT used, not the casing of the party list", () => {
    // Matching is lower-cased; what is published has to be what the document
    // wrote, or the obligations ledger quietly renames the party.
    expect(
      obligor(
        "The party receiving the Services under this Agreement, HALBROOK DIAGNOSTICS LLC shall pay the fees.",
      ),
    ).toBe("HALBROOK DIAGNOSTICS LLC");
  });

  it("falls back to the last few words when the subject names no known party", () => {
    // Deliberate, and the reason is recorded in this module: an unresolvable
    // subject yields a FRAGMENT rather than an empty string, because the
    // fragment is at least evidence a reader can check. The alternative —
    // emitting "" — is the state OBLI-001 exists to flag and the extractor
    // never produces.
    const fragment = obligor(
      "The party responsible for the retained subcontractor performing the work shall indemnify the other.",
    );
    expect(fragment).toBe("the retained subcontractor performing the work");
    expect(fragment!.split(/\s+/).length).toBeLessThanOrEqual(6);
  });
});

/**
 * A HYPHEN IS A WORD BOUNDARY, and employment documents are where that bites.
 *
 * `MODAL_RE` opens on `\b`, which sits between the "-" and the "will" of
 * "at-will", so the compound's second half read as the obligation modal. The
 * empty-action guard cannot reach these: the compound's FIRST half supplies a
 * plausible-looking obligor and its remainder a plausible-looking action, so
 * the row is nonsense rather than blank. 22 rows across 13 specimens.
 */
describe("extractObligations — a modal inside a hyphenated compound", () => {
  it("does not read the 'will' of 'at-will' as a modal", () => {
    const tree = buildTree([
      "Employment",
      "No provision of this Agreement alters the at-will nature of the employment.",
    ]);
    expect(extractObligations(tree, [])).toHaveLength(0);
  });

  it("does not turn an at-will section heading into a duty", () => {
    const tree = buildTree(["Employment", "Term; At-Will Employment."]);
    expect(extractObligations(tree, [])).toHaveLength(0);
  });

  it("keeps the real duty in a sentence that also says at-will", () => {
    const tree = buildTree([
      "Employment",
      "No manager has authority to alter the at-will relationship, and any such " +
        "alteration must be in a writing signed by the Chief Executive Officer.",
    ]);
    const oblis = extractObligations(tree, []);
    expect(oblis).toHaveLength(1);
    expect(oblis[0]!.modal).toBe("must");
    expect(oblis[0]!.action).toContain("be in a writing signed by the Chief Executive Officer");
  });

  it("still reads a modal that merely FOLLOWS a hyphenated word", () => {
    const tree = buildTree([
      "Services",
      "The sub-contractor shall deliver the Services on the agreed date.",
    ]);
    const oblis = extractObligations(tree, []);
    expect(oblis).toHaveLength(1);
    expect(oblis[0]!.modal).toBe("shall");
  });

  it("still reads a modal after a dash that opens a clause", () => {
    const tree = buildTree([
      "Services",
      "The Provider has one duty — Provider shall deliver the Services on time.",
    ]);
    const oblis = extractObligations(tree, []);
    expect(oblis.some((o) => o.modal === "shall")).toBe(true);
  });
});

/**
 * A subordinator is not part of the subject it introduces.
 *
 * "obtain written assurances from the recipient THAT the recipient will
 * notify …" makes the duty the recipient's; the "that" attaches the clause and
 * printed straight into the obligations ledger's obligor column. 11 rows
 * across the corpus.
 */
describe("resolveObligor — a leading subordinator", () => {
  it("strips a 'that' introducing the clause whose subject follows", () => {
    const tree = buildTree([
      "Confidentiality",
      "Business Associate shall obtain reasonable assurances from the recipient that " +
        "the PHI will be held confidentially, and that the recipient will notify " +
        "Business Associate of any breach of confidentiality.",
    ]);
    const oblis = extractObligations(tree, []);
    const row = oblis.find((o) => o.modal === "will");
    expect(row?.obligor).toBe("the recipient");
  });

  it("keeps a DEMONSTRATIVE 'that', which names which one", () => {
    // "that party" is a subject whose first word is doing real work: strip it
    // and the ledger no longer says which party owes the duty.
    const tree = buildTree([
      "Notices",
      "If a party receives a notice, that party shall acknowledge it within two days.",
    ]);
    const oblis = extractObligations(tree, []);
    expect(oblis[0]!.obligor.toLowerCase()).toContain("that party");
  });

  it("strips a leading 'which' the same way", () => {
    const tree = buildTree([
      "Approvals",
      "Tenant shall make the alterations with plans Landlord approves, which the " +
        "approval shall not be unreasonably withheld.",
    ]);
    const oblis = extractObligations(tree, []);
    expect(oblis.every((o) => !/^which\s/i.test(o.obligor))).toBe(true);
  });
});
