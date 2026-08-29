import { describe, expect, it } from "vitest";
import { extractDefinitions } from "./definitions.js";
import { buildTree } from "./_fixtures.js";

describe("extractDefinitions", () => {
  it("captures inline quoted definitions", () => {
    const tree = buildTree([
      "Body",
      '"Confidential Information" means any non-public information shared between the parties.',
      "Each party shall protect the Confidential Information.",
    ]);
    const map = extractDefinitions(tree);
    const entry = map.entries.find((e) => e.term === "Confidential Information");
    expect(entry).toBeDefined();
    expect(entry?.used_at.length).toBeGreaterThan(0);
  });

  it("captures a quoted defined term with an internal abbreviation period", () => {
    // "U.S. Person" / "U.K. Subsidiary" — a period-bearing abbreviation is a
    // common defined term in tax and securities agreements. The primary inline
    // matcher's term class dropped the period, so the closing quote never lined
    // up and the whole definition was lost (STRUCT-006 then reported the term as
    // used-but-undefined).
    const tree = buildTree([
      "Definitions",
      '"U.S. Person" means any person resident in the U.S.A. for tax purposes.',
      "Each U.S. Person shall provide a tax certification.",
    ]);
    const map = extractDefinitions(tree);
    const entry = map.entries.find((e) => e.term === "U.S. Person");
    expect(entry).toBeDefined();
    expect(entry?.definition).toContain("U.S.A.");
    expect(entry?.used_at.length).toBeGreaterThan(0);
  });

  it("captures a bare (unquoted) defined term with an internal period", () => {
    // Interpretation sections define terms unquoted — "U.S. Person means …",
    // "Non-U.S. Holder means …". The bare matcher's term class dropped the
    // period, so these period-bearing terms went unregistered.
    const tree = buildTree([
      "Definitions",
      "U.S. Person means any person resident in the U.S.A. for tax purposes.",
      "Non-U.S. Holder means a holder that is not a U.S. Person.",
    ]);
    const terms = extractDefinitions(tree).entries.map((e) => e.term);
    expect(terms).toEqual(expect.arrayContaining(["U.S. Person", "Non-U.S. Holder"]));
  });

  it("reads bare and glossary definitions under an 'Interpretation' heading", () => {
    // UK/commonwealth drafting titles the section "Interpretation" rather than
    // "Definitions"; the bare `Term means …` and quoted `"Term": …` glossary
    // forms are Pass-1-only, so without the heading they were missed and their
    // uses reported by STRUCT-006 as used-but-undefined.
    const tree = buildTree([
      "Interpretation",
      "Business Day means any day other than a Saturday, Sunday or public holiday.",
      '"Delivery Point": the loading dock at the facility.',
      "In this Agreement, the singular includes the plural and vice versa.",
      "Headings are for convenience only and shall not affect interpretation.",
      "The Business Day count starts at the Delivery Point.",
    ]);
    const entries = extractDefinitions(tree).entries;
    const terms = entries.map((e) => e.term);
    expect(terms).toContain("Business Day");
    expect(terms).toContain("Delivery Point");
    // The glossary definition text is captured cleanly — no stray fragment of
    // the term prepended (regression: a `text.slice(term.length)` offset landed
    // mid-term and produced 't": the loading dock …').
    const deliveryPoint = entries.find((e) => e.term === "Delivery Point");
    expect(deliveryPoint?.definition).toBe("the loading dock at the facility.");
    // Construction rules in the same section are not spurious defined terms.
    expect(terms).not.toContain("In this Agreement");
    expect(terms).not.toContain("Headings");
  });

  it("counts a plural use of a singular-defined term as a use", () => {
    // A term defined in the singular but used only in the plural was reported by
    // STRUCT-005 as an unused template leftover even though it is used.
    const tree = buildTree([
      "Definitions",
      '"Confidential Material" means any non-public information.',
      '"Disclosing Party" means the party sharing information.',
      "Each party shall protect the Confidential Materials it receives from the Disclosing Parties.",
    ]);
    const map = extractDefinitions(tree);
    expect(map.unused_terms).not.toContain("Confidential Material");
    expect(map.unused_terms).not.toContain("Disclosing Party");
    expect(map.entries.find((e) => e.term === "Confidential Material")?.used_at.length).toBe(1);
  });

  it("counts a singular use of a plural-defined term as a use", () => {
    // Mirror of the above: a term defined in the plural but used only in the
    // singular ("Deliverables" … "each Deliverable"; "Affiliates" … "an
    // Affiliate") is still used, not an unused template leftover.
    const tree = buildTree([
      "Definitions",
      '"Deliverables" means the items listed in the SOW.',
      '"Affiliates" means entities under common control.',
      "Provider shall submit each Deliverable to any Affiliate on request.",
      "A late Deliverable incurs a penalty.",
    ]);
    const map = extractDefinitions(tree);
    expect(map.unused_terms).not.toContain("Deliverables");
    expect(map.unused_terms).not.toContain("Affiliates");
  });

  it("does not treat an unrelated word sharing a prefix as a plural use", () => {
    const tree = buildTree([
      "Definitions",
      '"Fee" means the amount payable for the Services.',
      "The Customer may submit Feedback about the platform.",
    ]);
    const map = extractDefinitions(tree);
    // "Feedback" is not a use of "Fee"/"Fees"; the term stays unused.
    expect(map.unused_terms).toContain("Fee");
  });

  it("records defined-but-never-used terms", () => {
    const tree = buildTree([
      "Definitions",
      '"Unused Term" means something that is never referenced again.',
    ]);
    const map = extractDefinitions(tree);
    expect(map.unused_terms).toContain("Unused Term");
  });

  it("resolves a definition by reference to an exhibit", () => {
    const tree = buildTree([
      "Definitions",
      '"Master Agreement" means the Master Service Agreement attached as Exhibit A.',
      "The Master Agreement governs the relationship.",
    ]);
    const entry = extractDefinitions(tree).entries.find((e) => e.term === "Master Agreement");
    expect(entry?.reference).toBe("Exhibit A");
  });

  it("captures a scope-gated definition", () => {
    const tree = buildTree([
      "Pricing",
      'For the purposes of this Section 4, "Customer" means the end user only.',
      "The Customer pays the fees under this Section 4.",
    ]);
    const entry = extractDefinitions(tree).entries.find((e) => e.term === "Customer");
    expect(entry?.scope).toMatch(/Section 4/);
  });

  it("detects circular definitions", () => {
    const tree = buildTree([
      "Definitions",
      '"Term" means the period ending on the Termination Date.',
      '"Termination Date" means two years from the start of the Term.',
      "The Term and the Termination Date are referenced throughout.",
    ]);
    const map = extractDefinitions(tree);
    expect(map.circular_terms).toBeDefined();
    const flat = (map.circular_terms ?? []).flat();
    expect(flat).toContain("Term");
    expect(flat).toContain("Termination Date");
  });

  it("captures a definition whose 'Means' is capitalized", () => {
    // Sentence-initial / ALL-CAPS / OCR'd drafting capitalizes "Means"; the
    // quoted term makes it unambiguously a definition regardless of case.
    const tree = buildTree(["Definitions", '"Deliverable" Means any work product provided.']);
    expect(extractDefinitions(tree).entries.map((e) => e.term)).toContain("Deliverable");
    // A bare "means" in prose (no quoted term) is still not a definition.
    const prose = buildTree(["Body", "The parties agree this means nothing formal."]);
    expect(extractDefinitions(prose).entries).toHaveLength(0);
  });

  it("does not attach an unrelated later sentence's exhibit as a definition reference", () => {
    const tree = buildTree([
      "Definitions",
      '"Payment" means the amount due each month. Shipping is set forth in Exhibit B for reference only.',
    ]);
    const payment = extractDefinitions(tree).entries.find((e) => e.term === "Payment");
    expect(payment?.reference).toBeUndefined();
    // A genuine by-reference definition in the term's own clause still resolves.
    const specs = extractDefinitions(
      buildTree(["Definitions", '"Specs" means the specifications set forth in Exhibit A.']),
    ).entries.find((e) => e.term === "Specs");
    expect(specs?.reference).toBe("Exhibit A");
  });
});

describe("parenthetical definitions", () => {
  it("reads the convention commercial drafting actually uses", () => {
    // Recognizing only `"Term" means …` made STRUCT-004 report "Vaulytica did
    // not find a Definitions section or any inline-defined terms" on 15 of the
    // 19 minimal-PASS fixtures, every one of which defines its terms this way.
    const map = extractDefinitions(
      buildTree([
        "Agreement",
        'This MSA is between Acme Corp, a Delaware corporation ("Customer"), and Globex Solutions Inc., a California corporation ("Vendor").',
        'Vendor retains its pre-existing tools and methodologies ("Vendor Background IP") and grants Customer a license to them.',
      ]),
    );
    expect(map.entries.map((e) => e.term).sort()).toEqual([
      "Customer",
      "Vendor",
      "Vendor Background IP",
    ]);
    expect(map.entries.every((e) => e.form === "parenthetical")).toBe(true);
  });

  it("counts a use in the same paragraph as the parenthetical", () => {
    // The definition is mid-sentence in the operative text, and the same
    // paragraph routinely goes on to use the term. Skipping the whole
    // paragraph reported it as never used.
    const map = extractDefinitions(
      buildTree([
        "Precedence",
        'In the event of any conflict between this MSA and any Statement of Work ("SOW"), the SOW shall control as to the services it describes.',
      ]),
    );
    expect(map.unused_terms).toEqual([]);
  });

  it("still reports a parenthetical term that is never used again", () => {
    const map = extractDefinitions(
      buildTree([
        "Indemnity",
        'Vendor shall indemnify Customer and its officers, directors, and agents ("Customer Indemnitees") from third-party claims.',
      ]),
    );
    expect(map.unused_terms).toContain("Customer Indemnitees");
  });

  it("does not read a quoted phrase used mid-parenthetical as a definition", () => {
    const map = extractDefinitions(
      buildTree(["Services", 'Vendor shall provide the "Services" described in Exhibit A.']),
    );
    expect(map.entries.map((e) => e.term)).not.toContain("Services");
  });

  it("registers both terms of a paired collective/individual parenthetical", () => {
    const map = extractDefinitions(
      buildTree([
        "Parties",
        'The Persons admitted as limited partners (each a "Limited Partner" and, together with the General Partner, the "Partners") shall contribute capital.',
      ]),
    );
    expect(map.entries.map((e) => e.term).sort()).toEqual(["Limited Partner", "Partners"]);
  });

  it("registers both terms of an individually/collectively pair", () => {
    const map = extractDefinitions(
      buildTree(["Parties", 'The buyers (individually a "Party" and collectively the "Parties").']),
    );
    expect(map.entries.map((e) => e.term).sort()).toEqual(["Parties", "Party"]);
  });

  it("registers a term that trails a prose appositive inside the parenthetical", () => {
    // "$2,000,000 (together with all interest and earnings thereon, the
    // 'Escrow Fund')" — the whitelist-only DEFINITION_PARENTHETICAL never saw
    // this, so STRUCT-006 reported the escrow's central term as undefined.
    const map = extractDefinitions(
      buildTree([
        "Escrow Fund",
        'The Buyer shall deposit the sum of $2,000,000 (together with all interest and earnings thereon, the "Escrow Fund").',
      ]),
    );
    expect(map.entries.map((e) => e.term)).toContain("Escrow Fund");
  });

  it("registers a period/term defined by its bounds ('shall begin … until')", () => {
    // A tolling agreement defines its central term as `The "Tolling Period"
    // shall begin on the Effective Date and shall continue until …`, which the
    // "means"/"refers to" inline forms never saw, so STRUCT-006 reported it
    // used-but-undefined.
    const map = extractDefinitions(
      buildTree([
        "Tolling Period",
        'The "Tolling Period" shall begin on the Effective Date and shall continue until thirty (30) days after either Party delivers notice.',
      ]),
    );
    expect(map.entries.map((e) => e.term)).toContain("Tolling Period");
  });

  it("does not treat a non-period quoted term with 'shall begin' as a definition", () => {
    const map = extractDefinitions(
      buildTree(["Services", 'The "Services" shall begin promptly after the Effective Date.']),
    );
    expect(map.entries.map((e) => e.term)).not.toContain("Services");
  });

  it("registers a conditionally-occupied role defined with 'when it …' (mutual NDA)", () => {
    // Both parties share each role, so it is never "(the 'X')" or "means"; the
    // quoted term + "when it discloses/receives" is the definition.
    const map = extractDefinitions(
      buildTree([
        "Parties",
        'Each party may act as a "Disclosing Party" when it discloses Confidential Information and as a "Receiving Party" when it receives Confidential Information.',
      ]),
    );
    const terms = map.entries.map((e) => e.term);
    expect(terms).toContain("Disclosing Party");
    expect(terms).toContain("Receiving Party");
  });

  it("does not read a used-only quoted term without the appositive comma", () => {
    // "(a sum equal to the 'Base Amount')" USES the term; there is no comma
    // before 'the', so the trailing-parenthetical form must not register it.
    const map = extractDefinitions(
      buildTree(["Fees", 'The fee is a sum equal to the "Base Amount" set in Exhibit B.']),
    );
    expect(map.entries.map((e) => e.term)).not.toContain("Base Amount");
  });
});

describe("signature-block names are not undefined defined-terms", () => {
  it("does not flag a name+label bled across a joined 'Name:/Title:' block", () => {
    // Ingest joins the execution-block lines into one paragraph, so
    // "Name: Eleanor Vance Title: Chief Executive Officer" swept "Eleanor
    // Vance Title" into a phantom Title-Case term.
    const map = extractDefinitions(
      buildTree([
        "Signatures",
        "By: ____________________ Name: Eleanor Vance Title: Chief Executive Officer",
      ]),
    );
    const terms = map.undefined_capitalized.map((e) => e.term);
    expect(terms).not.toContain("Eleanor Vance Title");
    expect(terms).not.toContain("Eleanor Vance");
  });

  it("does not flag the printed name beneath a signature blank", () => {
    // "________ Elena Marquez, Incorporator" — the incorporator signs by bare
    // name and is named nowhere else, so STRUCT-006 read her as an undefined
    // Title-Case term.
    const map = extractDefinitions(
      buildTree([
        "Incorporator",
        "The name of the incorporator is Elena Marquez. _______________________________ Elena Marquez, Incorporator",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain("Elena Marquez");
  });
});

describe("a term defined by a copula and a value", () => {
  it("registers 'The \"X\" is <amount>' and its shall-be / percent variants", () => {
    // Ordinary drafting for a term whose definition is a single number. None
    // of the "means" / "refers to" / "is defined as" matchers saw it, so
    // STRUCT-006 reported a convertible note's own "Valuation Cap" as
    // used-but-undefined.
    const cap = extractDefinitions(
      buildTree([
        "Conversion",
        'The "Valuation Cap" is $12,000,000. The Valuation Cap applies at conversion.',
      ]),
    );
    expect(cap.entries.map((e) => e.term)).toContain("Valuation Cap");
    expect(cap.undefined_capitalized.map((e) => e.term)).not.toContain("Valuation Cap");

    const period = extractDefinitions(
      buildTree([
        "Cure",
        'The "Cure Period" shall be ten (10) business days. The Cure Period applies.',
      ]),
    );
    expect(period.entries.map((e) => e.term)).toContain("Cure Period");

    const pct = extractDefinitions(
      buildTree([
        "Discount",
        'The "Discount Rate" is twenty percent (20%). The Discount Rate applies.',
      ]),
    );
    expect(pct.entries.map((e) => e.term)).toContain("Discount Rate");
  });

  it("does not read a quoted usage as a definition", () => {
    // The gate is a NUMBER close behind the copula — that is what makes the
    // clause a value rather than a comment about the term.
    const m = extractDefinitions(
      buildTree([
        "Dispute",
        'The "Threshold" is ambiguous and the parties disagree about what it requires of them.',
      ]),
    );
    expect(m.entries.map((e) => e.term)).not.toContain("Threshold");
  });
});

describe("an alphanumeric instrument number is not an undefined defined-term", () => {
  it("does not flag 'Policy No' before a prefixed identifier", () => {
    // "Policy No. CGL-4471982" captures as "Policy No" — the abbreviation's
    // word survives, its period and number do not. The guard tested for
    // digits only, so a policy, claim, docket, or purchase-order number with
    // a letter prefix slipped through and every insurance letter was told it
    // had forgotten to define "Policy No".
    const map = extractDefinitions(
      buildTree([
        "Coverage",
        "Meridian issued Policy No. CGL-4471982 to the insured. Policy No. CGL-4471982 was in effect on the date of loss.",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain("Policy No");
  });

  it("still flags when a sentence merely continues after the abbreviation", () => {
    // The widened test requires a digit, so a capitalized word following the
    // period is not mistaken for an instrument number.
    const map = extractDefinitions(
      buildTree([
        "Orders",
        "The parties executed Change Order No. The Change Order No governs. The Change Order No is attached.",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term)).toContain("Change Order No");
  });
});

describe("the tail of a rules citation is not an undefined defined-term", () => {
  it("does not flag the authority named after 'Rules of'", () => {
    // "Ohio Rules of Professional Conduct" breaks into two Title-Case runs at
    // the lowercase "of": "Ohio Rules" (already excluded as a citation) and
    // "Professional Conduct". Every engagement letter, conflicts waiver, and
    // ethics policy cites the body repeatedly, and STRUCT-006 reported it as a
    // term the document forgot to define.
    const map = extractDefinitions(
      buildTree([
        "Confidentiality",
        "We will not disclose it except as the Ohio Rules of Professional Conduct permit. We may withdraw to the extent permitted by the Ohio Rules of Professional Conduct.",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain("Professional Conduct");
  });

  it("still flags an ordinary capitalized phrase that follows an 'of'", () => {
    // The exclusion is gated on the authority noun before the "of" — a
    // "Statement of Base Services" is exactly the sort of undefined document
    // title STRUCT-006 exists to surface.
    const map = extractDefinitions(
      buildTree([
        "Services",
        "The work is described in the Statement of Base Services. The Statement of Base Services governs the order of precedence.",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term)).toContain("Base Services");
  });
});

describe("place names are not undefined defined-terms", () => {
  it("does not flag a US state named in a governing-law clause", () => {
    const map = extractDefinitions(
      buildTree([
        "Governing Law",
        "This Agreement is governed by the laws of the State of New York, and the parties consent to the jurisdiction of the courts located in New York County, New York.",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain("New York");
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain("New York County");
  });

  it("a street name ending in Way, Place, or Court is an address, not a defined term", () => {
    // The street-suffix guard listed nine suffixes and not the ones a modern
    // address actually uses. "88 Harbor Way" was reported, twice, as a
    // Title-Case term a WARN notice had forgotten to define.
    const map = extractDefinitions(
      buildTree([
        "Notice",
        "The facility at 88 Harbor Way will close. Questions may be directed to the office at 88 Harbor Way.",
        "The hearing is set in the Superior Court. The Superior Court will rule on the motion.",
      ]),
    );
    const terms = map.undefined_capitalized.map((e) => e.term);
    expect(terms).not.toContain("Harbor Way");
    expect(terms).not.toContain("Superior Court");
  });

  it("a lawyer named with the post-nominal is a person, not a defined term", () => {
    // A privilege log, a certificate of service, and a signature block all
    // name people who are not parties, so the party extractor never sees
    // them and every name used twice was reported as undefined.
    const map = extractDefinitions(
      buildTree([
        "Privilege Log",
        "Author: Marcus Field, Esq. Recipients: Priya Raman.",
        "Entry 2 was prepared by Marcus Field, Esq. for the client.",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain("Marcus Field");
  });

  it("a rule of procedure is a citation, not a defined term", () => {
    // "Act", "Code", and "Law" were already excluded by suffix; "Rule" needs
    // the citation shape to follow it, because a document may genuinely
    // define a "Program Rule".
    const map = extractDefinitions(
      buildTree([
        "Order",
        "Good cause exists under Federal Rule of Civil Procedure 26(c).",
        "Production is governed by Federal Rule of Evidence 502(d).",
        "Each Program Rule adopted by the committee is binding. A Program Rule may be amended.",
      ]),
    );
    const terms = map.undefined_capitalized.map((e) => e.term);
    expect(terms).not.toContain("Federal Rule");
    expect(terms).toContain("Program Rule");
  });

  it("a statute title longer than the capture window is still a statute", () => {
    // TITLE_CASE_PHRASE caps at five words, so "New York Limited Liability
    // Company Law" captures as "New York Limited Liability Company" and the
    // Act/Code/Law suffix test cannot see the word that makes it a law. Every
    // set of New York articles of organization names it twice.
    const map = extractDefinitions(
      buildTree([
        "Articles of Organization",
        "The undersigned files these Articles under Section 203 of the New York Limited Liability Company Law.",
        "The company is formed for any lawful purpose under the New York Limited Liability Company Law.",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain(
      "New York Limited Liability Company",
    );
  });

  it("a revenue procedure or treasury regulation is a citation too", () => {
    // Every LLC and profits-interest agreement cites these by name, twice or
    // more, and each one was reported as a Title-Case term left undefined.
    const map = extractDefinitions(
      buildTree([
        "Award",
        "The Units are intended to be profits interests under Revenue Procedure 93-27.",
        "The Company and the Participant intend that the Units qualify under Revenue Procedure 93-27 and Revenue Ruling 99-5.",
        "Capital accounts are maintained as permitted by Treasury Regulation § 1.704-1(b)(2)(iv)(f), and the Company will follow Treasury Regulation § 1.704-1 in all events.",
      ]),
    );
    const terms = map.undefined_capitalized.map((e) => e.term);
    expect(terms).not.toContain("Revenue Procedure");
    expect(terms).not.toContain("Revenue Ruling");
    expect(terms).not.toContain("Treasury Regulation");
  });

  it("still flags an ordinary undefined Title-Case business term", () => {
    const map = extractDefinitions(
      buildTree([
        "Body",
        "The Special Reserve Fund shall be maintained. The Special Reserve Fund covers losses.",
      ]),
    );
    // The leading article is normalized off the reported term.
    expect(map.undefined_capitalized.map((e) => e.term)).toContain("Special Reserve Fund");
  });
});

describe("hyphenated-compound fragments are not undefined terms", () => {
  it("does not flag 'Disclosure Agreement' from 'Non-Disclosure Agreement'", () => {
    const map = extractDefinitions(
      buildTree([
        "NDA",
        "This Non-Disclosure Agreement governs the exchange. This Non-Disclosure Agreement is binding on both parties.",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain("Disclosure Agreement");
  });

  it("reads 'Cross-Border Transfer Mechanism' as ONE term, not a fragment", () => {
    const map = extractDefinitions(
      buildTree([
        "Transfers",
        "The Cross-Border Transfer Mechanism applies. The Cross-Border Transfer Mechanism is Annex II.",
      ]),
    );
    // A hyphenated word is one word, so the candidate is the whole compound
    // and never the tail of it.
    const terms = map.undefined_capitalized.map((e) => e.term);
    expect(terms).not.toContain("Border Transfer Mechanism");
    expect(terms).toContain("Cross-Border Transfer Mechanism");
  });
});

describe("truncated candidates of longer defined terms", () => {
  it("does not report a word-boundary prefix of a defined term as undefined", () => {
    // TITLE_CASE_PHRASE cannot cross an all-caps word, so the defined
    // "Contractor Background IP" yields the candidate "Contractor Background".
    const map = extractDefinitions(
      buildTree([
        "IP",
        'Contractor retains its pre-existing tools and methodologies ("Contractor Background IP").',
        "Company receives a license to use Contractor Background IP as incorporated. Contractor Background IP remains Contractor's property.",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain("Contractor Background");
  });

  it("registers 'refers to' / 'is defined as' / 'shall refer to' inline definitions", () => {
    const map = extractDefinitions(
      buildTree([
        "Definitions",
        '"Effective Date" refers to the date first written above. "Territory" is defined as the United States and Canada. "Deliverables" shall refer to all work product delivered under this Agreement.',
      ]),
    );
    const terms = map.entries.map((e) => e.term);
    expect(terms).toContain("Effective Date");
    expect(terms).toContain("Territory");
    expect(terms).toContain("Deliverables");
  });

  it("does not report a singular use of a defined plural term as undefined", () => {
    const map = extractDefinitions(
      buildTree([
        "Patents",
        'The "Licensed Patents" means the patents listed on Exhibit A.',
        "The obligation as to each Licensed Patent terminates on the expiration of such Licensed Patent.",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain("Licensed Patent");
  });
});

describe("a scope aside between the term and its defining verb", () => {
  it("registers a term defined through an 'as used herein' aside", () => {
    const map = extractDefinitions(
      buildTree([
        "Definitions",
        '"Confidential Information", as used herein, means all non-public data disclosed by a party.',
        "Body",
        "The Receiving Party shall protect the Confidential Information at all times.",
      ]),
    );
    expect(map.entries.map((e) => e.term)).toContain("Confidential Information");
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain("Confidential Information");
  });

  it("registers a term defined through a 'when used in this Agreement' aside", () => {
    const map = extractDefinitions(
      buildTree([
        "Definitions",
        '"Purchase Price", when used in this Agreement, means the amount stated in Section 3.',
        "Body",
        "Buyer shall pay the Purchase Price on the Closing Date.",
      ]),
    );
    expect(map.entries.map((e) => e.term)).toContain("Purchase Price");
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain("Purchase Price");
  });

  it("registers a 'collectively refer to' multi-instrument definition", () => {
    const map = extractDefinitions(
      buildTree([
        "Definitions",
        'The "Transaction Documents" collectively refer to this Agreement and the Exhibits.',
        "Body",
        "Each of the Transaction Documents shall be duly executed at Closing.",
      ]),
    );
    expect(map.entries.map((e) => e.term)).toContain("Transaction Documents");
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain("Transaction Documents");
  });

  it("does not read an 'as used herein' aside as a definition when no defining verb follows", () => {
    // The aside is present but the clause resolves with "are described", not
    // "means" — so it is an ordinary sentence, not a definition.
    const map = extractDefinitions(
      buildTree([
        "Body",
        '"Service Levels", as used herein, are described in the attached SLA table.',
      ]),
    );
    expect(map.entries.map((e) => e.term)).not.toContain("Service Levels");
  });

  it("registers a term defined with the 'denotes' verb", () => {
    const map = extractDefinitions(
      buildTree([
        "Definitions",
        'The "Restricted Territory" denotes the fifty United States and the District of Columbia.',
        "Body",
        "Seller shall not compete within the Restricted Territory.",
      ]),
    );
    expect(map.entries.map((e) => e.term)).toContain("Restricted Territory");
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain("Restricted Territory");
  });
});

describe("modal and verb variants of the inline defining forms", () => {
  it("registers a 'will mean' definition (will as an alternative modal to shall)", () => {
    const map = extractDefinitions(
      buildTree([
        "Definitions",
        '"Renewal Window" will mean the sixty-day period before expiry.',
        "Body",
        "Notice must be given during the Renewal Window. Each Renewal Window is fixed.",
      ]),
    );
    expect(map.entries.map((e) => e.term)).toContain("Renewal Window");
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain("Renewal Window");
  });

  it("registers 'is hereby defined to mean' / 'shall be defined as' / 'is defined to include'", () => {
    const map = extractDefinitions(
      buildTree([
        "Definitions",
        '"Governing Body" is hereby defined to mean the board of directors. "Applicable Standard" shall be defined as ISO 27001. "Restricted Data" is defined to include all customer records.',
      ]),
    );
    const terms = map.entries.map((e) => e.term);
    expect(terms).toContain("Governing Body");
    expect(terms).toContain("Applicable Standard");
    expect(terms).toContain("Restricted Data");
  });

  it("does not read a future-tense 'will' clause without a defining verb as a definition", () => {
    const map = extractDefinitions(
      buildTree([
        "Body",
        'The parties agree that "Best Efforts" will resolve the dispute amicably.',
      ]),
    );
    expect(map.entries.map((e) => e.term)).not.toContain("Best Efforts");
  });
});

describe("a quoted colon/dash glossary entry in a definitions section", () => {
  it("registers a 'Term: definition' glossary entry", () => {
    const map = extractDefinitions(
      buildTree([
        "Definitions",
        '"Delivery Point": the loading dock at the receiving facility.',
        "Body",
        "Risk of loss passes to Buyer at the Delivery Point.",
      ]),
    );
    expect(map.entries.map((e) => e.term)).toContain("Delivery Point");
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain("Delivery Point");
  });

  it("registers a 'Term — definition' em-dash glossary entry", () => {
    const map = extractDefinitions(
      buildTree(["Glossary", '"Cure Period" — the ten business days following notice of default.']),
    );
    expect(map.entries.map((e) => e.term)).toContain("Cure Period");
  });

  it("does not read a quoted colon phrase outside a definitions section as a definition", () => {
    // The glossary form is scoped to Pass 1 (definitions/glossary headings); a
    // quoted term followed by a colon in ordinary body text is not a definition.
    const map = extractDefinitions(
      buildTree([
        "Recitals",
        '"Force Majeure": a party is excused where an event of God intervenes.',
      ]),
    );
    expect(map.entries.map((e) => e.term)).not.toContain("Force Majeure");
  });

  it("does not read a mid-paragraph quoted colon phrase as a glossary entry", () => {
    const map = extractDefinitions(
      buildTree([
        "Definitions",
        'The parties note the following. "Widget": a red thing used later.',
      ]),
    );
    expect(map.entries.map((e) => e.term)).not.toContain("Widget");
  });
});

describe("the double-alias definition form", () => {
  it('registers both names of \'"X" or "Y" means …\'', () => {
    const map = extractDefinitions(
      buildTree([
        "Definitions",
        '"Protected Health Information" or "PHI" means individually identifiable health information transmitted or maintained in any form.',
        "Business Associate shall safeguard Protected Health Information. Access to Protected Health Information is limited. PHI shall not be sold. PHI records are retained.",
      ]),
    );
    const terms = map.entries.map((e) => e.term);
    expect(terms).toContain("Protected Health Information");
    expect(terms).toContain("PHI");
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain(
      "Protected Health Information",
    );
  });

  it("does not report the unused alias when only the SHORT alias is used", () => {
    // A BAA defines '"Protected Health Information" or "PHI" means …' and then
    // uses only "PHI" — a use of either alias satisfies both.
    const map = extractDefinitions(
      buildTree([
        "Definitions",
        '"Protected Health Information" or "PHI" means individually identifiable health information.',
        "Business Associate shall safeguard PHI and shall not disclose PHI except as permitted.",
      ]),
    );
    expect(map.unused_terms).not.toContain("Protected Health Information");
    expect(map.unused_terms).not.toContain("PHI");
  });
});

describe("named federal regulatory rules are not undefined terms", () => {
  it("does not flag HIPAA 'Privacy Rule'/'Security Rule' as used-but-undefined", () => {
    const map = extractDefinitions(
      buildTree([
        "1. Definitions",
        '"HIPAA Rules" means the Privacy, Security, Breach Notification, and Enforcement Rules at 45 C.F.R. Parts 160 and 164.',
        "Business Associate shall not use PHI in a manner that would violate the Privacy Rule.",
        "Business Associate shall comply with the Security Rule with respect to electronic PHI.",
      ]),
    );
    const undef = map.undefined_capitalized.map((e) => e.term);
    expect(undef).not.toContain("Privacy Rule");
    expect(undef).not.toContain("Security Rule");
  });
});

describe("street addresses are not defined terms", () => {
  it("does not report a street name as an undefined Title-Case term", () => {
    const map = extractDefinitions(
      buildTree([
        "Premises",
        "The studio at 88 Dockside Avenue is the location. The lease for 88 Dockside Avenue shall be assigned at the Closing.",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain("Dockside Avenue");
  });
});

describe("meaning-by-reference definitions", () => {
  it("registers a bare list of terms defined by reference to a statute", () => {
    const map = extractDefinitions(
      buildTree([
        "Definitions",
        "Personal Data, Data Subject, Processing, Controller and Processor shall have the meaning given in Article 4 GDPR. Personal Data Breach shall have the meaning given in Article 4(12) GDPR.",
        "Processor shall notify Controller of any Personal Data Breach without undue delay.",
      ]),
    );
    const terms = map.entries.map((e) => e.term);
    for (const t of [
      "Personal Data",
      "Data Subject",
      "Processing",
      "Controller",
      "Processor",
      "Personal Data Breach",
    ]) {
      expect(terms).toContain(t);
    }
    const pd = map.entries.find((e) => e.term === "Personal Data");
    expect(pd?.form).toBe("meaning-reference");
    expect(pd?.reference).toBe("Article 4");
  });

  it("registers a quoted term defined by reference to another instrument", () => {
    const entry = extractDefinitions(
      buildTree([
        "Definitions",
        '"Business Associate" shall have the meaning given to such term in 45 CFR § 160.103.',
      ]),
    ).entries.find((e) => e.term === "Business Associate");
    expect(entry).toBeDefined();
    expect(entry?.form).toBe("meaning-reference");
    expect(entry?.definition).toContain("160.103");
  });

  it("handles camelCase acronyms in a bare term list", () => {
    const terms = extractDefinitions(
      buildTree([
        "Definitions",
        "Protected Health Information, PHI, and ePHI shall have the meaning given in 45 CFR § 160.103.",
      ]),
    ).entries.map((e) => e.term);
    expect(terms).toContain("Protected Health Information");
    expect(terms).toContain("PHI");
    expect(terms).toContain("ePHI");
  });

  it("does not read an undefined-terms fallback clause as defining anything", () => {
    const map = extractDefinitions(
      buildTree([
        "Definitions",
        "Capitalized terms used but not defined herein shall have the meaning given in the MSA.",
      ]),
    );
    expect(map.entries).toHaveLength(0);
  });

  it("registers a term defined with 'has the same meaning as' (statutory import)", () => {
    const map = extractDefinitions(
      buildTree([
        "Definitions",
        '"Sensitive Data Category" has the same meaning as in the GDPR.',
        "Body",
        "The processor treats each Sensitive Data Category with heightened care.",
        "A Sensitive Data Category requires explicit consent.",
      ]),
    );
    expect(map.entries.map((e) => e.term)).toContain("Sensitive Data Category");
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain("Sensitive Data Category");
  });

  it("does not read 'has the same meaning' without a quoted subject as a definition", () => {
    const map = extractDefinitions(
      buildTree([
        "Body",
        "The word herein has the same meaning as it does in common usage everywhere.",
      ]),
    );
    expect(map.entries).toHaveLength(0);
  });
});

describe("construed-accordingly derivative terms", () => {
  it("registers the derivative forms next to their sibling definition", () => {
    const map = extractDefinitions(
      buildTree([
        "Definitions",
        '"Processing" means any operation performed on personal data, and "Process" and "Processed" shall be construed accordingly.',
        "Processor shall Process the data only on documented instructions.",
      ]),
    );
    const terms = map.entries.map((e) => e.term);
    expect(terms).toContain("Processing");
    expect(terms).toContain("Process");
    expect(terms).toContain("Processed");
    const process = map.entries.find((e) => e.term === "Process");
    expect(process?.form).toBe("construed");
    // The sibling express definition is not overwritten by the construed scan.
    const processing = map.entries.find((e) => e.term === "Processing");
    expect(processing?.form).toBeUndefined();
    expect(processing?.definition).toContain("any operation");
  });
});

describe("compounds of defined terms are not undefined phrases", () => {
  it("does not flag a phrase that segments fully into defined terms", () => {
    const map = extractDefinitions(
      buildTree([
        "Definitions",
        'Personal Data and Processing shall have the meaning given in Article 4 GDPR, and "Process" shall be construed accordingly.',
        "Processor may Process Personal Data solely as instructed. The parties shall follow the Data Retention Policy.",
        "Any request to Process Personal Data shall be documented. Updates to the Data Retention Policy are reviewed annually.",
      ]),
    );
    const undefinedTerms = map.undefined_capitalized.map((u) => u.term);
    expect(undefinedTerms).not.toContain("Process Personal Data");
    // A phrase that does NOT segment into defined terms is still reported.
    expect(undefinedTerms).toContain("Data Retention Policy");
  });
});

describe("caption and run-in heading phrases are not defined-term candidates", () => {
  it("does not read the document's own caption as an undefined term", () => {
    const map = extractDefinitions(
      buildTree([
        "Body",
        "Confidential Settlement Agreement and Mutual Release",
        'This Confidential Settlement Agreement and Mutual Release (this "Agreement") is entered into by the parties.',
        "4. Mutual Release by Meridian. Upon receipt of the payment, Meridian releases all claims.",
        "5. Mutual Release by Harbor Point. Upon the Effective Date, Harbor Point releases all claims.",
      ]),
    );
    expect(map.undefined_capitalized.map((u) => u.term)).not.toContain("Mutual Release");
  });

  it("a numbered sentence is not a run-in heading and its phrases still count", () => {
    const map = extractDefinitions(
      buildTree([
        "Body",
        "4. Vendor shall deliver the Statement Deliverables to Client. The Statement Deliverables are due monthly.",
        "5. Client shall review the Statement Deliverables within ten days.",
      ]),
    );
    expect(map.undefined_capitalized.map((u) => u.term)).toContain("Statement Deliverables");
  });
});

describe("statute names, officer titles, and entity names are not defined terms", () => {
  it("does not flag a cited statute title or a corporate office", () => {
    const map = extractDefinitions(
      buildTree([
        "Body",
        "The Corporation shall indemnify officers to the fullest extent permitted by the General Corporation Law of the State of Delaware. Special meetings may be called by the Chief Executive Officer.",
        "Any committee may exercise powers permitted under the General Corporation Law of the State of Delaware, subject to direction from the Chief Executive Officer.",
      ]),
    );
    const terms = map.undefined_capitalized.map((u) => u.term);
    expect(terms).not.toContain("General Corporation Law");
    expect(terms).not.toContain("Chief Executive Officer");
  });

  it("does not flag a statute / body-of-law name ending in 'Law'", () => {
    const map = extractDefinitions(
      buildTree([
        "Body",
        "The Corporation is organized under the General Corporation Law of the State of Delaware, and all rights are subject to the Delaware General Corporation Law.",
        "This Agreement is subject to Applicable State Law and the Delaware General Corporation Law.",
      ]),
    );
    const terms = map.undefined_capitalized.map((u) => u.term);
    expect(terms).not.toContain("Delaware General Corporation Law");
    expect(terms).not.toContain("Applicable State Law");
  });

  it("does not flag signature-block designations (Authorized Signatory, Managing Partner)", () => {
    const map = extractDefinitions(
      buildTree([
        "Signatures",
        "MEMBER: Ridgeline Holdings, LLC. By: Morgan Ellis. Title: Authorized Signatory.",
        "MEMBER: Cormorant Capital, LLC. By: Jesse Park. Title: Authorized Signatory.",
        "SELLER By: Dana Cole, Title: Managing Partner. BUYER By: Sam Poe, Title: Managing Partner.",
      ]),
    );
    const terms = map.undefined_capitalized.map((u) => u.term);
    expect(terms).not.toContain("Authorized Signatory");
    expect(terms).not.toContain("Managing Partner");
  });

  it("does not flag a company name followed by its corporate suffix", () => {
    const map = extractDefinitions(
      buildTree([
        "Body",
        "This agreement is with Beacon Instruments, Inc., a Delaware corporation. Beacon Instruments, Inc. maintains its office in Wilmington.",
      ]),
    );
    expect(map.undefined_capitalized.map((u) => u.term)).not.toContain("Beacon Instruments");
  });

  it("treats a caption ending in an entity abbreviation as a caption", () => {
    const map = extractDefinitions(
      buildTree([
        "Body",
        "Amended and Restated Bylaws of Beacon Instruments, Inc.",
        'These Amended and Restated Bylaws (these "Bylaws") govern the Corporation.',
      ]),
    );
    expect(map.undefined_capitalized.map((u) => u.term)).not.toContain("Restated Bylaws");
  });
});

describe("cover-block field labels and embedded definitions", () => {
  it("registers a field label and counts the body's uses", () => {
    const map = extractDefinitions(
      buildTree([
        "Note",
        "Principal Amount: $500,000 Issue Date: May 15, 2026",
        "Interest accrues from the Issue Date until paid.",
      ]),
    );
    const entry = map.entries.find((e) => e.term === "Issue Date");
    expect(entry?.form).toBe("field-label");
    expect(entry?.definition).toBe("May 15, 2026");
    expect(map.undefined_capitalized.map((u) => u.term)).not.toContain("Issue Date");
    expect(map.unused_terms).not.toContain("Issue Date");
  });

  it("a signature-block 'Date:' line does not register (single word)", () => {
    const map = extractDefinitions(buildTree(["Signatures", "Date: March 10, 2026"]));
    expect(map.entries.map((e) => e.term)).not.toContain("Date");
  });

  it("counts a use that precedes its embedded same-paragraph definition", () => {
    const map = extractDefinitions(
      buildTree([
        "Change of Control",
        'If the Company consummates a Change of Control, the Investor may elect a cash payment. "Change of Control" means a merger, consolidation, or sale of all or substantially all of the Company\'s assets.',
      ]),
    );
    expect(map.unused_terms).not.toContain("Change of Control");
  });

  it("a self-reference inside the definition body is still not a use", () => {
    const map = extractDefinitions(
      buildTree([
        "Definitions",
        '"Confidential Information" means non-public information, but Confidential Information does not include public data.',
      ]),
    );
    expect(map.unused_terms).toContain("Confidential Information");
  });
});

describe("field-label terms are facts, not template leftovers", () => {
  it("an unreferenced cover field is not an unused term", () => {
    const map = extractDefinitions(
      buildTree(["BAA", "Effective Date: January 1, 2026.", "The parties agree as follows."]),
    );
    expect(map.entries.some((e) => e.term === "Effective Date")).toBe(true);
    expect(map.unused_terms).not.toContain("Effective Date");
  });
});

describe("a sentence-initial article on a defined term is that term's use", () => {
  it("does not flag 'The Escrow Agent' when 'Escrow Agent' is defined", () => {
    const map = extractDefinitions(
      buildTree([
        "Escrow",
        'First Meridian Trust Company, acting as escrow agent (the "Escrow Agent"), holds the deposit.',
        "The Escrow Agent shall release the funds upon joint instruction.",
        "The Escrow Agent may resign upon thirty days' notice.",
      ]),
    );
    expect(map.undefined_capitalized.map((u) => u.term)).not.toContain("The Escrow Agent");
  });
});

describe("handbook-style captions and parenthetical subjects", () => {
  it("does not flag the document's own title or a parenthetical's subject", () => {
    const map = extractDefinitions(
      buildTree([
        "Body",
        "Employee Handbook — Halcyon Grid Systems, Inc.",
        'This Employee Handbook (this "Handbook") describes the policies of the Company. Employees should direct questions about the Employee Handbook to Human Resources.',
      ]),
    );
    const terms = map.undefined_capitalized.map((u) => u.term);
    expect(terms).not.toContain("Employee Handbook");
    expect(terms).not.toContain("Human Resources");
  });

  it("still flags an undefined phrase merely used near an unrelated parenthetical", () => {
    const map = extractDefinitions(
      buildTree([
        "Body",
        "Each site shall follow the Quality Assurance Plan at all times. Every site manager shall maintain the Quality Assurance Plan on file.",
      ]),
    );
    expect(map.undefined_capitalized.map((u) => u.term)).toContain("Quality Assurance Plan");
  });
});

describe("counties are places, not defined terms", () => {
  it("does not flag 'Pierce County' from a legal description", () => {
    const map = extractDefinitions(
      buildTree([
        "Legal Description",
        "The real property is situated in Pierce County, Washington, according to the records of Pierce County.",
      ]),
    );
    expect(map.undefined_capitalized.map((u) => u.term)).not.toContain("Pierce County");
  });
});

describe("ordinal instrument names are document titles, not defined terms", () => {
  it("does not flag 'First Amendment' from a lease reference", () => {
    const map = extractDefinitions(
      buildTree([
        "Re",
        "Lease dated March 1, 2024, as amended by First Amendment dated November 15, 2025.",
        "The Lease has not been modified except by the First Amendment identified above.",
      ]),
    );
    expect(map.undefined_capitalized.map((u) => u.term)).not.toContain("First Amendment");
  });
});

describe("change-order style terms", () => {
  it("registers '(this \"Change Order\")' and skips the numbered-instrument fragment", () => {
    const map = extractDefinitions(
      buildTree([
        "Change Order",
        'This Change Order No. 3 (this "Change Order") modifies the Contract, as previously modified by Change Order No. 1 and Change Order No. 2.',
        "Except as modified by this Change Order, the Contract remains in effect.",
      ]),
    );
    expect(map.entries.map((e) => e.term)).toContain("Change Order");
    const undef = map.undefined_capitalized.map((u) => u.term);
    expect(undef).not.toContain("Change Order No");
    expect(undef).not.toContain("Change Order");
  });

  it("merges 'The Contract Sum' occurrences into 'Contract Sum'", () => {
    const map = extractDefinitions(
      buildTree([
        "Adjustment",
        "The Contract Sum will be increased by this Change Order. The parties agree the increase modifies the Contract Sum accordingly.",
      ]),
    );
    const undef = map.undefined_capitalized.map((u) => u.term);
    expect(undef).toContain("Contract Sum");
    expect(undef).not.toContain("The Contract Sum");
  });
});

describe("natural persons are not defined terms", () => {
  it("does not flag signatories, notary appearances, or persons with residences", () => {
    const map = extractDefinitions(
      buildTree([
        "POA",
        'I, Nora Castellanos, residing at 41 Quarry Hill Road, Montpelier, VT 05602 (the "Principal"), appoint my brother, Diego Castellanos, residing at 9 Elm Row, Barre, VT 05641 (the "Agent").',
        "On October 28, 2026, before me personally appeared Nora Castellanos, known to me to be the person whose name is subscribed to this instrument.",
        "/s/ Nora Castellanos Nora Castellanos, Principal",
      ]),
    );
    const undef = map.undefined_capitalized.map((u) => u.term);
    expect(undef).not.toContain("Nora Castellanos");
    expect(undef).not.toContain("Diego Castellanos");
  });
});

describe("plural compounds of defined terms", () => {
  it("does not flag 'Your Contributions' when 'Your' and 'Contribution' are defined", () => {
    const map = extractDefinitions(
      buildTree([
        "Definitions",
        '"Your" means the individual entering into this Agreement. "Contribution" means any original work of authorship You submit.',
        "You hereby grant a license covering Your Contributions and derivative works.",
        "The Foundation may distribute Your Contributions under the Project license.",
      ]),
    );
    expect(map.undefined_capitalized.map((u) => u.term)).not.toContain("Your Contributions");
  });

  it("does not flag a stopword-led plural of a defined singular", () => {
    // "All Licensed Products" / "The Licensed Products" is the defined
    // "Licensed Product" in the plural with a leading article — its own use,
    // not a used-but-undefined term (STRUCT-006).
    const map = extractDefinitions(
      buildTree([
        "Agreement",
        '"Licensed Product" means the software listed in Exhibit A.',
        "Customer may resell the Licensed Products to end users.",
        "All Licensed Products remain the property of Licensor.",
        "The Licensed Products carry a warranty.",
      ]),
    );
    expect(map.undefined_capitalized.map((u) => u.term)).not.toContain("Licensed Products");
  });

  it("does not flag the singular of a defined 'y'→'ies' plural term", () => {
    // "Licensed Facility" is the singular of the defined "Licensed
    // Facilities"; the bare "+s"/"+es" check produced "licensed facilitys"/
    // "licensed facilityes" and missed it, leaking a STRUCT-006 false positive.
    const map = extractDefinitions(
      buildTree([
        "Agreement",
        '"Licensed Facilities" means the plants operated by Seller.',
        "Each Licensed Facility shall be maintained.",
        "A Licensed Facility may be inspected without notice.",
      ]),
    );
    expect(map.undefined_capitalized.map((u) => u.term)).not.toContain("Licensed Facility");
  });
});

describe("statute suffixes and office titles", () => {
  it("does not flag 'Bank Secrecy Act' or 'Compliance Officer'", () => {
    const map = extractDefinitions(
      buildTree([
        "AML",
        "The program complies with the Bank Secrecy Act and applicable regulations. Potential matches are escalated to the BSA Compliance Officer for review.",
        "Independent testing verifies compliance with the Bank Secrecy Act, and the Compliance Officer reports quarterly.",
      ]),
    );
    const undef = map.undefined_capitalized.map((u) => u.term);
    expect(undef).not.toContain("Bank Secrecy Act");
    expect(undef).not.toContain("Compliance Officer");
  });
});

describe("agency-name fragments and board organs", () => {
  it("does not flag 'Exchange Commission' or 'Audit Committee'", () => {
    const map = extractDefinitions(
      buildTree([
        "Ethics",
        "Reports are filed with the Securities and Exchange Commission. Violations are reported to the Audit Committee.",
        "The Securities and Exchange Commission's rules govern disclosure, and the Audit Committee oversees enforcement.",
      ]),
    );
    const undef = map.undefined_capitalized.map((u) => u.term);
    expect(undef).not.toContain("Exchange Commission");
    expect(undef).not.toContain("Audit Committee");
  });
});

describe("10-K style heading lines and self-references", () => {
  it("does not flag subheading lines or 'this Annual Report'", () => {
    const map = extractDefinitions(
      buildTree([
        "Item 1A",
        "Risks Related to Our Lending Business",
        "Our loan portfolio is concentrated in commercial real estate, as described in this Annual Report on Form 10-K.",
        "Risks Related to Our Lending Business",
        "Additional detail appears elsewhere in this Annual Report on Form 10-K.",
      ]),
    );
    const undef = map.undefined_capitalized.map((u) => u.term);
    expect(undef).not.toContain("Risks Related");
    expect(undef).not.toContain("Annual Report");
  });
});

describe("entity short forms", () => {
  it("does not flag 'Granite Peak' when 'Granite Peak Lenders LLC' appears", () => {
    const map = extractDefinitions(
      buildTree([
        "Brief",
        "Meridian sued Granite Peak Lenders LLC over the renewal condition.",
        "Granite Peak conditioned renewal on a deposit transfer. Granite Peak imposed the condition for an affiliate's benefit.",
      ]),
    );
    expect(map.undefined_capitalized.map((u) => u.term)).not.toContain("Granite Peak");
  });
});

describe("a judicial district is not an undefined defined-term", () => {
  it("does not flag the district inside a court's name", () => {
    const map = extractDefinitions(
      buildTree([
        "Recitals",
        "Ridgeline filed an action in the United States District Court for the Northern District of Illinois. The action is pending in the Northern District of Illinois.",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain("Northern District");
  });

  it("still flags an ordinary Title-Case phrase followed by 'of'", () => {
    const map = extractDefinitions(
      buildTree([
        "Services",
        "The work is described in the Statement of Base Services. The Statement of Base Services governs.",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term)).toContain("Base Services");
  });
});

describe("a time zone is not an undefined defined-term", () => {
  it("does not flag the time zone in a deadline", () => {
    // Every deadline in a purchase agreement, a discovery response, and a
    // notice clause is stated in one, so the Title-Case run picks it up as a
    // phrase the document uses twice and never defines.
    const map = extractDefinitions(
      buildTree([
        "Due Diligence",
        "Buyer has until 5:00 p.m. Eastern Time on the forty-fifth day to inspect the Property. Notices are effective before 5:00 p.m. Eastern Time on a business day.",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain("Eastern Time");
  });

  it("still flags an ordinary two-word Title-Case phrase", () => {
    const map = extractDefinitions(
      buildTree([
        "Due Diligence",
        "Buyer shall review the Diligence Package before the deadline. The Diligence Package is delivered by Seller.",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term)).toContain("Diligence Package");
  });
});

describe("a conformed signature doubled by the paste join", () => {
  // The paste path joins a block's lines with spaces, so the "/s/" line and
  // the printed name beneath it arrive as one string. The person collector
  // captured "Priya Raghunathan Priya Raghunathan", matched no use of the
  // name, and every mention of a member who SIGNS the agreement was reported
  // as a term the document forgot to define.
  it("does not flag a signer whose name is doubled by the join", () => {
    const map = extractDefinitions(
      buildTree([
        "Operating Agreement",
        "The initial Manager is Priya Raghunathan. Priya Raghunathan may bind the Company.",
        "/s/ Priya Raghunathan Priya Raghunathan, Member and Manager",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain("Priya Raghunathan");
  });

  // The bounded capture stops at four words, so a THREE-word name doubled
  // runs to six and the halving compared "adaeze chinelo" against "oduya
  // adaeze" and found no repetition. A revocable trust reported its own
  // settlor — named in the preamble, under the conformed signature, and in
  // the notary acknowledgment — as a term the drafter forgot to define.
  it("does not flag a doubled THREE-word name", () => {
    const map = extractDefinitions(
      buildTree([
        "Declaration of Trust",
        "This Declaration of Trust is made by Adaeze Chinelo Oduya, as Settlor.",
        "/s/ Adaeze Chinelo Oduya Adaeze Chinelo Oduya, Settlor and Trustee",
        "This instrument was acknowledged before me by Adaeze Chinelo Oduya.",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain("Adaeze Chinelo Oduya");
  });

  it("still flags a Title-Case term that merely repeats", () => {
    const map = extractDefinitions(
      buildTree([
        "Operating Agreement",
        "Each Member holds a Percentage Interest. The Percentage Interest is fixed.",
        "/s/ Priya Raghunathan Priya Raghunathan, Member and Manager",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term)).toContain("Percentage Interest");
  });
});

describe("a sentence-initial 'Every' fused onto a defined term", () => {
  // "Every" sat beside "Each" in every drafter's vocabulary and not in the
  // leading-stopword set, so "Every Owner is a member of the Association" was
  // reported as a use of an undefined term "Every Owner" — on a declaration
  // that defines "Owner" in its first article.
  const undefinedTerms = (...paras: string[]) =>
    extractDefinitions(buildTree(["Declaration", ...paras])).undefined_capitalized.map(
      (e) => e.term,
    );

  it("does not report 'Every Owner' as an undefined term", () => {
    expect(
      undefinedTerms(
        '"Owner" means the record owner of the fee simple title to any Lot.',
        "Every Owner is a member of the Association.",
        "Every Owner has a right and easement of enjoyment in and to the Common Area.",
      ),
    ).not.toContain("Every Owner");
  });

  it("still reports a genuinely undefined multi-word term", () => {
    expect(
      undefinedTerms(
        "The Special Reserve Fund shall be maintained by the Board.",
        "Withdrawals from the Special Reserve Fund require a two-thirds vote.",
      ),
    ).toContain("Special Reserve Fund");
  });
});

describe("a numbered heading that stands alone", () => {
  // A section heading ends with a period as often as not — "4. Due Diligence
  // Materials." — and the standalone-heading test required an UNPUNCTUATED
  // line, so a commercial purchase agreement was told "Due Diligence
  // Materials" was a term it forgot to define, on a document whose section 4
  // is headed with it.
  it("does not read a numbered heading's words as term uses", () => {
    const map = extractDefinitions(
      buildTree([
        "Purchase and Sale Agreement",
        "Buyer has forty-five days to review the Due Diligence Materials.",
        "4. Due Diligence Materials.",
        "Seller shall deliver the leases, the rent roll, and the surveys.",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain("Due Diligence Materials");
  });

  it("still reads a numbered prose SENTENCE as prose", () => {
    const map = extractDefinitions(
      buildTree([
        "Purchase and Sale Agreement",
        "Buyer shall review the Due Diligence Materials.",
        "4. Seller shall deliver the Due Diligence Materials to Buyer on Monday.",
      ]),
    );
    // Its lowercase function words are what keep it out of the heading test.
    expect(map.undefined_capitalized.map((e) => e.term)).toContain("Due Diligence Materials");
  });
});

describe("an entity name whose suffix is a Title-Case word", () => {
  // Half the corporate suffixes are Title-Case words rather than initialisms,
  // so the candidate phrase INCLUDES the suffix — "Meridian Optics Corp." is
  // captured as "Meridian Optics Corp", which no prefix of "Meridian Optics"
  // matches. The addressee of a cease-and-desist letter was reported as a
  // term the letter forgot to define.
  it("does not flag a company named with a Corp. suffix", () => {
    const map = extractDefinitions(
      buildTree([
        "Demand Letter",
        "Meridian Optics Corp. is marketing a reader under a confusingly similar mark.",
        "We demand that Meridian Optics Corp. cease all use of the mark.",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain("Meridian Optics Corp");
  });
});

describe("the title of an attachment on its label line", () => {
  // "Schedule A — Trust Property" names the attachment; it is not a use of a
  // defined term. The standalone-heading test only catches the label while it
  // has a paragraph to itself, so a trust pasted out of a PDF — where the
  // schedule label runs on into the notary block — was told "Trust Property"
  // was a term it forgot to define.
  it("does not read an attachment title as a term use", () => {
    const map = extractDefinitions(
      buildTree([
        "Declaration of Trust",
        "The Settlors transfer the Trust Property to the Trustees.",
        "This instrument was acknowledged before me. Schedule A — Trust Property",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain("Trust Property");
  });
});

describe("a term defined WITH its article", () => {
  // '"The Berth Agreement" means …' is used as "the Berth Agreement"
  // everywhere after, and the term went unmatched. A set of interrogatories
  // was told BOTH that "The Berth Agreement" is never used and that "Berth
  // Agreement" is a term it forgot to define — two findings that contradict
  // each other, about one term.
  const map = () =>
    extractDefinitions(
      buildTree([
        "Interrogatories",
        '"The Berth Agreement" means the Berth and Terminal Services Agreement dated March 2, 2024.',
        "Identify each person who negotiated the Berth Agreement on Your behalf.",
        "State when You first performed under the Berth Agreement.",
      ]),
    );

  it("counts the article-less uses", () => {
    expect(map().unused_terms).not.toContain("The Berth Agreement");
  });

  it("does not also report the article-less form as undefined", () => {
    expect(map().undefined_capitalized.map((e) => e.term)).not.toContain("Berth Agreement");
  });
});

describe("a cover block's field values and office abbreviations", () => {
  const undef = (...paras: string[]) =>
    extractDefinitions(
      buildTree(["Vendor Security Questionnaire", ...paras]),
    ).undefined_capitalized.map((e) => e.term);

  // The VALUE of a cover-block field is a fact the document states, not a term
  // it defines.
  it("does not report a field value as an undefined term", () => {
    expect(
      undef(
        "Requesting organisation: Thornbury Federal Credit Union",
        "The vendor shall notify Thornbury Federal Credit Union of any material change.",
      ),
    ).not.toContain("Thornbury Federal Credit Union");
  });

  // TITLE_CASE_PHRASE cannot include the all-caps abbreviation, so the capture
  // begins one word into the office and reads as an undefined term.
  it("does not report the tail of an abbreviated office", () => {
    expect(
      undef(
        "The VP Information Security reports to the Chief Technology Officer.",
        "Completed by Priyanka Deshmukh, VP Information Security.",
      ),
    ).not.toContain("Information Security");
  });

  it("still reports a genuine undefined term in the same paragraph shape", () => {
    expect(
      undef(
        "Scope of review: the Reference Architecture as delivered.",
        "The vendor shall maintain the Reference Architecture for the term.",
      ),
    ).toContain("Reference Architecture");
  });
});

describe("a statute named after its noun", () => {
  // "Code of Civil Procedure section 2033.010" is how every California filing
  // cites the CCP, and the statute-name guards read only the noun that
  // FOLLOWS the phrase — so "Civil Procedure" was reported as a term the
  // filing forgot to define.
  it("does not flag the name that follows 'Code of'", () => {
    const map = extractDefinitions(
      buildTree([
        "Requests for Admission",
        "Pursuant to Code of Civil Procedure section 2033.010, Plaintiff requests admissions.",
        "Responses are due under Code of Civil Procedure section 2033.250.",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain("Civil Procedure");
  });
});

describe("a fragment of the document's own all-caps caption", () => {
  // The Title-Case run cuts "NOTICE OF PRIVACY PRACTICES" at the lowercase
  // "of" wherever the body uses it, so "Privacy Practices" arrived as a
  // two-word candidate — and the caption test only suppressed a phrase on the
  // caption LINE. A HIPAA acknowledgment was told that a fragment of its own
  // title was a term it forgot to define.
  it("does not flag a phrase inside the caption, wherever it appears", () => {
    const map = extractDefinitions(
      buildTree([
        "",
        "ACKNOWLEDGMENT OF RECEIPT OF NOTICE OF PRIVACY PRACTICES",
        "I acknowledge that I have received a copy of the Notice of Privacy Practices.",
        "I may request a paper copy of the Notice of Privacy Practices at any time.",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain("Privacy Practices");
  });
});

describe("a professional corporation's suffix", () => {
  // The dotted spellings alone missed every medical, legal, and accounting
  // practice that drops the periods.
  it("does not flag a company named with a bare PC suffix", () => {
    const map = extractDefinitions(
      buildTree([
        "Acknowledgment",
        "Ridgeway Valley Pediatric Associates, PC maintains the privacy of your health information.",
        "You may contact Ridgeway Valley Pediatric Associates, PC at the address above.",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain(
      "Ridgeway Valley Pediatric Associates",
    );
  });
});

describe("the article inside the quotes", () => {
  // `("the Firm")` and `("the Client")` are the dominant convention in UK
  // drafting and common in US practice, and the parenthetical pattern required
  // the quote to open on a capital — so a contingency fee agreement that
  // defines both its parties in its first sentence was reported as having no
  // defined terms at all.
  const map = () =>
    extractDefinitions(
      buildTree([
        "Contingency Fee Agreement",
        'This agreement is made between Oyelaran Law Group, a professional corporation ("the Firm"), and Marisol Oyelaran-Diaz ("the Client").',
        "The Firm will represent the Client in a claim for personal injuries.",
      ]),
    );

  it("registers both terms without their article", () => {
    expect(
      map()
        .entries.map((e) => e.term)
        .sort(),
    ).toEqual(["Client", "Firm"]);
  });

  it("does not read a quoted phrase used mid-parenthetical as a definition", () => {
    const m = extractDefinitions(
      buildTree([
        "Agreement",
        'Vendor shall perform the services (the "Services" described in Exhibit A) with due care.',
      ]),
    );
    expect(m.entries.map((e) => e.term)).not.toContain("Services");
  });
});

describe("a person introduced by an honorific", () => {
  // "Dr. Ingrid Vasconcelos-Amaru" is a person. A research consent form names
  // its principal investigator that way twice — in the header block and in the
  // contact section — and the investigator was reported as a term the form
  // forgot to define.
  it("does not flag the name after Dr.", () => {
    const map = extractDefinitions(
      buildTree([
        "Consent to Participate in a Research Study",
        "Principal investigator: Dr. Ingrid Vasconcelos-Amaru, MD.",
        "For a question about the study, contact Dr. Ingrid Vasconcelos-Amaru at the number above.",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain("Ingrid Vasconcelos-Amaru");
  });
});

describe("a phrase that names one of the document's own headings", () => {
  // A set of discovery responses is headed "GENERAL OBJECTIONS" and its
  // answers say "subject to the General Objections above". That is a
  // cross-reference to a section of this document, not a term the drafter
  // forgot to define.
  it("does not flag a phrase that matches a section heading", () => {
    const map = extractDefinitions(
      buildTree([
        "Responses and Objections",
        "GENERAL OBJECTIONS",
        "Halloran objects to each interrogatory to the extent it seeks privileged information.",
        "Subject to the General Objections, Halloran responds as follows.",
        "Halloran incorporates the General Objections into each response below.",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term)).not.toContain("General Objections");
  });
});
