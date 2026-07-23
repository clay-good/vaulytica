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

  it("still flags an ordinary undefined Title-Case business term", () => {
    const map = extractDefinitions(
      buildTree([
        "Body",
        "The Special Reserve Fund shall be maintained. The Special Reserve Fund covers losses.",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term)).toContain("The Special Reserve Fund");
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

  it("does not flag 'Border Transfer' from 'Cross-Border Transfer'", () => {
    const map = extractDefinitions(
      buildTree([
        "Transfers",
        "The Cross-Border Transfer Mechanism applies. The Cross-Border Transfer Mechanism is Annex II.",
      ]),
    );
    expect(map.undefined_capitalized.map((e) => e.term).join(" ")).not.toContain("Border Transfer");
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
