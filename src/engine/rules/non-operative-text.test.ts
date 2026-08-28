/**
 * Front matter is not a clause.
 *
 * A table of contents lists the clauses an agreement is supposed to contain;
 * recitals say what the parties want it to do. Neither is operative, and both
 * were being read as document text by the presence rules.
 *
 * Appending nothing but a ten-line TOC to an agreement that contains neither
 * clause silenced RISK-001, RISK-005, IPDATA-001, TERM-002, and TERM-005 —
 * five clauses reported present because the front matter listed them — and
 * the same hole in `fullText` silenced the v4/v5 packs (IPL-004, IPL-005).
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../_test-fixtures.js";
import { isRecital, isTableOfContents } from "./_helpers.js";
import { rule as RISK_001 } from "./risk-allocation/RISK-001.js";
import { rule as RISK_005 } from "./risk-allocation/RISK-005.js";
import { rule as IPDATA_001 } from "./ip-and-data/IPDATA-001.js";
import { rule as TERM_002 } from "./termination/TERM-002.js";
import { rule as TERM_005 } from "./termination/TERM-005.js";

const BODY = [
  "Services Agreement",
  'This Services Agreement is made as of March 14, 2026 between Halloran Instruments, LLC ("Provider") and Vanterra Diagnostics, Inc. ("Customer").',
  "Provider shall perform the Services described in each Statement of Work.",
  "Customer shall pay the fees set forth in each Statement of Work within thirty (30) days of the invoice date.",
] as [string, ...string[]];

const TOC =
  "TABLE OF CONTENTS ARTICLE 1 DEFINITIONS ........................ 1 " +
  "ARTICLE 2 INTELLECTUAL PROPERTY OWNERSHIP ...... 9 " +
  "ARTICLE 3 INDEMNIFICATION ...................... 15 " +
  "ARTICLE 4 LIMITATION OF LIABILITY .............. 21 " +
  "ARTICLE 5 TERMINATION FOR CAUSE ................ 27 " +
  "ARTICLE 6 EFFECT OF TERMINATION ................ 29";

const RULES = [
  ["RISK-001", RISK_001],
  ["RISK-005", RISK_005],
  ["IPDATA-001", IPDATA_001],
  ["TERM-002", TERM_002],
  ["TERM-005", TERM_005],
] as const;

describe("a table of contents does not satisfy a presence rule", () => {
  for (const [id, rule] of RULES) {
    it(`${id} still fires when the TOC names its clause`, () => {
      const withToc = buildContext([...BODY, TOC]);
      expect(rule.check(withToc), `${id} was silenced by the TOC`).not.toBeNull();
    });
  }

  it("the same rules fire without the TOC, so the fixture is not vacuous", () => {
    const bare = buildContext(BODY);
    for (const [id, rule] of RULES) {
      expect(rule.check(bare), `${id} does not fire on the bare document`).not.toBeNull();
    }
  });

  it("a real clause in the same paragraph as a stray leader is still read", () => {
    // One entry in a long paragraph is not a table of contents.
    const ctx = buildContext([
      "Services Agreement",
      "See Schedule 1 ..... 4 for the fee table. Provider shall indemnify, defend, and hold harmless Customer from and against any and all third-party claims arising out of Provider's negligence, and shall pay all resulting damages and reasonable attorneys' fees.",
    ]);
    expect(RISK_001.check(ctx)).toBeNull();
  });
});

describe("a recital does not satisfy a presence rule", () => {
  // Recitals state what the parties WANT the agreement to do. They are not
  // operative and create no obligation, so a presence rule must not read one
  // as the clause it recites.
  const RECITALS = [
    "WHEREAS, Provider desires to grant Customer a limitation of liability and to indemnify Customer against third-party claims;",
    "WHEREAS, the parties intend that all intellectual property created under this Agreement be owned by Customer;",
    "WHEREAS, the parties wish to provide for termination for cause and for the effect of termination;",
  ];

  for (const [id, rule] of RULES) {
    it(`${id} still fires when a recital promises its clause`, () => {
      const ctx = buildContext([...BODY, ...RECITALS]);
      expect(rule.check(ctx), `${id} was silenced by the recitals`).not.toBeNull();
    });
  }

  it("an operative clause is not mistaken for a recital", () => {
    const ctx = buildContext([
      "Services Agreement",
      "Provider shall indemnify, defend, and hold harmless Customer from and against any and all third-party claims arising out of Provider's negligence.",
    ]);
    expect(RISK_001.check(ctx)).toBeNull();
  });

  it("only a leading WHEREAS marks a recital", () => {
    expect(isRecital("WHEREAS, the parties desire to enter into this Agreement;")).toBe(true);
    expect(isRecital("  whereas the Buyer has agreed to purchase the Property;")).toBe(true);
    expect(
      isRecital("The Agreement is void whereas the condition precedent was never satisfied."),
    ).toBe(false);
  });
});

describe("an index of defined terms is a list, not a clause", () => {
  const INDEX =
    "Indemnified Party Section 7.1 Cap on Liability Section 8.2 " +
    "Work Product Section 5.1 Termination for Cause Section 9.3";

  for (const [id, rule] of RULES) {
    it(`${id} still fires when the index names its clause`, () => {
      const ctx = buildContext([...BODY, INDEX]);
      expect(rule.check(ctx), `${id} was silenced by the index`).not.toBeNull();
    });
  }

  it("a clause that lists three cross-references is still read", () => {
    // It ends in a period, which an index does not.
    const ctx = buildContext([
      "Services Agreement",
      "Provider shall indemnify Customer as set forth in Section 7.1, Section 8.2, and Section 9.3.",
    ]);
    expect(
      isTableOfContents(
        "Provider shall indemnify Customer as set forth in Section 7.1, Section 8.2, and Section 9.3.",
      ),
    ).toBe(false);
    expect(RISK_001.check(ctx)).toBeNull();
  });

  it("two entries are not enough", () => {
    expect(isTableOfContents("Indemnified Party Section 7.1 Work Product Section 5.1")).toBe(false);
  });
});

describe("isTableOfContents", () => {
  it("needs two entries, or one in a short paragraph", () => {
    expect(isTableOfContents("ARTICLE 4 INDEMNIFICATION ......... 15")).toBe(true);
    expect(isTableOfContents("ARTICLE 4 INDEMNIFICATION ..... 15 ARTICLE 5 CAP ..... 21")).toBe(
      true,
    );
    expect(isTableOfContents("The parties agree as set forth below.")).toBe(false);
    expect(isTableOfContents("Provider shall indemnify Customer ... 30 days after notice.")).toBe(
      false,
    );
  });
});
