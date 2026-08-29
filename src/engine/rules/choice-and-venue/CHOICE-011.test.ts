import { describe, expect, it } from "vitest";
import { rule as CHOICE_011 } from "./CHOICE-011.js";
import { buildContext } from "../../_test-fixtures.js";

describe("CHOICE-011 — out-of-state choice-of-law on California worker", () => {
  it("fires when employee is California-based but governing law is Delaware", () => {
    const ctx = buildContext([
      "Parties",
      "Employee is a California resident who works from San Francisco, California.",
      "This Agreement shall be governed by and construed in accordance with the laws of the State of Delaware.",
    ]);
    const f = CHOICE_011.check(ctx);
    expect(f?.severity).toBe("warning");
    expect(f?.title).toMatch(/california/i);
  });

  it("is silent when governing law is California", () => {
    const ctx = buildContext([
      "Parties",
      "Employee is a California resident who works from Los Angeles, California.",
      "This Agreement shall be governed by the laws of the State of California.",
    ]);
    expect(CHOICE_011.check(ctx)).toBeNull();
  });

  it("is silent when no California-worker signal exists", () => {
    const ctx = buildContext([
      "Parties",
      "Employee is a New York resident based in Manhattan.",
      "This Agreement shall be governed by the laws of the State of Delaware.",
    ]);
    expect(CHOICE_011.check(ctx)).toBeNull();
  });

  it("is silent on a B2B contract whose party is merely a California corporation (v1.1.0)", () => {
    // § 925 protects a California employee, not a California entity. A mutual
    // NDA or MSA between corporations, one of which is a California
    // corporation, under Delaware law is lawful and must not fire.
    const ctx = buildContext([
      "Parties",
      'This Agreement is between Provider, a Delaware corporation, and Acme Retail Co., a California corporation ("Customer").',
      "This Agreement shall be governed by the laws of the State of Delaware.",
    ]);
    expect(CHOICE_011.check(ctx)).toBeNull();
  });

  it("is silent when a California LLC is a contracting entity (v1.1.0)", () => {
    const ctx = buildContext([
      "Parties",
      "Vendor is a California limited liability company.",
      "This Agreement shall be governed by the laws of the State of Texas.",
    ]);
    expect(CHOICE_011.check(ctx)).toBeNull();
  });

  const DEL = "This Agreement shall be governed by the laws of the State of Delaware.";

  it("reads the employment-specific worker signals (v1.2.0)", () => {
    for (const worker of [
      "Employee resides in California and reports to the New York office.",
      "Employee is employed in California under this Agreement.",
      "Employee's principal place of employment is in California.",
      "Executive's principal place of work is the State of California.",
    ]) {
      expect(
        CHOICE_011.check(buildContext(["Parties", worker, "Governing Law", DEL])),
        worker,
      ).not.toBeNull();
    }
  });

  it("does not fire on a B2B 'perform the Services in California' or 'principal place of business' (v1.2.0)", () => {
    expect(
      CHOICE_011.check(
        buildContext([
          "Services",
          "Provider shall perform the Services in California as directed by Customer.",
          "Governing Law",
          DEL,
        ]),
      ),
    ).toBeNull();
    expect(
      CHOICE_011.check(
        buildContext([
          "Parties",
          "Company's principal place of business is in California.",
          "Governing Law",
          DEL,
        ]),
      ),
    ).toBeNull();
  });
});

describe("CHOICE-011 — § 925 is a rule about EMPLOYMENT contracts", () => {
  // The v1.1.0 note removed the state-of-incorporation branch because it fired
  // on every B2B contract with a California party. The ADDRESS branches added
  // later reopened the same hole from the other side: a litigation funding
  // agreement between a Delaware LP "with offices at 300 Battery Street, San
  // Francisco, California" and a Massachusetts corporation was told its New
  // York governing law is void as to a California worker. There is no worker.
  it("does not fire on a B2B contract whose party has a California address", () => {
    expect(
      CHOICE_011.check(
        buildContext([
          "Parties",
          'This Agreement is between Sandpiper Capital Partners LP, with offices at 300 Battery Street, San Francisco, California 94111 (the "Funder"), and Ravensworth Instruments, Inc., a Massachusetts corporation.',
          "Governing Law",
          "This Agreement is governed by the laws of the State of New York.",
        ]),
      ),
    ).toBeNull();
  });

  it("still fires on an employment agreement with a California worker", () => {
    expect(
      CHOICE_011.check(
        buildContext([
          "Employment",
          "Employee resides in California and is employed at the Company's San Francisco, California office.",
          "Governing Law",
          "This Agreement is governed by the laws of the State of New York.",
        ]),
      ),
    ).not.toBeNull();
  });
});
