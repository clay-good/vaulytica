/**
 * Guards against misattribution and match-inside-a-word false findings in the
 * always-on TEMPORAL / TERMINATION launch rules — each case reproduced a
 * confident wrong finding (or a wrong silence) on realistic drafting before
 * the fix. Both directions are pinned so a future edit cannot regress either.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../_test-fixtures.js";
import { rule as TERM001 } from "./termination/TERM-001.js";
import { rule as TERM002 } from "./termination/TERM-002.js";
import { rule as TERM009 } from "./termination/TERM-009.js";
import { rule as TEMP005 } from "./temporal/TEMP-005.js";
import { rule as TEMP008 } from "./temporal/TEMP-008.js";
import { rule as TEMP009 } from "./temporal/TEMP-009.js";
import { rule as TEMP011 } from "./temporal/TEMP-011.js";

const clause = (...paras: string[]) => buildContext(["Clause", ...paras]);

describe("TERM-002 — for-cause path detection", () => {
  it("fires when the only breach language DISCLAIMS a termination right", () => {
    // "immaterial breach" must not satisfy the material-breach path.
    expect(
      TERM002.check(
        clause("An immaterial breach shall not give rise to any right of termination hereunder."),
      ),
    ).not.toBeNull();
  });

  it("stays silent for a real material breach, singular or plural", () => {
    expect(
      TERM002.check(clause("A party may terminate upon the other's material breach.")),
    ).toBeNull();
    expect(
      TERM002.check(
        clause("Repeated material breaches entitle the non-breaching party to terminate."),
      ),
    ).toBeNull();
  });
});

describe("TEMP-008 / TEMP-009 — breach-cure period", () => {
  it("does not read 'procure such breach-free …' as a cure period", () => {
    const procurement = clause(
      "Vendor shall procure such breach-free components within 45 days of order.",
    );
    expect(TEMP008.check(procurement)).toBeNull();
    expect(
      TEMP009.check(clause("Vendor shall procure such breach-free items within 5 days of order.")),
    ).toBeNull();
  });

  it("still fires on a genuine cure period", () => {
    expect(
      TEMP008.check(clause("A party may cure such breach within 45 days of notice.")),
    ).not.toBeNull();
  });
});

describe("TEMP-005 / TEMP-011 — auto-renewal non-renewal window", () => {
  const forCause =
    "This Agreement shall automatically renew for successive one-year terms. Either party may terminate for cause upon 15 days prior written notice.";

  it("does not misattribute a for-cause termination notice as the non-renewal window", () => {
    expect(TEMP005.check(clause(forCause))).toBeNull();
    expect(TEMP011.check(clause(forCause))).toBeNull();
  });

  it("still fires on a genuine short or unusual non-renewal window", () => {
    expect(
      TEMP011.check(
        clause(
          "This Agreement automatically renews unless either party gives 10 days notice of non-renewal.",
        ),
      ),
    ).not.toBeNull();
    expect(
      TEMP005.check(
        clause(
          "This Agreement shall automatically renew unless a party gives non-renewal notice at least 120 days before the end of the term.",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("TERM-001 — termination-for-convenience notice", () => {
  it("does not report an unrelated invoice-dispute deadline as the notice period", () => {
    expect(
      TERM001.check(
        clause(
          "Either party may terminate this Agreement for convenience. Invoices not disputed within 30 days of receipt are deemed accepted.",
        ),
      ),
    ).toBeNull();
  });

  it("still reports a genuine convenience notice period", () => {
    expect(
      TERM001.check(
        clause(
          "Either party may terminate this Agreement for convenience upon 30 days prior written notice.",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("TERM-009 — asymmetric termination-for-convenience", () => {
  it("does not fire when the counterparty merely gives notice (no cure gate)", () => {
    expect(
      TERM009.check(
        clause(
          "Vendor may terminate this Agreement for its convenience. Customer must terminate this Agreement and provide written notice at least 30 days prior.",
        ),
      ),
    ).toBeNull();
  });

  it("still fires on a genuine cure-gated asymmetry", () => {
    expect(
      TERM009.check(
        clause(
          "Vendor may terminate this Agreement at any time. Customer may only terminate this Agreement for the Vendor's material breach that remains uncured after a 30 day cure period.",
        ),
      ),
    ).not.toBeNull();
  });
});
