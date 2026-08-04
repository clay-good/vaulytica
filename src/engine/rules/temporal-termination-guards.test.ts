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

  it("reads the parenthesized cure-period count — the standard form (v1.1.0)", () => {
    const c = clause("The breaching party may cure such breach within thirty (30) days of notice.");
    const f8 = TEMP008.check(c);
    expect(f8, "TEMP-008 missed paren cure period").not.toBeNull();
    expect(f8!.title).toContain("30 days");
    // TEMP-009 evaluates the length: 30 is normal (no fire), 90 is unusual.
    expect(TEMP009.check(c)).toBeNull();
    const unusual = TEMP009.check(
      clause("The breaching party may cure such breach within ninety (90) days of notice."),
    );
    expect(unusual, "TEMP-009 missed unusual paren cure period").not.toBeNull();
    expect(unusual!.title).toContain("90 days");
  });

  // v1.2.0 — the day-count also leads the cure phrase ("shall have ninety (90)
  // days to cure", "a 5-day cure period"), which the phrase-first pattern
  // missed.
  it("TEMP-009 reads the count-first (reversed) and hyphenated-adjacent forms", () => {
    const reversed = TEMP009.check(
      clause("The breaching party shall have ninety (90) days to cure such breach."),
    );
    expect(reversed, "missed reversed 'N days to cure'").not.toBeNull();
    expect(reversed!.title).toContain("90 days");

    const adjacent = TEMP009.check(clause("A 5-day cure period applies to any monetary default."));
    expect(adjacent, "missed '5-day cure period'").not.toBeNull();
    expect(adjacent!.title).toContain("5 days");
  });

  it("TEMP-009 does not read an unrelated 'N days … procure' as a cure period", () => {
    expect(
      TEMP009.check(clause("Within 5 days, Customer may procure a replacement product.")),
    ).toBeNull();
  });

  // v1.2.0 (TEMP-008) / v1.3.0 (TEMP-009) — both rules share ./temporal/_cure.ts,
  // which reads the count-first order and the remedy/correct synonyms that the
  // presence rule previously missed entirely.
  it("TEMP-008 reads the count-first order and remedy/correct synonyms", () => {
    expect(
      TEMP008.check(clause("The defaulting party shall have thirty (30) days to cure such breach."))!
        .title,
    ).toContain("30 days");
    expect(
      TEMP008.check(clause("Tenant shall have thirty (30) days to remedy the breach."))!.title,
    ).toContain("30 days");
    expect(
      TEMP008.check(clause("Borrower shall have ten (10) days to correct any default."))!.title,
    ).toContain("10 days");
    expect(TEMP008.check(clause("A 5-day cure period applies to any monetary default."))!.title).toContain(
      "5 days",
    );
  });

  it("TEMP-008 locks onto the adjacent cure count, not a leading notice count", () => {
    // The cure period is 30 days; the 60 days is the termination-notice period.
    expect(
      TEMP008.check(
        clause("Either party may terminate on 60 days prior written notice and a 30-day cure period."),
      )!.title,
    ).toContain("30 days");
  });

  it("TEMP-008 does not read a 'sole remedy … 30 days' clause as a cure period", () => {
    expect(
      TEMP008.check(clause("The sole remedy for breach shall be termination upon 30 days notice.")),
    ).toBeNull();
  });
});

describe("TEMP-005 / TEMP-011 — auto-renewal non-renewal window", () => {
  const forCause =
    "This Agreement shall automatically renew for successive one-year terms. Either party may terminate for cause upon 15 days prior written notice.";

  it("does not misattribute a for-cause termination notice as the non-renewal window", () => {
    expect(TEMP005.check(clause(forCause))).toBeNull();
    expect(TEMP011.check(clause(forCause))).toBeNull();
  });

  it("does not misread a 'materially breaches … within N days' cure window (v1.2.0 guard)", () => {
    // The guard's "breach\b" missed the verb form, so a for-breach cure window
    // was reported as an unusual auto-renewal notice window.
    const breachCure =
      "This Agreement shall automatically renew for successive one-year terms. Either party may terminate if the other party materially breaches and fails to cure within 15 days' prior written notice.";
    expect(TEMP005.check(clause(breachCure))).toBeNull();
    expect(TEMP011.check(clause(breachCure))).toBeNull();
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

  it("reads the parenthesized non-renewal window count (v1.1.0)", () => {
    // Unusual (>90) window in the standard "one hundred twenty (120) days" form.
    const unusual = TEMP005.check(
      clause(
        "This Agreement automatically renews unless a party gives one hundred twenty (120) days notice of non-renewal.",
      ),
    );
    expect(unusual, "TEMP-005 missed paren window").not.toBeNull();
    expect(unusual!.title).toContain("120 days");
    // A normal (60) paren window does not fire.
    expect(
      TEMP005.check(
        clause(
          "This Agreement automatically renews unless a party gives sixty (60) days notice of non-renewal.",
        ),
      ),
    ).toBeNull();
  });

  it("reads the hyphenated 'auto-renews' / 'auto-renewal' spelling (TEMP-005 v1.1.0)", () => {
    // The dominant consumer spelling is hyphenated; the space-only separator
    // missed it while TEMP-004 / TEMP-011 already read the hyphen.
    const unusual = TEMP005.check(
      clause(
        "This Agreement auto-renews for successive terms; a party must give 120 days notice of non-renewal.",
      ),
    );
    expect(unusual).not.toBeNull();
    expect(unusual!.title).toContain("120 days");
    expect(
      TEMP005.check(
        clause("This is an auto-renewal contract requiring 15 days notice of non-renewal."),
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

  it("reads the parenthetical notice count and for-convenience synonyms (v1.1.0)", () => {
    // "thirty (30) days" is the standard drafting form; the ")" between the
    // digit and "days" used to defeat the match entirely.
    for (const [text, days] of [
      ["Either party may terminate for convenience upon thirty (30) days written notice.", 30],
      ["Either party may terminate without cause upon sixty (60) days' written notice.", 60],
      ["Customer may terminate for any reason upon 45 days prior written notice.", 45],
      ["Client may terminate with or without cause upon 30 days written notice.", 30],
    ] as const) {
      const f = TERM001.check(clause(text));
      expect(f, `MISSED: ${text}`).not.toBeNull();
      expect(f!.title).toContain(`${days} days`);
    }
  });

  it("does not read a for-cause termination as for-convenience", () => {
    for (const text of [
      "Either party may terminate for cause upon thirty (30) days notice to cure.",
      "The Bank may terminate at any time for cause upon 10 days written notice.",
    ]) {
      expect(TERM001.check(clause(text)), `FALSE convenience: ${text}`).toBeNull();
    }
  });

  it("reads the count-first order — notice period stated before the trigger (v1.2.0)", () => {
    for (const [text, days] of [
      ["Upon thirty (30) days' prior written notice, either party may terminate this Agreement for convenience.", 30],
      ["Upon sixty (60) days' written notice, Customer may terminate this Agreement without cause.", 60],
    ] as const) {
      const f = TERM001.check(clause(text));
      expect(f, `MISSED count-first: ${text}`).not.toBeNull();
      expect(f!.title).toContain(`${days} days`);
    }
  });

  it("count-first does not link a neighbouring-sentence notice to the convenience clause (v1.2.0)", () => {
    // The 30-day notice belongs to the warranty-claim sentence, not the
    // convenience termination in the next sentence; `[^.]` gaps keep them apart.
    expect(
      TERM001.check(
        clause(
          "Vendor shall give thirty (30) days' notice of any warranty claim. Either party may terminate this Agreement for convenience.",
        ),
      ),
    ).toBeNull();
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
