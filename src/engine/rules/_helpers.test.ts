import { describe, expect, it } from "vitest";
import {
  allMatches,
  enclosingSentence,
  firstParagraphMatch,
  firstUnnegatedParagraphMatch,
  amendsParentAgreement,
  isIncorporatedExhibit,
  isPresenceDisclaimed,
  expressDenial,
} from "./_helpers.js";
import type { RuleContext } from "../finding.js";
import { buildContext } from "../_test-fixtures.js";

/** Minimal RuleContext with a single-paragraph body. */
function ctxWith(text: string): RuleContext {
  return {
    tree: {
      type: "document",
      sections: [
        {
          id: "s1",
          heading: "",
          level: 1,
          paragraphs: [{ id: "p1", runs: [{ id: "r1", text, start: 0, end: text.length }] }],
          children: [],
        },
      ],
    },
  } as unknown as RuleContext;
}

describe("allMatches", () => {
  it("collects every non-overlapping match with positions", () => {
    const hits = allMatches(ctxWith("pay $100 then $250 then $5"), /\$\d+/);
    expect(hits.map((h) => h.match[0])).toEqual(["$100", "$250", "$5"]);
    expect(hits[0]!.position.start).toBe(4);
  });

  it("terminates on a zero-width-capable regex instead of hanging the tab (spec-v8 §5)", () => {
    // Before the lastIndex guard these spun forever (a synchronous hang). A
    // generous-but-bounded budget proves termination: each returns finitely.
    expect(allMatches(ctxWith("abc def"), /\b/g).length).toBe(4);
    expect(allMatches(ctxWith("abc def"), /x?/g).length).toBe(8); // 7 chars + end
    expect(allMatches(ctxWith(""), /a*/g).length).toBe(1); // one empty match at pos 0
  });

  it("returns an empty array when nothing matches", () => {
    expect(allMatches(ctxWith("no money here"), /\$\d+/)).toEqual([]);
  });
});

describe("firstParagraphMatch", () => {
  it("returns the first match with an absolute position", () => {
    const hit = firstParagraphMatch(ctxWith("term of 30 days notice"), /(\d+)\s+days/);
    expect(hit?.match[1]).toBe("30");
    expect(hit?.position.start).toBe(8);
  });

  it("returns null when there is no match", () => {
    expect(firstParagraphMatch(ctxWith("no number"), /(\d+)\s+days/)).toBeNull();
  });
});

describe("enclosingSentence", () => {
  const at = (text: string, needle: string) => enclosingSentence(text, text.indexOf(needle));

  it("does not truncate at a URL's internal dots", () => {
    const s =
      "The services are subject to the AUP at https://vendor.com/aup, which is for reference only.";
    expect(at(s, "subject")).toContain("for reference only");
  });

  it("does not truncate at a numbering abbreviation before its number", () => {
    // "Contract No. 5" — the "." sits before whitespace + a digit, which the
    // boundary rule read as the start of a new sentence, so the helper returned
    // " 5, which shall govern …" with the subject cut off the front.
    const s = "The contract number is Contract No. 5, which shall govern all disputes.";
    expect(at(s, "shall govern")).toBe(s);
    // The forward scan truncated symmetrically.
    const f = "The parties shall reference Contract No. 5 in all future correspondence.";
    expect(at(f, "shall reference")).toBe(f);
  });

  it("ends the sentence at an abbreviation that is followed by a capital", () => {
    // Ambiguous by construction: "5:00 p.m. Eastern time" is one sentence and
    // "5:00 p.m. The parties shall …" is two, and no local rule tells them
    // apart. Suppressing the boundary fixed the first and broke the second —
    // and the broken direction is the dangerous one, because the window then
    // reads the NEXT sentence (a merged neighbour once put a $9,000,000
    // insurance figure forward as a $500,000 liability cap). So the boundary
    // stands, and the cost is that the first case is cut short.
    const two = "Notice must be delivered no later than 5:00 p.m. The parties shall then execute.";
    expect(at(two, "Notice must")).toBe("Notice must be delivered no later than 5:00 p.m.");
    const one = "Notice must be delivered by 5:00 p.m. Eastern time on the Closing Date.";
    expect(at(one, "Notice must")).toBe("Notice must be delivered by 5:00 p.m.");
  });

  it("does not truncate at a month abbreviation before its day", () => {
    // Same unambiguous shape as "No. 5": no sentence starts with a bare digit
    // right after "Jan.".
    const s = "The renewal notice must be sent by Jan. 5 of each year to remain effective.";
    expect(at(s, "renewal notice")).toBe(s);
  });

  it("still ends the sentence at a genuine boundary", () => {
    // The suppressions must not swallow real sentence ends — the helper exists
    // to keep a neighbouring sentence OUT of a rule's scope.
    const s = "Acme Corp. shall indemnify the Buyer for all losses. The Seller shall not.";
    expect(at(s, "shall indemnify")).toBe("Acme Corp. shall indemnify the Buyer for all losses.");
  });

  it("does not truncate at a decimal citation's dot", () => {
    // "160.103" — a dot not followed by whitespace is not a sentence end.
    const s = "PHI is defined at 45 CFR 160.103, which the parties acknowledge is controlling.";
    expect(at(s, "PHI")).toContain("acknowledge");
  });

  it("still ends the sentence at a real period followed by a space", () => {
    const s = "First sentence here. Second sentence follows.";
    expect(at(s, "First")).toBe("First sentence here.");
  });

  it("does not truncate at a corporate-suffix abbreviation followed by a lowercase word", () => {
    // "Inc. shall …" — the period ends an abbreviation, not the sentence, so the
    // whole clause (subject + obligation) must stay intact for a rule reading it.
    const s = "XYZ Inc. shall indemnify Vendor from claims arising out of gross negligence.";
    expect(at(s, "indemnify")).toBe(s);
    expect(at(s, "XYZ")).toBe(s);
  });

  it("does not truncate at a Latin abbreviation ('p.m.', 'C.F.R.')", () => {
    const s = "Payment is due by 5 p.m. eastern time on the invoice date.";
    expect(at(s, "eastern")).toBe(s);
  });

  it("still ends at a period followed by a capitalized next sentence", () => {
    const s = "Fees are due. The Company shall pay within 30 days.";
    expect(at(s, "pay")).toBe(" The Company shall pay within 30 days.");
  });
});

describe("firstUnnegatedParagraphMatch — disclaims scope", () => {
  it("suppresses a trigger disclaimed as an obligation/duty", () => {
    expect(
      firstUnnegatedParagraphMatch(
        ctxWith("The Vendor disclaims any obligation to indemnify the Customer."),
        /indemnif\w+/i,
      ),
    ).toBeNull();
  });

  it("does NOT suppress a disclaimer that is itself the finding", () => {
    // "disclaims all warranties" is the warranty-disclaimer a rule wants to find.
    expect(
      firstUnnegatedParagraphMatch(
        ctxWith("The Vendor disclaims all warranties, express or implied."),
        /warrant\w+/i,
      ),
    ).not.toBeNull();
  });
});

describe("isPresenceDisclaimed — disclaimer forms", () => {
  const at = (text: string) => isPresenceDisclaimed(text, text.search(/indemnif/i));
  for (const t of [
    "Nothing herein shall require indemnification.",
    "Nothing in this Agreement obligates the Vendor to indemnify.",
    "No party is obligated to indemnify.",
    "The Vendor is not required to indemnify.",
    "This Agreement excludes any indemnification.",
  ]) {
    it(`suppresses: ${t}`, () => {
      expect(at(t)).toBe(true);
    });
  }
  for (const t of [
    "The Vendor shall indemnify the Customer against all claims.",
    "Each party shall indemnify the other for its breaches.",
  ]) {
    it(`does NOT suppress genuine: ${t.slice(0, 30)}`, () => {
      expect(at(t)).toBe(false);
    });
  }
});

describe("the reverse clause boundary is the shared, abbreviation-aware one", () => {
  // `enclosingSentence` walked the shared `SENTENCE_END`, but its two sibling
  // helpers kept private `lastIndexOf(". ")` / `split(/[.;]\s|\n/)` scans that
  // stop at the period in "Sec. 5". Both exist to FIND A NEGATION before the
  // trigger, so truncating there dropped the negation and let the rule fire on
  // drafting that had plainly disclaimed the clause — a confident false
  // accusation. All three now share one scan.
  it("isPresenceDisclaimed sees a negation separated by an abbreviation", () => {
    const text =
      "This Agreement does not include, per Sec. 5 hereof, an indemnification clause for third-party claims.";
    expect(isPresenceDisclaimed(text, text.indexOf("indemnification clause"))).toBe(true);
  });

  it("firstUnnegatedParagraphMatch sees a negator separated by an abbreviation", () => {
    expect(
      firstUnnegatedParagraphMatch(
        ctxWith("This Agreement shall not, per Sec. 5 hereof, automatically renew at the end."),
        /automatically renew/i,
      ),
    ).toBeNull();
  });

  // The other direction: widening the window must not suppress a real finding.
  it("does not let a PRIOR sentence's disclaimer suppress this one", () => {
    const text =
      "This Agreement does not include a warranty. The parties agree to an indemnification clause for third-party claims.";
    expect(isPresenceDisclaimed(text, text.indexOf("indemnification clause"))).toBe(false);
  });

  it("still fires on a genuine trigger after an unrelated negation", () => {
    expect(
      firstUnnegatedParagraphMatch(
        ctxWith("The Order shall not be amended. This Agreement shall automatically renew."),
        /automatically renew/i,
      ),
    ).not.toBeNull();
  });

  it("still fires on a plain unnegated trigger", () => {
    expect(
      firstUnnegatedParagraphMatch(
        ctxWith("This Agreement shall automatically renew at the end of the Term."),
        /automatically renew/i,
      ),
    ).not.toBeNull();
  });
});

describe("the clause scan stays linear on a large, densely-matching paragraph", () => {
  // The rule helpers had no perf gate: `fuzz-boundary.test.ts` caps its inputs
  // at a few hundred characters and targets the extractors, not this layer. So
  // when the reverse scan was unified, a version that ran `SENTENCE_END`
  // forward from index 0 on every call — once per match, inside a loop over
  // every match in the paragraph — went super-linear unnoticed: 94,000
  // characters took 190ms and doubling the input roughly quintupled it. The
  // paste limit allows a single very large paragraph, and this repo guarantees
  // no super-linear blowup on adversarial input.
  const unit = "The Order shall not automatically renew under this clause. ";

  it("is fast enough at 190,000 characters that a quadratic scan cannot hide", () => {
    // Every match is negated, so the loop runs to the very end — the worst case
    // for a per-match scan. Linear work here is single-digit milliseconds; the
    // quadratic version took over 800ms on the same input, so this budget is
    // loose enough to survive a loaded CI machine and still fail a regression
    // by two orders of magnitude.
    const text = unit.repeat(3200);
    const t0 = performance.now();
    const hit = firstUnnegatedParagraphMatch(ctxWith(text), /automatically renew/i);
    const ms = performance.now() - t0;
    expect(hit).toBeNull();
    expect(ms).toBeLessThan(500);
  });

  it("scales sub-quadratically between 47k and 190k characters", () => {
    // Three things make a ratio of two raw measurements unusable here, and all
    // three had to be fixed before this stopped flaking.
    //
    //  1. The 47k scan takes a fraction of a millisecond, so a single sample
    //     is mostly timer quantization. Each measurement therefore times a
    //     BATCH of identical scans, which puts every reading in the
    //     milliseconds where it means something.
    //  2. vitest runs files in parallel, so any one batch can be interrupted
    //     by another worker. The MINIMUM over repeated batches estimates the
    //     algorithm's own cost, because scheduling noise only ever ADDS time.
    //  3. A batch that runs four times longer is exposed to interruption for
    //     four times as long, so a FIXED batch size biases the ratio upward on
    //     a loaded machine no matter how many rounds are taken — this test
    //     failed at 20.0 during a full-suite run while passing alone. The
    //     batch size therefore scales INVERSELY with the input, so under a
    //     linear algorithm both windows are the same length and equally
    //     exposed, and the comparison is per-iteration cost.
    //
    // None of this weakens the signal: a quadratic scan's best case is still
    // ~16x its best case at a quarter of the input, and the bound is 10.
    const WORK = 16_000; // reps x batch, held constant across both sizes
    const perIterationBestOf = (reps: number): number => {
      const ctx = ctxWith(unit.repeat(reps));
      const batch = Math.max(1, Math.round(WORK / reps));
      let best = Infinity;
      for (let round = 0; round < 9; round++) {
        const t0 = performance.now();
        for (let i = 0; i < batch; i++) firstUnnegatedParagraphMatch(ctx, /automatically renew/i);
        best = Math.min(best, (performance.now() - t0) / batch);
      }
      return best;
    };
    perIterationBestOf(400); // warm the JIT so the first timed run is not the slow one
    const small = perIterationBestOf(800);
    const large = perIterationBestOf(3200);
    // 4x the input. Linear predicts ~4x; quadratic predicts ~16x, and that is
    // its BEST case — the bound only has to sit between the two. It is 12
    // rather than 10 because a heavily loaded full-suite run inflates even the
    // minimum window: this read 10.56 on a run that took six times its usual
    // wall clock, and 4.0 on an unloaded one. Twelve still fails a quadratic
    // scan by a wide margin.
    expect(large / small).toBeLessThan(12);
  });
});

describe("an exhibit incorporated into a named parent", () => {
  /**
   * "This Exhibit is incorporated into and forms part of the Subcontract dated
   * May 4, 2026" is the recital every exhibit opens on, and an exhibit dropped
   * in on its own is one of the commonest things a reviewer uploads. It
   * carries no ratification clause (it changes nothing) and is not "issued
   * under" its parent (it is part of it), so neither half of the
   * parent-agreement test saw it: a FAR flowdown exhibit was reported for
   * having no governing law, no venue, no IP allocation, no indemnity, no
   * liability cap, and no termination clause.
   */
  const ctx = (text: string) => ctxWith(text);

  it("recognizes the incorporation recital", () => {
    expect(
      isIncorporatedExhibit(
        ctx(
          "This Exhibit is incorporated into and forms part of the Subcontract dated May 4, 2026 between the Prime Contractor and the Subcontractor.",
        ),
      ),
    ).toBe(true);
  });

  it("recognizes the attached-to-and-made-part-of form", () => {
    expect(
      isIncorporatedExhibit(
        ctx("This Schedule is attached to and made a part of the Master Services Agreement."),
      ),
    ).toBe(true);
  });

  it("does not fire on an agreement incorporating its OWN exhibits", () => {
    expect(
      isIncorporatedExhibit(
        ctx("Each Exhibit referenced in this Agreement is incorporated into this Agreement."),
      ),
    ).toBe(false);
  });

  it("does not fire on an ordinary standalone agreement", () => {
    expect(
      isIncorporatedExhibit(
        ctx(
          "This Agreement is entered into as of March 2, 2026 between Alpha LLC and Beta Inc. and is governed by the laws of the State of Delaware.",
        ),
      ),
    ).toBe(false);
  });
});

describe("a negation inside a sentence-initial condition", () => {
  /**
   * "If Lessee gives NO notice, the Schedule renews on a month-to-month basis"
   * is a live holdover renewal. The negator search read the "no" — which
   * belongs to the CONDITION, not to the main clause — and suppressed
   * TEMP-004 on the commonest auto-renewal an equipment lease carries.
   *
   * The trim is scoped as tightly as the reading is: the negation window must
   * BEGIN with the subordinator, so a negation that governs the main clause is
   * untouched.
   */
  const hit = (text: string) => firstUnnegatedParagraphMatch(ctxWith(text), /automatically renew/i);

  it("does not suppress the main clause", () => {
    expect(
      hit("If Lessee gives no notice of return, the Schedule automatically renews for one year."),
    ).not.toBeNull();
  });

  it("still suppresses a negation that governs the main clause", () => {
    expect(
      hit("The Order shall not, if Customer gives notice, automatically renew for a further term."),
    ).toBeNull();
  });

  it("still suppresses a main clause with a negation of its own", () => {
    expect(
      hit("If the parties do not agree on a new rate, the Order does not automatically renew."),
    ).toBeNull();
  });
});

describe("a companion document that borrows its definitions", () => {
  /**
   * "Capitalized terms used but not defined in this Agreement have the
   * meanings given in the Purchase Agreement" is the recital every earnout,
   * escrow, side letter, and ancillary carries, and it says what the other
   * three parent tests say: the parent supplies what this document does not.
   * An earnout agreement was reported for having no IP allocation, no
   * liability cap, no termination-for-cause path, and no effect-of-termination
   * clause — all four live in the purchase agreement whose definitions it
   * borrows.
   */
  it("recognizes the borrowed-definitions recital", () => {
    expect(
      amendsParentAgreement(
        ctxWith(
          "The Purchase Agreement provides for contingent consideration, and capitalized terms used but not defined in this Agreement have the meanings given in the Purchase Agreement.",
        ),
      ),
    ).toBe(true);
  });

  it("does not fire on a contract that defines its own terms", () => {
    expect(
      amendsParentAgreement(
        ctxWith(
          'Capitalized terms used in this Agreement have the meanings given in Section 1. "Net Revenue" means the consolidated revenue of the Company.',
        ),
      ),
    ).toBe(false);
  });

  it("does not fire when the parent is not named", () => {
    expect(
      amendsParentAgreement(
        ctxWith("Capitalized terms not defined here have the meanings given below."),
      ),
    ).toBe(false);
  });
});

describe("expressDenial — a causative is not a denial", () => {
  // "Vendor shall not PERMIT any subprocessor or model provider to use
  // Customer Data to train a model" is a negative covenant about what a
  // subprocessor may do. Read as a denial, it told an AI addendum at
  // `warning` that it states its subprocessors are not disclosed — the
  // opposite of what the same sentence goes on to promise.
  const denies = (topic: string, text: string) => expressDenial(topic).some((re) => re.test(text));

  it("does not read 'shall not permit any X to Y' as denying X", () => {
    expect(
      denies(
        String.raw`(?:ai\s+)?sub.?processors?`,
        "Vendor shall not use, and shall not permit any subprocessor or model provider to use, Customer Data to train any model.",
      ),
    ).toBe(false);
  });

  it("does not read 'shall not allow / authorize / cause X' as denying X", () => {
    for (const frame of ["allow any", "authorize any", "cause any", "enable any"]) {
      expect(
        denies(
          String.raw`(?:ai\s+)?sub.?processors?`,
          `Vendor shall not ${frame} subprocessor to access Customer Data.`,
        ),
        frame,
      ).toBe(false);
    }
  });

  it("still reads a real denial of the same topic", () => {
    expect(
      denies(
        String.raw`(?:ai\s+)?sub.?processors?`,
        "Vendor does not disclose subprocessors and has no obligation to do so.",
      ) ||
        denies(
          String.raw`(?:ai\s+)?sub.?processors?`,
          "This Addendum contains no subprocessor list.",
        ),
    ).toBe(true);
  });
});

describe("amendsParentAgreement — an exhibit that names itself", () => {
  // "This INFORMATION SECURITY Exhibit is attached to and incorporated into
  // the Master Services Agreement dated October 12, 2024" is the recital such
  // a document opens on. The test required the bare noun immediately after
  // "This", and admitted "incorporated into" only when it followed "is"
  // directly — so a vendor security exhibit that relies on incorporation
  // rather than a ratification clause (it changes nothing, so it carries
  // none) was reported as having no governing law, no IP allocation, no
  // indemnity, no liability cap and no termination clause. All five live in
  // the agreement it is attached to.
  const RECITAL =
    'This Information Security Exhibit (this "Exhibit") is attached to and incorporated into the Master Services Agreement dated October 12, 2024 between Rowan Credit Union ("Customer") and Beacon Ledger Systems, Inc. ("Vendor").';

  it("recognizes a self-named exhibit incorporated into a named parent", () => {
    const ctx = buildContext(["Information Security Exhibit", RECITAL]);
    expect(amendsParentAgreement(ctx)).toBe(true);
    expect(isIncorporatedExhibit(ctx)).toBe(true);
  });

  it("does not treat an agreement incorporating its OWN exhibits as subordinate", () => {
    const ctx = buildContext([
      "Services Agreement",
      "Each Exhibit is incorporated into this Agreement and forms part of it.",
    ]);
    expect(isIncorporatedExhibit(ctx)).toBe(false);
  });
});
