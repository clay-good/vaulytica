import { describe, expect, it } from "vitest";
import { V4_RULES } from "../index.js";
import { buildContext } from "../../../_test-fixtures.js";
import type { Rule } from "../../../finding.js";

const rule = (id: string) => V4_RULES.find((r) => r.id === id) as Rule;

// A family note in plain words: an installment schedule with a start date and
// acceleration without the words "default" or "accelerate". Both were read as
// missing, at CRITICAL.
const NOTE = buildContext([
  "Note",
  'For value received, Julian Park ("Borrower") promises to pay to the order of Grace Park ("Lender") the principal sum of $30,000, with interest at 4% per year, in 24 equal monthly installments beginning June 1, 2026.',
  "If any installment is more than 15 days late, the entire balance becomes due at Lender's option.",
]);

describe("BNK-004 / BNK-005 — a note in plain words", () => {
  it("reads an installment schedule with a start date as a definite time", () => {
    expect(rule("BNK-004").check(NOTE)).toBeNull();
  });

  it("reads 'the entire balance becomes due' as acceleration", () => {
    expect(rule("BNK-005").check(NOTE)).toBeNull();
  });

  it("still asks a note with neither", () => {
    const bare = buildContext([
      "Note",
      "Borrower promises to pay Lender the principal sum of $30,000 with interest at 4% per year.",
    ]);
    expect(rule("BNK-004").check(bare)).not.toBeNull();
    expect(rule("BNK-005").check(bare)).not.toBeNull();
  });
});
