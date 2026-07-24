/**
 * These rules exist to catch consumer-facing dark patterns, but each was
 * written to a narrower phrasing than the patterns actually take, so the
 * textbook form of the very clause the rule polices went unreported. An
 * adversarial "Vendor Terms of Service" surfaced all of them at once. Both
 * directions are pinned: the genuine pattern fires, and the compliant /
 * disclaimed form of the same clause stays silent.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../../_test-fixtures.js";
import { rule as DARK_002 } from "./DARK-002.js";
import { rule as DARK_003 } from "./DARK-003.js";
import { rule as DARK_004 } from "./DARK-004.js";
import { rule as DARK_008 } from "./DARK-008.js";
import { rule as CHOICE_008 } from "../choice-and-venue/CHOICE-008.js";

describe("DARK-002 — 'renews automatically' with a (90)-day window (v1.1.0)", () => {
  it("fires on the adverb-after-verb form with a spelled-then-numeric window", () => {
    const ctx = buildContext(
      [
        "Renewal",
        "The subscription renews automatically for successive twelve (12) month terms unless you provide written notice of non-renewal at least ninety (90) days before the end of the term.",
      ],
      ["Other", "Unrelated content."],
    );
    expect(DARK_002.check(ctx)).not.toBeNull();
  });

  it("stays silent when the term does not auto-renew", () => {
    const ctx = buildContext([
      "Renewal",
      "This Agreement expires at the end of the term and does not renew automatically.",
    ]);
    expect(DARK_002.check(ctx)).toBeNull();
  });
});

describe("DARK-003 — 'you shall pay Vendor's attorneys' fees' (v1.1.0)", () => {
  it("fires when the second-person reader bears one-way fees", () => {
    const ctx = buildContext([
      "Disputes",
      "If Vendor prevails in any dispute, you shall pay Vendor's attorneys' fees.",
    ]);
    expect(DARK_003.check(ctx)).not.toBeNull();
  });

  it("stays silent on a mutual fee-bearing clause", () => {
    const ctx = buildContext([
      "Fees",
      "Each party shall bear its own attorneys' fees regardless of the outcome of any dispute.",
    ]);
    expect(DARK_003.check(ctx)).toBeNull();
  });
});

describe("DARK-004 — binding individual arbitration + class waiver by title (v1.1.0)", () => {
  it("fires when the consumer signal is the document title and the waivers chain", () => {
    const ctx = buildContext(
      ["Vendor Terms of Service", "By using the Service you agree to these Terms."],
      [
        "Disputes",
        "Any dispute shall be resolved by binding individual arbitration. You waive any right to a jury trial and any right to participate in a class action.",
      ],
    );
    expect(DARK_004.check(ctx)).not.toBeNull();
  });

  it("stays silent when arbitration and the class waiver are disclaimed", () => {
    const ctx = buildContext([
      "Terms of Service",
      "Disputes may be brought in court. This Agreement contains no mandatory arbitration and no class-action waiver.",
    ]);
    expect(DARK_004.check(ctx)).toBeNull();
  });
});

describe("DARK-008 — suspend OR TERMINATE your access without notice (v1.1.0)", () => {
  it("fires on suspension of access with no notice or cure", () => {
    const ctx = buildContext([
      "Suspension",
      "Vendor may suspend or terminate your access immediately, without notice and without any cure period, for any reason.",
    ]);
    expect(DARK_008.check(ctx)).not.toBeNull();
  });

  it("stays silent when suspension requires notice and cure", () => {
    const ctx = buildContext([
      "Suspension",
      "Vendor may suspend the Service only upon thirty days' written notice and an opportunity to cure.",
    ]);
    expect(DARK_008.check(ctx)).toBeNull();
  });
});

describe("CHOICE-008 — 'waive any right to a jury trial' (v1.1.0)", () => {
  it("fires on the ordinary American jury-trial waiver order", () => {
    const ctx = buildContext([
      "Disputes",
      "You waive any right to a jury trial in connection with any dispute arising under these Terms.",
    ]);
    expect(CHOICE_008.check(ctx)).not.toBeNull();
  });

  it("stays silent when the jury-trial right is preserved", () => {
    const ctx = buildContext([
      "Disputes",
      "Each party retains its right to a jury trial in any dispute.",
    ]);
    expect(CHOICE_008.check(ctx)).toBeNull();
  });
});

describe("DARK-003 — one-way fee shift in leases and loans (v1.2.0)", () => {
  it("fires on 'Tenant shall pay Landlord's attorneys' fees'", () => {
    expect(
      DARK_003.check(
        buildContext([
          "Lease",
          "Tenant shall pay Landlord's attorneys' fees in any action to enforce this Lease.",
        ]),
      ),
    ).not.toBeNull();
  });
  it("fires on 'Borrower shall pay Lender's attorneys' fees'", () => {
    expect(
      DARK_003.check(
        buildContext(["Note", "Borrower shall pay Lender's attorneys' fees upon default."]),
      ),
    ).not.toBeNull();
  });
  it("stays silent on a reciprocal prevailing-party clause", () => {
    expect(
      DARK_003.check(
        buildContext([
          "Terms",
          "The prevailing party shall be entitled to its reasonable attorneys' fees.",
        ]),
      ),
    ).toBeNull();
  });
});
