import { describe, expect, it } from "vitest";
import { rule as DARK_009 } from "./DARK-009.js";
import { buildContext } from "../../_test-fixtures.js";

describe("DARK-009 — unilateral amendment by posting", () => {
  it("fires on 'Vendor may modify the terms by posting on its website'", () => {
    const ctx = buildContext([
      "14.5 Modifications",
      "Vendor may modify the terms of this Agreement at any time by posting a revised version on its website; continued use of the Service constitutes acceptance.",
    ]);
    const f = DARK_009.check(ctx);
    expect(f).not.toBeNull();
    expect(f?.severity).toBe("warning");
  });

  it("fires on the continued-use-as-acceptance idiom alone", () => {
    const ctx = buildContext([
      "Updates",
      "We may update these Terms from time to time. Your continued use of the Service after an update will constitute your acceptance of the modified Terms.",
    ]);
    expect(DARK_009.check(ctx)).not.toBeNull();
  });

  it("silent on a balanced 'signed amendment' clause", () => {
    const ctx = buildContext([
      "14.5 Amendments",
      "This Agreement may be amended only by a written instrument signed by an authorized representative of each party.",
    ]);
    expect(DARK_009.check(ctx)).toBeNull();
  });

  it("silent on simple 'notice in writing' language without posting/url", () => {
    const ctx = buildContext([
      "14.5 Notices",
      "Either party may amend this Agreement by notice in writing delivered to the other party.",
    ]);
    expect(DARK_009.check(ctx)).toBeNull();
  });

  // Regression: a clause that REJECTS continued-use-as-acceptance is compliant.
  it("silent on `continued use does NOT constitute acceptance`", () => {
    const ctx = buildContext([
      "Amendments",
      "We may amend this Agreement only by a written amendment signed by both parties. Continued use of the Service does not constitute acceptance of any change that has not been separately signed by Customer.",
    ]);
    expect(DARK_009.check(ctx)).toBeNull();
  });
});

describe("DARK-009 — compliant notice-based amendment is not a dark pattern", () => {
  // It was firing on the compliant OPPOSITE: a privacy policy that posts a
  // notice AND emails / in-app notifies AND gives 30 days advance — exactly the
  // "written notice (email + at least 30 days) with a defined objection right"
  // the rule's own recommendation prescribes.
  const doc = (t: string) => buildContext(["Updates to This Policy", t]);

  it("stays silent when posting is paired with direct notice and an advance period", () => {
    expect(
      DARK_009.check(
        doc(
          "We may update this Privacy Policy from time to time. When we make material changes, we will post a notice on our website and, where required by law, notify you by email or in-app notification at least thirty (30) days before the changes take effect.",
        ),
      ),
    ).toBeNull();
  });

  it("still fires on amendment by posting with continued-use acceptance", () => {
    expect(
      DARK_009.check(
        doc(
          "Provider may modify these terms at any time by posting the revised Agreement on its website, and your continued use of the Service constitutes acceptance.",
        ),
      ),
    ).not.toBeNull();
  });

  it("still fires on post-only amendment with no individual notice", () => {
    expect(
      DARK_009.check(
        doc(
          "We reserve the right to change this policy by publishing an updated version on our site at any time.",
        ),
      ),
    ).not.toBeNull();
  });
});
