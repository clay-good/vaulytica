/**
 * DARK-009 flags amendment by posting a new version online with implicit
 * acceptance. It was firing on the compliant OPPOSITE: a privacy policy that
 * posts a notice AND emails / in-app notifies the user AND gives 30 days
 * advance — exactly the "written notice (email + at least 30 days) with a
 * defined objection right" the rule's own recommendation prescribes.
 */
import { describe, expect, it } from "vitest";
import { rule as DARK_009 } from "./DARK-009.js";
import { buildContext } from "../../_test-fixtures.js";

const doc = (t: string) => buildContext(["Updates to This Policy", t]);

describe("DARK-009 — unilateral amendment by posting", () => {
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
