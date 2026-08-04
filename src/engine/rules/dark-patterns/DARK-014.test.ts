/**
 * DARK-014 flags a consumer anti-review "gag" clause, void under the Consumer
 * Review Fairness Act (15 U.S.C. § 45b). Pinned both ways: the review
 * restriction fires at critical, while an honest-review-preserving carve-out
 * and a confidential-information restriction stay silent.
 */
import { describe, expect, it } from "vitest";
import { rule as DARK_014 } from "./DARK-014.js";
import { buildContext } from "../../_test-fixtures.js";

describe("DARK-014 — consumer anti-review gag clause", () => {
  it("fires (critical) on a bar against negative reviews", () => {
    const f = DARK_014.check(
      buildContext([
        "Terms",
        "Customer shall not post any negative reviews or disparaging comments about the Company online.",
      ]),
    );
    expect(f).not.toBeNull();
    expect(f?.severity).toBe("critical");
  });

  it("fires on 'agree not to publish any critical review' (adjective-before form)", () => {
    expect(
      DARK_014.check(
        buildContext([
          "Terms",
          "You agree not to publish any critical review of the Service on any website.",
        ]),
      ),
    ).not.toBeNull();
  });

  it("stays silent when the right to post honest reviews is preserved", () => {
    expect(
      DARK_014.check(
        buildContext(["Terms", "Customer may post honest reviews of the product at any time."]),
      ),
    ).toBeNull();
  });

  it("stays silent on a confidential-information restriction (not a review bar)", () => {
    expect(
      DARK_014.check(
        buildContext([
          "Terms",
          "Customer shall not post confidential information on public forums.",
        ]),
      ),
    ).toBeNull();
  });

  it("recognizes Subscriber / Member / Account Holder / End User as the consumer (v1.1.0)", () => {
    for (const clause of [
      "Subscriber shall not post negative reviews of the Service.",
      "Members may not leave a bad rating for the Service.",
      "Account holders shall not post disparaging reviews.",
      "End Users are not permitted to publish critical reviews.",
    ]) {
      const f = DARK_014.check(buildContext(["Reviews", clause]));
      expect(f, clause).not.toBeNull();
      expect(f?.severity).toBe("critical");
    }
  });

  it("still exempts a confidential-info bar / preserved-review-right for those parties", () => {
    expect(
      DARK_014.check(
        buildContext(["Reviews", "Subscriber shall not post confidential information about us."]),
      ),
    ).toBeNull();
    expect(
      DARK_014.check(
        buildContext(["Reviews", "Members are free to post any honest review of the Service."]),
      ),
    ).toBeNull();
  });
});
