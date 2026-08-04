import { describe, expect, it } from "vitest";
import { rule as DARK_007 } from "./DARK-007.js";
import { buildContext } from "../../_test-fixtures.js";

describe("DARK-007 — browsewrap / passive acceptance", () => {
  it("fires on `by using the Service you agree`", () => {
    const ctx = buildContext([
      "Acceptance",
      "By using the Service you agree to be bound by these Terms.",
    ]);
    expect(DARK_007.check(ctx)?.severity).toBe("warning");
  });

  it("fires on `continued use constitutes acceptance`", () => {
    const ctx = buildContext([
      "Modifications",
      "Vendor may update the Terms at any time. Continued use of the Service constitutes acceptance of the updated Terms.",
    ]);
    expect(DARK_007.check(ctx)).not.toBeNull();
  });

  it("fires on `you are deemed to have agreed`", () => {
    const ctx = buildContext([
      "Terms",
      "By accessing this Site, you are deemed to have agreed to all provisions of these Terms.",
    ]);
    expect(DARK_007.check(ctx)).not.toBeNull();
  });

  it("is silent on an affirmative-consent clickwrap clause", () => {
    const ctx = buildContext([
      "Acceptance",
      "By clicking 'I Agree' below, Customer agrees to the terms of this Agreement.",
    ]);
    expect(DARK_007.check(ctx)).toBeNull();
  });

  it("is silent when no acceptance language is present", () => {
    const ctx = buildContext([
      "Term",
      "This Agreement is effective for two years from the Effective Date.",
    ]);
    expect(DARK_007.check(ctx)).toBeNull();
  });

  it("reads download/install and 'your use constitutes' passive-assent forms (v1.1.0)", () => {
    for (const clause of [
      "By downloading the Application you agree to be bound by these Terms.",
      "By installing the Software you accept these Terms.",
      "Your use of the Service constitutes your acceptance of these Terms.",
    ]) {
      expect(DARK_007.check(buildContext(["Acceptance", clause])), clause).not.toBeNull();
    }
  });

  it("does not flag a neutral 'your use … is subject to' clause", () => {
    expect(
      DARK_007.check(
        buildContext([
          "Availability",
          "Your use of the Service is subject to the availability of the network.",
        ]),
      ),
    ).toBeNull();
  });
});
