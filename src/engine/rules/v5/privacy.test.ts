import { describe, expect, it } from "vitest";
import { buildContext } from "../../_test-fixtures.js";
import { V5_RULES } from "./index.js";

const rule = (id: string) => {
  const r = V5_RULES.find((x) => x.id === id);
  if (!r) throw new Error(`no v5 rule ${id}`);
  return r;
};

/**
 * BIPA § 15(b) asks the form to say what is collected, why, for how long, and
 * to obtain a written release. A form that recites those elements in the
 * statute's own words was told at `critical` that it obtained no written
 * release.
 */
describe("PRV-101 — the BIPA release as a form writes it", () => {
  const CONSENT = [
    "Biometric Information Consent and Release",
    "Larkfield Logistics, Inc. is collecting, storing, and using a biometric identifier and biometric information about me, the specific purpose for which it is being collected, and the length of time for which it will be stored and used.",
    "I give my written consent, or my legally authorized representative gives it, to that collection, storage, and use.",
  ] as [string, ...string[]];

  it("reads the statutory recital", () => {
    expect(rule("PRV-101").check(buildContext(CONSENT))).toBeNull();
  });

  it("still fires on a notice that asks for nothing", () => {
    expect(
      rule("PRV-101").check(
        buildContext([
          "Timekeeping Notice",
          "Our timekeeping system scans the shape of your hand at the start and end of each shift.",
        ]),
      ),
    ).not.toBeNull();
  });
});
