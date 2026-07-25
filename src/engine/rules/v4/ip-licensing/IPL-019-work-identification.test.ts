import { describe, expect, it } from "vitest";
import { V4_RULES } from "../index.js";
import { buildContext } from "../../../_test-fixtures.js";
import type { Rule } from "../../../finding.js";

const IPL019 = V4_RULES.find((r) => r.id === "IPL-019") as Rule;

// Guard: IPL-019 (copyright-scoped) warns when the licensed work is not
// identified. A copyright license as often identifies it by a defined "Work" and
// an attachment ("the Work described on Exhibit A") as by the literal phrase
// "licensed works", so both must satisfy the rule; a license that names no work
// still warns.
describe("IPL-019 licensed-work identification", () => {
  for (const clause of [
    "Licensor owns all copyright in and to the Work described on Exhibit A.",
    '"Work" means the illustrated book titled "The Lantern Keeper," as described on Exhibit A.',
    "The Licensor grants a license to the copyrighted works listed on Schedule B.",
  ]) {
    it(`recognizes: ${clause.slice(0, 46)}`, () => {
      expect(IPL019.check(buildContext(["Grant", clause]))).toBeNull();
    });
  }

  it("still warns when no licensed work is identified", () => {
    expect(
      IPL019.check(
        buildContext([
          "Grant",
          "The Licensor grants the Licensee a non-exclusive license during the Term.",
        ]),
      ),
    ).not.toBeNull();
  });
});
