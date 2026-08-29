import { describe, expect, it } from "vitest";
import { V4_RULES } from "../index.js";
import { buildContext } from "../../../_test-fixtures.js";
import type { Rule } from "../../../finding.js";

const EST027 = V4_RULES.find((r) => r.id === "EST-027") as Rule;

/**
 * "My agent's authority BEGINS when my attending physician determines in
 * writing that I LACK THE CAPACITY to make or communicate my own health care
 * decisions" is the ordinary drafting of the springing clause. EST-027 wanted
 * "takes effect upon" and "incapacity", and reported the clause missing at
 * `critical` on the document that states it.
 */
describe("EST-027 — the springing clause as one is written", () => {
  it("reads 'authority begins when … lacks the capacity'", () => {
    expect(
      EST027.check(
        buildContext([
          "Health Care Power of Attorney",
          "My agent's authority begins when my attending physician determines in writing that I lack the capacity to make or communicate my own health care decisions, and ends when I regain that capacity.",
        ]),
      ),
    ).toBeNull();
  });

  it("still fires on a power of attorney that never says when it starts", () => {
    expect(
      EST027.check(
        buildContext([
          "Health Care Power of Attorney",
          "I appoint Tobias Osgood-Reyes as my health care agent to make health care decisions for me.",
        ]),
      ),
    ).not.toBeNull();
  });
});
