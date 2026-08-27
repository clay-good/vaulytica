import { describe, expect, it } from "vitest";
import { rule as STRUCT_009 } from "./STRUCT-009.js";
import { buildContext } from "../../_test-fixtures.js";

/**
 * A lowercase occurrence inside a QUOTED phrase is a quotation, not a
 * miscapitalized use of the defined term.
 *
 * Every EULA sold to the US government recites FAR 12.212: the Software is
 * "commercial computer software" — the regulation's own defined phrase,
 * written in lowercase and in quotation marks because it is being quoted.
 * STRUCT-009 read the "software" inside it as a lowercase use of the
 * agreement's defined "Software", and reported an inconsistency the drafter
 * cannot fix without misquoting the regulation.
 */
describe("STRUCT-009 — a lowercase term inside a quotation (v1.7.0)", () => {
  const DEFINED =
    '"Software" means the Vanterra Sensor Studio desktop application and the accompanying documentation.';

  it("does not report a quoted statutory phrase", () => {
    expect(
      STRUCT_009.check(
        buildContext([
          "End-User License Agreement",
          DEFINED,
          "You may install the Software on three Devices.",
          'If You are a U.S. government end user, the Software is "commercial computer software" under FAR 12.212 and DFARS 227.7202.',
        ]),
      ),
    ).toBeNull();
  });

  it("still reports a genuine lowercase use of the defined term", () => {
    const finding = STRUCT_009.check(
      buildContext([
        "End-User License Agreement",
        DEFINED,
        "You may install the Software on three Devices.",
        "You shall not resell the software or provide it as a service.",
      ]),
    );
    expect(finding).not.toBeNull();
    expect(finding!.description).toContain("Software");
  });
});
