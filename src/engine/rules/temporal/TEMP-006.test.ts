import { describe, expect, it } from "vitest";
import { rule as TEMP_006 } from "./TEMP-006.js";
import { buildContext } from "../../_test-fixtures.js";

const doc = (heading: string, ...rest: string[]) => buildContext([heading, ...rest]);

describe("TEMP-006 — survival clause present", () => {
  it("fires on the verb-first form 'shall survive the termination'", () => {
    expect(
      TEMP_006.check(
        doc("Survival", "Sections 5 through 8 shall survive the termination of this Agreement."),
      ),
    ).not.toBeNull();
  });

  // v1.1.0 — the dominant phrasing leads with the event ("Upon termination …
  // shall survive"), and survival is as often tied to expiration.
  it("fires on the event-first (reversed) form", () => {
    expect(
      TEMP_006.check(
        doc(
          "Survival",
          "Upon termination or expiration of this Agreement, the confidentiality obligations shall survive.",
        ),
      ),
    ).not.toBeNull();
  });

  it("fires when survival is tied to expiration rather than termination", () => {
    expect(
      TEMP_006.check(doc("Survival", "These provisions survive expiration of the Agreement.")),
    ).not.toBeNull();
  });

  it("is silent on an unrelated 'surviving spouse … upon termination' clause", () => {
    // The reversed branch excludes the participle so a person surviving is not
    // read as clause survival.
    expect(
      TEMP_006.check(
        doc(
          "Benefits",
          "Upon termination of employment, benefits pass to the surviving spouse of the employee.",
        ),
      ),
    ).toBeNull();
  });

  it("is silent when nothing survives", () => {
    expect(
      TEMP_006.check(doc("Term", "Either party may effect termination on 30 days written notice.")),
    ).toBeNull();
  });
});
