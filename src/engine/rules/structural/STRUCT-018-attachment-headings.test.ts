import { describe, expect, it } from "vitest";
import { rule as STRUCT_018 } from "./STRUCT-018.js";
import { buildContext } from "../../_test-fixtures.js";

// Guard: an attachment that IS present must be recognized by its heading form,
// however the identifier is written, so a plainly attached exhibit is not
// reported as "referenced but not attached".
describe("STRUCT-018 attachment-heading recognition", () => {
  const presentWithHeading = (ref: string, heading: string) =>
    STRUCT_018.check(
      buildContext(
        ["Agreement", `The parties shall comply with ${ref}.`],
        [heading, "This attachment sets out the relevant terms."],
      ),
    );

  it("recognizes a plain heading", () => {
    expect(presentWithHeading("Exhibit C", "Exhibit C — Data Terms")).toBeNull();
  });
  it("recognizes an all-caps colon heading", () => {
    expect(presentWithHeading("Exhibit C", "EXHIBIT C: DATA TERMS")).toBeNull();
  });
  it("recognizes a quoted-identifier heading", () => {
    expect(presentWithHeading("Exhibit C", 'Exhibit "C" — Data Terms')).toBeNull();
  });
  it("recognizes a No.-prefixed heading", () => {
    expect(presentWithHeading("Exhibit 3", "Exhibit No. 3 — Terms")).toBeNull();
  });

  it("still flags a genuinely absent attachment", () => {
    expect(
      STRUCT_018.check(
        buildContext(
          ["Agreement", "The parties shall comply with Exhibit D."],
          ["Body", "No exhibit is attached here."],
        ),
      ),
    ).not.toBeNull();
  });
});
