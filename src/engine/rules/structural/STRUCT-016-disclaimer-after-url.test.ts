import { describe, expect, it } from "vitest";
import { rule as STRUCT_016 } from "./STRUCT-016.js";
import { buildContext } from "../../_test-fixtures.js";

// Guard: a URL-incorporation carve-out placed AFTER the URL — the natural order —
// must silence STRUCT-016. The sentence splitter used to truncate at the URL's
// own dots ("vendor.com"), so the trailing disclaimer was never seen and a
// properly-disclaimed reference was flagged.
const BASE =
  "The services are subject to Vendor's Acceptable Use Policy available at https://vendor.com/aup";

describe("STRUCT-016 disclaimer after a URL", () => {
  for (const disclaimer of [
    ", which is provided for informational purposes only.",
    ", which does not form part of this Agreement.",
    ", which is not part of this Agreement.",
    ", which is provided for reference only.",
    " for convenience only.",
  ]) {
    it(`silences on: ${disclaimer.trim()}`, () => {
      expect(STRUCT_016.check(buildContext(["Services", BASE + disclaimer]))).toBeNull();
    });
  }

  it("still fires when the incorporation carries no carve-out", () => {
    expect(STRUCT_016.check(buildContext(["Services", BASE + "."]))).not.toBeNull();
  });
});
