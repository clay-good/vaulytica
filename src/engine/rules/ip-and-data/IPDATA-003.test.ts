/**
 * IPDATA-003 surfaces the scope of an IP license grant. v1.1.0 adds a
 * negated-detector guard: a no-license clause ("does not grant a … license",
 * "Nothing herein grants …", "Neither party grants …") reuses the same
 * "grants a <scope> license" shape but grants nothing, so it must not be
 * surfaced as a stated grant. An unrelated earlier "not" still fires.
 */
import { describe, expect, it } from "vitest";
import { rule as IPDATA_003 } from "./IPDATA-003.js";
import { buildContext } from "../../_test-fixtures.js";

const clause = (text: string) => buildContext(["Agreement", text]);

describe("IPDATA-003 — license grant scope", () => {
  it("fires on a genuine scoped grant", () => {
    expect(
      IPDATA_003.check(clause("Licensor grants a perpetual, worldwide license to the Software.")),
    ).not.toBeNull();
  });

  it("still fires when an unrelated 'not' sits earlier in the sentence", () => {
    expect(
      IPDATA_003.check(
        clause(
          "Although the parties have not agreed on price, Licensor grants a perpetual license.",
        ),
      ),
    ).not.toBeNull();
  });

  it("does not fire on 'does not grant a … license'", () => {
    expect(
      IPDATA_003.check(
        clause("This Agreement does not grant a perpetual or worldwide license to the data."),
      ),
    ).toBeNull();
  });

  it("does not fire on 'Nothing herein grants a … license'", () => {
    expect(
      IPDATA_003.check(
        clause("Nothing in this Agreement grants a non-exclusive license to either party."),
      ),
    ).toBeNull();
  });

  it("does not fire on 'Neither party grants a … license'", () => {
    expect(
      IPDATA_003.check(clause("Neither party grants a royalty-free license under this NDA.")),
    ).toBeNull();
  });
});
