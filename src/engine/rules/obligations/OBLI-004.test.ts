/**
 * OBLI-004 surfaces the ambiguous "best efforts" standard. v1.1.0 also
 * recognises the British direct equivalent "best endeavours" / "best
 * endeavors", while still suppressing an explicit disclaimer of the standard.
 */
import { describe, expect, it } from "vitest";
import { rule as OBLI_004 } from "./OBLI-004.js";
import { buildContext } from "../../_test-fixtures.js";

describe("OBLI-004 — best efforts / best endeavours ambiguity", () => {
  it("fires on 'best efforts'", () => {
    expect(
      OBLI_004.check(buildContext(["Agreement", "Vendor shall use best efforts to deliver."])),
    ).not.toBeNull();
  });

  it("fires on the British 'best endeavours'", () => {
    expect(
      OBLI_004.check(
        buildContext(["Agreement", "The Supplier shall use its best endeavours to complete."]),
      ),
    ).not.toBeNull();
  });

  it("fires on the American-spelled 'best endeavors'", () => {
    expect(
      OBLI_004.check(
        buildContext(["Agreement", "Each party shall use best endeavors to obtain consents."]),
      ),
    ).not.toBeNull();
  });

  it("stays silent when the standard is explicitly disclaimed", () => {
    expect(
      OBLI_004.check(
        buildContext([
          "Agreement",
          "The Vendor shall use commercially reasonable efforts, and not best efforts, to deliver.",
        ]),
      ),
    ).toBeNull();
  });

  it("stays silent on 'reasonable efforts' alone", () => {
    expect(
      OBLI_004.check(
        buildContext(["Agreement", "Vendor shall use reasonable efforts to deliver."]),
      ),
    ).toBeNull();
  });
});
