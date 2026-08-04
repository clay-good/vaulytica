import { describe, expect, it } from "vitest";
import { rule as IPDATA_006 } from "./IPDATA-006.js";
import { buildContext } from "../../_test-fixtures.js";

const fires = (body: string) => IPDATA_006.check(buildContext(["Escrow", body])) !== null;

describe("IPDATA-006 — source code escrow", () => {
  it("fires on the canonical 'source code escrow'", () => {
    expect(fires("The parties shall establish a source code escrow with a neutral agent.")).toBe(
      true,
    );
  });

  // v1.1.0 — "software escrow" / "technology escrow" are the same arrangement,
  // and the object also leads ("escrow of the source code").
  it("fires on the software / technology escrow synonyms and the reversed form", () => {
    expect(fires("Vendor shall enter into a software escrow agreement with a neutral agent.")).toBe(
      true,
    );
    expect(fires("A technology escrow arrangement protects the licensee on insolvency.")).toBe(
      true,
    );
    expect(
      fires("The Agreement provides for escrow of the source code and build instructions."),
    ).toBe(true);
  });

  it("does not read an unrelated purchase-price escrow as a source-code escrow", () => {
    expect(fires("The purchase price shall be held in escrow pending closing.")).toBe(false);
  });
});
