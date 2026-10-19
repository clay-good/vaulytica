import { describe, expect, it } from "vitest";
import { rule as TERM_001 } from "./TERM-001.js";
import { buildContext } from "../../_test-fixtures.js";

const doc = (text: string) => buildContext(["Termination", text]);

describe("TERM-001 — the notice period in either order", () => {
  it("reads the count first", () => {
    const f = TERM_001.check(
      doc(
        "Either party may terminate this Agreement for convenience upon thirty (30) days' prior written notice.",
      ),
    );
    expect(f?.title).toBe("Termination for convenience: 30 days' notice");
  });

  it("reads the noun first", () => {
    // "notice of thirty (30) days" is the same period, in the order much
    // English drafting uses; TERM-001 read only the count-first order.
    const f = TERM_001.check(
      doc(
        "Either party may terminate this Agreement for convenience upon prior written notice of thirty (30) days.",
      ),
    );
    expect(f?.title).toBe("Termination for convenience: 30 days' notice");
  });

  it("reads 'not less than' between them", () => {
    const f = TERM_001.check(
      doc(
        "Either party may terminate this Agreement without cause on notice of not less than ninety (90) days.",
      ),
    );
    expect(f?.title).toBe("Termination for convenience: 90 days' notice");
  });
});
