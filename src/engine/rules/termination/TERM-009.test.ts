import { describe, expect, it } from "vitest";
import { rule as TERM_009 } from "./TERM-009.js";
import { buildContext } from "../../_test-fixtures.js";

describe("TERM-009 — asymmetric termination-for-convenience", () => {
  it("fires when Vendor can terminate at any time and Customer needs material breach", () => {
    const ctx = buildContext([
      "Termination",
      "Vendor may terminate this Agreement at any time upon written notice.",
      "Customer may only terminate this Agreement for material breach following a 30-day cure period.",
    ]);
    const f = TERM_009.check(ctx);
    expect(f?.severity).toBe("warning");
    expect(f?.title).toMatch(/asymmetric/i);
  });

  it("fires when Employer can terminate for convenience and Employee needs cure period", () => {
    const ctx = buildContext([
      "Termination",
      "Employer may terminate for any reason in its sole discretion.",
      "Employee shall terminate this Agreement only after providing 60 days written notice of any material breach.",
    ]);
    expect(TERM_009.check(ctx)).not.toBeNull();
  });

  it("is silent when both parties have the same termination right", () => {
    const ctx = buildContext([
      "Termination",
      "Either party may terminate this Agreement at any time upon 30 days notice.",
    ]);
    expect(TERM_009.check(ctx)).toBeNull();
  });

  it("is silent when only one termination clause exists (no asymmetry)", () => {
    const ctx = buildContext([
      "Termination",
      "Vendor may terminate this Agreement at any time upon 30 days notice.",
    ]);
    expect(TERM_009.check(ctx)).toBeNull();
  });
});

describe("TERM-009 — convenience trigger recognizes 'without cause' / bare 'for convenience' (v1.1.0)", () => {
  const CURE =
    "Customer may only terminate this Agreement upon a material breach by Vendor that remains uncured after a 30-day cure period.";
  const fires = (conv: string) =>
    TERM_009.check(buildContext(["Termination", conv, CURE])) !== null;

  it.each([
    "Vendor may terminate this Agreement at any time.",
    "Vendor may terminate this Agreement for any reason.",
    "Vendor may terminate this Agreement without cause upon thirty days notice.",
    "Vendor may terminate this Agreement for convenience or without cause.",
  ])("fires on an asymmetric convenience right: %s", (conv) => {
    expect(fires(conv)).toBe(true);
  });

  it.each([
    "Either party may terminate this Agreement at any time.",
    "Vendor may terminate this Agreement upon a material breach by Customer.",
  ])("stays silent on a bilateral / for-cause-only right: %s", (conv) => {
    expect(fires(conv)).toBe(false);
  });
  // v1.2.0 — the gate is written with the adverb on either side of the verb,
  // and only one order was read. A cloud services agreement whose provider
  // could walk at any time while the customer needed cause produced no finding
  // at all: "Customer may terminate only for …" rather than "may only
  // terminate for …".
  it("reads the cure gate written 'may terminate only for'", () => {
    const f = TERM_009.check(
      buildContext([
        "Termination",
        "Provider may terminate this Agreement at any time upon thirty (30) days notice.",
        "Customer may terminate only for Provider's uncured material breach.",
      ]),
    );
    expect(f?.title).toMatch(/asymmetric/i);
  });

  it("stays silent where the counterparty's cause right is not confined", () => {
    expect(
      TERM_009.check(
        buildContext([
          "Termination",
          "Provider may terminate this Agreement at any time upon thirty (30) days notice.",
          "Customer may terminate for Provider's uncured material breach or for convenience on like notice.",
        ]),
      ),
    ).toBeNull();
  });
});
