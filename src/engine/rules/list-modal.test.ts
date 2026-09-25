/**
 * `distributeListModal` — a lettered list under one modal states the modal of
 * every item. Every presence builder (v3 regulated, v4, v5) reads this form as
 * well as the text as written.
 */
import { describe, expect, it } from "vitest";
import { distributeListModal } from "./_helpers.js";

describe("distributeListModal", () => {
  it("puts the modal before each lettered item", () => {
    expect(
      distributeListModal(
        "Service Provider shall not (a) Sell or Share the data; (b) retain it; or (c) combine it.",
      ),
    ).toBe(
      "Service Provider shall not Sell or Share the data; shall not retain it; or shall not combine it.",
    );
  });

  it("reads roman and numeric lists, and a colon after the modal", () => {
    expect(distributeListModal("Tenant must: (i) pay rent; (ii) keep the Premises clean.")).toBe(
      "Tenant must pay rent; must keep the Premises clean.",
    );
    expect(distributeListModal("Buyer will (1) inspect; (2) accept.")).toBe(
      "Buyer will inspect; will accept.",
    );
  });

  it("leaves a list that no modal introduces alone", () => {
    const text = "The Services include (a) hosting; (b) support.";
    expect(distributeListModal(text)).toBe(text);
  });
});
