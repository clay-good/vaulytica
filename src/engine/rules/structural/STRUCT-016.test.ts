import { describe, expect, it } from "vitest";
import { rule as STRUCT_016 } from "./STRUCT-016.js";
import { buildContext } from "../../_test-fixtures.js";

describe("STRUCT-016 — incorporation by reference to external / unattached document", () => {
  it("fires on AUP incorporation by URL", () => {
    const ctx = buildContext([
      "14.10 Acceptable Use",
      "Customer's use of the Service shall be subject to Vendor's Acceptable Use Policy available at https://vendor.example.com/aup, which is incorporated herein by reference.",
    ]);
    const f = STRUCT_016.check(ctx);
    expect(f).not.toBeNull();
    expect(f?.title).toMatch(/URL/i);
  });

  it("fires when an Exhibit referenced in the body is missing", () => {
    const ctx = buildContext([
      "9.3 Service Levels",
      "The service level commitments and remedies are as set forth in Exhibit B.",
    ]);
    const f = STRUCT_016.check(ctx);
    expect(f).not.toBeNull();
    expect(f?.title).toMatch(/Exhibit B/i);
  });

  it("fires when the referenced Exhibit exists but is empty", () => {
    const ctx = buildContext(
      ["Body", "The remedies are as set forth in Exhibit B."],
      ["Exhibit B — Service Levels", "[To be agreed]"],
    );
    expect(STRUCT_016.check(ctx)).not.toBeNull();
  });

  it("silent when the referenced Exhibit is present and substantive", () => {
    const ctx = buildContext(
      ["Body", "The remedies are as set forth in Exhibit A."],
      [
        "Exhibit A — Remedies",
        "If the Service fails to meet 99.5% uptime in any calendar month, Customer shall be entitled to a service credit equal to 10% of the monthly fee, applied to the next invoice.",
      ],
    );
    expect(STRUCT_016.check(ctx)).toBeNull();
  });

  it("silent on a contract that incorporates nothing external", () => {
    const ctx = buildContext(["Body", "Provider shall provide the Services."]);
    expect(STRUCT_016.check(ctx)).toBeNull();
  });
});
