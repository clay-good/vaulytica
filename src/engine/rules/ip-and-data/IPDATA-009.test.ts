import { describe, expect, it } from "vitest";
import { rule as IPDATA_009 } from "./IPDATA-009.js";
import { buildContext } from "../../_test-fixtures.js";

describe("IPDATA-009 — AI / model-training rights over Customer Data", () => {
  it("fires on a license to use Customer Data to train models", () => {
    const ctx = buildContext([
      "Data License",
      "Customer grants Vendor a perpetual license to use Customer Data to train Vendor's machine-learning models and to develop new AI features.",
    ]);
    const f = IPDATA_009.check(ctx);
    expect(f?.severity).toBe("critical");
    expect(f?.title).toMatch(/training/i);
  });

  it("fires on `use Customer Data ... to improve our models`", () => {
    const ctx = buildContext([
      "Data Use",
      "Vendor may use Customer Data and your content to train and improve our models on an ongoing basis.",
    ]);
    expect(IPDATA_009.check(ctx)).not.toBeNull();
  });

  it("is silent on a plain DPA without training language", () => {
    const ctx = buildContext([
      "Data Processing",
      "Vendor shall process Customer Data solely on Customer's instructions and for the purpose of providing the Service.",
    ]);
    expect(IPDATA_009.check(ctx)).toBeNull();
  });
});
