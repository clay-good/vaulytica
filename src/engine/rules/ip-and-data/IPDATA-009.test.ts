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

  // v1.1.0 — the standard privacy-protective commitment ("we NEVER train on
  // your data", "AT NO TIME will we …") is the opposite of the training grant;
  // flagging it critical is the worst false positive this rule can make. The
  // prior guard covered only "<modal> not".
  it("is silent on a 'we never use Customer Data to train' commitment", () => {
    expect(
      IPDATA_009.check(
        buildContext(["Data and AI", "We never use Customer Data to train our models."]),
      ),
    ).toBeNull();
  });

  it("is silent on an 'at no time will we …' commitment", () => {
    expect(
      IPDATA_009.check(
        buildContext([
          "Data and AI",
          "At no time will we use your data to train or develop our machine-learning models.",
        ]),
      ),
    ).toBeNull();
  });

  it("is silent on an 'under no circumstances' commitment", () => {
    expect(
      IPDATA_009.check(
        buildContext([
          "Data and AI",
          "Under no circumstances will we use Customer Data to train our AI models.",
        ]),
      ),
    ).toBeNull();
  });

  it("still fires when a 'will not sell' promise sits beside a real training grant", () => {
    // The unrelated "will not sell" negation must not suppress a genuine grant.
    expect(
      IPDATA_009.check(
        buildContext([
          "Data and AI",
          "Although we will not sell your data, we use Customer Data to train our models.",
        ]),
      ),
    ).not.toBeNull();
  });
});
