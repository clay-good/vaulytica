import { describe, expect, it } from "vitest";
import { rule as IPDATA_010 } from "./IPDATA-010.js";
import { buildContext } from "../../_test-fixtures.js";

describe("IPDATA-010 — perpetual / irrevocable license overreach", () => {
  it("fires on a sublicensable, perpetual, irrevocable, royalty-free feedback license", () => {
    const ctx = buildContext([
      "6.4 Feedback",
      "Customer hereby grants Vendor a perpetual, irrevocable, worldwide, royalty-free, sublicensable, transferable license to use any Feedback for any purpose.",
    ]);
    expect(IPDATA_010.check(ctx)).not.toBeNull();
  });

  it("fires on user-generated-content license overreach", () => {
    const ctx = buildContext([
      "Submissions",
      "By submitting any User Content, you grant us a worldwide, perpetual, irrevocable, royalty-free, sublicensable, transferable license to use, reproduce, and distribute such content.",
    ]);
    expect(IPDATA_010.check(ctx)).not.toBeNull();
  });

  it("silent on a narrow non-transferable Feedback license", () => {
    const ctx = buildContext([
      "Feedback",
      "Customer grants Vendor a non-exclusive, non-transferable license to use Feedback for the limited purpose of improving the Service, terminating on termination of this Agreement.",
    ]);
    expect(IPDATA_010.check(ctx)).toBeNull();
  });

  it("silent on the ordinary Vendor → Customer Service license (no counterparty subject)", () => {
    const ctx = buildContext([
      "License",
      "Subject to this Agreement, Vendor grants Customer a perpetual, irrevocable, worldwide, royalty-free, non-exclusive license to use the Service for internal business purposes.",
    ]);
    // No Feedback / Customer Data / User Content subject mentioned, so
    // the rule does not fire — this is the normal SaaS subscription
    // license to use the vendor's product.
    expect(IPDATA_010.check(ctx)).toBeNull();
  });

  it("reads the lowercase consumer-ToS 'your content / data / photos' subject (v1.1.0)", () => {
    for (const clause of [
      "You hereby grant us a perpetual, irrevocable, royalty-free license to use your content.",
      "You grant Provider a perpetual, irrevocable, sublicensable license to your data.",
      "You grant us a worldwide, perpetual, irrevocable license to your photos and videos.",
    ]) {
      expect(IPDATA_010.check(buildContext(["License", clause])), clause).not.toBeNull();
    }
  });

  it("silent on an ordinary 'worldwide license to process your data' (below the 3-modifier gate)", () => {
    expect(
      IPDATA_010.check(
        buildContext([
          "Data",
          "You grant us a worldwide license to process your data to provide the Services.",
        ]),
      ),
    ).toBeNull();
  });

  // Only the FIRST grant in the document was examined, and the whole clause
  // was matched from the grant word — four hundred characters of it, which
  // swallowed the operative grant behind the run-in heading that announces
  // it. A EULA's broad Feedback license went unreported because a narrow
  // grant preceded it, and a media release lost its finding entirely as soon
  // as its blank lines went and "1. Grant of Rights." ran into the sentence.
  it("reads a broad grant that a NARROW one precedes (v1.2.0)", () => {
    const ctx = buildContext([
      "Terms",
      "Customer grants Vendor a non-exclusive, non-transferable, revocable license to use the Marks during the Term.",
      "Customer grants Vendor a perpetual, irrevocable, royalty-free license to use Feedback without obligation.",
    ]);
    expect(IPDATA_010.check(ctx)).not.toBeNull();
  });

  it("reads a grant behind a run-in heading (v1.2.0)", () => {
    const ctx = buildContext([
      "Release",
      "1. Grant of Rights. I grant Riverbend the irrevocable, perpetual, worldwide, royalty-free right to use my name, likeness, image, and voice.",
    ]);
    expect(IPDATA_010.check(ctx)).not.toBeNull();
  });
});
