import { describe, expect, it } from "vitest";

import { MSA_DEEP_RULES } from "./rules.js";
import { buildContext } from "../../../_test-fixtures.js";

const MSA_001 = MSA_DEEP_RULES.find((r) => r.id === "MSA-001")!;

describe("MSA-001 — an IP indemnity that states the claim before the promise", () => {
  // In a DOCX the "Indemnification." line is a section heading, so only the
  // clause beneath it can satisfy the rule.
  it("finds the indemnity under a heading", () => {
    const clause =
      "Provider shall defend Customer and its officers, directors, and employees against any third-party claim alleging that a deliverable infringes or misappropriates that third party's intellectual property rights, and shall indemnify Customer for damages finally awarded.";
    expect(MSA_001.check(buildContext(["8.1 By Provider.", clause]))).toBeNull();
  });

  it("still reports an MSA with no IP indemnity", () => {
    const clause =
      "Provider shall defend Customer against any third-party claim alleging bodily injury caused by Provider personnel.";
    expect(MSA_001.check(buildContext(["8.1 By Provider.", clause]))?.title).toMatch(
      /IP infringement indemnity missing/,
    );
  });
});
