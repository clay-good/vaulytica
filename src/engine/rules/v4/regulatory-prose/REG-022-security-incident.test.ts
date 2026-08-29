import { describe, expect, it } from "vitest";
import { V4_RULES } from "../index.js";
import { buildContext } from "../../../_test-fixtures.js";
import type { Rule } from "../../../finding.js";

const REG022 = V4_RULES.find((r) => r.id === "REG-022") as Rule;

/**
 * "Security incident" is the dominant term — it is what the SEC's own Form 8-K
 * Item 1.05 and every incident-response plan call the event — and a filer
 * whose risk factor is headed "Risks Related to Data Privacy and Security" was
 * reported as having no cybersecurity risk factor at all.
 */
describe("REG-022 — the words a filer actually writes", () => {
  for (const clause of [
    "A security incident affecting our platform would harm our reputation and expose us to liability.",
    "A successful attack could result in unauthorized access to customer data, litigation, and regulatory investigations.",
    "We have experienced attempted cyber attacks in the past and expect to experience them in the future.",
  ]) {
    it(`recognizes: ${clause.slice(0, 46)}`, () => {
      expect(REG022.check(buildContext(["Item 1A. Risk Factors", clause]))).toBeNull();
    });
  }

  it("still fires on risk factors that never mention security", () => {
    expect(
      REG022.check(
        buildContext([
          "Item 1A. Risk Factors",
          "We have a history of losses and may not achieve or sustain profitability. Our sales cycle is long and unpredictable.",
        ]),
      ),
    ).not.toBeNull();
  });
});
