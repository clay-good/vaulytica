import { describe, expect, it } from "vitest";
import type { ExecutionLogEntry } from "../engine/finding.js";
import type { ConsistencyExecutionLogEntry } from "../engine/consistency/types.js";
import {
  describeConsistencyLogEntry,
  describeExecutionLogEntry,
  erroredRuleNotice,
} from "./execution-log.js";

const entry = (over: Partial<ExecutionLogEntry> = {}): ExecutionLogEntry => ({
  rule_id: "FIN-001",
  rule_version: "1",
  ran: true,
  fired: false,
  elapsed_ms: 1,
  ...over,
});

describe("what one line of the audit trail says", () => {
  it("distinguishes a rule that CRASHED from one that found nothing", () => {
    // The whole point. "silent" is what the report means by "screened, and
    // clean", and a crashing rule rendered as "silent" told a lawyer their
    // document had passed a check that never ran.
    expect(describeExecutionLogEntry(entry())).toBe("silent");
    expect(describeExecutionLogEntry(entry({ errored: true }))).toBe("errored");
  });

  it("keeps the three outcomes it already distinguished", () => {
    expect(describeExecutionLogEntry(entry({ ran: false }))).toBe("skipped");
    expect(describeExecutionLogEntry(entry({ fired: true }))).toBe("fired");
    // A rule that never ran cannot have errored, and `ran` wins if both are set.
    expect(describeExecutionLogEntry(entry({ ran: false, errored: true }))).toBe("skipped");
  });

  it("reports an error ahead of a finding, not behind it", () => {
    // `errored` is checked before `fired` so a rule that threw after pushing a
    // finding cannot be reported as a clean hit.
    expect(describeExecutionLogEntry(entry({ fired: true, errored: true }))).toBe("errored");
  });
});

describe("the roll-up above the list", () => {
  it("says nothing at all when nothing errored", () => {
    // Gated on presence: this is what keeps every existing golden byte-identical.
    expect(erroredRuleNotice([entry(), entry({ fired: true })])).toBeUndefined();
    expect(erroredRuleNotice([])).toBeUndefined();
  });

  it("names the rules and says the document was not checked against them", () => {
    const notice = erroredRuleNotice([
      entry(),
      entry({ rule_id: "RISK-002", errored: true }),
      entry({ rule_id: "TERM-009", errored: true }),
    ]);
    expect(notice).toContain("2 rules could not be evaluated");
    expect(notice).toContain("RISK-002, TERM-009");
    expect(notice).toContain("NOT checked");
    expect(notice).toContain("unreviewed");
  });

  it("reads as one rule in the singular", () => {
    const notice = erroredRuleNotice([entry({ rule_id: "FIN-005", errored: true })]);
    expect(notice).toContain("1 rule could not be evaluated because it ended in an error");
  });
});

describe("the cross-document pass's own line", () => {
  const cEntry = (over: Partial<ConsistencyExecutionLogEntry> = {}): ConsistencyExecutionLogEntry =>
    ({
      rule_id: "CROSS-001",
      rule_version: "1",
      ran: true,
      findings_count: 0,
      elapsed_ms: 1,
      ...over,
    }) as ConsistencyExecutionLogEntry;

  it("had the same defect a third time", () => {
    expect(describeConsistencyLogEntry(cEntry(), "0 findings")).toBe("ran, 0 findings");
    expect(describeConsistencyLogEntry(cEntry({ errored: true }), "0 findings")).toBe("errored");
    expect(describeConsistencyLogEntry(cEntry({ ran: false }), "0 findings")).toBe(
      "skipped (requires not satisfied)",
    );
  });
});
