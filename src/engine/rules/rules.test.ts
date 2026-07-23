import { describe, expect, it } from "vitest";
import { buildContext } from "../_test-fixtures.js";

import { rule as STRUCT_001 } from "./structural/STRUCT-001.js";
import { rule as STRUCT_002 } from "./structural/STRUCT-002.js";
import { rule as STRUCT_003 } from "./structural/STRUCT-003.js";
import { rule as STRUCT_004 } from "./structural/STRUCT-004.js";
import { rule as STRUCT_005 } from "./structural/STRUCT-005.js";
import { rule as STRUCT_006 } from "./structural/STRUCT-006.js";
import { rule as STRUCT_007 } from "./structural/STRUCT-007.js";
import { rule as STRUCT_008 } from "./structural/STRUCT-008.js";
import { rule as FIN_001 } from "./financial/FIN-001.js";
import { rule as FIN_002 } from "./financial/FIN-002.js";
import { rule as TEMP_001 } from "./temporal/TEMP-001.js";
import { rule as RISK_009 } from "./risk-allocation/RISK-009.js";

describe("STRUCT-001 — party identification", () => {
  it("fires when no parties are present", () => {
    const ctx = buildContext(["Untitled", "Body without preamble."]);
    expect(STRUCT_001.check(ctx)?.severity).toBe("warning");
  });
  it("silent when preamble names parties", () => {
    const ctx = buildContext([
      "H",
      'This Agreement is between Acme Corp., a Delaware corporation ("Provider"), and Globex Industries, Inc., a New York corporation ("Customer").',
    ]);
    expect(STRUCT_001.check(ctx)).toBeNull();
  });
});

describe("STRUCT-002 — effective date present", () => {
  it("fires when no effective date is present", () => {
    const ctx = buildContext(["H", "Some unrelated body text."]);
    expect(STRUCT_002.check(ctx)).not.toBeNull();
  });
  it("silent when an Effective Date anchor is used", () => {
    const ctx = buildContext(["H", "Effective on the Effective Date as defined in Schedule A."]);
    expect(STRUCT_002.check(ctx)).toBeNull();
  });
});

describe("STRUCT-003 — signature block present", () => {
  it("fires when the document has no signature block", () => {
    const ctx = buildContext(["H", "Some body text."]);
    expect(STRUCT_003.check(ctx)?.severity).toBe("critical");
  });
  it("silent when a By/Name/Title/Date block appears at the end", () => {
    const ctx = buildContext([
      "H",
      "Body paragraph.",
      "By: ____ Name: Jane Doe Title: CEO Date: 2025-01-01",
    ]);
    expect(STRUCT_003.check(ctx)).toBeNull();
  });
});

describe("STRUCT-004 — defined terms identifiable", () => {
  it("fires when no definitions exist and no heading is found", () => {
    const ctx = buildContext(["H", "Body."]);
    expect(STRUCT_004.check(ctx)).not.toBeNull();
  });
  it("silent when an inline definition is present", () => {
    const ctx = buildContext([
      "H",
      '"Confidential Information" means any non-public data. Body references Confidential Information later.',
    ]);
    expect(STRUCT_004.check(ctx)).toBeNull();
  });
});

describe("STRUCT-005 — defined-but-never-used", () => {
  it("fires when a defined term is never used", () => {
    const ctx = buildContext(["Definitions", '"Unused Term" means a thing not referenced again.']);
    expect(STRUCT_005.check(ctx)).not.toBeNull();
  });
});

describe("STRUCT-006 — used-but-never-defined", () => {
  it("fires when capitalized phrases appear undefined", () => {
    const ctx = buildContext([
      "H",
      "The Special Reserve Fund applies. The Special Reserve Fund applies again.",
    ]);
    expect(STRUCT_006.check(ctx)).not.toBeNull();
  });
});

describe("STRUCT-007 — cross-reference resolution", () => {
  it("fires on a phantom Section reference", () => {
    const ctx = buildContext(["1. Body", "Cross to Section 99.4 which does not exist."]);
    expect(STRUCT_007.check(ctx)).not.toBeNull();
  });
});

describe("STRUCT-008 — numbering integrity", () => {
  it("fires on duplicate / skipped / out-of-order numbers", () => {
    const ctx = buildContext(["1. First", "Body."], ["3. Third (skipped 2)", "Body."]);
    expect(STRUCT_008.check(ctx)).not.toBeNull();
  });
  it("silent on a clean 1, 2, 3 sequence", () => {
    const ctx = buildContext(["1. First", "Body."], ["2. Second", "Body."], ["3. Third", "Body."]);
    expect(STRUCT_008.check(ctx)).toBeNull();
  });
});

describe("FIN-001 — word-numeral mismatch", () => {
  it("fires when the word and numeral disagree", () => {
    const ctx = buildContext(["Fees", "The fee is one million dollars ($1,500,000)."]);
    const finding = FIN_001.check(ctx);
    expect(finding?.severity).toBe("critical");
  });
  it("silent when the word and numeral agree", () => {
    const ctx = buildContext(["Fees", "The fee is one million dollars ($1,000,000)."]);
    expect(FIN_001.check(ctx)).toBeNull();
  });
});

describe("FIN-002 — inconsistent named amounts", () => {
  it("fires when a named amount has two values", () => {
    const ctx = buildContext([
      "Fees",
      "the Cap of $1,000,000 applies generally. However, the Cap of $2,000,000 applies for indemnities.",
    ]);
    expect(FIN_002.check(ctx)).not.toBeNull();
  });
  it("silent when the named amount is consistent", () => {
    const ctx = buildContext([
      "Fees",
      "the Cap of $1,000,000 applies generally. The Cap of $1,000,000 also applies for indemnities.",
    ]);
    expect(FIN_002.check(ctx)).toBeNull();
  });
});

describe("TEMP-001 — impossible date", () => {
  it("fires on Feb 30", () => {
    const ctx = buildContext(["H", "On 2025-02-30 the parties shall meet."]);
    expect(TEMP_001.check(ctx)?.severity).toBe("critical");
  });
  it("silent on a real date", () => {
    const ctx = buildContext(["H", "On 2025-02-15 the parties shall meet."]);
    expect(TEMP_001.check(ctx)).toBeNull();
  });
});

describe("RISK-009 — uncapped liability", () => {
  it("fires when 'unlimited liability' appears", () => {
    const ctx = buildContext([
      "Liability",
      "Provider has unlimited liability under this Agreement.",
    ]);
    expect(RISK_009.check(ctx)?.severity).toBe("critical");
  });
  it("silent when liability is capped", () => {
    const ctx = buildContext([
      "Liability",
      "Provider's aggregate liability shall not exceed the fees paid in the preceding 12 months.",
    ]);
    expect(RISK_009.check(ctx)).toBeNull();
  });
});

describe("STRUCT-006 — party-name prefixes (v1.1.0)", () => {
  it("does not call a party's shortened name an undefined term", () => {
    // TITLE_CASE_PHRASE cannot include the all-caps suffix, so the candidate
    // "Halewood Media" is the party "Halewood Media LLC", not a new term.
    const ctx = buildContext([
      "Preamble",
      'This Agreement is entered into by and between Halewood Media LLC, a New York limited liability company ("Company"), and Priya Raman, an individual ("Contractor").',
      "Halewood Media handles scheduling. Halewood Media provides the equipment.",
    ]);
    expect(STRUCT_006.check(ctx)).toBeNull();
  });
});

describe("STRUCT-007 — attachment references are not section references (v1.1.0)", () => {
  it("does not report a referenced attachment as an unresolved section", () => {
    // Attachment refs never resolve by design (the outline models sections
    // only); their presence or absence is STRUCT-016/018's finding.
    const ctx = buildContext([
      "2. Scope",
      "Vendor shall configure the forms listed in Attachment 1 and meet the criteria in Attachment 2.",
    ]);
    expect(STRUCT_007.check(ctx)).toBeNull();
  });

  it("still fires on a phantom Section reference alongside attachment refs", () => {
    const ctx = buildContext([
      "2. Scope",
      "The forms listed in Attachment 1 shall meet the standards of Section 44.",
    ]);
    expect(STRUCT_007.check(ctx)?.description).toContain("Section 44");
  });
});
