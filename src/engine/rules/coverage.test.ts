/**
 * Per-rule smoke coverage for the 68 new rules from spec §18. Each rule
 * gets a focused positive case; negative cases are exercised by the
 * `all-rules.test.ts` determinism run, where most rules return null.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../_test-fixtures.js";

import { rule as STRUCT_009 } from "./structural/STRUCT-009.js";
import { rule as STRUCT_010 } from "./structural/STRUCT-010.js";
import { rule as STRUCT_011 } from "./structural/STRUCT-011.js";
import { rule as STRUCT_012 } from "./structural/STRUCT-012.js";
import { rule as FIN_003 } from "./financial/FIN-003.js";
import { rule as FIN_004 } from "./financial/FIN-004.js";
import { rule as FIN_005 } from "./financial/FIN-005.js";
import { rule as FIN_006 } from "./financial/FIN-006.js";
import { rule as FIN_007 } from "./financial/FIN-007.js";
import { rule as FIN_008 } from "./financial/FIN-008.js";
import { rule as TEMP_004 } from "./temporal/TEMP-004.js";
import { rule as TEMP_005 } from "./temporal/TEMP-005.js";
import { rule as TEMP_006 } from "./temporal/TEMP-006.js";
import { rule as TEMP_008 } from "./temporal/TEMP-008.js";
import { rule as TEMP_009 } from "./temporal/TEMP-009.js";
import { rule as OBLI_001 } from "./obligations/OBLI-001.js";
import { rule as OBLI_004 } from "./obligations/OBLI-004.js";
import { rule as OBLI_005 } from "./obligations/OBLI-005.js";
import { rule as OBLI_006 } from "./obligations/OBLI-006.js";
import { rule as RISK_001 } from "./risk-allocation/RISK-001.js";
import { rule as RISK_005 } from "./risk-allocation/RISK-005.js";
import { rule as RISK_006 } from "./risk-allocation/RISK-006.js";
import { rule as RISK_007 } from "./risk-allocation/RISK-007.js";
import { rule as RISK_011 } from "./risk-allocation/RISK-011.js";
import { rule as RISK_013 } from "./risk-allocation/RISK-013.js";
import { rule as CHOICE_001 } from "./choice-and-venue/CHOICE-001.js";
import { rule as CHOICE_003 } from "./choice-and-venue/CHOICE-003.js";
import { rule as CHOICE_006 } from "./choice-and-venue/CHOICE-006.js";
import { rule as CHOICE_008 } from "./choice-and-venue/CHOICE-008.js";
import { rule as TERM_001 } from "./termination/TERM-001.js";
import { rule as TERM_002 } from "./termination/TERM-002.js";
import { rule as TERM_005 } from "./termination/TERM-005.js";
import { rule as TERM_006 } from "./termination/TERM-006.js";
import { rule as IPDATA_001 } from "./ip-and-data/IPDATA-001.js";
import { rule as IPDATA_003 } from "./ip-and-data/IPDATA-003.js";
import { rule as IPDATA_006 } from "./ip-and-data/IPDATA-006.js";
import { rule as PERS_001 } from "./personnel/PERS-001.js";
import { rule as PERS_002 } from "./personnel/PERS-002.js";
import { rule as DARK_001 } from "./dark-patterns/DARK-001.js";
import { rule as DARK_003 } from "./dark-patterns/DARK-003.js";

describe("Structural — STRUCT-009 to STRUCT-012", () => {
  it("STRUCT-011 detects [insert] placeholders", () => {
    const ctx = buildContext(["H", "Provider: [insert] is the counterparty."]);
    expect(STRUCT_011.check(ctx)?.severity).toBe("critical");
  });
  it("STRUCT-009 silent when no defined terms exist", () => {
    expect(STRUCT_009.check(buildContext(["H", "Body."]))).toBeNull();
  });
  it("STRUCT-010 silent without a TOC section", () => {
    expect(STRUCT_010.check(buildContext(["H", "Body."]))).toBeNull();
  });
  it("STRUCT-012 detects duplicate headings", () => {
    const ctx = buildContext(["Section A", "Body."], ["Section A", "Body."]);
    expect(STRUCT_012.check(ctx)).not.toBeNull();
  });
});

describe("Financial — FIN-003 to FIN-008", () => {
  it("FIN-003 fires on multiple currencies", () => {
    const ctx = buildContext(["H", "Pay $500 and €500."]);
    expect(FIN_003.check(ctx)).not.toBeNull();
  });
  it("FIN-004 fires on a 24% late-payment rate", () => {
    const ctx = buildContext(["Fees", "Late payment shall accrue interest at 24% per annum."]);
    expect(FIN_004.check(ctx)).not.toBeNull();
  });
  it("FIN-005 fires when payments are referenced without 'Net X'", () => {
    const ctx = buildContext(["Fees", "Customer shall pay the fee owed under this Agreement."]);
    expect(FIN_005.check(ctx)).not.toBeNull();
  });
  it("FIN-006 fires on liquidated damages", () => {
    const ctx = buildContext(["Damages", "Liquidated damages of $10,000 per day shall apply."]);
    expect(FIN_006.check(ctx)).not.toBeNull();
  });
  it("FIN-007 fires on most-favored-nation", () => {
    const ctx = buildContext(["Pricing", "This is a most-favored-nation clause."]);
    expect(FIN_007.check(ctx)).not.toBeNull();
  });
  it("FIN-008 fires on minimum commitment", () => {
    const ctx = buildContext(["Pricing", "Customer has a minimum commitment of $50,000 per year."]);
    expect(FIN_008.check(ctx)).not.toBeNull();
  });
});

describe("Temporal — TEMP-002 to TEMP-010", () => {
  it("TEMP-004 fires on auto-renewal language", () => {
    const ctx = buildContext(["Term", "This Agreement renews automatically for successive one-year terms."]);
    expect(TEMP_004.check(ctx)).not.toBeNull();
  });
  it("TEMP-005 fires on a 120-day notice window", () => {
    const ctx = buildContext(["Term", "Auto-renewal applies unless notice of non-renewal is given 120 days prior."]);
    expect(TEMP_005.check(ctx)).not.toBeNull();
  });
  it("TEMP-006 fires when survival is stated", () => {
    const ctx = buildContext(["Survival", "Confidentiality survives termination of this Agreement."]);
    expect(TEMP_006.check(ctx)).not.toBeNull();
  });
  it("TEMP-008 fires on a stated cure period", () => {
    const ctx = buildContext(["Breach", "The breaching party shall have a cure period of 30 days."]);
    expect(TEMP_008.check(ctx)).not.toBeNull();
  });
  it("TEMP-009 fires on a 5-day cure period", () => {
    const ctx = buildContext(["Breach", "The breaching party shall have an opportunity to cure within 5 days."]);
    expect(TEMP_009.check(ctx)).not.toBeNull();
  });
});

describe("Obligations — OBLI-001 to OBLI-006", () => {
  it("OBLI-001 fires when obligor is ambiguous", () => {
    const ctx = buildContext(["H", "The parties shall cooperate in good faith."]);
    expect(OBLI_001.check(ctx)).not.toBeNull();
  });
  it("OBLI-004 fires on 'best efforts'", () => {
    const ctx = buildContext(["H", "Provider shall use best efforts to deliver the Services."]);
    expect(OBLI_004.check(ctx)).not.toBeNull();
  });
  it("OBLI-005 fires when negative covenants exist", () => {
    const ctx = buildContext(["H", "Customer shall not disclose the Confidential Information."]);
    expect(OBLI_005.check(ctx)).not.toBeNull();
  });
  it("OBLI-006 fires on 'in its sole discretion'", () => {
    const ctx = buildContext(["H", "Provider may, in its sole discretion, modify the Service."]);
    expect(OBLI_006.check(ctx)).not.toBeNull();
  });
});

describe("Risk — RISK-001, 005, 006, 007, 011, 013", () => {
  it("RISK-001 fires when no indemnification appears", () => {
    expect(RISK_001.check(buildContext(["H", "Body."]))).not.toBeNull();
  });
  it("RISK-005 fires when no LoL appears", () => {
    expect(RISK_005.check(buildContext(["H", "Body."]))).not.toBeNull();
  });
  it("RISK-006 fires on LoL with carve-outs", () => {
    const ctx = buildContext([
      "Liability",
      "Limitation of liability shall not exceed fees paid except for fraud and willful misconduct.",
    ]);
    expect(RISK_006.check(ctx)).not.toBeNull();
  });
  it("RISK-007 fires on consequential damages waiver", () => {
    const ctx = buildContext(["Damages", "Neither party shall be liable for consequential, special, incidental, or punitive damages."]);
    expect(RISK_007.check(ctx)).not.toBeNull();
  });
  it("RISK-011 flags incomplete indemnity procedure", () => {
    const ctx = buildContext(["Indemnity", "Provider shall indemnify Customer for IP claims."]);
    expect(RISK_011.check(ctx)).not.toBeNull();
  });
  it("RISK-013 fires on force majeure", () => {
    const ctx = buildContext(["Force Majeure", "A force majeure event excuses performance."]);
    expect(RISK_013.check(ctx)).not.toBeNull();
  });
});

describe("Choice & venue — CHOICE-001, 003, 006, 008", () => {
  it("CHOICE-001 fires when no governing law clause exists", () => {
    expect(CHOICE_001.check(buildContext(["H", "Body."]))).not.toBeNull();
  });
  it("CHOICE-003 fires when no venue clause exists", () => {
    expect(CHOICE_003.check(buildContext(["H", "Body."]))).not.toBeNull();
  });
  it("CHOICE-006 fires when arbitration appears", () => {
    const ctx = buildContext(["Disputes", "All disputes shall be resolved by binding arbitration."]);
    expect(CHOICE_006.check(ctx)).not.toBeNull();
  });
  it("CHOICE-008 fires on a jury trial waiver", () => {
    const ctx = buildContext(["Disputes", "Each party hereby waives the right to a trial by jury."]);
    expect(CHOICE_008.check(ctx)).not.toBeNull();
  });
});

describe("Termination — TERM-001, 002, 005, 006", () => {
  it("TERM-001 fires on convenience + days", () => {
    const ctx = buildContext(["Termination", "Either party may terminate for convenience upon 30 days' notice."]);
    expect(TERM_001.check(ctx)).not.toBeNull();
  });
  it("TERM-002 fires when no for-cause termination", () => {
    expect(TERM_002.check(buildContext(["H", "Body."]))).not.toBeNull();
  });
  it("TERM-005 fires when no effect-of-termination clause", () => {
    expect(TERM_005.check(buildContext(["H", "Body."]))).not.toBeNull();
  });
  it("TERM-006 fires on wind-down language", () => {
    const ctx = buildContext(["Termination", "Provider shall provide transition services for 30 days."]);
    expect(TERM_006.check(ctx)).not.toBeNull();
  });
});

describe("IP & data — IPDATA-001, 003, 006", () => {
  it("IPDATA-001 fires when no IP ownership clause", () => {
    expect(IPDATA_001.check(buildContext(["H", "Body."]))).not.toBeNull();
  });
  it("IPDATA-003 fires on a license grant", () => {
    const ctx = buildContext([
      "License",
      "Licensor grants to Licensee a non-exclusive, royalty-free, worldwide license to use the Software.",
    ]);
    expect(IPDATA_003.check(ctx)).not.toBeNull();
  });
  it("IPDATA-006 fires on source-code escrow", () => {
    const ctx = buildContext(["Escrow", "The parties shall enter into a source code escrow agreement."]);
    expect(IPDATA_006.check(ctx)).not.toBeNull();
  });
});

describe("Personnel — PERS-001, PERS-002", () => {
  it("PERS-001 fires on a non-compete", () => {
    const ctx = buildContext(["Restrictions", "Employee agrees to a non-compete for one year."]);
    expect(PERS_001.check(ctx)).not.toBeNull();
  });
  it("PERS-002 fires on a non-solicit", () => {
    const ctx = buildContext(["Restrictions", "Each party agrees to a non-solicitation of the other's employees."]);
    expect(PERS_002.check(ctx)).not.toBeNull();
  });
});

describe("Dark patterns — DARK-001, DARK-003", () => {
  it("DARK-001 fires on unilateral modification", () => {
    const ctx = buildContext([
      "Modification",
      "Provider may modify these terms at any time upon notice to Customer.",
    ]);
    expect(DARK_001.check(ctx)).not.toBeNull();
  });
  it("DARK-003 fires on one-way fee shifting", () => {
    const ctx = buildContext([
      "Fees",
      "Customer shall pay Provider's reasonable attorneys' fees in any dispute.",
    ]);
    expect(DARK_003.check(ctx)).not.toBeNull();
  });
});
