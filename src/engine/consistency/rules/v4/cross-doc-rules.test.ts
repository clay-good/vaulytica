/**
 * v4 cross-document rule tests (spec-v4.md §10, Step 43).
 *
 * Covers the seven CROSS-* rule families: PARTY, JURIS, DEFTERM, DATE,
 * AMOUNT, MISSING, PRECEDENCE. Each rule gets a positive case + a
 * negative case + (where relevant) a determinism check. The registry
 * contract + the aggregate `ALL_CONSISTENCY_RULES` size are also
 * locked in.
 */

import { describe, expect, it } from "vitest";

import { runConsistency } from "../../runner.js";
import {
  V4_CROSS_RULES,
  CROSS_PARTY_001,
  CROSS_JURIS_001,
  CROSS_DEFTERM_001,
  CROSS_DATE_001,
  CROSS_AMOUNT_001,
  CROSS_MISSING_001,
  CROSS_PRECEDENCE_001,
  CROSS_DEFTERM_002,
  CROSS_INDEMNITY_001,
  CROSS_SURVIVAL_001,
  CROSS_TERM_001,
  CROSS_CARVEOUT_001,
  CROSS_CURRENCY_001,
} from "./index.js";
import { ALL_CONSISTENCY_RULES, CONSISTENCY_RULES } from "../index.js";
import type { ConsistencyDocument } from "../../types.js";
import { buildContext } from "../../../_test-fixtures.js";

function makeDoc(
  doc_id: string,
  playbook_id: string,
  ...sections: [string, ...string[]][]
): ConsistencyDocument {
  const ctx = buildContext(...sections);
  return {
    doc_id,
    source_file_name: `${doc_id}.docx`,
    playbook_id,
    tree: ctx.tree,
    extracted: ctx.extracted,
  };
}

const STARTER_DKB = (() => buildContext(["x", "y"]).dkb)();

/* ---------------- registry ----------------- */

describe("V4_CROSS_RULES registry", () => {
  it("ships thirteen CROSS-* rules with unique ids", () => {
    expect(V4_CROSS_RULES).toHaveLength(13);
    const ids = V4_CROSS_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(13);
    for (const id of ids) expect(id).toMatch(/^CROSS-[A-Z]+-\d{3}$/);
  });

  it("ALL_CONSISTENCY_RULES is the v3 CC-NNN set plus the v4 CROSS-* set", () => {
    expect(ALL_CONSISTENCY_RULES.length).toBe(CONSISTENCY_RULES.length + V4_CROSS_RULES.length);
  });
});

/* ---------------- CROSS-PARTY-001 ----------------- */

describe("CROSS-PARTY-001", () => {
  it("fires when the same party appears as 'Acme Corp.' in one doc and 'Acme, Inc.' in another", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep", [
      "Agreement",
      'This Master Services Agreement is between Acme Corp., a Delaware corporation ("Provider"), and Globex Industries, Inc., a New York corporation ("Customer").',
    ]);
    const baa = makeDoc("baa", "baa", [
      "Agreement",
      'This Business Associate Agreement is between Acme, Inc., a Delaware corporation ("Business Associate"), and Globex Industries, Inc., a New York corporation ("Covered Entity").',
    ]);
    const run = await runConsistency({
      rules: [CROSS_PARTY_001],
      documents: [msa, baa],
      dkb: STARTER_DKB,
    });
    expect(run.findings.length).toBeGreaterThanOrEqual(1);
    const f = run.findings[0]!;
    expect(f.rule_id).toBe("CROSS-PARTY-001");
    expect(f.title.toLowerCase()).toMatch(/acme/);
    expect(f.excerpts).toHaveLength(2);
  });

  it("does not fire when both documents use the same party name", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep", [
      "Agreement",
      "This Agreement is between Acme Corp., a Delaware corporation, and Globex Industries, Inc.",
    ]);
    const baa = makeDoc("baa", "baa", [
      "Agreement",
      "This Agreement is between Acme Corp., a Delaware corporation, and Globex Industries, Inc.",
    ]);
    const run = await runConsistency({
      rules: [CROSS_PARTY_001],
      documents: [msa, baa],
      dkb: STARTER_DKB,
    });
    expect(run.findings).toHaveLength(0);
  });
});

/* ---------------- CROSS-JURIS-001 ----------------- */

describe("CROSS-JURIS-001", () => {
  it("fires on a 3-document bundle with two different governing laws", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep", [
      "Governing Law",
      "This Agreement shall be governed by the laws of the State of Delaware.",
    ]);
    const dpa = makeDoc("dpa", "dpa-controller-processor", [
      "Governing Law",
      "This DPA shall be governed by the laws of Ireland.",
    ]);
    const baa = makeDoc("baa", "baa", [
      "Governing Law",
      "This BAA shall be governed by the laws of the State of California.",
    ]);
    const run = await runConsistency({
      rules: [CROSS_JURIS_001],
      documents: [msa, dpa, baa],
      dkb: STARTER_DKB,
    });
    expect(run.findings).toHaveLength(1);
    expect(run.findings[0]!.severity).toBe("warning");
  });

  it("does not fire when a 3-document bundle agrees on one governing law", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep", [
      "Governing Law",
      "This Agreement shall be governed by the laws of the State of Delaware.",
    ]);
    const dpa = makeDoc("dpa", "dpa-controller-processor", [
      "Governing Law",
      "This DPA shall be governed by the laws of the State of Delaware.",
    ]);
    const baa = makeDoc("baa", "baa", [
      "Governing Law",
      "This BAA shall be governed by the laws of the State of Delaware.",
    ]);
    const run = await runConsistency({
      rules: [CROSS_JURIS_001],
      documents: [msa, dpa, baa],
      dkb: STARTER_DKB,
    });
    expect(run.findings).toHaveLength(0);
  });

  it("does not fire on a 2-document bundle (CC-005 covers that)", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep", [
      "Governing Law",
      "This Agreement shall be governed by the laws of the State of Delaware.",
    ]);
    const dpa = makeDoc("dpa", "dpa-controller-processor", [
      "Governing Law",
      "This DPA shall be governed by the laws of Ireland.",
    ]);
    const run = await runConsistency({
      rules: [CROSS_JURIS_001],
      documents: [msa, dpa],
      dkb: STARTER_DKB,
    });
    expect(run.findings).toHaveLength(0);
  });
});

/* ---------------- CROSS-DEFTERM-001 --------------- */

describe("CROSS-DEFTERM-001", () => {
  it("fires when 'Customer Data' is defined differently across docs", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep", [
      "Definitions",
      '"Customer Data" means data that Customer provides to Provider through the Services.',
    ]);
    const dpa = makeDoc("dpa", "dpa-controller-processor", [
      "Definitions",
      '"Customer Data" means any data processed by Provider on behalf of Customer, including derivative analytics.',
    ]);
    const run = await runConsistency({
      rules: [CROSS_DEFTERM_001],
      documents: [msa, dpa],
      dkb: STARTER_DKB,
    });
    expect(run.findings.length).toBeGreaterThanOrEqual(1);
    expect(run.findings[0]!.title).toMatch(/Customer Data/);
  });

  it("does not fire when definitions match", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep", [
      "Definitions",
      '"Customer Data" means data Customer provides to Provider.',
    ]);
    const dpa = makeDoc("dpa", "dpa-controller-processor", [
      "Definitions",
      '"Customer Data" means data Customer provides to Provider.',
    ]);
    const run = await runConsistency({
      rules: [CROSS_DEFTERM_001],
      documents: [msa, dpa],
      dkb: STARTER_DKB,
    });
    expect(run.findings).toHaveLength(0);
  });
});

/* ---------------- CROSS-DATE-001 ----------------- */

describe("CROSS-DATE-001", () => {
  it("fires when MSA dated 2026-01-01 references a BAA dated 2026-06-01", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep", [
      "Agreement",
      "This Master Services Agreement is effective as of January 1, 2026. The Business Associate Agreement is incorporated by reference.",
    ]);
    const baa = makeDoc("baa", "baa", [
      "Agreement",
      "This Business Associate Agreement is effective as of June 1, 2026.",
    ]);
    const run = await runConsistency({
      rules: [CROSS_DATE_001],
      documents: [msa, baa],
      dkb: STARTER_DKB,
    });
    expect(run.findings.length).toBeGreaterThanOrEqual(1);
    expect(run.findings[0]!.title).toMatch(/chronology impossible/);
  });

  it("does not fire when the chronology is sane", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep", [
      "Agreement",
      "This Master Services Agreement is effective as of July 1, 2026. The Business Associate Agreement is incorporated by reference.",
    ]);
    const baa = makeDoc("baa", "baa", [
      "Agreement",
      "This Business Associate Agreement is effective as of June 1, 2026.",
    ]);
    const run = await runConsistency({
      rules: [CROSS_DATE_001],
      documents: [msa, baa],
      dkb: STARTER_DKB,
    });
    expect(run.findings).toHaveLength(0);
  });
});

/* ---------------- CROSS-AMOUNT-001 --------------- */

describe("CROSS-AMOUNT-001", () => {
  it("fires when aggregate liability caps differ across docs", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep", [
      "Limitation of Liability",
      "Provider's aggregate liability under this Agreement shall not exceed $1,000,000.",
    ]);
    const sow = makeDoc("sow", "sow", [
      "Limitation of Liability",
      "Provider's aggregate liability under this Statement of Work shall not exceed $50,000.",
    ]);
    const run = await runConsistency({
      rules: [CROSS_AMOUNT_001],
      documents: [msa, sow],
      dkb: STARTER_DKB,
    });
    expect(run.findings).toHaveLength(1);
    expect(run.findings[0]!.title).toMatch(/\$50,000|caps? differ/);
  });

  it("does not fire when caps match", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep", [
      "Limitation of Liability",
      "Provider's aggregate liability under this Agreement shall not exceed $1,000,000.",
    ]);
    const sow = makeDoc("sow", "sow", [
      "Limitation of Liability",
      "Provider's aggregate liability under this SOW shall not exceed $1,000,000.",
    ]);
    const run = await runConsistency({
      rules: [CROSS_AMOUNT_001],
      documents: [msa, sow],
      dkb: STARTER_DKB,
    });
    expect(run.findings).toHaveLength(0);
  });
});

/* ---------------- CROSS-MISSING-001 -------------- */

describe("CROSS-MISSING-001", () => {
  it("fires when MSA references a Data Processing Agreement that isn't in the bundle", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep", [
      "Privacy",
      "Customer Data is processed under the Data Processing Agreement attached as Schedule B.",
    ]);
    // No DPA in the bundle.
    const baa = makeDoc("baa", "baa", ["Agreement", "Some BAA content."]);
    const run = await runConsistency({
      rules: [CROSS_MISSING_001],
      documents: [msa, baa],
      dkb: STARTER_DKB,
    });
    expect(run.findings.length).toBeGreaterThanOrEqual(1);
    expect(run.findings[0]!.title).toMatch(/Data Processing Agreement/);
  });

  it("does not fire when the referenced companion is present", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep", [
      "Privacy",
      "Customer Data is processed under the Data Processing Agreement attached as Schedule B.",
    ]);
    const dpa = makeDoc("dpa", "dpa-controller-processor", [
      "Agreement",
      "This Data Processing Agreement governs Customer Data.",
    ]);
    const run = await runConsistency({
      rules: [CROSS_MISSING_001],
      documents: [msa, dpa],
      dkb: STARTER_DKB,
    });
    expect(run.findings).toHaveLength(0);
  });
});

/* ---------------- CROSS-PRECEDENCE-001 ----------- */

describe("CROSS-PRECEDENCE-001", () => {
  it("fires when both MSA and SOW claim to control", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep", [
      "Order of Precedence",
      "In the event of any conflict between this Agreement and any Statement of Work, this Agreement shall control.",
    ]);
    const sow = makeDoc("sow", "sow", [
      "Order of Precedence",
      "In the event of any conflict between this Statement of Work and the Master Services Agreement, this Statement of Work shall control.",
    ]);
    const run = await runConsistency({
      rules: [CROSS_PRECEDENCE_001],
      documents: [msa, sow],
      dkb: STARTER_DKB,
    });
    expect(run.findings).toHaveLength(1);
    expect(run.findings[0]!.title).toMatch(/claim controlling status/);
  });

  it("does not fire when only one document claims controlling status", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep", [
      "Order of Precedence",
      "In the event of any conflict between this Agreement and any Statement of Work, this Agreement shall control.",
    ]);
    const sow = makeDoc("sow", "sow", [
      "Scope",
      "The Services are described herein. The parties agree the MSA defines defined terms.",
    ]);
    const run = await runConsistency({
      rules: [CROSS_PRECEDENCE_001],
      documents: [msa, sow],
      dkb: STARTER_DKB,
    });
    expect(run.findings).toHaveLength(0);
  });
});

/* ---------------- determinism ---------------- */

describe("V4_CROSS_RULES — determinism", () => {
  it("produces identical result_hash on repeated runs", async () => {
    const msa = makeDoc(
      "msa",
      "msa-vendor-deep",
      [
        "Agreement",
        "This MSA is between Acme Corp., a Delaware corporation, and Globex Industries, Inc.",
      ],
      ["Limitation of Liability", "Provider's aggregate liability shall not exceed $1,000,000."],
      ["Governing Law", "Governed by Delaware law."],
    );
    const sow = makeDoc(
      "sow",
      "sow",
      ["Order of Precedence", "In the event of any conflict, this SOW shall control."],
      ["Limitation of Liability", "Provider's aggregate liability shall not exceed $50,000."],
    );
    const r1 = await runConsistency({
      rules: V4_CROSS_RULES,
      documents: [msa, sow],
      dkb: STARTER_DKB,
    });
    const r2 = await runConsistency({
      rules: V4_CROSS_RULES,
      documents: [msa, sow],
      dkb: STARTER_DKB,
    });
    expect(r2.result_hash).toBe(r1.result_hash);
  });
});

/* ---------------- CROSS-DEFTERM-002 (spec-v6 §20) --------------- */

describe("CROSS-DEFTERM-002", () => {
  it("fires when a term defined in the MSA is used undefined in the SOW", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep", [
      "Definitions",
      '"Authorized Users" means the employees and contractors of Customer permitted to access the Services.',
    ]);
    const sow = makeDoc("sow", "sow", [
      "Access",
      "Provider shall provision access only to the Authorized Users identified in this Statement of Work.",
    ]);
    const run = await runConsistency({
      rules: [CROSS_DEFTERM_002],
      documents: [msa, sow],
      dkb: STARTER_DKB,
    });
    expect(run.findings.length).toBeGreaterThanOrEqual(1);
    expect(run.findings[0]!.title).toMatch(/Authorized Users/);
    expect(run.findings[0]!.excerpts).toHaveLength(2);
  });

  it("does not fire when the using document incorporates definitions by reference", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep", [
      "Definitions",
      '"Authorized Users" means the employees of Customer permitted to access the Services.',
    ]);
    const sow = makeDoc("sow", "sow", [
      "Interpretation",
      "Capitalized terms not defined herein have the meanings given in the Master Services Agreement. Provider shall provision access only to the Authorized Users.",
    ]);
    const run = await runConsistency({
      rules: [CROSS_DEFTERM_002],
      documents: [msa, sow],
      dkb: STARTER_DKB,
    });
    expect(run.findings).toHaveLength(0);
  });
});

/* ---------------- CROSS-INDEMNITY-001 (spec-v6 §20) ------------- */

describe("CROSS-INDEMNITY-001", () => {
  it("fires when indemnity caps differ across the MSA and the order form", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep", [
      "Indemnification",
      "Each party's indemnification obligations under this Agreement shall not exceed $2,000,000 in the aggregate.",
    ]);
    const order = makeDoc("order", "sow", [
      "Indemnification",
      "Vendor's indemnification liability under this Order Form is limited to $500,000.",
    ]);
    const run = await runConsistency({
      rules: [CROSS_INDEMNITY_001],
      documents: [msa, order],
      dkb: STARTER_DKB,
    });
    expect(run.findings).toHaveLength(1);
    expect(run.findings[0]!.title).toMatch(/Indemnity caps differ|\$500,000|\$2,000,000/);
  });

  it("does not fire when only one document caps indemnity", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep", [
      "Indemnification",
      "Each party's indemnification obligations shall not exceed $2,000,000.",
    ]);
    const order = makeDoc("order", "sow", [
      "Scope",
      "Vendor shall deliver the Services described herein.",
    ]);
    const run = await runConsistency({
      rules: [CROSS_INDEMNITY_001],
      documents: [msa, order],
      dkb: STARTER_DKB,
    });
    expect(run.findings).toHaveLength(0);
  });
});

/* ---------------- CROSS-SURVIVAL-001 (spec-v6 §20) ------------- */

describe("CROSS-SURVIVAL-001", () => {
  it("fires when confidentiality survives a fixed term in one doc and in perpetuity in another", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep", [
      "Survival",
      "The confidentiality obligations in this Agreement shall survive termination for a period of three (3) years.",
    ]);
    const dpa = makeDoc("dpa", "dpa-controller-processor", [
      "Survival",
      "The confidentiality obligations shall survive termination of this Agreement in perpetuity.",
    ]);
    const run = await runConsistency({
      rules: [CROSS_SURVIVAL_001],
      documents: [msa, dpa],
      dkb: STARTER_DKB,
    });
    expect(run.findings).toHaveLength(1);
    expect(run.findings[0]!.title).toMatch(/Confidentiality survives/);
    expect(run.findings[0]!.excerpts).toHaveLength(2);
  });

  it("does not fire when both documents survive confidentiality for the same period", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep", [
      "Survival",
      "The confidentiality obligations shall survive termination for three (3) years.",
    ]);
    const dpa = makeDoc("dpa", "dpa-controller-processor", [
      "Survival",
      "The confidentiality obligations shall survive termination for three (3) years.",
    ]);
    const run = await runConsistency({
      rules: [CROSS_SURVIVAL_001],
      documents: [msa, dpa],
      dkb: STARTER_DKB,
    });
    expect(run.findings).toHaveLength(0);
  });
});

/* ---------------- CROSS-TERM-001 (spec-v7 §13) ----------------- */

describe("CROSS-TERM-001", () => {
  it("fires when a convenience-terminable master sits over a cause-only companion", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep", [
      "Term",
      "Either party may terminate this Master Services Agreement for convenience upon thirty (30) days written notice.",
    ]);
    const sow = makeDoc("sow", "msa-vendor-deep", [
      "Term",
      "This Statement of Work is non-terminable except for cause.",
    ]);
    const run = await runConsistency({
      rules: [CROSS_TERM_001],
      documents: [msa, sow],
      dkb: STARTER_DKB,
    });
    expect(run.findings).toHaveLength(1);
    expect(run.findings[0]!.title).toMatch(/terminable for convenience/);
    expect(run.findings[0]!.excerpts).toHaveLength(2);
  });

  it("does not fire when both documents are terminable for convenience", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep", [
      "Term",
      "Either party may terminate this Agreement for convenience upon notice.",
    ]);
    const sow = makeDoc("sow", "msa-vendor-deep", [
      "Term",
      "Either party may terminate this Statement of Work for convenience upon notice.",
    ]);
    const run = await runConsistency({
      rules: [CROSS_TERM_001],
      documents: [msa, sow],
      dkb: STARTER_DKB,
    });
    expect(run.findings).toHaveLength(0);
  });
});

/* ---------------- CROSS-CARVEOUT-001 (spec-v7 §13) ------------- */

describe("CROSS-CARVEOUT-001", () => {
  it("fires when the liability-cap carveout sets differ across documents", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep", [
      "Liability",
      "The foregoing limitation of liability shall not apply to breaches of confidentiality, intellectual property infringement, or bodily injury.",
    ]);
    const dpa = makeDoc("dpa", "dpa-controller-processor", [
      "Liability",
      "This limitation of liability shall not apply to breaches of confidentiality.",
    ]);
    const run = await runConsistency({
      rules: [CROSS_CARVEOUT_001],
      documents: [msa, dpa],
      dkb: STARTER_DKB,
    });
    expect(run.findings).toHaveLength(1);
    expect(run.findings[0]!.title).toMatch(/carveouts differ/);
    expect(run.findings[0]!.excerpts).toHaveLength(2);
  });

  it("does not fire when the carveout sets match", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep", [
      "Liability",
      "This limitation of liability shall not apply to breaches of confidentiality or intellectual property infringement.",
    ]);
    const dpa = makeDoc("dpa", "dpa-controller-processor", [
      "Liability",
      "This limitation of liability shall not apply to intellectual property infringement or breaches of confidentiality.",
    ]);
    const run = await runConsistency({
      rules: [CROSS_CARVEOUT_001],
      documents: [msa, dpa],
      dkb: STARTER_DKB,
    });
    expect(run.findings).toHaveLength(0);
  });
});

/* ---------------- CROSS-CURRENCY-001 (spec-v7 §13) ------------- */

describe("CROSS-CURRENCY-001", () => {
  it("fires when documents state amounts in different dominant currencies", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep", [
      "Fees",
      "The annual fee is $250,000 payable in advance. A late fee of $5,000 applies.",
    ]);
    const appendix = makeDoc("appendix", "msa-vendor-deep", [
      "Fee Schedule",
      "The annual fee is €250,000 payable in advance. A late fee of €5,000 applies.",
    ]);
    const run = await runConsistency({
      rules: [CROSS_CURRENCY_001],
      documents: [msa, appendix],
      dkb: STARTER_DKB,
    });
    expect(run.findings).toHaveLength(1);
    expect(run.findings[0]!.title).toMatch(/Currency differs/);
    expect(run.findings[0]!.excerpts).toHaveLength(2);
  });

  it("does not fire when both documents use the same currency", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep", [
      "Fees",
      "The annual fee is $250,000 payable in advance.",
    ]);
    const appendix = makeDoc("appendix", "msa-vendor-deep", [
      "Fee Schedule",
      "The annual fee is $250,000 payable in advance.",
    ]);
    const run = await runConsistency({
      rules: [CROSS_CURRENCY_001],
      documents: [msa, appendix],
      dkb: STARTER_DKB,
    });
    expect(run.findings).toHaveLength(0);
  });
});
