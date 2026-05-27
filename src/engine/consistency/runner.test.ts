import { describe, expect, it } from "vitest";
import { runConsistency, CONSISTENCY_ENGINE_VERSION } from "./runner.js";
import {
  CONSISTENCY_RULES,
  CC_001_BAA_PURPOSE,
  CC_002_DPA_PURPOSE,
  CC_003_DPA_CATEGORIES,
  CC_004_BAA_TERM,
  CC_005_GOVERNING_LAW,
  CC_006_NOTICE,
  CC_007_ORDER_OF_PRECEDENCE,
} from "./rules/index.js";
import { kindOf } from "./_helpers.js";
import type { ConsistencyDocument } from "./types.js";
import { buildContext } from "../_test-fixtures.js";

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

const STARTER_DKB = (() => buildContext(["Doc", "hello"]).dkb)();

/* ---------------- registry contract ----------------- */

describe("CONSISTENCY_RULES registry", () => {
  it("ships seven rules with unique CC-NNN ids", () => {
    expect(CONSISTENCY_RULES).toHaveLength(7);
    const ids = CONSISTENCY_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(7);
    for (const id of ids) {
      expect(id).toMatch(/^CC-\d{3}$/);
    }
  });

  it("every rule has category=consistency and a non-empty version", () => {
    for (const r of CONSISTENCY_RULES) {
      expect(r.category).toBe("consistency");
      expect(r.version).toMatch(/^\d+\.\d+\.\d+/);
    }
  });
});

/* ---------------- kindOf classifier ----------------- */

describe("kindOf", () => {
  it("classifies playbook ids into the right document kinds", () => {
    expect(kindOf(makeDoc("a", "msa-vendor-deep", ["A", "x"]))).toBe("msa");
    expect(kindOf(makeDoc("a", "msa-customer-deep", ["A", "x"]))).toBe("msa");
    expect(kindOf(makeDoc("a", "msa-general", ["A", "x"]))).toBe("msa");
    // family-msa is the v4 Family-Law Marital Settlement Agreement
    // playbook — completely unrelated to a vendor MSA. The current
    // `startsWith("msa-")` check correctly classifies it as "other"
    // because "family-msa" does not start with "msa-". A future
    // refactor that broadened the match (e.g. `includes("msa")`)
    // would silently misroute family-law documents into two-doc MSA
    // mode; pin the negative case so the regression surfaces.
    expect(kindOf(makeDoc("a", "family-msa", ["A", "x"]))).toBe("other");
    expect(kindOf(makeDoc("a", "baa", ["A", "x"]))).toBe("baa");
    expect(kindOf(makeDoc("a", "baa-subcontractor", ["A", "x"]))).toBe("baa");
    expect(kindOf(makeDoc("a", "dpa-controller-processor", ["A", "x"]))).toBe("dpa");
    expect(kindOf(makeDoc("a", "scc-module-2", ["A", "x"]))).toBe("dpa");
    expect(kindOf(makeDoc("a", "mutual-nda-deep", ["A", "x"]))).toBe("nda");
    expect(kindOf(makeDoc("a", "unilateral-nda-deep", ["A", "x"]))).toBe("nda");
    expect(kindOf(makeDoc("a", "mutual-nda", ["A", "x"]))).toBe("nda");
    expect(kindOf(makeDoc("a", "unilateral-nda", ["A", "x"]))).toBe("nda");
    expect(kindOf(makeDoc("a", "sow", ["A", "x"]))).toBe("sow");
    expect(kindOf(makeDoc("a", "generic-fallback", ["A", "x"]))).toBe("other");
  });
});

/* ---------------- determinism ----------------- */

describe("runConsistency — determinism", () => {
  it("produces identical result_hash on repeated runs", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep",
      ["Services", "Provider shall provide the Services described herein. Scope of services: claims processing."],
      ["Governing Law", "This Agreement shall be governed by the laws of the State of Delaware."],
    );
    const baa = makeDoc("baa", "baa",
      ["Permitted Uses", "Business Associate may use PHI for any business purpose authorized by Covered Entity."],
      ["Governing Law", "This Agreement is governed by the laws of the State of California."],
    );
    const run1 = await runConsistency({ rules: CONSISTENCY_RULES, documents: [msa, baa], dkb: STARTER_DKB });
    const run2 = await runConsistency({ rules: CONSISTENCY_RULES, documents: [msa, baa], dkb: STARTER_DKB });
    expect(run1.result_hash).toBe(run2.result_hash);
    expect(run1.version).toBe(CONSISTENCY_ENGINE_VERSION);
  });

  it("rejects bundles with fewer than two documents", async () => {
    const only = makeDoc("only", "msa-vendor-deep", ["Services", "x"]);
    await expect(
      runConsistency({ rules: CONSISTENCY_RULES, documents: [only], dkb: STARTER_DKB }),
    ).rejects.toThrow(/at least two documents/);
  });

  it("rejects duplicate doc_ids", async () => {
    const a = makeDoc("dup", "msa-vendor-deep", ["A", "x"]);
    const b = makeDoc("dup", "baa", ["B", "y"]);
    await expect(
      runConsistency({ rules: CONSISTENCY_RULES, documents: [a, b], dkb: STARTER_DKB }),
    ).rejects.toThrow(/Duplicate doc_id/);
  });
});

/* ---------------- per-rule behavior ----------------- */

describe("CC-001 BAA purpose no broader than MSA", () => {
  it("fires when the BAA permits 'any business purpose' use of PHI", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep",
      ["Scope of Services", "The Services to be provided are claims processing on behalf of Customer."],
    );
    const baa = makeDoc("baa", "baa",
      ["Permitted Uses", "Business Associate may use PHI for any business purpose authorized by Covered Entity."],
    );
    const run = await runConsistency({ rules: [CC_001_BAA_PURPOSE], documents: [msa, baa], dkb: STARTER_DKB });
    expect(run.findings).toHaveLength(1);
    expect(run.findings[0]!.rule_id).toBe("CC-001");
    expect(run.findings[0]!.excerpts).toHaveLength(2);
    expect(run.findings[0]!.excerpts.map((e) => e.doc_id).sort()).toEqual(["baa", "msa"]);
  });

  it("does not fire when the BAA's permitted uses are bounded", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep",
      ["Scope of Services", "The Services to be provided are claims processing on behalf of Customer."],
    );
    const baa = makeDoc("baa", "baa",
      ["Permitted Uses", "Business Associate may use PHI only to perform the Services described in the Master Services Agreement."],
    );
    const run = await runConsistency({ rules: [CC_001_BAA_PURPOSE], documents: [msa, baa], dkb: STARTER_DKB });
    expect(run.findings).toHaveLength(0);
  });

  it("is skipped (ran=false) when the bundle has no BAA", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep", ["A", "x"]);
    const dpa = makeDoc("dpa", "dpa-controller-processor", ["A", "y"]);
    const run = await runConsistency({ rules: [CC_001_BAA_PURPOSE], documents: [msa, dpa], dkb: STARTER_DKB });
    expect(run.findings).toHaveLength(0);
    expect(run.execution_log[0]!.ran).toBe(false);
  });
});

describe("CC-002 DPA purpose matches MSA services", () => {
  it("fires when the DPA's purpose is open-ended", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep",
      ["Scope of Services", "Provider shall provide payroll processing services to Customer."],
    );
    const dpa = makeDoc("dpa", "dpa-controller-processor",
      ["Subject Matter", "The processing purposes shall be any purpose authorized by Controller from time to time."],
    );
    const run = await runConsistency({ rules: [CC_002_DPA_PURPOSE], documents: [msa, dpa], dkb: STARTER_DKB });
    expect(run.findings).toHaveLength(1);
    expect(run.findings[0]!.rule_id).toBe("CC-002");
  });
});

describe("CC-003 DPA data categories not broader than MSA", () => {
  it("fires when the DPA names health data but the MSA does not", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep",
      ["Scope of Services", "Provider shall provide logistics and shipping services to Customer."],
    );
    const dpa = makeDoc("dpa", "dpa-controller-processor",
      ["Annex I.B Categories", "The categories of personal data include names, email addresses, and health data."],
    );
    const run = await runConsistency({ rules: [CC_003_DPA_CATEGORIES], documents: [msa, dpa], dkb: STARTER_DKB });
    expect(run.findings.length).toBeGreaterThanOrEqual(1);
    expect(run.findings[0]!.title).toMatch(/health data/);
  });

  it("does not fire when the MSA anchors the category", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep",
      ["Scope of Services", "Provider shall provide health data analytics services."],
    );
    const dpa = makeDoc("dpa", "dpa-controller-processor",
      ["Annex I.B Categories", "Categories include health data and demographic data."],
    );
    const run = await runConsistency({ rules: [CC_003_DPA_CATEGORIES], documents: [msa, dpa], dkb: STARTER_DKB });
    expect(run.findings).toHaveLength(0);
  });
});

describe("CC-004 BAA term aligns with MSA", () => {
  it("fires when the BAA sets its own independent term", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep",
      ["Term", "This Agreement shall commence on the Effective Date and continue for an initial term of three years."],
    );
    const baa = makeDoc("baa", "baa",
      ["Term", "This BAA shall be effective and remain in effect for a term of 5 years from the Effective Date."],
    );
    const run = await runConsistency({ rules: [CC_004_BAA_TERM], documents: [msa, baa], dkb: STARTER_DKB });
    expect(run.findings).toHaveLength(1);
    expect(run.findings[0]!.rule_id).toBe("CC-004");
  });

  it("does not fire when the BAA is co-terminous with the MSA", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep",
      ["Term", "This Agreement shall commence on the Effective Date for an initial term of three years."],
    );
    const baa = makeDoc("baa", "baa",
      ["Term", "This BAA shall be co-terminous with the Master Services Agreement, and the return-or-destruction obligations shall survive termination."],
    );
    const run = await runConsistency({ rules: [CC_004_BAA_TERM], documents: [msa, baa], dkb: STARTER_DKB });
    expect(run.findings).toHaveLength(0);
  });
});

describe("CC-005 governing-law alignment", () => {
  it("fires when two documents pick different governing laws", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep",
      ["Governing Law", "This Agreement shall be governed by and construed in accordance with the laws of the State of Delaware."],
    );
    const dpa = makeDoc("dpa", "dpa-controller-processor",
      ["Governing Law", "This DPA shall be governed by the laws of Ireland."],
    );
    const run = await runConsistency({ rules: [CC_005_GOVERNING_LAW], documents: [msa, dpa], dkb: STARTER_DKB });
    expect(run.findings).toHaveLength(1);
    expect(run.findings[0]!.severity).toBe("warning");
  });

  it("does not fire when the governing-law clauses agree", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep",
      ["Governing Law", "This Agreement shall be governed by the laws of the State of Delaware."],
    );
    const dpa = makeDoc("dpa", "dpa-controller-processor",
      ["Governing Law", "This DPA shall be governed by the laws of the State of Delaware."],
    );
    const run = await runConsistency({ rules: [CC_005_GOVERNING_LAW], documents: [msa, dpa], dkb: STARTER_DKB });
    expect(run.findings).toHaveLength(0);
  });
});

describe("CC-006 notice alignment", () => {
  it("fires when notice clauses differ across documents", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep",
      ["Notices", "Any notices required under this Agreement shall be sent to Customer at 1 Main Street, Wilmington, Delaware, Attention: General Counsel."],
    );
    const dpa = makeDoc("dpa", "dpa-controller-processor",
      ["Notices", "Any notices required under this Agreement shall be sent to Customer at 99 Privacy Lane, Dublin, Ireland, Attention: Data Protection Officer."],
    );
    const run = await runConsistency({ rules: [CC_006_NOTICE], documents: [msa, dpa], dkb: STARTER_DKB });
    expect(run.findings).toHaveLength(1);
    expect(run.findings[0]!.severity).toBe("info");
  });
});

describe("CC-007 order of precedence consistency", () => {
  it("fires when the MSA controls but indemnity lives only in the SOW", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep",
      ["Order of Precedence", "In the event of any conflict between this MSA and any Statement of Work, the MSA shall control."],
      ["Services", "Provider shall provide the Services as described in each SOW."],
    );
    const sow = makeDoc("sow", "sow",
      ["Indemnification", "Provider shall indemnify Customer against all losses, claims, damages, or liabilities arising from Provider's breach."],
    );
    const run = await runConsistency({ rules: [CC_007_ORDER_OF_PRECEDENCE], documents: [msa, sow], dkb: STARTER_DKB });
    expect(run.findings.length).toBeGreaterThanOrEqual(1);
    expect(run.findings[0]!.rule_id).toBe("CC-007");
  });

  it("does not fire when the MSA does not name itself controlling", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep",
      ["Services", "Provider shall provide the Services as described in each SOW."],
    );
    const sow = makeDoc("sow", "sow",
      ["Indemnification", "Provider shall indemnify Customer against all losses."],
    );
    const run = await runConsistency({ rules: [CC_007_ORDER_OF_PRECEDENCE], documents: [msa, sow], dkb: STARTER_DKB });
    expect(run.findings).toHaveLength(0);
  });
});

/* ---------------- ordering ----------------- */

describe("runConsistency — finding ordering", () => {
  it("sorts findings by (severity, rule_id, doc_id, start_offset)", async () => {
    const msa = makeDoc("msa", "msa-vendor-deep",
      ["Scope of Services", "Provider shall provide logistics services."],
      ["Order of Precedence", "In the event of any conflict, the MSA shall control."],
      ["Governing Law", "Governed by Delaware law."],
    );
    const baa = makeDoc("baa", "baa",
      ["Permitted Uses", "Business Associate may use PHI for any business purpose."],
      ["Governing Law", "Governed by Ireland law."],
      ["Term", "This BAA shall remain in effect until terminated by either party."],
    );
    const run = await runConsistency({ rules: CONSISTENCY_RULES, documents: [msa, baa], dkb: STARTER_DKB });
    // Severity ranks must be non-decreasing.
    const rank = { critical: 0, warning: 1, info: 2 } as const;
    for (let i = 1; i < run.findings.length; i++) {
      expect(rank[run.findings[i]!.severity]).toBeGreaterThanOrEqual(rank[run.findings[i - 1]!.severity]);
    }
    // CC-001 (critical) appears before CC-005 (warning).
    const ids = run.findings.map((f) => f.rule_id);
    if (ids.includes("CC-001") && ids.includes("CC-005")) {
      expect(ids.indexOf("CC-001")).toBeLessThan(ids.indexOf("CC-005"));
    }
  });
});
