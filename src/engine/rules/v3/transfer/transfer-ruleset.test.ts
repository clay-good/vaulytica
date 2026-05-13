import { describe, expect, it } from "vitest";

import { TRANSFER_RULES } from "./rules.js";
import { buildContext } from "../../../_test-fixtures.js";
import { runEngine } from "../../../runner.js";
import type { Playbook, RuleContext } from "../../../finding.js";

const SCC2: Playbook = { id: "scc-module-2", version: "1.0.0" };
const UK: Playbook = { id: "uk-idta-addendum", version: "1.0.0" };
const SRC = { name: "test.docx", sha256: "0".repeat(64), size_bytes: 1 };

const withPb = (ctx: RuleContext, p: Playbook): RuleContext => ({ ...ctx, playbook: p });

const COMPLIANT_SCC2: [string, ...string[]][] = [
  ["EU SCCs Module 2", "Effective Date: January 1, 2026. The parties agree to incorporate the EU Standard Contractual Clauses."],
  ["Clause 1 — Purpose and Scope", "These Clauses ensure compliance with Article 46(1) GDPR."],
  ["Clause 2 — Effect and Invariability", "The Parties undertake not to modify the Clauses, except to select the appropriate Module(s) or to add other clauses that do not contradict."],
  ["Clause 8 — Data Protection Safeguards", "The data importer shall process the personal data only on documented instructions from the data exporter."],
  ["Clause 9 — Use of Sub-processors", "The data importer shall have the data exporter's prior specific or general written authorisation for engaging Sub-processors. Annex III lists the current Sub-processors."],
  ["Clause 11 — Redress", "The data importer shall inform data subjects in a transparent manner of the redress mechanisms."],
  ["Clause 14 — Local laws", "The Parties have conducted a Transfer Impact Assessment of local laws and practices."],
  ["Clause 15 — Public Authority Access", "The data importer shall notify the data exporter promptly of any legally-binding request from a public authority and challenge such request where permitted."],
  ["Clause 16 — Non-Compliance", "The data importer shall promptly inform the data exporter if it is unable to comply with these Clauses."],
  ["Clause 18 — Governing Law and Forum", "These Clauses shall be governed by the law of an EU Member State allowing third-party-beneficiary rights, namely Ireland."],
  ["Onward Transfer", "Onward transfers shall comply with Clause 8.7 and Clause 8.8."],
];

const COMPLIANT_UK_ADDENDUM: [string, ...string[]][] = [
  ["International Data Transfer Addendum", "ICO Approved Addendum."],
  ["Table 1 — Parties", "Exporter and Importer details."],
  ["Table 2 — Selected SCC Modules", "Module 2 is selected."],
  ["Table 3 — Appendix Information", "SCC Annex I, II, III incorporated."],
  ["Table 4 — Ending This Addendum When the Approved Addendum Changes", "Either party may end this Addendum on a revision."],
  ["TIA", "A Transfer Risk Assessment has been completed pursuant to local laws and practices analysis."],
];

describe("Transfer ruleset — registry contract", () => {
  it("exports exactly 20 rules with stable TRANSFER-NNN ids", () => {
    expect(TRANSFER_RULES.length).toBe(20);
    const ids = TRANSFER_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(20);
    for (const r of TRANSFER_RULES) {
      expect(r.id).toMatch(/^TRANSFER-\d{3}$/);
      expect(r.category).toBe("transfer");
      // Either SCC-scoped, UK-scoped, or cross-cutting (covers both).
      const playbooks = r.applies_to_playbooks ?? [];
      const isScc = playbooks.includes("scc-module-2");
      const isUk = playbooks.includes("uk-idta-addendum");
      expect(isScc || isUk).toBe(true);
    }
  });

  it("does not run when no transfer playbook is active", async () => {
    const ctx = buildContext(["Agreement", "Generic services agreement with personal data references."]);
    const run = await runEngine({ rules: TRANSFER_RULES, ctx, executed_at: "2026-05-13T00:00:00Z", source_file: SRC });
    expect(run.findings).toHaveLength(0);
  });
});

describe("Transfer ruleset — compliant SCC Module 2 fixture", () => {
  it("zero critical findings", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_SCC2), SCC2);
    const run = await runEngine({ rules: TRANSFER_RULES, ctx, executed_at: "2026-05-13T00:00:00Z", source_file: SRC });
    const criticals = run.findings.filter((f) => f.severity === "critical");
    expect(criticals).toHaveLength(0);
  });
});

describe("Transfer ruleset — failure modes", () => {
  it("modified SCC clauses fires TRANSFER-003", async () => {
    const ctx = withPb(buildContext([
      "SCCs",
      "The Standard Contractual Clauses as modified by Schedule 2 hereto apply to all transfers.",
    ]), SCC2);
    const run = await runEngine({ rules: TRANSFER_RULES, ctx, executed_at: "2026-05-13T00:00:00Z", source_file: SRC });
    expect(run.findings.find((f) => f.rule_id === "TRANSFER-003")).toBeTruthy();
  });

  it("missing Clause 14 (TIA) fires TRANSFER-007", async () => {
    const ctx = withPb(buildContext([
      "SCCs Module 2",
      "Clause 1 Purpose and Scope. Clause 2 Effect and Invariability. Clause 8 safeguards. Clause 9 sub-processors. Clause 11 redress. Clause 15 public authority. Clause 16 non-compliance. Clause 18 governing law.",
    ]), SCC2);
    const run = await runEngine({ rules: TRANSFER_RULES, ctx, executed_at: "2026-05-13T00:00:00Z", source_file: SRC });
    expect(run.findings.find((f) => f.rule_id === "TRANSFER-007")).toBeTruthy();
  });

  it("DPF reliance fires TRANSFER-017 (warning)", async () => {
    const ctx = withPb(buildContext([
      "Adequacy",
      "Transfers rely on the EU-US Data Privacy Framework adequacy decision.",
    ]), SCC2);
    const run = await runEngine({ rules: TRANSFER_RULES, ctx, executed_at: "2026-05-13T00:00:00Z", source_file: SRC });
    expect(run.findings.find((f) => f.rule_id === "TRANSFER-017")).toBeTruthy();
  });
});

describe("Transfer ruleset — UK Addendum compliant fixture", () => {
  it("Tables 1–4 + TIA present produces no critical findings", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_UK_ADDENDUM), UK);
    const run = await runEngine({ rules: TRANSFER_RULES, ctx, executed_at: "2026-05-13T00:00:00Z", source_file: SRC });
    const criticals = run.findings.filter((f) => f.severity === "critical");
    expect(criticals).toHaveLength(0);
  });
});

describe("Transfer ruleset — determinism", () => {
  it("two runs over the same input produce the same result_hash", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_SCC2), SCC2);
    const a = await runEngine({ rules: TRANSFER_RULES, ctx, executed_at: "2026-05-13T00:00:00Z", source_file: SRC });
    const b = await runEngine({ rules: TRANSFER_RULES, ctx, executed_at: "2026-05-13T00:00:00Z", source_file: SRC });
    expect(a.result_hash).toBe(b.result_hash);
  });
});
