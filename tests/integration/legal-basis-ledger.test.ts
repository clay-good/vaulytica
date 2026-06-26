/**
 * Legal-basis ledger machine-mirror (spec-v5 Part III, Step 75).
 *
 * The ledger (`docs/legal-basis/ledger.json`) is the attorney-signed record of
 * the legal authority each rule rests on (spec-v5 §12). This test is the
 * machine mirror §12 requires: it asserts the ledger stays internally
 * consistent and consistent with the live engine, so a surfaced `tier` badge
 * can never be author-asserted or cite a DKB node the engine does not carry.
 *
 * The ledger is honestly **empty** until attorney review (Steps 76/77,
 * human-gated) lands real sign-offs — so most assertions are guards that
 * activate on the first real entry. The coverage assertion runs today and
 * reports the honest 0-of-N state, the same posture the SCOREBOARD takes.
 */

import { describe, expect, it } from "vitest";

import {
  loadLegalBasisLedger,
  indexLedger,
  tierForRule,
  ledgerCoverage,
  LegalBasisEntrySchema,
} from "../../tools/accuracy/legal-basis.js";
import { loadStarterDkbSync } from "../../src/engine/_test-fixtures.js";
import { LAUNCH_RULES, V3_RULES, V4_RULES } from "../../src/engine/index.js";
import { ALL_CONSISTENCY_RULES } from "../../src/engine/consistency/rules/index.js";
import type { RuleTier } from "../../src/engine/index.js";

/** The live single-document catalog, exactly as the UI runs it. */
const SINGLE_DOC_RULES = [...LAUNCH_RULES, ...V3_RULES, ...V4_RULES];
/** Every rule id the ledger may legitimately reference (single-doc + cross-doc). */
const ALL_RULE_IDS = new Set<string>([
  ...SINGLE_DOC_RULES.map((r) => r.id),
  ...ALL_CONSISTENCY_RULES.map((r) => r.id),
]);

/** Every DKB node id a `legal_basis` authority may pin to. */
function allDkbNodeIds(): Set<string> {
  const dkb = loadStarterDkbSync();
  const ids = new Set<string>();
  for (const c of dkb.clauses) ids.add(c.id);
  for (const j of dkb.jurisdictions) ids.add(j.id);
  for (const d of dkb.definitions) ids.add(d.id);
  for (const p of dkb.dark_patterns) ids.add(p.id);
  for (const s of dkb.statutes) ids.add(s.id);
  return ids;
}

describe("legal-basis ledger (spec-v5 §12–§15, Step 75)", () => {
  it("validates against the strict schema (no stray keys, non-empty legal_basis)", async () => {
    const ledger = await loadLegalBasisLedger();
    for (const entry of ledger) {
      expect(() => LegalBasisEntrySchema.parse(entry)).not.toThrow();
    }
  });

  it("has no duplicate rule_id (one record per rule)", async () => {
    const ledger = await loadLegalBasisLedger();
    // indexLedger throws on a duplicate.
    expect(() => indexLedger(ledger)).not.toThrow();
  });

  it("every signed rule_id names a real rule in the live catalog", async () => {
    const ledger = await loadLegalBasisLedger();
    const unknown = ledger.map((e) => e.rule_id).filter((id) => !ALL_RULE_IDS.has(id));
    expect(unknown, "ledger references rules that do not exist").toEqual([]);
  });

  it("every legal_basis authority pins to a DKB node the engine carries", async () => {
    const ledger = await loadLegalBasisLedger();
    const dkbNodes = allDkbNodeIds();
    const dangling: string[] = [];
    for (const entry of ledger) {
      for (const basis of entry.legal_basis) {
        if (!dkbNodes.has(basis.dkb_node)) dangling.push(`${entry.rule_id} → ${basis.dkb_node}`);
      }
    }
    expect(dangling, "legal_basis cites DKB nodes that do not exist").toEqual([]);
  });

  it("every Rule.tier set inline is backed by a matching signed ledger entry", async () => {
    const ledger = await loadLegalBasisLedger();
    const byRule = indexLedger(ledger);
    const violations: string[] = [];
    for (const rule of SINGLE_DOC_RULES) {
      const inlineTier = (rule as { tier?: RuleTier }).tier;
      if (inlineTier === undefined) continue; // unsigned rule — fine, field omitted
      const expected = tierForRule(byRule, rule.id);
      if (expected !== inlineTier) {
        violations.push(
          `${rule.id}: inline tier "${inlineTier}" but ledger derives "${expected ?? "none"}"`,
        );
      }
    }
    expect(
      violations,
      "a Rule.tier must never be author-asserted — every inline tier needs a signed ledger entry",
    ).toEqual([]);
  });

  it("reports honest coverage (signed of total) without fabricating verdicts", async () => {
    const ledger = await loadLegalBasisLedger();
    const coverage = ledgerCoverage(ledger, ALL_RULE_IDS.size);
    expect(coverage.total_rules).toBe(ALL_RULE_IDS.size);
    expect(coverage.signed).toBe(ledger.length);
    expect(coverage.signed).toBeLessThanOrEqual(coverage.total_rules);
    // Until attorney review (Steps 76/77) lands, the ledger is honestly empty.
    // This assertion documents the current state; when the first real entry is
    // signed, update it to the new count in the same commit as the sign-off.
    expect(coverage.signed).toBe(0);
  });
});
