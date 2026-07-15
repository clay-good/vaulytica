import { describe, expect, it } from "vitest";

import { PNOT_RULES, PRIVACY_NOTICE_PLAYBOOK_IDS, pnotRulesForRegimes } from "./rules.js";
import { buildContext } from "../../_test-fixtures.js";
import { runEngine } from "../../runner.js";
import type { Playbook, RuleContext } from "../../finding.js";
import { REGIMES } from "../../../privacy/regime-data.js";

const PNOT_US_PLAYBOOK: Playbook = { id: "privacy-notice-us", version: "1.0.0" };
const SRC = { name: "notice.docx", sha256: "0".repeat(64), size_bytes: 1 };

function withPnot(ctx: RuleContext, playbook: Playbook = PNOT_US_PLAYBOOK): RuleContext {
  return { ...ctx, playbook };
}

describe("PNOT rules — registry contract", () => {
  it("all ids start with PNOT- and are unique", () => {
    const ids = PNOT_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const r of PNOT_RULES) {
      expect(r.id).toMatch(/^PNOT-(CCPA|GDPR13|GDPR14)-\d{3}$/);
      expect(r.category).toBe("privacy-notice");
    }
  });

  it("every rule declares non-empty applies_to_playbooks containing privacy-notice-us", () => {
    for (const r of PNOT_RULES) {
      expect(r.applies_to_playbooks?.length ?? 0).toBeGreaterThan(0);
      expect(r.applies_to_playbooks).toContain("privacy-notice-us");
      expect(r.applies_to_playbooks).toContain("privacy-notice-gdpr");
    }
  });

  it("one rule per content item, per regime", () => {
    for (const [id, regime] of Object.entries(REGIMES)) {
      const count = PNOT_RULES.filter((r) => r.regime === id).length;
      expect(count).toBe(regime.items.length);
    }
  });

  it("PRIVACY_NOTICE_PLAYBOOK_IDS is the exact expected pair", () => {
    expect(PRIVACY_NOTICE_PLAYBOOK_IDS).toEqual(["privacy-notice-us", "privacy-notice-gdpr"]);
  });
});

describe("pnotRulesForRegimes", () => {
  it("returns only the rules for the requested regime(s)", () => {
    const ccpaRules = pnotRulesForRegimes(["ccpa"]);
    expect(ccpaRules.length).toBe(REGIMES.ccpa.items.length);
    for (const r of ccpaRules) {
      expect(r.id.startsWith("PNOT-CCPA-")).toBe(true);
    }
  });

  it("returns rules for multiple regimes when asked", () => {
    const rules = pnotRulesForRegimes(["ccpa", "gdpr-13"]);
    expect(rules.length).toBe(REGIMES.ccpa.items.length + REGIMES["gdpr-13"].items.length);
  });

  it("returns an empty list for no regimes", () => {
    expect(pnotRulesForRegimes([])).toHaveLength(0);
  });
});

describe("PNOT rules — presence behavior", () => {
  it("fires on a barebones tree lacking the item, and is silent when a present_pattern matches", async () => {
    const rule = PNOT_RULES.find((r) => r.id === "PNOT-CCPA-001");
    expect(rule).toBeTruthy();
    if (!rule) return;

    const missingCtx = withPnot(
      buildContext(["Privacy Policy", "This notice says nothing relevant at all."]),
    );
    const missingRun = await runEngine({
      rules: [rule],
      ctx: missingCtx,
      executed_at: "2026-07-15T00:00:00Z",
      source_file: SRC,
    });
    expect(missingRun.findings.find((f) => f.rule_id === rule.id)).toBeTruthy();

    const presentCtx = withPnot(
      buildContext([
        "Privacy Policy",
        "We describe the categories of personal information we collect from you.",
      ]),
    );
    const presentRun = await runEngine({
      rules: [rule],
      ctx: presentCtx,
      executed_at: "2026-07-15T00:00:00Z",
      source_file: SRC,
    });
    expect(presentRun.findings.find((f) => f.rule_id === rule.id)).toBeFalsy();
  });

  it("does not run when the playbook is not a privacy-notice playbook", async () => {
    const ctx = buildContext(["Agreement", "Generic services agreement, not a privacy notice."]);
    const run = await runEngine({
      rules: PNOT_RULES,
      ctx,
      executed_at: "2026-07-15T00:00:00Z",
      source_file: SRC,
    });
    expect(run.findings).toHaveLength(0);
    expect(run.execution_log.every((e) => e.fired === false)).toBe(true);
  });

  it("a GDPR-13 rule also runs under the privacy-notice-gdpr playbook", async () => {
    const rule = PNOT_RULES.find((r) => r.id === "PNOT-GDPR13-001");
    expect(rule).toBeTruthy();
    if (!rule) return;
    const ctx = withPnot(
      buildContext(["Privacy Notice", "This notice says nothing relevant at all."]),
      { id: "privacy-notice-gdpr", version: "1.0.0" },
    );
    const run = await runEngine({
      rules: [rule],
      ctx,
      executed_at: "2026-07-15T00:00:00Z",
      source_file: SRC,
    });
    expect(run.findings.find((f) => f.rule_id === rule.id)).toBeTruthy();
  });
});

describe("PNOT rules — determinism", () => {
  it("two runs over the same input produce the same result_hash", async () => {
    const ctx = withPnot(buildContext(["Privacy Policy", "We collect your name and email."]));
    const a = await runEngine({
      rules: PNOT_RULES,
      ctx,
      executed_at: "2026-07-15T00:00:00Z",
      source_file: SRC,
    });
    const b = await runEngine({
      rules: PNOT_RULES,
      ctx,
      executed_at: "2026-07-15T00:00:00Z",
      source_file: SRC,
    });
    expect(a.result_hash).toBe(b.result_hash);
  });
});
