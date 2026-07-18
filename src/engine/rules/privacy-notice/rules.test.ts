import { describe, expect, it } from "vitest";

import {
  OPT_OUT_RULES,
  PNOT_RULES,
  PRIVACY_NOTICE_PLAYBOOK_IDS,
  TX_EXACT_RULES,
  pnotRulesForRegimes,
} from "./rules.js";
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
      expect(r.id).toMatch(/^PNOT-(CCPA|GDPR13|GDPR14|CO|VA|TX|OR)-\d{3}$/);
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

  it("one rule per content item, per regime, plus the TX exact-wording and VA/TX opt-out rules", () => {
    for (const [id, regime] of Object.entries(REGIMES)) {
      const count = PNOT_RULES.filter((r) => r.regime === id).length;
      const extras =
        (id === "tx" ? TX_EXACT_RULES.length : 0) +
        OPT_OUT_RULES.filter((r) => r.regime === id).length;
      expect(count).toBe(regime.items.length + extras);
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

  it("a DENIAL of a right does not count as its disclosure (negation guard)", async () => {
    // Audit finding: "You have no right to access or delete personal
    // information" satisfied /right to (know|access|delete)/ and scored
    // the rights item as disclosed.
    const rule = PNOT_RULES.find((r) => r.id === "PNOT-CCPA-006")!;
    const denialCtx = withPnot(
      buildContext([
        "Privacy Policy",
        "You have no right to access or delete personal information under this policy.",
      ]),
    );
    const denialRun = await runEngine({
      rules: [rule],
      ctx: denialCtx,
      executed_at: "2026-07-15T00:00:00Z",
      source_file: SRC,
    });
    expect(denialRun.findings.find((f) => f.rule_id === rule.id)).toBeTruthy();

    // An unrelated nearby negation must NOT suppress a genuine disclosure
    // (over-suppression risk from the negation-FP campaign).
    const genuineCtx = withPnot(
      buildContext([
        "Privacy Policy",
        "We will not discriminate against you for exercising your right to access personal information.",
      ]),
    );
    const genuineRun = await runEngine({
      rules: [rule],
      ctx: genuineCtx,
      executed_at: "2026-07-15T00:00:00Z",
      source_file: SRC,
    });
    expect(genuineRun.findings.find((f) => f.rule_id === rule.id)).toBeFalsy();
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

describe("PNOT-TX exact-wording rules (§ 541.102(b)–(c))", () => {
  const sensitiveRule = TX_EXACT_RULES.find((r) => r.id === "PNOT-TX-007")!;
  const biometricRule = TX_EXACT_RULES.find((r) => r.id === "PNOT-TX-008")!;

  async function findingsFor(rule: (typeof TX_EXACT_RULES)[number], paragraphs: string[]) {
    const ctx = withPnot(buildContext(["Privacy Policy", ...paragraphs]));
    const run = await runEngine({
      rules: [rule],
      ctx,
      executed_at: "2026-07-17T00:00:00Z",
      source_file: SRC,
    });
    return run.findings.filter((f) => f.rule_id === rule.id);
  }

  it("is silent when the exact mandated notice is present (whitespace-normalized)", async () => {
    const found = await findingsFor(sensitiveRule, [
      "We may sell data as described below.",
      "NOTICE: We  may sell your\nsensitive personal data.",
    ]);
    expect(found).toHaveLength(0);
  });

  it("fires 'present but altered' on a paraphrased or re-cased notice, quoting it", async () => {
    const found = await findingsFor(sensitiveRule, [
      "Notice: we may sell your sensitive personal data.",
    ]);
    expect(found).toHaveLength(1);
    expect(found[0]!.title).toMatch(/present but altered/);
    expect(found[0]!.excerpt.text).toMatch(/we may sell your sensitive personal data/i);
  });

  it("fires 'missing' when the document indicates a sale of sensitive data with no notice", async () => {
    const found = await findingsFor(sensitiveRule, [
      "We may disclose or sell certain categories of sensitive data to our partners.",
    ]);
    expect(found).toHaveLength(1);
    expect(found[0]!.title).toMatch(/missing/);
  });

  it("is silent when the document never suggests selling that data (§3 honesty)", async () => {
    const found = await findingsFor(sensitiveRule, [
      "We collect your name and email. We do not sell personal data of any kind.",
      "We process sensitive data only with your consent.",
    ]);
    expect(found).toHaveLength(0);
  });

  it("the biometric rule mirrors the sensitive one and matches its own mandated text", async () => {
    const compliant = await findingsFor(biometricRule, [
      "NOTICE: We may sell your biometric personal data.",
    ]);
    expect(compliant).toHaveLength(0);
    const missing = await findingsFor(biometricRule, [
      "Biometric data we hold may be sold to verification vendors.",
    ]);
    expect(missing).toHaveLength(1);
    expect(missing[0]!.title).toMatch(/missing/);
  });
});

describe("PNOT opt-out disclosure rules (VA § 59.1-578(D) / TX § 541.103)", () => {
  const vaRule = OPT_OUT_RULES.find((r) => r.id === "PNOT-VA-007")!;
  const txRule = OPT_OUT_RULES.find((r) => r.id === "PNOT-TX-009")!;

  async function findingsFor(rule: (typeof OPT_OUT_RULES)[number], paragraphs: string[]) {
    const ctx = withPnot(buildContext(["Privacy Policy", ...paragraphs]));
    const run = await runEngine({
      rules: [rule],
      ctx,
      executed_at: "2026-07-17T00:00:00Z",
      source_file: SRC,
    });
    return run.findings.filter((f) => f.rule_id === rule.id);
  }

  it("fires when the notice says personal data is sold but never mentions opting out", async () => {
    const found = await findingsFor(vaRule, [
      "We may sell your personal information to marketing partners.",
    ]);
    expect(found).toHaveLength(1);
    expect(found[0]!.title).toMatch(/Opt-out disclosure missing/);
    expect(found[0]!.description).toMatch(/selling personal data/);
  });

  it("still fires when the only opt-out mention is a DENIAL ('you cannot opt out')", async () => {
    // Audit finding: the silencer accepted any opt-out token, including
    // the denial of the right — the opposite of the mandated disclosure.
    const found = await findingsFor(vaRule, [
      "We sell personal information to advertising partners.",
      "You cannot opt out of the sale of personal information.",
    ]);
    expect(found).toHaveLength(1);
  });

  it("catches an affirmative sale after a guarded CCPA link-text mention (all matches scanned)", async () => {
    // Audit finding: .exec inspected only the FIRST sale match — inside
    // the disclaimed 'Do Not Sell' link text — hiding the later sale.
    const found = await findingsFor(vaRule, [
      "Do Not Sell Or Share My Personal Information: California residents may submit requests under the CCPA.",
      "Separately, we sell personal information to advertising partners for consideration.",
    ]);
    expect(found).toHaveLength(1);
  });

  it("a disclaimer survives a citation dot ('as stated in Section 59.1 …')", async () => {
    // Audit finding: the '.' in '59.1' read as a sentence boundary,
    // truncating away 'We do not' and flipping the disclaimer into a
    // false accusation.
    const found = await findingsFor(vaRule, [
      "We do not, as stated in Section 59.1 of our charter, sell personal information to anyone.",
    ]);
    expect(found).toHaveLength(0);
  });

  it("fires on targeted advertising with no opt-out (TX § 541.103)", async () => {
    const found = await findingsFor(txRule, [
      "We process your personal data for targeted advertising across our services.",
    ]);
    expect(found).toHaveLength(1);
    expect(found[0]!.description).toMatch(/targeted advertising/);
  });

  it("is silent when an opt-out disclosure is present", async () => {
    const found = await findingsFor(vaRule, [
      "We may sell your personal information to marketing partners.",
      "You may opt out of the sale of your personal data at any time via our rights form.",
    ]);
    expect(found).toHaveLength(0);
  });

  it("is silent when the notice disclaims selling and targeted advertising (§3 honesty)", async () => {
    const found = await findingsFor(txRule, [
      "We do not sell your personal information.",
      "We do not process personal data for targeted advertising.",
    ]);
    expect(found).toHaveLength(0);
  });

  it("is silent when the notice never touches the subject at all", async () => {
    const found = await findingsFor(vaRule, [
      "We collect your name and email to provide the service.",
    ]);
    expect(found).toHaveLength(0);
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
