import { describe, expect, it } from "vitest";
import { LAUNCH_RULES } from "../engine/rules/index.js";
import { ESTATE_CHECK_RULES } from "../engine/rules/v4/trust-estate/estate-checks.js";
import { activateEstateChecks, ESTATE_CHECK_PLAYBOOK_IDS } from "./activate.js";

describe("activateEstateChecks", () => {
  it("is a no-op when the assertion is not made", () => {
    const w = activateEstateChecks(false, "last-will-and-testament", LAUNCH_RULES);
    expect(w.rules).toBe(LAUNCH_RULES);
    expect(w.estate_checks_asserted).toBeUndefined();
  });

  it("is a no-op for a non-will playbook even when asserted", () => {
    const w = activateEstateChecks(true, "mutual-nda", LAUNCH_RULES);
    expect(w.rules).toBe(LAUNCH_RULES);
  });

  it("adds the EST rules and stamps the assertion for each will/trust/codicil playbook", () => {
    for (const id of ESTATE_CHECK_PLAYBOOK_IDS) {
      const w = activateEstateChecks(true, id, LAUNCH_RULES);
      expect(w.rules.length, id).toBe(LAUNCH_RULES.length + ESTATE_CHECK_RULES.length);
      expect(w.estate_checks_asserted, id).toBe(true);
    }
  });

  it("every estate-check rule declares the assertion gate and the playbook gate", () => {
    for (const r of ESTATE_CHECK_RULES) {
      expect(r.assertion_gate, r.id).toBe("estate-checks");
      expect(r.applies_to_playbooks, r.id).toContain("last-will-and-testament");
    }
  });

  it("--state implies the pack and stamps the normalized state", () => {
    const w = activateEstateChecks(false, "last-will-and-testament", LAUNCH_RULES, "us-pa");
    expect(w.estate_checks_asserted).toBe(true);
    expect(w.asserted_state).toBe("us-pa");
    expect(w.rules.length).toBe(LAUNCH_RULES.length + ESTATE_CHECK_RULES.length);
  });

  it("--state on a non-will playbook stays a no-op", () => {
    const w = activateEstateChecks(false, "mutual-nda", LAUNCH_RULES, "us-pa");
    expect(w.rules).toBe(LAUNCH_RULES);
    expect(w.asserted_state).toBeUndefined();
  });

  it("without --state the appended rules are the exact neutral constants (hash stability)", () => {
    const w = activateEstateChecks(true, "last-will-and-testament", LAUNCH_RULES);
    const appended = w.rules.slice(LAUNCH_RULES.length);
    for (let i = 0; i < ESTATE_CHECK_RULES.length; i++) {
      expect(appended[i]).toBe(ESTATE_CHECK_RULES[i]);
    }
    expect(w.asserted_state).toBeUndefined();
  });

  it("an unseeded state runs the neutral rules unchanged (honest N/A) but is still stamped", () => {
    // The formalities catalog now covers all 50 states + DC, so no real
    // state exercises this path — but the honest-N/A fallback survives in
    // code for ids the catalog lacks (the CLI normalizes and rejects
    // these first; direct callers still get neutral rules, never a guess).
    const w = activateEstateChecks(false, "last-will-and-testament", LAUNCH_RULES, "us-zz");
    expect(w.asserted_state).toBe("us-zz");
    const appended = w.rules.slice(LAUNCH_RULES.length);
    expect(appended.length).toBe(ESTATE_CHECK_RULES.length);
    for (let i = 0; i < ESTATE_CHECK_RULES.length; i++) {
      expect(appended[i]).toBe(ESTATE_CHECK_RULES[i]);
    }
  });

  it("a seeded witness-expecting state appends EST-107; PA (zero-witness) does not", () => {
    const ca = activateEstateChecks(false, "last-will-and-testament", LAUNCH_RULES, "us-ca");
    const caAppended = ca.rules.slice(LAUNCH_RULES.length);
    expect(caAppended.length).toBe(ESTATE_CHECK_RULES.length + 1);
    const est107 = caAppended[caAppended.length - 1]!;
    expect(est107.id).toBe("EST-107");
    expect(est107.default_severity).toBe("warning");
    expect(est107.assertion_gate).toBe("estate-checks");
    // The neutral constants come first, unswapped (CA has no variants).
    for (let i = 0; i < ESTATE_CHECK_RULES.length; i++) {
      expect(caAppended[i]).toBe(ESTATE_CHECK_RULES[i]);
    }

    // PA expects zero witnesses — no statute count to enforce.
    const pa = activateEstateChecks(false, "last-will-and-testament", LAUNCH_RULES, "us-pa");
    expect(pa.rules.some((r) => r.id === "EST-107")).toBe(false);

    // CO's EST-107 is conditional in check() (silent when a notarial
    // acknowledgment is detected), not severity-downgraded.
    const co = activateEstateChecks(false, "last-will-and-testament", LAUNCH_RULES, "us-co");
    const coEst107 = co.rules.find((r) => r.id === "EST-107")!;
    expect(coEst107.default_severity).toBe("warning");
    expect(coEst107.dkb_citations).toContain("co-rev-stat-15-11-502");
  });

  it("a seeded state swaps in overlay-aware variants for the adapted rules only", () => {
    const w = activateEstateChecks(false, "last-will-and-testament", LAUNCH_RULES, "us-pa");
    const appended = w.rules.slice(LAUNCH_RULES.length);
    const byId = new Map(appended.map((r) => [r.id, r]));
    // PA: witness-related absence downgrades to info citing 20 Pa. C.S. § 2502.
    expect(byId.get("EST-101")!.default_severity).toBe("info");
    expect(byId.get("EST-105")!.default_severity).toBe("info");
    expect(byId.get("EST-101")!.dkb_citations).toContain("pa-20-pacs-2502");
    // Unadapted rules keep their exact neutral objects.
    expect(byId.get("EST-201")).toBe(ESTATE_CHECK_RULES.find((r) => r.id === "EST-201"));
    expect(byId.get("EST-102")).toBe(ESTATE_CHECK_RULES.find((r) => r.id === "EST-102"));
  });

  it("LA escalates the notary block to a warning; CO keeps EST-105 severity but rewords", () => {
    const la = activateEstateChecks(false, "last-will-and-testament", LAUNCH_RULES, "us-la");
    const laById = new Map(la.rules.slice(LAUNCH_RULES.length).map((r) => [r.id, r]));
    expect(laById.get("EST-103")!.default_severity).toBe("warning");
    expect(laById.get("EST-103")!.dkb_citations).toContain("la-civ-code-1577");

    const co = activateEstateChecks(false, "last-will-and-testament", LAUNCH_RULES, "us-co");
    const coById = new Map(co.rules.slice(LAUNCH_RULES.length).map((r) => [r.id, r]));
    expect(coById.get("EST-105")!.default_severity).toBe("warning");
    expect(coById.get("EST-105")).not.toBe(ESTATE_CHECK_RULES.find((r) => r.id === "EST-105"));
    expect(coById.get("EST-105")!.dkb_citations).toContain("co-rev-stat-15-11-502");
  });
});
