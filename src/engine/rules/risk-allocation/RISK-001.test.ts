/**
 * RISK-001 detects indemnification language and fires when it is absent. It
 * required "hold" and "harmless" to be adjacent, but the indemnitee is
 * routinely named between them — "hold Client harmless", "hold the other
 * party harmless" — so a plainly present indemnity was reported as missing.
 */
import { describe, expect, it } from "vitest";
import { rule as RISK_001 } from "./RISK-001.js";
import { buildContext } from "../../_test-fixtures.js";

const doc = (...paras: string[]) => buildContext(["Indemnification", ...paras]);

describe("RISK-001 — indemnification present", () => {
  it("reads 'hold Client harmless' with the indemnitee named between the words", () => {
    expect(
      RISK_001.check(
        doc("Consultant will defend and hold Client harmless from third-party claims."),
      ),
    ).toBeNull();
  });

  it("reads 'hold the other party harmless'", () => {
    expect(
      RISK_001.check(doc("Each party shall hold the other party harmless from any loss.")),
    ).toBeNull();
  });

  it("still reads the adjacent 'hold harmless' form", () => {
    expect(RISK_001.check(doc("Company shall hold harmless the other party."))).toBeNull();
  });

  it("still reads 'indemnify'", () => {
    expect(RISK_001.check(doc("Vendor shall indemnify Customer against all claims."))).toBeNull();
  });

  it("fires when no indemnification language appears at all", () => {
    expect(
      RISK_001.check(doc("Each party is responsible for its own acts under this Agreement.")),
    ).not.toBeNull();
  });

  it("does not treat an unrelated 'hold' as indemnity", () => {
    expect(
      RISK_001.check(doc("The Receiving Party shall hold all information in strict confidence.")),
    ).not.toBeNull();
  });
});
