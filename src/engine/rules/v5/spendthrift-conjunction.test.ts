/**
 * EST-402 asserted a statutory conjunction and checked an OR.
 *
 * Its own rationale states the rule: "UTC § 502 makes a spendthrift provision
 * valid only if it restrains BOTH voluntary and involuntary transfer. A
 * clause restraining only one is ineffective as a spendthrift provision."
 *
 * `pat` defaults to an OR, so a trust whose "Spendthrift" article restrained
 * the beneficiary alone — leaving every creditor free to reach the interest,
 * which is exactly the clause § 502 says does not work — scored clean on a
 * CRITICAL check. So did one that barred creditors and let the beneficiary
 * assign.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../../_test-fixtures.js";
import { V5_RULES } from "./index.js";

const EST_402 = (() => {
  const r = V5_RULES.find((x) => x.id === "EST-402");
  if (!r) throw new Error("no EST-402");
  return r;
})();

const trust = (...rest: string[]) => buildContext(["Revocable Living Trust", ...rest]);

describe("EST-402 — both directions of restraint", () => {
  it("stays silent on a clause restraining both, as the corpus trust does", () => {
    const f = EST_402.check(
      trust(
        "Spendthrift. No beneficiary may voluntarily or involuntarily transfer, assign, anticipate, or encumber any beneficial interest in this Trust. No creditor of any beneficiary or any attachment may reach any beneficial interest before actual payment to such beneficiary.",
      ),
    );
    expect(f, `EST-402 flagged a complete spendthrift clause: ${f?.title ?? ""}`).toBeNull();
  });

  it("stays silent on the other conventional phrasing", () => {
    const f = EST_402.check(
      trust(
        "Spendthrift Provision. The interests of each beneficiary are not subject to voluntary or involuntary alienation and shall not be reached by any creditor or by legal process.",
      ),
    );
    expect(f, `EST-402 flagged a complete spendthrift clause: ${f?.title ?? ""}`).toBeNull();
  });

  it("fires when only the beneficiary is restrained", () => {
    // § 502's ineffective clause: the beneficiary cannot assign, but nothing
    // stops a creditor from reaching the interest.
    const f = EST_402.check(
      trust(
        "Spendthrift. No beneficiary may assign, anticipate, pledge, or encumber any beneficial interest in this Trust.",
      ),
    );
    expect(f, "EST-402 accepted a one-directional spendthrift clause").not.toBeNull();
  });

  it("fires when only creditors are restrained", () => {
    const f = EST_402.check(
      trust(
        "Spendthrift. No creditor of any beneficiary may reach any beneficial interest by attachment, garnishment, or other legal process.",
      ),
    );
    expect(f, "EST-402 accepted a one-directional spendthrift clause").not.toBeNull();
  });

  it("still fires when the trust has no spendthrift clause at all", () => {
    const f = EST_402.check(
      trust("The Trustee shall distribute income and principal to the beneficiaries quarterly."),
    );
    expect(f).not.toBeNull();
  });
});
