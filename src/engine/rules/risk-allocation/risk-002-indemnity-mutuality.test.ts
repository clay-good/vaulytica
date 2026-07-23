/**
 * RISK-002 indemnity-mutuality accounting.
 *
 * The rule tallied an indemnity sentence against a party whenever the party's
 * LEGAL NAME appeared anywhere in it. Two problems compounded:
 *
 *  - Contracts write the defined ROLE ("Vendor shall indemnify …"), not
 *    "Globex Services Inc. shall indemnify …", so both tallies stayed at zero
 *    and the rule returned early. It was effectively inert on ordinary drafting.
 *  - Counting any MENTION conflates indemnitor with indemnitee: "Customer shall
 *    indemnify Vendor" names both, so a wholly one-sided clause scored equally
 *    for each party and the asymmetry cancelled itself out.
 *
 * The tally now credits the INDEMNITOR — the party surface form (name or role)
 * closest before the verb.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../../_test-fixtures.js";
import { rule as risk002 } from "./RISK-002.js";

const PREAMBLE =
  'This Agreement is entered into between Acme Corporation, a Delaware corporation ("Customer"), and Globex Services Inc., a New York corporation ("Vendor").';
const doc = (...clauses: string[]) =>
  buildContext(["Services Agreement", PREAMBLE, ...clauses] as [string, ...string[]]);

describe("RISK-002 — indemnity mutuality", () => {
  it("flags a one-sided indemnity written with defined roles", () => {
    const finding = risk002.check(
      doc(
        "Indemnification. Customer shall indemnify Vendor against all third-party claims arising from the Services. Customer shall indemnify and hold harmless Vendor for any breach. Customer shall further indemnify Vendor against any regulatory penalty.",
      ),
    );
    expect(finding).not.toBeNull();
    // The indemnitor is credited, not merely every party the sentence names.
    expect(finding?.description).toContain("acme corporation=3");
    expect(finding?.description).toContain("globex services inc=0");
  });

  it("stays silent when both parties indemnify each other", () => {
    expect(
      risk002.check(
        doc(
          "Indemnification. Customer shall indemnify Vendor against all third-party claims. Vendor shall indemnify Customer against all third-party claims.",
        ),
      ),
    ).toBeNull();
  });

  it("stays silent when the document has no indemnity language", () => {
    expect(risk002.check(doc("Term. This Agreement runs for three years."))).toBeNull();
  });
});
