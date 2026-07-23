/**
 * A parenthetical names a term for the ordinary noun it follows, so that noun
 * keeps appearing in lowercase for its ordinary meaning: a CCPA addendum that
 * defines `acting as service provider ("Service Provider")` then writes
 * 'Service Provider is a "service provider" as defined in Cal. Civ. Code', and
 * an MFN clause that defines `("Customer")` then promises terms "no less
 * favorable than those offered to any other customer".
 *
 * Both are correct drafting. Only an express definition constitutes a term
 * whose lowercase use is the slip these rules exist to report.
 */
import { describe, expect, it } from "vitest";
import { rule as STRUCT_009 } from "./STRUCT-009.js";
import { rule as STRUCT_014 } from "./STRUCT-014.js";
import { buildContext } from "../../_test-fixtures.js";

describe("capitalization rules and the parenthetical form", () => {
  it("does not call the ordinary noun behind a parenthetical a slip", () => {
    const ctx = buildContext([
      "Pricing",
      'Globex Solutions Inc., a California corporation acting as service provider ("Service Provider"), shall provide the Services.',
      'For purposes of the CCPA/CPRA, Service Provider is a "service provider" as defined in Cal. Civ. Code § 1798.140(ag).',
    ]);
    expect(STRUCT_009.check(ctx)).toBeNull();
    expect(STRUCT_014.check(ctx)).toBeNull();
  });

  it("still reports a lowercase use of an expressly defined term", () => {
    const ctx = buildContext([
      "Definitions",
      '"Confidential Information" means all non-public information disclosed by either party.',
      "Recipient shall protect confidential information with reasonable care.",
    ]);
    expect(STRUCT_009.check(ctx)).not.toBeNull();
  });
});

describe("the reasonable-care 'own confidential information' idiom is not a slip", () => {
  const ctx = () =>
    buildContext(
      ["Mutual NDA", "This Agreement is between Acme Inc. and Globex Inc."],
      [
        "Definitions",
        '"Confidential Information" means any non-public information disclosed by a party.',
      ],
      [
        "Care",
        "Each party shall protect the other party's Confidential Information using the same degree of care it uses to protect its own confidential information of like importance, but in no event less than reasonable care.",
      ],
    );

  it("STRUCT-009 stays silent on 'its own confidential information'", () => {
    expect(STRUCT_009.check(ctx())).toBeNull();
  });

  it("STRUCT-014 stays silent on 'its own confidential information'", () => {
    expect(STRUCT_014.check(ctx())).toBeNull();
  });

  it("STRUCT-009 still fires on a genuine lowercase use of the defined term", () => {
    const slip = buildContext(
      ["Mutual NDA", "This Agreement is between Acme Inc. and Globex Inc."],
      [
        "Definitions",
        '"Confidential Information" means any non-public information disclosed by a party.',
      ],
      [
        "Use",
        "The receiving party shall not disclose the confidential information to any third party.",
      ],
    );
    expect(STRUCT_009.check(slip)).not.toBeNull();
  });
});
