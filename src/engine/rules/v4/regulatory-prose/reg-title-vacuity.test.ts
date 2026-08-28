/**
 * Six securities-filing checks could not fire on the filing they check.
 *
 * `present_patterns` defaults to an OR, and in each of these one pattern was
 * a word from the family's own name — "Brochure" and "Part 2A" on the "Form
 * ADV Part 2A Brochure", "Risk" on "S-1 Risk Factors", "10-K" on "10-K Risk
 * Factors", "Offering Circular" on the "Reg A+ Offering Circular". An S-1
 * whose risk-factor section said nothing about cybersecurity scored clean,
 * because the words "S-1 Risk Factors" contain "risk".
 *
 * The patterns are pillars, so they are conjoined. REG-016's second pillar
 * also had to be broadened first: the conventional S-1 introduction is "You
 * should carefully consider the risks described below", and requiring the
 * words "material risks" would have flagged the standard drafting.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../../../_test-fixtures.js";
import { V4_RULES } from "../index.js";

const rule = (id: string) => {
  const r = V4_RULES.find((x) => x.id === id);
  if (!r) throw new Error(`no rule ${id}`);
  return r;
};

const CASES: Array<{ id: string; title: string; compliant: string }> = [
  {
    id: "REG-008",
    title: "Form ADV Part 2A Brochure",
    compliant:
      "This brochure cover page provides information about the qualifications and business practices of the Adviser. Item 2 — Material Changes. Since the last annual update, the Adviser has revised its fee schedule.",
  },
  {
    id: "REG-016",
    title: "S-1 Risk Factors (prose only)",
    compliant:
      "RISK FACTORS. You should carefully consider the risks described below, together with the other information in this prospectus, before deciding to invest in our common stock.",
  },
  {
    id: "REG-022",
    title: "S-1 Risk Factors (prose only)",
    compliant:
      "A cybersecurity incident or data breach could disrupt our operations, expose customer information, and subject us to regulatory penalties and litigation.",
  },
  {
    id: "REG-023",
    title: "S-1 Risk Factors (prose only)",
    compliant:
      "Climate change presents both physical and transition risk to our operations, including exposure to severe weather at our manufacturing sites and future limits on greenhouse gas emissions.",
  },
  {
    id: "REG-024",
    title: "10-K Risk Factors (prose only)",
    compliant:
      "The following risk factors have been updated since our prior annual report on Form 10-K to reflect changes in our supply chain and the addition of a new manufacturing facility.",
  },
  {
    id: "REG-034",
    title: "Reg A+ Offering Circular",
    compliant:
      "This offering circular follows the Form 1-A item structure. Part I contains the notification, Part II the offering circular itself, and Part III the exhibits.",
  },
];

describe.each(CASES)("$id — can fire, and reads a compliant filing", ({ id, title, compliant }) => {
  it("reports the item missing when the filing only carries its own title", () => {
    const f = rule(id).check(
      buildContext([title, "This document was filed with the Commission on March 14, 2026."]),
    );
    expect(f, `${id} cannot fire — its family's title alone satisfies it`).not.toBeNull();
  });

  it("stays silent on a filing that carries the item", () => {
    const f = rule(id).check(buildContext([title, compliant]));
    expect(f, `${id} flagged a compliant filing: ${f?.title ?? ""}`).toBeNull();
  });
});
