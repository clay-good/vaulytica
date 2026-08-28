/**
 * Nine compliance-policy checks could not fire on the policy they check.
 *
 * `present_patterns` defaults to an OR, and in each of these the first or
 * second pattern was the family's own name — /fcpa/ on the "Anti-Bribery /
 * Anti-Corruption Policy (FCPA / UKBA)", /insider trading/ on the "Insider
 * Trading Policy", /retention/ on the "Document Retention Policy",
 * /conflict of interest/ on the "Conflict of Interest Policy". The title is
 * always there, so the check never reported anything, on any document.
 *
 * The patterns were never synonyms: they are pillars — the topic, the
 * requirement, and the object it applies to — so they are conjoined.
 *
 * Both directions for each: a policy drafted the way the rule's own
 * recommendation asks must stay silent, and a policy that names the subject
 * and says nothing about it must fire.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../../../_test-fixtures.js";
import { V4_RULES } from "../index.js";

const rule = (id: string) => {
  const r = V4_RULES.find((x) => x.id === id);
  if (!r) throw new Error(`no rule ${id}`);
  return r;
};

type Case = { id: string; title: string; compliant: string };

const CASES: Case[] = [
  {
    id: "POL-006",
    title: "Anti-Bribery / Anti-Corruption Policy (FCPA / UKBA)",
    compliant:
      "The FCPA prohibits offering, promising, or giving anything of value to a foreign official to obtain or retain business. No employee may offer or pay a bribe to any government official, directly or through a third party.",
  },
  {
    id: "POL-010",
    title: "Anti-Bribery / Anti-Corruption Policy (FCPA / UKBA)",
    compliant:
      "This policy applies on a cross-border basis. The UK Bribery Act 2010 creates a corporate offence of failure to prevent bribery, and the Company maintains adequate procedures designed to prevent bribery by associated persons.",
  },
  {
    id: "POL-012",
    title: "Anti-Money-Laundering Policy",
    compliant:
      "The Company maintains an anti-money-laundering program. The Board has designated a BSA/AML compliance officer responsible for day-to-day administration. The program includes annual training, independent testing, and customer due diligence.",
  },
  {
    id: "POL-018",
    title: "Insider Trading Policy",
    compliant:
      "No employee may trade in Company securities while in possession of material non-public information. Insider trading is prohibited by federal law and by this policy, and applies to tipping others.",
  },
  {
    id: "POL-019",
    title: "Insider Trading Policy",
    compliant:
      "A quarterly blackout period begins two weeks before the end of each fiscal quarter and ends after earnings are released. Section 16 officers and directors must obtain pre-clearance from the General Counsel before any transaction.",
  },
  {
    id: "POL-030",
    title: "Document Retention Policy",
    compliant:
      "Electronically stored information, including email, cloud-hosted files, and data on mobile devices, is subject to the retention schedule below and to the same destruction rules as paper records.",
  },
  {
    id: "POL-033",
    title: "Conflict of Interest Policy",
    compliant:
      "A conflict of interest exists whenever a director, officer, or employee has a financial interest in, or a business relationship with, a party transacting with the Company, or where a family member holds such an interest.",
  },
  {
    id: "POL-047",
    title: "Lobbying / Political Contribution Policy",
    compliant:
      "No lobbying expenditure may be incurred without the prior approval of the General Counsel, and no employee may engage a covered official on the Company's behalf without pre-approval.",
  },
  {
    id: "POL-048",
    title: "Lobbying / Political Contribution Policy",
    compliant:
      "The Federal Election Campaign Act prohibits corporate contributions to federal candidates. No corporate political contributions may be made. Individual employees may contribute personally, and the Company's PAC may make contributions consistent with FECA.",
  },
];

describe.each(CASES)("$id — can fire, and reads a compliant policy", ({ id, title, compliant }) => {
  it("reports the requirement missing when the policy only names its subject", () => {
    const f = rule(id).check(
      buildContext([title, "This policy is reviewed annually by the Board."]),
    );
    expect(f, `${id} cannot fire — its family's title alone satisfies it`).not.toBeNull();
  });

  it("stays silent on a policy that states the requirement", () => {
    const f = rule(id).check(buildContext([title, compliant]));
    expect(f, `${id} flagged a compliant policy: ${f?.title ?? ""}`).toBeNull();
  });
});
