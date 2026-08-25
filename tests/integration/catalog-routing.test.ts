/**
 * End-to-end routing for the v5 and v6 catalog waves.
 *
 * Every other guard on these waves is structural: the rules exist, they are
 * gated, they fire on an empty document, they stay silent on a compliant
 * clause. None of them proves the thing a user actually depends on — that
 * dropping the document in front of them **reaches** the new family at all.
 * A playbook whose match features never win is 605 checks that never run.
 *
 * The failure mode is specific and easy to create: 120 new playbooks were
 * added to a matcher that scores every playbook against every document, so
 * a new family can lose to an older sibling on a document that is plainly
 * its own. This test drops a short, realistic instance of a representative
 * family from each wave and asserts the matcher picks it.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { matchPlaybook } from "../../src/playbooks/matcher.js";
import { parsePlaybooks } from "../../src/playbooks/loader.js";
import { buildTree } from "../../src/extract/_fixtures.js";
import { extractAll } from "../../src/extract/index.js";
import { loadStarterDkbSync } from "../../src/engine/_test-fixtures.js";
import { V5_RULES } from "../../src/engine/rules/v5/index.js";
import { V6_RULES } from "../../src/engine/rules/v6/index.js";

const PLAYBOOKS = parsePlaybooks(
  JSON.parse(readFileSync(join(process.cwd(), "playbooks", "extended.json"), "utf8")),
);
const dkb = loadStarterDkbSync();

/** A short, realistic instance of the family — a title and a few real clauses. */
const CASES: Array<{ id: string; title: string; body: string[] }> = [
  {
    id: "purchase-order-terms",
    title: "Purchase Order Terms and Conditions",
    body: [
      "Acceptance of this Purchase Order is expressly limited to its terms. Any additional or different terms proposed by Seller are rejected.",
      "Payment terms are net 30 from receipt of a conforming invoice. Goods conforming to the specifications shall be delivered F.O.B. destination.",
    ],
  },
  {
    id: "qdro",
    title: "Qualified Domestic Relations Order",
    body: [
      "The Alternate Payee shall receive a separate interest in the Plan as of the valuation date.",
      "The plan administrator shall determine whether this order is a qualified domestic relations order. Earnings and losses shall be allocated to the Alternate Payee's share.",
    ],
  },
  {
    id: "preliminary-lien-notice",
    title: "Preliminary Notice",
    body: [
      "You are hereby notified that the claimant has furnished labor and materials to the property described below.",
      "NOTICE TO PROPERTY OWNER: a mechanic's lien may be placed against your property even if you have paid your contractor in full.",
    ],
  },
  {
    id: "engagement-letter",
    title: "Engagement Letter",
    body: [
      "We are pleased to represent you. The scope of the representation is the matter described below, and we do not represent your affiliates.",
      "Our fees are billed at an hourly rate of $650. Conflicts of interest have been checked. Any retainer is held in our client trust account.",
    ],
  },
  {
    id: "privilege-log",
    title: "Privilege Log",
    body: [
      "The following documents are withheld on the basis of the attorney-client privilege and the work product doctrine.",
      "The author, recipients, date, and bates number are listed for each entry.",
    ],
  },
  {
    id: "complaint",
    title: "Complaint",
    body: [
      "Plaintiff alleges as follows. 1. This Court has jurisdiction under 28 U.S.C. § 1332.",
      "2. Venue is proper in this district. WHEREFORE, Plaintiff demands judgment against Defendant.",
    ],
  },
];

describe("v5 / v6 catalog routing", () => {
  it.each(CASES)("$id — a realistic instance reaches its own playbook", ({ id, title, body }) => {
    const tree = buildTree([title, ...body]);
    const extracted = extractAll(tree, {
      classifier: {
        vocab: { vocab: {} },
        patterns: dkb.classifier.patterns.map((p) => ({
          category: p.category,
          pattern: p.pattern,
        })),
      },
    });
    const match = matchPlaybook(extracted, extracted.classified, PLAYBOOKS, {
      title,
      body_text: [title, ...body].join("\n"),
    });
    expect(match.playbook_id, `${id} routed to ${match.playbook_id} instead`).toBe(id);
    // A family that only just wins is one sibling edit away from losing. The
    // matcher's own floor is 0.5; require a real margin above it.
    expect(match.confidence, `${id} matched at only ${match.confidence}`).toBeGreaterThanOrEqual(
      0.7,
    );
  });

  it("every v5 and v6 playbook the rules are gated to is in the served bundle", () => {
    // The rules are gated by playbook id. If a playbook never made it into
    // `playbooks/extended.json`, its whole ruleset is dead in the deployed
    // product while every unit test still passes.
    const served = new Set(PLAYBOOKS.map((p) => p.id));
    const gated = new Set([...V5_RULES, ...V6_RULES].flatMap((r) => r.applies_to_playbooks ?? []));
    const missing = [...gated].filter((id) => !served.has(id)).sort();
    expect(
      missing,
      `gated to playbooks absent from the served bundle: ${missing.join(", ")}`,
    ).toEqual([]);
  });
});
