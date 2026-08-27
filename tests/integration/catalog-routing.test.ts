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
import { matchPlaybook, titleCorpus } from "../../src/playbooks/matcher.js";
import { parsePlaybook, parsePlaybooks } from "../../src/playbooks/loader.js";
import { LAUNCH_PLAYBOOK_IDS } from "../../src/playbooks/registry.js";
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

/**
 * The competition the guard above cannot see.
 *
 * `PLAYBOOKS` is `playbooks/extended.json` alone — the 253 specialized
 * families. The live pipeline matches against those **plus** the twelve
 * launch playbooks, so a specialized family can be beaten by a launch one on
 * a document that is plainly not its own, and no guard here would notice.
 *
 * A hand-written law-firm engagement letter was: `employment-at-will-us`
 * reached 0.6 on one ubiquitous classifier category
 * (`confidentiality-obligation`, worth 0.4) plus the bare word "Employee",
 * which the letter used once in a boilerplate list of the people the firm is
 * NOT representing. `engagement-letter` also scored 0.6 — five of its own
 * distinguishing phrases, capped — and lost the tie to the lexicographic
 * rule, because "employment-at-will-us" sorts first. Every ENG check was
 * skipped and six generic contract warnings were raised about a document
 * that is not a bilateral bargain.
 *
 * The fix was the phrase, not the scoring: a single common noun that appears
 * in NDAs, leases, policies, and engagement letters does not distinguish an
 * employment offer, and the playbook's seven remaining phrases ("at-will",
 * "base compensation", "your position", "FLSA", …) all genuinely do.
 */
const LAUNCH = LAUNCH_PLAYBOOK_IDS.map((id) =>
  parsePlaybook(JSON.parse(readFileSync(join(process.cwd(), "playbooks", `${id}.json`), "utf8"))),
);

describe("a specialized family against the launch playbooks", () => {
  it("a law-firm engagement letter is not routed to the employment playbook", () => {
    // Deliberately shaped like the real thing: a letter has no styled title,
    // so its title corpus is the firm's letterhead and NO title keyword hits;
    // it has a confidentiality section (the classifier category the
    // employment playbook scores 0.4 on); and it says "employee" once, in a
    // boilerplate list of people the firm is NOT representing.
    const title = "Harlow & Vance LLP 1200 Bellweather Street, Suite 900 Columbus, Ohio 43215";
    const body: [string, ...string[]] = [
      title,
      "Re: Engagement for Representation — Trade Secret Litigation",
      "Thank you for asking us to represent Northgate Instrument Company (the “Client”) in the above matter.",
      "Scope of the Engagement. We will represent you in the matter described above. Our representation is limited to the Matter. We are not undertaking to represent any parent, subsidiary, affiliate, officer, director, or employee of the Client unless we agree in a separate writing.",
      "Our fees are based on the hourly rates in effect when the services are performed. Our current rates are $695 per hour for partners.",
      "Conflicts of Interest. We have run a conflicts check and have identified no conflict that prevents us from undertaking the Matter. We may represent another client in an unrelated matter adverse to you provided we have not obtained confidential information from you that is material to that matter.",
      "We will hold the retainer in our client trust account. Information you give us is protected by the attorney-client privilege and by our duty of confidentiality, and we will not disclose it except as you authorize.",
    ];
    const tree = buildTree(body);
    // The DKB patterns are passed WITH their flags, as the live pipeline
    // passes them: `confidentiality-obligation` is a case-insensitive
    // pattern, and dropping the flag is what keeps the category — and so the
    // tie this test exists to reproduce — from appearing at all.
    const extracted = extractAll(tree, {
      classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
    });
    const match = matchPlaybook(extracted, extracted.classified, [...LAUNCH, ...PLAYBOOKS], {
      title,
      body_text: body.join("\n"),
    });
    expect(match.playbook_id, `routed to ${match.playbook_id}`).toBe("engagement-letter");
  });
});

/**
 * A court filing names itself BELOW its caption, and the response to a
 * discovery request necessarily carries the request's own name in its title.
 *
 * Both cost this document its routing. A defendant's responses and objections
 * to interrogatories reached the matcher as "IN THE UNITED STATES DISTRICT
 * COURT FOR THE NORTHERN DISTRICT OF ILLINOIS" — the name of a courthouse,
 * the same for every filing — matched no title keyword, scored 0.6 on
 * "plaintiff", "venue", and "jury", and routed to `complaint`, which reported
 * at `critical` that it had no jurisdictional statement, no demand for relief,
 * and no jury demand. It is a discovery response; it is not supposed to have
 * any of them.
 *
 * With the caption title read it routed to `interrogatories` instead — the
 * PROPOUNDING family, whose title keywords ("interrogatories", "first set of
 * interrogatories") are a literal substring of the response's title. The
 * propounding playbooks now carry the response-only language as negative
 * features: no set of interrogatories contains "subject to and without
 * waiving", "general objections", or "objects to this interrogatory".
 */
describe("a discovery response against the request it answers", () => {
  it("responses and objections route to discovery-responses, not to the request or the complaint", () => {
    const body: [string, ...string[]] = [
      "IN THE UNITED STATES DISTRICT COURT FOR THE NORTHERN DISTRICT OF ILLINOIS EASTERN DIVISION",
      "RIDGELINE AEROSPACE COMPONENTS, INC.,",
      "Plaintiff,",
      "v. Case No. 1:26-cv-04412 Hon. Marisol Aguirre-Vance HALLORAN PRECISION CASTINGS, LLC,",
      "Defendant.",
      "DEFENDANT'S RESPONSES AND OBJECTIONS TO PLAINTIFF'S FIRST SET OF INTERROGATORIES",
      "Pursuant to Rules 26 and 33 of the Federal Rules of Civil Procedure, Defendant responds and objects as follows.",
      "GENERAL OBJECTIONS",
      "Halloran objects to each interrogatory to the extent it seeks information protected by the attorney-client privilege. Venue and jurisdiction are not disputed.",
      "INTERROGATORY NO. 1: Identify each person with knowledge of the dimensional inspection.",
      "RESPONSE: Halloran objects to this interrogatory as overbroad. Subject to and without waiving the foregoing objections, Halloran responds: Dermot Halloran and Ana Petrosyan.",
      "VERIFICATION. I have read the foregoing responses to interrogatories. Plaintiff may demand a jury.",
    ];
    const tree = buildTree(body);
    const extracted = extractAll(tree, {
      classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
    });
    const match = matchPlaybook(extracted, extracted.classified, [...LAUNCH, ...PLAYBOOKS], {
      title: titleCorpus(tree, "responses.txt"),
      body_text: body.join("\n"),
    });
    expect(match.playbook_id, `routed to ${match.playbook_id}`).toBe("discovery-responses");
  });
});
