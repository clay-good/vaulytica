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
import { MATCH_THRESHOLD, MATCH_WEIGHTS } from "../../src/playbooks/types.js";
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

/**
 * The legend above the title.
 *
 * "EXECUTION VERSION" and "CONFIDENTIAL" sit on the first line of a very large
 * share of real negotiated documents, and they were what the matcher scored.
 * A mutual NDA carrying them routed to `unilateral-nda` — the mutual
 * playbook's title keyword never hit, and the unilateral one won on "the
 * Disclosing Party" / "the Receiving Party", which a mutual NDA uses too
 * because each party is both. This is the launch families' own routing, so it
 * is the widest of the three title-corpus holes found here.
 */
describe("a legend above the title", () => {
  it("a mutual NDA stamped EXECUTION VERSION is not routed to the unilateral playbook", () => {
    const body: [string, ...string[]] = [
      "EXECUTION VERSION",
      "CONFIDENTIAL",
      "MUTUAL NON-DISCLOSURE AGREEMENT",
      'This Mutual Non-Disclosure Agreement (this "Agreement") is entered into by Northgate Instrument Company ("Northgate") and Cardinal Metrology, Inc. ("Cardinal"), each a "Party".',
      "Each Party may disclose Confidential Information to the other. The Receiving Party shall protect the Disclosing Party's Confidential Information and shall not disclose it to any third party.",
      "Each Party is both a Disclosing Party and a Receiving Party under this Agreement.",
    ];
    const tree = buildTree(body);
    const extracted = extractAll(tree, {
      classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
    });
    const match = matchPlaybook(extracted, extracted.classified, [...LAUNCH, ...PLAYBOOKS], {
      title: titleCorpus(tree, "nda.txt"),
      body_text: body.join("\n"),
    });
    expect(match.playbook_id, `routed to ${match.playbook_id}`).toBe("mutual-nda");
  });
});

/**
 * The restrictive-securities legend, and the title keyword that is a substring
 * of every sibling's title.
 *
 * "THIS NOTE AND THE SECURITIES ISSUABLE UPON CONVERSION HEREOF HAVE NOT BEEN
 * REGISTERED UNDER THE SECURITIES ACT OF 1933 …" opens essentially every note,
 * warrant, SAFE, and stock certificate — and it is a whole uppercase SENTENCE
 * rather than a stamp, so the legend-line rule did not catch it. It cost a
 * genuine convertible promissory note its routing twice over: the preamble was
 * the legend, and `promissory-note` carried the bare title keyword "note",
 * which matches inside the word NOTE in the legend AND inside every sibling's
 * title. Every conversion check — valuation cap, discount, qualified
 * financing, change-of-control premium, the accredited-investor
 * representation — was skipped.
 */
describe("a convertible note against its plainer sibling", () => {
  it("is not routed to promissory-note", () => {
    // The empty first element is the heading: pasted text and plain text carry
    // no styled heading, so the legend arrives as the first PARAGRAPH — which
    // is what made it the preamble the matcher scored.
    const body: [string, ...string[]] = [
      "",
      "THIS NOTE AND THE SECURITIES ISSUABLE UPON CONVERSION HEREOF HAVE NOT BEEN REGISTERED UNDER THE SECURITIES ACT OF 1933, AS AMENDED, AND MAY NOT BE OFFERED OR SOLD EXCEPT PURSUANT TO AN EFFECTIVE REGISTRATION STATEMENT OR AN AVAILABLE EXEMPTION.",
      "CONVERTIBLE PROMISSORY NOTE",
      'FOR VALUE RECEIVED, Northgate Instrument Company (the "Company") promises to pay to the order of Fairhaven Seed Partners, LP the principal sum of $500,000.',
      "All outstanding principal and accrued interest automatically convert upon a Qualified Financing at the lesser of a discount to the price per share and the price obtained by dividing the Valuation Cap by the fully diluted capitalization.",
      "Unless earlier converted, all outstanding principal and accrued interest are due on the Maturity Date.",
      "This Note is subordinated in right of payment to the Company's senior indebtedness. Subordination applies to each holder in the series.",
      "This Note may be amended only with the written consent of the Company and the holders of a majority in principal amount of the notes issued in the same series.",
    ];
    const tree = buildTree(body);
    const extracted = extractAll(tree, {
      classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
    });
    const match = matchPlaybook(extracted, extracted.classified, [...LAUNCH, ...PLAYBOOKS], {
      title: titleCorpus(tree, "note.txt"),
      body_text: body.join("\n"),
    });
    expect(match.playbook_id, `routed to ${match.playbook_id}`).toBe("convertible-note");
  });

  it("a plain promissory note still reaches its own playbook", () => {
    // The bare "note" keyword was removed, so the specific forms have to carry
    // it: this is the check that they do.
    const body: [string, ...string[]] = [
      "",
      "PROMISSORY NOTE",
      'FOR VALUE RECEIVED, the undersigned (the "Maker") promises to pay to the order of Fairhaven Capital (the "Payee") the principal amount of $250,000.',
      "Interest accrues at the interest rate of six percent per annum until the maturity date.",
    ];
    const tree = buildTree(body);
    const extracted = extractAll(tree, {
      classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
    });
    const match = matchPlaybook(extracted, extracted.classified, [...LAUNCH, ...PLAYBOOKS], {
      title: titleCorpus(tree, "note.txt"),
      body_text: body.join("\n"),
    });
    expect(match.playbook_id, `routed to ${match.playbook_id}`).toBe("promissory-note");
  });
});

/**
 * Self-reachability: every family must win on a document that names itself and
 * speaks its own vocabulary.
 *
 * The three routing defects fixed on 2026-08-27 were each a family that could
 * not be reached — an engagement letter beaten by an employment playbook, a
 * convertible note beaten by `promissory-note`, a discovery response beaten by
 * the request it answers — and each was found by hand, one document at a time.
 * This is the mechanical version: for every playbook, a document titled with
 * its first title keyword whose body carries three of its own distinguishing
 * phrases. If that does not reach it, some sibling is taking its documents.
 *
 * It is deliberately a weak document (a title and three phrases, nothing
 * else), because the point is the FLOOR: a family that cannot win on its own
 * vocabulary cannot win on a real document either.
 */
const PERSPECTIVE_PAIRS = new Map<string, string[]>([
  // A document does not say which SIDE of it you are on, and it does not say
  // whether you want the launch pack or its deep successor. Both are the
  // user's choice (`--role`, `--playbook`), not the document's, so these
  // legitimately lose to a sibling that reads the same text. Every OTHER
  // playbook must reach itself.
  //
  // The two MSA-deep entries also list "master subscription agreement", which
  // is the canonical title of a SaaS agreement — a document so titled reaching
  // `saas-customer` is the right answer, not a shadow.
  ["msa-customer-deep", ["saas-customer"]],
  ["msa-vendor-deep", ["msa-general", "saas-customer"]],
  ["mutual-nda-deep", ["mutual-nda"]],
  ["saas-vendor", ["saas-customer"]],
  ["scc-module-3", ["scc-module-2"]],
  ["unilateral-nda", ["unilateral-nda-deep"]],
]);

describe("every playbook is reachable by its own name and vocabulary", () => {
  // A 265-playbook x every-title-keyword sweep: seconds, not milliseconds, and
  // slower again under coverage instrumentation. An explicit budget keeps it
  // from flaking against the 5s default on a loaded runner.
  it("no family is shadowed by a sibling", () => {
    const shadowed: string[] = [];
    let checked = 0;
    for (const pb of [...LAUNCH, ...PLAYBOOKS]) {
      if (pb.id === "generic-fallback") continue;
      const phrases = pb.match_features.distinguishing_phrases.slice(0, 3);
      // Every playbook in the catalog has at least one title keyword and three
      // distinguishing phrases; asserting it here keeps the sweep from
      // silently shrinking if one ever does not.
      expect(
        pb.match_features.title_keywords.length,
        `${pb.id} has no title keyword`,
      ).toBeGreaterThan(0);
      expect(phrases.length, `${pb.id} has fewer than three distinguishing phrases`).toBe(3);
      checked += 1;
      // EVERY title keyword, not just the first. `convertible-note` reached
      // itself under "convertible note" and lost under "convertible
      // promissory note", because the longer title is the one that also
      // contains a sibling's keyword — which is exactly the defect this sweep
      // exists to catch.
      for (const kw of pb.match_features.title_keywords) {
        const body: [string, ...string[]] = [
          "",
          kw.toUpperCase(),
          `This document is made as of January 1, 2026. ${phrases.join(". ")}.`,
        ];
        const tree = buildTree(body);
        const extracted = extractAll(tree, {
          classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
        });
        const match = matchPlaybook(extracted, extracted.classified, [...LAUNCH, ...PLAYBOOKS], {
          title: titleCorpus(tree, "d.txt"),
          body_text: body.join("\n"),
        });
        if (match.playbook_id === pb.id) continue;
        if (PERSPECTIVE_PAIRS.get(pb.id)?.includes(match.playbook_id)) continue;
        shadowed.push(`${pb.id} -> ${match.playbook_id} @${match.confidence} (title "${kw}")`);
      }
    }
    expect(checked, "the sweep found no playbooks — it is broken").toBeGreaterThan(250);
    expect(shadowed.sort(), `shadowed by a sibling:\n  ${shadowed.sort().join("\n  ")}`).toEqual(
      [],
    );
  });
});

/**
 * The mirror of the self-reachability sweep: no family may claim a document
 * that is nobody's.
 *
 * Self-reachability asks whether a family can win its OWN document. It cannot
 * see the opposite failure — a family whose "distinguishing" phrases are so
 * common that it wins documents belonging to somebody else. `code-of-conduct`
 * listed four bare nouns ("directors", "officers", "employees", "waiver"), all
 * four of which appear in the indemnity clause of essentially every commercial
 * contract, and reached 0.6 with NO title match at all. A construction
 * subcontract routed to it and was told at `critical` that it was missing its
 * SOX § 406 elements clause and its non-retaliation channel.
 *
 * The document below is deliberately nobody's: a title that names no family,
 * and only the clauses every commercial agreement carries. Nothing should
 * reach the 0.5 threshold on it, and the matcher should fall back.
 */
const NOBODYS_DOCUMENT: [string, ...string[]] = [
  "",
  "AGREEMENT",
  'This Agreement is made as of January 1, 2026 between Acme Inc. ("Acme") and Globex Inc. ("Globex"), each a "party".',
  "Each party shall indemnify, defend, and hold harmless the other and its officers, directors, agents, and employees from all claims, damages, losses, and expenses, including attorneys' fees.",
  "Each party shall maintain insurance and shall give the other prompt written notice of any claim.",
  "This Agreement constitutes the entire agreement and may be amended only by a written agreement signed by both parties. Any notice must be in writing and is effective upon receipt. No waiver of any provision is effective unless in writing.",
  "This Agreement is governed by the laws of the State of Delaware. If any provision is held invalid, the remainder shall continue in full force and effect. The term of this Agreement is one year.",
  "IN WITNESS WHEREOF, the parties have duly executed and signed this Agreement by their authorized representatives.",
];

describe("no family claims a document that is nobody's", () => {
  it("nothing reaches the match threshold on generic commercial boilerplate", () => {
    const tree = buildTree(NOBODYS_DOCUMENT);
    const extracted = extractAll(tree, {
      classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
    });
    const title = titleCorpus(tree, "d.txt").toLowerCase();
    const body = NOBODYS_DOCUMENT.join("\n").toLowerCase();
    const categories = new Set(extracted.classified.map((c) => c.category));
    const defined = new Set(extracted.definitions.entries.map((e) => e.term.toLowerCase()));

    const claimed: string[] = [];
    for (const pb of [...LAUNCH, ...PLAYBOOKS]) {
      const f = pb.match_features;
      const tk = f.title_keywords.filter((k) => title.includes(k.toLowerCase()));
      const rc = f.required_clauses.filter(
        (c) => categories.has(c) || defined.has(c.toLowerCase()),
      );
      const dp = f.distinguishing_phrases.filter((p) => body.includes(p.toLowerCase()));
      const nf = f.negative_features.filter((n) => body.includes(n.toLowerCase()));
      const raw =
        Math.min(tk.length * MATCH_WEIGHTS.title_keyword, MATCH_WEIGHTS.title_keyword * 2) +
        Math.min(rc.length * MATCH_WEIGHTS.required_clause, MATCH_WEIGHTS.required_clause * 2) +
        Math.min(
          dp.length * MATCH_WEIGHTS.distinguishing_phrase,
          MATCH_WEIGHTS.distinguishing_phrase * 3,
        ) +
        nf.length * MATCH_WEIGHTS.negative_feature;
      if (raw >= MATCH_THRESHOLD) {
        claimed.push(`${pb.id} @${raw.toFixed(2)} on ${JSON.stringify([...tk, ...rc, ...dp])}`);
      }
    }
    expect(
      claimed.sort(),
      `these families claim a document that is nobody's:\n  ${claimed.sort().join("\n  ")}`,
    ).toEqual([]);

    const match = matchPlaybook(extracted, extracted.classified, [...LAUNCH, ...PLAYBOOKS], {
      title: titleCorpus(tree, "d.txt"),
      body_text: NOBODYS_DOCUMENT.join("\n"),
    });
    expect(match.playbook_id).toBe("generic-fallback");
  });

  it("a construction subcontract is not routed to the code of conduct", () => {
    // The document the defect was found on. `subcontractor-agreement` also
    // carried "lien waiver" as a NEGATIVE feature, which is backwards — a
    // subcontract almost always has a lien-waiver clause — so it lost 0.1 and
    // tied at 0.6, and the tie went to the alphabet.
    const body: [string, ...string[]] = [
      "",
      "SUBCONTRACT AGREEMENT",
      'This Subcontract is made between Larkspur Construction Group, Inc. ("Contractor") and Vanterra Mechanical Services, LLC ("Subcontractor").',
      "Subcontractor assumes toward Contractor all obligations that Contractor assumes toward Owner under the prime contract.",
      "Contractor shall pay Subcontractor within seven days after Contractor receives payment from Owner.",
      "Subcontractor shall indemnify, defend, and hold harmless Contractor, Owner, and their respective officers, directors, agents, and employees from all claims.",
      "With each application for payment, Subcontractor shall deliver an unconditional waiver and release of lien.",
    ];
    const tree = buildTree(body);
    const extracted = extractAll(tree, {
      classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
    });
    const match = matchPlaybook(extracted, extracted.classified, [...LAUNCH, ...PLAYBOOKS], {
      title: titleCorpus(tree, "sub.txt"),
      body_text: body.join("\n"),
    });
    expect(match.playbook_id, `routed to ${match.playbook_id}`).toBe("subcontractor-agreement");
  });
});
