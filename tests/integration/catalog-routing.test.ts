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
    // `mutual-nda-deep`, not `mutual-nda`: the point of this test is MUTUAL vs
    // UNILATERAL, and the legacy mutual family is deprecated in favour of the
    // deep one, which the matcher now promotes.
    expect(match.playbook_id, `routed to ${match.playbook_id}`).toBe("mutual-nda-deep");
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

describe("a cease-and-desist letter's vocabulary is its own", () => {
  // Four of the six distinguishing phrases were the bare topic words
  // "infringement", "trademark", "copyright", and "patent" — which every IP
  // document on earth contains. An IP ASSIGNMENT scored 0.6 on this playbook
  // on the strength of "United States Patent and Trademark Office" appearing
  // in its recordation clause. A distinguishing phrase has to distinguish.
  function route(body: [string, ...string[]]) {
    const tree = buildTree(body);
    const extracted = extractAll(tree, {
      classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
    });
    return matchPlaybook(extracted, extracted.classified, [...LAUNCH, ...PLAYBOOKS], {
      title: titleCorpus(tree, "doc.txt"),
      body_text: body.join("\n"),
    });
  }

  it("does not claim an internal portfolio memo that is nobody's demand", () => {
    // An IP portfolio review memorandum to a board. It threatens no one and
    // demands nothing, and it scored 0.5 — over the threshold, and enough to
    // win outright, because it says "patent", "trademark", "copyright",
    // "infringement", and (of the outdated product literature) "recall".
    const match = route([
      "",
      "INTELLECTUAL PROPERTY PORTFOLIO REVIEW MEMORANDUM",
      "This memorandum summarizes the status of the Company's intellectual property portfolio. It is prepared for internal planning purposes.",
      "The Company holds eleven issued United States patents, all recorded with the United States Patent and Trademark Office.",
      "A watch service monitors for confusingly similar filings that may constitute infringement of the marks.",
      "Firmware and documentation are protected by copyright. Registration of the 2025 firmware release remains outstanding.",
      "Counsel recommends that the Company recall the outdated product literature that references a discontinued mark.",
    ]);
    expect(match.playbook_id, `routed to ${match.playbook_id}`).not.toBe("cease-and-desist");
  });

  it("still reaches a real demand letter", () => {
    const match = route([
      "",
      "Re: Unauthorized Use of the LUMAREAD Mark — Demand to Cease and Desist",
      "We represent Vanterra Diagnostics, Inc., the owner of United States Trademark Registration No. 6,412,908 for the mark LUMAREAD.",
      "Accordingly, we demand that you immediately cease all use of the infringing designation and recall all marketing materials bearing it.",
      "Should you fail to comply, our client is prepared to pursue all available remedies without further notice to you.",
    ]);
    expect(match.playbook_id, `routed to ${match.playbook_id}`).toBe("cease-and-desist");
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
  // A processor-to-subprocessor DPA and a controller-to-processor DPA are the
  // same instrument seen from two links in the same chain; which one you want
  // is your position in it, not the document's.
  ["dpa-processor-subprocessor", ["dpa-controller-processor"]],
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
        // A DEPRECATED family reaching its own named successor is deprecation
        // working, not shadowing. `mutual-nda` and `unilateral-nda` carry
        // `superseded_by`, and the matcher promotes the successor whenever it
        // clears the threshold on its own merits — which is what puts the 23
        // NDA-D rules on the auto-routed path at all. Both remain reachable by
        // an explicit `--playbook` and by a golden's sidecar pin.
        if (pb.deprecated === true && pb.superseded_by === match.playbook_id) continue;
        shadowed.push(`${pb.id} -> ${match.playbook_id} @${match.confidence} (title "${kw}")`);
      }
    }
    expect(checked, "the sweep found no playbooks — it is broken").toBeGreaterThan(250);
    expect(shadowed.sort(), `shadowed by a sibling:\n  ${shadowed.sort().join("\n  ")}`).toEqual(
      [],
    );
  }, 60_000);

  /**
   * The mirror of the keyword sweep: a document titled with the family's own
   * DISPLAY NAME must reach it.
   *
   * A family's keywords and its name are written separately and drift apart.
   * `healthcare-poa` listed the CLOSED spelling only — "healthcare power of
   * attorney" — while its name, and every document of the kind, is "Health
   * Care Power of Attorney", so one so titled fell to `generic-fallback` and
   * not one of the family's checks ran on it.
   */
  it("a document titled with the family's own name reaches it", () => {
    const shadowed: string[] = [];
    let checked = 0;
    for (const pb of [...LAUNCH, ...PLAYBOOKS]) {
      if (pb.id === "generic-fallback") continue;
      const phrases = pb.match_features.distinguishing_phrases.slice(0, 3);
      checked += 1;
      const body: [string, ...string[]] = [
        "",
        pb.name.toUpperCase(),
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
      if (pb.deprecated === true && pb.superseded_by === match.playbook_id) continue;
      shadowed.push(`${pb.id} -> ${match.playbook_id} @${match.confidence} (name "${pb.name}")`);
    }
    expect(checked, "the sweep found no playbooks — it is broken").toBeGreaterThan(250);
    expect(
      shadowed.sort(),
      `a family cannot be reached by its own name:\n  ${shadowed.sort().join("\n  ")}`,
    ).toEqual([]);
  }, 60_000);
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

  /**
   * Five families found by one sweep of deliberately bad documents. Each is a
   * document that states its subject and none of the protections its family
   * checks for — which is the document that most needs the family, and the one
   * the family's own vocabulary was least able to recognise.
   */
  const BAD_DOCUMENTS: Array<{ id: string; title: string; body: string[] }> = [
    {
      // Its own routing phrases were the flow-down terms 164.504(e)(5)
      // requires, so the GENERAL `baa` took a document whose title says
      // subcontractor, and audited it as the upstream agreement.
      id: "baa-subcontractor",
      title: "SUBCONTRACTOR BUSINESS ASSOCIATE AGREEMENT",
      body: [
        'This Subcontractor Business Associate Agreement is between Beacon Ledger Systems, Inc. ("Business Associate") and Sable Notification Services LLC ("Subcontractor"), which will handle protected health information on Business Associate\'s behalf.',
        "Subcontractor may use the information for its own analytics.",
      ],
    },
    {
      // Every phrase was a CCPA compliance term. A service provider addendum
      // that lets the service provider use the personal information for its
      // own products — the paradigm violation — reached no family at all.
      id: "dpa-ccpa-service-provider",
      title: "SERVICE PROVIDER ADDENDUM",
      body: [
        'This Service Provider Addendum is between Halcyon Analytics, Inc. ("Business") and Kestrel Data LLC ("Service Provider") and covers personal information Business shares under the California Consumer Privacy Act.',
        "Service Provider may use the personal information to improve its own products.",
      ],
    },
    {
      // "sba 7(a)", "sop 50 10", "unconditional guarantee" — all of them
      // things a compliant SBA loan carries. The general `loan-agreement` took
      // it, and the SBA ruleset never ran.
      id: "sba-loan-agreement",
      title: "SBA LOAN AGREEMENT",
      body: [
        'This SBA Loan Agreement is between Summit Commercial Bank, N.A. ("Lender") and Thistledown Robotics, Inc. ("Borrower") for a loan guaranteed by the U.S. Small Business Administration.',
        "Lender will lend Borrower $1,750,000 at prime plus 2.75%, payable over ten years.",
      ],
    },
    {
      // Right of first refusal, the company's consent, Rule 144, § 4(a)(7) —
      // the four things a compliant secondary transfer carries.
      id: "secondary-stock-transfer",
      title: "STOCK TRANSFER AGREEMENT",
      body: [
        'This Stock Transfer Agreement is between Adaeze Ferreira-Lindqvist ("Transferor"), a former employee, and Vantage Growth Fund II, L.P. ("Transferee").',
        "Transferor sells to Transferee 250,000 shares of common stock at $6.40 per share.",
      ],
    },
    {
      // Routed at EXACTLY 0.5, the threshold — one negative feature from
      // falling off — because four of its five phrases are the covenant's own
      // protections.
      id: "ma-restrictive-covenant",
      title: "NON-COMPETITION AGREEMENT (SALE OF BUSINESS)",
      body: [
        'This Agreement is made in connection with the sale of the business of Sablefield Software, Inc. between Pinehurst Capital Partners, L.P. ("Buyer") and Devin Marchetti ("Seller").',
        "For ten (10) years after closing, Seller will not compete with the acquired business anywhere in the world.",
      ],
    },
  ];

  /**
   * The same test for three families whose bad document reached them at
   * EXACTLY 0.5 — the threshold, one negative feature from falling to
   * `generic-fallback`. All three had the same cause: the phrases were the
   * protections the ruleset checks for (an IRB and an informed-consent form; a
   * maturity date and a subordination term; a valuation cap and a discount
   * rate), and a document with none of them scored its title and one phrase.
   */
  const THIN_MARGINS: Array<{ id: string; title: string; body: string[] }> = [
    {
      id: "clinical-trial-agreement",
      title: "CLINICAL TRIAL AGREEMENT",
      body: [
        'This Clinical Trial Agreement is between Halcyon Therapeutics, Inc. ("Sponsor"), Calloway State University ("Institution"), and Dr. Priya Raghunathan ("Investigator").',
        "The Institution will conduct the study described in the protocol. Sponsor will pay the Institution $8,400 per enrolled subject.",
      ],
    },
    {
      id: "convertible-note",
      title: "CONVERTIBLE PROMISSORY NOTE",
      body: [
        'For value received, Thistledown Robotics, Inc. (the "Company") promises to pay Vantage Growth Fund II, L.P. (the "Holder") $750,000.',
        "The note converts into equity on a qualified financing at the conversion price.",
      ],
    },
    {
      id: "safe-yc",
      title: "SIMPLE AGREEMENT FOR FUTURE EQUITY",
      body: [
        'This Simple Agreement for Future Equity is between Thistledown Robotics, Inc. (the "Company") and Vantage Growth Fund II, L.P. (the "Investor").',
        "On the next equity financing or a liquidity event the Investor gets shares.",
      ],
    },
  ];

  /**
   * Five more, from a sweep of the estate, litigation and lending families.
   * Four of the five reached NO family at all, and the fifth reached its own
   * at the threshold — an engagement letter with no scope and no conflicts
   * paragraph, a demand note, a settlement with no no-admission clause, a will
   * with no residue clause, and a power of attorney with no incapacity term.
   * Each is the document a reviewer most needs the family for.
   */
  const BARE_INSTRUMENTS: Array<{ id: string; title: string; body: string[] }> = [
    {
      id: "engagement-letter",
      title: "ENGAGEMENT LETTER",
      body: [
        "Thank you for asking Ashford & Reyes LLP to represent you. We will represent you in your dispute with Wrenfield Audio Labs, Inc.",
        "Our rate is $525 per hour and we will bill you monthly for this engagement.",
      ],
    },
    {
      id: "promissory-note",
      title: "PROMISSORY NOTE",
      body: [
        "For value received, Thistledown Robotics, Inc. promises to pay Summit Commercial Bank, N.A. the principal sum of $250,000.",
        "Interest accrues at 9.5% per year and the entire balance is due on demand.",
      ],
    },
    {
      id: "confidential-settlement",
      title: "SETTLEMENT AGREEMENT AND RELEASE",
      body: [
        "This Settlement Agreement and Release is made to resolve the lawsuit pending in the Franklin County Court of Common Pleas.",
        "Defendant will pay Plaintiff $325,000 within thirty days, and Plaintiff releases all claims against Defendant.",
      ],
    },
    {
      id: "last-will-and-testament",
      title: "LAST WILL AND TESTAMENT OF MARGARET OKAFOR",
      body: [
        "I, Margaret Okafor, of Franklin County, Ohio, declare this to be my will.",
        "I give my estate to my daughter, and I name my brother as executor.",
      ],
    },
    {
      id: "durable-poa-financial",
      title: "GENERAL POWER OF ATTORNEY",
      body: [
        "I, Margaret Okafor, of Franklin County, Ohio, appoint my brother David Lin as my attorney-in-fact.",
        "My agent may act on my behalf in anything to do with my property and finances.",
      ],
    },
  ];

  /**
   * Ten more, from a sweep of the technology, healthcare, government and real
   * estate families. Five reached no family at all — including a SaaS
   * agreement, whose family is one of the ten the product launched with — and
   * three more reached their own at the threshold.
   */
  const BARE_COMMERCIAL: Array<{ id: string; title: string; body: string[] }> = [
    {
      // The title keyword was written "software-as-a-service", with hyphens.
      id: "saas-customer",
      title: "SOFTWARE AS A SERVICE AGREEMENT",
      body: [
        'This Software as a Service Agreement is between Halcyon Analytics, Inc. ("Provider") and Rowan Credit Union ("Customer").',
        "Provider will make the platform available to Customer for $8,000 per month, and may change it or suspend access at any time.",
      ],
    },
    {
      id: "consulting-agreement",
      title: "CONSULTING AGREEMENT",
      body: [
        'This Consulting Agreement is between Halcyon Analytics, Inc. ("Company") and Devin Marchetti ("Consultant").',
        "Consultant will advise the Company on data architecture for $250 per hour, and either party may end this Agreement at any time.",
      ],
    },
    {
      id: "equipment-lease",
      title: "EQUIPMENT LEASE AGREEMENT",
      body: [
        'This Equipment Lease Agreement is between Kestrel Equipment Finance LLC ("Lessor") and Larkspur Construction Group, Inc. ("Lessee") for one excavator.',
        "The lease term is thirty-six months at $4,200 per month, and Lessee is responsible for all maintenance, insurance and loss of the equipment.",
      ],
    },
    {
      id: "gsa-schedule-contract",
      title: "GSA SCHEDULE CONTRACT",
      body: [
        "This contract is between the General Services Administration and Halcyon Analytics, Inc. under Multiple Award Schedule 54151S.",
        "The contractor will provide information technology services to ordering agencies at its listed prices.",
      ],
    },
    {
      id: "real-estate-psa",
      title: "REAL ESTATE PURCHASE AGREEMENT",
      body: [
        'This Real Estate Purchase Agreement is between Ashford Property Holdings LLC ("Seller") and Terrence Okonjo-Whitfield ("Buyer") for the property at 14 Colston Avenue, Columbus, Ohio.',
        "The purchase price is $485,000 and closing will occur on August 15, 2026. Buyer takes the property as is.",
      ],
    },
    {
      id: "api-terms",
      title: "API TERMS OF USE",
      body: [
        "These API Terms of Use govern your use of the Halcyon API.",
        "We grant your application api access and may change or withdraw any endpoint at any time without notice.",
      ],
    },
    {
      id: "medical-director-agreement",
      title: "MEDICAL DIRECTOR AGREEMENT",
      body: [
        'This Medical Director Agreement is between Rowan Regional Health System ("Hospital") and Dr. Priya Raghunathan ("Medical Director").',
        "Dr. Raghunathan will direct the clinical services of the audiology service and the Hospital will pay her $9,000 per month.",
      ],
    },
    {
      id: "privacy-policy-lint",
      title: "PRIVACY POLICY",
      body: [
        "This Privacy Policy explains how Wrenfield Audio Labs, Inc. handles information about you.",
        "We collect your name, email and device identifiers, and we share information with our advertising partners.",
      ],
    },
  ];

  /**
   * Ten more, from the commercial and employment families. One reached nothing
   * and six reached their own at the threshold — the highest thin-margin count
   * of any batch, and every one of them a document type a reviewer sees weekly.
   */
  const BARE_EVERYDAY: Array<{ id: string; title: string; body: string[] }> = [
    {
      id: "manufacturing-supply-agreement",
      title: "SUPPLY AGREEMENT",
      body: [
        'This Supply Agreement is between Kestrel Components GmbH ("Supplier") and Wrenfield Audio Labs, Inc. ("Buyer").',
        "The supplier will sell Buyer transducers at $14.20 each against a purchase order from time to time, and may change the price on thirty days' notice.",
      ],
    },
    {
      id: "escrow-agreement",
      title: "ESCROW AGREEMENT",
      body: [
        'This Escrow Agreement is between Pinehurst Capital Partners, L.P. ("Buyer"), Marchetti Holdings LLC ("Seller"), and Summit Commercial Bank, N.A. ("Escrow Agent").',
        "Buyer deposits $4,200,000 at closing and the escrow agent will release the funds when the parties tell it to.",
      ],
    },
    {
      id: "employee-handbook",
      title: "EMPLOYEE HANDBOOK",
      body: [
        "This handbook describes Silverthorne Diagnostics, Inc.'s company policies for its employees.",
        "Employees are expected to be at work on time. The Company may change any policy at any time. Employment is at-will.",
      ],
    },
    {
      id: "offer-letter",
      title: "OFFER OF EMPLOYMENT",
      body: [
        "We are pleased to offer you the position of Director of Assay Development at Silverthorne Diagnostics, Inc.",
        "Your annual salary will be $196,000 and your employment is at-will.",
      ],
    },
    {
      id: "sow",
      title: "STATEMENT OF WORK",
      body: [
        "This Statement of Work is issued under the master services agreement between Halcyon Analytics, Inc. and Rowan Credit Union.",
        "The fee is $180,000, invoiced monthly, and the work starts July 1, 2026.",
      ],
    },
    {
      id: "subcontractor-agreement",
      title: "SUBCONTRACT AGREEMENT",
      body: [
        'This Subcontract Agreement is between Larkspur Construction Group, Inc. ("Contractor") and Vanterra Mechanical Services, LLC ("Subcontractor").',
        "The subcontractor will perform the mechanical work, and Contractor will pay $310,000 when contractor is paid by the Owner.",
      ],
    },
    {
      id: "distribution-agreement",
      title: "RESELLER AGREEMENT",
      body: [
        'This Reseller Agreement is between Halcyon Analytics, Inc. ("Vendor") and Vantage Systems LLC ("Reseller").',
        "Reseller may resell the Halcyon platform in Texas and buys at a 30% discount off list.",
      ],
    },
  ];

  /**
   * Governance, transport, data and media. Three of these reached NOTHING and
   * one its own at the threshold — and the sweep also found three document
   * types with no family at all (a commercial general liability policy, a
   * charitable gift agreement, a power purchase agreement, a student
   * enrollment agreement), which are catalog gaps rather than routing defects
   * and are recorded in BUILD_PROGRESS rather than papered over here.
   */
  const BARE_SPECIALIST: Array<{ id: string; title: string; body: string[] }> = [
    {
      id: "freight-transportation-agreement",
      title: "TRANSPORTATION SERVICES AGREEMENT",
      body: [
        'This Transportation Services Agreement is between Vantage Grocery Distribution, Inc. ("Shipper") and Larkspur Freight Systems, LLC ("Carrier").',
        "Carrier will transport Shipper's freight between the warehouses at the rates in the attached schedule.",
      ],
    },
    {
      id: "data-license-agreement",
      title: "DATA LICENSE AGREEMENT",
      body: [
        'This Data License Agreement is between Kestrel Data LLC ("Licensor") and Halcyon Analytics, Inc. ("Licensee").',
        "Licensor grants Licensee the right to use the Kestrel consumer dataset for $240,000 per year.",
      ],
    },
    {
      id: "board-resolution",
      title: "BOARD RESOLUTION",
      body: [
        "RESOLVED, that Thistledown Robotics, Inc. is authorized to enter into the credit facility with Summit Commercial Bank, N.A.",
        "RESOLVED FURTHER, that any officer may sign the documents. Adopted May 4, 2026.",
      ],
    },
  ];

  /**
   * Five more, chosen where a family's whole distinguishing list was
   * vocabulary a THIN instance of it does not have.
   *
   * `trademark-license` listed "licensed marks", "quality control",
   * "goodwill", "inures", "channels of trade" and "field of use" — the
   * naked-licensing protections, which is exactly what a bad trademark
   * licence leaves out. It reached 0.3, its own title and nothing else, and
   * LOST to `data-license-agreement` at 0.4 on a document titled TRADEMARK
   * LICENSE AGREEMENT — because that family listed "licensor", "licensee",
   * "the licensor" and "the licensee": four of its eleven phrase slots spent
   * on the two role words of EVERY licence in the catalog. A bare party role
   * is the genus, not the species, and here it outscored a family that named
   * itself in its own title.
   *
   * `grant-agreement` and `lease-assignment` failed the same way and reached
   * nothing at all. `nonprofit-bylaws` lost to `bylaws-corporation`: it
   * claimed "501(c)(3)", "tax-exempt" and "no part of the net earnings", and
   * its sibling's negative features were the same three words, so a
   * conservancy's bylaws saying only that it "is organized exclusively for
   * charitable and educational purposes" — the § 501(c)(3) organizational
   * test, in the words the IRS itself uses — was audited as a stock
   * corporation's.
   */
  const BARE_LICENCES: Array<{ id: string; title: string; body: string[] }> = [
    {
      id: "trademark-license",
      title: "TRADEMARK LICENSE AGREEMENT",
      body: [
        'This Trademark License Agreement is between Wrenfield Audio Labs, Inc. ("Licensor") and Ashford Retail Group LLC ("Licensee").',
        "Licensor grants Licensee a non-exclusive license to use the Mark in connection with retail packaging. Licensee will pay $40,000 per year.",
      ],
    },
    {
      id: "grant-agreement",
      title: "GRANT AGREEMENT",
      body: [
        'This Grant Agreement is between the Ashford Family Foundation ("Foundation") and Pemberton Ridge Land Conservancy ("Grantee").',
        "The Foundation will give the Grantee $500,000 over two years for trail restoration. The Grantee will send a report each year.",
      ],
    },
    {
      id: "lease-assignment",
      title: "ASSIGNMENT OF LEASE",
      body: [
        'Wrenfield Audio Labs, Inc. ("Assignor") assigns to Halcyon Analytics, Inc. ("Assignee") all of its interest in the lease of Suite 400, 1200 Guadalupe Street, Austin, Texas, dated June 1, 2024.',
        "Assignee assumes all of Assignor's obligations under the lease from the effective date.",
      ],
    },
    {
      id: "nonprofit-bylaws",
      title: "BYLAWS OF PEMBERTON RIDGE LAND CONSERVANCY",
      body: [
        "The Conservancy is organized exclusively for charitable and educational purposes.",
        "The board of directors will have between five and fifteen members. The board may amend these bylaws by majority vote.",
      ],
    },
    {
      id: "patent-license",
      title: "PATENT LICENSE AGREEMENT",
      body: [
        'This Patent License Agreement is between Halcyon Bioacoustics, Inc. ("Licensor") and Kestrel Devices LLC ("Licensee").',
        "Licensor grants Licensee a licence under the patents listed on Exhibit A to make and sell hearing devices. Licensee will pay a royalty of five percent (5%) of net sales.",
      ],
    },
  ];

  /**
   * Three more of the same class, and the third is the one that mattered.
   *
   * `subscription-agreement` listed the whole Regulation D apparatus
   * ("accredited investor", "rule 506", "the securities have not been
   * registered", "restrictive legend", "suitability") and `teaming-agreement`
   * the whole FAR one ("contracting officer", "organizational conflict",
   * "workshare"). Both reached 0.3 — their own title and nothing else.
   *
   * The NON-COMPETITION AGREEMENT below runs five years, nationwide, against
   * any competitor, and chooses California law, where Bus. & Prof. Code
   * § 16600 voids it outright. Its title is a keyword of BOTH restrictive-
   * covenant families, so each scored 0.3 and neither reached: the worst
   * covenant in the catalog got `generic-fallback` and four findings. The
   * employment family now also claims the words a plainly-drafted covenant
   * actually uses.
   */
  const BARE_COVENANTS: Array<{ id: string; title: string; body: string[] }> = [
    {
      id: "subscription-agreement",
      title: "SUBSCRIPTION AGREEMENT",
      body: [
        "The undersigned subscribes for 400,000 shares of Series Seed Preferred Stock of Thistledown Robotics, Inc. at $2.50 per share.",
        "The purchase price is $1,000,000, payable at closing. The undersigned has reviewed the materials the Company provided.",
      ],
    },
    {
      id: "teaming-agreement",
      title: "TEAMING AGREEMENT",
      body: [
        'This Teaming Agreement is between Larkspur Systems, Inc. ("Prime") and Kestrel Analytics LLC ("Subcontractor") for the Department of Energy solicitation DE-SOL-0014772.',
        "Prime will submit the proposal. If Prime wins, Prime will decide what work to give Subcontractor.",
      ],
    },
    {
      id: "employment-restrictive-covenant",
      title: "NON-COMPETITION AGREEMENT",
      body: [
        "Desmond Vaillancourt agrees that for five years after leaving Halcyon Analytics, Inc. he will not work for any competitor anywhere in the United States.",
        "This applies to any business that competes with the Company in any way. California law governs.",
      ],
    },
  ];

  it.each([
    ...BAD_DOCUMENTS,
    ...BARE_LICENCES,
    ...BARE_COVENANTS,
    ...THIN_MARGINS,
    ...BARE_INSTRUMENTS,
    ...BARE_COMMERCIAL,
    ...BARE_EVERYDAY,
    ...BARE_SPECIALIST,
    // Five more instrument families. A severance agreement and a SaaS order
    // form reached nothing; a certificate of insurance and a deed of trust
    // reached their own at the threshold. `separation-agreement` claimed "21
    // days", "45 days", "seven days", "revocation" and "adea" — the entire
    // OWBPA apparatus, which is precisely what the deficient severance
    // agreement omits.
    {
      id: "separation-agreement",
      title: "SEVERANCE AGREEMENT",
      body: [
        "Silverthorne Diagnostics, Inc. and Rosalind Achterberg-Nwosu, whose employment ends June 30, 2026, agree as follows.",
        "The Company will pay twelve weeks of base salary. Employee gives up all claims against the Company, of every kind.",
      ],
    },
    {
      id: "coi",
      title: "CERTIFICATE OF LIABILITY INSURANCE",
      body: [
        "This certificate is issued as a matter of information only and confers no rights upon the certificate holder.",
        "The insured is Larkspur Construction Group, Inc. Commercial General Liability: $1,000,000 each occurrence.",
      ],
    },
    {
      id: "deed-of-trust",
      title: "DEED OF TRUST",
      body: [
        'Margaret Okafor ("Borrower") conveys to First Title Agency ("Trustee"), in trust for Summit Commercial Bank, N.A., the property at 14 Colston Avenue, to secure a note of $340,000.',
        "If Borrower defaults, Trustee may sell the property at public auction.",
      ],
    },
    // Six litigation-practice families, from a sweep of the v6 wave. A closing
    // letter and a privilege log reached NO family; requests for admission, a
    // limited-scope agreement and interrogatories reached their own at or near
    // the threshold. Same cause throughout: `termination-of-representation`
    // claimed "representation has concluded" as an adjacent bigram, and a real
    // letter says "our representation OF YOU IN THE WRENFIELD MATTER has
    // concluded"; `requests-for-admission` claimed "deemed admitted" and
    // "genuineness of the document", which appear in the RESPONSE, not the
    // request.
    {
      id: "termination-of-representation",
      title: "CLOSING LETTER",
      body: [
        "This letter confirms that our representation of you in the Wrenfield matter has concluded.",
        "We are closing our file. Please let us know if you would like your documents.",
      ],
    },
    {
      id: "privilege-log",
      title: "PRIVILEGE LOG",
      body: [
        "Defendant withholds the following documents from production. The basis for withholding is stated for each entry.",
        "Bates THIS-000412. Date: March 5, 2025. Description: email seeking legal advice. Privilege asserted: attorney-client.",
      ],
    },
    {
      id: "requests-for-admission",
      title: "PLAINTIFF'S FIRST REQUESTS FOR ADMISSION",
      body: [
        "Plaintiff asks Defendant to admit the following.",
        "Admit that you received Plaintiff's design files on March 3, 2025.",
      ],
    },
    {
      id: "limited-scope-representation",
      title: "LIMITED SCOPE REPRESENTATION AGREEMENT",
      body: [
        "Ashford & Reyes LLP will represent Terrence Okonjo-Whitfield for the limited purpose of drafting a response to the motion to dismiss.",
        "We will not appear in court or handle any other part of the case. Our fee for this task is $4,500.",
      ],
    },
    {
      id: "interrogatories",
      title: "PLAINTIFF'S FIRST SET OF INTERROGATORIES TO DEFENDANT",
      body: [
        "Plaintiff asks Defendant to answer the following under oath.",
        "Identify every person who worked on the transducer design, and identify all documents relating to the matters in the complaint.",
      ],
    },
    // A SHAREHOLDERS agreement. `stockholders-agreement`'s title keywords were
    // "stockholders agreement" and "stockholders' agreement" only, so the
    // other spelling of the same instrument — the one a British or
    // British-trained drafter uses, and the commoner one outside Delaware —
    // reached no family at all and drew three generic findings. It now draws
    // eighteen.
    {
      id: "stockholders-agreement",
      title: "SHAREHOLDERS AGREEMENT",
      body: [
        "This Shareholders Agreement is among Thistledown Robotics, Inc. and the shareholders listed on Schedule A.",
        "The shareholders will vote their shares to elect three directors, and a shareholder may not transfer shares without the board's consent.",
      ],
    },
    // A gym waiver. `hold-harmless-agreement` listed "waiver and release" and
    // "participant release" but not "release and waiver" or "waiver of
    // liability" — the two commonest headings on the document itself.
    {
      id: "hold-harmless-agreement",
      title: "RELEASE AND WAIVER OF LIABILITY",
      body: [
        "I release Ashford Climbing Gym LLC from all claims arising from my use of its facilities.",
        "I understand climbing is dangerous and I accept the risk, and I waive any claim, including for the gym's negligence.",
      ],
    },
    // A plainly-drafted motion to compel. `trial-motion`'s phrases were the
    // formal components of a filed motion — "points and authorities",
    // "declaration in support", "proposed order", "wherefore" — so a motion
    // that just states what it wants scored its title and nothing else. The
    // consequence reaches past the finding list: `--court` scopes the filing
    // format lint to three families, so a motion that cannot route to one of
    // them cannot be format-linted at all, however the user invokes the tool.
    {
      id: "trial-motion",
      title: "MOTION TO COMPEL DISCOVERY",
      body: [
        "Plaintiff Wrenfield Audio Labs, Inc. moves the Court to compel Defendant Thistledown Robotics, Inc. to produce the documents requested in Plaintiff's First Request for Production.",
        "In support of this motion, Plaintiff states that it served the requests on March 3, 2026 and Defendant has produced nothing.",
      ],
    },
  ])("a bad document still reaches $id", ({ id, title, body }) => {
    const doc: [string, ...string[]] = ["", title, ...body];
    const tree = buildTree(doc);
    const extracted = extractAll(tree, {
      classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
    });
    const match = matchPlaybook(extracted, extracted.classified, [...LAUNCH, ...PLAYBOOKS], {
      title: titleCorpus(tree, `${id}.txt`),
      body_text: doc.join("\n"),
    });
    expect(match.playbook_id, `routed to ${match.playbook_id}`).toBe(id);
  });

  it("a BARE stock purchase agreement reaches its family", () => {
    // All five of `stock-purchase-agreement`'s distinguishing phrases —
    // "purchase and sale", "working capital", "material adverse effect",
    // "indemnification", "survival" — are the deal-protection terms
    // MNA-010..019 check for. An SPA that states the sale and the price and
    // nothing else scored 0.3 on its title, fell to `generic-fallback`, and
    // drew one generic finding. It now draws seven of the M&A criticals.
    const body: [string, ...string[]] = [
      "",
      "STOCK PURCHASE AGREEMENT",
      'This Stock Purchase Agreement is made between Marchetti Holdings LLC ("Seller") and Pinehurst Capital Partners, L.P. ("Buyer").',
      "Seller sells to Buyer all of the outstanding shares of Sablefield Software, Inc. for $42,000,000 in cash at closing.",
      "Closing will occur on a closing date the parties agree.",
    ];
    const tree = buildTree(body);
    const extracted = extractAll(tree, {
      classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
    });
    const match = matchPlaybook(extracted, extracted.classified, [...LAUNCH, ...PLAYBOOKS], {
      title: titleCorpus(tree, "spa.txt"),
      body_text: body.join("\n"),
    });
    expect(match.playbook_id, `routed to ${match.playbook_id}`).toBe("stock-purchase-agreement");
  });

  it("a DEFECTIVE restricted stock purchase agreement reaches its family", () => {
    // Four of `rspa`'s five distinguishing phrases — "repurchase right",
    // "83(b)", "stock power", "escrow" — are the clauses EQT-036..042 require.
    // A founder agreement that takes a promissory note for the purchase price
    // and states no 83(b) advisory, no escrow, no stock power, no right of
    // first refusal, no legend and no lock-up scored 0.3 on its title, an
    // EXACT title keyword, fell to `generic-fallback`, and drew ZERO findings.
    // The phrases that identify a restricted stock purchase whatever it says —
    // "restricted stock", "unvested shares", "shares of common stock" — now
    // carry the routing, with the standalone 83(b) ELECTION FORM excluded by
    // negative feature so it keeps its own family.
    const body: [string, ...string[]] = [
      "",
      "RESTRICTED STOCK PURCHASE AGREEMENT",
      'This Agreement is made between Thistledown Robotics, Inc. and Yusuf Oyelaran-Bright ("Purchaser").',
      "The Company sells to Purchaser 1,800,000 shares of Common Stock at $0.0001 per share. Purchaser shall deliver a promissory note for the purchase price.",
      "The shares vest over four years. If Purchaser stops providing services, the Company may buy back the unvested shares at the price Purchaser paid.",
    ];
    const tree = buildTree(body);
    const extracted = extractAll(tree, {
      classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
    });
    const match = matchPlaybook(extracted, extracted.classified, [...LAUNCH, ...PLAYBOOKS], {
      title: titleCorpus(tree, "rspa.txt"),
      body_text: body.join("\n"),
    });
    expect(match.playbook_id, `routed to ${match.playbook_id}`).toBe("rspa");
  });

  it("a university licence reaches its family WITHOUT reciting Bayh-Dole", () => {
    // Six of `technology-transfer-agreement`'s seven distinguishing phrases
    // were the Bayh-Dole clauses its own checks require — "bayh-dole",
    // "march-in rights", "government license rights", "substantially
    // manufactured in the united states", "diligence milestones", "sponsored
    // research". A licence that recites none of them scored 0.5 on its title
    // and the one remaining phrase, lost to `patent-license` at 0.6, and
    // IPL-123 — the CRITICAL check for the government's retained licence —
    // could only ever fire on a document that had already recited it. A
    // family whose routing is its own compliance checks is a family that
    // reviews the documents needing review least.
    const body: [string, ...string[]] = [
      "",
      "TECHNOLOGY TRANSFER AGREEMENT",
      'This Technology Transfer Agreement is made between The Board of Trustees of Calloway State University ("University") and Halcyon Bioacoustics, Inc. ("Licensee").',
      "University grants Licensee an exclusive worldwide license under the Licensed Patents listed on Exhibit A to make, use, and sell Licensed Products.",
      "Licensee shall pay University a royalty of four percent (4%) of net sales and twenty percent (20%) of Sublicense Income.",
      "The Office of Technology Commercialization administers this Agreement on University's behalf.",
    ];
    const tree = buildTree(body);
    const extracted = extractAll(tree, {
      classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
    });
    const match = matchPlaybook(extracted, extracted.classified, [...LAUNCH, ...PLAYBOOKS], {
      title: titleCorpus(tree, "tt.txt"),
      body_text: body.join("\n"),
    });
    expect(match.playbook_id, `routed to ${match.playbook_id}`).toBe(
      "technology-transfer-agreement",
    );
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
