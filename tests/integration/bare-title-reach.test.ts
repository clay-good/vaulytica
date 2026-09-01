/**
 * Can a family recognise a document that is titled exactly its own name and
 * says nothing else?
 *
 * `catalog-routing`'s self-reachability sweep builds each family's probe
 * document by handing it **its own first three distinguishing phrases**. That
 * proves the features are wired up, and it is blind by construction to the
 * defect this file measures: a family whose distinguishing list is the
 * vocabulary of a WELL-DRAFTED instance. Sessions 283-285 found twenty-three
 * such families by hand, one bad document at a time — `trademark-license`
 * listing the whole naked-licensing apparatus, `subscription-agreement` the
 * whole of Regulation D, `union-cba` an apparatus a thin CBA has not yet
 * bargained for, `litigation-hold` demanding the word "preserve" from a notice
 * that says "keep all documents. Do not delete anything."
 *
 * A title alone is worth 0.30 against a 0.5 threshold, so a family reaches its
 * own bare document only if a distinguishing phrase or a second title keyword
 * also fires. Over half the catalog does not.
 *
 * This is a RATCHET, not a pass/fail line. The listed families are the
 * standing worklist, and the two assertions are: the list may not grow, and an
 * entry that has been fixed must be removed from it. Both directions matter —
 * without the second, a family fixed in one step and broken in the next looks
 * clean.
 *
 * A bare title is a harsher standard than a real thin document, which carries
 * two or three sentences of its own subject matter. Treat an entry here as a
 * candidate to investigate with a hand-written bad document, not as a defect
 * on its own.
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

const PLAYBOOKS = parsePlaybooks(
  JSON.parse(readFileSync(join(process.cwd(), "playbooks", "extended.json"), "utf8")),
);
const LAUNCH = LAUNCH_PLAYBOOK_IDS.map((id) =>
  parsePlaybook(JSON.parse(readFileSync(join(process.cwd(), "playbooks", `${id}.json`), "utf8"))),
);
const dkb = loadStarterDkbSync();

/**
 * The families that cannot yet be reached by their own bare title, as of
 * 9.303.0 — 135 of 266. **This list may only shrink.** Removing an entry is
 * the work; adding one is a regression.
 */
const UNREACHED_BY_OWN_TITLE: ReadonlySet<string> = new Set([
  "acceptable-use-policy",
  "ai-addendum",
  "ai-aup-policy",
  "aml-policy",
  "appellate-brief",
  "arbitration-agreement-employment",
  "arbitration-demand",
  "articles-of-organization",
  "assignment-of-claim",
  "auto-renewal-terms",
  "bill-of-sale",
  "biometric-consent",
  "board-resolution",
  "bonus-plan",
  "business-continuity-plan",
  "ccrs",
  "change-order",
  "charter-incorporation",
  "clinical-trial-agreement",
  "code-of-conduct",
  "codicil",
  "cohabitation-agreement",
  "commission-plan",
  "committee-charter",
  "complaint",
  "consent-judgment",
  "construction-contract",
  "construction-lien-waiver",
  "consulting-agreement",
  "convertible-note",
  "cookie-notice",
  "copyright-license",
  "cyber-insurance-policy",
  "data-license-agreement",
  "data-sharing-agreement",
  "deposition-notice",
  "discovery-responses",
  "do-policy",
  "document-requests",
  "dpa-multi-state-us",
  "dpa-processor-subprocessor",
  "dpia-art-35",
  "employee-handbook",
  "employment-restrictive-covenant",
  "engagement-letter",
  "equipment-lease",
  "equity-incentive-plan",
  "escrow-agreement",
  "expert-witness-retention",
  "export-control-policy",
  "factoring-agreement",
  "family-msa",
  "forbearance-agreement",
  "form-d-narrative",
  "franchise-agreement",
  "grant-agreement",
  "guaranty",
  "incident-notification",
  "indemnification-agreement",
  "insurance-endorsement",
  "internship-agreement",
  "interrogatories",
  "investor-rights-agreement",
  "ip-assignment",
  "irrevocable-trust",
  "last-will-and-testament",
  "lease-assignment",
  "listing-agreement",
  "litigation-hold",
  "loan-agreement",
  "loyalty-program-terms",
  "ma-restrictive-covenant",
  "manufacturing-supply-agreement",
  "master-purchase-agreement",
  "media-release",
  "meeting-minutes",
  "membership-interest-purchase-agreement",
  "merger-agreement",
  "msa-customer-deep",
  "msa-vendor-deep",
  "mutual-nda",
  "mutual-nda-deep",
  "mutual-release",
  "nonprofit-bylaws",
  "offer-letter",
  "option-to-purchase-real-estate",
  "oss-compliance",
  "partnership-agreement",
  "patent-assignment",
  "patent-license",
  "payer-provider-agreement",
  "payment-performance-bond",
  "petition",
  "privacy-notice-gdpr",
  "privacy-notice-us",
  "privacy-policy-lint",
  "privilege-log",
  "promissory-note",
  "property-management-agreement",
  "relocation-agreement",
  "requests-for-admission",
  "residential-purchase-agreement",
  "ropa-art-30",
  "saas-customer",
  "saas-tos",
  "saas-vendor",
  "sba-loan-agreement",
  "secondary-stock-transfer",
  "section-83b-election",
  "security-agreement",
  "separation-agreement",
  "sms-consent-disclosure",
  "source-code-escrow-agreement",
  "special-needs-trust",
  "staffing-services-agreement",
  "stipulation-of-dismissal",
  "sweepstakes-official-rules",
  "teaming-agreement",
  "technology-transfer-agreement",
  "termination-of-representation",
  "tolling-agreement",
  "trademark-assignment",
  "trademark-license",
  "trial-motion",
  "trust-amendment",
  "unilateral-nda",
  "unilateral-nda-deep",
  "union-cba",
  "venue-rental-agreement",
  "voting-agreement",
  "warehousing-3pl-agreement",
  "warn-notice",
  "warrant-agreement",
  "warranty-deed",
  "written-consent",
]);

function reachedByOwnTitle(name: string): string {
  const body: [string, ...string[]] = [
    "",
    name.toUpperCase(),
    "This document is made as of January 1, 2026 between Acme Inc. and Globex Inc.",
  ];
  const tree = buildTree(body);
  const extracted = extractAll(tree, {
    classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
  });
  return matchPlaybook(extracted, extracted.classified, [...LAUNCH, ...PLAYBOOKS], {
    title: titleCorpus(tree, "d.txt"),
    body_text: body.join("\n"),
  }).playbook_id;
}

describe("a family's own bare title reaches it", () => {
  const unreached: string[] = [];
  let checked = 0;
  for (const pb of [...LAUNCH, ...PLAYBOOKS]) {
    if (pb.id === "generic-fallback") continue;
    checked += 1;
    if (reachedByOwnTitle(pb.name) !== pb.id) unreached.push(pb.id);
  }

  it("the sweep ran over the whole catalog", () => {
    expect(checked).toBeGreaterThan(250);
  });

  it("no family that was reachable has become unreachable", () => {
    const regressed = unreached.filter((id) => !UNREACHED_BY_OWN_TITLE.has(id)).sort();
    expect(
      regressed,
      `these families used to reach their own bare title and no longer do:\n  ${regressed.join("\n  ")}`,
    ).toEqual([]);
  });

  it("every listed family is still unreachable — fixed ones come off the list", () => {
    const live = new Set(unreached);
    const fixed = [...UNREACHED_BY_OWN_TITLE].filter((id) => !live.has(id)).sort();
    expect(
      fixed,
      `these families now reach their own bare title — remove them from UNREACHED_BY_OWN_TITLE:\n  ${fixed.join("\n  ")}`,
    ).toEqual([]);
  });
});
