/**
 * A document that DISCUSSES a regime is not an instrument under it.
 *
 * The rule layer already knows this defect: a check that names the regulated
 * noun fires on every document that merely defines a term for it. This is the
 * same defect at the ROUTING layer, and it is worse, because a mis-route runs
 * an entire pack of the wrong questions rather than one.
 *
 * The RISK FACTORS section of an IPO prospectus routed to `baa`, the HIPAA
 * Business Associate Agreement, and drew forty-eight findings, seventeen of
 * them critical — no permitted-uses clause, no subcontractor flow-down, no
 * accounting of disclosures, no HHS books-and-records access. ONE risk factor
 * in it mentions protected health information, a covered entity, and a
 * business associate, which is that family's whole distinguishing list. A
 * board memorandum on the privacy programme routed to
 * `dpa-controller-processor` the same way.
 *
 * The regime families are AGREEMENTS. They now decline the registers a
 * document that talks about the regime is written in — a memorandum, a
 * training, a prospectus — and this file is what holds them there.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ingestPaste } from "../../src/ingest/paste.js";
import { extractAll } from "../../src/extract/index.js";
import { matchPlaybook, titleCorpus } from "../../src/playbooks/matcher.js";
import { parsePlaybook, parsePlaybooks } from "../../src/playbooks/loader.js";
import { loadStarterDkbSync } from "../../src/engine/_test-fixtures.js";

const DIR = join(process.cwd(), "playbooks");
const ALL = [
  ...readdirSync(DIR)
    .filter((f) => f.endsWith(".json") && f !== "extended.json")
    .map((f) => parsePlaybook(JSON.parse(readFileSync(join(DIR, f), "utf8")))),
  ...parsePlaybooks(JSON.parse(readFileSync(join(DIR, "extended.json"), "utf8"))),
];
const dkb = loadStarterDkbSync();

/** The families that are two-party instruments under a named regime. */
const REGIME_AGREEMENTS = new Set([
  "baa",
  "baa-subcontractor",
  "dpa-controller-processor",
  "dpa-processor-subprocessor",
  "dpa-ccpa-service-provider",
  "dpa-multi-state-us",
  "scc-module-2",
  "scc-module-3",
  "uk-idta-addendum",
]);

async function route(text: string): Promise<string> {
  const tree = (await ingestPaste(text)).tree;
  const extracted = extractAll(tree, {
    classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
  });
  return matchPlaybook(extracted, extracted.classified, ALL, {
    title: titleCorpus(tree, "d.txt"),
    body_text: text,
  }).playbook_id;
}

const PROSPECTUS = [
  "RISK FACTORS",
  "Investing in our common stock involves a high degree of risk. You should carefully consider the risks described below before deciding to invest.",
  "We handle protected health information, and a breach or a failure to comply with HIPAA, state privacy laws, or the GDPR could result in significant liability. We are a covered entity under HIPAA and a business associate to certain of our customers. We are also subject to the California Consumer Privacy Act and to the EU General Data Protection Regulation, and to the standard contractual clauses for transfers of personal data out of the EEA. A security incident could result in penalties.",
  "You could lose all or part of your investment.",
].join("\n\n");

const BOARD_MEMO = [
  "MEMORANDUM",
  "TO: The Board of Directors",
  "FROM: General Counsel",
  "RE: Privacy compliance program update",
  "This memorandum summarises our obligations as a data controller under the GDPR and as a business under the CCPA. Our processors sign a data processing agreement; where personal data leaves the EEA we rely on the standard contractual clauses (Module Two, controller to processor). We are a business associate for two customers and sign a business associate agreement with each. We maintain a record of processing activities under Article 30 and complete a data protection impact assessment where Article 35 requires one.",
  "No action is requested.",
].join("\n\n");

describe("a document that discusses a regime is not an instrument under it", () => {
  it("a prospectus's risk factors are not a business associate agreement", async () => {
    const got = await route(PROSPECTUS);
    expect(REGIME_AGREEMENTS.has(got), `routed to ${got}`).toBe(false);
    expect(got).toBe("s-1-risk-factors");
  });

  it("a board memorandum on the privacy programme is not a DPA", async () => {
    const got = await route(BOARD_MEMO);
    expect(REGIME_AGREEMENTS.has(got), `routed to ${got}`).toBe(false);
  });

  /**
   * STILL BROKEN, and recorded rather than hidden.
   *
   * An employee training document dense with the regime's own vocabulary still
   * reaches `baa` at exactly the 0.5 threshold, on distinguishing phrases
   * ALONE and with no title keyword matched at all. That is the structural
   * shape of the defect: a family whose document always announces itself on
   * its front page can be reached without ever matching its title.
   *
   * It is not fixed by another negative feature — "workforce training" is a
   * clause BAA-031 requires a real BAA to contain, so the word cannot be
   * declined. The fix is a routing-level one (a family of agreements wanting
   * agreement-shaped evidence) and is left for its own change.
   */
  it("an employee training document still reaches the BAA family", async () => {
    const TRAINING = [
      "ANNUAL PRIVACY AND SECURITY TRAINING",
      "This training explains what protected health information is, what a covered entity and a business associate are, and what the minimum necessary standard requires. It also explains the GDPR's lawful bases for processing personal data, the rights of a data subject, and what a security incident is and how to report one. Completion is required of every employee by December 31.",
      "Questions to the Privacy Officer.",
    ].join("\n\n");
    expect(await route(TRAINING)).toBe("baa");
  });
});
