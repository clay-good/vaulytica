/**
 * Ten hand-written documents, and the findings each is allowed to produce.
 *
 * Every routing and rule defect fixed on 2026-08-27 was found the same way:
 * write a realistic document, run the CLI on it, and read what comes back.
 * None was reachable from the suite — the fixtures are shorter, cleaner, and
 * more cooperative than anything a lawyer would actually drop in. A letter
 * puts its title in a "Re:" line; a filing puts it under a caption; a
 * negotiated agreement stamps "EXECUTION VERSION" above it; an amendment
 * defines nothing and points at its parent; a discovery response carries the
 * name of the request it answers.
 *
 * These are those documents. Pinning the rule ids each produces makes the
 * method permanent: a future change that mis-routes an engagement letter, or
 * that starts reporting a lease amendment's own defined terms as undefined,
 * fails here rather than in a user's hands.
 *
 * The set is the assertion, in both directions — a new false finding fails,
 * and so does a real one that stops firing. When a change legitimately alters
 * one, update the row and say why in the commit.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText } from "../../tools/cli/api.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

type Expectation = { playbook: string; findings: string[] };

const EXPECTED: Record<string, Expectation> = {
  // A civil complaint filed in state court. Pleads jurisdiction under an
  // Illinois long-arm statute and venue in a county, which the PLDG checks
  // could not read until they stopped assuming a federal caption.
  "complaint.txt": { playbook: "complaint", findings: [] },

  // An employee handbook: a policy nobody signs, which says so in its first
  // substantive sentence.
  "handbook.txt": { playbook: "employee-handbook", findings: ["STRUCT-006", "OBLI-005"] },

  // A convertible promissory note behind a restrictive-securities legend.
  "convertible-note.txt": {
    playbook: "convertible-note",
    findings: ["EQT-018", "OBLI-005", "STRUCT-006", "CHOICE-003"],
  },

  // A law-firm engagement letter: no styled title, and the only thing above
  // its "Re:" line is the firm's letterhead.
  "engagement-letter.txt": {
    playbook: "engagement-letter",
    findings: ["STRUCT-006", "CHOICE-006", "OBLI-005", "OBLI-008", "RISK-010"],
  },

  // Responses and objections to interrogatories. The three criticals are
  // real: Rule 34(b)(2)(C) withholding statement, the "subject to and without
  // waiving" boilerplate, and no production completion date.
  "interrogatory-responses.txt": {
    playbook: "discovery-responses",
    findings: ["DISC-018", "DISC-019", "DISC-020", "STRUCT-006"],
  },

  // A third amendment to an office lease: defines nothing, ratifies the rest.
  "lease-amendment.txt": {
    playbook: "lease-commercial-multitenant",
    findings: ["RISK-015", "STRUCT-016", "STRUCT-018", "OBLI-005", "RISK-011"],
  },

  // A mutual NDA stamped EXECUTION VERSION / CONFIDENTIAL above its title.
  "legend-nda.txt": {
    playbook: "mutual-nda",
    findings: ["RISK-005", "TERM-002", "TERM-005", "OBLI-005", "RISK-001", "RISK-014"],
  },

  // A medical director agreement drafted to the Stark and AKS personal-service
  // exceptions, with a three-year term.
  "medical-director.txt": {
    playbook: "medical-director-agreement",
    findings: [
      "IPDATA-001",
      "RISK-001",
      "RISK-005",
      "STRUCT-018",
      "TERM-002",
      "TERM-005",
      "OBLI-005",
      "RISK-010",
      "TERM-001",
    ],
  },

  // An insurer's reservation-of-rights letter, titled only in its "Re:" line.
  "ror-letter.txt": { playbook: "reservation-of-rights-letter", findings: ["OBLI-005"] },

  // A post-money SAFE behind the same securities legend. An instrument, not a
  // bilateral bargain — nobody indemnifies and nothing terminates for cause.
  "safe.txt": {
    playbook: "safe-yc",
    findings: ["EQT-006", "STRUCT-006", "OBLI-005", "STRUCT-005"],
  },

  // A statement of work issued under a named master agreement.
  "sow.txt": { playbook: "sow", findings: ["STRUCT-016", "STRUCT-018", "OBLI-005"] },

  // A contractor-favorable construction subcontract.
  "subcontract.txt": {
    playbook: "subcontractor-agreement",
    findings: [
      "IPDATA-001",
      "RISK-005",
      "RISK-015",
      "STRUCT-006",
      "STRUCT-016",
      "STRUCT-018",
      "TERM-002",
      "CHOICE-003",
      "FIN-006",
      "OBLI-002",
      "RISK-010",
      "RISK-011",
    ],
  },
};

describe("hand-written specimens", () => {
  it("every specimen on disk has an expectation", () => {
    const onDisk = readdirSync(DIR)
      .filter((f) => f.endsWith(".txt"))
      .sort();
    expect(onDisk.length, "no specimens found — the path is wrong").toBeGreaterThan(5);
    expect(onDisk).toEqual(Object.keys(EXPECTED).sort());
  });

  it.each(Object.entries(EXPECTED))(
    "%s",
    async (name, expectation) => {
      const result = await analyzeText(readFileSync(join(DIR, name), "utf8"), name);
      expect(result.run.playbook_id, `routed to ${result.run.playbook_id}`).toBe(
        expectation.playbook,
      );
      const ids = result.run.findings.map((f) => f.rule_id).sort();
      expect(ids).toEqual([...expectation.findings].sort());
    },
    120_000,
  );
});
