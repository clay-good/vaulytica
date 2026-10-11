/**
 * An exhibit is not its parent (spec-v50 §10).
 *
 * "EXHIBIT B TO THE MASTER SERVICES AGREEMENT" names two documents, and the
 * one after "to" is not the one in hand. Read as a title, that heading routed
 * a service level schedule to the master services family — 31 findings, two
 * of them critical, on an attachment — and where the document did have a type
 * of its own, ran the parent's whole pack over it as a second type.
 *
 * Two fixes are held here. Routing drops the parent's name from an exhibit
 * heading; and the helpers that stand whole-agreement checks down for an
 * incorporated exhibit read the heading form as well as the recital.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { analyzeText, loadAccuracyDeps, type AnalyzeResult } from "../../tools/cli/api.js";
import { dropExhibitParent } from "../../src/playbooks/matcher.js";
import { headedAsExhibitToParent } from "../../src/engine/rules/_helpers.js";
import { buildContext } from "../../src/engine/_test-fixtures.js";

const DIR = join(process.cwd(), "tests", "fixtures", "exhibits");
const FORMS = [
  "sla-standalone.txt",
  "sla-recital.txt",
  "sla-headed-recital.txt",
  "sla-headed.txt",
] as const;

const results = new Map<string, AnalyzeResult>();
beforeAll(async () => {
  const deps = await loadAccuracyDeps();
  for (const file of [...FORMS, "pricing-headed.txt"]) {
    results.set(file, await analyzeText(readFileSync(join(DIR, file), "utf8"), file, { deps }));
  }
}, 120_000);

const ids = (r: AnalyzeResult): string[] => r.run.findings.map((f) => f.rule_id).sort();

describe("the four forms of one service level schedule", () => {
  it("route to one type", () => {
    expect(FORMS.map((f) => results.get(f)!.playbook_id)).toEqual(
      FORMS.map(() => "service-level-agreement"),
    );
  });

  it("draw the same findings, whichever way the exhibit says what it is", () => {
    const [standalone, ...attached] = FORMS.map((f) => ids(results.get(f)!));
    for (const found of attached) expect(found).toEqual(standalone);
  });

  it("are not scanned as the parent agreement a second time", () => {
    for (const f of FORMS) {
      const second = results.get(f)!.secondary_families.map((s) => s.playbook_id);
      expect(
        second.filter((id) => id.startsWith("msa-")),
        f,
      ).toEqual([]);
    }
  });
});

describe("an exhibit with no type of its own", () => {
  it("is not judged as the agreement it is attached to", () => {
    const r = results.get("pricing-headed.txt")!;
    expect(r.playbook_id).toBe("generic-fallback");
    expect(r.secondary_families.map((s) => s.playbook_id)).toEqual([]);
    // No whole-agreement accusation: a rate card has no signature block,
    // governing law, indemnity or termination clause of its own.
    expect(r.run.findings.filter((f) => f.severity === "critical")).toEqual([]);
    expect(ids(r)).not.toContain("STRUCT-003");
  });
});

describe("the heading form, read", () => {
  it.each([
    ["EXHIBIT B TO THE MASTER SERVICES AGREEMENT", "EXHIBIT B"],
    ["Schedule 2 to the Lease", "Schedule 2"],
    ["ANNEX A-1 TO THAT CERTAIN CREDIT AGREEMENT", "ANNEX A-1"],
    ["SCHEDULE 2 TO THE LEASE: RULES AND REGULATIONS", "SCHEDULE 2: RULES AND REGULATIONS"],
    ["ATTACHMENT 3 TO THE SUBCONTRACT — FLOWDOWN CLAUSES", "ATTACHMENT 3— FLOWDOWN CLAUSES"],
  ])("drops the parent's name from %j", (line, expected) => {
    expect(dropExhibitParent(line)).toBe(expected);
  });

  it.each([
    "MASTER SERVICES AGREEMENT",
    "AMENDMENT NO. 2 TO THE MASTER SERVICES AGREEMENT",
    "DATA PROCESSING ADDENDUM TO THE MASTER SERVICES AGREEMENT",
    "EXHIBIT B",
    "Exhibit B is attached to the Agreement.",
  ])("leaves %j alone", (line) => {
    // An amendment or an addendum has a type of its own and its title is read
    // whole; a sentence that mentions an exhibit is not a heading.
    expect(dropExhibitParent(line)).toBe(line);
  });

  it("is a statement of incorporation only at the top of the document", () => {
    const top = buildContext(["EXHIBIT B TO THE MASTER SERVICES AGREEMENT", "SERVICE LEVELS"]);
    expect(headedAsExhibitToParent(top)).toBe(true);
    const body = buildContext([
      "MASTER SERVICES AGREEMENT",
      "This Agreement is between the parties.",
      "1. Services. Provider will perform the services.",
      "2. Fees. Customer will pay the fees.",
      "Exhibit B to the Master Services Agreement sets out the service levels.",
    ]);
    expect(headedAsExhibitToParent(body)).toBe(false);
    expect(headedAsExhibitToParent(buildContext(["EXHIBIT B", "SERVICE LEVELS"]))).toBe(false);
  });
});
