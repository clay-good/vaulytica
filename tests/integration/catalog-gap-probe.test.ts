/**
 * The documents people bring that the catalog has no type for (spec-v49 §1).
 *
 * Every one of the 327 specimens matches a document type: the corpus was
 * written from the catalog, so it holds only documents the catalog knows, and
 * it cannot see what is missing. These ten are short, correctly titled
 * documents of types the catalog does not name. Seven fall to the generic
 * fallback; three are taken for a neighbour and judged by its rules — a
 * service level agreement, an attachment, is told it has no indemnification
 * clause.
 *
 * Pinned as measured. A row flips the day its type ships: once the catalog
 * names the type, the document must route to it.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import {
  analyzeFile,
  isDocumentType,
  loadAccuracyDeps,
  type AnalyzeResult,
} from "../../tools/cli/api.js";

const DIR = join(process.cwd(), "tests", "fixtures", "probe-v49");

/** file → the type it should have, and where it goes while that type does not exist. */
const PROBE: ReadonlyArray<{ file: string; wants: string; today: string }> = [
  { file: "advisor-agreement.txt", wants: "advisor-agreement", today: "generic-fallback" },
  {
    file: "buyer-representation-agreement.txt",
    wants: "buyer-representation-agreement",
    today: "generic-fallback",
  },
  { file: "pilot-agreement.txt", wants: "pilot-evaluation-agreement", today: "generic-fallback" },
  {
    file: "training-repayment-agreement.txt",
    wants: "training-repayment-agreement",
    today: "generic-fallback",
  },
  { file: "merchant-cash-advance.txt", wants: "merchant-cash-advance", today: "generic-fallback" },
  {
    file: "residential-solar-ppa.txt",
    wants: "residential-solar-agreement",
    today: "generic-fallback",
  },
  { file: "roommate-agreement.txt", wants: "roommate-agreement", today: "generic-fallback" },
  { file: "service-level-agreement.txt", wants: "service-level-agreement", today: "saas-customer" },
  {
    file: "hipaa-data-use-agreement.txt",
    wants: "hipaa-data-use-agreement",
    today: "data-sharing-agreement",
  },
  {
    file: "software-development-agreement.txt",
    wants: "software-development-agreement",
    today: "msa-general",
  },
];

const results = new Map<string, AnalyzeResult>();
beforeAll(async () => {
  const deps = await loadAccuracyDeps();
  for (const { file } of PROBE) results.set(file, await analyzeFile(join(DIR, file), { deps }));
}, 120_000);

describe("documents the catalog has no type for", () => {
  it("routes each one where it was measured to go, until its type ships", async () => {
    const wrong: string[] = [];
    for (const { file, wants, today } of PROBE) {
      const expected = (await isDocumentType(wants)) ? wants : today;
      const actual = results.get(file)!.playbook_id;
      if (actual !== expected) wrong.push(`${file}: routed to ${actual}, expected ${expected}`);
    }
    expect(wrong).toEqual([]);
  });

  it("each document says what it is in its first line", () => {
    for (const { file } of PROBE) {
      const title = readFileSync(join(DIR, file), "utf8").split("\n")[0]!;
      expect(title, file).toMatch(/^[A-Z][A-Z /-]+$/);
    }
  });

  it("an unmatched document says so, and gets only the generic rules", () => {
    for (const { file, today } of PROBE) {
      if (today !== "generic-fallback") continue;
      const r = results.get(file)!;
      if (r.playbook_id !== "generic-fallback") continue; // its type has shipped
      expect(r.run.classification_notice, file).toBeDefined();
      // Nothing type-specific ran: every finding is from a general rule.
      const ran = r.run.execution_log.filter((e) => e.ran).length;
      expect(ran, file).toBeLessThan(100);
    }
  });

  it("the training-repayment clause is read, whatever the document is called", () => {
    // spec-v49 §1: this sentence drew nothing until PERS-008 was widened.
    const r = results.get("training-repayment-agreement.txt")!;
    expect(r.run.findings.map((f) => f.rule_id)).toContain("PERS-008");
  });

  it("an attachment taken for its parent is accused of what an attachment never carries", () => {
    // The false accusation the SLA family exists to remove. When it ships this
    // test's premise goes with it, and the row above flips.
    const r = results.get("service-level-agreement.txt")!;
    if (r.playbook_id !== "saas-customer") return;
    const titles = r.run.findings.filter((f) => f.severity === "critical").map((f) => f.title);
    expect(titles).toContain("No indemnification clause detected");
  });
});
