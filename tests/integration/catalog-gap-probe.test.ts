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

/**
 * Tranche B (spec-v49 §4, Step 312): thirteen more candidates, measured the
 * same way on 9.878.0. All thirteen are now built or routed (9.886.0). Eight fell to the fallback. Three were judged as a
 * neighbour — a founder's stock purchase and a community memorandum of
 * understanding each drew eight criticals from an M&A pack. Two were already
 * handled, by a type whose title keywords name them.
 *
 * `wants` is the type the document should have; `today` is where it went when
 * measured. A row flips the day its type ships. Where the two are equal the
 * catalog already had it.
 */
const DIR_B = join(process.cwd(), "tests", "fixtures", "probe-v49b");
const PROBE_B: ReadonlyArray<{ file: string; wants: string; today: string }> = [
  // A beta test is an evaluation: the pilot type's checks are the ones it
  // needs, so it took the title rather than a type of its own (9.881.0).
  {
    file: "beta-test-agreement.txt",
    wants: "pilot-evaluation-agreement",
    today: "generic-fallback",
  },
  {
    file: "board-observer-agreement.txt",
    wants: "board-observer-agreement",
    today: "generic-fallback",
  },
  { file: "buy-sell-agreement.txt", wants: "buy-sell-agreement", today: "generic-fallback" },
  {
    file: "commercial-power-purchase-agreement.txt",
    wants: "commercial-power-purchase-agreement",
    today: "generic-fallback",
  },
  {
    file: "management-services-agreement.txt",
    wants: "management-services-agreement",
    today: "generic-fallback",
  },
  {
    file: "student-data-privacy-agreement.txt",
    wants: "student-data-privacy-agreement",
    today: "generic-fallback",
  },
  {
    file: "support-maintenance-agreement.txt",
    wants: "support-maintenance-agreement",
    today: "generic-fallback",
  },
  {
    file: "vehicle-purchase-agreement.txt",
    wants: "vehicle-purchase-agreement",
    today: "generic-fallback",
  },
  // The catalog had the type all along — `rspa` describes itself as the
  // founder's agreement — and did not know the founder's title for it. Until
  // 9.880.0 this went to `stock-purchase-agreement`, the M&A purchase.
  { file: "founder-stock-purchase-agreement.txt", wants: "rspa", today: "rspa" },
  {
    file: "memorandum-of-understanding.txt",
    wants: "memorandum-of-understanding",
    today: "loi-term-sheet",
  },
  // Judged as a commercial construction contract, which is the catalog's
  // deliberate home for it (its title keywords name it). A California
  // overlay is the open question, not a missing type.
  {
    file: "home-improvement-contract.txt",
    wants: "construction-contract",
    today: "construction-contract",
  },
  // Already handled.
  {
    file: "liability-waiver.txt",
    wants: "hold-harmless-agreement",
    today: "hold-harmless-agreement",
  },
  {
    file: "reseller-agreement.txt",
    wants: "distribution-agreement",
    today: "distribution-agreement",
  },
];

describe("tranche B: more documents the catalog may have no type for", () => {
  const routed = new Map<string, AnalyzeResult>();
  beforeAll(async () => {
    const deps = await loadAccuracyDeps();
    for (const { file } of PROBE_B)
      routed.set(file, await analyzeFile(join(DIR_B, file), { deps }));
    routed.set(
      "_acquisition-mou.txt",
      await analyzeFile(join(DIR_B, "_acquisition-mou.txt"), { deps }),
    );
  }, 180_000);

  it("routes each one where it was measured to go, until its type ships", async () => {
    const wrong: string[] = [];
    for (const { file, wants, today } of PROBE_B) {
      const expected = (await isDocumentType(wants)) ? wants : today;
      const actual = routed.get(file)!.playbook_id;
      if (actual !== expected) wrong.push(`${file}: routed to ${actual}, expected ${expected}`);
    }
    expect(wrong).toEqual([]);
  });

  it("a cooperation memorandum is not told it lacks a purchase price", () => {
    // The eight criticals were MNA-001…009: exclusivity, purchase price,
    // transaction structure — on a library's summer reading program.
    const r = routed.get("memorandum-of-understanding.txt")!;
    if (r.playbook_id !== "memorandum-of-understanding") return;
    expect(r.run.findings.filter((f) => f.rule_id.startsWith("MNA-"))).toEqual([]);
  });

  it("a founder's stock purchase is not scanned as an M&A stock purchase", () => {
    const r = routed.get("founder-stock-purchase-agreement.txt")!;
    expect(r.secondary_families.map((f) => f.playbook_id)).not.toContain(
      "stock-purchase-agreement",
    );
    // "at $0.0001 per share" is a purchase price.
    expect(r.run.findings.map((f) => f.rule_id)).not.toContain("EQT-036");
  });

  it("a memorandum of understanding for an acquisition is still read as a letter of intent", () => {
    expect(routed.get("_acquisition-mou.txt")!.playbook_id).toBe("loi-term-sheet");
  });
});
