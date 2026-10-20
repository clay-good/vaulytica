/**
 * The contract abstract and the inventory (add-contract-abstract-inventory).
 *
 * Each cell is a projection of what the extractor read, with the section it
 * was read from, and a blank where it read nothing. These tests hold that,
 * the CSV's two lines of context, the formula guard, and the determinism the
 * `inventory_hash` promises (no clock, no input order).
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { analyzeText, loadAccuracyDeps } from "../../tools/cli/api.js";
import { titleCorpus } from "../../src/playbooks/matcher.js";
import {
  buildDocumentAbstract,
  buildInventory,
  buildInventoryCsv,
  buildInventoryJson,
} from "../../src/report/abstract.js";
import { ABSTRACT_STATEMENT } from "../../src/report/disclaimers.js";

const SUPPLY = `SUPPLY AGREEMENT

This Supply Agreement (this "Agreement") is made as of June 3, 2026 between Acme Components, Inc., a Delaware corporation ("Supplier"), and Beta Devices LLC, an Ohio limited liability company ("Buyer").

1. Supply. Supplier shall sell and Buyer shall purchase the Products listed in Schedule A.

12. Miscellaneous.

12.1 Governing Law. This Agreement is governed by the laws of the State of New York, without regard to its conflict of laws principles.

12.2 Venue. Any dispute arising out of this Agreement shall be brought exclusively in the state or federal courts located in New York County, New York.
`;

async function abstractOf(text: string, file: string) {
  const deps = await loadAccuracyDeps({});
  const r = await analyzeText(text, file, { deps });
  return buildDocumentAbstract({
    file,
    tree: r.ingest.tree,
    run: r.run,
    playbookName: r.playbook.name,
    title: titleCorpus(r.ingest.tree, file).split("\n")[0]!.trim(),
  });
}

afterEach(() => {
  vi.useRealTimers();
});

describe("the abstract of one document", () => {
  it("projects the facts the extractor read, with where it read them", async () => {
    const a = await abstractOf(SUPPLY, "supply.txt");
    expect(a.title).toBe("SUPPLY AGREEMENT");
    expect(a.parties.map((p) => [p.name, p.role])).toEqual(
      expect.arrayContaining([
        ["Acme Components, Inc", "Supplier"],
        ["Beta Devices LLC", "Buyer"],
      ]),
    );
    // No defined Effective Date: the preamble's own "made as of" date.
    expect(a.effective_date).toEqual({ value: "2026-06-03" });
    expect(a.governing_law).toEqual({ value: "New York", section: "§ 12.1" });
    expect(a.forum?.section).toBe("§ 12.2");
    expect(a.result_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("leaves a cell blank when the document does not state the fact", async () => {
    const a = await abstractOf("SHORT NOTE\n\nThe parties met and talked.\n", "note.txt");
    expect(a.effective_date).toBeUndefined();
    expect(a.governing_law).toBeUndefined();
    expect(a.renewal).toBeUndefined();
  });
});

describe("the inventory", () => {
  it("writes the header, then the statement with the coverage, then the rows", async () => {
    const inventory = await buildInventory(
      [await abstractOf(SUPPLY, "supply.txt")],
      [{ file: "scan.pdf", reason: "Invalid PDF structure." }],
    );
    const lines = buildInventoryCsv(inventory).trimEnd().split("\r\n");
    expect(lines[0]!.startsWith("file,document_type,")).toBe(true);
    expect(lines[1]!).toContain(ABSTRACT_STATEMENT);
    expect(lines[1]!).toContain("Filled, of 1:");
    expect(lines[2]!.startsWith("supply.txt,")).toBe(true);
    expect(lines[3]!).toMatch(/^scan\.pdf,not analyzed,,Invalid PDF structure\./);
    expect(inventory.coverage.governing_law).toBe(1);
    expect(JSON.parse(buildInventoryJson(inventory)).statement).toBe(ABSTRACT_STATEMENT);
  });

  it("guards a title that would run as a spreadsheet formula", async () => {
    const hostile = `=HYPERLINK("http://example.test","Open")\n\n${SUPPLY}`;
    const inventory = await buildInventory([await abstractOf(hostile, "hostile.txt")]);
    const row = buildInventoryCsv(inventory).split("\r\n")[2]!;
    expect(row).toContain(`"'=HYPERLINK(`);
  });

  it("is the same inventory whatever order the files arrive in, and whatever the date", async () => {
    const a = await abstractOf(SUPPLY, "a-supply.txt");
    const b = await abstractOf(SUPPLY.replace("SUPPLY AGREEMENT", "PURCHASE AGREEMENT"), "b.txt");
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
    const first = await buildInventory([a, b]);
    vi.setSystemTime(new Date("2031-07-15T12:00:00Z"));
    const second = await buildInventory([b, a]);
    expect(second.inventory_hash).toBe(first.inventory_hash);
    expect(buildInventoryCsv(second)).toBe(buildInventoryCsv(first));
    expect(first.rows.map((r) => r.title)).toEqual(["PURCHASE AGREEMENT", "SUPPLY AGREEMENT"]);
  });
});
