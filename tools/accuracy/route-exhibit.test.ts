/**
 * The maintainer's tool for adding an EDGAR exhibit to the routing sample
 * (spec-v53 §8): the record it writes carries the route and the hash, and no
 * part of the exhibit.
 */
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { htmlToText, main, recordFileName, routeExhibit, writeRecord } from "./route-exhibit.js";
import { loadAccuracyDeps, type AccuracyDeps } from "./pipeline.js";
import { RoutingLabelTableSchema, RoutingRecordSchema, measureRouting } from "./routing.js";

const EXHIBIT_HTML = `<html><head><title>EX-10.1</title><style>p{margin:0}</style></head>
<body><!-- filed by a filing agent -->
<p align="center"><b>CONSULTING AGREEMENT</b></p>
<p>This Consulting Agreement is entered into as of March&nbsp;2, 2026 between Alder Corporation (the &ldquo;Company&rdquo;) and Jordan Reyes (the &#8220;Consultant&#8221;).</p>
<p>1. Services. Consultant will advise the Company on logistics &amp; routing as an independent contractor.</p>
<p>2. Fees. The Company will pay Consultant $200 per hour.</p>
<script>track()</script>
</body></html>`;

const LABELS = RoutingLabelTableSchema.parse([
  {
    label: "consulting agreement",
    exact: "consulting-agreement",
    acceptable: ["independent-contractor"],
  },
]);
const FACTS = {
  accession: "0001193125-24-123456",
  exhibit_url: "https://www.sec.gov/Archives/edgar/data/1/000119312524123456/d1ex101.htm",
  retrieved_at: "2026-10-11",
  title: "Consulting Agreement",
  label: "consulting agreement",
};

let deps: AccuracyDeps;
let tmp: string;
beforeAll(async () => {
  deps = await loadAccuracyDeps();
  tmp = mkdtempSync(join(tmpdir(), "vaulytica-route-"));
}, 60_000);
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

describe("reading a saved exhibit", () => {
  it("turns EDGAR HTML into the text a reader sees", () => {
    const text = htmlToText(EXHIBIT_HTML);
    expect(text.split("\n")[0]).toBe("CONSULTING AGREEMENT");
    expect(text).toContain("as of March 2, 2026 between Alder Corporation (the “Company”)");
    expect(text).toContain("(the “Consultant”)");
    expect(text).toContain("logistics & routing");
    expect(text).not.toMatch(/<|track\(\)|margin:0|filing agent|EX-10\.1/);
    // The same file always yields the same text, and so the same hash.
    expect(htmlToText(EXHIBIT_HTML)).toBe(text);
  });
});

describe("the record", () => {
  it("holds the route and the hash, and no part of the exhibit", async () => {
    const text = htmlToText(EXHIBIT_HTML);
    const record = await routeExhibit({ ...FACTS, text }, LABELS, deps);
    expect(record.observed_route).toBe("consulting-agreement");
    expect(record.text_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(Object.keys(record).sort()).toEqual(
      [
        "accession",
        "exhibit_url",
        "label",
        "observed_route",
        "retrieved_at",
        "text_sha256",
        "title",
      ].sort(),
    );
    const written = JSON.stringify(record);
    for (const phrase of ["Jordan Reyes", "Alder Corporation", "logistics", "$200"]) {
      expect(written, phrase).not.toContain(phrase);
    }
    expect(RoutingRecordSchema.parse(record)).toEqual(record);
    expect(measureRouting([record], LABELS, ["consulting-agreement"]).counts.exact).toBe(1);
  });

  it("refuses a label that is not a row of the table, and an exhibit with no text", async () => {
    const text = htmlToText(EXHIBIT_HTML);
    await expect(
      routeExhibit({ ...FACTS, text, label: "advice contract" }, LABELS, deps),
    ).rejects.toThrow(/not a row of corpus\/routing\/labels\.json/);
    await expect(routeExhibit({ ...FACTS, text: "  \n " }, LABELS, deps)).rejects.toThrow(
      /no text/,
    );
    await expect(
      routeExhibit({ ...FACTS, text, exhibit_url: "https://example.com/ex.htm" }, LABELS, deps),
    ).rejects.toThrow();
  });

  it("is written once: the same exhibit twice is refused", async () => {
    const dir = join(tmp, "records-a");
    const record = await routeExhibit({ ...FACTS, text: htmlToText(EXHIBIT_HTML) }, LABELS, deps);
    const path = await writeRecord(record, dir);
    expect(path.endsWith(recordFileName(record))).toBe(true);
    expect(recordFileName(record)).toBe(
      `${FACTS.accession}-${record.text_sha256.slice(0, 8)}.json`,
    );
    await expect(writeRecord(record, dir)).rejects.toThrow(/already in the sample/);
    expect(readdirSync(dir)).toHaveLength(1);
  });
});

describe("the command", () => {
  it("writes one record into the corpus it is pointed at, and nothing else", async () => {
    const corpus = join(tmp, "corpus");
    mkdirSync(join(corpus, "routing"), { recursive: true });
    writeFileSync(join(corpus, "routing", "labels.json"), JSON.stringify(LABELS));
    const saved = join(tmp, "ex10-1.htm");
    writeFileSync(saved, EXHIBIT_HTML);
    const line = await main(
      [
        "--file",
        saved,
        "--accession",
        FACTS.accession,
        "--url",
        FACTS.exhibit_url,
        "--retrieved",
        FACTS.retrieved_at,
        "--title",
        FACTS.title,
        "--label",
        FACTS.label,
      ],
      corpus,
    );
    expect(line).toMatch(/^Routed to consulting-agreement\. Wrote .*no exhibit text\.$/);
    const files = readdirSync(join(corpus, "routing", "records"));
    expect(files).toHaveLength(1);
    const body = readFileSync(join(corpus, "routing", "records", files[0]!), "utf8");
    expect(body).not.toContain("Jordan Reyes");
    expect(RoutingRecordSchema.parse(JSON.parse(body)).observed_route).toBe("consulting-agreement");
  });

  it("says what is missing", async () => {
    await expect(main(["--file", join(tmp, "nope.htm")], tmp)).rejects.toThrow(/no such file/);
    const saved = join(tmp, "ex.pdf");
    writeFileSync(saved, "x");
    await expect(main(["--file", saved], tmp)).rejects.toThrow(/save the exhibit as \.htm/);
    await expect(main([], tmp)).rejects.toThrow(/missing --file/);
  });
});
