/**
 * The compact projection's own promises (spec-v48 §6, §9), tested on a result
 * edited by hand: the ingest already drops most control characters, so only a
 * finding built here can show that the projection does not depend on that.
 */
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { analyzeFile, type AnalyzeResult } from "./api.js";
import { BRIEF_EXCERPT_CHARS, buildBrief, buildBriefJson } from "./brief.js";

const NDA = join(process.cwd(), "tests", "fixtures", "specimens", "mutual-nda-complete.txt");
const CONTROLS = "A\u0007B\u001b[31mC\u0000D\u2028E\u2029F\u0085G\nH\r\tI";

let result: AnalyzeResult;
beforeAll(async () => {
  result = await analyzeFile(NDA, { secondaryFamilies: true });
});

/** The result with its first finding's document-derived strings replaced. */
function hostile(text: string): AnalyzeResult {
  const [first, ...rest] = result.run.findings;
  return {
    ...result,
    run: {
      ...result.run,
      source_file: { ...result.run.source_file, name: text },
      findings: [
        { ...first!, title: text, excerpt: { ...first!.excerpt, text, section_label: text } },
        ...rest,
      ],
    },
  };
}

describe("the compact projection", () => {
  it("flattens every document-derived string to one printable line", () => {
    const b = buildBrief(hostile(CONTROLS));
    const f = b.findings[0]!;
    for (const value of [f.excerpt!, f.title, f.section_label!, b.document.name]) {
      // eslint-disable-next-line no-control-regex
      expect(value).not.toMatch(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/);
      expect(value).toMatch(/^A B \[31mC D E F G H I$/);
    }
    // One line of JSON, whatever the document said.
    expect(buildBriefJson(hostile(CONTROLS)).split("\n")).toHaveLength(1);
  });

  it("caps each quoted string and says when it cut", () => {
    const b = buildBrief(hostile("word ".repeat(500)));
    const f = b.findings[0]!;
    // A LABEL is cut at the cap exactly: `truncate` stops at the character
    // limit, which is right for a title or a file name.
    for (const value of [f.title, f.section_label!, b.document.name]) {
      expect(value.length).toBe(BRIEF_EXCERPT_CHARS);
      expect(value.endsWith("…")).toBe(true);
    }
    // ⚠️ The EXCERPT is the document's own words, so it is cut at the last word
    // boundary inside the cap and comes back a few characters shorter. The
    // documented contract is a CAP — "a quoted excerpt is capped here; the
    // offsets still locate the whole span" — and `.toBe(cap)` was asserting the
    // hard cut's arithmetic rather than that contract.
    expect(f.excerpt!.length).toBeLessThanOrEqual(BRIEF_EXCERPT_CHARS);
    expect(f.excerpt!.length).toBeGreaterThan(BRIEF_EXCERPT_CHARS - 25);
    expect(f.excerpt!.endsWith("…")).toBe(true);
    // The quote ends on a word: no partial token before the ellipsis.
    expect(f.excerpt!).toMatch(/\w…$/);
    // The offsets still locate the whole span.
    expect(f.end_offset).toBe(result.run.findings[0]!.excerpt.end_offset);
  });

  it("drops the excerpt and keeps the id and offsets when asked", () => {
    const f = buildBrief(result, { excerpts: false }).findings[0]!;
    expect(f).not.toHaveProperty("excerpt");
    expect(f.id).toBe(result.run.findings[0]!.id);
    expect(typeof f.start_offset).toBe("number");
  });

  it("replaces the execution log with two counts", () => {
    const b = buildBrief(result);
    expect(b).not.toHaveProperty("execution_log");
    expect(b.rules_registered).toBe(result.run.execution_log.length);
    expect(b.rules_run).toBe(result.run.execution_log.filter((e) => e.ran).length);
    expect(b.rules_run).toBeLessThan(b.rules_registered);
  });

  it("keeps one citation and the total", () => {
    const many = result.run.findings.find((f) => f.source_citations.length > 0)!;
    const f = buildBrief(result).findings.find((x) => x.id === many.id)!;
    expect(f.citation).toEqual({
      source: many.source_citations[0]!.source,
      source_url: many.source_citations[0]!.source_url,
    });
    expect(f.citations_total).toBe(many.source_citations.length);
  });
});
