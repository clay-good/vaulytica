/**
 * Reviewed-copy export invariants (add-word-comment-export).
 *
 * The reviewed copy is the attorney's own DOCX plus anchored Word
 * comments — nothing else. These tests pin the promises that make that
 * safe: the body is the uploaded body (strip the inserted comment
 * markers and you get the original document.xml back, byte for byte),
 * no tracked-change elements are ever introduced (lint, not draft),
 * output is deterministic, and no finding is ever dropped — anchored
 * or collected in the document-start aggregation comment.
 */

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { strFromU8, unzipSync } from "fflate";
import { describe, expect, it } from "vitest";

import { analyzeFile } from "../../tools/cli/api.js";
import {
  buildReviewedDocx,
  indexDocumentText,
  locateExcerpt,
} from "../../src/report/docx-comments.js";
import type { EngineRun } from "../../src/engine/finding.js";

const CONTRACTS = join(process.cwd(), "tests", "fixtures", "contracts");
const FIXTURE = join(CONTRACTS, "bad-nda.docx");

function toArrayBuffer(b: Buffer): ArrayBuffer {
  const ab = new ArrayBuffer(b.byteLength);
  new Uint8Array(ab).set(b);
  return ab;
}

/** Strip exactly the marker patterns the writer inserts. */
function stripCommentMarkers(xml: string): string {
  return xml
    .replace(/<w:commentRangeStart w:id="\d+"\/>/g, "")
    .replace(/<w:commentRangeEnd w:id="\d+"\/>/g, "")
    .replace(
      /<w:r><w:rPr><w:rStyle w:val="CommentReference"\/><\/w:rPr><w:commentReference w:id="\d+"\/><\/w:r>/g,
      "",
    );
}

const COMMENT_PARTS = new Set([
  "word/document.xml",
  "word/comments.xml",
  "word/_rels/document.xml.rels",
  "[Content_Types].xml",
]);

describe("buildReviewedDocx — invariants", () => {
  it("is deterministic, body-preserving, and never drops a finding", async () => {
    const original = toArrayBuffer(readFileSync(FIXTURE));
    const r = await analyzeFile(FIXTURE);
    expect(r.run.findings.length).toBeGreaterThan(0);

    const a = buildReviewedDocx(original, r.run);
    const b = buildReviewedDocx(original, r.run);
    expect(Buffer.from(a.bytes).equals(Buffer.from(b.bytes))).toBe(true);
    expect(a.anchored + a.unanchored).toBe(r.run.findings.length);

    const inEntries = unzipSync(new Uint8Array(original));
    const outEntries = unzipSync(a.bytes);

    // Only comment-related parts may differ; everything else is the
    // attorney's own bytes, untouched.
    for (const [name, data] of Object.entries(outEntries)) {
      if (COMMENT_PARTS.has(name)) continue;
      expect(inEntries[name], `unexpected new entry ${name}`).toBeDefined();
      expect(Buffer.from(data).equals(Buffer.from(inEntries[name]!)), `${name} changed`).toBe(true);
    }

    // The body IS the uploaded body: strip the inserted markers and the
    // original document.xml comes back byte for byte.
    const outDoc = strFromU8(outEntries["word/document.xml"]!);
    const inDoc = strFromU8(inEntries["word/document.xml"]!);
    expect(stripCommentMarkers(outDoc)).toBe(inDoc);

    // Lint, not draft: no tracked-change elements, ever.
    expect(outDoc).not.toMatch(/<w:ins\b|<w:del\b/);

    // Every anchored finding's comment carries its rule id; the comments
    // part is declared and wired.
    const commentsXml = strFromU8(outEntries["word/comments.xml"]!);
    for (const f of r.run.findings) expect(commentsXml).toContain(f.rule_id);
    expect(strFromU8(outEntries["word/_rels/document.xml.rels"]!)).toContain("comments.xml");
    expect(strFromU8(outEntries["[Content_Types].xml"]!)).toContain("/word/comments.xml");
  });

  it("the commented span contains the finding's excerpt (anchor round-trip)", async () => {
    const original = toArrayBuffer(readFileSync(FIXTURE));
    const r = await analyzeFile(FIXTURE);
    const out = unzipSync(buildReviewedDocx(original, r.run).bytes);
    const outDoc = strFromU8(out["word/document.xml"]!);

    const anchorable = r.run.findings.filter((f) =>
      locateExcerpt(
        indexDocumentText(strFromU8(unzipSync(new Uint8Array(original))["word/document.xml"]!)),
        f.excerpt.text,
      ),
    );
    expect(anchorable.length).toBeGreaterThan(0);

    // For each comment id, the text between its range markers must contain
    // the corresponding finding's excerpt (whitespace-normalized).
    const commentsXml = strFromU8(out["word/comments.xml"]!);
    const ids = [...commentsXml.matchAll(/w:comment w:id="(\d+)"/g)].map((m) => m[1]!);
    for (const id of ids.slice(0, anchorable.length)) {
      const start = outDoc.indexOf(`<w:commentRangeStart w:id="${id}"/>`);
      const end = outDoc.indexOf(`<w:commentRangeEnd w:id="${id}"/>`);
      expect(start, `range for comment ${id}`).toBeGreaterThanOrEqual(0);
      expect(end).toBeGreaterThan(start);
      const spanText = indexDocumentText(outDoc.slice(start, end)).text.replace(/\s+/g, " ");
      const excerpt = anchorable[Number(id)]?.excerpt.text.replace(/\s+/g, " ").trim();
      if (excerpt && excerpt.length >= 8) {
        expect(spanText).toContain(excerpt);
      }
    }
  });

  it("unanchorable findings land in one aggregation comment — never dropped", async () => {
    const original = toArrayBuffer(readFileSync(FIXTURE));
    const r = await analyzeFile(FIXTURE);
    const doctored: EngineRun = JSON.parse(JSON.stringify(r.run)) as EngineRun;
    doctored.findings[0]!.excerpt.text = "THIS TEXT APPEARS NOWHERE IN THE DOCUMENT AT ALL";

    const result = buildReviewedDocx(original, doctored);
    expect(result.unanchored).toBeGreaterThanOrEqual(1);
    expect(result.anchored + result.unanchored).toBe(doctored.findings.length);

    const out = unzipSync(result.bytes);
    const commentsXml = strFromU8(out["word/comments.xml"]!);
    expect(commentsXml).toContain("could not be anchored");
    expect(commentsXml).toContain(doctored.findings[0]!.rule_id);
  });

  it("rejects a non-DOCX container", () => {
    expect(() =>
      buildReviewedDocx(new ArrayBuffer(8), { findings: [] } as unknown as EngineRun),
    ).toThrow();
  });

  it("corpus sweep: every fixture DOCX round-trips with the count invariant", async () => {
    const fixtures = readdirSync(CONTRACTS).filter((f) => f.endsWith(".docx"));
    expect(fixtures.length).toBeGreaterThan(5);
    for (const name of fixtures) {
      const path = join(CONTRACTS, name);
      const original = toArrayBuffer(readFileSync(path));
      const r = await analyzeFile(path);
      const result = buildReviewedDocx(original, r.run);
      expect(result.anchored + result.unanchored, name).toBe(r.run.findings.length);
      const out = unzipSync(result.bytes);
      const stripped = stripCommentMarkers(strFromU8(out["word/document.xml"]!));
      const inDoc = strFromU8(unzipSync(new Uint8Array(original))["word/document.xml"]!);
      expect(stripped, name).toBe(inDoc);
    }
  }, 120_000);
});
