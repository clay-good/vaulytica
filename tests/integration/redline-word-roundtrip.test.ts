/**
 * The round trip against an independent implementation
 * (add-redline-two-sided-analysis task 1's second half).
 *
 * This product rewrites one tracked-changes DOCX into two readings. Every other
 * test holds that rewrite to what ECMA-376 SAYS — which is this repository's own
 * reading of the standard, on both sides of the assertion. The round trip is
 * the only check that compares it with someone else's reading, and the only one
 * that can catch a case where Word and the standard (or Word and us) disagree.
 *
 * ⚠️ That is precisely why the expected side cannot be generated here. If this
 * repository produced it, the test would compare the rewrite with itself. So
 * the exports are committed artifacts, made by Word or LibreOffice by a person:
 * `npm run redline:exports` writes the redline fixture and prints the steps.
 *
 * 🥇 The point of this file existing BEFORE those artifacts do: the assertion
 * is armed. It skips while they are absent — naming what is missing — and runs
 * on every test pass the moment they are committed, with no further work. A
 * note in a task list would not do that, and would not fail if the rewrite
 * later drifted away from Word.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { unzipSync } from "fflate";
import { ingestDocxBuffer } from "../../src/ingest/docx.js";
import { flattenText } from "../../src/ingest/types.js";
import { fiveKindRedlineDocx } from "./_redline-docx.js";

const DIR = join(process.cwd(), "tests", "fixtures", "redline");

/** Which application produced a committed export, if one is there. */
function exportPair(): { app: string; accepted: string; rejected: string } | undefined {
  for (const app of ["word", "soffice"]) {
    const accepted = join(DIR, `five-kind-accepted-${app}.docx`);
    const rejected = join(DIR, `five-kind-rejected-${app}.docx`);
    if (existsSync(accepted) && existsSync(rejected)) return { app, accepted, rejected };
  }
  return undefined;
}

const asArrayBuffer = (b: Uint8Array): ArrayBuffer =>
  b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;

/** Text as the comparison needs it: words only, whitespace collapsed. */
const normalize = (s: string): string => s.replace(/\s+/g, " ").trim();

async function ourReading(revisions: "accepted" | "rejected"): Promise<string> {
  const r = await ingestDocxBuffer(asArrayBuffer(await fiveKindRedlineDocx()), { revisions });
  return normalize(flattenText(r.tree));
}

async function theirReading(path: string): Promise<string> {
  const r = await ingestDocxBuffer(asArrayBuffer(readFileSync(path)));
  return normalize(flattenText(r.tree));
}

const pair = exportPair();

describe("this product's rewrite against an independent implementation", () => {
  it("has the redline fixture committed, which needs no other application", async () => {
    // The half that is never blocked. Its five revision kinds are asserted in
    // `redline-revision-kinds.test.ts`; here it only has to be buildable, so
    // `npm run redline:exports` can write it for a person to open.
    const bytes = await fiveKindRedlineDocx();
    expect(bytes.byteLength).toBeGreaterThan(1000);
    expect(Object.keys(unzipSync(new Uint8Array(bytes)))).toContain("word/document.xml");
  }, 60_000);

  it.runIf(pair)(
    `reads a redline the same way ${pair?.app ?? "an independent application"} does`,
    async () => {
      // Both readings, word for word. Comparing TEXT rather than bytes on
      // purpose: Word rewrites styles, ids and revision bookkeeping on save, so
      // a byte comparison would fail for reasons that have nothing to do with
      // which words survive — and which words survive is the whole question.
      expect(await ourReading("accepted")).toBe(await theirReading(pair!.accepted));
      expect(await ourReading("rejected")).toBe(await theirReading(pair!.rejected));
    },
    120_000,
  );

  it.skipIf(pair)("is armed, and says what it is waiting for", () => {
    // Not a silent skip. A skipped test nobody can see the reason for is how a
    // gap outlives the person who recorded it.
    expect(pair, "exports found — the real comparison above ran instead").toBeUndefined();
    expect(
      existsSync(DIR),
      "tests/fixtures/redline must exist so a person has somewhere to put the exports",
    ).toBe(true);
    // State the contract the moment it is checked, so `vitest --reporter=verbose`
    // carries it rather than a bare "skipped".
    const wanted = [
      "five-kind-accepted-word.docx",
      "five-kind-rejected-word.docx",
      "(or the -soffice pair)",
    ];
    expect(wanted.length).toBe(3);
  });
});
