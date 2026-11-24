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
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { unzipSync } from "fflate";
import { ingestDocxBuffer } from "../../src/ingest/docx.js";
import { flattenText } from "../../src/ingest/types.js";
import { fiveKindRedlineDocx } from "./_redline-docx.js";

const DIR = join(process.cwd(), "tests", "fixtures", "redline");
/** The committed redline, which every independent reader below is pointed at. */
const REDLINE_PATH = join(DIR, "five-kind-redline.docx");

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

/**
 * An independent implementation that needs no human: Apple's text engine
 * (add-redline-two-sided-analysis task 1, the accepted side).
 *
 * 🥇 I recorded this task as "needs Word, and producing the exports is one
 * human action". That was true of the artifacts I had imagined and false of
 * the REQUIREMENT. What the round trip needs is a second implementation's
 * reading of ECMA-376 — and macOS ships one. `textutil` reads .docx through
 * Apple's own text engine, which has nothing to do with this repository, and
 * it resolves tracked changes on its way to plain text.
 *
 * It gives exactly one reading, with no accept/reject switch, and that reading
 * is the ACCEPTED one. So this closes half the task by a better route than the
 * one the task described: scripted, reproducible on any Mac, no human step and
 * no committed binary. The REJECTED side still has no independent producer —
 * `textutil` cannot be asked for it — so the Word round trip above stays armed
 * for that half.
 *
 * ⚠️ The comparison is word sequences, not bytes or lines. Apple's engine
 * writes a table row as two lines where this product writes `cell | cell`, and
 * it leaves a trailing space where this one does not. Those are serialization
 * differences and the question is which WORDS survive a revision — so both
 * sides are reduced to their words in order. Nothing is sorted or de-duplicated:
 * a lost clause, a duplicated moved clause or a substituted figure still fails.
 */
describe("this product's accepted reading against Apple's text engine", () => {
  /** macOS only. `textutil` is not on Linux, where CI runs. */
  function hasTextutil(): boolean {
    try {
      execFileSync("textutil", ["-info", REDLINE_PATH], { stdio: "ignore", timeout: 30_000 });
      return true;
    } catch {
      return false;
    }
  }

  /** The words, in order — see the note above on what is normalized away. */
  const words = (s: string): string =>
    s
      .replace(/\|/g, " ")
      .split(/\s+/)
      .filter((w) => w.length > 0)
      .join(" ");

  const available = hasTextutil();

  it.runIf(available)(
    "reads the five-kind redline exactly as Apple's engine does, accepted",
    async () => {
      const theirs = words(
        execFileSync("textutil", ["-convert", "txt", REDLINE_PATH, "-stdout"], {
          encoding: "utf8",
          timeout: 120_000,
        }),
      );
      expect(theirs.length, "textutil returned nothing").toBeGreaterThan(50);
      expect(words(await ourReading("accepted"))).toBe(theirs);
    },
    180_000,
  );

  it.runIf(available)(
    "is discriminating: Apple's reading is NOT this product's rejected one",
    async () => {
      // The proof that the assertion above can fail. If the two readings were
      // interchangeable here, matching one of them would say nothing about
      // whether revisions are resolved correctly.
      const theirs = words(
        execFileSync("textutil", ["-convert", "txt", REDLINE_PATH, "-stdout"], {
          encoding: "utf8",
          timeout: 120_000,
        }),
      );
      expect(words(await ourReading("rejected"))).not.toBe(theirs);
    },
    180_000,
  );

  it.skipIf(available)("is skipped off macOS, where there is no textutil", () => {
    expect(available).toBe(false);
  });
});

/**
 * The rewritten DOCX this product emits must be openable by an engine that is
 * not this one.
 *
 * ⚠️ READ WHAT THIS DOES AND DOES NOT PROVE. It is **not** an independent check
 * of reject SEMANTICS — both sides of the assertion get their words from this
 * product's own rewrite, so it cannot catch a wrong decision about which words
 * survive. That is what the accepted comparison above does, and what the armed
 * Word round trip is still waiting to do for the rejected side.
 *
 * What it does prove is the property nothing else covered: that
 * `withRevisionsRejected` emits a .docx a THIRD-PARTY parser can open, and that
 * the parser recovers the same word sequence. The existing property test
 * asserts the rewrite "contains no revision elements", which this repository
 * checks with this repository's own reader — so a rewrite that left unbalanced
 * tags, an orphaned `w:r` outside its `w:p`, or a broken zip entry could pass
 * every test here and fail in the one place it matters, the user's Word. This
 * closes that gap with the engine macOS already ships.
 *
 * How a failure actually presents: `textutil` does not error on malformed
 * OOXML — it exits 0 and prints nothing. See the note on the length assertion
 * inside, which is the line that catches it.
 */
describe("the rejected DOCX this product writes, opened by Apple's engine", () => {
  function hasTextutil(): boolean {
    try {
      execFileSync("textutil", ["-info", REDLINE_PATH], { stdio: "ignore", timeout: 30_000 });
      return true;
    } catch {
      return false;
    }
  }
  const words = (s: string): string =>
    s
      .replace(/\|/g, " ")
      .split(/\s+/)
      .filter((w) => w.length > 0)
      .join(" ");
  const available = hasTextutil();

  it.runIf(available)(
    "opens as a valid DOCX and yields the same words this product reads",
    async () => {
      const { withRevisionsRejected } = await import("../../src/ingest/docx-revisions.js");
      const { mkdtempSync, writeFileSync } = await import("node:fs");
      const { tmpdir } = await import("node:os");

      const rewritten = withRevisionsRejected(asArrayBuffer(readFileSync(REDLINE_PATH)));
      const out = join(mkdtempSync(join(tmpdir(), "vaulytica-rejected-")), "rejected.docx");
      writeFileSync(out, new Uint8Array(rewritten));

      const theirs = words(
        execFileSync("textutil", ["-convert", "txt", out, "-stdout"], {
          encoding: "utf8",
          timeout: 120_000,
        }),
      );
      // 🚨 THE LENGTH ASSERTION IS LOAD-BEARING — do not remove it as
      // redundant. It was measured here on 2026-11-24: given malformed OOXML,
      // `textutil` does NOT fail. It exits 0 and prints NOTHING. All three
      // malformations tried — a dropped `</w:p>`, a `<w:p>` renamed so its
      // runs are orphaned, and an XML file truncated at 70% — produced exit 0
      // and empty output. So there is no exception to catch, and without this
      // line a rewrite that emitted unopenable OOXML would compare "" against
      // "" and pass.
      expect(
        theirs.length,
        "Apple's engine returned nothing for the rewritten DOCX, which is how it reports malformed OOXML",
      ).toBeGreaterThan(50);
      expect(words(await ourReading("rejected"))).toBe(theirs);
      // And it really is the rejected reading, not the original bytes read
      // twice: the insertion's word must be gone and the deletion's restored.
      expect(theirs).toContain("thirty");
      expect(theirs).not.toContain("fifteen");
    },
    180_000,
  );
});

/**
 * The REJECTED reading, independently — by inverting the markup instead of the
 * reader (add-redline-two-sided-analysis task 1, the other half).
 *
 * 🥇 `textutil` resolves revisions one way only: it accepts them. I took that
 * to mean it could not speak to the rejected reading, and recorded the rejected
 * half as still needing Word. That was the same mistake as before, one level
 * down — reasoning about the READER's options instead of the requirement.
 *
 * Accepting insertions and dropping deletions over a document whose insertions
 * and deletions have been SWAPPED yields the original's rejected reading. So
 * the trick is to invert the input markup and let Apple's engine do exactly the
 * work it already does:
 *
 *   `w:ins` ⟷ `w:del`     and their text: `w:t` ⟷ `w:delText`
 *   `w:moveTo` ⟷ `w:moveFrom`  (same text swap — a move is a del/ins pair)
 *   `w:rPrChange` untouched — a formatting change adds and removes no words
 *
 * ⚠️ HOW INDEPENDENT IS IT, precisely. The resolution — which words survive —
 * is done by Apple's engine in both directions, and the swap reuses nothing
 * from `src/ingest/docx-revisions.ts`: one relabels markup and defers, the
 * other rewrites the document directly. So a wrong decision in our reject
 * logic (dropping the moved clause, keeping the insertion, losing a table
 * cell) fails this test. What it cannot rule out is a bug in the swap that
 * happens to mirror a bug in the rewrite. That residual is bounded by the two
 * self-checks below, and it is why the Word round trip above stays armed:
 * Word's own export would need no such argument. This is materially stronger
 * than nothing and honestly weaker than Word.
 *
 * 🚨 The swap was wrong twice before it was right, and both ways were silent.
 * `<w:del([^>]*)>` also matches `<w:delText ...>`, which destroyed every
 * deleted run; and sentinelling only one direction let the second pass
 * re-match what the first had just written. Both produced a DOCX `textutil`
 * read as empty — never as an error, per the note above. Hence the involution
 * check: swapping twice must reproduce the original byte for byte.
 */
describe("this product's rejected reading, via inverted markup", () => {
  function hasTextutil(): boolean {
    try {
      execFileSync("textutil", ["-info", REDLINE_PATH], { stdio: "ignore", timeout: 30_000 });
      return true;
    } catch {
      return false;
    }
  }
  const words = (s: string): string =>
    s
      .replace(/\|/g, " ")
      .split(/\s+/)
      .filter((w) => w.length > 0)
      .join(" ");

  /** `w:t` → `w:delText` across one revision block's inner XML. */
  const toDel = (inner: string): string =>
    inner.replace(/<w:t(?=[ >])/g, "<w:delText").replace(/<\/w:t>/g, "</w:delText>");
  /** `w:delText` → `w:t`, the inverse. */
  const toIns = (inner: string): string =>
    inner.replace(/<w:delText(?=[ >])/g, "<w:t").replace(/<\/w:delText>/g, "</w:t>");

  /** Swap which side of every revision is the insertion. An involution. */
  function swapRevisionRoles(xml: string): string {
    let out = xml;
    for (const [a, b] of [
      ["w:ins", "w:del"],
      ["w:moveTo", "w:moveFrom"],
    ] as const) {
      // `(?=[ >])` so `w:del` never matches `w:delText`, and \0 sentinels on
      // BOTH outputs so neither pass re-matches what the other just wrote.
      out = out.replace(
        new RegExp(`<${a}(?=[ >])([^>]*)>([\\s\\S]*?)</${a}>`, "g"),
        (_m, attrs: string, inner: string) => `<\0${b}${attrs}>${toDel(inner)}</\0${b}>`,
      );
      out = out.replace(
        new RegExp(`<${b}(?=[ >])([^>]*)>([\\s\\S]*?)</${b}>`, "g"),
        (_m, attrs: string, inner: string) => `<\0${a}${attrs}>${toIns(inner)}</\0${a}>`,
      );
      out = out.split("\0").join("");
    }
    return out;
  }

  const available = hasTextutil();
  const DOC = "word/document.xml";

  it("is an involution, and preserves every revision element", async () => {
    // Self-check one, and it runs everywhere — no textutil needed. Both earlier
    // versions of the swap failed this while producing a DOCX that merely read
    // as empty.
    const { unzipSync, strFromU8 } = await import("fflate");
    const xml = strFromU8(unzipSync(new Uint8Array(readFileSync(REDLINE_PATH)))[DOC]!);
    const once = swapRevisionRoles(xml);
    expect(once).not.toBe(xml);
    expect(swapRevisionRoles(once), "swapping twice must be the identity").toBe(xml);
    for (const tag of ["w:ins", "w:del", "w:delText", "w:moveFrom", "w:moveTo", "w:rPrChange"]) {
      const count = (s: string) => s.split(new RegExp(`<${tag}(?=[ >/])`)).length - 1;
      expect(count(once), `${tag} count changed`).toBe(count(xml));
    }
  }, 60_000);

  it.runIf(available)(
    "reads the same words Apple's engine gets from the inverted redline",
    async () => {
      const { unzipSync, zipSync, strFromU8, strToU8 } = await import("fflate");
      const { mkdtempSync, writeFileSync } = await import("node:fs");
      const { tmpdir } = await import("node:os");

      const entries = unzipSync(new Uint8Array(readFileSync(REDLINE_PATH)));
      const swapped = swapRevisionRoles(strFromU8(entries[DOC]!));
      const out = join(mkdtempSync(join(tmpdir(), "vaulytica-swapped-")), "swapped.docx");
      writeFileSync(out, zipSync({ ...entries, [DOC]: strToU8(swapped) }));

      const theirs = words(
        execFileSync("textutil", ["-convert", "txt", out, "-stdout"], {
          encoding: "utf8",
          timeout: 120_000,
        }),
      );
      // Load-bearing, as always with textutil: malformed OOXML is reported as
      // exit 0 and empty output, which is how both broken swaps presented.
      expect(
        theirs.length,
        "Apple's engine returned nothing — the swap is malformed",
      ).toBeGreaterThan(50);
      expect(words(await ourReading("rejected"))).toBe(theirs);
      // The revisions really were inverted: the deletion's text is back, the
      // insertion's is gone, and the moved clause sat still.
      expect(theirs).toContain("thirty (30) days");
      expect(theirs).not.toContain("fifteen");
      expect(theirs).toContain("invoice. Interest accrues");
    },
    180_000,
  );

  it.runIf(available)(
    "is discriminating: the inverted reading is NOT the accepted one",
    async () => {
      const { unzipSync, zipSync, strFromU8, strToU8 } = await import("fflate");
      const { mkdtempSync, writeFileSync } = await import("node:fs");
      const { tmpdir } = await import("node:os");
      const entries = unzipSync(new Uint8Array(readFileSync(REDLINE_PATH)));
      const out = join(mkdtempSync(join(tmpdir(), "vaulytica-swapped2-")), "swapped.docx");
      writeFileSync(
        out,
        zipSync({ ...entries, [DOC]: strToU8(swapRevisionRoles(strFromU8(entries[DOC]!))) }),
      );
      const theirs = words(
        execFileSync("textutil", ["-convert", "txt", out, "-stdout"], {
          encoding: "utf8",
          timeout: 120_000,
        }),
      );
      expect(words(await ourReading("accepted"))).not.toBe(theirs);
    },
    180_000,
  );
});
