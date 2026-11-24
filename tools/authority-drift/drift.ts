/**
 * Has a mandated text's WORDING changed at its official source?
 *
 * The product already answers two neighbouring questions. `citation:check`
 * asks whether a citation URL still resolves. The "verify currency" label asks
 * whether a reading is older than the horizon. Neither notices the thing that
 * matters most to a rule whose premise is exact wording: **the words changed.**
 *
 * `TEXT-001` reports a notice that is "close to the text 16 C.F.R. § 433.2
 * prescribes but not the same", measured against a passage committed to this
 * repository. If the FTC amends § 433.2, that committed passage silently
 * becomes the wrong yardstick: every conforming notice is reported as altered,
 * and every notice matching the new text is reported as altered too. A stale
 * reading date would eventually hint at it after twelve months; nothing would
 * say the words moved.
 *
 * So each row carries the SHA-256 of its own committed text, and this tool
 * re-reads the section at its official source and compares. Two halves, the
 * same split `citation-check` uses:
 *
 *   - `committedDigests()` is pure — no clock, no socket — and the per-commit
 *     test asserts every row's recorded digest matches its own text, so a row
 *     cannot be edited without its digest moving.
 *   - `compareAgainstSource()` takes the fetched body and is therefore
 *     testable without a network; the scheduled path supplies the fetch.
 *
 * POSTURE: build/CI-only, never imported by `src/`. The engine opens no
 * socket.
 */
import { createHash } from "node:crypto";
import { MANDATED_TEXTS, type MandatedText } from "../../src/engine/rules/text/mandated-texts.js";

/** Whitespace-normalized, case-preserving: the form the rules compare in. */
export function normalizeForDigest(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}

export function textDigest(text: string): string {
  return createHash("sha256").update(normalizeForDigest(text), "utf8").digest("hex");
}

export type RowDigest = {
  /** `<row id>#<subsection>`, e.g. `ftc-holder-notice#§ 433.2(a)`. */
  key: string;
  citation: string;
  where: string;
  source_url: string;
  retrieved_at: string;
  digest: string;
  /** The passage itself, so a report can show what moved. */
  text: string;
};

/** Every mandated variant with the digest of its committed text. */
export function committedDigests(rows: readonly MandatedText[] = MANDATED_TEXTS): RowDigest[] {
  const out: RowDigest[] = [];
  for (const row of rows) {
    for (const v of row.variants) {
      out.push({
        key: `${row.id}#${v.where}`,
        citation: row.citation,
        where: v.where,
        source_url: row.source_url,
        retrieved_at: row.retrieved_at,
        digest: textDigest(v.text),
        text: v.text,
      });
    }
  }
  return out;
}

export type DriftVerdict =
  | { key: string; status: "unchanged" }
  | { key: string; status: "drifted"; detail: string }
  | { key: string; status: "not-found"; detail: string };

/**
 * Is the committed passage still present, verbatim, in what the source serves?
 *
 * Deliberately a CONTAINMENT test rather than an equality one. The fetched
 * body is a whole section — the regulation's own subsection labels, its
 * amendment history, and in the eCFR's case XML markup — so the passage is a
 * fragment of it. "Still there, word for word" is the question the rules care
 * about, and it is the one a containment test answers without this tool having
 * to parse every source's markup.
 *
 * `not-found` is reported, never thrown: a source that moved its markup around
 * is a result a person should read, not a crash. It is also NOT the same
 * verdict as `drifted`, because the two need different responses — re-read the
 * statute, versus fix the fetch.
 */
export function compareAgainstSource(row: RowDigest, fetchedBody: string): DriftVerdict {
  const haystack = normalizeForDigest(stripMarkup(fetchedBody));
  const needle = normalizeForDigest(row.text);
  if (haystack.includes(needle)) return { key: row.key, status: "unchanged" };
  // Case is not the requirement — § 433.2 prints its notice in capitals and a
  // contract may set it either way, and the rules compare case-blind. A
  // case-only difference is not drift.
  if (haystack.toLowerCase().includes(needle.toLowerCase())) {
    return { key: row.key, status: "unchanged" };
  }
  if (haystack.length === 0) {
    return { key: row.key, status: "not-found", detail: "the source served an empty body" };
  }
  // Say WHERE it stops matching, so a reader can see the amendment rather than
  // being told only that something differs.
  const words = needle.split(" ");
  let kept = 0;
  const lower = haystack.toLowerCase();
  while (
    kept < words.length &&
    lower.includes(
      words
        .slice(0, kept + 1)
        .join(" ")
        .toLowerCase(),
    )
  ) {
    kept++;
  }
  if (kept === 0) {
    return {
      key: row.key,
      status: "not-found",
      detail: "not one word of the passage appears in the body — check the fetch, not the statute",
    };
  }
  return {
    key: row.key,
    status: "drifted",
    detail: `the source matches the first ${kept} of ${words.length} words and then diverges, after "…${words.slice(Math.max(0, kept - 6), kept).join(" ")}"`,
  };
}

/** Tags out, entities for the few characters a regulation's text uses. */
function stripMarkup(body: string): string {
  return body
    .replace(/<[^>]*>/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&nbsp;/g, " ");
}
