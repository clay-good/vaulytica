/**
 * Changing a document's FORMAT must not change what the engine says about it.
 *
 * Text copied out of a PDF keeps its line breaks and loses its blank lines,
 * and it is one of the commonest things a reviewer pastes in. Paragraphs in
 * the paste path were separated by blank lines ALONE, so such a document
 * arrived as ONE paragraph: a mutual release that reads as thirty-five
 * paragraphs became a single six-thousand-character block. Every internal
 * cross-reference in it was reported unresolved — with no paragraph boundaries
 * there is no numbered-clause label left to resolve against — and every
 * paragraph-scoped rule degraded the same way: the negation window, the
 * excerpt, the section scope.
 *
 * Twenty-seven of the ninety-two specimens survived that treatment unchanged.
 * Two were mis-routed outright: an all-caps guaranty to `complaint`, a GDPR
 * privacy notice to `dpa-controller-processor` with eighty-three findings.
 *
 * This is the same method as `allcaps-guaranty.txt`: take a document the
 * engine already handles and change only its FORMAT. Nothing about the words
 * changed, so any difference is the engine's.
 *
 * The list below is debt, not design. It may only shrink.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText } from "../../tools/cli/api.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

/**
 * The five format transforms, each with the specimens whose finding SET still
 * moves under it. Routing is invariant under EVERY transform for EVERY
 * specimen, with no exceptions — a document that is reformatted must not
 * become a different kind of document — and only the finding sets carry debt.
 *
 * Each list may only shrink.
 */

/**
 * Specimens whose finding SET still moves when the blank lines go. Each is a
 * paragraph-boundary sensitivity in one rule, not a routing failure — the
 * routing is invariant across the whole corpus and is asserted for every
 * specimen below, with no exceptions.
 *
 * Mostly attachment detection (STRUCT-018 counts a reference it can no longer
 * pair with a heading), signature-block detection (STRUCT-003), and the
 * placeholder / carve-out rules that read a paragraph as their unit.
 */
const KNOWN_UNSTABLE = new Set<string>([
  "83b-election.txt",
  "advance-directive.txt",
  "cease-and-desist.txt",
  "cre-psa.txt",
  "media-release.txt",
  "option-grant.txt",
  "po-terms.txt",
  "saas-tos.txt",
]);

const SPECIMENS = readdirSync(DIR)
  .filter((f) => f.endsWith(".txt"))
  .sort();

/** The same text with every blank line removed, as a PDF copy-paste produces. */
function stripBlankLines(text: string): string {
  return text
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .join("\n");
}

/** The same text with Windows line endings, as half the world's files have. */
function crlf(text: string): string {
  return text.replace(/\n/g, "\r\n");
}

/**
 * The same text hard-wrapped at 62 columns, as a mail client, a legacy export,
 * or a justified PDF column produces — including the break AT a hyphen that
 * turns "month-to-month" into two lines.
 */
function hardWrap(text: string, width = 62): string {
  const out: string[] = [];
  for (const line of text.split("\n")) {
    if (line.trim().length === 0) {
      out.push("");
      continue;
    }
    let rest = line.trim();
    while (rest.length > width) {
      const slice = rest.slice(0, width + 1);
      const cut = Math.max(slice.lastIndexOf(" "), slice.lastIndexOf("-"));
      if (cut <= 0) break;
      out.push(rest.slice(0, cut + (slice[cut] === "-" ? 1 : 0)).trimEnd());
      rest = rest.slice(cut + 1).trimStart();
    }
    out.push(rest);
  }
  return out.join("\n");
}

/**
 * The same text as Word writes it: paired curly quotes and curly apostrophes.
 * This one has always held — it is here so it keeps holding.
 */
function smartQuotes(text: string): string {
  let open = true;
  let out = "";
  for (const ch of text) {
    if (ch === '"') {
      out += open ? "\u201C" : "\u201D";
      open = !open;
    } else if (ch === "'") {
      out += "\u2019";
    } else {
      out += ch;
      if (ch === "\n") open = true;
    }
  }
  return out;
}

/**
 * The format axes that must not change a single finding, on any specimen.
 *
 * Each was found by running the whole corpus through the transform and reading
 * what moved: CRLF cost a general warranty deed its title (a Windows blank
 * line is "\r\n\r\n", and the blank-line test read the raw text); hard
 * wrapping broke "month-to-month" across a line and the join put a space in
 * the middle of it.
 */
const LOSSLESS_TRANSFORMS: Array<[string, (t: string) => string]> = [
  ["CRLF line endings", crlf],
  ["hard-wrapped at 62 columns", hardWrap],
  ["Word smart quotes", smartQuotes],
];

/** A blank line between EVERY line, as a double-spaced export produces. */
function doubleSpaced(text: string): string {
  return text.split("\n").join("\n\n");
}

/**
 * The mirror of stripping the blank lines: every line becomes its own
 * paragraph, so a construct laid out over two lines — a signature rule and the
 * name under it, an exhibit reference and its heading — arrives split.
 *
 * This list started at fourteen and is down to one. Every entry that came off
 * it came off because the DOUBLE-SPACED reading was the correct one and the
 * normal case held a false positive: only the first entry of an attachment
 * list counted as attached, and a signatory named twice in a signature block
 * was reported as an undefined defined-term.
 */
const DOUBLE_SPACED_UNSTABLE = new Set<string>(["revocable-trust.txt"]);

describe("format is not load-bearing", () => {
  it("the corpus is present", () => {
    expect(SPECIMENS.length).toBeGreaterThan(50);
  });

  it.each(SPECIMENS)(
    "%s routes the same with its blank lines stripped",
    async (name) => {
      const text = readFileSync(join(DIR, name), "utf8");
      const normal = await analyzeText(text, name);
      const stripped = await analyzeText(stripBlankLines(text), name);
      // Routing is invariant for EVERY specimen, with no exceptions: a
      // document that loses its blank lines must not become a different kind
      // of document.
      expect(stripped.run.playbook_id, `${name} re-routed`).toBe(normal.run.playbook_id);
    },
    120_000,
  );

  it.each(SPECIMENS.filter((n) => !KNOWN_UNSTABLE.has(n)))(
    "%s reports the same findings with its blank lines stripped",
    async (name) => {
      const text = readFileSync(join(DIR, name), "utf8");
      const normal = await analyzeText(text, name);
      const stripped = await analyzeText(stripBlankLines(text), name);
      const ids = (r: typeof normal) => [...new Set(r.run.findings.map((f) => f.rule_id))].sort();
      expect(ids(stripped)).toEqual(ids(normal));
    },
    120_000,
  );

  it.each(
    LOSSLESS_TRANSFORMS.flatMap(([label, fn]) =>
      SPECIMENS.map((n) => [`${n} — ${label}`, n, fn] as const),
    ),
  )(
    "%s",
    async (_label, name, transform) => {
      const text = readFileSync(join(DIR, name), "utf8");
      const normal = await analyzeText(text, name);
      const transformed = await analyzeText(transform(text), name);
      const ids = (r: typeof normal) => [...new Set(r.run.findings.map((f) => f.rule_id))].sort();
      expect(transformed.run.playbook_id).toBe(normal.run.playbook_id);
      expect(ids(transformed)).toEqual(ids(normal));
    },
    120_000,
  );

  it.each(SPECIMENS)(
    "%s routes the same double-spaced",
    async (name) => {
      const text = readFileSync(join(DIR, name), "utf8");
      const normal = await analyzeText(text, name);
      const spaced = await analyzeText(doubleSpaced(text), name);
      expect(spaced.run.playbook_id, `${name} re-routed`).toBe(normal.run.playbook_id);
    },
    120_000,
  );

  it.each(SPECIMENS.filter((n) => !DOUBLE_SPACED_UNSTABLE.has(n)))(
    "%s reports the same findings double-spaced",
    async (name) => {
      const text = readFileSync(join(DIR, name), "utf8");
      const normal = await analyzeText(text, name);
      const spaced = await analyzeText(doubleSpaced(text), name);
      const ids = (r: typeof normal) => [...new Set(r.run.findings.map((f) => f.rule_id))].sort();
      expect(ids(spaced)).toEqual(ids(normal));
    },
    120_000,
  );

  it("every listed specimen is still unstable, so the list cannot outlive its entries", async () => {
    // A specimen that has become stable must be REMOVED from the list, or the
    // list silently permits the instability to come back.
    const stable: string[] = [];
    for (const [list, transform] of [
      [KNOWN_UNSTABLE, stripBlankLines],
      [DOUBLE_SPACED_UNSTABLE, doubleSpaced],
    ] as const) {
      for (const name of list) {
        const text = readFileSync(join(DIR, name), "utf8");
        const normal = await analyzeText(text, name);
        const other = await analyzeText(transform(text), name);
        const ids = (r: typeof normal) => [...new Set(r.run.findings.map((f) => f.rule_id))].sort();
        if (JSON.stringify(ids(normal)) === JSON.stringify(ids(other))) stable.push(name);
      }
    }
    expect(
      stable.sort(),
      `these specimens are stable now — take them off KNOWN_UNSTABLE:\n  ${stable.join("\n  ")}`,
    ).toEqual([]);
  }, 300_000);
});
