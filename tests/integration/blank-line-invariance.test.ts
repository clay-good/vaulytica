/**
 * Stripping a document's blank lines must not change what the engine says
 * about it.
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
  "hold-harmless.txt",
  "media-release.txt",
  "option-grant.txt",
  "po-terms.txt",
  "revocable-trust.txt",
  "saas-tos.txt",
  "security-agreement.txt",
  "snda.txt",
  "trademark-assignment.txt",
  "warrant.txt",
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

describe("blank lines are not load-bearing", () => {
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

  it("every listed specimen is still unstable, so the list cannot outlive its entries", async () => {
    // A specimen that has become stable must be REMOVED from the list, or the
    // list silently permits the instability to come back.
    const stable: string[] = [];
    for (const name of KNOWN_UNSTABLE) {
      const text = readFileSync(join(DIR, name), "utf8");
      const normal = await analyzeText(text, name);
      const stripped = await analyzeText(stripBlankLines(text), name);
      const ids = (r: typeof normal) => [...new Set(r.run.findings.map((f) => f.rule_id))].sort();
      if (JSON.stringify(ids(normal)) === JSON.stringify(ids(stripped))) stable.push(name);
    }
    expect(
      stable.sort(),
      `these specimens are stable now — take them off KNOWN_UNSTABLE:\n  ${stable.join("\n  ")}`,
    ).toEqual([]);
  }, 300_000);
});
