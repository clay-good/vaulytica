/**
 * What a contract calls the thing it staples to the back.
 *
 * An American agreement attaches an Exhibit, an English one a Schedule, an EU
 * instrument an Annex, and Indian and South African drafting an Annexure. They
 * are the same object under six names — and six lists in this engine had
 * drifted to five different answers about which of them exist.
 *
 * Three rewritings, 73 to 83 specimens each. What they found:
 *
 *   - `crossrefs.ts`, `STRUCT-007` and `STRUCT-018` could not read an Annexure
 *     or an Appendix as an attachment at all, so a document that attached one
 *     and referred to it was told the attachment is missing.
 *   - The four subordinate-document recitals in `rules/_helpers.ts` — the ones
 *     that stand a whole column of absence checks down because the parent
 *     supplies the clause — knew Annex but not Annexure, and the SOW recital
 *     knew neither Annexure nor Appendix.
 *   - RE-009 and BNK-040 wanted a legal description on an "Exhibit A"; DISC-040
 *     wanted a document request on a "Schedule A"; IPL-101 wanted patents on a
 *     schedule or exhibit; MNA-043 wanted an SPA-keyed "Schedule 3.12".
 *   - **The MATCHER, which is where it actually hurt.** A vendor security
 *     addendum titled "Information Security Annexure" fell from
 *     `vendor-security-addendum` at confidence 1 to `incident-notification` at
 *     0.6 — a different playbook and a different set of findings — and a set of
 *     disclosure schedules retitled as annexes fell to `generic-fallback`
 *     outright. The nouns are now folded on both sides, exactly as the
 *     apostrophe and the hyphen already were.
 *
 * ── the rewriting has to be exact, and three drafts were not ──
 *
 * A heading reads "EXHIBIT A — STATEMENT OF WORK", and renaming every
 * reference while leaving the ALL-CAPS heading standing makes a document that
 * really does refer to an attachment it does not have: nine non-defects. A
 * VESTING schedule and a FEE schedule are timetables, not attachments, and
 * renaming those makes a document nobody drafts: five more. And "Schedule K-1"
 * is a form the IRS issues and a "Disclosure Schedule" is the M&A instrument
 * of that name — terms of art that keep their noun in London too, exactly as
 * "Section 409A" does.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ATTACHMENT_KIND } from "../../src/extract/attachment-kinds.js";
import { analyzeText } from "../../tools/cli/api.js";
import { loadAccuracyDeps } from "../../tools/accuracy/pipeline.js";
import { recognizerSources, sourceFiles } from "./_recognizer-sources.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");
const SPECIMENS = readdirSync(DIR).filter((f) => f.endsWith(".txt"));

/** The six nouns, lower-cased, as the canonical list declares them. */
const KINDS = ATTACHMENT_KIND.toLowerCase().split("|");

/**
 * Two terms of art that are not attachments and never change their noun.
 * Everything outside them is rewritten; these are spliced out first.
 */
const TERM_OF_ART = /\b(?:Schedule\s+K-[123]\b|Disclosure\s+Schedules?\b)/gi;

/** Apply `f` to everything except the terms of art. */
function splice(s: string, f: (part: string) => string): string {
  const out: string[] = [];
  let last = 0;
  for (const m of s.matchAll(TERM_OF_ART)) {
    out.push(f(s.slice(last, m.index)), m[0]);
    last = m.index + m[0].length;
  }
  out.push(f(s.slice(last)));
  return out.join("");
}

/**
 * Rename one attachment noun to another, in the ATTACHMENT sense only — the
 * noun must be followed by a designator. Case is carried across, ALL-CAPS
 * headings included, because a rewriting that renames the references and not
 * the heading they point at is not the same document.
 */
const rename =
  (from: string, to: string) =>
  (text: string): string =>
    splice(text, (part) =>
      part.replace(
        new RegExp(`\\b${from}(s|es)?\\b(?=\\s+(?:No\\.?\\s+)?["'“”‘’]?[A-Za-z0-9])`, "gi"),
        (m, plural: string | undefined) => {
          const word = plural
            ? to === "Appendix"
              ? "Appendices"
              : to === "Annex"
                ? "Annexes"
                : `${to}s`
            : to;
          if (m === m.toUpperCase()) return word.toUpperCase();
          if (m[0] === m[0]!.toUpperCase()) return word;
          return word.toLowerCase();
        },
      ),
    );

describe("the thing a contract staples to the back", () => {
  it("every reader of an attachment noun reads all six", () => {
    // The canonical list is SINGULAR: a caller that lower-cases the matched
    // kind to build a key would read "Appendices" as a seventh kind and report
    // the attachment it had just found as missing.
    expect(KINDS).toEqual([
      "exhibit",
      "schedule",
      "annexure",
      "annex",
      "appendix",
      "attachment",
      "addendum",
    ]);

    const files = [
      ...sourceFiles(join(process.cwd(), "src", "engine", "rules")),
      ...sourceFiles(join(process.cwd(), "src", "extract")),
    ];
    expect(files.length, "no sources found — the walk is broken").toBeGreaterThan(50);

    // A recognizer that enumerates attachment nouns — two or more of them
    // together, which is what marks it as a LIST of kinds rather than a rule
    // about one — must enumerate the ones a non-US instrument uses. "Annex"
    // alone is not enough: it is the EU noun, and it was in four lists that
    // still had no Annexure.
    const partial: string[] = [];
    for (const file of files) {
      for (const { line, text } of recognizerSources(file)) {
        const low = text.toLowerCase();
        const named = KINDS.filter((k) => new RegExp(`(?<![a-z])${k}`).test(low));
        if (named.length < 2) continue;
        const missing = ["annexure", "annex", "appendix"].filter((k) => !named.includes(k));
        if (missing.length) partial.push(`${file}:${line}  missing ${missing.join(",")}`);
      }
    }
    expect(
      partial,
      `these enumerate attachment kinds but not all of them — use ATTACHMENT_KIND:\n  ${partial.join("\n  ")}`,
    ).toEqual([]);
  });

  it.each([
    ["Exhibit", "Annexure"],
    ["Exhibit", "Appendix"],
    ["Schedule", "Annex"],
  ])(
    "renaming every %s to an %s changes no finding",
    async (from, to) => {
      const deps = await loadAccuracyDeps({});
      const mutate = rename(from, to);
      const broken: string[] = [];
      let probed = 0;
      for (const name of SPECIMENS) {
        const text = readFileSync(join(DIR, name), "utf8");
        const mutated = mutate(text);
        if (mutated === text) continue;
        probed++;
        const before = await analyzeText(text, name, { deps });
        const after = await analyzeText(mutated, name, { deps });
        const ids = (r: typeof before): string[] =>
          [...new Set(r.run.findings.map((f) => f.rule_id))].sort();
        const lost = ids(before).filter((id) => !ids(after).includes(id));
        const gained = ids(after).filter((id) => !ids(before).includes(id));
        if (lost.length || gained.length) {
          broken.push(`${name}: lost ${lost.join(",") || "-"} gained ${gained.join(",") || "-"}`);
        }
      }
      expect(probed, "the corpus never attaches anything").toBeGreaterThanOrEqual(60);
      expect(broken).toEqual([]);
    },
    300_000,
  );
});
