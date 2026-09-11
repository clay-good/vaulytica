/**
 * A Word report is not a Markdown file.
 *
 * OBLI-008's explanation shipped as:
 *
 *     "…*Bloor v. Falstaff* (2d Cir. 1979) and its progeny treat `best
 *      efforts` as the most demanding…"
 *
 * and the `.docx` a lawyer sends to a client rendered every asterisk and
 * backtick **literally**. So did the HTML report and the findings CSV. The
 * prose is authored once and shown on six surfaces, and Markdown is the
 * convention of exactly ONE of them — the fix list. 55 lines across 21 rule
 * files carried it: case names in italics (`*McLaren Macomb*`, `*Brulotte /
 * Kimble*`, `*Shelley v. Kraemer*`) and quoted phrases in code spans
 * (`` `best efforts` ``, `` `shall maintain insurance` ``).
 *
 * The single owner is the prose itself, so it was fixed there rather than by
 * stripping markup per surface: a case name is plain text and a quoted phrase
 * takes the single quotes this codebase's prose already uses ('Net 30', 'gag
 * clause'). Every surface is then right with no rendering code at all.
 *
 * 🚨 Rule prose is covered by `result_hash`, so this moved every golden. The
 * regeneration changed hashes and nothing else — no finding, id, severity or
 * count.
 */
import { readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";
import { DOCUMENT_READING_ROOTS, declaredExceptions, sourceFiles } from "./_recognizer-sources.js";

/**
 * Backticks around a FIELD NAME in a schema-validation message are a terminal
 * convention, not report prose: these strings reach a user who supplied a
 * malformed playbook file, in a monospaced CLI error, and never reach a .docx.
 * Every entry is asserted to still fire, so a stale one fails here.
 */
const NOT_REPORT_PROSE = declaredExceptions([
  {
    file: "src/playbooks/types.ts",
    pattern: "requires `deprecated: true`",
    why: "zod message naming two schema fields, shown only in a CLI validation error",
  },
  {
    file: "src/playbooks/custom-playbook.ts",
    pattern: "needs `pattern` or `section_heading`",
    why: "zod message naming two schema fields, shown only in a CLI validation error",
  },
  {
    file: "src/playbooks/custom-interpreter.ts",
    pattern: "(?:auto(?:matic(?:ally)?)?",
    why: "REGEX SOURCE for the auto-renewal recognizer, not prose — the asterisks are quantifiers",
  },
]);

/**
 * A function whose name ends in `Markdown` renders Markdown by contract, and
 * its asterisks and backticks are the point.
 *
 * This is the principled form of the exemption: not a list of files, which
 * goes stale the moment a renderer moves, but the naming convention the
 * codebase already follows (`diffPlaybooksMarkdown`,
 * `buildClosingChecklistMarkdown`, `buildFixListMarkdown`). A renderer that
 * leaves the convention loses the exemption, which is the right default.
 */
const MARKDOWN_RENDERER = /^(?:export\s+)?(?:async\s+)?function\s+(\w*Markdown)\s*\(/;

/** A double-quoted string literal, escapes respected. */
const STRING_LITERAL = /"(?:[^"\\\n]|\\.)*"/g;

/**
 * A single-line TEMPLATE literal, escapes respected.
 *
 * 🚨 The first form of this guard read double-quoted literals only, and a
 * template literal is precisely where a code span gets written: it is the
 * literal you reach for when the prose INTERPOLATES the phrase it is quoting.
 * `RISK-015` and `IPDATA-007` shipped
 *
 *     `Indemnification language is present (\`${hit.raw}\`) but no clause…`
 *
 * through the sweep that closed this class over 21 rule files, and printed a
 * literal backtick on 47 findings across the corpus. A sweep's blind spot is
 * not a gap in the thing it sweeps.
 */
const TEMPLATE_LITERAL = /`(?:[^`\\]|\\.)*`/g;

/**
 * The literals on one line, as the READER of the report will see them.
 *
 * A template literal's own delimiters are backticks, so they are stripped
 * before the markup test — otherwise every template literal reads as one giant
 * code span — and the escaped backticks INSIDE it are unescaped, because a
 * `\`` in the source is a backtick on the page.
 *
 * Single-quoted literals are not scanned: Prettier holds this codebase to
 * double quotes, so a `'…'` in the source is a quoted phrase INSIDE another
 * literal (the convention this guard recommends), not a literal of its own.
 */
function literalsOn(line: string): string[] {
  const out = [...(line.match(STRING_LITERAL) ?? [])];
  for (const t of line.match(TEMPLATE_LITERAL) ?? []) {
    out.push(t.slice(1, -1).replace(/\\`/g, "`"));
  }
  return out;
}

/**
 * Markdown that renders as itself outside a Markdown viewer.
 *
 * `**bold**` and `*emphasis*` reach the reader as asterisks; a `` ` `` code
 * span reaches them as a backtick. Each pattern requires a closing mark on the
 * same string, so an asterisk used as a footnote marker or a multiplication
 * sign ("2 * the fees") is not caught — it is the PAIR that is markup.
 */
const MARKUP: ReadonlyArray<[name: string, re: RegExp]> = [
  ["bold (**…**)", /\*\*[A-Za-z][^*]{2,80}?\*\*/],
  ["emphasis (*…*)", /(?<![\w*\\])\*(?!\*)[A-Za-z][^*]{2,80}?\*(?![\w*])/],
  ["code span (`…`)", /`[^`\n]{1,80}?`/],
];

describe("report prose carries no Markdown", () => {
  it("no rule's prose renders as asterisks and backticks in a Word report", () => {
    const files = DOCUMENT_READING_ROOTS.flatMap((r) => sourceFiles(join(process.cwd(), r)));
    // Anti-vacuity: an empty walk finds no markup, which is indistinguishable
    // from prose that has none.
    expect(files.length, "no rule sources found — the walk is broken").toBeGreaterThan(50);

    const offenders: string[] = [];
    let literals = 0;

    const markdownRenderersSkipped = new Set<string>();

    for (const file of files) {
      const src = readFileSync(file, "utf8");
      // The renderer the walk is currently inside, by this codebase's flat
      // one-function-per-top-level-declaration module style.
      let currentFn = "";
      for (const line of src.split("\n")) {
        const declared = /^(?:export\s+)?(?:async\s+)?function\s+(\w+)/.exec(line);
        if (declared) currentFn = declared[1]!;
        if (MARKDOWN_RENDERER.test(line)) markdownRenderersSkipped.add(currentFn);
        if (currentFn.endsWith("Markdown")) continue;
        // Comments explain the markup they mention; only shipped strings count.
        if (/^\s*(?:\/\/|\*\s|\/\*)/.test(line)) continue;
        for (const lit of literalsOn(line)) {
          literals += 1;
          for (const [name, re] of MARKUP) {
            if (!re.test(lit)) continue;
            if (NOT_REPORT_PROSE.exempts(file, lit)) continue;
            offenders.push(
              `${relative(process.cwd(), file).replace(/\\/g, "/")}: ${name} in ${lit.slice(0, 90)}`,
            );
          }
        }
      }
    }

    expect(literals, "no string literals were examined").toBeGreaterThan(500);
    // Anti-vacuity for the exemption itself: if the naming convention moves,
    // the skip silently stops applying and this guard starts reporting a
    // Markdown renderer's own Markdown as a defect.
    expect(
      [...markdownRenderersSkipped].sort(),
      "no *Markdown renderer was skipped — the naming convention moved",
    ).not.toEqual([]);
    expect(
      offenders,
      "this prose reaches a .docx, an HTML report and a CSV, none of which render Markdown — " +
        "use plain text for a case name and single quotes for a quoted phrase",
    ).toEqual([]);

    // An exception that no longer fires is indistinguishable from a wrong one,
    // and a path-keyed set silently stops applying on Windows unless something
    // asserts it was USED.
    expect(
      NOT_REPORT_PROSE.unused(),
      "these NOT_REPORT_PROSE entries no longer fire — delete them",
    ).toEqual([]);
  });
});
