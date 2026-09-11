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
]);

/** A double-quoted string literal, escapes respected. */
const STRING_LITERAL = /"(?:[^"\\\n]|\\.)*"/g;

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

    for (const file of files) {
      const src = readFileSync(file, "utf8");
      for (const line of src.split("\n")) {
        // Comments explain the markup they mention; only shipped strings count.
        if (/^\s*(?:\/\/|\*\s|\/\*)/.test(line)) continue;
        for (const lit of line.match(STRING_LITERAL) ?? []) {
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
