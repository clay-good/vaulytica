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
 * Both debt lists below are now EMPTY: all ninety-two specimens report
 * identically under all five transforms, with no exceptions. The lists stay
 * because the assertion at the bottom is what holds them there.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText } from "../../tools/cli/api.js";
import { flattenText } from "../../src/ingest/types.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

/**
 * Specimens whose finding SET still moves when the blank lines go — none.
 *
 * The list started at eight. Five of those eight were false NEGATIVES in the
 * NORMAL case rather than false positives in the reformatted one: a signature
 * label read only at the start of its paragraph, a preamble window measured in
 * paragraphs rather than characters, a liability cap named in the section
 * HEADING, an auto-renewal clause read for its heading and no further. Each is
 * a rule that took a fact about the LAYOUT for a fact about the document.
 */
const KNOWN_UNSTABLE = new Set<string>([]);

/**
 * The CLEAN analysis of each specimen, computed once for the whole file.
 *
 * Every relation below compares a transformed specimen against its untouched
 * self, and each one used to re-analyze the untouched side from scratch — so
 * the clean corpus was analyzed once PER TRANSFORM. With ten relations over 311
 * specimens that is nine wasted passes over the entire corpus, and it pushed
 * the cross-OS matrix past its 15-minute job timeout, where a job that runs out
 * of time is reported as `cancelled` and reads, at a glance, like a run that was
 * superseded rather than one that failed.
 */
const cleanCache = new Map<string, Awaited<ReturnType<typeof analyzeText>>>();
async function clean(name: string, text: string): Promise<Awaited<ReturnType<typeof analyzeText>>> {
  const hit = cleanCache.get(name);
  if (hit) return hit;
  const result = await analyzeText(text, name);
  cleanCache.set(name, result);
  return result;
}

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
 * This list started at fourteen and is now EMPTY: double-spacing a document
 * changes nothing the engine says about it, for all ninety-two specimens.
 * Every entry that came off it came off because the DOUBLE-SPACED reading was
 * the correct one and the normal case held a false positive — only the first
 * entry of an attachment list counted as attached, a signatory named twice in
 * a signature block was reported as an undefined defined-term, and a settlor
 * whose conformed signature and printed name the paste path had joined into
 * one doubled string was reported the same way.
 *
 * It stays here, empty, because the assertion below is what holds it there.
 */
const DOUBLE_SPACED_UNSTABLE = new Set<string>([]);

/** The same text with `stamp(page)` set off on its own line every 45 lines. */
function stampEvery(text: string, stamp: (page: number) => string): string {
  const lines = hardWrap(text).split("\n");
  const out: string[] = [];
  for (let i = 0; i < lines.length; i += 1) {
    out.push(lines[i]!);
    if ((i + 1) % 45 === 0) out.push("", stamp(Math.ceil((i + 1) / 45)), "");
  }
  return out.join("\n");
}

describe("format is not load-bearing", () => {
  it("a privilege legend on every page moves no finding", async () => {
    // 36 specimens moved before page legends were recognized. One still does,
    // and it is not a defect: a hold notice short enough to cross ONE page
    // boundary carries ONE stamp, which is indistinguishable from a caption —
    // and SET-030 asks a hold notice to carry exactly that caption
    // ("Confidential — Attorney Work Product"), so the transform genuinely
    // adds meaning there rather than preserving it. A legend is only treated
    // as furniture once it REPEATS; the first one may be the document's own.
    const SEMANTIC = new Set(["litigation-hold-notice.txt"]);
    const broken: string[] = [];
    let probed = 0;
    for (const name of SPECIMENS) {
      if (SEMANTIC.has(name)) continue;
      const text = readFileSync(join(DIR, name), "utf8");
      const mutated = stampEvery(text, () => "CONFIDENTIAL — ATTORNEY WORK PRODUCT");
      if (mutated === text) continue;
      probed++;
      const normal = await clean(name, text);
      const after = await analyzeText(mutated, name);
      const ids = (r: typeof normal): string[] =>
        [...new Set(r.run.findings.map((f) => f.rule_id))].sort();
      const lost = ids(normal).filter((id) => !ids(after).includes(id));
      const gained = ids(after).filter((id) => !ids(normal).includes(id));
      if (lost.length || gained.length) {
        broken.push(`${name}: lost ${lost.join(",") || "-"} gained ${gained.join(",") || "-"}`);
      }
    }
    expect(probed).toBeGreaterThanOrEqual(250);
    expect(broken).toEqual([]);
  }, 300_000);

  it("the corpus is present", () => {
    expect(SPECIMENS.length).toBeGreaterThan(50);
  });

  it.each(SPECIMENS)(
    "%s routes the same with its blank lines stripped",
    async (name) => {
      const text = readFileSync(join(DIR, name), "utf8");
      const normal = await clean(name, text);
      const stripped = await analyzeText(stripBlankLines(text), name);
      // Routing is invariant for EVERY specimen, with no exceptions: a
      // document that loses its blank lines must not become a different kind
      // of document.
      expect(stripped.run.playbook_id, `${name} re-routed`).toBe(normal.run.playbook_id);
    },
    120_000,
  );

  it("the ligatures a PDF text layer emits move no finding", async () => {
    // The VISIBLE sibling of the soft hyphen and the zero-width characters the
    // normalizer has always folded. A PDF text layer emits U+FB01 for "fi" and
    // U+FB02 for "fl", so "notiﬁcation", "conﬁdential", "beneﬁciary",
    // "eﬀective" and "conﬂict" all read correctly to a human and match nothing
    // at all — no recognizer in the catalog spells them.
    //
    // Not one of the 310 specimens contains a ligature, and ligating the
    // corpus moved a finding on 125 of 307 before the fold was added: the
    // widest divergence any probe in this repo has produced, from a defect
    // that lives in one function. Every PDF this tool ingests is a candidate.
    const ligate = (text: string): string =>
      text
        .replace(/ffi/g, "\uFB03")
        .replace(/ffl/g, "\uFB04")
        .replace(/ff/g, "\uFB00")
        .replace(/fi/g, "\uFB01")
        .replace(/fl/g, "\uFB02");
    const broken: string[] = [];
    let probed = 0;
    for (const name of SPECIMENS) {
      const text = readFileSync(join(DIR, name), "utf8");
      const ligated = ligate(text);
      if (ligated === text) continue;
      probed++;
      const normal = await clean(name, text);
      const after = await analyzeText(ligated, name);
      const ids = (r: typeof normal): string[] =>
        [...new Set(r.run.findings.map((f) => f.rule_id))].sort();
      const lost = ids(normal).filter((id) => !ids(after).includes(id));
      const gained = ids(after).filter((id) => !ids(normal).includes(id));
      if (lost.length || gained.length) {
        broken.push(`${name}: lost ${lost.join(",") || "-"} gained ${gained.join(",") || "-"}`);
      }
    }
    expect(probed, "no specimen carries an f-ligature pair").toBeGreaterThanOrEqual(250);
    expect(broken).toEqual([]);
  }, 300_000);

  it.each([
    [
      "fullwidth punctuation",
      (t: string): string => t.replace(/\(/g, "（").replace(/\)/g, "）"),
      250,
    ],
    [
      "the minus sign a PDF emits for a hyphen",
      (t: string): string => t.replace(/(\d)\s*-\s*(\d)/g, "$1\u2212$2"),
      80,
    ],
    ["the numero sign", (t: string): string => t.replace(/\bNo\.\s*(?=\d)/g, "\u2116 "), 30],
    [
      // The page number a PDF paste carries, in the place it actually falls:
      // hard-wrapped text with "Page n of m" every 45 lines, wherever that
      // lands — usually mid-sentence. Two rules had learned to skip page
      // furniture individually and the other 1,823 had not, so 24 specimens
      // moved a finding. Deleting the line is only half the repair: the
      // sentence it interrupted arrives as two paragraphs either way, and
      // every scan that reads "the enclosing sentence" still saw half of one.
      "a page number every 45 lines of a PDF paste",
      (t: string): string => {
        const lines = hardWrap(t).split("\n");
        const pages = Math.ceil(lines.length / 45);
        const out: string[] = [];
        for (let i = 0; i < lines.length; i += 1) {
          out.push(lines[i]!);
          if ((i + 1) % 45 === 0) out.push("", `Page ${Math.ceil((i + 1) / 45)} of ${pages}`, "");
        }
        return out.join("\n");
      },
      250,
    ],
    [
      // The other half of the same paste: the RUNNING HEADER, which repeats the
      // document's own title on every page. A repeated line is not by itself
      // suspicious — ten specimens carry one, and every one of those is content
      // ("ANSWER:" eight times, counsel's name four, an execution date) — so
      // only a repetition of the OPENING BLOCK's leading text is claimed.
      "a running header every 45 lines of a PDF paste",
      (t: string): string => {
        const lines = hardWrap(t).split("\n");
        const title = t
          .split("\n")
          .find((l) => l.trim().length > 0)!
          .trim();
        const pages = Math.ceil(lines.length / 45);
        const out: string[] = [];
        for (let i = 0; i < lines.length; i += 1) {
          out.push(lines[i]!);
          if ((i + 1) % 45 === 0)
            out.push("", `Page ${Math.ceil((i + 1) / 45)} of ${pages}`, "", title, "");
        }
        return out.join("\n");
      },
      250,
    ],
    [
      // PLEADING PAPER. A court filing is typed on paper with 28 numbered
      // lines down the left edge, and a PDF text layer emits each number as
      // the first token of its line. The catalog covers complaints, motions,
      // briefs and judgments, so this is the shape a large part of it arrives
      // in — and it moved a finding on 207 of 311 specimens, the widest
      // divergence any probe here has produced except the f-ligatures.
      "pleading-paper line numbers in the left margin",
      (t: string): string => {
        let n = 0;
        return t
          .split("\n")
          .map((line) => {
            n = (n % 28) + 1;
            return line.trim().length ? `${n} ${line}` : `${n}`;
          })
          .join("\n");
      },
      250,
    ],
    [
      // A BATES NUMBER on every produced page. Unlike a legend it is DIFFERENT
      // on every page, so no repetition test can find it — the shape is all
      // there is. 29 specimens moved a finding.
      "a Bates stamp on every page",
      (t: string): string => stampEvery(t, (n) => `ACME-${String(n).padStart(6, "0")}`),
      250,
    ],
    [
      // The other page stamp a legal document carries. 29 specimens moved.
      "an EXECUTION VERSION legend on every page",
      (t: string): string => stampEvery(t, () => "EXECUTION VERSION"),
      250,
    ],
    [
      // A FOOTNOTE MARKER, in the place a PDF puts one: between the period and
      // the space after it. 177 of 311 specimens moved a finding, because a
      // marker there makes every sentence-boundary scan read two sentences as
      // one. Only a marker after sentence punctuation is folded away — a
      // superscript attached to a word ("10²", "500 m²") is left alone.
      "a footnote marker after every sentence",
      (t: string): string => {
        const SUP = ["⁰", "¹", "²", "³", "⁴", "⁵", "⁶", "⁷", "⁸", "⁹"];
        let n = 0;
        return t.replace(/([.;:])(\s)/g, (_m, punct: string, space: string) => {
          n = (n % 9) + 1;
          return `${punct}${SUP[n]!}${space}`;
        });
      },
      250,
    ],
    [
      "Roman-numeral codepoints",
      (t: string): string =>
        t.replace(
          /\b(Article|ARTICLE|Section|Annex|Exhibit|Schedule)\s+(I{1,3}|IV|VI{0,3}|IX|X)\b/g,
          (_m, kind: string, roman: string) =>
            `${kind} ${String.fromCharCode(0x2160 + ["I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X"].indexOf(roman))}`,
        ),
      15,
    ],
  ])(
    "%s moves no finding",
    async (_label, mutate, floor) => {
      // The rest of the ligature's class: presentation forms that render as
      // ordinary characters and match none of them. Fullwidth ASCII is what an
      // English contract typed on a CJK input method carries, and rewriting the
      // corpus with fullwidth parentheses alone moved a finding on 182 of 290
      // specimens — wider even than the ligatures.
      //
      // NOT folded, and recorded rather than guessed at: the SUPERSCRIPT digits
      // (U+00B9, U+2070-2079). A PDF puts a footnote marker inline — "…as set
      // out below.¹" — and 33 specimens move when one is injected, but a
      // superscript is not always noise ("10²", an ordinal "1ˢᵗ"), and dropping
      // it is a decision about meaning rather than a fold of presentation.
      const broken: string[] = [];
      let probed = 0;
      for (const name of SPECIMENS) {
        const text = readFileSync(join(DIR, name), "utf8");
        const mutated = mutate(text);
        if (mutated === text) continue;
        probed++;
        const normal = await clean(name, text);
        const after = await analyzeText(mutated, name);
        const ids = (r: typeof normal): string[] =>
          [...new Set(r.run.findings.map((f) => f.rule_id))].sort();
        const lost = ids(normal).filter((id) => !ids(after).includes(id));
        const gained = ids(after).filter((id) => !ids(normal).includes(id));
        if (lost.length || gained.length) {
          broken.push(`${name}: lost ${lost.join(",") || "-"} gained ${gained.join(",") || "-"}`);
        }
      }
      expect(probed, "the corpus never carries this shape").toBeGreaterThanOrEqual(floor);
      expect(broken).toEqual([]);
    },
    300_000,
  );

  it("one sentence per line moves no finding", async () => {
    // The OTHER direction from stripping blank lines, and the one a PDF text
    // layer actually produces: hard line breaks at every sentence, so a
    // paragraph that carried two signals together — a cap phrase and the
    // carve-out beneath it — becomes several paragraphs that carry one each.
    // Three hundred and one specimens, and the engine holds on all of them.
    // Recorded as a standing relation because paragraph boundaries are the
    // one piece of structure a rule cannot see across.
    const perSentence = (text: string): string =>
      text
        .split("\n")
        .map((line) =>
          line.length > 200 ? line.replace(/(?<=[a-z0-9)”"']\.)\s+(?=[A-Z])/g, "\n") : line,
        )
        .join("\n");
    const broken: string[] = [];
    let probed = 0;
    for (const name of SPECIMENS) {
      const text = readFileSync(join(DIR, name), "utf8");
      const split = perSentence(text);
      if (split === text) continue;
      probed++;
      const normal = await clean(name, text);
      const after = await analyzeText(split, name);
      const ids = (r: typeof normal): string[] =>
        [...new Set(r.run.findings.map((f) => f.rule_id))].sort();
      const lost = ids(normal).filter((id) => !ids(after).includes(id));
      const gained = ids(after).filter((id) => !ids(normal).includes(id));
      if (lost.length || gained.length) {
        broken.push(`${name}: lost ${lost.join(",") || "-"} gained ${gained.join(",") || "-"}`);
      }
    }
    expect(probed, "no specimen has a paragraph long enough to split").toBeGreaterThanOrEqual(250);
    expect(broken).toEqual([]);
  }, 300_000);

  it.each(SPECIMENS.filter((n) => !KNOWN_UNSTABLE.has(n)))(
    "%s reports the same findings with its blank lines stripped",
    async (name) => {
      const text = readFileSync(join(DIR, name), "utf8");
      const normal = await clean(name, text);
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
      const normal = await clean(name, text);
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
      const normal = await clean(name, text);
      const spaced = await analyzeText(doubleSpaced(text), name);
      expect(spaced.run.playbook_id, `${name} re-routed`).toBe(normal.run.playbook_id);
    },
    120_000,
  );

  it.each(SPECIMENS.filter((n) => !DOUBLE_SPACED_UNSTABLE.has(n)))(
    "%s reports the same findings double-spaced",
    async (name) => {
      const text = readFileSync(join(DIR, name), "utf8");
      const normal = await clean(name, text);
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
        const normal = await clean(name, text);
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

/**
 * A finding QUOTES the document, and the quote must be real.
 *
 * This lives HERE, beside the format relations, for one reason: it needs the
 * clean analysis of every specimen, and this file already has exactly that,
 * cached. As its own file it re-analyzed all 311 specimens from scratch; folded
 * in here it costs about 18 seconds (155.7s -> 173.5s, measured back to back —
 * absolute timings on a laptop drift by 50% between runs, so only the A/B is
 * meaningful). The concern is different; the corpus pass is the same one, and
 * the matrix budget this file dominates had just been rescued from a timeout.
 *
 * A quote that is not in the document would be the worst failure this tool
 * has: it looks exactly like evidence, and a reviewer would go hunting through
 * their own copy for a sentence that was never there.
 *
 * What is deliberately NOT asserted, because each is a real design rather than
 * a defect — written down so the next probe does not rediscover them:
 *
 *   - `excerpt.text` is readable CONTEXT and may be wider than the span. The
 *     offsets locate the matched phrase; the text gives the sentence around
 *     it. Asserting `slice(start, end) === text` fails on 594 of 858, and
 *     every one of those is the design working.
 *   - The quote and the location may point at DIFFERENT OCCURRENCES when that
 *     is the finding's point: STRUCT-014 ("defined terms used in lowercase")
 *     shows the defined form "Protected Material" while its span points at the
 *     lowercase slip.
 *   - An ABSENCE finding has nothing to quote and carries a zero-width excerpt
 *     holding a synthetic label ("(no payment-term clause)").
 */
describe("a finding's quote is really in the document", () => {
  it("every excerpt that carries a span quotes text the document contains", async () => {
    const broken: string[] = [];
    let quoted = 0;
    let labels = 0;

    for (const name of SPECIMENS) {
      const text = readFileSync(join(DIR, name), "utf8");
      const result = await clean(name, text);
      const flat = flattenText(result.ingest.tree);
      for (const f of result.run.findings) {
        const ex = f.excerpt;
        if (!ex) continue;
        if (ex.end_offset <= ex.start_offset) {
          labels += 1;
          continue;
        }
        quoted += 1;
        if (!flat.includes(ex.text)) {
          broken.push(`${name} ${f.rule_id}: ${JSON.stringify(ex.text.slice(0, 80))}`);
        }
        if (ex.end_offset > flat.length) {
          broken.push(
            `${name} ${f.rule_id}: span ends at ${ex.end_offset}, past the document's ${flat.length}`,
          );
        }
      }
    }

    // Floors, so this cannot pass by finding nothing to check.
    expect(quoted, "no finding carried a span-bearing excerpt").toBeGreaterThanOrEqual(700);
    expect(labels, "no absence finding carried a label excerpt").toBeGreaterThanOrEqual(200);
    expect(broken).toEqual([]);
  }, 600_000);
});
