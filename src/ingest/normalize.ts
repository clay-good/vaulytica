import type { DocumentTree, Paragraph, Run, Section } from "./types.js";
import { makeParagraphId, makeRunId, makeSectionId } from "./types.js";
import { MAX_SECTION_DEPTH } from "./limits.js";
import { runningHeaderCopies, stripPageFurniture } from "./page-furniture.js";

/**
 * Iteratively collect every paragraph in a subtree in document order, without
 * recursion — so flattening a pathologically deep subtree (spec-v8 §7
 * recursion guard) cannot itself overflow the stack.
 */
function collectDescendantParagraphs(sections: Section[]): Paragraph[] {
  const out: Paragraph[] = [];
  const stack: Section[] = [...sections].reverse();
  while (stack.length > 0) {
    const s = stack.pop()!;
    for (const p of s.paragraphs) out.push(p);
    for (let i = s.children.length - 1; i >= 0; i -= 1) stack.push(s.children[i]!);
  }
  return out;
}

/**
 * Normalize a DocumentTree:
 *
 * - assign stable ids (`s1`, `s1.1`, `s1.p2`, `s1.p2.r0`, ...) based on
 *   document-order position, replacing whatever the upstream ingest produced;
 * - assign contiguous character offsets to every run, computed exactly from
 *   the run text after whitespace normalization;
 * - normalize whitespace inside runs: collapse runs of internal whitespace
 *   to a single space, trim only trailing whitespace at end-of-paragraph
 *   boundaries, preserve newlines that separate paragraphs (paragraphs
 *   themselves are the boundary — runs never contain `\n`);
 * - drop empty paragraphs and empty runs.
 *
 * Pure function: same input tree (structurally) ⇒ same output tree.
 */
export function normalize(tree: DocumentTree): DocumentTree {
  let cursor = 0;

  // The running header can only be recognized across the whole document — it is
  // the document's own title, repeated — so it is identified once here and
  // handed to the per-section pass alongside the page numbers.
  const headerCopies = runningHeaderCopies(collectDescendantParagraphs(tree.sections));

  // Collapse runs of ANY Unicode whitespace (`\s`) to a single ASCII space —
  // not just `[ \t\r\n]`. Two reasons: (1) determinism — a finding's text and
  // offsets must not depend on whether a drafter typed a regular space, a
  // non-breaking space (U+00A0), or an ideographic space (U+3000); they are all
  // semantically a space. (2) Robustness — the downstream extractors match with
  // `\s`, which spans those exotic whitespace characters, but the *old* fold
  // left them intact, so a crafted run of thousands of NBSPs reached the
  // extractors and drove several regexes into O(n²) backtracking (a ReDoS hang,
  // spec-v8 §5). Folding them here removes the run at the source for every
  // extractor at once. ASCII-only documents (every fixture) are byte-unchanged.
  /** U+2160-216F, in codepoint order. */
  const ROMAN_NUMERAL_FORMS = [
    "I",
    "II",
    "III",
    "IV",
    "V",
    "VI",
    "VII",
    "VIII",
    "IX",
    "X",
    "XI",
    "XII",
    "L",
    "C",
    "D",
    "M",
  ] as const;

  const normalizeRunText = (text: string): string => {
    // First strip zero-width / soft-hyphen format characters that carry no
    // semantic content and, crucially, are NOT matched by JS `\s`: SOFT HYPHEN
    // (U+00AD) and the zero-width family (U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ,
    // U+2060 WORD JOINER). Word and PDF line-wrapping routinely inject these
    // mid-word ("in­clude"); left in place they split a word for every
    // downstream literal/word-boundary regex — silently defeating a presence
    // disclaimer ("does not include …") into a false accusation, or a trigger
    // word into a silent under-scan. Removing (not spacing) them rejoins the
    // word. ASCII-only documents (every fixture) are byte-unchanged.
    //
    // Then drop the C0/DEL control characters that XML 1.0 forbids outright
    // (Char production excludes #x0\u2013#x8, #xB\u2013#xC, #xE\u2013#x1F, #x7F). OCR/PDF
    // extraction routinely leaves these stray bytes in the text; left in, they
    // flow through every finding into the DOCX report and the "reviewed copy",
    // producing an OOXML part a strict parser (or Word) rejects as corrupt.
    // \t (#x9), \n (#xA), \r (#xD) are legal and, along with the illegal but
    // whitespace #xB/#xC, are handled by the `\s+`\u2192space collapse below.
    // Then expand the LATIN LIGATURES a PDF text layer emits for these letter
    // pairs: U+FB00 ff, U+FB01 fi, U+FB02 fl, U+FB03 ffi, U+FB04 ffl. They are
    // the VISIBLE sibling of the invisible characters above — "notiﬁcation",
    // "conﬁdential", "beneﬁciary", "eﬀective", "conﬂict" all read correctly to
    // a human and match nothing at all, because no recognizer in the catalog
    // spells them. Not one of the 310 specimens contains a ligature; ligating
    // the corpus moved a finding on **125 of 307** of them, which is the widest
    // divergence any probe in this repo has produced. Every PDF this tool
    // ingests is a candidate.
    //
    // Expansion is length-CHANGING, exactly as the removals around it are, and
    // the offsets a finding carries are computed after this fold — so an
    // excerpt still quotes the normalized text it was found in.
    return (
      text
        .replace(/[\u00AD\u200B-\u200D\u2060]/g, "")
        .replace(/\uFB00/g, "ff")
        .replace(/\uFB01/g, "fi")
        .replace(/\uFB02/g, "fl")
        .replace(/\uFB03/g, "ffi")
        .replace(/\uFB04/g, "ffl")
        .replace(/\uFB05|\uFB06/g, "st")
        // The rest of the same class: PRESENTATION FORMS that render as
        // ordinary characters and match none of them.
        //
        //  - FULLWIDTH ASCII (U+FF01-FF5E). An English contract typed on a
        //    CJK input method, or exported from one, carries "（a）" and
        //    "Ｓｅｃｔｉｏｎ". 182 of 290 specimens moved a finding when the
        //    corpus was rewritten with fullwidth parentheses alone — the
        //    widest of all of them. The offset is a fixed 0xFEE0.
        //  - HYPHEN (U+2010) and NON-BREAKING HYPHEN (U+2011), alongside the
        //    MINUS SIGN (U+2212) that was already folded here. Unicode's own
        //    name for U+002D is HYPHEN-MINUS and for U+2010 is HYPHEN: they
        //    are the same character, and only one of them is on a keyboard. A
        //    PDF text layer emits U+2010 routinely and Word inserts U+2011
        //    wherever a compound must not break across a line, so "non-
        //    disclosure", "third-party", "arm's-length" and "co-employment"
        //    arrive spelled with a character no recognizer in the catalog
        //    contains. Rewriting the corpus with U+2010 between letters moved
        //    a finding on a THIRD of the specimens and re-routed one outright,
        //    and its loudest effect was a false positive: FIN-001 fired on 75
        //    of 285, because a hyphen it could not read broke the number it
        //    was reading. This is the apostrophe defect of the last session
        //    one character over.
        //  - MINUS SIGN (U+2212), which a PDF emits for the hyphen in a range:
        //    "30−60 days", "Sections 5−9".
        //  - NUMERO (U+2116) for "No.", as in "Statement of Work № 4".
        //  - ROMAN NUMERAL FORMS (U+2160-216F) for "Article Ⅶ". A document
        //    that numbers its articles this way had no articles at all.
        .replace(/[\uFF01-\uFF5E]/g, (c) => String.fromCharCode(c.charCodeAt(0) - 0xfee0))
        .replace(/[\u2010\u2011\u2212]/g, "-")
        .replace(/\u2116/g, "No.")
        .replace(/[\u2160-\u216F]/g, (c) => ROMAN_NUMERAL_FORMS[c.charCodeAt(0) - 0x2160] ?? c)
        // A FOOTNOTE MARKER. A PDF puts one inline — "…as set out below.¹" —
        // where it reads as part of the sentence and matches nothing: 177 of
        // 311 specimens moved a finding when one was placed after each
        // sentence, because the marker sits between the period and the space
        // and every sentence-boundary scan then reads two sentences as one.
        //
        // Only a marker that follows SENTENCE PUNCTUATION is removed, which is
        // where a footnote reference is placed and where the meaning is never
        // in doubt. A superscript attached to a WORD is left alone: "10²" is an
        // exponent and "500 m²" is an area, and telling those from
        // "Agreement¹" needs to know whether the word is a unit — a judgment
        // about meaning, not a fold of presentation.
        .replace(/([.;:,!?)\]"'\u201D\u2019])[\u00B2\u00B3\u00B9\u2070\u2074-\u2079]+/g, "$1")
        // eslint-disable-next-line no-control-regex
        .replace(/[\x00-\x08\x0E-\x1F\x7F]/g, "")
        .replace(/\s+/g, " ")
    );
  };

  const normalizeParagraph = (
    p: Paragraph,
    sectionId: string,
    paragraphIndex: number,
  ): Paragraph | null => {
    const runs: Run[] = [];
    let runIndex = 0;
    // A run that normalizes to a single space is not content, but when it sits
    // BETWEEN two content runs it is the only separator between two words — a
    // DOCX artifact whenever a lone space falls inside a formatting/tracked-
    // change span (e.g. "does not<b> </b>include"). Dropping it outright fused
    // the neighbours ("does notinclude"), silently defeating a downstream
    // negation/trigger regex. Defer it: carry the space forward and attach it
    // to the preceding run only once a following content run confirms it is a
    // real separator (a leading or trailing whitespace-only run stays dropped).
    let pendingSpace = false;
    for (const r of p.runs) {
      const text = normalizeRunText(r.text);
      if (text.length === 0) continue;
      if (text === " ") {
        if (runs.length > 0) pendingSpace = true;
        continue;
      }
      if (pendingSpace) {
        const prev = runs[runs.length - 1]!;
        if (!prev.text.endsWith(" ") && !text.startsWith(" ")) {
          prev.text += " ";
          cursor += 1;
          prev.end = cursor;
        }
        pendingSpace = false;
      }
      const start = cursor;
      cursor += text.length;
      runs.push({
        id: makeRunId(sectionId, paragraphIndex, runIndex),
        text,
        start,
        end: cursor,
        formatting: r.formatting,
      });
      runIndex += 1;
    }
    if (runs.length === 0) return null;
    // Trim trailing whitespace at the end of the paragraph.
    const last = runs[runs.length - 1]!;
    const trimmed = last.text.replace(/\s+$/, "");
    if (trimmed.length === 0) {
      cursor -= last.text.length;
      runs.pop();
      if (runs.length === 0) return null;
    } else if (trimmed.length !== last.text.length) {
      cursor -= last.text.length - trimmed.length;
      last.text = trimmed;
      last.end = cursor;
    }
    // Paragraph break contributes one newline to the offset stream.
    cursor += 1;
    return {
      id: makeParagraphId(sectionId, paragraphIndex),
      runs,
    };
  };

  const normalizeSection = (s: Section, path: number[]): Section => {
    const id = makeSectionId(path);
    // Normalize the heading exactly the way run text is normalized, so the
    // offset stream (and therefore every finding offset and the result_hash)
    // never depends on non-semantic whitespace in a heading. Without this, two
    // documents identical except for extra spaces/tabs in a heading produce
    // different result_hashes — a determinism leak the metamorphic suite caught
    // (spec-v7 Step 119). Clean single-spaced headings are unchanged (no churn).
    //
    // This routes through `normalizeRunText` rather than repeating its final
    // `\s+`-collapse, because the two strips that precede that collapse matter
    // just as much in a heading as in a run: Word and PDF inject soft hyphens
    // and zero-width joiners mid-word in headings too, and a heading is read
    // literally by the v4 document classifier (`headings.includes(keyword)`),
    // so an invisible U+00AD inside "Con[shy]fidentiality" silently defeats the
    // family match. C0 control bytes left in a heading flow into the DOCX
    // report the same way they would from a run, producing the OOXML a strict
    // parser rejects. The heading was the one text path that skipped both.
    const heading = normalizeRunText(s.heading).trim();
    if (heading) {
      // The heading text itself takes up its own offset span plus a newline.
      cursor += heading.length + 1;
    }
    // Recursion guard (spec-v8 §7): at the depth cap, stop recursing and
    // flatten every descendant section's paragraphs into this one (collected
    // iteratively, so a 50,000-deep hostile tree cannot overflow the stack).
    // Content is preserved; only the nesting past the cap is discarded.
    const atDepthCap = path.length >= MAX_SECTION_DEPTH;
    const ownParagraphs = atDepthCap
      ? [...s.paragraphs, ...collectDescendantParagraphs(s.children)]
      : s.paragraphs;

    const paragraphs: Paragraph[] = [];
    let pIdx = 0;
    for (const p of stripPageFurniture(ownParagraphs, headerCopies)) {
      const np = normalizeParagraph(p, id, pIdx);
      if (np) {
        paragraphs.push(np);
        pIdx += 1;
      }
    }
    const children: Section[] = atDepthCap
      ? []
      : s.children.map((c, i) => normalizeSection(c, [...path, i + 1]));
    return {
      id,
      heading,
      level: s.level,
      paragraphs,
      children,
    };
  };

  return {
    type: "document",
    sections: tree.sections.map((s, i) => normalizeSection(s, [i + 1])),
  };
}

/**
 * Count words in a tree by splitting every run on whitespace. Iterative (an
 * explicit stack, no recursion) so it is stack-safe on an arbitrarily deep
 * tree — part of the spec-v8 §7 recursion-guard contract.
 */
export function countWords(tree: DocumentTree): number {
  let n = 0;
  const stack: Section[] = [...tree.sections].reverse();
  while (stack.length > 0) {
    const s = stack.pop()!;
    if (s.heading) n += s.heading.trim().split(/\s+/).filter(Boolean).length;
    for (const p of s.paragraphs) {
      for (const r of p.runs) {
        n += r.text.trim().split(/\s+/).filter(Boolean).length;
      }
    }
    for (let i = s.children.length - 1; i >= 0; i -= 1) stack.push(s.children[i]!);
  }
  return n;
}
