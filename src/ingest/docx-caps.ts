/**
 * Which paragraphs Word DISPLAYS in capitals (`w:caps` / `w:smallCaps`).
 *
 * 🚨 The defect this exists for. `TEXT-003` asks whether a warranty disclaimer
 * is conspicuous, and U.C.C. § 1-201(b)(10) counts capitals as one way to be.
 * The rule tested the TEXT's own case — and a Word user who applies All Caps
 * formatting, which is the ordinary way to do it, leaves the stored text mixed
 * case. Mammoth drops `w:caps` entirely, so the ingest never saw it either.
 *
 * Measured before this module existed: the same document fired `TEXT-003`
 * identically with and without `w:caps` on the disclaimer, so a disclaimer
 * Word displays in capitals was reported as "in plain body type". That is a
 * false statement about the document, which is the most expensive kind of
 * wrong this product can be.
 *
 * ⚠️ The task list recorded this item as "`w:caps` is not read, and no row
 * needs capitals". The second half was wrong: no MANDATED TEXT row needs
 * capitals, but `TEXT-003` does, and it is not a mandated-text row.
 *
 * Read from `word/document.xml` directly, like `docx-sizes.ts` reads `w:sz`,
 * and keyed by the paragraph's text as the tree will carry it.
 *
 * Scope, stated rather than implied: a run's own `w:rPr` and the paragraph's
 * `w:pPr/w:rPr` are read. A character or paragraph STYLE that sets caps
 * without the run saying so is not followed — `w:sz` needed that chain because
 * most text inherits its size, whereas `w:caps` is nearly always applied
 * directly. A missed caps marker leaves the previous behaviour, which is the
 * safe direction here: it can only make the rule speak, never silence it
 * wrongly.
 */
import { inflateOoxmlParts } from "./ooxml.js";

/** The text of a paragraph, normalized the way the tree carries it. */
function normalize(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}

/** Decode the handful of entities OOXML text uses. */
function decode(xml: string): string {
  return xml
    .replace(/<[^>]*>/g, "")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'");
}

/** `<w:caps/>` or `<w:smallCaps/>`, not explicitly switched off. */
function setsCaps(rPr: string | undefined): boolean {
  if (!rPr) return false;
  // 🚨 OOXML spells these `w:caps` and `w:smallCaps` — the first LOWERCASE.
  // A `(?:small)?Caps` pattern matches only the second, which is the rarer of
  // the two, so the common case was silently missed and this module returned an
  // empty set. Both spellings, named explicitly.
  for (const m of rPr.matchAll(/<w:(?:caps|smallCaps)\b([^>]*)\/?>/g)) {
    // `<w:caps w:val="0"/>` turns it OFF, which Word writes when a style set
    // it on and the run overrides.
    if (!/\bw:val="(?:0|false|off)"/.test(m[1] ?? "")) return true;
  }
  return false;
}

/**
 * Paragraph texts that Word displays in capitals.
 *
 * A paragraph counts when EVERY run carrying text is caps-formatted, or when
 * the paragraph's own run properties set it. Partially-capitalized text is not
 * "in capitals" for conspicuousness purposes — a single capitalized word in a
 * mixed-case clause is not what § 1-201(b)(10) describes.
 */
export function capsParagraphs(bytes: ArrayBuffer): Set<string> {
  let xml: string;
  try {
    xml = inflateOoxmlParts(bytes, new Set(["word/document.xml"]))["word/document.xml"] ?? "";
  } catch {
    return new Set();
  }
  const out = new Set<string>();
  for (const p of xml.matchAll(/<w:p\b[^>]*>([\s\S]*?)<\/w:p>/g)) {
    const body = p[1]!;
    const pPr = /<w:pPr\b[^>]*>([\s\S]*?)<\/w:pPr>/.exec(body)?.[1];
    const paragraphCaps = setsCaps(/<w:rPr\b[^>]*>([\s\S]*?)<\/w:rPr>/.exec(pPr ?? "")?.[1]);
    let text = "";
    let runs = 0;
    let capsRuns = 0;
    for (const r of body.matchAll(/<w:r\b[^>]*>([\s\S]*?)<\/w:r>/g)) {
      const runBody = r[1]!;
      const runText = decode(
        [...runBody.matchAll(/<w:t\b[^>]*>([\s\S]*?)<\/w:t>/g)].map((t) => t[1]!).join(""),
      );
      if (!runText.trim()) continue;
      text += runText;
      runs++;
      const rPr = /<w:rPr\b[^>]*>([\s\S]*?)<\/w:rPr>/.exec(runBody)?.[1];
      if (setsCaps(rPr) || paragraphCaps) capsRuns++;
    }
    const key = normalize(text);
    if (key && runs > 0 && capsRuns === runs) out.add(key);
  }
  return out;
}
