/**
 * Word's automatic numbering, read the way Word renders it.
 *
 * A clause numbered by a list style carries no number in its text. mammoth
 * gives a numbered body paragraph as an `<ol>` item and a numbered HEADING as a
 * bare `<h1>` — the number is simply gone, and with it every "Section 3.2" the
 * document cross-refers to. Most professionally drafted Word contracts number
 * their articles and sections this way.
 *
 * This module reads `numbering.xml`, `styles.xml` and `document.xml` and
 * computes, for each numbered paragraph in document order, the label Word
 * shows: the level's `lvlText` ("%1.", "%1.%2", "Article %1", "(%3)") with each
 * placeholder rendered in its level's format (decimal, roman, letter). The
 * ingest prefixes the label to the paragraph and drops its list flag, so the
 * paragraph arrives exactly as if the number had been typed.
 *
 * The XML is read with patterns, not a parser: these are machine-written
 * parts with a fixed shape, and the ingest must run in a browser and in Node
 * alike. Anything not understood yields no label, and the paragraph falls back
 * to mammoth's list rendering.
 */
import { inflateOoxmlParts } from "./ooxml.js";

const PARTS = new Set(["word/document.xml", "word/numbering.xml", "word/styles.xml"]);

/** `legal`: Word's "legal style numbering" (`w:isLgl`) — every number in the label decimal. */
type Level = { start: number; fmt: string; text: string; legal: boolean };

const attr = (xml: string, tag: string): string | undefined =>
  new RegExp(`<w:${tag}\\b[^>]*\\bw:val="([^"]*)"`).exec(xml)?.[1];

function roman(n: number): string {
  const table: [number, string][] = [
    [1000, "M"],
    [900, "CM"],
    [500, "D"],
    [400, "CD"],
    [100, "C"],
    [90, "XC"],
    [50, "L"],
    [40, "XL"],
    [10, "X"],
    [9, "IX"],
    [5, "V"],
    [4, "IV"],
    [1, "I"],
  ];
  let out = "";
  for (const [v, s] of table)
    while (n >= v) {
      out += s;
      n -= v;
    }
  return out;
}

function letter(n: number): string {
  // a … z, aa … zz, as Word repeats the letter.
  const ch = String.fromCharCode(97 + ((n - 1) % 26));
  return ch.repeat(Math.floor((n - 1) / 26) + 1);
}

function format(n: number, fmt: string): string | undefined {
  switch (fmt) {
    case "decimal":
    case "decimalZero":
      return fmt === "decimalZero" && n < 10 ? `0${n}` : String(n);
    case "upperRoman":
      return roman(n);
    case "lowerRoman":
      return roman(n).toLowerCase();
    case "upperLetter":
      return letter(n).toUpperCase();
    case "lowerLetter":
      return letter(n);
    case "bullet":
      return "";
    default:
      return undefined;
  }
}

function decode(s: string): string {
  return s
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}

/** A paragraph's visible text, as a key the mammoth paragraph can be matched on. */
export function paragraphKey(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}

/**
 * Labels for the numbered paragraphs of a DOCX, keyed by paragraph text, in
 * document order (a text that recurs gets its labels in turn). Empty when the
 * document has no numbering or a part cannot be read.
 */
export function numberingLabels(bytes: ArrayBuffer): Map<string, string[]> {
  const labels = new Map<string, string[]>();
  let parts: Record<string, string>;
  try {
    parts = inflateOoxmlParts(bytes, PARTS);
  } catch {
    return labels;
  }
  const numberingXml = parts["word/numbering.xml"] ?? "";
  const documentXml = parts["word/document.xml"] ?? "";
  if (!numberingXml || !documentXml) return labels;

  // abstractNumId → level → format
  const abstract = new Map<string, Map<number, Level>>();
  for (const m of numberingXml.matchAll(
    /<w:abstractNum\b[^>]*w:abstractNumId="([^"]+)"[^>]*>([\s\S]*?)<\/w:abstractNum>/g,
  )) {
    const levels = new Map<number, Level>();
    for (const l of m[2]!.matchAll(/<w:lvl\b[^>]*w:ilvl="(\d+)"[^>]*>([\s\S]*?)<\/w:lvl>/g)) {
      levels.set(Number(l[1]), {
        start: Number(attr(l[2]!, "start") ?? "1"),
        fmt: attr(l[2]!, "numFmt") ?? "decimal",
        text: decode(attr(l[2]!, "lvlText") ?? ""),
        legal: /<w:isLgl\b(?![^>]*w:val="(?:0|false)")/.test(l[2]!),
      });
    }
    abstract.set(m[1]!, levels);
  }
  // numId → abstractNumId
  const numToAbstract = new Map<string, string>();
  for (const m of numberingXml.matchAll(
    /<w:num\b[^>]*w:numId="([^"]+)"[^>]*>([\s\S]*?)<\/w:num>/g,
  )) {
    const a = attr(m[2]!, "abstractNumId");
    if (a) numToAbstract.set(m[1]!, a);
  }
  // styleId → numPr inherited from the style (a Heading style linked to a list)
  const styleNum = new Map<string, { numId: string; ilvl: number }>();
  for (const m of (parts["word/styles.xml"] ?? "").matchAll(
    /<w:style\b[^>]*w:styleId="([^"]+)"[^>]*>([\s\S]*?)<\/w:style>/g,
  )) {
    const numPr = /<w:numPr>([\s\S]*?)<\/w:numPr>/.exec(m[2]!)?.[1];
    const numId = numPr ? attr(numPr, "numId") : undefined;
    if (numId) styleNum.set(m[1]!, { numId, ilvl: Number(attr(numPr!, "ilvl") ?? "0") });
  }

  // Counters per abstract list, per level; Word restarts deeper levels when a
  // shallower one advances.
  const counters = new Map<string, number[]>();
  for (const p of documentXml.matchAll(/<w:p\b[^>]*>([\s\S]*?)<\/w:p>/g)) {
    const body = p[1]!;
    const pPr = /<w:pPr>([\s\S]*?)<\/w:pPr>/.exec(body)?.[1] ?? "";
    const numPr = /<w:numPr>([\s\S]*?)<\/w:numPr>/.exec(pPr)?.[1];
    const style = attr(pPr, "pStyle");
    const inherited = style ? styleNum.get(style) : undefined;
    const numId = (numPr ? attr(numPr, "numId") : undefined) ?? inherited?.numId;
    if (!numId || numId === "0") continue;
    const ilvl = Number((numPr ? attr(numPr, "ilvl") : undefined) ?? inherited?.ilvl ?? 0);
    const abstractId = numToAbstract.get(numId);
    const levels = abstractId ? abstract.get(abstractId) : undefined;
    const level = levels?.get(ilvl);
    if (!abstractId || !levels || !level) continue;
    const c = counters.get(abstractId) ?? [];
    for (let k = 0; k < ilvl; k++) c[k] ??= levels.get(k)?.start ?? 1;
    c[ilvl] = c[ilvl] === undefined ? level.start : c[ilvl]! + 1;
    c.length = ilvl + 1;
    counters.set(abstractId, c);
    let ok = true;
    const label = level.text.replace(/%(\d)/g, (_m, d: string) => {
      const k = Number(d) - 1;
      // "Article I" over "Section 1.1": a legal-style level renders the
      // article's number in decimal inside its own label.
      const fmt = level.legal ? "decimal" : (levels.get(k)?.fmt ?? "decimal");
      const f = format(c[k] ?? levels.get(k)?.start ?? 1, fmt);
      if (f === undefined) ok = false;
      return f ?? "";
    });
    if (!ok) continue;
    const text = paragraphKey(
      decode([...body.matchAll(/<w:t\b[^>]*>([^<]*)<\/w:t>/g)].map((t) => t[1]).join("")),
    );
    if (!text) continue;
    const queue = labels.get(text) ?? [];
    queue.push(level.fmt === "bullet" ? "•" : label.trim());
    labels.set(text, queue);
  }
  return labels;
}
