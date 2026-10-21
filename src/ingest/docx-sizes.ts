/**
 * The point size Word sets a run in (add-mandated-text-conformance, task 5).
 *
 * mammoth reads a run's own `w:sz` and nothing else, but most text has none:
 * its size comes from its character style, its paragraph's style (each
 * `basedOn` another), or the document defaults. This resolves that chain from
 * `word/styles.xml` the way Word does, and answers `undefined` whenever a
 * link is missing, so a size is reported only when the file states it.
 */
import { inflateOoxmlParts } from "./ooxml.js";

type Style = { basedOn?: string; size?: number };

export type SizeResolver = {
  /** The run's size in points, or undefined when the file does not determine it. */
  size(
    run: { fontSize?: number | null; styleId?: string | null },
    paragraphStyleId?: string | null,
  ): number | undefined;
};

/** Half-points (`w:sz w:val="20"`) to points, from an rPr's XML. */
function sizeIn(rPr: string | undefined): number | undefined {
  const v = rPr ? /<w:sz\b[^>]{0,100}?\bw:val="(\d{1,4})"/.exec(rPr)?.[1] : undefined;
  return v ? Number(v) / 2 : undefined;
}

/** Read `styles.xml`. Never throws; an unreadable part resolves nothing. */
export function sizeResolver(bytes: ArrayBuffer): SizeResolver {
  let xml = "";
  try {
    xml = inflateOoxmlParts(bytes, new Set(["word/styles.xml"]))["word/styles.xml"] ?? "";
  } catch {
    xml = "";
  }
  const paragraph = new Map<string, Style>();
  const character = new Map<string, Style>();
  let defaultParagraph: string | undefined;
  for (const m of xml.matchAll(/<w:style\b([^>]{0,400})>([\s\S]*?)<\/w:style>/g)) {
    const attrs = m[1]!;
    const body = m[2]!;
    const id = /\bw:styleId="([^"]{1,100})"/.exec(attrs)?.[1];
    if (!id) continue;
    const style: Style = {
      basedOn: /<w:basedOn\b[^>]{0,100}?\bw:val="([^"]{1,100})"/.exec(body)?.[1],
      size: sizeIn(/<w:rPr\b[^>]*>([\s\S]*?)<\/w:rPr>/.exec(body)?.[1]),
    };
    if (/\bw:type="character"/.test(attrs)) character.set(id, style);
    else if (/\bw:type="paragraph"/.test(attrs)) {
      paragraph.set(id, style);
      if (/\bw:default="(?:1|true)"/.test(attrs)) defaultParagraph = id;
    }
  }
  const defaults = /<w:rPrDefault\b[^>]*>([\s\S]*?)<\/w:rPrDefault>/.exec(xml)?.[1];
  const documentDefault = sizeIn(defaults);

  /** A style's size through its `basedOn` chain; bounded, so a cycle ends. */
  const chain = (styles: Map<string, Style>, id: string | undefined): number | undefined => {
    for (let i = 0; id && i < 20; i++) {
      const s = styles.get(id);
      if (!s) return undefined;
      if (s.size !== undefined) return s.size;
      id = s.basedOn;
    }
    return undefined;
  };

  return {
    size(run, paragraphStyleId) {
      if (run.fontSize) return run.fontSize;
      const fromCharacter = run.styleId ? chain(character, run.styleId) : undefined;
      if (fromCharacter !== undefined) return fromCharacter;
      const pid = paragraphStyleId ?? defaultParagraph;
      const fromParagraph = pid ? chain(paragraph, pid) : undefined;
      if (fromParagraph !== undefined) return fromParagraph;
      return documentDefault;
    },
  };
}
