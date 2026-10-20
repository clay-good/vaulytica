/**
 * A filled box painted over a PDF's text (add-redaction-integrity-scan,
 * tasks 1–2): the redaction that hides words on screen and leaves them in the
 * file, selectable, searchable and copyable.
 *
 * The page's operator list is walked once, in paint order, tracking the
 * transformation matrix, the text state and the fill. Every glyph shown is
 * placed (its centre, in page space). Every opaque, single-colour,
 * axis-aligned rectangle that is FILLED becomes a candidate, and the glyphs
 * painted BEFORE it whose centres it covers are what it hides. Paint order is
 * the whole test: a box painted before its text is a background (a table
 * shading, a highlight) and covers nothing, and text painted after a box (a
 * white heading on a dark bar) shows over it.
 *
 * What is reported is the covered text's SHAPE, never the text (the masking
 * invariant), and the page. Nothing is said about whether the box was meant
 * as a redaction; that it hides text still in the file is the fact.
 *
 * A `Square` annotation is read the same way, from the appearance pdf.js
 * draws for it after the page content: a filled square over text hides it.
 *
 * Not read: a box inside an image (a scanned page), any other annotation (the
 * annotation reader handles `/Redact`; a highlight blends with what is under
 * it), a pattern or shading fill, a translucent or blended fill, a curved
 * path, text in a Type 3 font (its glyph widths are not in thousandths of an
 * em).
 */
import type { RedactionFact } from "./types.js";
import { maskShape } from "./container.js";

/** pdf.js `OPS` ids used here, by name; passed in so this module stays pure. */
export type PaintOps = Record<
  | "fill"
  | "eoFill"
  | "fillStroke"
  | "eoFillStroke"
  | "closeFillStroke"
  | "closeEOFillStroke"
  | "constructPath"
  | "transform"
  | "save"
  | "restore"
  | "setGState"
  | "setFillRGBColor"
  | "setFillGray"
  | "setFillCMYKColor"
  | "setFillColorN"
  | "setFillColor"
  | "beginText"
  | "setTextMatrix"
  | "moveText"
  | "setLeadingMoveText"
  | "nextLine"
  | "setLeading"
  | "setFont"
  | "setCharSpacing"
  | "setWordSpacing"
  | "setHScale"
  | "setTextRise"
  | "showText"
  | "showSpacedText"
  | "nextLineShowText"
  | "nextLineSetSpacingShowText"
  | "paintFormXObjectBegin"
  | "paintFormXObjectEnd"
  | "beginAnnotation"
  | "endAnnotation",
  number
>;

/** pdf.js's path-data opcodes inside `constructPath` (its internal `DrawOPS`). */
const MOVE_TO = 0;
const LINE_TO = 1;
const CLOSE_PATH = 4;

/** An operator list past this length on one page is not walked. */
export const MAX_OPS_PER_PAGE = 250_000;
/** Pages past this are not walked. */
export const MAX_PAINT_PAGES = 500;
const MAX_FACTS = 200;

type M = [number, number, number, number, number, number];
const IDENTITY: M = [1, 0, 0, 1, 0, 0];

/** `a` then `b`, in PDF's row-vector convention. */
function mul(a: readonly number[], b: readonly number[]): M {
  return [
    a[0]! * b[0]! + a[1]! * b[2]!,
    a[0]! * b[1]! + a[1]! * b[3]!,
    a[2]! * b[0]! + a[3]! * b[2]!,
    a[2]! * b[1]! + a[3]! * b[3]!,
    a[4]! * b[0]! + a[5]! * b[2]! + b[4]!,
    a[4]! * b[1]! + a[5]! * b[3]! + b[5]!,
  ];
}

function apply(m: readonly number[], x: number, y: number): [number, number] {
  return [m[0]! * x + m[2]! * y + m[4]!, m[1]! * x + m[3]! * y + m[5]!];
}

type Glyph = { x: number; y: number; ch: string; op: number; run: number };
type Box = { x0: number; y0: number; x1: number; y1: number };

/** The axis-aligned rectangles a path is made of, or none when any part is not one. */
function rectsOf(data: ArrayLike<number>, ctm: M): Box[] {
  const boxes: Box[] = [];
  let pts: Array<[number, number]> = [];
  const close = (): boolean => {
    if (pts.length === 0) return true;
    // A closing point that repeats the first is the same rectangle.
    const p = pts.length === 5 && pts[4]![0] === pts[0]![0] && pts[4]![1] === pts[0]![1];
    const corners = p ? pts.slice(0, 4) : pts;
    if (corners.length !== 4) return false;
    for (let i = 0; i < 4; i++) {
      const [ax, ay] = corners[i]!;
      const [bx, by] = corners[(i + 1) % 4]!;
      if (ax !== bx && ay !== by) return false;
    }
    const page = corners.map(([x, y]) => apply(ctm, x, y));
    const xs = page.map((q) => q[0]);
    const ys = page.map((q) => q[1]);
    boxes.push({
      x0: Math.min(...xs),
      y0: Math.min(...ys),
      x1: Math.max(...xs),
      y1: Math.max(...ys),
    });
    pts = [];
    return true;
  };
  let i = 0;
  while (i < data.length) {
    const op = data[i]!;
    if (op === MOVE_TO) {
      if (!close()) return [];
      pts = [[data[i + 1]!, data[i + 2]!]];
      i += 3;
    } else if (op === LINE_TO) {
      pts.push([data[i + 1]!, data[i + 2]!]);
      i += 3;
    } else if (op === CLOSE_PATH) {
      if (!close()) return [];
      i += 1;
    } else return [];
  }
  return close() ? boxes : [];
}

/** A pdf.js glyph in a `showText` argument. */
type PdfGlyph = { unicode?: string; width?: number; isSpace?: boolean } | number | null;

/**
 * Every filled box on one page that covers text painted before it. Pure:
 * `fnArray`/`argsArray` are a pdf.js operator list, `ops` its `OPS` table.
 */
export function boxesOverText(
  fnArray: ArrayLike<number>,
  argsArray: ArrayLike<unknown>,
  ops: PaintOps,
  page: number,
  /** Annotation id → subtype, from `page.getAnnotations()`; only `Square` is read. */
  annotations: ReadonlyMap<string, string> = new Map(),
): RedactionFact[] {
  const fills = new Set([
    ops.fill,
    ops.eoFill,
    ops.fillStroke,
    ops.eoFillStroke,
    ops.closeFillStroke,
    ops.closeEOFillStroke,
  ]);
  type State = { ctm: M; solid: boolean; alpha: number; blended: boolean };
  let gs: State = { ctm: [...IDENTITY], solid: true, alpha: 1, blended: false };
  /** Inside an annotation this does not read: its operations are skipped. */
  let skipping = 0;
  const annotationCtms: M[] = [];
  let inSquare = false;
  const stack: State[] = [];
  const forms: M[] = [];
  let tm: M = [...IDENTITY];
  let tlm: M = [...IDENTITY];
  let size = 0;
  let leading = 0;
  let charSpacing = 0;
  let wordSpacing = 0;
  let hScale = 1;
  let rise = 0;
  let run = 0;
  const glyphs: Glyph[] = [];
  const facts: RedactionFact[] = [];

  const show = (items: readonly PdfGlyph[], op: number): void => {
    run += 1;
    for (const g of items) {
      if (typeof g === "number") {
        tm = mul([1, 0, 0, 1, (-g / 1000) * size * hScale, 0], tm);
        continue;
      }
      if (!g) continue;
      const w = ((g.width ?? 0) / 1000) * size;
      const advance = (w + charSpacing + (g.isSpace ? wordSpacing : 0)) * hScale;
      const [x, y] = apply(mul(tm, gs.ctm), (w * hScale) / 2, rise + size * 0.3);
      if (g.unicode) glyphs.push({ x, y, ch: g.unicode, op, run });
      tm = mul([1, 0, 0, 1, advance, 0], tm);
    }
  };
  const nextLine = (): void => {
    tlm = mul([1, 0, 0, 1, 0, -leading], tlm);
    tm = [...tlm];
  };

  for (let i = 0; i < fnArray.length; i++) {
    const fn = fnArray[i]!;
    const args = (argsArray[i] ?? []) as unknown[];
    if (fn === ops.beginAnnotation) {
      if (skipping > 0 || annotations.get(String(args[0])) !== "Square") {
        skipping += 1;
        continue;
      }
      // The appearance is drawn through the annotation's own placement, then
      // its form matrix (pdf.js's canvas does the same).
      annotationCtms.push([...gs.ctm]);
      const placed = Array.isArray(args[2]) ? mul(args[2] as number[], gs.ctm) : gs.ctm;
      gs.ctm = Array.isArray(args[3]) ? mul(args[3] as number[], placed) : placed;
      inSquare = true;
      continue;
    }
    if (fn === ops.endAnnotation) {
      if (skipping > 0) skipping -= 1;
      else {
        gs.ctm = annotationCtms.pop() ?? gs.ctm;
        inSquare = false;
      }
      continue;
    }
    if (skipping > 0) continue;
    switch (fn) {
      case ops.save:
        stack.push({ ...gs, ctm: [...gs.ctm] });
        break;
      case ops.restore:
        gs = stack.pop() ?? gs;
        break;
      case ops.transform:
        gs.ctm = mul(args as number[], gs.ctm);
        break;
      case ops.paintFormXObjectBegin:
        forms.push([...gs.ctm]);
        if (Array.isArray(args[0])) gs.ctm = mul(args[0] as number[], gs.ctm);
        break;
      case ops.paintFormXObjectEnd:
        gs.ctm = forms.pop() ?? gs.ctm;
        break;
      case ops.setGState:
        for (const pair of (args[0] ?? []) as Array<[string, unknown]>) {
          if (pair[0] === "ca" && typeof pair[1] === "number") gs.alpha = pair[1];
          // A blend mode other than normal (a highlighter's Multiply) shows what is under it.
          if (pair[0] === "BM") {
            gs.blended = !/^(?:normal|source-over|compatible)$/i.test(String(pair[1]));
          }
        }
        break;
      case ops.setFillRGBColor:
      case ops.setFillGray:
      case ops.setFillCMYKColor:
        gs.solid = true;
        break;
      case ops.setFillColorN:
      case ops.setFillColor:
        // A pattern or an unconverted colour space: not a solid fill this reads.
        gs.solid = false;
        break;
      case ops.beginText:
        tm = [...IDENTITY];
        tlm = [...IDENTITY];
        break;
      case ops.setTextMatrix:
        tlm = [...(args as number[])] as M;
        tm = [...tlm];
        break;
      case ops.moveText:
        tlm = mul([1, 0, 0, 1, args[0] as number, args[1] as number], tlm);
        tm = [...tlm];
        break;
      case ops.setLeadingMoveText:
        leading = -(args[1] as number);
        tlm = mul([1, 0, 0, 1, args[0] as number, args[1] as number], tlm);
        tm = [...tlm];
        break;
      case ops.nextLine:
        nextLine();
        break;
      case ops.setLeading:
        leading = args[0] as number;
        break;
      case ops.setFont:
        size = (args[1] as number) ?? size;
        break;
      case ops.setCharSpacing:
        charSpacing = args[0] as number;
        break;
      case ops.setWordSpacing:
        wordSpacing = args[0] as number;
        break;
      case ops.setHScale:
        hScale = (args[0] as number) / 100;
        break;
      case ops.setTextRise:
        rise = args[0] as number;
        break;
      case ops.showText:
      case ops.showSpacedText:
        show((args[0] ?? []) as PdfGlyph[], i);
        break;
      case ops.nextLineShowText:
        nextLine();
        show((args[0] ?? []) as PdfGlyph[], i);
        break;
      case ops.nextLineSetSpacingShowText:
        wordSpacing = args[0] as number;
        charSpacing = args[1] as number;
        nextLine();
        show((args[2] ?? []) as PdfGlyph[], i);
        break;
      case ops.constructPath: {
        if (!fills.has(args[0] as number) || !gs.solid || gs.alpha < 1 || gs.blended) break;
        const data = (args[1] as ArrayLike<number>[] | undefined)?.[0];
        if (!data) break;
        for (const box of rectsOf(data, gs.ctm)) {
          const covered = glyphs.filter(
            (g) => g.x > box.x0 && g.x < box.x1 && g.y > box.y0 && g.y < box.y1,
          );
          if (!covered.some((g) => g.ch.trim())) continue;
          let text = "";
          let prevRun = covered[0]!.run;
          for (const g of covered) {
            if (g.run !== prevRun && !text.endsWith(" ")) text += " ";
            text += g.ch;
            prevRun = g.run;
          }
          facts.push({
            kind: "pdf-filled-box",
            reason: inSquare
              ? "a filled square annotation over text that is still in the file"
              : "a filled box painted over text that is still in the file",
            location: `page ${page}`,
            masked_shape: maskShape(text.trim()),
          });
          if (facts.length >= MAX_FACTS) return facts;
        }
        break;
      }
    }
  }
  return facts;
}

/** A pdf.js document, as far as this reader needs it. */
type PaintDoc = {
  numPages: number;
  getPage: (n: number) => Promise<{
    getAnnotations: () => Promise<Array<{ id?: string; subtype?: string }>>;
    getOperatorList: (o?: { annotationMode?: number }) => Promise<{
      fnArray: ArrayLike<number>;
      argsArray: ArrayLike<unknown>;
    }>;
  }>;
  destroy?: () => Promise<void>;
};

/**
 * Every page's filled boxes over text. Never throws: a document pdf.js cannot
 * open, or a page past the bounds, is reported in `uninspectable` with the
 * reason. Reads a COPY of the bytes, because pdf.js detaches the buffer it is
 * given and the caller still needs them.
 */
export async function readBoxesOverText(bytes: ArrayBuffer): Promise<{
  facts: RedactionFact[];
  pages_scanned: number;
  uninspectable: string[];
  /** pdf.js could not open the file at all. */
  unopened?: boolean;
}> {
  const uninspectable: string[] = [];
  let doc: PaintDoc;
  let OPS: PaintOps;
  let annotationsOn: number | undefined;
  try {
    const { loadPdfJs } = await import("../ingest/pdf.js");
    const pdfjs = (await loadPdfJs()) as unknown as {
      getDocument: (p: { data: ArrayBuffer; useSystemFonts?: boolean }) => {
        promise: Promise<PaintDoc>;
      };
      OPS: PaintOps;
      AnnotationMode?: { ENABLE: number };
    };
    OPS = pdfjs.OPS;
    annotationsOn = pdfjs.AnnotationMode?.ENABLE;
    doc = await pdfjs.getDocument({ data: bytes.slice(0), useSystemFonts: true }).promise;
  } catch {
    return { facts: [], pages_scanned: 0, uninspectable: [], unopened: true };
  }
  const facts: RedactionFact[] = [];
  const last = Math.min(doc.numPages, MAX_PAINT_PAGES);
  if (doc.numPages > last)
    uninspectable.push(`pages ${last + 1}–${doc.numPages} (past the page bound)`);
  let scanned = 0;
  for (let n = 1; n <= last; n++) {
    try {
      const page = await doc.getPage(n);
      // Annotations drawn, so a Square's fill is in the list after the content;
      // the walk reads Squares only, by id.
      const list = await page.getOperatorList(
        annotationsOn !== undefined ? { annotationMode: annotationsOn } : undefined,
      );
      const subtypes = new Map(
        (await page.getAnnotations()).map((a) => [String(a.id), String(a.subtype)] as const),
      );
      if (list.fnArray.length > MAX_OPS_PER_PAGE) {
        uninspectable.push(
          `page ${n} (over ${MAX_OPS_PER_PAGE.toLocaleString("en-US")} drawing operations)`,
        );
        continue;
      }
      facts.push(...boxesOverText(list.fnArray, list.argsArray, OPS, n, subtypes));
      scanned += 1;
    } catch {
      uninspectable.push(`page ${n} (could not be read)`);
    }
  }
  await doc.destroy?.();
  return { facts: facts.slice(0, MAX_FACTS), pages_scanned: scanned, uninspectable };
}
