/**
 * The container-read surface (spec-v9 §5/§6, Step 148). A pure, **total**
 * function over a document's original bytes that recovers the revision,
 * comment, hidden-content, and metadata facts the normalizing ingest discards.
 *
 * Posture (§3 corollary 1): parsing a zip member, an OOXML element, or a PDF
 * Info dictionary is a pure function of the input bytes — no clock, no network,
 * no randomness. The v8 Thrust A guards (byte caps, decompression-ratio
 * ceiling) are applied *before* any member is read. The function never throws
 * and never hangs: every path resolves to typed {@link ContainerFacts} or a
 * typed "could not inspect" note. All regexes are linear and match-capped to
 * preserve the repo's ReDoS-free guarantee (commit 3b545b6).
 *
 * It runs *alongside* normalization and never mutates the `DocumentTree`. A
 * text-only or metadata-free document yields empty `ContainerFacts` and zero
 * findings, so no existing golden moves.
 */

import { unzipSync, strFromU8 } from "fflate";
import type {
  ContainerFacts,
  ContainerSource,
  MetadataFact,
  RevisionFact,
  CommentFact,
  HiddenFact,
} from "./types.js";
import { scanSensitive } from "./sensitive.js";

/** Container byte ceiling — mirrors the ingest single-document cap (v8 §7). */
const MAX_CONTAINER_BYTES = 50 * 1024 * 1024;
/** Per-OOXML-part inflate ceiling — bounds the regex work on any one member. */
const MAX_PART_BYTES = 16 * 1024 * 1024;
/** Decompression-ratio ceiling — the zip-bomb guard (v8 §8, matches multi.ts). */
const MAX_COMPRESSION_RATIO = 200;
/** Per-fact-array cap — a pathological document cannot produce unbounded output. */
const MAX_FACTS = 2000;
/** Excerpt truncation length — location only, never the full content. */
const EXCERPT_LEN = 80;

/** The OOXML parts we inspect. Everything else in the archive is never inflated. */
const DOCX_PARTS = new Set([
  "word/document.xml",
  "word/comments.xml",
  "docProps/core.xml",
  "docProps/app.xml",
]);

/**
 * Read the original container bytes into typed facts. `source` selects the
 * format reader; `text` is the already-flattened document text the engine read
 * (the sensitive-data scan runs over it, so the scan sees the same content the
 * recipient's tooling renders). Never throws.
 */
export function readContainer(
  bytes: ArrayBuffer,
  source: ContainerSource,
  text: string,
): ContainerFacts {
  const empty = (note: string, inspectable = false): ContainerFacts => ({
    source,
    inspectable,
    note,
    revisions: [],
    comments: [],
    hidden: [],
    metadata: [],
    sensitive: scanSensitive(text),
  });

  if (source === "paste") return empty("Pasted text has no container to inspect.");
  if (source === "image") return empty("Image-only input carries no document container to inspect.");
  if (bytes.byteLength === 0) return empty("Empty input — no container to inspect.");
  if (bytes.byteLength > MAX_CONTAINER_BYTES) {
    return empty("Input exceeds the container-scan size limit; skipped.");
  }

  try {
    if (source === "docx") return readDocx(bytes, text);
    if (source === "pdf") return readPdf(bytes, text);
  } catch {
    // Totality contract: a malformed container yields an honest note, never a throw.
    return empty("The container could not be parsed; it may be malformed or encrypted.");
  }
  return empty("Unrecognized container format.");
}

/* ------------------------------- DOCX --------------------------------- */

function readDocx(bytes: ArrayBuffer, text: string): ContainerFacts {
  const parts = inflateDocxParts(bytes);
  const document = parts["word/document.xml"] ?? "";
  const comments = parts["word/comments.xml"] ?? "";
  const core = parts["docProps/core.xml"] ?? "";
  const app = parts["docProps/app.xml"] ?? "";

  return {
    source: "docx",
    inspectable: true,
    revisions: parseRevisions(document),
    comments: parseComments(comments),
    hidden: parseHidden(document),
    metadata: parseDocxMetadata(core, app),
    sensitive: scanSensitive(text),
  };
}

/**
 * Inflate only the handoff-relevant OOXML parts, applying the v8 zip-bomb
 * guards in fflate's pre-inflate filter so a malicious member is rejected
 * before it is expanded.
 */
function inflateDocxParts(bytes: ArrayBuffer): Record<string, string> {
  const out: Record<string, string> = {};
  const unzipped = unzipSync(new Uint8Array(bytes), {
    filter: (file) => {
      if (!DOCX_PARTS.has(file.name)) return false; // never inflated
      const ratio = file.size > 0 ? file.originalSize / file.size : file.originalSize;
      if (ratio > MAX_COMPRESSION_RATIO) return false;
      if (file.originalSize > MAX_PART_BYTES) return false;
      return true;
    },
  });
  for (const [name, data] of Object.entries(unzipped)) {
    if (!DOCX_PARTS.has(name)) continue;
    out[name] = strFromU8(data);
  }
  return out;
}

const TAG_AUTHOR = /\bw:author="([^"]{0,200})"/;

/** Parse `w:ins` / `w:del` / `w:moveFrom` / `w:moveTo` revision elements. */
function parseRevisions(xml: string): RevisionFact[] {
  const facts: RevisionFact[] = [];
  const open = /<w:(ins|del|moveFrom|moveTo)\b([^>]{0,400})>/g;
  let m: RegExpExecArray | null;
  while ((m = open.exec(xml)) !== null && facts.length < MAX_FACTS) {
    const tag = m[1]!;
    const attrs = m[2] ?? "";
    const kind: RevisionFact["kind"] =
      tag === "ins" ? "insertion" : tag === "del" ? "deletion" : "move";
    const author = TAG_AUTHOR.exec(attrs)?.[1];
    // Bounded forward scan for the revision's text, for location only.
    const tail = xml.slice(m.index, m.index + 2000);
    const txt =
      /<w:(?:t|delText)\b[^>]{0,200}>([^<]{0,200})<\/w:(?:t|delText)>/.exec(tail)?.[1];
    facts.push(compact({ kind, author: clean(author), excerpt: excerpt(txt) }));
  }
  return facts;
}

/** Parse the comment store: each `w:comment` element with its author. */
function parseComments(xml: string): CommentFact[] {
  if (!xml) return [];
  const facts: CommentFact[] = [];
  const open = /<w:comment\b([^>]{0,400})>/g;
  let m: RegExpExecArray | null;
  while ((m = open.exec(xml)) !== null && facts.length < MAX_FACTS) {
    const attrs = m[1] ?? "";
    const author = TAG_AUTHOR.exec(attrs)?.[1];
    const tail = xml.slice(m.index, m.index + 4000);
    const txt = /<w:t\b[^>]{0,200}>([^<]{0,400})<\/w:t>/.exec(tail)?.[1];
    facts.push(compact({ author: clean(author), excerpt: excerpt(txt) }));
  }
  return facts;
}

/**
 * Surface hidden / non-printing content: `w:vanish` runs and the text inside
 * deleted-but-retained `w:del` ranges (`w:delText`). Reports the recovered
 * span (§9/§10), never a judgment of intent.
 */
function parseHidden(xml: string): HiddenFact[] {
  const facts: HiddenFact[] = [];
  // w:vanish lives in a run's rPr; capture the following run text in a bounded window.
  const vanish = /<w:vanish\b[^>]{0,80}\/?>/g;
  let m: RegExpExecArray | null;
  while ((m = vanish.exec(xml)) !== null && facts.length < MAX_FACTS) {
    const tail = xml.slice(m.index, m.index + 2000);
    const txt = /<w:t\b[^>]{0,200}>([^<]{0,200})<\/w:t>/.exec(tail)?.[1];
    facts.push(compact({ kind: "vanish" as const, excerpt: excerpt(txt) }));
  }
  // Deleted-but-retained text.
  const delText = /<w:delText\b[^>]{0,200}>([^<]{0,200})<\/w:delText>/g;
  while ((m = delText.exec(xml)) !== null && facts.length < MAX_FACTS) {
    facts.push(compact({ kind: "deleted" as const, excerpt: excerpt(m[1]) }));
  }
  return facts;
}

/** Parse `docProps/core.xml` and `docProps/app.xml` into verbatim metadata facts. */
function parseDocxMetadata(core: string, app: string): MetadataFact[] {
  const facts: MetadataFact[] = [];
  const push = (field: string, value: string | undefined): void => {
    const v = clean(value);
    if (v && facts.length < MAX_FACTS) facts.push({ field, value: v });
  };
  const tag = (xml: string, name: string): string | undefined =>
    new RegExp(`<${name}\\b[^>]{0,200}>([^<]{0,400})</${name}>`).exec(xml)?.[1];

  push("creator", tag(core, "dc:creator"));
  push("lastModifiedBy", tag(core, "cp:lastModifiedBy"));
  push("title", tag(core, "dc:title"));
  push("subject", tag(core, "dc:subject"));
  push("description", tag(core, "dc:description"));
  push("keywords", tag(core, "cp:keywords"));
  push("category", tag(core, "cp:category"));
  push("revision", tag(core, "cp:revision"));
  push("created", tag(core, "dcterms:created"));
  push("modified", tag(core, "dcterms:modified"));
  push("lastPrinted", tag(core, "cp:lastPrinted"));

  push("company", tag(app, "Company"));
  push("manager", tag(app, "Manager"));
  push("template", tag(app, "Template"));
  push("application", tag(app, "Application"));
  push("totalEditTime", tag(app, "TotalTime"));
  return facts;
}

/* -------------------------------- PDF --------------------------------- */

/**
 * Best-effort PDF read: authoring-metadata (the Info dictionary) **and**
 * reviewer markup/comment annotations (spec-v9 §7 — sticky notes and
 * text-markup), both parsed from the uncompressed byte regions of the file.
 *
 * Honest partial coverage (§3 corollary 3): a PDF whose Info dictionary or
 * whose annotations live in an encrypted or object-stream-compressed region is
 * not fully readable from the raw bytes, so the note states the scan's reach
 * rather than implying a clean bill. We deliberately read the raw bytes (not
 * pdf.js) to keep this pure, bounded, and ReDoS-free — the same posture the
 * DOCX path holds.
 */
function readPdf(bytes: ArrayBuffer, text: string): ContainerFacts {
  // Decode as latin1 so byte offsets map 1:1 to characters (PDF is byte-oriented).
  const ascii = strFromU8(new Uint8Array(bytes.slice(0, Math.min(bytes.byteLength, MAX_PART_BYTES))), true);
  const metadata = parsePdfInfo(ascii);
  const comments = parsePdfAnnotations(ascii);
  return {
    source: "pdf",
    inspectable: true,
    note:
      "PDF scan reads authoring metadata and reviewer annotations (sticky notes, text markup) from the uncompressed byte regions; annotations or metadata inside a compressed object stream or an encrypted region are not recovered.",
    revisions: [],
    comments,
    hidden: [],
    metadata,
    sensitive: scanSensitive(text),
  };
}

/** Reviewer markup/comment annotation subtypes we surface (spec-v9 §7). */
const PDF_ANNOT_SUBTYPES = "Text|FreeText|Highlight|Underline|StrikeOut|Squiggly";
const PDF_ANNOT_RE = new RegExp(`/Subtype\\s{0,8}/(${PDF_ANNOT_SUBTYPES})\\b`, "g");
const PDF_ANNOT_LABEL: Record<string, string> = {
  Text: "sticky note",
  FreeText: "free-text note",
  Highlight: "highlight",
  Underline: "underline",
  StrikeOut: "strikeout",
  Squiggly: "squiggly underline",
};

/**
 * Recover reviewer annotations as {@link CommentFact}s. For each markup /
 * sticky-note annotation in the uncompressed body, capture its author (`/T`)
 * and a bounded excerpt of its note (`/Contents`, literal or hex); a markup
 * mark with no note still surfaces with a `[highlight]`-style label so the
 * recipient-visible mark is reported. The window is clamped to the annotation's
 * own object (between `endobj` markers) so a neighbouring object's fields are
 * never pulled in. All regexes are linear and bounded — ReDoS-free.
 */
function parsePdfAnnotations(ascii: string): CommentFact[] {
  const facts: CommentFact[] = [];
  PDF_ANNOT_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = PDF_ANNOT_RE.exec(ascii)) !== null && facts.length < MAX_FACTS) {
    const subtype = m[1]!;
    // Clamp the search window to this annotation's object: back to the prior
    // `endobj`, forward to this object's `endobj`, each within a bounded span.
    const rawBefore = ascii.slice(Math.max(0, m.index - 1200), m.index);
    const cut = rawBefore.lastIndexOf("endobj");
    const before = cut >= 0 ? rawBefore.slice(cut + 6) : rawBefore;
    const rawAfter = ascii.slice(m.index, Math.min(ascii.length, m.index + 1200));
    const end = rawAfter.indexOf("endobj");
    const after = end >= 0 ? rawAfter.slice(0, end) : rawAfter;
    const window = before + after;

    const authorLit = /\/T\s{0,8}\(([^)]{0,200})\)/.exec(window)?.[1];
    const authorHex = /\/T\s{0,8}<([0-9A-Fa-f]{0,400})>/.exec(window)?.[1];
    const author = authorLit !== undefined ? decodePdfLiteral(authorLit) : authorHex !== undefined ? decodePdfHex(authorHex) : undefined;

    const contentsLit = /\/Contents\s{0,8}\(([^)]{0,400})\)/.exec(window)?.[1];
    const contentsHex = /\/Contents\s{0,8}<([0-9A-Fa-f]{0,800})>/.exec(window)?.[1];
    const contents = contentsLit !== undefined ? decodePdfLiteral(contentsLit) : contentsHex !== undefined ? decodePdfHex(contentsHex) : undefined;

    const exc = excerpt(contents) ?? `[${PDF_ANNOT_LABEL[subtype] ?? subtype.toLowerCase()}]`;
    facts.push(compact({ author: clean(author), excerpt: exc }));
  }
  return facts;
}

function parsePdfInfo(ascii: string): MetadataFact[] {
  const facts: MetadataFact[] = [];
  const fields: Array<[string, string]> = [
    ["Author", "author"],
    ["Creator", "creator"],
    ["Producer", "producer"],
    ["Title", "title"],
    ["Subject", "subject"],
    ["Keywords", "keywords"],
    ["CreationDate", "created"],
    ["ModDate", "modified"],
  ];
  for (const [key, field] of fields) {
    // /Key (literal string) or /Key <hex string>, bounded.
    const lit = new RegExp(`/${key}\\s*\\(([^)]{0,400})\\)`).exec(ascii)?.[1];
    const hex = new RegExp(`/${key}\\s*<([0-9A-Fa-f]{0,800})>`).exec(ascii)?.[1];
    const value = lit !== undefined ? decodePdfLiteral(lit) : hex !== undefined ? decodePdfHex(hex) : undefined;
    const v = clean(value);
    if (v && facts.length < MAX_FACTS) facts.push({ field, value: v });
  }
  return facts;
}

function decodePdfLiteral(s: string): string {
  // Minimal PDF literal-string unescaping: \) \( \\ and \n \r \t. Whitespace
  // normalization and trimming happen downstream in `clean()`.
  return s
    .replace(/\\([nrtbf()\\])/g, (_, c: string) => {
      const map: Record<string, string> = { n: "\n", r: "\r", t: "\t", b: "\b", f: "\f" };
      return map[c] ?? c;
    });
}

function decodePdfHex(h: string): string {
  const hex = h.replace(/\s/g, "");
  let out = "";
  for (let i = 0; i + 1 < hex.length; i += 2) {
    const code = parseInt(hex.slice(i, i + 2), 16);
    if (!Number.isNaN(code) && code >= 0x20) out += String.fromCharCode(code);
  }
  return out;
}

/* ------------------------------ helpers ------------------------------- */

/** Decode the handful of XML entities OOXML uses, trim, and bound length. */
function clean(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const decoded = value
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/\s+/g, " ")
    .trim();
  return decoded.length > 0 ? decoded.slice(0, 400) : undefined;
}

/** Truncate a recovered text span to an excerpt — for location, never reproduction. */
function excerpt(value: string | undefined): string | undefined {
  const c = clean(value);
  if (!c) return undefined;
  return c.length > EXCERPT_LEN ? c.slice(0, EXCERPT_LEN) + "…" : c;
}

/** Drop undefined fields so the canonical hash body is stable and minimal. */
function compact<T extends Record<string, unknown>>(obj: T): T {
  for (const k of Object.keys(obj)) {
    if (obj[k] === undefined) delete obj[k];
  }
  return obj;
}
