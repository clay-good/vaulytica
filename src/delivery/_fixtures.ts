/**
 * Deterministic adversarial-container builders (spec-v9 §16, Step 148 —
 * mirroring the v8 Step-127 discipline). These construct DOCX containers from
 * scratch with `fflate`, so no real document is ever committed as a test
 * artifact (§Part XIV). Test-only: imported by `*.test.ts`, never by shipped
 * `src/` code (asserted by the accuracy-corpus guard).
 */

import { zipSync, strToU8 } from "fflate";

const CONTENT_TYPES = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/comments.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml"/>
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>`;

const ROOT_RELS = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`;

const DOC_RELS = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rIdC" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/comments" Target="comments.xml"/>
</Relationships>`;

const W_NS =
  'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"';
const CP_NS =
  'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/"';

export type DocxParts = {
  document?: string;
  comments?: string;
  core?: string;
  app?: string;
};

/** Assemble a DOCX `ArrayBuffer` from raw OOXML part strings. */
export function buildDocx(parts: DocxParts): ArrayBuffer {
  const files: Record<string, Uint8Array> = {
    "[Content_Types].xml": strToU8(CONTENT_TYPES),
    "_rels/.rels": strToU8(ROOT_RELS),
    "word/_rels/document.xml.rels": strToU8(DOC_RELS),
  };
  if (parts.document !== undefined) files["word/document.xml"] = strToU8(parts.document);
  if (parts.comments !== undefined) files["word/comments.xml"] = strToU8(parts.comments);
  if (parts.core !== undefined) files["docProps/core.xml"] = strToU8(parts.core);
  if (parts.app !== undefined) files["docProps/app.xml"] = strToU8(parts.app);
  const zipped = zipSync(files);
  return zipped.buffer.slice(zipped.byteOffset, zipped.byteOffset + zipped.byteLength) as ArrayBuffer;
}

/** A clean document body wrapping the given inner run XML. */
export function documentXml(inner: string): string {
  return `<?xml version="1.0"?><w:document ${W_NS}><w:body>${inner}</w:body></w:document>`;
}

/** A DOCX with a tracked insertion, a deletion, and a comment-reference run. */
export function trackedChangesDocx(): ArrayBuffer {
  const body = documentXml(
    `<w:p><w:ins w:id="1" w:author="Opposing Counsel" w:date="2026-01-01T00:00:00Z"><w:r><w:t>indemnify and hold harmless</w:t></w:r></w:ins></w:p>` +
      `<w:p><w:del w:id="2" w:author="Jane Partner"><w:r><w:delText>net 30 days</w:delText></w:r></w:del></w:p>` +
      `<w:p><w:r><w:t>Ordinary visible text.</w:t></w:r></w:p>`,
  );
  const comments = `<?xml version="1.0"?><w:comments ${W_NS}><w:comment w:id="1" w:author="Reviewer Bob" w:date="2026-01-02T00:00:00Z"><w:p><w:r><w:t>Push back on this number.</w:t></w:r></w:p></w:comment></w:comments>`;
  return buildDocx({ document: body, comments });
}

/** A DOCX with a hidden (`w:vanish`) run. */
export function hiddenContentDocx(): ArrayBuffer {
  const body = documentXml(
    `<w:p><w:r><w:rPr><w:vanish/></w:rPr><w:t>internal margin: 40 percent</w:t></w:r></w:p>` +
      `<w:p><w:r><w:t>Visible paragraph.</w:t></w:r></w:p>`,
  );
  return buildDocx({ document: body });
}

/** A DOCX whose metadata names a company that is not a party (cross-matter leak). */
export function metadataLeakDocx(): ArrayBuffer {
  const core = `<?xml version="1.0"?><cp:coreProperties ${CP_NS}><dc:creator>Alex Drafter</dc:creator><cp:lastModifiedBy>Alex Drafter</cp:lastModifiedBy><dc:title>Acme MSA</dc:title><cp:revision>7</cp:revision></cp:coreProperties>`;
  const app = `<?xml version="1.0"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Company>Globex Corporation</Company><Template>C:\\templates\\PriorClient_MSA.dotx</Template><TotalTime>415</TotalTime></Properties>`;
  return buildDocx({ document: documentXml(`<w:p><w:r><w:t>Body.</w:t></w:r></w:p>`), core, app });
}

/* ---- malformed / adversarial inputs for the totality contract ---- */

/** A "DOCX" whose document.xml is truncated mid-element. */
export function truncatedDocx(): ArrayBuffer {
  return buildDocx({ document: `<?xml version="1.0"?><w:document ${W_NS}><w:body><w:p><w:ins w:author="X"` });
}

/** A DOCX with a comments part but a malformed comments.xml. */
export function malformedCommentsDocx(): ArrayBuffer {
  return buildDocx({
    document: documentXml(`<w:p><w:r><w:t>ok</w:t></w:r></w:p>`),
    comments: `<<not xml at all <<< &&& <w:comment`,
  });
}

/** A revision element with no author attribute. */
export function authorlessRevisionDocx(): ArrayBuffer {
  return buildDocx({
    document: documentXml(`<w:p><w:ins w:id="9"><w:r><w:t>added</w:t></w:r></w:ins></w:p>`),
  });
}

/** Bytes that are not a zip at all. */
export function notAZip(): ArrayBuffer {
  return strToU8("this is plainly not a zip archive").buffer as ArrayBuffer;
}
