/** The size Word sets a run in, resolved through the file's own styles (docx-sizes.ts). */
import { describe, expect, it } from "vitest";
import { buildDocx, documentXml } from "../delivery/_fixtures.js";
import { sizeResolver } from "./docx-sizes.js";

const W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"';
const file = (styles?: string) =>
  buildDocx({ document: documentXml("<w:p/>"), ...(styles ? { styles } : {}) });
const style = (type: string, id: string, inner: string, extra = "") =>
  `<w:style w:type="${type}" w:styleId="${id}"${extra}>${inner}</w:style>`;

describe("sizeResolver", () => {
  const styles = `<w:styles ${W}><w:docDefaults><w:rPrDefault><w:rPr><w:sz w:val="22"/></w:rPr></w:rPrDefault></w:docDefaults>${style(
    "paragraph",
    "Normal",
    "<w:name w:val='Normal'/>",
    ' w:default="1"',
  )}${style("paragraph", "Small", '<w:basedOn w:val="Normal"/><w:rPr><w:sz w:val="16"/></w:rPr>')}${style(
    "paragraph",
    "SmallChild",
    '<w:basedOn w:val="Small"/>',
  )}${style("character", "Tiny", '<w:rPr><w:sz w:val="12"/></w:rPr>')}${style(
    "paragraph",
    "LoopA",
    '<w:basedOn w:val="LoopB"/>',
  )}${style("paragraph", "LoopB", '<w:basedOn w:val="LoopA"/>')}</w:styles>`;
  const r = sizeResolver(file(styles));

  it("prefers the run's own size", () => {
    expect(r.size({ fontSize: 14 }, "Small")).toBe(14);
  });
  it("then its character style, then its paragraph style through basedOn", () => {
    expect(r.size({ styleId: "Tiny" }, "Small")).toBe(6);
    expect(r.size({}, "SmallChild")).toBe(8);
  });
  it("then the document defaults, for the default paragraph style", () => {
    expect(r.size({}, null)).toBe(11);
    expect(r.size({}, "Normal")).toBe(11);
  });
  it("ends a basedOn cycle at the document default", () => {
    expect(r.size({}, "LoopA")).toBe(11);
  });
  it("answers undefined when the file states no size anywhere", () => {
    expect(sizeResolver(file()).size({}, null)).toBeUndefined();
    expect(sizeResolver(file(`<w:styles ${W}/>`)).size({}, "Normal")).toBeUndefined();
  });
});
