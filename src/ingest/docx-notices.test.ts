import { describe, expect, it } from "vitest";
import {
  buildDocx,
  documentXml,
  hiddenContentDocx,
  trackedChangesDocx,
} from "../delivery/_fixtures.js";
import { countRevisions, docxNotices } from "./docx-notices.js";

describe("countRevisions", () => {
  it("counts the insertions and deletions in a redline", () => {
    expect(countRevisions(trackedChangesDocx())).toEqual({
      insertions: 1,
      deletions: 1,
      moves: 0,
      hidden: 0,
    });
  });

  it("counts nothing in a clean document", () => {
    const clean = buildDocx({
      document: documentXml(`<w:p><w:r><w:t>The fee is due in 30 days.</w:t></w:r></w:p>`),
    });
    expect(countRevisions(clean)).toEqual({ insertions: 0, deletions: 0, moves: 0, hidden: 0 });
  });

  it("does not throw on bytes that are not a container", () => {
    expect(countRevisions(new Uint8Array([1, 2, 3]).buffer)).toEqual({
      insertions: 0,
      deletions: 0,
      moves: 0,
      hidden: 0,
    });
  });

  it("counts a hidden (w:vanish) run", () => {
    expect(countRevisions(hiddenContentDocx()).hidden).toBe(1);
  });

  it("does not count a w:vanish that turns hiding OFF", () => {
    const doc = buildDocx({
      document: documentXml(
        `<w:p><w:r><w:rPr><w:vanish w:val="0"/></w:rPr><w:t>Visible.</w:t></w:r></w:p>`,
      ),
    });
    expect(countRevisions(doc).hidden).toBe(0);
  });

  it("does not mistake w:delText for another deletion", () => {
    // `<w:del>` wraps `<w:delText>`, and a bare `indexOf("<w:del")` counts both.
    const doc = buildDocx({
      document: documentXml(
        `<w:p><w:del w:id="1" w:author="A"><w:r><w:delText>net 30 days</w:delText></w:r></w:del></w:p>`,
      ),
    });
    expect(countRevisions(doc).deletions).toBe(1);
  });
});

describe("docxNotices", () => {
  const none = { insertions: 0, deletions: 0, moves: 0, hidden: 0 };

  it("is silent on an ordinary document", () => {
    expect(docxNotices(none)).toEqual([]);
  });

  it("names which version of a redline was read", () => {
    const [w] = docxNotices({ ...none, insertions: 3, deletions: 2 });
    expect(w).toContain("3 insertions, 2 deletions");
    expect(w).toContain("ACCEPTED");
  });

  it("says the deleted text was not analyzed — only when there are deletions", () => {
    expect(docxNotices({ ...none, insertions: 1 })[0]).not.toContain("NOT analyzed");
    expect(docxNotices({ ...none, deletions: 1 })[0]).toContain("NOT analyzed");
  });

  it("pluralizes honestly", () => {
    expect(docxNotices({ ...none, insertions: 1 })[0]).toContain("1 insertion)");
    expect(docxNotices({ ...none, insertions: 2 })[0]).toContain("2 insertions)");
  });

  it("warns that hidden text WAS analyzed — the opposite failure", () => {
    const [w] = docxNotices({ ...none, hidden: 2 });
    expect(w).toContain("2 hidden text runs");
    expect(w).toContain("They WERE analyzed");
    expect(w).toContain("cannot see");
  });

  it("agrees with itself about number", () => {
    expect(docxNotices({ ...none, hidden: 1 })[0]).toContain("1 hidden text run that");
    expect(docxNotices({ ...none, hidden: 1 })[0]).toContain("It WAS analyzed");
    expect(docxNotices({ ...none, hidden: 1 })[0]).not.toContain("They WERE");
  });

  it("gives a document with both its own notice for each", () => {
    expect(docxNotices({ ...none, insertions: 1, hidden: 1 })).toHaveLength(2);
  });
});
