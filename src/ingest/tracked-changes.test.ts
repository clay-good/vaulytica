import { describe, expect, it } from "vitest";
import { buildDocx, documentXml, trackedChangesDocx } from "../delivery/_fixtures.js";
import { countRevisions, trackedChangesWarning } from "./tracked-changes.js";

describe("countRevisions", () => {
  it("counts the insertions and deletions in a redline", () => {
    expect(countRevisions(trackedChangesDocx())).toEqual({
      insertions: 1,
      deletions: 1,
      moves: 0,
    });
  });

  it("counts nothing in a clean document", () => {
    const clean = buildDocx({
      document: documentXml(`<w:p><w:r><w:t>The fee is due in 30 days.</w:t></w:r></w:p>`),
    });
    expect(countRevisions(clean)).toEqual({ insertions: 0, deletions: 0, moves: 0 });
  });

  it("does not throw on bytes that are not a container", () => {
    expect(countRevisions(new Uint8Array([1, 2, 3]).buffer)).toEqual({
      insertions: 0,
      deletions: 0,
      moves: 0,
    });
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

describe("trackedChangesWarning", () => {
  it("is silent on a clean document", () => {
    expect(trackedChangesWarning({ insertions: 0, deletions: 0, moves: 0 })).toBeNull();
  });

  it("names which version was read", () => {
    const w = trackedChangesWarning({ insertions: 3, deletions: 2, moves: 0 })!;
    expect(w).toContain("3 insertions, 2 deletions");
    expect(w).toContain("ACCEPTED");
  });

  it("says the deleted text was not analyzed — only when there are deletions", () => {
    expect(trackedChangesWarning({ insertions: 1, deletions: 0, moves: 0 })).not.toContain(
      "NOT analyzed",
    );
    expect(trackedChangesWarning({ insertions: 0, deletions: 1, moves: 0 })).toContain(
      "NOT analyzed",
    );
  });

  it("pluralizes honestly", () => {
    expect(trackedChangesWarning({ insertions: 1, deletions: 0, moves: 0 })).toContain(
      "1 insertion)",
    );
    expect(trackedChangesWarning({ insertions: 2, deletions: 0, moves: 0 })).toContain(
      "2 insertions)",
    );
  });
});
