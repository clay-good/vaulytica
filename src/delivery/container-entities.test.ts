import { describe, expect, it } from "vitest";

import { readContainer } from "./container.js";
import { buildDocx, documentXml } from "./_fixtures.js";

const W_NS = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"';

/**
 * File bytes `&amp;lt;` are the XML encoding of the four literal characters
 * ampersand-l-t-semicolon. Correct decoding returns those four characters.
 * Author bytes `Smith &amp; Co` encode the true name `Smith & Co`.
 */
function entityCommentDocx(): ArrayBuffer {
  const body = documentXml(`<w:p><w:r><w:t>Body.</w:t></w:r></w:p>`);
  const comments =
    `<?xml version="1.0"?><w:comments ${W_NS}>` +
    `<w:comment w:id="1" w:author="Smith &amp; Co" w:date="2026-01-02T00:00:00Z">` +
    `<w:p><w:r><w:t>Type &amp;lt; to escape a bracket.</w:t></w:r></w:p>` +
    `</w:comment></w:comments>`;
  return buildDocx({ document: body, comments });
}

/**
 * The pre-disclosure report exists to show a reviewer exactly what a document
 * carries before it leaves the building, so its decoder has to be faithful.
 * `clean()` used to run a CHAIN of `.replace` calls with `&amp;` first, which
 * double-decodes: `&amp;lt;` — the correct encoding of the four characters a
 * reviewer typed as `&lt;` — became `&lt;` after the first step and then `<`
 * after the second, so the comment shown said something the document did not.
 */
describe("container XML entity decoding", () => {
  it("decodes each entity exactly once", () => {
    const facts = readContainer(entityCommentDocx(), "docx", "Body.");
    const c = facts.comments[0];
    expect(c).toBeDefined();
    // File bytes `Smith &amp; Co` encode the name `Smith & Co`.
    expect(c!.author).toBe("Smith & Co");
    // File bytes `Type &amp;lt; to escape a bracket.` encode text whose
    // literal content is `&lt;` — NOT a live `<`.
    expect(c!.excerpt).toContain("Type &lt; to escape a bracket.");
    expect(c!.excerpt).not.toContain("Type < to");
  });
});
