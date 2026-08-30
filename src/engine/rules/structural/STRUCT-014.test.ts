import { describe, expect, it } from "vitest";
import { rule as STRUCT_014 } from "./STRUCT-014.js";
import { buildContext } from "../../_test-fixtures.js";

describe("STRUCT-014 — inconsistent defined-term casing", () => {
  it("fires when a defined Title-Case term is referenced in lowercase elsewhere", () => {
    const ctx = buildContext([
      "Definitions",
      `"Confidential Information" means non-public information disclosed by Discloser.`,
      `Recipient shall protect Confidential Information using reasonable care.`,
      `Recipient may not share confidential information with third parties.`,
    ]);
    const f = STRUCT_014.check(ctx);
    expect(f?.severity).toBe("info");
    expect(f?.title).toMatch(/lowercase/i);
    expect(f?.description).toContain("Confidential Information");
  });

  it("silent when every occurrence preserves the defined casing", () => {
    const ctx = buildContext([
      "Definitions",
      `"Confidential Information" means non-public information.`,
      `Recipient shall protect Confidential Information.`,
    ]);
    expect(STRUCT_014.check(ctx)).toBeNull();
  });

  it("ignores single-word defined terms (too noisy to flag)", () => {
    const ctx = buildContext([
      "Definitions",
      `"Term" means the duration of this Agreement.`,
      `The term begins on the Effective Date.`,
    ]);
    expect(STRUCT_014.check(ctx)).toBeNull();
  });

  it("ignores occurrences at the start of a sentence", () => {
    const ctx = buildContext([
      "Definitions",
      `"Permitted Purpose" means evaluation of a potential transaction.`,
      `Recipient shall use information only for the Permitted Purpose. permitted purpose evaluation continues.`,
    ]);
    // The lowercase "permitted purpose" at sentence-start is preceded
    // by `. ` and so should be skipped by the heuristic.
    expect(STRUCT_014.check(ctx)).toBeNull();
  });

  it("does not flag a lowercase recital use that PRECEDES the definition (v1.3.0)", () => {
    // A recital "may disclose certain confidential information" comes before the
    // Section 1 definition; the term is not yet defined, so it is not a slip.
    const ctx = buildContext([
      "Recitals",
      "The parties may disclose certain confidential information to each other.",
      "Definitions",
      `"Confidential Information" means non-public information disclosed by Discloser.`,
      `Recipient shall protect Confidential Information using reasonable care.`,
    ]);
    expect(STRUCT_014.check(ctx)).toBeNull();
  });

  it("still flags a lowercase slip that follows the definition", () => {
    const ctx = buildContext([
      "Recitals",
      "The parties may disclose certain confidential information to each other.",
      "Definitions",
      `"Confidential Information" means non-public information.`,
      `Recipient may not share confidential information with third parties.`,
    ]);
    expect(STRUCT_014.check(ctx)).not.toBeNull();
  });

  it("flags multiple lowercase variants in one finding with a count", () => {
    const ctx = buildContext([
      "Definitions",
      `"Confidential Information" means private data.`,
      `Treat confidential information with care.`,
      `Even more confidential information must be protected.`,
    ]);
    const f = STRUCT_014.check(ctx);
    expect(f).not.toBeNull();
    expect(f!.description).toMatch(/2 references|references use/);
  });
});

describe("STRUCT-014 — a lowercase use inside its own definition (v1.4.0)", () => {
  it('does not report "Common Stock" for the noun inside its own definition', () => {
    // `"Common Stock" means the Company's common stock, par value $0.0001 per
    // share` states what the term refers to, in the ordinary noun the term is
    // built from. Every ESPP, charter, and note defines its stock that way.
    const ctx = buildContext([
      "2026 Employee Stock Purchase Plan",
      '"Common Stock" means the Company\'s common stock, par value $0.0001 per share.',
      "The maximum number of shares of Common Stock that may be issued under the Plan is 1,800,000.",
    ]);
    expect(STRUCT_014.check(ctx)).toBeNull();
  });

  it("still reports a lowercase use elsewhere in the document", () => {
    const ctx = buildContext([
      "2026 Employee Stock Purchase Plan",
      '"Common Stock" means the Company\'s stock, par value $0.0001 per share.',
      "The maximum number of shares of common stock that may be issued under the Plan is 1,800,000.",
    ]);
    expect(STRUCT_014.check(ctx)).not.toBeNull();
  });
});
