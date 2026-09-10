import { describe, expect, it } from "vitest";
import { rule as RISK_006 } from "./RISK-006.js";
import { buildContext } from "../../_test-fixtures.js";

describe("RISK-006 — a carve-out list that cites the sections it excepts", () => {
  // "Except for the INDEMNITY OBLIGATIONS in Sections 8.1 and 8.2, breach of
  // Section 9, and a party's gross negligence or WILLFUL MISCONDUCT, neither
  // party's aggregate liability shall exceed…" — a bare `[^.;\n]` window
  // stopped at the "8.1", so every carve-out after the first citation was
  // invisible, and the `indemnif` stem does not match "indemnity".
  it("reads past a section citation and recognizes the noun 'indemnity'", () => {
    const f = RISK_006.check(
      buildContext([
        "Liability",
        "8.5 Limitation of Liability. Except for the indemnity obligations in Sections 8.1 and 8.2, breach of Section 9, and a party's gross negligence or willful misconduct, neither party's aggregate liability under this Agreement shall exceed the amounts paid in the twelve months preceding the claim.",
      ]),
    );
    expect(f).not.toBeNull();
    expect(f?.description).toContain("willful misconduct");
    expect(f?.description).toContain("indemnification");
  });
});

// A limitation-of-liability section states its exceptions in more than one
// sentence, and the first one is usually not the cap's — the textbook layout is
// a damages exclusion with its own narrow exception, then the cap, then the
// carve-out list. And the carve-out list is introduced by "These limits do not
// apply to …" as often as by "except for".
describe("RISK-006 — every exception clause in the section (v1.3.0)", () => {
  const LOL =
    "19. Limitation of Liability. NEITHER PARTY IS LIABLE FOR INDIRECT, INCIDENTAL, SPECIAL, " +
    "CONSEQUENTIAL OR PUNITIVE DAMAGES, OR FOR LOST PROFITS, EXCEPT FOR AMOUNTS PAYABLE UNDER " +
    "SECTION 11. FRANCHISOR'S TOTAL LIABILITY IS LIMITED TO THE FEES PAID IN THE TWENTY-FOUR " +
    "(24) MONTHS BEFORE THE CLAIM. These limits do not apply to Franchisor's indemnity under " +
    "Section 7.3, either party's breach of Section 9.1, or either party's gross negligence, " +
    "willful misconduct or fraud.";

  it("reads the carve-out list introduced by 'do not apply to'", () => {
    const f = RISK_006.check(buildContext(["Liability", LOL]));
    expect(f).not.toBeNull();
    expect(f?.description).toContain("fraud");
    expect(f?.description).toContain("willful misconduct");
    expect(f?.description).toContain("indemnification");
    expect(f?.title).toContain("3/6");
  });

  it("still bounds each exception clause to its own sentence", () => {
    const f = RISK_006.check(
      buildContext([
        "Liability",
        "Limitation of Liability. Neither party is liable for indirect damages except for " +
          "amounts payable under Section 11. Nothing in this Section limits the cap. The " +
          "parties acknowledge that fraud and willful misconduct are serious.",
      ]),
    );
    expect(f?.title).toContain("0/6");
  });
});

// A limitation-of-liability article puts its heading in one paragraph and its
// clause in the next, so a paragraph-scoped read could never see both. The
// symptom was a finding that depended on the document's blank lines: strip
// them, the paragraphs merge, and the finding appears. Ten corpus specimens
// state their carve-outs this way and drew nothing.
describe("RISK-006 — the section, not the paragraph (v1.4.0)", () => {
  it("reads a heading paragraph and the clause paragraph after it", () => {
    const f = RISK_006.check(
      buildContext([
        "Distribution Agreement",
        "11. Limitation of Liability.",
        "Neither party is liable for indirect, incidental, or consequential damages. These " +
          "limits do not apply to a party's indemnity obligations under Section 10, to breach " +
          "of Section 9, or to liability that may not be limited under mandatory law.",
      ]),
    );
    expect(f).not.toBeNull();
    expect(f?.description).toContain("indemnification");
  });

  it("quotes a paragraph the document actually contains", () => {
    const f = RISK_006.check(
      buildContext([
        "Distribution Agreement",
        "11. Limitation of Liability.",
        "Neither party is liable for indirect damages. These limits do not apply to fraud.",
      ]),
    );
    expect(f?.excerpt.text).toBe(
      "Neither party is liable for indirect damages. These limits do not apply to fraud.",
    );
  });

  // A corporate exculpation article is not a commercial cap: its exceptions are
  // the duty of loyalty and bad faith, and reading it as one reported "0/6" on
  // an articles of organization.
  it("is silent on a manager-exculpation article", () => {
    const f = RISK_006.check(
      buildContext([
        "Articles of Organization",
        "ARTICLE VII. LIMITATION OF LIABILITY OF MANAGERS",
        "To the fullest extent permitted by law, no manager is liable to the company for " +
          "monetary damages for breach of fiduciary duty, except for liability for a breach of " +
          "the duty of loyalty or for acts not in good faith.",
      ]),
    );
    expect(f).toBeNull();
  });
});
