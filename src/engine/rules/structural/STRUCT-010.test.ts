import { describe, expect, it } from "vitest";
import { rule as STRUCT_010 } from "./STRUCT-010.js";
import { buildContext } from "../../_test-fixtures.js";

/**
 * STRUCT-010 tells a reader that the Table of Contents no longer matches the
 * document — a renumbering that never made it back to the front page. It had
 * no test of its own, and the reason is worth recording: it cannot fire on the
 * specimen corpus at all. Every specimen is plain text, and pasted text has no
 * headings (`ingestPaste` says so in its own docstring), so the check has
 * nothing to compare a TOC against. The documents it CAN reach are the ones
 * that carry headings — in practice, DOCX. In practice, Word wrote the TOC.
 *
 * And a Word TOC puts its page number on a TAB STOP. Flattened to text, a
 * perfectly correct "1. Services" entry arrives as "1. Services\t3", which
 * matches no heading — so the rule reported EVERY line of a correct TOC as
 * unresolved. Measured before the fix, on the four shapes below: 3, 3, 0 and 2
 * false accusations.
 */
describe("STRUCT-010 — TOC parity (v1.1.0)", () => {
  const BODY: [string, ...string[]][] = [
    ["1. Services", "Provider shall perform the Services described in each Statement of Work."],
    ["2. Compensation", "Client shall pay the fees set out in each Statement of Work."],
    ["3. Term and Termination", "This Agreement continues until terminated under this Section."],
  ];

  const check = (...toc: string[]) =>
    STRUCT_010.check(
      buildContext(
        ["Master Services Agreement", "This Agreement is made as of the Effective Date."],
        ["Table of Contents", ...toc],
        ...BODY,
      ),
    );

  it("reports an entry that resolves to no section", () => {
    const finding = check("1. Services", "9. Source Code Escrow");
    expect(finding, "a stale TOC entry went unreported").not.toBeNull();
    expect(finding!.title).toBe("TOC entries with no matching section: 1");
    expect(finding!.description).toBe("9. Source Code Escrow");
    expect(finding!.severity).toBe("info");
  });

  it("says nothing when every entry resolves", () => {
    expect(check("1. Services", "2. Compensation", "3. Term and Termination")).toBeNull();
  });

  it("reads a Word tab-leader page number as a page number", () => {
    expect(check("1. Services\t3", "2. Compensation\t4", "3. Term and Termination\t5")).toBeNull();
    expect(check("1. Services 3", "2. Compensation 4")).toBeNull();
  });

  it("reads a dot leader as a leader", () => {
    expect(check("1. Services ......... 3", "2. Compensation ....... 4")).toBeNull();
  });

  it("does not treat a trailing period, case, or dash style as a renumbering", () => {
    expect(check("1. Services.", "2. Compensation.")).toBeNull();
    expect(check("1. SERVICES", "2. compensation")).toBeNull();
  });

  it("still matches a heading that legitimately ends in a number", () => {
    // The page-number strip is tried IN ADDITION to the literal line, never
    // instead of it, so "Exhibit 3" does not become "Exhibit".
    expect(
      STRUCT_010.check(
        buildContext(
          ["Equipment Schedule", "The following exhibits are attached."],
          ["Table of Contents", "Exhibit 3", "Exhibit 4\t11"],
          ["Exhibit 3", "Leased equipment located at the Cedar Park facility."],
          ["Exhibit 4", "Leased equipment located at the Round Rock facility."],
        ),
      ),
    ).toBeNull();
  });

  it("says nothing at all when the document has no Table of Contents", () => {
    expect(STRUCT_010.check(buildContext(...BODY))).toBeNull();
  });
});
