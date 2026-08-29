import { describe, expect, it } from "vitest";
import { rule as TEMP_012 } from "./TEMP-012.js";
import { buildContext } from "../../_test-fixtures.js";

describe("TEMP-012 — survival clause silent on sticky obligations", () => {
  it("fires when confidentiality + IP exist but survival names neither", () => {
    const ctx = buildContext(
      [
        "Confidentiality",
        "Recipient shall protect Confidential Information using reasonable care.",
      ],
      ["IP Assignment", "All work for hire produced by Consultant shall be owned by Company."],
      ["Survival", "Sections 4 and 5 of this Agreement shall survive termination."],
    );
    const f = TEMP_012.check(ctx);
    expect(f?.severity).toBe("warning");
    expect(f?.description).toMatch(/confidentiality.*IP/i);
  });

  it("fires when indemnity exists but survival doesn't name it", () => {
    const ctx = buildContext(
      ["Indemnification", "Vendor shall indemnify Customer against any third-party claim."],
      ["Survival", "The confidentiality obligations shall survive termination."],
    );
    const f = TEMP_012.check(ctx);
    expect(f).not.toBeNull();
    expect(f!.description).toMatch(/indemnif/i);
  });

  it("is silent when survival expressly names every present sticky obligation", () => {
    const ctx = buildContext(
      ["Confidentiality", "Recipient shall protect Confidential Information."],
      ["Indemnification", "Vendor shall indemnify Customer."],
      [
        "Survival",
        "The provisions regarding confidentiality and indemnification obligations shall survive termination of this Agreement.",
      ],
    );
    expect(TEMP_012.check(ctx)).toBeNull();
  });

  it("is silent when no survival clause exists (different rule's territory)", () => {
    const ctx = buildContext(
      ["Confidentiality", "Recipient shall protect Confidential Information."],
      ["Indemnification", "Vendor shall indemnify Customer."],
    );
    expect(TEMP_012.check(ctx)).toBeNull();
  });

  it("is silent when no sticky obligations are present", () => {
    const ctx = buildContext(
      ["Term", "This Agreement is effective for two years."],
      ["Survival", "The notice provisions shall survive termination."],
    );
    expect(TEMP_012.check(ctx)).toBeNull();
  });
});

describe("numbered survival lists and distributed survival (v1.1.0)", () => {
  it("resolves 'Sections 2, 5, 7, and 9 survive' against the sections it names", () => {
    const ctx = buildContext([
      "Agreement",
      "2. Work Made for Hire; Assignment. Artist hereby irrevocably assigns to Company all right, title, and interest in and to the Work.",
      "7. Confidentiality. Artist shall keep confidential all non-public information. These obligations survive termination of this Agreement for three (3) years.",
      "8. Termination. Either party may terminate for material breach. Sections 2, 5, 7, and 9 survive termination.",
    ]);
    expect(TEMP_012.check(ctx)).toBeNull();
  });

  it("still fires when neither survival sentence covers a present sticky obligation", () => {
    const ctx = buildContext([
      "Agreement",
      "2. Assignment. Contractor agrees to ip assignment of all deliverables to Company.",
      "7. Confidentiality. Recipient shall protect Confidential Information. Confidentiality obligations survive termination.",
    ]);
    expect(TEMP_012.check(ctx)?.description).toContain("IP ownership");
  });
});

describe("TEMP-012 — the survival clause that names sections, not topics (v1.2.0)", () => {
  /**
   * "Sections 2 through 5 and Section 7 survive termination indefinitely" is
   * the commonest survival drafting there is. Two things defeated it: the
   * enumeration expander read only the first endpoint of a RANGE, and the
   * indemnity test used the stem `indemnif`, which does not match the word a
   * section is HEADED with — "Indemnity".
   */
  it("reads an indemnity section incorporated by a range", () => {
    expect(
      TEMP_012.check(
        buildContext([
          "Hold Harmless Agreement",
          "2. Indemnity.",
          "Indemnitor shall indemnify, defend, and hold harmless Indemnitee from and against any and all claims.",
          "5. No Cap.",
          "The obligations of Indemnitor are not subject to any cap.",
          "9. Term and Survival.",
          "Sections 2 through 5 and Section 7 survive termination indefinitely.",
        ]),
      ),
    ).toBeNull();
  });

  it("reads a section headed 'Indemnity' named by number", () => {
    expect(
      TEMP_012.check(
        buildContext([
          "Agreement",
          "7. Indemnity.",
          "Each party shall indemnify the other against third-party claims.",
          "12. Survival.",
          "Sections 7 and 11 survive any termination of this Agreement.",
        ]),
      ),
    ).toBeNull();
  });

  it("still fires when the survival clause names a section that is not the indemnity", () => {
    expect(
      TEMP_012.check(
        buildContext([
          "Agreement",
          "7. Indemnity.",
          "Each party shall indemnify the other against third-party claims.",
          "12. Survival.",
          "Section 3 survives any termination of this Agreement.",
          "3. Notices.",
          "Notices must be in writing.",
        ]),
      )?.description,
    ).toContain("indemnification");
  });
});

describe("TEMP-012 — a survival clause that names sections by number", () => {
  // The clause number's trailing delimiter is OPTIONAL in modern drafting:
  // "6.3 Confidentiality." — number, space, heading. The section-reference
  // expander required a "." or ")" right after the digits, so no paragraph in
  // such a document was ever incorporated, and a survival clause reading
  // "Sections 6, 7 and 8.2 survive" was reported as naming neither the
  // confidentiality section it incorporates nor the indemnity.
  it("reads an undelimited clause label, and a section reference reaches its subsections", () => {
    expect(
      TEMP_012.check(
        buildContext([
          "Escrow",
          "6.3 Confidentiality. The Deposit Materials are the confidential information of Depositor.",
          "8.2 Indemnity. Depositor shall indemnify Escrow Agent against any loss arising out of this Agreement.",
          "9.3 Effect. On termination, Escrow Agent shall return the Deposit Materials, except that Sections 6, 7 and 8.2 survive any termination.",
        ]),
      ),
    ).toBeNull();
  });

  it("still fires when the survival clause names sections that carry neither obligation", () => {
    expect(
      TEMP_012.check(
        buildContext([
          "Escrow",
          "6.3 Confidentiality. The Deposit Materials are the confidential information of Depositor.",
          "10.1 Notices. All notices shall be in writing.",
          "9.3 Effect. On termination, Section 10 survives any termination.",
        ]),
      ),
    ).not.toBeNull();
  });
});

describe("TEMP-012 — an indemnity this document does not contain", () => {
  // A stockholders' agreement covenants that the Company "shall not amend the
  // INDEMNIFICATION PROVISIONS OF ITS CERTIFICATE OF INCORPORATION", and its
  // drag-along protects each holder from being "required ... to INDEMNIFY
  // beyond its pro rata share". Neither is an indemnity of this document, and
  // both made the survival clause report an indemnification that is not there.
  it("does not treat another instrument's indemnity as this document's", () => {
    expect(
      TEMP_012.check(
        buildContext([
          "Stockholders' Agreement",
          "The Company shall maintain directors' and officers' liability insurance and shall not amend the indemnification provisions of its certificate of incorporation or bylaws in a manner adverse to any director.",
          "5.3 Confidentiality. Each Investor shall keep confidential all information it receives under this Section 5.",
          "7.2 Effect of Termination. On termination, Sections 5.3, 6.2 and 8 survive.",
        ]),
      ),
    ).toBeNull();
  });

  it("does not treat a LIMIT on an indemnity as an indemnity", () => {
    expect(
      TEMP_012.check(
        buildContext([
          "Stockholders' Agreement",
          "No Stockholder shall be required, as a condition of the drag-along, to indemnify beyond its pro rata share of the consideration actually received.",
          "5.3 Confidentiality. Each Investor shall keep confidential all information it receives.",
          "7.2 Effect of Termination. On termination, Sections 5.3 and 8 survive.",
        ]),
      ),
    ).toBeNull();
  });

  it("still reports a real indemnity the survival clause omits", () => {
    expect(
      TEMP_012.check(
        buildContext([
          "Services Agreement",
          "6. Indemnity. Vendor shall indemnify Customer against any third-party claim arising out of the Services.",
          "5. Confidentiality. Each party shall keep the other's Confidential Information confidential.",
          "9. Effect of Termination. On termination, Section 5 survives.",
        ]),
      ),
    ).not.toBeNull();
  });
});
