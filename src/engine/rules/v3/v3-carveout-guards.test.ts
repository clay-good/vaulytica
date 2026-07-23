/**
 * Guards against v3 language rules whose finding was contradicted by its own
 * excerpt.
 *
 * The v3 language builders had no carve-out mechanism at all (v4's has had
 * `exclude_if` for a while), so a paragraph stating the COMPLIANT form of a
 * pattern was reported as the violation:
 *
 *  - BAA-023 read the "successful" half of HIPAA's own definition, "attempted
 *    or successful unauthorized access", as a narrowing to successful access —
 *    accusing the exact wording its own `recommendation` field prescribes.
 *  - BAA-024 read "commercially reasonable EFFORTS" (manner of performance) as
 *    open-ended timing, and reported "lacks definite outer bound" on a clause
 *    that said "within 30 days of termination".
 *  - DPA-023's lookahead scanned only FORWARD for an Annex, so "As set forth in
 *    Annex II … Processor shall implement industry-standard security covering
 *    encryption at rest, access controls, and network segmentation" was called
 *    "undefined hand-waving" despite naming the Annex and listing measures.
 *
 * Both directions are pinned for each rule.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../../_test-fixtures.js";
import { BAA_RULES } from "./baa/index.js";
import { DPA_GDPR_RULES } from "./dpa-gdpr/index.js";

const baa = (id: string) => BAA_RULES.find((r) => r.id === id)!;
const dpa = (id: string) => DPA_GDPR_RULES.find((r) => r.id === id)!;
const doc = (heading: string, ...rest: string[]) => buildContext([heading, ...rest]);

describe("BAA-023 — HIPAA's own Security Incident definition", () => {
  it("stays silent on the full 'attempted or successful' definition", () => {
    expect(
      baa("BAA-023").check(
        doc(
          "Definitions",
          '"Security Incident" means the attempted or successful unauthorized access, use, disclosure, modification, or destruction of information or interference with system operations in an information system, in accordance with 45 CFR 164.304.',
        ),
      ),
    ).toBeNull();
  });

  it("still flags a definition narrowed to successful access only", () => {
    expect(
      baa("BAA-023").check(
        doc(
          "Definitions",
          '"Security Incident" means the successful unauthorized access, use, or disclosure of information in an information system.',
        ),
      ),
    ).not.toBeNull();
  });
});

describe("BAA-024 — return-or-destruction outer bound", () => {
  it("stays silent when the clause states a definite day count", () => {
    expect(
      baa("BAA-024").check(
        doc(
          "Termination",
          "Upon termination, Business Associate shall return or destroy, using commercially reasonable efforts, all Protected Health Information within 30 days of termination of this Agreement.",
        ),
      ),
    ).toBeNull();
  });

  it("still flags a genuinely open-ended return-or-destruction clause", () => {
    expect(
      baa("BAA-024").check(
        doc(
          "Termination",
          "Upon termination, Business Associate shall return or destroy all Protected Health Information as soon as practicable.",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("DPA-023 — 'appropriate measures' with an Annex", () => {
  it("stays silent when an Annex is named before the trigger phrase", () => {
    expect(
      dpa("DPA-023").check(
        doc(
          "Security",
          "As set forth in Annex II (Technical and Organisational Measures), Processor shall implement industry-standard security covering encryption at rest, access controls, and network segmentation.",
        ),
      ),
    ).toBeNull();
  });

  it("still flags bare hand-waving with no Annex or specifics", () => {
    expect(
      dpa("DPA-023").check(
        doc("Security", "Processor shall implement industry-standard security."),
      ),
    ).not.toBeNull();
  });

  it("still flags bare 'commercially reasonable security' with no Annex", () => {
    expect(
      dpa("DPA-023").check(
        doc("Security", "Processor shall maintain commercially reasonable security."),
      ),
    ).not.toBeNull();
  });
});
