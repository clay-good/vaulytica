import { describe, expect, it } from "vitest";
import { V4_RULES } from "../index.js";
import { buildContext } from "../../../_test-fixtures.js";
import type { Rule } from "../../../finding.js";

const rule = (id: string) => V4_RULES.find((r) => r.id === id) as Rule;

/**
 * A set of disclosure schedules opens with three or four paragraphs of general
 * notes. MNA-039 required the literal heading "General Notes" — one firm's
 * house style — and MNA-042 required the negator "not" and the noun
 * "admission", when the sentences every set carries are "Nothing disclosed
 * here is an admission that the matter is material" and "The inclusion of any
 * dollar amount is not a representation that the amount is material".
 */
describe("the introduction a set of disclosure schedules actually carries", () => {
  const intro = (...paragraphs: string[]) => buildContext(["Disclosure Schedules", ...paragraphs]);

  it("MNA-039 reads an introduction with no 'General Notes' heading", () => {
    expect(
      rule("MNA-039").check(
        intro(
          'These Disclosure Schedules are delivered by the Company pursuant to the Stock Purchase Agreement dated as of February 20, 2026 (the "Purchase Agreement").',
          "The section numbers below correspond to the section numbers of the Purchase Agreement, and any matter disclosed in any section is deemed disclosed for the purposes of every other section to the extent its relevance is reasonably apparent.",
        ),
      ),
    ).toBeNull();
  });

  it("MNA-039 still reports a bare list of exceptions with no introduction", () => {
    expect(
      rule("MNA-039").check(
        intro(
          "Schedule 3.9 — Material Contracts",
          "1. Master Supply Agreement with Corvid Optical Systems, Inc. dated August 12, 2022.",
        ),
      ),
    ).not.toBeNull();
  });

  it("MNA-042 reads the two materiality sentences as they are written", () => {
    expect(
      rule("MNA-042").check(
        intro(
          "Nothing disclosed here is an admission that the matter is material, that it is required to be disclosed, or that it constitutes a breach of any representation.",
          "The inclusion of any dollar amount is not a representation that the amount is material or that a lower amount would not be material.",
        ),
      ),
    ).toBeNull();
  });

  it("MNA-042 still reports schedules that disclaim nothing", () => {
    expect(
      rule("MNA-042").check(
        intro(
          "These Disclosure Schedules are delivered pursuant to the Purchase Agreement.",
          "Schedule 3.15 — Litigation. None.",
        ),
      ),
    ).not.toBeNull();
  });
});
