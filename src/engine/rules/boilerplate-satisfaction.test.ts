/**
 * A pack check must not be SATISFIED by a document that says nothing.
 *
 * The sibling guards ask whether a check can FIRE at all — title vacuity,
 * self-reachability. This one asks the other direction, which is where the
 * quieter failure lives: a check whose patterns are matched by the skeleton
 * every contract carries is silent on every document, and a silent check reads
 * to an attorney exactly like a clause that is present and correct.
 *
 * Eight were found this way, and they failed for two reasons that recur:
 *
 *   - A pillar with no word boundary. MNA-105 and SET-139 both listed the bare
 *     word "cap", which matches inside "CAPitalized terms have the meanings
 *     given in Section 1" — so a purchase agreement with no cap, no basket and
 *     no survival period passed on the strength of its definitions
 *     cross-reference.
 *   - A LOCATOR pillar joined by an OR. "Arbitration clause quoted AND
 *     located", "Background IP identified AND licensed", "Amount or percentage
 *     AND valuation date" — each names two things, and each had its second
 *     pillar written as something every document carries: a section number, a
 *     date, the word "identified". `pat` defaults to an OR, so the locator
 *     alone scored every document clean.
 *
 * The patterns are probed DIRECTLY through `PACK_SPECS` rather than through
 * `check`, because a rule's applicability gate would otherwise short-circuit
 * the check before its patterns are ever consulted — and a conditional column
 * ("Crummey withdrawal rights where applicable") is right to stay silent here.
 */
import { describe, expect, it } from "vitest";
import { PACK_SPECS } from "./v5/_pack.js";
import { V4_PRESENCE_SPECS } from "./v4/_helpers.js";
import { V4_RULES } from "./v4/index.js";
import "./v5/index.js";

/**
 * A contract with a preamble, a definitions cross-reference, an intent
 * recital, and an execution block — and no substantive term of any kind.
 * Deliberately free of governing law, assignment, severability and the rest:
 * those ARE substantive clauses, and a check about them is right to read one.
 */
const SKELETON = [
  "This Agreement is made as of January 5, 2026.",
  "Capitalized terms have the meanings given in Section 1.",
  "The parties intend to be bound by it.",
].join("\n");

/** The columns a skeleton satisfies, by id, with the patterns that matched. */
function satisfiedBy(specs: Map<string, { pat: RegExp[]; all: boolean }>): string[] {
  const out: string[] = [];
  for (const [id, spec] of specs) {
    const hits = spec.pat.filter((p) => p.test(SKELETON));
    const ok = spec.all ? hits.length === spec.pat.length : hits.length > 0;
    if (ok) out.push(`${id} — matched ${hits.map((h) => String(h)).join(" ; ")}`);
  }
  return out;
}

describe("no check is satisfied by a contentless skeleton", () => {
  it("v5 compliance-matrix columns", () => {
    const satisfied = satisfiedBy(PACK_SPECS);
    expect(
      satisfied,
      `these columns are silent on a document that says nothing:\n${satisfied.join("\n")}`,
    ).toEqual([]);
  });

  it("v4 presence rules", () => {
    const satisfied = satisfiedBy(V4_PRESENCE_SPECS);
    expect(
      satisfied,
      `these rules are silent on a document that says nothing:\n${satisfied.join("\n")}`,
    ).toEqual([]);
  });

  it("the probe is load-bearing — both registries are populated", () => {
    expect(PACK_SPECS.size).toBeGreaterThan(500);
    expect(V4_PRESENCE_SPECS.size).toBeGreaterThan(500);
    expect(V4_RULES.length).toBeGreaterThan(500);
  });
});
