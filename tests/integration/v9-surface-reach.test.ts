/**
 * Every v9 surface must actually REACH every renderer that claims it.
 *
 * `V9Surfaces` is the single optional bundle the DOCX, HTML, and SARIF
 * builders accept, and its own doc comment promises "the same three surfaces
 * render everywhere the report does". Nothing checked that. Thrust B — the
 * closing checklist, the surface that says what is left to do before signing —
 * was declared on the bundle, rendered by DOCX and HTML, and read by SARIF
 * NOWHERE: a CI pipeline consuming the SARIF got the readiness results but no
 * way to know which of them were the readiness set, or how many were open.
 *
 * The gap survived because it is invisible from either end. The type
 * compiles whether or not a builder destructures the field, and the field name
 * differs between the bundle (`closingChecklist`) and the JSON payload
 * (`closing_checklist`), so a grep for one spelling reports the other as
 * present. This asserts the reach directly instead.
 *
 * The rule: a field on `V9Surfaces` is either read by all three builders, or
 * it is DECLARED below with the reason. A declared exception that matches
 * nothing fails too, so a stale entry cannot outlive its cause.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const SRC = join(process.cwd(), "src", "report");

/** The builders that take the bundle, by the file that must read each field. */
const BUILDERS = ["html.ts", "docx.ts", "sarif.ts"] as const;

/**
 * Fields a given builder deliberately does not read, and why.
 *
 * Empty — and it should stay that way. The one entry this file was written to
 * hold (`sarif.ts`/`closingChecklist`) was fixed rather than declared: the
 * checklist body genuinely must not become SARIF results, because every item
 * is a re-projection of a result already present and a CI gate thresholds on
 * the count. So SARIF carries the ROLL-UP instead, and reads the field.
 */
const DECLARED: ReadonlyArray<[string, string, string]> = [];

/** The optional field names declared on the `V9Surfaces` type. */
function surfaceFields(): string[] {
  const src = readFileSync(join(SRC, "v9-surfaces.ts"), "utf8");
  const body = /export type V9Surfaces = \{([\s\S]*?)\n\};/.exec(src);
  expect(body, "V9Surfaces is no longer a plain type literal — update this guard").toBeTruthy();
  const fields = [...body![1]!.matchAll(/^\s{2}(\w+)\??:/gm)].map((m) => m[1]!);
  expect(fields.length, "V9Surfaces parsed as empty").toBeGreaterThanOrEqual(3);
  return fields;
}

describe("every v9 surface reaches every renderer", () => {
  it("each builder reads each field of the bundle", () => {
    const fields = surfaceFields();
    const declared = new Set(DECLARED.map(([b, f]) => `${b}:${f}`));
    const used = new Set<string>();
    const missing: string[] = [];

    for (const builder of BUILDERS) {
      const src = readFileSync(join(SRC, builder), "utf8");
      for (const field of fields) {
        // `v9.field` or `v9?.field` — the only two ways a builder gets at it.
        if (new RegExp(`\\bv9\\??\\.${field}\\b`).test(src)) continue;
        const key = `${builder}:${field}`;
        if (declared.has(key)) {
          used.add(key);
          continue;
        }
        missing.push(key);
      }
    }

    expect(missing, "a v9 surface is declared on the bundle but dropped by a renderer").toEqual([]);
    // A declared exception matching nothing is a stale entry, not a pass.
    expect(
      [...declared].filter((k) => !used.has(k)),
      "stale DECLARED entry",
    ).toEqual([]);
  });

  it("detects a renderer that drops a field", () => {
    // The guard is only worth its runtime if it fails on the real shape of the
    // defect: a field present on the type and referenced by no builder.
    const fields = [...surfaceFields(), "notReadByAnyone"];
    const missing = BUILDERS.filter(
      (b) => !/\bv9\??\.notReadByAnyone\b/.test(readFileSync(join(SRC, b), "utf8")),
    );
    expect(fields).toContain("notReadByAnyone");
    expect(missing).toEqual([...BUILDERS]);
  });
});
