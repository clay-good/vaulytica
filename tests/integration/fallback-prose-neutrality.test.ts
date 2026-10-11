/**
 * A finding that runs on an UNRECOGNIZED document must not assert what the
 * document is.
 *
 * When no family matches, the engine says so in as many words:
 *
 *   > No known document type matched this document … The findings below may
 *   > be irrelevant or misleading **for a document that is not a contract**.
 *
 * And then it printed, about a bread recipe:
 *
 *   > [CRITICAL] STRUCT-003 — The end of **this Agreement** does not contain
 *   > the standard signature pattern.
 *   > [WARNING] STRUCT-001 — Vaulytica could not identify the parties to
 *   > **this Agreement**.
 *
 * The notice says "this may not be a contract" and the findings call it an
 * Agreement, three lines apart — the same self-contradiction as the posture row
 * that disagreed with its own guidance (9.697.0) and the portfolio rollup that
 * disagreed with its own legend (9.704.0). "This document" is true whether or
 * not it is a contract, and loses nothing when it is one.
 *
 * 🚨 **No specimen could have caught this.** The corpus is 327 recognized
 * documents, so nothing in it routes to the fallback — the defect lives on
 * exactly the input the corpus cannot contain. The guard is therefore static,
 * over the packs the fallback runs.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { sourceFiles } from "./_recognizer-sources.js";
import { LAUNCH_RULES } from "../../src/engine/index.js";

/**
 * The packs the generic fallback has always run whole.
 */
const FALLBACK_PACKS = [
  "src/engine/rules/structural",
  "src/engine/rules/financial",
  "src/engine/rules/temporal",
  "src/engine/rules/dark-patterns",
] as const;

/**
 * …and every other rule it runs. The notice used to name those four packs and
 * this guard read only them, while the fallback also ran choice-of-law, IP,
 * obligation, personnel and risk rules nobody had checked. The set is derived:
 * each launch rule the fallback playbook does not skip, by its own file, plus
 * the notes written for the fallback alone.
 */
const FALLBACK_SKIPS = new Set(
  Object.entries(
    (
      JSON.parse(
        readFileSync(join(process.cwd(), "playbooks", "generic-fallback.json"), "utf8"),
      ) as { rule_overrides: Record<string, { skip?: boolean }> }
    ).rule_overrides,
  )
    .filter(([, v]) => v.skip)
    .map(([id]) => id),
);
const RULE_FILES = sourceFiles(join(process.cwd(), "src", "engine", "rules"));
const FALLBACK_RULE_FILES: string[] = [
  ...LAUNCH_RULES.filter((r) => !FALLBACK_SKIPS.has(r.id)).flatMap((r) =>
    RULE_FILES.filter((f) => f.endsWith(`/${r.id}.ts`)),
  ),
  join(process.cwd(), "src", "engine", "rules", "v7", "fallback.ts"),
];

/** The finding fields a reader sees. */
const READER_FIELDS = /(?:title|description|explanation|recommendation|missing_description):/;

/** Prose that tells the reader what the document IS. */
const ASSERTS_A_TYPE = /\b(?:this|the)\s+(?:Agreement|Contract)\b/;

describe("a fallback finding does not assert what the document is", () => {
  it("no reader-facing string in a fallback pack calls the document an Agreement", () => {
    const offenders: string[] = [];
    let scanned = 0;

    const files = new Map<string, string>();
    for (const pack of FALLBACK_PACKS) {
      for (const file of sourceFiles(join(process.cwd(), pack))) files.set(file, pack);
    }
    for (const file of FALLBACK_RULE_FILES) if (!files.has(file)) files.set(file, "fallback rule");
    // The derivation must find the rules outside the four packs, or it adds nothing.
    expect([...files.values()].filter((v) => v === "fallback rule").length).toBeGreaterThan(5);

    {
      for (const [file, pack] of files) {
        const src = readFileSync(file, "utf8");
        const lines = src.split("\n");
        for (let i = 0; i < lines.length; i += 1) {
          const line = lines[i]!;
          if (/^\s*(?:\/\/|\*|\/\*)/.test(line)) continue;
          // The field name and its value are often on separate lines.
          const region = `${lines[i - 1] ?? ""}\n${line}`;
          if (!READER_FIELDS.test(region)) continue;
          for (const lit of line.match(/"(?:[^"\\\n]|\\.)*"/g) ?? []) {
            scanned += 1;
            if (ASSERTS_A_TYPE.test(lit)) {
              offenders.push(`${pack}/${file.split("/").pop()!}: ${lit.slice(0, 90)}`);
            }
          }
        }
      }
    }

    // Anti-vacuity: a walk that read nothing finds no offender either.
    expect(scanned, "no reader-facing strings were examined").toBeGreaterThan(50);
    expect(
      offenders,
      "this fires on a document no family matched — say 'this document', not 'this Agreement'",
    ).toEqual([]);
  });
});
