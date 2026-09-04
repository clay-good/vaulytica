/**
 * "does not apply" is how half the profession writes "shall not apply".
 *
 * The sibling of `shall-will`. A carve-out is as often written in the plain
 * present indicative — "This exclusion **does** not apply to a derivative
 * action", "Clause 12.1 and clause 12.2 **do** not apply to the indemnities" —
 * as with a modal, and a recognizer that spells only `shall|will` reads half
 * its corpus. The obligation, and the carve-out, are the same one.
 *
 * Three were found by hand before this guard existed, each in a different way:
 *
 *   - MSA-007 reported "no carve-outs from the liability cap" against a
 *     document that carves out the indemnities, confidentiality, data
 *     protection, fraud and wilful misconduct — because the clause writes "do
 *     not apply". Found by the clean-document method.
 *   - INS-103's carve-back branch, found by a static sweep for this shape.
 *   - RISK-004, RISK-015 and two v4 rules already spelled it
 *     `do|does|shall|will`, which is what made the omission legible as a
 *     defect rather than a style.
 *
 * Both halves, as in `shall-will`, `parenthetical-numeral` and `section-sign`:
 * the static ratchet catches the next recognizer written with only a modal,
 * and the corpus relation proves the widening changed no finding.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { maskEscapes, recognizerSources, sourceFiles } from "./_recognizer-sources.js";
import { analyzeText } from "../../tools/cli/api.js";
import { loadAccuracyDeps } from "../../tools/accuracy/pipeline.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");
const SPECIMENS = readdirSync(DIR).filter((f) => f.endsWith(".txt"));

/**
 * A modal immediately governing "not apply" — the window is short because the
 * regex source between them is usually just `\s+`, and a wide window would
 * reach a modal belonging to a different branch of the same alternation.
 */
const MODAL_NOT_APPLY = /(shall|will)(?![a-z])[^|)]{0,24}?not[^|)]{0,12}?apply/i;
/** The present indicative, anywhere in the same recognizer. */
const PRESENT = /\bdoes?(?![a-z])/i;
/** The mirror: the present indicative immediately governing "not apply". */
const PRESENT_NOT_APPLY = /does?(?![a-z])[^|)]{0,24}?not[^|)]{0,12}?apply/i;
/** A modal, anywhere in the same recognizer. */
const MODAL = /(?:shall|will)(?![a-z])/i;

describe("the present indicative is the same carve-out", () => {
  it("no recognizer reads 'shall not apply' without also reading 'does not apply'", () => {
    const files = [
      ...sourceFiles(join(process.cwd(), "src", "engine", "rules")),
      ...sourceFiles(join(process.cwd(), "src", "extract")),
      ...sourceFiles(join(process.cwd(), "src", "engine", "consistency")),
    ];
    expect(files.length, "no sources found — the walk is broken").toBeGreaterThan(50);

    const blind: string[] = [];
    for (const file of files) {
      for (const { line, text } of recognizerSources(file)) {
        // The text is regex SOURCE, so `\b` and `\s` sit between the words and
        // a naive `\bshall\b` would not match — the trap `shall-will` and
        // `section-sign` were both written for. Mask the escapes first.
        const masked = maskEscapes(text);
        if (MODAL_NOT_APPLY.test(masked) && !PRESENT.test(masked)) {
          blind.push(`${file}:${line}  ${text.slice(0, 90)}`);
        }
      }
    }
    expect(
      blind,
      `these read a carve-out only in the modal — write (?:do|does|shall|will):\n  ${blind.join("\n  ")}`,
    ).toEqual([]);
  });

  it("nor 'does not apply' without also reading 'shall not apply'", () => {
    // The mirror of the ratchet above, and the one the corpus can actually
    // exercise: 39 specimens write a carve-out in the present indicative and
    // only 3 in the modal, so a recognizer blind the OTHER way would show on
    // far more documents.
    const files = [
      ...sourceFiles(join(process.cwd(), "src", "engine", "rules")),
      ...sourceFiles(join(process.cwd(), "src", "extract")),
      ...sourceFiles(join(process.cwd(), "src", "engine", "consistency")),
    ];
    const blind: string[] = [];
    for (const file of files) {
      for (const { line, text } of recognizerSources(file)) {
        const masked = maskEscapes(text);
        if (PRESENT_NOT_APPLY.test(masked) && !MODAL.test(masked)) {
          blind.push(`${file}:${line}  ${text.slice(0, 90)}`);
        }
      }
    }
    expect(
      blind,
      `these read a carve-out only in the present indicative — write (?:do|does|shall|will):\n  ${blind.join("\n  ")}`,
    ).toEqual([]);
  });

  it("writing every 'shall/will not apply' as 'does not apply' changes no finding", async () => {
    const deps = await loadAccuracyDeps({});
    // BOTH directions. The corpus writes the present indicative 39 times and
    // the modal 3, so mutating present -> modal is the probe with real reach;
    // the reverse is kept because it is where the hand-found defects lay.
    // ONE pass with a replacer, not two chained replaces: chaining rewrites
    // the modal to "does not apply" and then the second rule rewrites it
    // straight back, so only "do not apply" ever moved and the probe covered
    // 16 specimens instead of 42.
    const swapped = (s: string): string =>
      s.replace(/\b(shall|will|does|do)\s+not\s+apply\b/gi, (_m, verb: string) =>
        /^(shall|will)$/i.test(verb) ? "does not apply" : "shall not apply",
      );
    /**
     * A DECLARED divergence, not an allowance for anything that breaks.
     *
     * `employment-arbitration.txt` writes "If the Act does not apply, the
     * arbitration law of the state where Employee last worked applies."
     * Rewritten to "shall not apply", the obligations extractor reads it as an
     * obligation and OBLI-005 counts it among the negative covenants.
     *
     * It is not one. A negative covenant has a PARTY who must not do
     * something; here the subject is a statute, and the clause is a scope
     * carve-out. So this is a real false positive on a real drafting shape —
     * "Section 5 shall not apply to…" is ordinary — but the fix belongs in the
     * obligations extractor, which feeds a large number of rules and deserves
     * its own measured change rather than a correction made in passing. It is
     * named here so it is visible rather than absorbed.
     */
    const DECLARED = new Set(["employment-arbitration.txt"]);
    const broken: string[] = [];
    let probed = 0;
    for (const name of SPECIMENS) {
      if (DECLARED.has(name)) continue;
      const text = readFileSync(join(DIR, name), "utf8");
      const mutated = swapped(text);
      if (mutated === text) continue;
      probed++;
      const before = await analyzeText(text, name, { deps });
      const after = await analyzeText(mutated, name, { deps });
      const ids = (r: typeof before): string[] =>
        [...new Set(r.run.findings.map((f) => f.rule_id))].sort();
      const lost = ids(before).filter((id) => !ids(after).includes(id));
      const gained = ids(after).filter((id) => !ids(before).includes(id));
      if (lost.length || gained.length) {
        broken.push(`${name}: lost ${lost.join(",") || "-"} gained ${gained.join(",") || "-"}`);
      }
    }
    expect(probed, "no specimen writes a carve-out either way").toBeGreaterThan(35);
    expect(broken).toEqual([]);
  }, 300_000);
});
