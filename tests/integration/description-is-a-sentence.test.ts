/**
 * A finding's description is a sentence the document contains, not a regex's
 * span.
 *
 * Forty rules printed `hit.match[0]` under the finding's title, so the line a
 * reader sees first began and ended wherever the pattern did — "On
 * termination, the Supplier shall return or destroy the Customer's
 * confidential" — and every surface (DOCX, HTML, CSV, SARIF) carried the cut.
 * They now use `matchedSentence`, and this sweep keeps the class closed: a
 * new rule that reaches for the raw match fails here.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = join(process.cwd(), "src", "engine", "rules");

function ruleFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) return ruleFiles(p);
    return name.endsWith(".ts") && !name.endsWith(".test.ts") ? [p] : [];
  });
}

describe("a finding's description is a sentence", () => {
  it("no rule prints a regex match as its description", () => {
    const files = ruleFiles(ROOT);
    expect(files.length).toBeGreaterThan(100);
    const offenders = files.filter((f) =>
      // `hit.match[0]`, and the bare exec result `altHit[0]` (RISK-017's
      // fallback printed its 200-character regex span and was missed by the
      // first version of this pattern).
      /description:\s*[A-Za-z_$][\w$]*(?:\.match)?\[0\]/.test(
        readFileSync(f, "utf8").replace(/\/\/.*$|\/\*[\s\S]*?\*\//gm, ""),
      ),
    );
    expect(offenders.map((f) => f.slice(process.cwd().length + 1))).toEqual([]);
  });

  // The EXCERPT had the same defect in another form: 43 sites built it as
  // `excerptWindow(text, match.index, 30, 280)`, a character window that began
  // thirty characters before the match — mid-sentence — and ran 280 past it,
  // into whatever followed. A clean sponsorship agreement's OBLI-008 quoted
  // "gives prompt notice and uses reasonable efforts to resume performance.
  // Section 5.3 governs any refund owed…". They now quote the sentence.
  it("no rule builds its excerpt from a character window", () => {
    const offenders = ruleFiles(ROOT).filter((f) =>
      /excerpt:\s*excerptWindow\(/.test(
        readFileSync(f, "utf8").replace(/\/\/.*$|\/\*[\s\S]*?\*\//gm, ""),
      ),
    );
    expect(offenders.map((f) => f.slice(process.cwd().length + 1))).toEqual([]);
  });
});
