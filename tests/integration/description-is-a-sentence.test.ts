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
      /description:\s*[A-Za-z_$][\w$]*\.match\[0\]/.test(
        readFileSync(f, "utf8").replace(/\/\/.*$|\/\*[\s\S]*?\*\//gm, ""),
      ),
    );
    expect(offenders.map((f) => f.slice(process.cwd().length + 1))).toEqual([]);
  });
});
