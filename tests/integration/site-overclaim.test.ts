/**
 * Site overclaim guard (spec-v53 §3).
 *
 * The tool has no measured recall: the accuracy scoreboard is empty and no
 * rule is attorney-signed. So the site may claim determinism — the same
 * checks run every time, and the report lists them — and may not claim
 * completeness. Six sentences did, across the homepage and one landing page.
 * This holds the rewrite: a banned phrase in a site source fails here.
 *
 * "The same answer every time" is the determinism claim and stays legal.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const BANNED: Array<{ what: string; pattern: RegExp }> = [
  { what: '"exhaustive"', pattern: /\bexhaustive(?:ly)?\b/i },
  {
    what: '"catches that failure mode every time"',
    pattern: /catch(?:es)?\s+(?:that|this|every)\s+failure\s+mode/i,
  },
  { what: '"never skip"', pattern: /never\s+skips?\b/i },
  {
    what: '"nothing on the checklist was missed"',
    pattern: /nothing\s+(?:on\s+the\s+checklist\s+)?(?:was|is|gets)\s+missed/i,
  },
  { what: '"prove you didn\'t"', pattern: /prove\s+you\s+did(?:n['’]t|\s+not)/i },
];

/** Hand-written site sources: the pages and the modules that generate pages. */
function siteSources(): string[] {
  const out: string[] = [];
  for (const dir of ["site", join("tools", "site")]) {
    for (const entry of readdirSync(dir, { recursive: true, encoding: "utf8" })) {
      if (/\.(?:html|ts|txt|md)$/.test(entry) && !/\.test\.ts$/.test(entry)) {
        out.push(join(dir, entry));
      }
    }
  }
  return out;
}

describe("site overclaim guard", () => {
  const sources = siteSources();

  it("walks the homepage and the landing-page generator", () => {
    expect(sources).toContain(join("site", "index.html"));
    expect(sources).toContain(join("tools", "site", "seo-pages.ts"));
  });

  it("no site source claims completeness", () => {
    const hits: string[] = [];
    for (const file of sources) {
      const text = readFileSync(file, "utf8");
      for (const { what, pattern } of BANNED) {
        if (pattern.test(text)) hits.push(`${file}: ${what}`);
      }
    }
    expect(hits).toEqual([]);
  });

  it("each pattern catches the sentence it was written for", () => {
    const old = [
      "Vaulytica does the work those tools cannot: exhaustive, identical, cited checking.",
      "A deterministic checklist runner catches that failure mode every time.",
      "it will never skip a check or invent a clause",
      "a deterministic checker makes sure nothing on the checklist was missed",
      "Stop hoping you didn't miss anything. Prove you didn't.",
    ];
    BANNED.forEach(({ pattern }, i) => expect(pattern.test(old[i]!)).toBe(true));
  });

  it("leaves the determinism claim alone", () => {
    const fine = "A contract reviewer that gives the same answer every time.";
    for (const { pattern } of BANNED) expect(pattern.test(fine)).toBe(false);
  });
});
