/**
 * Landing-page document-type drift-guard.
 *
 * The front page names every document type Vaulytica has a playbook for, and
 * states the count in three places. Both claims are hand-maintained markup, so
 * a playbook added to `playbooks/` silently ages the page — which is exactly
 * what had already happened once: the FAQ still advertised "twelve playbooks"
 * against 145 shipped. A stale count on a page whose whole argument is
 * "we tell you precisely what we checked" is the one kind of marketing claim
 * this product exists to break.
 *
 * These assertions read the playbooks off disk, so adding one fails here until
 * the page lists it.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { EMPTY_STATE_COPY } from "../../src/ui/v3/copy.js";

const root = process.cwd();
const landing = readFileSync(join(root, "site", "index.html"), "utf8");

/** Every shipped playbook's display name, from the standalone files and the extended bundle. */
function playbookNames(): string[] {
  const dir = join(root, "playbooks");
  const byId = new Map<string, string>();
  for (const file of readdirSync(dir)) {
    if (!file.endsWith(".json")) continue;
    const parsed: unknown = JSON.parse(readFileSync(join(dir, file), "utf8"));
    const entries = Array.isArray(parsed) ? parsed : [parsed];
    for (const p of entries as Array<{ id?: string; name?: string }>) {
      if (p.id && p.name) byId.set(p.id, p.name);
    }
  }
  return [...byId.values()];
}

/**
 * HTML-escape the way the page does, so a name carrying an ampersand
 * ("M&A Escrow Agreement") is looked up in its escaped form rather than
 * reported as a spurious omission.
 */
function escapeHtml(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

describe("landing page document-type index", () => {
  it("lists every shipped playbook by name", () => {
    const missing = playbookNames().filter((n) => !landing.includes(escapeHtml(n)));
    expect(missing, `document types missing from site/index.html: ${missing.join(", ")}`).toEqual(
      [],
    );
  });

  it("names the v3 §63 families the drop-zone caption used to carry", () => {
    // The empty-state caption named BAAs, DPAs and SCCs because that was the
    // only place the page said what it understood. The index says it in full
    // now, so the caption stopped repeating a partial list — this keeps the
    // §63 guarantee attached to the place that actually satisfies it.
    for (const family of [
      "Business Associate Agreement (HIPAA)",
      "DPA — Controller to Processor (EU/UK)",
      "EU Standard Contractual Clauses — Module 2 (Controller to Processor)",
    ]) {
      expect(landing, `${family} missing from the document-type index`).toContain(family);
    }
  });

  it("states the document-type count, and states the same one everywhere", () => {
    const quoted = [...landing.matchAll(/data-doc-types>([\d,]+)</g)].map((m) =>
      Number(m[1]!.replace(/,/g, "")),
    );
    expect(quoted.length, "no data-doc-types count on the page").toBeGreaterThan(0);
    for (const n of quoted) expect(n).toBe(playbookNames().length);
  });
});

describe("landing page drop-zone copy", () => {
  /**
   * The static HTML paints the idle drop zone, and `renderEmpty()` repaints it
   * from `EMPTY_STATE_COPY` the moment the app boots. When the two disagree,
   * the page visibly flips from one wording to the other on load — and the
   * markup a crawler reads is not the copy a user sees.
   */
  it("the static drop-zone text matches the copy the app repaints it with", () => {
    expect(landing).toContain(`>${EMPTY_STATE_COPY.headline}<`);
    expect(landing).toContain(`>${EMPTY_STATE_COPY.sub}<`);
  });
});
