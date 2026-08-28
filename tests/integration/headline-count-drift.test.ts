/**
 * The two numbers on the front of the product.
 *
 * "1,808 checks across 265 document types" is the headline claim, and it
 * appears on the README badge line, in the README's own architecture diagram,
 * and four times in the landing page's metadata — the description, the social
 * card, the JSON-LD, and a layout comment. The per-wave rule counts already
 * have a drift guard; the TOTAL, which is the number a reader actually sees,
 * did not, and neither did the document-type count.
 *
 * A wave that adds rules and forgets one of these surfaces ships a product
 * that misstates its own size on its front page.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { LAUNCH_RULES } from "../../src/engine/rules/index.js";
import { V3_RULES } from "../../src/engine/rules/v3/index.js";
import { V4_RULES } from "../../src/engine/rules/v4/index.js";
import { V5_RULES } from "../../src/engine/rules/v5/index.js";
import { V6_RULES } from "../../src/engine/rules/v6/index.js";
import { LAUNCH_PLAYBOOK_IDS } from "../../src/playbooks/registry.js";

const TOTAL_RULES =
  LAUNCH_RULES.length + V3_RULES.length + V4_RULES.length + V5_RULES.length + V6_RULES.length;

const EXTENDED = JSON.parse(
  readFileSync(join(process.cwd(), "playbooks", "extended.json"), "utf8"),
) as unknown[];
const TOTAL_PLAYBOOKS = EXTENDED.length + LAUNCH_PLAYBOOK_IDS.length;

const grouped = (n: number) => n.toLocaleString("en-US");

const README = readFileSync(join(process.cwd(), "README.md"), "utf8");
const SITE = readFileSync(join(process.cwd(), "site", "index.html"), "utf8");

describe("the headline rule and document-type counts", () => {
  it("the README badge names the live rule total", () => {
    expect(
      README,
      `README badge is stale — the catalog holds ${grouped(TOTAL_RULES)} rules`,
    ).toContain(`\`${grouped(TOTAL_RULES)} deterministic rules\``);
  });

  it("the README architecture diagram names both live totals", () => {
    expect(README).toContain(`${grouped(TOTAL_RULES)} rules · ${TOTAL_PLAYBOOKS} playbooks`);
  });

  it("the landing page names both live totals wherever it states them", () => {
    // Every occurrence, not the first — the claim is repeated in the meta
    // description, the social card, and the JSON-LD, and a wave that updates
    // one and not the others is the drift this guards.
    const claims = SITE.match(/[\d,]+ checks across \d+ document types/g) ?? [];
    expect(claims.length, "the landing page no longer states the claim").toBeGreaterThan(1);
    for (const claim of claims) {
      expect(claim).toBe(`${grouped(TOTAL_RULES)} checks across ${TOTAL_PLAYBOOKS} document types`);
    }
  });

  it("the landing page's document-type index is sized for the live catalog", () => {
    const sized = SITE.match(/so (\d+) entries read as a/);
    expect(sized, "the document-type index comment no longer states a count").toBeTruthy();
    expect(Number(sized![1])).toBe(TOTAL_PLAYBOOKS);
  });
});
