import { describe, expect, it } from "vitest";
import { buildAliasMap, loadTaxonomy, reconcileCategory, slugify } from "./taxonomy.js";

describe("taxonomy", () => {
  it("loads the committed taxonomy and contains every spec §13 canonical category", async () => {
    const t = await loadTaxonomy();
    const canon = t.categories.map((c) => c.canonical);
    for (const id of [
      "governing-law",
      "indemnification",
      "limitation-of-liability",
      "confidentiality-obligation",
      "term",
      "termination-for-cause",
      "termination-for-convenience",
      "force-majeure",
      "assignment",
      "entire-agreement",
      "severability",
      "waiver",
      "notices",
      "counterparts",
    ]) {
      expect(canon, id).toContain(id);
    }
    // ~80 categories per spec — at least 55 in the launch starter.
    expect(canon.length).toBeGreaterThan(50);
  });

  it("buildAliasMap collapses CUAD/LEDGAR labels to canonical ids (via slugified keys)", async () => {
    const t = await loadTaxonomy();
    const m = buildAliasMap(t);
    // Aliases are stored slugified; downstream consumers go through
    // `reconcileCategory` so this lookup mirrors that.
    expect(m.get("governing-law")).toBe("governing-law");
    expect(m.get("non-disclosure")).toBe("confidentiality-obligation");
    expect(m.get("liability-limitation")).toBe("limitation-of-liability");
  });

  it("reconcileCategory returns the canonical for known aliases and a slug for unknown", async () => {
    const t = await loadTaxonomy();
    const m = buildAliasMap(t);
    expect(reconcileCategory("Governing Law", m)).toBe("governing-law");
    expect(reconcileCategory("Mystery Clause Type", m)).toBe("mystery-clause-type");
  });

  it("slugify normalizes whitespace/punctuation", () => {
    expect(slugify("Force Majeure & Acts of God!")).toBe("force-majeure-acts-of-god");
  });
});
