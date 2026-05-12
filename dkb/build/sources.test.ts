import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parseSourcesYaml, loadSourcesYaml, findSource } from "./sources.js";

describe("sources.yaml", () => {
  it("the committed YAML loads and validates", async () => {
    const file = await loadSourcesYaml();
    expect(file.sources.length).toBe(8);
    const ids = file.sources.map((s) => s.id).sort();
    expect(ids).toEqual([
      "commonpaper",
      "cuad",
      "ecfr",
      "edgar",
      "govinfo",
      "ledgar",
      "ulc",
      "uscode",
    ]);
  });

  it("every source has rate_limit_rps > 0 and a non-empty UA", async () => {
    const file = await loadSourcesYaml();
    for (const s of file.sources) {
      expect(s.rate_limit_rps, s.id).toBeGreaterThan(0);
      expect(s.user_agent.length, s.id).toBeGreaterThan(0);
    }
  });

  it("rejects malformed YAML at the schema layer", () => {
    expect(() => parseSourcesYaml("sources: not-an-array")).toThrow();
  });

  it("findSource locates by id", async () => {
    const file = await loadSourcesYaml();
    expect(findSource(file, "edgar")?.parser).toBe("edgar");
    expect(findSource(file, "missing")).toBeUndefined();
  });

  it("EDGAR User-Agent contains a contact identifier per SEC rules", () => {
    const yaml = readFileSync(join(process.cwd(), "dkb", "build", "sources.yaml"), "utf8");
    expect(yaml).toContain("Vaulytica DKB Builder");
  });
});
