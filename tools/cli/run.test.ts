import { afterAll, describe, expect, it } from "vitest";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, basename } from "node:path";
import { splitGlob, globToRegExp, resolveInputs } from "./run.js";

describe("splitGlob (CLI glob resolution)", () => {
  it("resolves a bare glob against the current directory", () => {
    // Regression: the previous slice(0, lastIndexOf('/')) produced "*.doc"
    // for a bare "*.docx", so readdir failed and nothing matched.
    expect(splitGlob("*.docx")).toEqual({ dir: ".", pattern: "*.docx" });
  });

  it("splits a dir/pattern glob at the last slash", () => {
    expect(splitGlob("contracts/*.docx")).toEqual({ dir: "contracts", pattern: "*.docx" });
    expect(splitGlob("./deal-room/*.pdf")).toEqual({ dir: "./deal-room", pattern: "*.pdf" });
    expect(splitGlob("a/b/c/*.txt")).toEqual({ dir: "a/b/c", pattern: "*.txt" });
  });

  it("keeps an absolute root directory", () => {
    expect(splitGlob("/*.docx")).toEqual({ dir: "/", pattern: "*.docx" });
  });
});

describe("globToRegExp", () => {
  it("matches files by extension and treats dots literally", () => {
    const re = globToRegExp("*.docx");
    expect(re.test("nda.docx")).toBe(true);
    expect(re.test("nda.docxx")).toBe(false);
    expect(re.test("ndaXdocx")).toBe(false); // the dot is literal, not 'any char'
  });

  it("anchors so a prefix/suffix does not partial-match", () => {
    const re = globToRegExp("contract-*.pdf");
    expect(re.test("contract-2026.pdf")).toBe(true);
    expect(re.test("my-contract-2026.pdf")).toBe(false);
    expect(re.test("contract-2026.pdf.bak")).toBe(false);
  });
});

describe("resolveInputs (directory walk ordering)", () => {
  const dirs: string[] = [];
  afterAll(async () => {
    for (const d of dirs) await rm(d, { recursive: true, force: true });
  });

  it("orders directory files by code unit, not host locale", async () => {
    // Regression: `walkDir` sorted with bare `localeCompare`, which is
    // locale/ICU-dependent — a directory analysis could ingest files (and so
    // print its per-file report lines and evaluate `--fail-on`) in a different
    // order on a host with a different LANG. Code-unit ordering is stable
    // everywhere: uppercase (`A`=65) sorts before lowercase (`a`=97), which
    // `localeCompare` would not do.
    const dir = await mkdtemp(join(tmpdir(), "vaulytica-walk-"));
    dirs.push(dir);
    // Distinct names (no case-only collisions — those collapse on a
    // case-insensitive filesystem) chosen so code-unit and locale orderings
    // *differ*: code-unit puts uppercase (`B`=66, `C`=67) before lowercase
    // (`a`=97, `d`=100), whereas an `"en"` `localeCompare` would interleave
    // them as apple < Banana < Cherry < date.
    const names = ["date.txt", "Banana.txt", "apple.txt", "Cherry.txt", "1.md", ".hidden.txt"];
    for (const n of names) await writeFile(join(dir, n), "x");
    await mkdir(join(dir, "sub"));
    await writeFile(join(dir, "sub", "z.txt"), "x");

    const got = (await resolveInputs(dir)).map((p) => p.slice(dir.length + 1));
    // Dotfiles skipped; nested files included; everything code-unit ordered
    // (digits < uppercase < lowercase), top-level before `sub/` content.
    expect(got).toEqual([
      "1.md",
      "Banana.txt",
      "Cherry.txt",
      "apple.txt",
      "date.txt",
      join("sub", "z.txt"),
    ]);
  });

  it("a single file resolves to itself", async () => {
    const dir = await mkdtemp(join(tmpdir(), "vaulytica-walk-"));
    dirs.push(dir);
    const file = join(dir, "only.txt");
    await writeFile(file, "x");
    expect((await resolveInputs(file)).map((p) => basename(p))).toEqual(["only.txt"]);
  });
});
