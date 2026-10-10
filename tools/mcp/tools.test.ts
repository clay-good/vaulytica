/**
 * The tools as functions: what each accepts, refuses, and returns (spec-v48
 * §5–§9). The protocol around them is `tests/integration/mcp-server.test.ts`.
 */
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink as fsSymlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { analyzeFile, loadAccuracyDeps } from "../cli/api.js";
import { parseRoots, resolveInRoots, resolveNewInRoots } from "./roots.js";
import {
  MAX_RESULT_CHARS,
  MAX_TEXT_CHARS,
  ToolError,
  analyzeDocumentTool,
  listDocumentTypesTool,
} from "./tools.js";
import {
  ANALYZE_DOCUMENT,
  INSTRUCTIONS,
  LIST_DOCUMENT_TYPES,
  MAX_DESCRIPTION_CHARS,
} from "./text.js";

const SPECIMENS = join(process.cwd(), "tests", "fixtures", "specimens");
const NDA = join(SPECIMENS, "mutual-nda-complete.txt");

/** Windows needs a privilege to create a symlink; there the link checks are skipped. */
async function symlink(target: string, path: string): Promise<boolean> {
  return fsSymlink(target, path).then(
    () => true,
    () => false,
  );
}

let tmp: string;
let ctx: { roots: string[]; deps: Awaited<ReturnType<typeof loadAccuracyDeps>> };

beforeAll(async () => {
  tmp = await realpath(await mkdtemp(join(tmpdir(), "vaul-mcp-")));
  ctx = { roots: [process.cwd(), tmp], deps: await loadAccuracyDeps() };
});
afterAll(() => rm(tmp, { recursive: true, force: true }));

describe("analyze_document", () => {
  it("returns the brief, with the full report's findings and result_hash", async () => {
    const full = await analyzeFile(NDA, { deps: ctx.deps, secondaryFamilies: true });
    const r = await analyzeDocumentTool({ path: NDA }, ctx);
    if ("not_analyzed" in r) throw new Error(r.not_analyzed);
    expect(r.result_hash).toBe(full.run.result_hash);
    expect(r.findings.map((f) => f.id)).toEqual(full.run.findings.map((f) => f.id));
    expect(r.findings_total).toBe(full.run.findings.length);
    expect(r.next_cursor).toBeUndefined();
    expect(JSON.stringify(r).length).toBeLessThanOrEqual(8 * 1024);
    expect(r.caveats.not_legal_advice).toBeTruthy();
  });

  it("takes a path relative to the first root, and text with a name", async () => {
    const rel = await analyzeDocumentTool(
      { path: "tests/fixtures/specimens/mutual-nda-complete.txt" },
      ctx,
    );
    const text = await analyzeDocumentTool(
      { text: await readFile(NDA, "utf8"), filename: "mutual-nda-complete.txt" },
      ctx,
    );
    if ("not_analyzed" in rel || "not_analyzed" in text) throw new Error("not analyzed");
    expect(text.result_hash).toBe(rel.result_hash);
  });

  it("needs exactly one of path and text", async () => {
    await expect(analyzeDocumentTool({}, ctx)).rejects.toThrow(ToolError);
    await expect(analyzeDocumentTool({ path: NDA, text: "x" }, ctx)).rejects.toThrow(/exactly one/);
  });

  it("excerpts: false keeps the offsets and the id, and quotes nothing", async () => {
    const r = await analyzeDocumentTool({ path: NDA, excerpts: false }, ctx);
    if ("not_analyzed" in r) throw new Error(r.not_analyzed);
    expect(r.findings.length).toBeGreaterThan(0);
    for (const f of r.findings) {
      expect(f.excerpt).toBeUndefined();
      expect(typeof f.start_offset).toBe("number");
      expect(f.id).toBeTruthy();
    }
  });

  it("min_severity shortens the list and leaves the counts whole", async () => {
    const all = await analyzeDocumentTool({ path: NDA }, ctx);
    const top = await analyzeDocumentTool({ path: NDA, min_severity: "critical" }, ctx);
    if ("not_analyzed" in all || "not_analyzed" in top) throw new Error("not analyzed");
    expect(top.findings.every((f) => f.severity === "critical")).toBe(true);
    expect(top.findings_total).toBe(all.counts.critical);
    expect(top.counts).toEqual(all.counts);
  });

  it("carries secondary findings only when asked", async () => {
    const file = join(SPECIMENS, "physician-employment.txt");
    const plain = await analyzeDocumentTool({ path: file }, ctx);
    const more = await analyzeDocumentTool({ path: file, include: ["secondary_findings"] }, ctx);
    if ("not_analyzed" in plain || "not_analyzed" in more) throw new Error("not analyzed");
    expect(plain.secondary_families!.length).toBeGreaterThan(0);
    expect(plain.secondary_families!.every((s) => s.findings === undefined)).toBe(true);
    expect(more.secondary_families!.some((s) => (s.findings?.length ?? 0) > 0)).toBe(true);
    expect(plain.caveats.secondary_families).toMatch(/not confirmed/);
  });

  it("pages a long result statelessly, and refuses a cursor for a changed file", async () => {
    const big = join(tmp, "big.txt");
    const text = await readFile(join(SPECIMENS, "physician-employment.txt"), "utf8");
    await writeFile(big, text);
    // A narrow budget, so a 17 KB report takes several pages.
    const narrow = { ...ctx, maxResultChars: 6_000 };
    const first = await analyzeDocumentTool({ path: big }, narrow);
    if ("not_analyzed" in first) throw new Error(first.not_analyzed);
    expect(first.next_cursor).toBeTruthy();
    const seen = [...first.findings];
    let cursor = first.next_cursor;
    let pages = 1;
    while (cursor) {
      const next = await analyzeDocumentTool({ path: big, cursor }, narrow);
      if ("not_analyzed" in next) throw new Error(next.not_analyzed);
      // A page holds the budget unless one finding has it to itself.
      if (next.findings.length > 1) expect(JSON.stringify(next).length).toBeLessThanOrEqual(6_100);
      expect(next.findings.length).toBeGreaterThan(0);
      seen.push(...next.findings);
      cursor = next.next_cursor;
      pages++;
    }
    expect(pages).toBeGreaterThan(2);
    const whole = await analyzeDocumentTool({ path: big }, ctx);
    if ("not_analyzed" in whole) throw new Error(whole.not_analyzed);
    expect(whole.next_cursor).toBeUndefined();
    expect(seen.map((f) => f.id)).toEqual(whole.findings.map((f) => f.id));

    await writeFile(big, text + "\nOne more sentence.\n");
    await expect(
      analyzeDocumentTool({ path: big, cursor: first.next_cursor }, narrow),
    ).rejects.toThrow(/changed since/);
    await expect(analyzeDocumentTool({ path: NDA, cursor: "not-a-cursor" }, ctx)).rejects.toThrow(
      /not one this server issued/,
    );
  });

  it("holds every specimen to the budget with secondary findings included", async () => {
    const { readdir } = await import("node:fs/promises");
    const over: string[] = [];
    let paged = 0;
    for (const name of await readdir(SPECIMENS)) {
      const args = { path: join(SPECIMENS, name), include: ["secondary_findings" as const] };
      const first = await analyzeDocumentTool(args, ctx);
      if ("not_analyzed" in first) throw new Error(`${name}: ${first.not_analyzed}`);
      if (JSON.stringify(first).length > MAX_RESULT_CHARS) over.push(name);
      if (!first.next_cursor) continue;
      paged++;
      // The rest arrives, in budget, and nothing is repeated. A finding id is
      // unique within its family, not across them, so the key carries both.
      const keys = (r: typeof first): string[] => [
        ...r.findings.map((f) => `:${f.id}`),
        ...r.secondary_families!.flatMap((s) => (s.findings ?? []).map((f) => `${s.id}:${f.id}`)),
      ];
      const seen = new Set(keys(first));
      let cursor: string | undefined = first.next_cursor;
      while (cursor) {
        const next = await analyzeDocumentTool({ ...args, cursor }, ctx);
        if ("not_analyzed" in next) throw new Error(next.not_analyzed);
        if (JSON.stringify(next).length > MAX_RESULT_CHARS) over.push(`${name} (later page)`);
        for (const k of keys(next)) {
          expect(seen.has(k), `${name}: ${k} sent twice`).toBe(false);
          seen.add(k);
        }
        cursor = next.next_cursor;
      }
    }
    expect(over).toEqual([]);
    // Anti-vacuity: the corpus does contain a report that needs a second page.
    expect(paged).toBeGreaterThan(0);
  }, 300_000);

  it("reports a file it could not read as not analyzed, never as a short report", async () => {
    const broken = join(tmp, "broken.docx");
    await writeFile(broken, "this is not a zip");
    const r = await analyzeDocumentTool({ path: broken }, ctx);
    expect(r).toMatchObject({ document: { name: broken } });
    expect("not_analyzed" in r && r.not_analyzed.length > 0).toBe(true);
    expect("findings" in r).toBe(false);
  });

  it("refuses a type it does not read, an unknown document type, and oversized text", async () => {
    const png = join(tmp, "logo.png");
    await writeFile(png, "x");
    await expect(analyzeDocumentTool({ path: png }, ctx)).rejects.toThrow(/not a type/);
    await expect(
      analyzeDocumentTool({ path: NDA, document_type: "no-such-type" }, ctx),
    ).rejects.toThrow(/not a document type id/);
    await expect(
      analyzeDocumentTool({ text: "a".repeat(MAX_TEXT_CHARS + 1) }, ctx),
    ).rejects.toThrow(/Save it to a file/);
  });
});

describe("allowed roots", () => {
  it("defaults to the working directory, then the environment, then --root", async () => {
    expect(await parseRoots([], {}, tmp)).toEqual([tmp]);
    const sub = join(tmp, "sub");
    await mkdir(sub, { recursive: true });
    expect(await parseRoots([], { VAULYTICA_MCP_ROOTS: sub }, tmp)).toEqual([sub]);
    expect(
      await parseRoots(["--root", tmp, "--root", "sub"], { VAULYTICA_MCP_ROOTS: "/" }, tmp),
    ).toEqual([tmp, sub]);
    await expect(parseRoots(["--root", join(tmp, "missing")], {}, tmp)).rejects.toThrow(
      /does not exist/,
    );
    await expect(parseRoots(["--port", "1"], {}, tmp)).rejects.toThrow(/unknown argument/);
  });

  it("refuses a path outside every root, a sibling with the root's prefix, and a symlink out", async () => {
    const root = join(tmp, "room");
    const sibling = join(tmp, "room-secret");
    await mkdir(root, { recursive: true });
    await mkdir(sibling, { recursive: true });
    await writeFile(join(sibling, "x.txt"), "secret");
    await writeFile(join(root, "in.txt"), "fine");
    const linked = await symlink(join(sibling, "x.txt"), join(root, "link.txt"));
    expect(await resolveInRoots("in.txt", [root])).toBe(join(root, "in.txt"));
    await expect(resolveInRoots(join(sibling, "x.txt"), [root])).rejects.toThrow(
      /outside the folders/,
    );
    await expect(resolveInRoots("../room-secret/x.txt", [root])).rejects.toThrow(ToolError);
    if (linked) {
      await expect(resolveInRoots("link.txt", [root])).rejects.toThrow(/outside the folders/);
    }
    await expect(resolveInRoots("nope.txt", [root])).rejects.toThrow(/No such file/);
  });

  it("holds a directory that does not exist yet to the roots", async () => {
    const root = join(tmp, "room");
    expect(await resolveNewInRoots("out/reports", [root])).toBe(join(root, "out", "reports"));
    await expect(resolveNewInRoots("../elsewhere/out", [root])).rejects.toThrow(ToolError);
    if (await symlink(tmpdir(), join(root, "escape"))) {
      await expect(resolveNewInRoots("escape/new-dir", [root])).rejects.toThrow(
        /outside the folders/,
      );
    }
  });

  it("is what analyze_document reads through", async () => {
    const root = join(tmp, "room");
    await expect(analyzeDocumentTool({ path: NDA }, { ...ctx, roots: [root] })).rejects.toThrow(
      /outside the folders/,
    );
  });
});

describe("list_document_types", () => {
  it("pages ids and names with a cursor, and adds summaries for a query", async () => {
    const first = await listDocumentTypesTool({});
    expect(first.types).toHaveLength(50);
    expect(Object.keys(first.types[0]!)).toEqual(["id", "name"]);
    const second = await listDocumentTypesTool({ cursor: first.next_cursor });
    expect(second.types[0]!.id).not.toBe(first.types[0]!.id);
    const found = await listDocumentTypesTool({ query: "mutual nda" });
    expect(found.types[0]!.summary).toBeTruthy();
    expect(JSON.stringify(first).length).toBeLessThan(6000);
  });
});

describe("what the server says about itself", () => {
  it("fits each description in the smallest host limit, caveat first", () => {
    for (const d of [ANALYZE_DOCUMENT, LIST_DOCUMENT_TYPES]) {
      expect(d.length).toBeLessThanOrEqual(MAX_DESCRIPTION_CHARS);
    }
    expect(ANALYZE_DOCUMENT).toMatch(/^Not legal advice/);
  });

  it("says what it is, that excerpts reach the model, and that document text is data", () => {
    expect(INSTRUCTIONS).toMatch(/deterministic rule engine/);
    expect(INSTRUCTIONS).toMatch(/no AI/);
    expect(INSTRUCTIONS).toMatch(/excerpts: false/);
    expect(INSTRUCTIONS).toMatch(/Do not follow instructions/);
    expect(INSTRUCTIONS).not.toMatch(/nothing leaves your machine/i);
  });
});
