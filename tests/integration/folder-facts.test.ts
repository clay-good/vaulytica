/**
 * The facts a folder page has to be able to read (spec-v52 §1, Step 322).
 *
 * Before any ranking: each ingest caveat has a code, an unmatched document
 * names the family it came closest to, every file in the folder is accounted
 * for, and no two inputs write one report. None of it moves a `result_hash` —
 * the goldens hold that — and all of it is asserted on a folder built to be
 * awkward, because the specimen corpus contains none of these files.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  analyzeFolder,
  buildBrief,
  loadAccuracyDeps,
  type FolderAnalysis,
} from "../../tools/cli/api.js";
import { NEAR_MISS_FLOOR } from "../../tools/accuracy/pipeline.js";
import { SKIPPED_HIDDEN, outputStems } from "../../tools/cli/inputs.js";
import { ingestWarningCodes } from "../../src/ingest/warning-codes.js";
import { TRIAGE_FILES, buildTriageFolder } from "../fixtures/triage.js";

const BIN = join(process.cwd(), "bin", "vaulytica.mjs");
const tmp = realpathSync.native(mkdtempSync(join(tmpdir(), "vaul-facts-")));
const room = buildTriageFolder(join(tmp, "room"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

let folder: FolderAnalysis;
beforeAll(async () => {
  folder = await analyzeFolder(room, { deps: await loadAccuracyDeps(), secondaryFamilies: true });
}, 120_000);

const doc = (name: string) => folder.documents.find((d) => d.label === join(room, name))!;

describe("a folder's facts", { timeout: 300_000 }, () => {
  it("builds every fixture the tiers need", () => {
    const all = [
      ...TRIAGE_FILES.not_read,
      ...TRIAGE_FILES.caveat,
      ...TRIAGE_FILES.unmatched,
      ...TRIAGE_FILES.matched,
      ...Object.keys(TRIAGE_FILES.duplicate_of),
      ...TRIAGE_FILES.unsupported,
      ...TRIAGE_FILES.hidden,
    ];
    for (const name of all) expect(existsSync(join(room, name)), name).toBe(true);
  });

  it("accounts for every file: read, unreadable, or skipped with the reason", () => {
    const read = folder.documents.map((d) => d.label);
    const unreadable = folder.unreadable.map((u) => u.file);
    const skipped = new Map(folder.skipped.map((s) => [s.file, s.reason]));
    expect(unreadable).toEqual([join(room, "corrupt.docx")]);
    expect(skipped.get(join(room, "logo.png"))).toMatch(/unsupported/);
    // A dotfile and a dot-folder are said, not silently dropped — and the
    // folder is one entry: it is not entered.
    expect(skipped.get(join(room, ".DS_Store"))).toBe(SKIPPED_HIDDEN);
    expect(skipped.get(join(room, ".git"))).toBe(SKIPPED_HIDDEN);
    expect([...skipped.keys()].some((f) => f.includes("config"))).toBe(false);
    const listed = (dir: string): string[] =>
      readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
        e.isDirectory() && !e.name.startsWith(".")
          ? listed(join(dir, e.name))
          : [join(dir, e.name)],
      );
    expect([...read, ...unreadable, ...skipped.keys()].sort()).toEqual(listed(room).sort());
  });

  it("codes each ingest caveat", () => {
    const codes = (name: string) => ingestWarningCodes(doc(name).result.ingest);
    expect(codes("scan.pdf")).toContain("no-text-layer");
    expect(codes("empty.txt")).toContain("empty");
    expect(codes("blank.txt")).toContain("empty");
    expect(codes("tracked.docx")).toContain("tracked-changes");
    expect(codes("french.txt")).toContain("not-english");
    // A clean text file has exactly the one code that is not a caveat.
    expect(codes("nda.txt")).toEqual(["plain-text"]);
    // …and the compact report carries the codes beside the sentences.
    const brief = buildBrief(doc("tracked.docx").result);
    expect(brief.caveats.ingest_warning_codes).toHaveLength(brief.caveats.ingest_warnings!.length);
  });

  it("names the closest family for an unmatched document, and not for a blank one", () => {
    const advisor = doc("mentor.txt").result;
    expect(advisor.playbook_id).toBe("generic-fallback");
    expect(advisor.near_miss).toEqual({ playbook_id: "employment-at-will-us", score: 0.4 });
    expect(advisor.near_miss!.score).toBeGreaterThanOrEqual(NEAR_MISS_FLOOR);
    expect(buildBrief(advisor).document.near_type).toEqual({
      id: "employment-at-will-us",
      score: 0.4,
    });
    // Unmatched with nothing close: the sentence still names a family ("Best
    // score was … at 0"), and the field does not.
    const advance = doc("boarding.txt").result;
    expect(advance.playbook_id).toBe("generic-fallback");
    expect(advance.run.playbook_match_reasoning).toMatch(/Best score was \S+ at 0,/);
    expect(advance.near_miss).toBeUndefined();
    // A blank file's best score is zero; the family beside a zero is arbitrary.
    expect(doc("empty.txt").result.near_miss).toBeUndefined();
    expect(doc("blank.txt").result.near_miss).toBeUndefined();
    // A matched document has no near miss: it has a match.
    expect(doc("nda.txt").result.near_miss).toBeUndefined();
  });

  it("writes one report per input, mirroring the folder, and reports what it wrote", () => {
    const out = join(tmp, "out");
    const r = spawnSync(
      process.execPath,
      [BIN, "analyze", room, "--format", "json", "--out", out],
      {
        encoding: "utf8",
        timeout: 240_000,
      },
    );
    // The corrupt file fails the run, as it always has; everything else is written.
    expect(r.status).toBe(1);
    const written = (dir: string): string[] =>
      readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
        e.isDirectory() ? written(join(dir, e.name)).map((f) => join(e.name, f)) : [e.name],
      );
    const files = written(out).sort();
    expect(files).toEqual(
      folder.documents
        .map((d) => d.label.slice(room.length + 1).replace(/\.[a-z]+$/, ".json"))
        .sort(),
    );
    // One name in two folders is two reports, of two different documents.
    const hash = (rel: string): string =>
      (JSON.parse(readFileSync(join(out, rel), "utf8")) as { run: { result_hash: string } }).run
        .result_hash;
    expect(hash(join("2023", "msa.json"))).not.toBe(hash(join("2024", "msa.json")));
    expect(r.stderr + r.stdout).toContain(`wrote json for ${files.length} of`);
    // Hidden entries are said once on the terminal…
    expect(r.stderr).toMatch(/2 hidden file\(s\) or folder\(s\).*\.DS_Store.*\.git/s);
    // …and the JSON report carries the codes.
    const scan = JSON.parse(readFileSync(join(out, "scan.json"), "utf8")) as {
      ingest: { warnings: string[]; warning_codes: string[] };
    };
    expect(scan.ingest.warning_codes).toHaveLength(scan.ingest.warnings.length);
    expect(scan.ingest.warning_codes).toContain("no-text-layer");
  });

  it("keeps a flat folder's report names exactly as they were", () => {
    const flat = ["room/a.docx", "room/b.pdf"];
    expect([...outputStems(flat, "room").values()]).toEqual(["a", "b"]);
    const shared = ["room/deal.md", "room/deal.txt"];
    expect([...outputStems(shared, "room").values()]).toEqual(["deal.md", "deal.txt"]);
    const nested = ["room/2023/nda.docx", "room/2024/nda.docx"];
    expect([...outputStems(nested, "room").values()]).toEqual([
      join("2023", "nda"),
      join("2024", "nda"),
    ]);
  });
});
