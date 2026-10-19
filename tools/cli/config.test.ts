/**
 * The project configuration file (add-project-config-file): the schema, the
 * discovery boundary, `extends`, path containment, the globs, the published
 * JSON Schema, and — through `resolveAnalyzeArgs` — the precedence of every
 * key against the flag that stands for it.
 */
import { mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  CONFIG_FILE_NAME,
  CONFIG_KEYS,
  ConfigError,
  ConfigSchema,
  EXAMPLE_CONFIG,
  buildConfigJsonSchema,
  discoverConfig,
  documentTypeFor,
  findConfig,
  isExcluded,
  isRelated,
  loadConfig,
  pathGlobToRegExp,
  provenance,
  provenanceLine,
} from "./config.js";
import { isDocumentType } from "./api.js";
import { resolveAnalyzeArgs } from "./run.js";

const NDA = join(process.cwd(), "tests", "fixtures", "specimens", "mutual-nda-complete.txt");

let tmp: string;
beforeAll(async () => {
  tmp = await realpath(await mkdtemp(join(tmpdir(), "vaul-config-")));
});
afterAll(() => rm(tmp, { recursive: true, force: true }));

/** A fresh repository folder (it holds `.git`) with a config and one document. */
async function repo(name: string, config: unknown, extra: Record<string, string> = {}) {
  const dir = join(tmp, name);
  await mkdir(join(dir, ".git"), { recursive: true });
  if (config !== undefined) {
    await writeFile(
      join(dir, CONFIG_FILE_NAME),
      typeof config === "string" ? config : JSON.stringify(config),
    );
  }
  for (const [rel, text] of Object.entries(extra)) {
    await mkdir(join(dir, rel, ".."), { recursive: true });
    await writeFile(join(dir, rel), text);
  }
  const doc = join(dir, "contract.txt");
  await writeFile(doc, await readFile(NDA));
  return { dir, doc };
}

describe("the schema", () => {
  it("rejects an unknown key, naming it — a typo must not switch a gate off", async () => {
    const { dir } = await repo("typo", { "fail-on": "critical" });
    await expect(loadConfig(join(dir, CONFIG_FILE_NAME))).rejects.toThrow(/unknown key "fail-on"/);
  });

  it("rejects a value the matching flag would reject", async () => {
    const { dir } = await repo("bad-enum", { fail_on: "critcal" });
    await expect(loadConfig(join(dir, CONFIG_FILE_NAME))).rejects.toThrow(/fail_on/);
  });

  it("rejects an unknown state code", async () => {
    const { dir } = await repo("bad-state", { state: "zz" });
    await expect(loadConfig(join(dir, CONFIG_FILE_NAME))).rejects.toThrow(/US state code/);
  });

  it("rejects text that is not JSON, and a file over the size limit", async () => {
    const { dir } = await repo("not-json", "{ fail_on: critical }");
    await expect(loadConfig(join(dir, CONFIG_FILE_NAME))).rejects.toThrow(/not valid JSON/);
    const big = await repo("big", JSON.stringify({ $comment: "x".repeat(70_000) }));
    await expect(loadConfig(join(big.dir, CONFIG_FILE_NAME))).rejects.toThrow(/limit/);
  });

  it("accepts the example `vaulytica init` writes, and every type id it names exists", async () => {
    const parsed = ConfigSchema.safeParse(JSON.parse(EXAMPLE_CONFIG));
    expect(parsed.success).toBe(true);
    for (const id of Object.values(parsed.data?.document_types ?? {})) {
      expect(await isDocumentType(id), id).toBe(true);
    }
  });
});

describe("discovery", () => {
  it("finds the nearest file at or above the start folder", async () => {
    const { dir } = await repo("nearest", { fail_on: "critical" }, { "a/b/doc.txt": "x" });
    expect(await findConfig(join(dir, "a", "b"))).toBe(join(dir, CONFIG_FILE_NAME));
  });

  it("stops at the repository root: a file above it is never read", async () => {
    const outer = join(tmp, "outer");
    await mkdir(join(outer, "project", ".git"), { recursive: true });
    await writeFile(join(outer, CONFIG_FILE_NAME), JSON.stringify({ fail_on: "info" }));
    expect(await findConfig(join(outer, "project"))).toBeNull();
  });

  it("stops at an explicit boundary (an MCP root)", async () => {
    const outer = join(tmp, "bounded");
    await mkdir(join(outer, "root", "docs"), { recursive: true });
    await writeFile(join(outer, CONFIG_FILE_NAME), JSON.stringify({ fail_on: "info" }));
    expect(await findConfig(join(outer, "root", "docs"), join(outer, "root"))).toBeNull();
  });
});

describe("paths stay inside the configuration's folder", () => {
  it("refuses a playbook_file that escapes", async () => {
    const { dir } = await repo("escape", { playbook_file: "../../secrets/team.json" });
    await expect(loadConfig(join(dir, CONFIG_FILE_NAME))).rejects.toThrow(
      /playbook_file "..\/..\/secrets\/team.json" resolves outside/,
    );
  });

  it("refuses an absolute playbook_file", async () => {
    const { dir } = await repo("absolute", { playbook_file: "/etc/passwd" });
    await expect(loadConfig(join(dir, CONFIG_FILE_NAME))).rejects.toThrow(/relative/);
  });

  it("refuses a symlink inside the folder that points outside it", async () => {
    const { dir } = await repo("link", { playbook_file: "team.json" });
    await writeFile(join(tmp, "outside.json"), "{}");
    await symlink(join(tmp, "outside.json"), join(dir, "team.json")).catch(() => null);
    await expect(loadConfig(join(dir, CONFIG_FILE_NAME))).rejects.toThrow(/outside/);
  });
});

describe("extends", () => {
  it("merges a base under the file's own keys, one key at a time", async () => {
    const { dir } = await repo(
      "extends",
      { extends: "base/vaulytica.base.json", fail_on: "critical" },
      {
        "base/vaulytica.base.json": JSON.stringify({
          fail_on: "info",
          delivery: true,
          exclude: ["drafts/**"],
        }),
      },
    );
    const cfg = await loadConfig(join(dir, CONFIG_FILE_NAME));
    expect(cfg.values.fail_on).toBe("critical");
    expect(cfg.values.delivery).toBe(true);
    // A base's globs are relative to the BASE, re-anchored to the file.
    expect(cfg.values.exclude).toEqual(["base/drafts/**"]);
    expect(cfg.extends?.path).toBe(join(dir, "base", "vaulytica.base.json"));
  });

  it("is one level deep", async () => {
    const { dir } = await repo(
      "extends-twice",
      { extends: "a.json" },
      { "a.json": JSON.stringify({ extends: "b.json" }), "b.json": "{}" },
    );
    await expect(loadConfig(join(dir, CONFIG_FILE_NAME))).rejects.toThrow(/one level only/);
  });

  it("refuses a base outside the folder", async () => {
    const { dir } = await repo("extends-escape", { extends: "../shared.json" });
    await expect(loadConfig(join(dir, CONFIG_FILE_NAME))).rejects.toThrow(ConfigError);
  });
});

describe("globs", () => {
  it.each([
    ["vendors/**/dpa-*.docx", "vendors/acme/dpa-1.docx", true],
    ["vendors/**/dpa-*.docx", "vendors/dpa-1.docx", true],
    ["vendors/**/dpa-*.docx", "vendors/acme/eu/dpa-1.docx", true],
    ["vendors/**/dpa-*.docx", "other/dpa-1.docx", false],
    ["*.txt", "a.txt", true],
    ["*.txt", "d/a.txt", false],
    ["drafts/**", "drafts/x/y.txt", true],
    ["deal-?", "deal-1", true],
    ["a.b", "axb", false],
  ])("%s matches %s: %s", (glob, path, expected) => {
    expect(pathGlobToRegExp(glob).test(path)).toBe(expected);
  });

  it("maps a file to a type, excludes, and recognizes a related folder", async () => {
    const { dir } = await repo("globs", {
      document_types: {
        "vendors/**/dpa-*.txt": "dpa-controller-processor",
        "**/*.txt": "unilateral-nda-deep",
      },
      exclude: ["drafts/**"],
      related: ["deal-rooms/*"],
    });
    const cfg = await loadConfig(join(dir, CONFIG_FILE_NAME));
    // The first glob, in the file's key order, wins.
    expect(documentTypeFor(cfg, join(dir, "vendors", "a", "dpa-1.txt"))).toBe(
      "dpa-controller-processor",
    );
    expect(documentTypeFor(cfg, join(dir, "x.txt"))).toBe("unilateral-nda-deep");
    expect(documentTypeFor(cfg, join(tmp, "elsewhere.txt"))).toBeUndefined();
    expect(isExcluded(cfg, join(dir, "drafts", "v1.txt"))).toBe(true);
    expect(isExcluded(cfg, join(dir, "final.txt"))).toBe(false);
    expect(isRelated(cfg, join(dir, "deal-rooms", "acme"))).toBe(true);
    expect(isRelated(cfg, join(dir, "deal-rooms", "acme", "msa.txt"))).toBe(true);
    expect(isRelated(cfg, join(dir, "deal-rooms"))).toBe(false);
  });
});

describe("provenance", () => {
  it("names no absolute path and sorts its lists", async () => {
    const { dir } = await repo("prov", { fail_on: "critical" });
    const cfg = await loadConfig(join(dir, CONFIG_FILE_NAME));
    const p = provenance(cfg, join(dir, "sub"), ["fail_on", "delivery"], ["playbook"]);
    expect(p.path).toBe("../vaulytica.config.json");
    expect(p.applied).toEqual(["delivery", "fail_on"]);
    expect(p.overridden).toEqual(["playbook"]);
    expect(p.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(provenanceLine(p)).toBe(
      "vaulytica: config ../vaulytica.config.json applied: delivery, fail_on; overridden by flags: playbook\n",
    );
  });
});

describe("the published JSON Schema", () => {
  it("equals the one built from the Zod schema (run tools/cli/write-config-schema.ts)", () => {
    const committed = readFileSync(join(process.cwd(), "docs", "config.schema.json"), "utf8");
    expect(committed).toBe(buildConfigJsonSchema());
  });

  it("is strict and lists every key", () => {
    const schema = JSON.parse(buildConfigJsonSchema()) as {
      additionalProperties: boolean;
      properties: Record<string, unknown>;
    };
    expect(schema.additionalProperties).toBe(false);
    for (const k of CONFIG_KEYS) expect(Object.keys(schema.properties)).toContain(k);
  });
});

/* ---------------- precedence: every key against its flag ---------------- */

describe("precedence", { timeout: 60_000 }, () => {
  const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  beforeEach(() => stderr.mockClear());
  afterAll(() => stderr.mockRestore());

  /**
   * One row per key: the file's value, what the run uses without a flag, the
   * flag that overrides it, and what the run uses then.
   */
  const table: Array<{
    key: string;
    value: unknown;
    field: string;
    fromFile: unknown;
    flag: string[];
    fromFlag: unknown;
  }> = [
    {
      key: "playbook",
      value: "unilateral-nda-deep",
      field: "playbook",
      fromFile: "unilateral-nda-deep",
      flag: ["--playbook", "mutual-nda-deep"],
      fromFlag: "mutual-nda-deep",
    },
    {
      key: "fail_on",
      value: "critical",
      field: "failOn",
      fromFile: "critical",
      flag: ["--fail-on", "warning"],
      fromFlag: "warning",
    },
    {
      key: "formats",
      value: ["md", "csv"],
      field: "formats",
      fromFile: ["md", "csv"],
      flag: ["--format", "json"],
      fromFlag: ["json"],
    },
    {
      key: "deadline_profile",
      value: "frcp-6",
      field: "deadlineProfile",
      fromFile: "frcp-6",
      flag: ["--deadline-profile", "cal-ccp-12"],
      fromFlag: "cal-ccp-12",
    },
    {
      key: "service_method",
      value: "mail",
      field: "serviceMethod",
      fromFile: "mail",
      flag: ["--service-method", "electronic"],
      fromFlag: "electronic",
    },
    {
      key: "court",
      value: "frap-default",
      field: "court",
      fromFile: "frap-default",
      flag: ["--court", "ca9-appellate"],
      fromFlag: "ca9-appellate",
    },
    {
      key: "regime",
      value: ["gdpr"],
      field: "regimes",
      fromFile: ["gdpr-13", "gdpr-14"],
      flag: ["--regime", "tx"],
      fromFlag: ["tx"],
    },
    {
      key: "state",
      value: "pa",
      field: "estateState",
      fromFile: "us-pa",
      flag: ["--state", "la"],
      fromFlag: "us-la",
    },
  ];

  it.each(table)("$key: the file applies without the flag, the flag wins with it", async (row) => {
    const { dir, doc } = await repo(`prec-${row.key}`, { [row.key]: row.value });
    const plain = (await resolveAnalyzeArgs([doc])) as unknown as Record<string, unknown>;
    expect(plain[row.field]).toEqual(row.fromFile);
    expect(plain.configProvenance).toMatchObject({ applied: [row.key], overridden: [] });

    const typed = (await resolveAnalyzeArgs([doc, ...row.flag])) as unknown as Record<
      string,
      unknown
    >;
    expect(typed[row.field]).toEqual(row.fromFlag);
    expect(typed.configProvenance).toMatchObject({ applied: [], overridden: [row.key] });
    expect(String(stderr.mock.calls.at(-1)?.[0])).toContain(`overridden by flags: ${row.key}`);
    expect(dir).toBeTruthy();
  });

  it.each([
    ["delivery", "--delivery", "delivery"],
    ["consistency", "--consistency", "consistency"],
    ["estate_checks", "--estate-checks", "estateChecks"],
  ])("%s: true in the file switches it on; the flag is an override", async (key, flag, field) => {
    const { doc } = await repo(`bool-${key}`, { [key]: true });
    const plain = (await resolveAnalyzeArgs([doc])) as unknown as Record<string, unknown>;
    expect(plain[field]).toBe(true);
    const typed = await resolveAnalyzeArgs([doc, flag]);
    expect(typed.configProvenance?.overridden).toEqual([key]);
  });

  it("out and playbook_file resolve against the configuration's folder", async () => {
    const { dir, doc } = await repo(
      "paths",
      { out: "reports", playbook_file: "team/playbook.json" },
      { "team/playbook.json": "{}" },
    );
    const args = await resolveAnalyzeArgs([doc]);
    expect(args.out).toBe(join(dir, "reports"));
    expect(args.playbookFile).toBe(join(dir, "team", "playbook.json"));
  });

  it("--consistency-only overrides formats", async () => {
    const { doc } = await repo("cons-only", { formats: ["md"] });
    const args = await resolveAnalyzeArgs([doc, "--consistency-only"]);
    expect(args.configProvenance?.overridden).toEqual(["formats"]);
  });

  it("a typed --playbook makes document_types stand down", async () => {
    const { doc } = await repo("dt-flag", { document_types: { "*.txt": "unilateral-nda-deep" } });
    const args = await resolveAnalyzeArgs([doc, "--playbook", "mutual-nda-deep"]);
    expect(args.playbookFromFlag).toBe(true);
    expect(args.configProvenance?.overridden).toEqual(["document_types"]);
  });

  it("related turns the cross-document run on for a folder it names", async () => {
    const { dir } = await repo("related", { related: ["rooms/*"] }, { "rooms/acme/a.txt": "x" });
    const args = await resolveAnalyzeArgs([join(dir, "rooms", "acme")]);
    expect(args.consistency).toBe(true);
    const other = await resolveAnalyzeArgs([dir]);
    expect(other.consistency).toBeUndefined();
  });

  it("refuses a document type id that does not exist", async () => {
    const { doc } = await repo("bad-id", { document_types: { "*.txt": "no-such-type" } });
    await expect(resolveAnalyzeArgs([doc])).rejects.toThrow(
      /"no-such-type" is not a document type/,
    );
  });

  it("with no file, the arguments are the flags alone and nothing is said", async () => {
    const dir = join(tmp, "none");
    await mkdir(join(dir, ".git"), { recursive: true });
    await writeFile(join(dir, "c.txt"), "x");
    const args = await resolveAnalyzeArgs([join(dir, "c.txt"), "--fail-on", "info"]);
    expect(args.config).toBeUndefined();
    expect(args.failOn).toBe("info");
    expect(stderr).not.toHaveBeenCalled();
    expect(await discoverConfig(dir)).toBeNull();
  });
});
