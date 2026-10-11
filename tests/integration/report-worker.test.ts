/**
 * The report endpoint (spec-v53 §5) — not deployed, and tested as if it were.
 *
 * The Worker's SQL runs here against the real migration, through SQLite, so
 * the CHECK constraints, the unique dedupe key and the retention delete are
 * the ones production would run. What is held:
 *
 *   - a contract cannot fit through it: 4 KB, an exact key set, ids from the
 *     shipped catalog, a 280-character note with control characters stripped;
 *   - nothing identifying the reporter is written;
 *   - the daily ceilings, the dedupe, and the 30-day deletion;
 *   - missing configuration fails closed;
 *   - and the app cannot reach it: nothing in `src/` or `tools/` imports the
 *     Worker, and no shipped script names its path.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { beforeEach, describe, expect, it } from "vitest";
import {
  BODY_KEYS,
  MAX_BODY_BYTES,
  NOTE_MAX,
  cleanNote,
  parseReport,
  type Catalog,
} from "../../workers/reports/src/validate.js";
import {
  LIMITS,
  RETENTION_DAYS,
  dedupeKey,
  purgeExpired,
  reporterKey,
  storeReport,
  type Database,
} from "../../workers/reports/src/store.js";
import {
  REPORT_PATH,
  handleRequest,
  handleScheduled,
  type Deps,
  type Env,
} from "../../workers/reports/src/handler.js";
import { CATALOG_IDS_PATH, catalogIds } from "../../tools/reports/write-catalog-ids.js";

const ROOT = process.cwd();
const MIGRATION = readFileSync(
  join(ROOT, "workers", "reports", "migrations", "0001_reports.sql"),
  "utf8",
);

/** D1's prepare/bind/run/first, over SQLite. */
function openDb(): { db: Database; raw: DatabaseSync } {
  const raw = new DatabaseSync(":memory:");
  raw.exec(MIGRATION);
  const db: Database = {
    prepare(sql) {
      const stmt = raw.prepare(sql);
      let args: unknown[] = [];
      const self = {
        bind(...values: unknown[]) {
          args = values;
          return self;
        },
        run: async () => ({ meta: { changes: Number(stmt.run(...(args as never[])).changes) } }),
        first: async <T>() => (stmt.get(...(args as never[])) as T | undefined) ?? null,
      };
      return self;
    },
  };
  return { db, raw };
}

const CATALOG: Catalog = {
  rules: new Set(["NDA-D-019", "RISK-001"]),
  types: new Set(["mutual-nda-deep", "employment-at-will-us"]),
};
const GOOD = {
  kind: "wrong-finding",
  rule: "NDA-D-019",
  rv: "1.1.0",
  engine: "9.883.0",
  dkb: "v2026-10-05-local",
  type: "mutual-nda-deep",
  note: "The clause is there, in section 4.",
  token: "tok",
};
const NOW = new Date("2026-10-11T12:00:00.000Z");

describe("what the endpoint accepts", () => {
  it("takes a well-formed report and maps it to the stored columns", () => {
    const p = parseReport(JSON.stringify(GOOD), CATALOG);
    expect(p).toEqual({
      ok: true,
      token: "tok",
      report: {
        kind: "wrong-finding",
        rule_id: "NDA-D-019",
        rule_version: "1.1.0",
        engine_version: "9.883.0",
        dkb_version: "v2026-10-05-local",
        document_type: "mutual-nda-deep",
        near_family: null,
        note: "The clause is there, in section 4.",
      },
    });
  });

  it("has no key a document could ride in", () => {
    expect([...BODY_KEYS].sort()).toEqual(
      ["dkb", "engine", "kind", "near", "note", "rule", "rv", "token", "type"].sort(),
    );
    for (const extra of ["excerpt", "filename", "sha256", "result_hash", "text", "document"]) {
      const p = parseReport(JSON.stringify({ ...GOOD, [extra]: "x" }), CATALOG);
      expect(p, extra).toEqual({ ok: false, status: 400, error: "unknown key" });
    }
  });

  it("refuses a body over 4 KB, however it is filled", () => {
    const big = JSON.stringify({ ...GOOD, note: "x".repeat(MAX_BODY_BYTES) });
    expect(parseReport(big, CATALOG)).toEqual({ ok: false, status: 413, error: "body too large" });
  });

  it("refuses an id that is not in the shipped catalog — a custom playbook's included", () => {
    for (const bad of [
      { rule: "MY-FIRM-001" },
      { type: "our-house-nda" },
      { near: "our-house-nda" },
    ]) {
      expect(
        parseReport(JSON.stringify({ ...GOOD, ...bad }), CATALOG).ok,
        JSON.stringify(bad),
      ).toBe(false);
    }
  });

  it("refuses the wrong shape", () => {
    for (const bad of [
      { kind: "praise" },
      { engine: "latest" },
      { rv: "one" },
      { dkb: "the newest one" },
      { token: "" },
      { note: 280 },
      { rule: { id: "NDA-D-019" } },
    ]) {
      expect(
        parseReport(JSON.stringify({ ...GOOD, ...bad }), CATALOG).ok,
        JSON.stringify(bad),
      ).toBe(false);
    }
    const { rule: _rule, rv: _rv, ...noRule } = GOOD;
    expect(parseReport(JSON.stringify(noRule), CATALOG).ok).toBe(false);
    expect(parseReport("[]", CATALOG).ok).toBe(false);
    expect(parseReport("not json", CATALOG).ok).toBe(false);
  });

  it("caps the note at 280 characters and strips what cannot be printed", () => {
    expect(parseReport(JSON.stringify({ ...GOOD, note: "x".repeat(NOTE_MAX) }), CATALOG).ok).toBe(
      true,
    );
    expect(
      parseReport(JSON.stringify({ ...GOOD, note: "x".repeat(NOTE_MAX + 1) }), CATALOG).ok,
    ).toBe(false);
    const hostile = `a${String.fromCharCode(0)}b${String.fromCharCode(0x202e)}c${String.fromCharCode(0x2028)}d\n\te`;
    expect(cleanNote(hostile)).toBe("a b c d e");
    const p = parseReport(JSON.stringify({ ...GOOD, note: " \n " }), CATALOG);
    expect(p.ok && p.report.note).toBeNull();
  });
});

describe("what it stores, and for how long", () => {
  let db: Database;
  let raw: DatabaseSync;
  const report = (over: Record<string, string> = {}) => {
    const p = parseReport(JSON.stringify({ ...GOOD, ...over }), CATALOG);
    if (!p.ok) throw new Error(p.error);
    return p.report;
  };
  beforeEach(() => {
    ({ db, raw } = openDb());
  });
  const rows = () =>
    raw.prepare("SELECT * FROM finding_reports").all() as Array<Record<string, unknown>>;

  it("stores a report once: the same report twice is one row", async () => {
    expect(await storeReport(db, report(), "r1", NOW)).toBe("stored");
    expect(await storeReport(db, report(), "r1", NOW)).toBe("duplicate");
    expect(await storeReport(db, report(), "someone-else", NOW)).toBe("duplicate");
    expect(rows()).toHaveLength(1);
    expect(await dedupeKey(report())).toBe(await dedupeKey(report()));
    expect(await dedupeKey(report())).not.toBe(await dedupeKey(report({ note: "different" })));
  });

  it("writes nothing that identifies the reporter", async () => {
    await storeReport(db, report(), await reporterKey("203.0.113.9", "secret", "2026-10-11"), NOW);
    const everything = JSON.stringify([
      rows(),
      raw.prepare("SELECT * FROM report_reporter_days").all(),
      raw.prepare("SELECT * FROM report_days").all(),
    ]);
    expect(everything).not.toContain("203.0.113.9");
    expect(Object.keys(rows()[0]!).sort()).toEqual(
      [
        "created_at",
        "dedupe_key",
        "dkb_version",
        "document_type",
        "engine_version",
        "id",
        "kind",
        "near_family",
        "note",
        "resolution_note",
        "resolved_at",
        "rule_id",
        "rule_version",
        "status",
      ].sort(),
    );
  });

  it("keys a reporter for one day, under the secret", async () => {
    const a = await reporterKey("203.0.113.9", "secret", "2026-10-11");
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(await reporterKey("203.0.113.9", "secret", "2026-10-11")).toBe(a);
    expect(await reporterKey("203.0.113.9", "secret", "2026-10-12")).not.toBe(a);
    expect(await reporterKey("203.0.113.9", "other", "2026-10-11")).not.toBe(a);
    expect(await reporterKey("203.0.113.10", "secret", "2026-10-11")).not.toBe(a);
  });

  it("accepts five reports a day from one reporter, then stops", async () => {
    for (let i = 0; i < LIMITS.reporterAccepted; i++) {
      expect(await storeReport(db, report({ note: `n${i}` }), "r1", NOW)).toBe("stored");
    }
    expect(await storeReport(db, report({ note: "one more" }), "r1", NOW)).toBe("limited");
    // Someone else is unaffected, and so is the same reporter tomorrow.
    expect(await storeReport(db, report({ note: "one more" }), "r2", NOW)).toBe("stored");
    const tomorrow = new Date(NOW.getTime() + 86_400_000);
    expect(await storeReport(db, report({ note: "next day" }), "r1", tomorrow)).toBe("stored");
  });

  it("accepts two hundred a day in total, then stops for everyone", async () => {
    for (let i = 0; i < LIMITS.totalAccepted; i++) {
      expect(await storeReport(db, report({ note: `n${i}` }), `r${i}`, NOW), String(i)).toBe(
        "stored",
      );
    }
    expect(await storeReport(db, report({ note: "201" }), "fresh", NOW)).toBe("limited");
    expect(rows()).toHaveLength(LIMITS.totalAccepted);
  });

  it("caps verified attempts too, so duplicates cannot be replayed without end", async () => {
    await storeReport(db, report(), "r1", NOW);
    for (let i = 1; i < LIMITS.reporterAttempts; i++) {
      expect(await storeReport(db, report(), "r1", NOW)).toBe("duplicate");
    }
    expect(await storeReport(db, report(), "r1", NOW)).toBe("limited");
  });

  it("deletes every report after thirty days — on the cron, and before each write", async () => {
    const old = new Date(NOW.getTime() - (RETENTION_DAYS + 1) * 86_400_000);
    const recent = new Date(NOW.getTime() - (RETENTION_DAYS - 1) * 86_400_000);
    await storeReport(db, report({ note: "old" }), "r1", old);
    await storeReport(db, report({ note: "recent" }), "r1", recent);
    expect(rows()).toHaveLength(2);
    // A write sweeps first.
    await storeReport(db, report({ note: "new" }), "r1", NOW);
    expect(
      rows()
        .map((r) => r.note)
        .sort(),
    ).toEqual(["new", "recent"]);
    // And so does the cron.
    const later = new Date(NOW.getTime() + 5 * 86_400_000);
    expect(await handleScheduled({ DB: db }, later)).toBe(1);
    expect(rows().map((r) => r.note)).toEqual(["new"]);
    expect(await purgeExpired(db, later)).toBe(0);
    expect(raw.prepare("SELECT COUNT(*) AS n FROM report_reporter_days").get()).toEqual({ n: 0 });
  });

  it("the schema itself refuses a long note and an unknown kind", () => {
    const insert = (kind: string, note: string) =>
      raw
        .prepare(
          "INSERT INTO finding_reports (id, created_at, kind, engine_version, note, dedupe_key) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .run(
          `${kind}-${note.length}`,
          NOW.toISOString(),
          kind,
          "9.883.0",
          note,
          `${kind}${note.length}`,
        );
    expect(() => insert("site", "x".repeat(281))).toThrow();
    expect(() => insert("praise", "x")).toThrow();
    expect(() => insert("site", "x".repeat(280))).not.toThrow();
  });
});

describe("the request handler", () => {
  let env: Env;
  let raw: DatabaseSync;
  const deps = (verified = true): Deps => ({
    catalog: CATALOG,
    now: () => NOW,
    verifyToken: async () => verified,
  });
  const post = (body: unknown, headers: Record<string, string> = {}) =>
    new Request(`https://vaulytica.com${REPORT_PATH}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "cf-connecting-ip": "203.0.113.9",
        ...headers,
      },
      body: typeof body === "string" ? body : JSON.stringify(body),
    });
  beforeEach(() => {
    const opened = openDb();
    raw = opened.raw;
    env = { DB: opened.db, TURNSTILE_SECRET: "ts", REPORTER_HMAC_SECRET: "hs" };
  });
  const count = () =>
    (raw.prepare("SELECT COUNT(*) AS n FROM finding_reports").get() as { n: number }).n;

  it("stores a verified report, and answers a duplicate the same way", async () => {
    const first = await handleRequest(post(GOOD), env, deps());
    expect(first.status).toBe(201);
    expect(await first.json()).toEqual({ ok: true });
    expect(first.headers.get("cache-control")).toBe("no-store");
    expect((await handleRequest(post(GOOD), env, deps())).status).toBe(200);
    expect(count()).toBe(1);
  });

  it("fails closed when any part of its configuration is missing", async () => {
    for (const missing of ["DB", "TURNSTILE_SECRET", "REPORTER_HMAC_SECRET"] as const) {
      const res = await handleRequest(post(GOOD), { ...env, [missing]: undefined }, deps());
      expect(res.status, missing).toBe(503);
      expect(await res.json()).toEqual({ error: "reporting is unavailable" });
    }
    expect(count()).toBe(0);
  });

  it("stores nothing without a verified token", async () => {
    expect((await handleRequest(post(GOOD), env, deps(false))).status).toBe(403);
    expect(count()).toBe(0);
  });

  it("has no read endpoint, and serves no other path", async () => {
    const get = new Request(`https://vaulytica.com${REPORT_PATH}`);
    expect((await handleRequest(get, env, deps())).status).toBe(405);
    const other = new Request("https://vaulytica.com/api/reports/all", { method: "POST" });
    expect((await handleRequest(other, env, deps())).status).toBe(404);
  });

  it("refuses an oversized body, an unknown key, and a body that is not JSON", async () => {
    const big = post({ ...GOOD, note: "x".repeat(MAX_BODY_BYTES) });
    expect((await handleRequest(big, env, deps())).status).toBe(413);
    expect((await handleRequest(post({ ...GOOD, excerpt: "WHEREAS" }), env, deps())).status).toBe(
      400,
    );
    expect((await handleRequest(post("{"), env, deps())).status).toBe(400);
    const form = post("kind=site", { "content-type": "application/x-www-form-urlencoded" });
    expect((await handleRequest(form, env, deps())).status).toBe(415);
    expect(count()).toBe(0);
  });

  it("answers 429 at the ceiling", async () => {
    for (let i = 0; i < LIMITS.reporterAccepted; i++) {
      expect((await handleRequest(post({ ...GOOD, note: `n${i}` }), env, deps())).status).toBe(201);
    }
    expect((await handleRequest(post({ ...GOOD, note: "more" }), env, deps())).status).toBe(429);
  });
});

describe("the id list the Worker carries", () => {
  it("is the shipped catalog (run `npm run reports:ids` if this fails)", async () => {
    const committed = JSON.parse(readFileSync(CATALOG_IDS_PATH, "utf8")) as {
      rules: string[];
      types: string[];
    };
    expect(committed).toEqual(await catalogIds());
    expect(committed.rules.length).toBeGreaterThan(1500);
    expect(committed.types).toContain("mutual-nda-deep");
  });
});

describe("the app cannot reach it", () => {
  const walk = (dir: string): string[] =>
    readdirSync(dir).flatMap((name) => {
      const path = join(dir, name);
      return statSync(path).isDirectory() ? walk(path) : [path];
    });

  it("nothing in src/ imports the Worker or names its path", () => {
    const offenders = walk(join(ROOT, "src"))
      .filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts"))
      .filter((f) => {
        const text = readFileSync(f, "utf8");
        return text.includes("workers/reports") || text.includes(REPORT_PATH);
      });
    expect(offenders).toEqual([]);
  });

  it("no script the site ships names the endpoint, and the page still says it does not send", () => {
    for (const file of ["report.js", "index.html"]) {
      expect(readFileSync(join(ROOT, "site", file), "utf8"), file).not.toContain(REPORT_PATH);
    }
    // The Worker is written and not deployed. Until it is, the site's claims
    // are unchanged — and this is the line that fails on the day they must be.
    expect(readFileSync(join(ROOT, "site", "report.js"), "utf8")).toContain("sends nothing");
  });

  it("only the id-list generator in tools/ touches the Worker's directory", () => {
    const touching = walk(join(ROOT, "tools"))
      .filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts"))
      .filter((f) => readFileSync(f, "utf8").includes('"workers"'))
      .map((f) => f.slice(ROOT.length + 1).replaceAll("\\", "/"));
    expect(touching).toEqual(["tools/reports/write-catalog-ids.ts"]);
  });
});

describe("the Worker is in the repository", () => {
  it("is tracked by git, not swallowed by an ignore rule", () => {
    // 9.884.0 shipped without `workers/reports/` and `tools/reports/`: a bare
    // `reports/` line in .gitignore, written for the mutation tool's output,
    // matched both, and a green local gate was red on every CI runner.
    let tracked: string;
    try {
      tracked = execFileSync("git", ["ls-files", "workers", "tools/reports"], {
        cwd: ROOT,
        encoding: "utf8",
        timeout: 10_000,
      });
    } catch {
      return; // not a git checkout (an extracted archive)
    }
    for (const file of [
      "workers/reports/src/index.ts",
      "workers/reports/src/handler.ts",
      "workers/reports/src/store.ts",
      "workers/reports/src/validate.ts",
      "workers/reports/src/catalog-ids.json",
      "workers/reports/migrations/0001_reports.sql",
      "workers/reports/wrangler.jsonc",
      "tools/reports/write-catalog-ids.ts",
    ]) {
      expect(tracked.split("\n"), file).toContain(file);
    }
  });
});
