/**
 * The key terms and the inventory, byte for byte on both surfaces
 * (add-contract-abstract-inventory, task 5).
 *
 * The tab offers a document's key terms (the CLI's `abstract-csv` /
 * `abstract-json`) and a folder's inventory (`inventory-csv` /
 * `inventory-json`). Each is the same builder over the same run, so the
 * downloads must be the files the CLI writes: the browser pipeline and
 * `vaulytica analyze --out` run here on the same bytes, and the outputs are
 * compared as strings. A title computed differently on one side (the tab once
 * passed `""`) is the drift this guards.
 */
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

import {
  prepareBundle,
  prepareDocument,
  runBundleReport,
  runReport,
} from "../../src/ui/pipeline.js";
import { runAnalyze } from "../../tools/cli/run.js";
import { resolveDkbDir } from "../../tools/dkb/resolve.js";

const SAMPLES = join(process.cwd(), "tests", "e2e", "sample-docs");
const DKB_DIR = resolveDkbDir();
const PLAYBOOK_DIR = join(process.cwd(), "playbooks");
const CONFIG = { dkb_base: "/x-dkb", playbook_base: "/x-playbooks" };

const realFetch = globalThis.fetch;
globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
  const url = String(input);
  const serve = (dir: string, name: string): Response => {
    try {
      return new Response(readFileSync(join(dir, name)), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    } catch {
      return new Response("not found", { status: 404 });
    }
  };
  if (url.startsWith("/x-dkb/"))
    return Promise.resolve(serve(DKB_DIR, url.slice("/x-dkb/".length)));
  if (url.startsWith("/x-playbooks/"))
    return Promise.resolve(serve(PLAYBOOK_DIR, url.slice("/x-playbooks/".length)));
  return realFetch(input, init);
}) as typeof fetch;

const dirs: string[] = [];
afterAll(async () => {
  globalThis.fetch = realFetch;
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});
async function tmp(prefix: string): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), prefix));
  dirs.push(d);
  return d;
}
const fileOf = (path: string, name: string): File =>
  new File([new Uint8Array(readFileSync(path))], name);

describe("key terms and inventory: the tab writes the CLI's bytes", () => {
  it("one document's key terms, CSV and JSON", async () => {
    const name = "vendor-saas-agreement.docx";
    const path = join(SAMPLES, "single", name);
    const ui = await runReport(await prepareDocument(fileOf(path, name), "docx", CONFIG));

    const out = await tmp("vaulytica-abstract-");
    await runAnalyze([path, "--format", "abstract-csv,abstract-json", "--out", out]);
    const csv = await readFile(join(out, "vendor-saas-agreement.abstract.csv"), "utf8");
    const json = await readFile(join(out, "vendor-saas-agreement.abstract.json"), "utf8");

    expect(await ui.abstract_csv_blob.text()).toBe(csv);
    expect(await ui.abstract_json_blob.text()).toBe(json);
    // A title, not a blank: the row names the document.
    expect(JSON.parse(json).rows[0].title).not.toBe("");
  }, 180_000);

  // The tab drops a file it cannot read before planning (`expandBundleInputs`),
  // so a skipped `.png` reaches the CLI's `not_analyzed` but not the tab's.
  // The documents' rows are what must agree.
  it("a folder's inventory, CSV and JSON", async () => {
    const names = ["master-services-agreement.docx", "statement-of-work.docx"];
    const room = join(await tmp("vaulytica-room-"), "room");
    await mkdir(room);
    for (const n of names) await writeFile(join(room, n), readFileSync(join(SAMPLES, "bundle", n)));
    const files = names.map((n) => fileOf(join(room, n), n));
    const ui = await runBundleReport(await prepareBundle(files, {}, CONFIG, {}));

    const out = await tmp("vaulytica-inventory-");
    await runAnalyze([room, "--format", "inventory-csv,inventory-json", "--out", out]);
    const csv = await readFile(join(out, "INVENTORY.csv"), "utf8");
    const json = await readFile(join(out, "INVENTORY.json"), "utf8");

    expect((JSON.parse(json) as { rows: unknown[] }).rows).toHaveLength(2);
    expect(await ui.inventory_json_blob.text()).toBe(json);
    expect(await ui.inventory_csv_blob.text()).toBe(csv);
  }, 240_000);
});
