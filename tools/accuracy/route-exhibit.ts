/**
 * Add one EDGAR exhibit to the routing sample (spec-v53 §8).
 *
 *   npm run accuracy:route -- --file ex10-1.htm \
 *     --accession 0001193125-24-123456 \
 *     --url https://www.sec.gov/Archives/edgar/data/…/ex10-1.htm \
 *     --title "Employment Agreement" --label "employment agreement" \
 *     --retrieved 2026-10-11
 *
 * The exhibit is a file the maintainer saved by hand; this opens no network
 * connection. It extracts the text, routes it through the real pipeline, and
 * writes a record of seven facts: where the exhibit is, when it was fetched,
 * the hash of the text that was routed, its title, its label, and where the
 * tool sent it. **The text is not written anywhere.** The saved file stays
 * wherever the maintainer put it and is not copied into the repository.
 */

import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { extname, join } from "node:path";
import { analyzeText } from "../cli/api.js";
import { loadAccuracyDeps, type AccuracyDeps } from "./pipeline.js";
import { CORPUS_DIR } from "./corpus.js";
import {
  RoutingLabelTableSchema,
  RoutingRecordSchema,
  type RoutingLabel,
  type RoutingRecord,
} from "./routing.js";

const BLOCK =
  "address|article|aside|blockquote|br|caption|dd|div|dl|dt|footer|h[1-6]|header|hr|li|ol|p|pre|section|table|td|th|tr|ul";
const ENTITIES: Record<string, string> = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
  nbsp: " ",
  sect: "§",
  ldquo: "“",
  rdquo: "”",
  lsquo: "‘",
  rsquo: "’",
  ndash: "–",
  mdash: "—",
};

/**
 * An EDGAR exhibit's HTML as the text a reader sees: scripts and styles gone,
 * a line break at each block element, entities decoded, blank runs collapsed.
 * Deterministic, so the same saved file always hashes the same.
 */
export function htmlToText(html: string): string {
  return html
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<(script|style|head)\b[\s\S]*?<\/\1\s*>/gi, " ")
    .replace(new RegExp(`<\\/?(?:${BLOCK})\\b[^>]*>`, "gi"), "\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&#(\d+);/g, (_, n: string) => String.fromCodePoint(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, n: string) => String.fromCodePoint(parseInt(n, 16)))
    .replace(/&([a-z]+);/gi, (whole, name: string) => ENTITIES[name.toLowerCase()] ?? whole)
    .replace(/\u00a0/g, " ")
    .split("\n")
    .map((line) => line.replace(/[ \t]+/g, " ").trim())
    .join("\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

export type ExhibitInput = {
  /** The exhibit's text, already extracted. */
  text: string;
  accession: string;
  exhibit_url: string;
  retrieved_at: string;
  title: string;
  label: string;
};

/** Route one exhibit and return its record. Holds the text only while it runs. */
export async function routeExhibit(
  input: ExhibitInput,
  labels: readonly RoutingLabel[],
  deps: AccuracyDeps,
): Promise<RoutingRecord> {
  if (!labels.some((l) => l.label === input.label)) {
    throw new Error(
      `"${input.label}" is not a row of corpus/routing/labels.json — add the row first, so the label is reviewed on its own`,
    );
  }
  if (input.text.trim().length === 0) throw new Error("the exhibit has no text");
  // A fixed name: the file's own name must not be a routing signal, and the
  // name is inside `result_hash`.
  const analysis = await analyzeText(input.text, "exhibit.txt", { deps });
  return RoutingRecordSchema.parse({
    accession: input.accession,
    exhibit_url: input.exhibit_url,
    retrieved_at: input.retrieved_at,
    text_sha256: createHash("sha256").update(input.text, "utf8").digest("hex"),
    title: input.title,
    label: input.label,
    observed_route: analysis.playbook_id,
  });
}

/** `<accession>-<first 8 of the text hash>.json`: stable, and unique per exhibit. */
export function recordFileName(record: RoutingRecord): string {
  return `${record.accession}-${record.text_sha256.slice(0, 8)}.json`;
}

/** Write a record, refusing an exhibit that is already in the sample. */
export async function writeRecord(record: RoutingRecord, recordsDir: string): Promise<string> {
  await mkdir(recordsDir, { recursive: true });
  for (const name of (await readdir(recordsDir)).filter((f) => f.endsWith(".json"))) {
    const existing = JSON.parse(await readFile(join(recordsDir, name), "utf8")) as RoutingRecord;
    if (existing.text_sha256 === record.text_sha256) {
      throw new Error(`this exhibit is already in the sample: ${name}`);
    }
  }
  const path = join(recordsDir, recordFileName(record));
  await writeFile(path, JSON.stringify(record, null, 2) + "\n");
  return path;
}

function flag(argv: readonly string[], name: string): string {
  const i = argv.indexOf(`--${name}`);
  const value = i >= 0 ? argv[i + 1] : undefined;
  if (!value || value.startsWith("--")) throw new Error(`missing --${name}`);
  return value;
}

export async function main(argv: readonly string[], corpusDir = CORPUS_DIR): Promise<string> {
  const file = flag(argv, "file");
  if (!existsSync(file)) throw new Error(`no such file: ${file}`);
  const ext = extname(file).toLowerCase();
  if (![".htm", ".html", ".txt"].includes(ext)) {
    throw new Error(
      `save the exhibit as .htm, .html or .txt — not ${ext || "a file with no extension"}`,
    );
  }
  const raw = await readFile(file, "utf8");
  const labelsPath = join(corpusDir, "routing", "labels.json");
  const labels = RoutingLabelTableSchema.parse(JSON.parse(await readFile(labelsPath, "utf8")));
  const record = await routeExhibit(
    {
      text: ext === ".txt" ? raw : htmlToText(raw),
      accession: flag(argv, "accession"),
      exhibit_url: flag(argv, "url"),
      retrieved_at: flag(argv, "retrieved"),
      title: flag(argv, "title"),
      label: flag(argv, "label"),
    },
    labels,
    await loadAccuracyDeps(),
  );
  const path = await writeRecord(record, join(corpusDir, "routing", "records"));
  return `Routed to ${record.observed_route}. Wrote ${path} — seven facts, no exhibit text.`;
}

if (process.argv[1]?.endsWith("route-exhibit.ts")) {
  main(process.argv.slice(2)).then(
    (line) => console.log(line),
    (err: unknown) => {
      console.error(err instanceof Error ? err.message : String(err));
      process.exitCode = 1;
    },
  );
}
