/**
 * Routing on public filings (spec-v53 §8, Step 332).
 *
 * "Is this finding legally right" needs an attorney. "Did the tool recognize
 * a document for what its own title says it is" does not. This measures the
 * second on EDGAR material-contract exhibits — and holds NONE of their text.
 * An exhibit is written by private parties; "publicly filed" is a statement
 * about access, not a license. A record is seven facts about a document:
 * where it is, when it was fetched, the hash of what was read, its title, the
 * label a maintainer gave that title, and where the tool sent it.
 *
 * The label is a row of a committed table from a title to an ACCEPTABLE SET of
 * types, because the catalog declares ties (`msa-general`, `msa-customer-deep`
 * and `msa-vendor-deep` are all right for "Master Services Agreement"). A
 * title the catalog has no type for is a row too, and its share is printed,
 * not filtered out.
 *
 * Three caveats are printed with the numbers, every time ({@link routingCaveats}).
 */

import { existsSync } from "node:fs";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";

export const GENERIC_FALLBACK = "generic-fallback";

/** One row of the label table: a title, and the types that are right for it. */
export const RoutingLabelSchema = z
  .object({
    /** The key a record's `label` names. Lower-case, the title's own words. */
    label: z
      .string()
      .min(1)
      .regex(/^[a-z0-9][a-z0-9 &'/().,-]*$/),
    /** The type the title names, when the catalog has one. */
    exact: z.string().min(1).optional(),
    /** Other types the suite already treats as right for this title. */
    acceptable: z.array(z.string().min(1)).default([]),
    /** No type exists for this title. Kept and counted, never dropped. */
    no_family: z.literal(true).optional(),
  })
  .strict()
  .refine((l) => (l.no_family === true) !== (l.exact !== undefined), {
    message: "a label names an exact type or says no_family, and not both",
  })
  .refine((l) => !l.no_family || l.acceptable.length === 0, {
    message: "a no_family label has no acceptable types",
  });
export type RoutingLabel = z.infer<typeof RoutingLabelSchema>;

export const RoutingLabelTableSchema = z
  .array(RoutingLabelSchema)
  .refine((rows) => new Set(rows.map((r) => r.label)).size === rows.length, {
    message: "label keys are unique",
  });

/**
 * One exhibit, with no part of its text. `.strict()`: a record cannot grow a
 * field that carries the document.
 */
export const RoutingRecordSchema = z
  .object({
    /** SEC accession number, e.g. `0001193125-24-123456`. */
    accession: z.string().regex(/^\d{10}-\d{2}-\d{6}$/),
    exhibit_url: z
      .string()
      .url()
      .refine((u) => new URL(u).hostname === "www.sec.gov" && u.startsWith("https://"), {
        message: "an exhibit is read from https://www.sec.gov",
      }),
    /** ISO date the exhibit was fetched. */
    retrieved_at: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
    /** SHA-256 of the extracted text that was routed. */
    text_sha256: z.string().regex(/^[0-9a-f]{64}$/),
    /** The exhibit's own title — a few words, not its text. */
    title: z.string().min(1).max(200),
    /** A key of the label table. */
    label: z.string().min(1),
    /** The type the tool routed it to. */
    observed_route: z.string().min(1),
  })
  .strict();
export type RoutingRecord = z.infer<typeof RoutingRecordSchema>;

export type RoutingOutcome = "exact" | "acceptable" | "wrong" | "fallback" | "no_family";
export const ROUTING_OUTCOMES: readonly RoutingOutcome[] = [
  "exact",
  "acceptable",
  "wrong",
  "fallback",
  "no_family",
];

/** Which of the five shares one record falls in. */
export function routingOutcome(record: RoutingRecord, label: RoutingLabel): RoutingOutcome {
  // The catalog has no type for this title. Wherever it went, that is the fact
  // worth counting — a fallback here is the right answer, not a miss.
  if (label.no_family) return "no_family";
  if (record.observed_route === label.exact) return "exact";
  if (label.acceptable.includes(record.observed_route)) return "acceptable";
  if (record.observed_route === GENERIC_FALLBACK) return "fallback";
  return "wrong";
}

export type RoutingCounts = Record<RoutingOutcome, number>;
const zero = (): RoutingCounts => ({
  exact: 0,
  acceptable: 0,
  wrong: 0,
  fallback: 0,
  no_family: 0,
});

export type RoutingMeasure = {
  /** Records measured. */
  n: number;
  counts: RoutingCounts;
  /** Each count over `n`; null when there are no records. */
  shares: Record<RoutingOutcome, number | null>;
  /** The same counts per labelled type (`exact`), sorted by type id. */
  per_family: Array<{ family: string; n: number; counts: RoutingCounts }>;
  /** Types with at least one real document labelled to them. */
  families_with_documents: number;
  /** Types in the catalog. */
  families_total: number;
  caveats: string[];
};

/**
 * Printed with the number, every time — including when there is no number.
 * `zeroFamilies` of `total` types have no real document behind them.
 */
export function routingCaveats(zeroFamilies: number, total: number): string[] {
  return [
    "The title is both the label and the classifier's strongest feature, so this is an upper bound for well-titled documents.",
    "EDGAR is large-company commercial paper, as HTML. It says nothing about residential leases, consumer documents, court filings, or PDF and DOCX ingest.",
    `Document types with zero real documents: ${zeroFamilies} of ${total}.`,
  ];
}

export function measureRouting(
  records: readonly RoutingRecord[],
  labels: readonly RoutingLabel[],
  /** Every type id in the catalog, the fallback excluded. */
  catalog: readonly string[],
): RoutingMeasure {
  const table = new Map(labels.map((l) => [l.label, l]));
  const counts = zero();
  const families = new Map<string, { n: number; counts: RoutingCounts }>();
  for (const record of records) {
    const label = table.get(record.label);
    if (!label)
      throw new Error(`routing record ${record.accession} names unknown label "${record.label}"`);
    const outcome = routingOutcome(record, label);
    counts[outcome] += 1;
    if (label.exact) {
      const f = families.get(label.exact) ?? { n: 0, counts: zero() };
      f.n += 1;
      f.counts[outcome] += 1;
      families.set(label.exact, f);
    }
  }
  const n = records.length;
  const shares = Object.fromEntries(
    ROUTING_OUTCOMES.map((o) => [o, n === 0 ? null : counts[o] / n]),
  ) as RoutingMeasure["shares"];
  const withDocs = [...families.keys()].filter((id) => catalog.includes(id)).length;
  return {
    n,
    counts,
    shares,
    per_family: [...families.entries()]
      .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
      .map(([family, f]) => ({ family, ...f })),
    families_with_documents: withDocs,
    families_total: catalog.length,
    caveats: routingCaveats(catalog.length - withDocs, catalog.length),
  };
}

/** Labels that name a type the catalog does not have — a stale table row. */
export function unknownLabelTargets(
  labels: readonly RoutingLabel[],
  catalog: readonly string[],
): string[] {
  const known = new Set(catalog);
  return labels
    .flatMap((l) => [...(l.exact ? [l.exact] : []), ...l.acceptable].map((id) => [l.label, id]))
    .filter(([, id]) => !known.has(id!))
    .map(([label, id]) => `${label} → ${id}`);
}

export type RoutingSample = { labels: RoutingLabel[]; records: RoutingRecord[] };

/** Read `corpus/routing/labels.json` and `corpus/routing/records/*.json`. */
export async function loadRoutingSample(corpusDir: string): Promise<RoutingSample> {
  const dir = join(corpusDir, "routing");
  const labelsPath = join(dir, "labels.json");
  const labels = existsSync(labelsPath)
    ? RoutingLabelTableSchema.parse(JSON.parse(await readFile(labelsPath, "utf8")))
    : [];
  const recordsDir = join(dir, "records");
  const records: RoutingRecord[] = [];
  if (existsSync(recordsDir)) {
    for (const name of (await readdir(recordsDir)).filter((f) => f.endsWith(".json")).sort()) {
      records.push(
        RoutingRecordSchema.parse(JSON.parse(await readFile(join(recordsDir, name), "utf8"))),
      );
    }
  }
  return { labels, records };
}
