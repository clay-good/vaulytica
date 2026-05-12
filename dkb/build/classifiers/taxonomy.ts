/**
 * Loader + alias resolver for `classifier_taxonomy.json` (spec §13).
 *
 * Input clauses arrive labeled with whatever CUAD/LEDGAR called them.
 * The taxonomy collapses those into ~80 canonical categories. The
 * reconciliation is deterministic: aliases are matched after
 * `slugify`, and the first matching canonical wins. Unknown labels
 * pass through with a `slugify` normalization so the orchestrator can
 * surface them in the regression report.
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";

export const TaxonomyEntrySchema = z.object({
  canonical: z.string().min(1),
  aliases: z.array(z.string().min(1)),
});

export const TaxonomyFileSchema = z.object({
  schema_version: z.string().min(1),
  description: z.string(),
  categories: z.array(TaxonomyEntrySchema),
});

export type Taxonomy = z.infer<typeof TaxonomyFileSchema>;

export function parseTaxonomy(raw: string): Taxonomy {
  return TaxonomyFileSchema.parse(JSON.parse(raw));
}

export async function loadTaxonomy(path?: string): Promise<Taxonomy> {
  const p = path ?? join(process.cwd(), "dkb", "build", "classifier_taxonomy.json");
  return parseTaxonomy(await readFile(p, "utf8"));
}

/** Build a fast alias → canonical lookup table. */
export function buildAliasMap(t: Taxonomy): Map<string, string> {
  const m = new Map<string, string>();
  for (const e of t.categories) {
    m.set(slugify(e.canonical), e.canonical);
    for (const a of e.aliases) m.set(slugify(a), e.canonical);
  }
  return m;
}

export function reconcileCategory(label: string, aliases: Map<string, string>): string {
  const slug = slugify(label);
  return aliases.get(slug) ?? slug;
}

export function slugify(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}
