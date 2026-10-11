/**
 * Generate the id list the report Worker carries (spec-v53 §5).
 *
 * The endpoint accepts a `rule` or a `type` only if it is an id in the shipped
 * catalog, so a custom playbook's ids are refused even if a client sends
 * them. `npm run reports:ids` rewrites the list; a test fails when it drifts.
 */

import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { listDocumentTypes, ruleCatalog } from "../cli/api.js";

export async function catalogIds(): Promise<{ rules: string[]; types: string[] }> {
  const rules = [...ruleCatalog().keys()].sort();
  const types: string[] = [];
  for (let offset: number | undefined = 0; offset !== undefined; ) {
    const page = await listDocumentTypes({ offset, limit: 100 });
    types.push(...page.types.map((t) => t.id));
    offset = page.next_offset;
  }
  return { rules, types: types.sort() };
}

export const CATALOG_IDS_PATH = join(process.cwd(), "workers", "reports", "src", "catalog-ids.json");

if (process.argv[1]?.endsWith("write-catalog-ids.ts")) {
  const ids = await catalogIds();
  await writeFile(CATALOG_IDS_PATH, JSON.stringify(ids) + "\n");
  console.log(`Wrote ${ids.rules.length} rule ids and ${ids.types.length} document types`);
}
