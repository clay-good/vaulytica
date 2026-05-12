/**
 * Playbook loading helpers. Browser builds fetch JSON over HTTP; tests
 * and the DKB build pipeline read straight from disk.
 *
 * Every loaded playbook is validated against {@link PlaybookSchema}
 * before being returned so a corrupted file cannot poison the runner.
 */

import { PlaybookSchema, type Playbook } from "./types.js";

export function parsePlaybook(raw: unknown): Playbook {
  return PlaybookSchema.parse(raw);
}

export function parsePlaybooks(raw: unknown[]): Playbook[] {
  return raw.map(parsePlaybook);
}

/**
 * Fetch and validate a list of playbooks from a base URL. Filenames
 * are joined as `${base}/${id}.json` so the on-disk directory shape
 * (`playbooks/<id>.json`) is preserved.
 */
export async function fetchPlaybooks(
  base: string,
  ids: readonly string[],
  fetchImpl: typeof fetch = fetch,
): Promise<Playbook[]> {
  const out: Playbook[] = [];
  for (const id of ids) {
    const url = `${base.replace(/\/$/, "")}/${id}.json`;
    const res = await fetchImpl(url);
    if (!res.ok) {
      throw new Error(`failed to fetch playbook ${id}: ${res.status} ${res.statusText}`);
    }
    out.push(parsePlaybook(await res.json()));
  }
  return out;
}
