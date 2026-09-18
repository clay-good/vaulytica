/**
 * The per-document-type data behind `/review/<playbook-id>` and `/reviews`.
 *
 * One page per document type the engine recognizes, listing the checks that
 * actually run on it. The set is computed from the same two things the
 * runner reads (`src/engine/runner.ts`): a rule runs on a playbook unless the
 * playbook's `rule_overrides` skips it, or the rule's `applies_to_playbooks`
 * names other playbooks. Rules added only on an explicit assertion (the
 * filing, privacy-notice and estate packs) are not in the default catalog and
 * are not listed.
 *
 * `npm run site:doc-types` writes `tools/site/doc-types.json`;
 * `tests/integration/site-doc-types.test.ts` fails when it is stale.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { LAUNCH_RULES } from "../../src/engine/rules/index.js";
import { V3_RULES } from "../../src/engine/rules/v3/index.js";
import { V4_RULES } from "../../src/engine/rules/v4/index.js";
import { V5_RULES } from "../../src/engine/rules/v5/index.js";
import { V6_RULES } from "../../src/engine/rules/v6/index.js";

export interface DocTypeCheck {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly severity: string;
}

export interface DocType {
  readonly id: string;
  readonly name: string;
  readonly group: string;
  readonly summary: string;
  readonly checks: ReadonlyArray<DocTypeCheck>;
  readonly general_checks: number;
  readonly companions: ReadonlyArray<string>;
  readonly sources: ReadonlyArray<{ readonly title: string; readonly url: string }>;
}

export interface DocTypesData {
  readonly types: ReadonlyArray<DocType>;
  /** Group headings in the order the landing page lists them. */
  readonly groups: ReadonlyArray<string>;
  /** Deprecated playbook id → the playbook that superseded it. */
  readonly superseded: Readonly<Record<string, string>>;
}

interface RawPlaybook {
  id: string;
  name: string;
  description: string;
  deprecated?: boolean;
  superseded_by?: string;
  rule_overrides?: Record<string, { skip?: boolean }>;
  companion_playbooks?: string[];
  sources?: Array<string | { source?: string; source_url?: string }>;
}

/**
 * Playbook descriptions end with an engine-internal selector ("Selects the
 * COMM-140..145 ruleset (6 checks).") that means nothing to a reader. Keep
 * what it covers, drop the selector.
 */
export function publicSummary(description: string): string {
  return (
    description
      // Packs that run only on request: say what the reader does, not the flag.
      .replace(
        /\s*Selects the [^.]*?--estate-checks[^.]*\./,
        " Estate-planning checks run when you turn them on in the estate panel.",
      )
      .replace(
        /\s*Selects the [^.]*?--court[^.]*\./,
        " Court-filing format checks run when you choose a court profile.",
      )
      .replace(/\s*Contract-lint rules are suppressed[^.]*\./, "")
      // Rule-id ranges and spec references mean nothing to a reader.
      .replace(/\s*\([^()]*\b[A-Z]{2,7}-\d{1,3}[^()]*\)/g, "")
      .replace(/\bv\d lints prose only\b/g, "only the prose is checked")
      .replace(/Per spec §[\d.A-Z]+ caveat:\s*([a-z])/g, (_m, c: string) => c.toUpperCase())
      // "Selects the … ruleset: a, b, c." / "… covering a, b, c." → keep the list.
      .replace(
        /\s*Selects the [^.:]*?(?::\s*|\s+covering\s+)([\s\S]*?)\.(?=\s+[A-Z][a-z]|\s*$)/,
        (_m, covering: string) => ` Checks cover ${covering}.`,
      )
      .replace(/\s*Selects the [\s\S]*?\.(?=\s+[A-Z][a-z]|\s*$)/, "")
      .replace(/\s*Replaces v\d[^.]*\./g, "")
      .replace(/\s*Companion:[^.]*\./g, "")
      .replace(
        /v2's dark-patterns ruleset is also active on this surface/,
        "Dark-pattern checks also run",
      )
      .replace(/Re-runs the §\d+ DPA-GDPR ruleset/, "Also runs the GDPR Article 28 checks")
      .replace(/against the §\d+ default/, "against a default")
      // A sentence that is a note to maintainers (a DKB file, a follow-up
      // commit, an internal id in backticks) is dropped whole. Sentences end
      // at a period after a lowercase letter or bracket, so "U.S.C. §" holds.
      .split(/(?<=[a-z)\]']\.)\s+(?=[A-Z])/)
      .filter((s) => !/DKB|follow-up commit|`|ruleset of its own/.test(s))
      .join(" ")
      .trim()
  );
}

function loadPlaybooks(root: string): RawPlaybook[] {
  const dir = join(root, "playbooks");
  const out: RawPlaybook[] = [];
  for (const file of readdirSync(dir).sort()) {
    if (!file.endsWith(".json")) continue;
    const parsed = JSON.parse(readFileSync(join(dir, file), "utf8")) as unknown;
    out.push(...((Array.isArray(parsed) ? parsed : [parsed]) as RawPlaybook[]));
  }
  return out;
}

/** Group headings as the landing page's document-type index states them. */
function groupsFromLanding(root: string): Map<string, string> {
  const html = readFileSync(join(root, "site", "index.html"), "utf8");
  const byName = new Map<string, string>();
  for (const g of html.matchAll(/<h3>([^<]+?) <span>\d+<\/span><\/h3>\s*<ul>([\s\S]*?)<\/ul>/g)) {
    const group = g[1]!.replace(/&amp;/g, "&");
    for (const li of g[2]!.matchAll(/<li>([^<]+)<\/li>/g)) {
      byName.set(li[1]!.trim().replace(/&amp;/g, "&"), group);
    }
  }
  return byName;
}

export function buildDocTypes(root: string = process.cwd()): DocTypesData {
  const rules = [...LAUNCH_RULES, ...V3_RULES, ...V4_RULES, ...V5_RULES, ...V6_RULES];
  const playbooks = loadPlaybooks(root);
  const groups = groupsFromLanding(root);
  const names = new Map(playbooks.map((p) => [p.id, p.name]));
  const superseded: Record<string, string> = {};
  const types: DocType[] = [];
  for (const p of playbooks) {
    if (p.id === "generic-fallback") continue;
    if (p.deprecated && p.superseded_by) {
      superseded[p.id] = p.superseded_by;
      continue;
    }
    const runs = rules.filter((r) => !p.rule_overrides?.[r.id]?.skip);
    const specific = runs
      .filter((r) => r.applies_to_playbooks?.includes(p.id))
      .sort((a, b) => a.id.localeCompare(b.id));
    const general = runs.filter((r) => !r.applies_to_playbooks?.length).length;
    types.push({
      id: p.id,
      name: p.name,
      group: groups.get(p.name) ?? "Other",
      summary: publicSummary(p.description),
      checks: specific.map((r) => ({
        id: r.id,
        name: r.name,
        description: r.description,
        severity: r.default_severity,
      })),
      general_checks: general,
      companions: (p.companion_playbooks ?? []).filter((c) => names.has(c) && c !== p.id),
      sources: (p.sources ?? [])
        .filter(
          (s): s is { source: string; source_url: string } =>
            typeof s === "object" && !!s.source && !!s.source_url,
        )
        .map((s) => ({ title: s.source, url: s.source_url })),
    });
  }
  types.sort((a, b) => a.id.localeCompare(b.id));
  return { types, groups: [...new Set(groups.values())], superseded };
}

export const serializeDocTypes = (d: DocTypesData): string => JSON.stringify(d, null, 1) + "\n";
