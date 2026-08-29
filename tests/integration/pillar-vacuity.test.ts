/**
 * A conjunction may not rest on a pillar the family's own TITLE satisfies.
 *
 * `v34-title-vacuity.test.ts` asks whether a WHOLE rule is satisfied by its
 * family's title. A conjunction never is — the other pillars fail — so that
 * guard cannot see the failure one level down: a pillar met by the title
 * contributes nothing, and the check silently collapses onto whatever pillars
 * are left.
 *
 * That is where the unsatisfiable-by-compliance defects concentrate. Three of
 * the worst this catalog has had were exactly this shape:
 *
 *   - `GOV-071` conjoined "501(c)(3)" — inside the family title "Nonprofit
 *     Bylaws (501(c)(3))" — with two spellings a recital does not use.
 *   - `EMP-032` conjoined "proprietary information", the whole first half of
 *     "Employee Proprietary Information and Inventions Agreement", with
 *     "non-disclosure", which the agreement never says.
 *   - `MNA-055` conjoined "transition services" with two more spellings of the
 *     same fact, in the `transition-services-agreement` pack.
 *
 * The list below is the remaining population: conjunctions whose surviving
 * pillars are believed to carry the check, but which have not each been proved
 * with a hand-written compliant clause. It is DEBT, and it may only shrink.
 * Take an entry off by proving the rule silent on a compliant clause in
 * `compliant-conjunctions.test.ts` and either splitting the vacuous pillar out
 * or replacing it with a form the title cannot satisfy.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const CATALOG = JSON.parse(
  readFileSync(join(process.cwd(), "playbooks", "extended.json"), "utf8"),
) as Array<{ id: string; name: string; match_features: { title_keywords: string[] } }>;

/**
 * Conjunctions with a pillar the family's title already satisfies. Reviewed,
 * not yet proved. May only shrink.
 */
const KNOWN_COLLAPSED = new Set<string>([
  "BNK-127",
  "COMM-231",
  "COMM-237",
  "DISC-001",
  "DISC-007",
  "DISC-017",
  "DISC-020",
  "DISC-024",
  "DISC-030",
  "DISC-036",
  "EMP-101",
  "EMP-110",
  "EMP-121",
  "EMP-148",
  "EMP-150",
  "ENG-006",
  "ENG-008",
  "ENG-016",
  "ENG-018",
  "ENG-021",
  "ENG-024",
  "ENG-027",
  "ENG-028",
  "ENG-029",
  "EST-401",
  "EST-426",
  "GOV-101",
  "HC-127",
  "PLDG-006",
  "PLDG-009",
  "PLDG-012",
  "PRV-102",
  "PRV-113",
  "SET-106",
]);

const files: string[] = [];
const walk = (dir: string): void => {
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) walk(p);
    else if (p.endsWith(".ts") && !p.endsWith(".test.ts")) files.push(p);
  }
};
walk(join(process.cwd(), "src", "engine", "rules"));

/** The object literal containing `text[idAt]`, by brace balance. */
function objectAt(text: string, idAt: number): string {
  const start = text.lastIndexOf("{", idAt);
  let depth = 0;
  for (let i = start; i < text.length; i++) {
    if (text[i] === "{") depth += 1;
    else if (text[i] === "}") {
      depth -= 1;
      if (depth === 0) return text.slice(start, i + 1);
    }
  }
  return "";
}

/** The regex literals of a `pat:` / `present_patterns:` array. */
function pillars(block: string, key: string): RegExp[] | null {
  const m = new RegExp(`${key}:\\s*\\[`).exec(block);
  if (!m) return null;
  let i = m.index + m[0].length;
  let depth = 1;
  const start = i;
  for (; i < block.length && depth > 0; i += 1) {
    if (block[i] === "[") depth += 1;
    else if (block[i] === "]") depth -= 1;
  }
  const out: RegExp[] = [];
  for (const line of block.slice(start, i - 1).split("\n")) {
    const t = line.trim();
    if (t.startsWith("//") || t.startsWith("*")) continue;
    const rm = /^\/((?:\\.|\[(?:\\.|[^\]])*\]|[^/\\])+)\/([a-z]*)\s*,?$/.exec(t);
    if (rm) {
      try {
        out.push(new RegExp(rm[1]!, rm[2]));
      } catch {
        /* a pattern this crude parser cannot rebuild is skipped, not failed */
      }
    }
  }
  return out;
}

function collapsedConjunctions(): string[] {
  const byId = new Map(CATALOG.map((p) => [p.id, p]));
  const found: string[] = [];
  for (const file of files) {
    const text = readFileSync(file, "utf8");
    for (const pk of text.matchAll(/\bpack\(\s*"([a-z0-9-]+)"/g)) {
      const pb = byId.get(pk[1]!);
      if (!pb) continue;
      const title = `${pb.name} ${pb.match_features.title_keywords.join(" ")}`;
      const next = text.indexOf("pack(", pk.index! + 5);
      const region = text.slice(pk.index!, next === -1 ? text.length : next);
      for (const m of region.matchAll(/\bid: "([A-Z]+-\d+)",/g)) {
        const block = objectAt(region, m.index!);
        const pats = pillars(block, "pat") ?? pillars(block, "present_patterns");
        if (!pats || pats.length < 2) continue;
        if (!/(?:require_all_present|all):\s*true/.test(block)) continue;
        if (pats.some((re) => re.test(title))) found.push(m[1]!);
      }
    }
  }
  return [...new Set(found)].sort();
}

describe("a conjunction does not rest on a pillar its family's title satisfies", () => {
  const collapsed = collapsedConjunctions();

  it("the sweep found conjunctions to look at", () => {
    expect(collapsed.length, "the parser is broken — it found nothing").toBeGreaterThan(10);
  });

  it("no NEW conjunction has collapsed onto its remaining pillars", () => {
    const added = collapsed.filter((id) => !KNOWN_COLLAPSED.has(id));
    expect(
      added,
      `a pillar of these is satisfied by the family's own title, so the check has collapsed onto whatever pillars are left:\n  ${added.join("\n  ")}`,
    ).toEqual([]);
  });

  it("every listed conjunction is still collapsed, so the list cannot outlive its entries", () => {
    const live = new Set(collapsed);
    const stale = [...KNOWN_COLLAPSED].filter((id) => !live.has(id)).sort();
    expect(
      stale,
      `these are repaired — take them off KNOWN_COLLAPSED:\n  ${stale.join("\n  ")}`,
    ).toEqual([]);
  });
});
