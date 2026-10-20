import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit } from "../_helpers.js";
import { scanParagraphs } from "./_scan.js";

/** The corporate forms a party's name ends in, each in the spellings a drafter uses. */
const SUFFIX = String.raw`Incorporated|Inc|Corporation|Corp|Company|Co|Limited|Ltd|L\.?L\.?C|L\.?L\.?P|L\.?P|P\.?L\.?L\.?C|P\.?C`;
const NAMED = new RegExp(`^(.+?),?\\s+(?:${SUFFIX})\\.?$`, "i");

/** A suffix's spelling with case and punctuation set aside: "L.L.C." and "LLC" are one. */
const spelling = (s: string): string => s.toLowerCase().replace(/[.\s]/g, "");
/** The corporate form each spelling writes; two spellings of one form are the drift. */
const FORM: Record<string, string> = {
  inc: "inc",
  incorporated: "inc",
  corp: "corp",
  corporation: "corp",
  co: "co",
  company: "co",
  ltd: "ltd",
  limited: "ltd",
};
const escape = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export type NameDrift = { core: string; forms: string[]; at: number; length: number };

/**
 * Each party the document names with two spellings of one corporate form:
 * "Acme Corp." and "Acme Corporation", "Acme Inc." and "Acme Incorporated".
 * Two DIFFERENT forms are not compared: "Acme Holdings, Inc." and "Acme
 * Holdings LLC" are as often a parent and its subsidiary as one name drifted.
 *
 * Read from the text, not from the extractor's party list: the extractor
 * keeps one name per party, and the drift is in the other places the name
 * is written. Both occurrences must state a form — "Acme" for "Acme Corp." is
 * the short name every agreement defines, and CROSS-PARTY-001 makes the same
 * call across documents. Case and punctuation are not spellings, so a
 * signature block's "ACME CORP" and a comma before "Inc." move nothing.
 */
export function partyNameDrift(names: readonly string[], text: string): NameDrift[] {
  const out: NameDrift[] = [];
  const seen = new Set<string>();
  for (const name of names) {
    const core = NAMED.exec(name.trim())?.[1]?.trim();
    if (!core || core.length < 3 || seen.has(core.toLowerCase())) continue;
    seen.add(core.toLowerCase());
    const re = new RegExp(
      `(?<![\\w&])${escape(core).replace(/\s+/g, "\\s{1,3}")},?\\s{1,3}(${SUFFIX})(?!\\w)\\.?`,
      "gi",
    );
    // Spellings seen, grouped by the form they write.
    const byForm = new Map<string, Map<string, { text: string; at: number }>>();
    for (const m of text.matchAll(re)) {
      const key = spelling(m[1]!);
      const form = FORM[key];
      if (!form) continue;
      const spellings = byForm.get(form) ?? new Map<string, { text: string; at: number }>();
      if (!spellings.has(key)) spellings.set(key, { text: m[0], at: m.index! });
      byForm.set(form, spellings);
    }
    for (const spellings of byForm.values()) {
      if (spellings.size < 2) continue;
      const [, second] = [...spellings.values()];
      out.push({
        core,
        forms: [...spellings.values()].map((f) => f.text),
        at: second!.at,
        length: second!.text.length,
      });
    }
  }
  return out;
}

/** PROOF-004 — Party name written two ways (warning). */
export const rule: Rule = {
  id: "PROOF-004",
  version: "1.0.0",
  name: "Party name written two ways",
  category: "proofreading",
  default_severity: "warning",
  description:
    'Flags a party whose corporate form the document spells two ways, such as "Acme Corp." and "Acme Corporation".',
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const paragraphs = scanParagraphs(ctx, (text) => [{ at: 0, length: text.length, detail: "" }]);
    const starts: number[] = [];
    let joined = "";
    for (const p of paragraphs) {
      starts.push(joined.length);
      joined += `${p.text}\n`;
    }
    const names = ctx.extracted.parties.flatMap((p) => [p.name, ...(p.aliases ?? [])]);
    const hits = partyNameDrift(names, joined);
    if (hits.length === 0) return null;
    const first = hits[0]!;
    let i = starts.length - 1;
    while (i > 0 && starts[i]! > first.at) i -= 1;
    const p = paragraphs[i]!;
    const local = first.at - starts[i]!;
    return emit(ctx, rule, {
      title: `Party name written two ways (${hits.length})`,
      description: `The document names one party as ${first.forms.map((f) => `"${f}"`).join(" and ")}.`,
      excerpt: p.text,
      explanation:
        "A party's legal name is how a court, a lender or a registry identifies it; two corporate forms for one name read as two entities, and a notice or a lien filed under the wrong one can miss.",
      recommendation: `Use one legal name throughout — the one the party's formation records show — and define a short name for the rest.`,
      position: {
        ...p.position,
        start: p.position.start + local,
        end: p.position.start + local + first.length,
      },
    });
  },
};
