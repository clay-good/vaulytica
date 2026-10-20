/**
 * The contract abstract and the inventory (add-contract-abstract-inventory).
 *
 * The first table every diligence builds by hand: one row per agreement, with
 * its type, parties, effective date, term, renewal, governing law, forum and
 * cap. Every one of those facts is already extracted for every document; this
 * module only PROJECTS them, with the section each was read from, and a blank
 * where the extractor found nothing — never a guess.
 *
 * Render-side and namespaced: nothing here enters `result_hash`.
 * `inventory_hash` is its own SHA-256 over the canonical rows, so the same
 * folder yields the same inventory on any machine. Nothing relative to the
 * clock enters it; an expiry is printed only when the document's own dates
 * resolve it.
 */

import type { EngineRun } from "../engine/finding.js";
import { stableStringify } from "../engine/runner.js";
import { extractAll } from "../extract/index.js";
import { sectionLabels } from "../extract/sections.js";
import type { DocumentTree } from "../ingest/types.js";
import { flattenText } from "../ingest/types.js";
import { sha256Hex } from "../ingest/hash.js";
import type { ExtractedData } from "../extract/types.js";
import { resolveAnchors } from "./critical-dates.js";
import { ABSTRACT_STATEMENT } from "./disclaimers.js";
import { csvField } from "./exports.js";

/** One cell: the value as the document states it, and where it was read. */
export type AbstractCell = { value: string; section?: string };

export type AbstractParty = { name: string; role?: string; formation?: string; section?: string };

export type DocumentAbstract = {
  file: string;
  /** The type the document routed to; `unmatched` when none did. */
  document_type: string;
  document_type_label: string;
  title: string;
  parties: AbstractParty[];
  effective_date?: AbstractCell;
  /** The auto-renewal clause as TEMP-004 reads it; absent when none was found. */
  renewal?: AbstractCell;
  governing_law?: AbstractCell;
  forum?: AbstractCell;
  /** Capped / uncapped / no cap clause, as the liability rules read it; absent when they did not run. */
  liability_cap?: AbstractCell;
  /**
   * The sentence that says whether the instrument itself may be assigned,
   * verbatim and truncated. QUOTED, not classified: "Buyer may assign to an
   * affiliate" beside "neither party may assign without consent" is a reading
   * a person makes, and a label that misread it would be a wrong fact in the
   * one table a diligence trusts.
   */
  assignment?: AbstractCell;
  /** `mentioned` when that sentence names a change of control, a merger or a sale of substantially all assets. */
  change_of_control?: AbstractCell;
  word_count: number;
  result_hash: string;
};

/** A file that could not be read, listed so the inventory accounts for every input. */
export type NotAnalyzed = { file: string; reason: string };

export type Inventory = {
  statement: string;
  rows: DocumentAbstract[];
  not_analyzed: NotAnalyzed[];
  /** For each column, how many rows carry a value — a rarely filled column is visible as such. */
  coverage: Record<string, number>;
  /** SHA-256 over the canonical rows. Independent of every `result_hash`. */
  inventory_hash: string;
};

const FALLBACK = "generic-fallback";

/** The abstract of one analyzed document. Pure in its inputs. */
export async function buildDocumentAbstract(input: {
  file: string;
  tree: DocumentTree;
  run: EngineRun;
  playbookName: string;
  title: string;
}): Promise<DocumentAbstract> {
  const { tree, run } = input;
  const extracted = extractAll(tree);
  const labelOf = sectionLabels(tree);
  const clauseOf = clauseNumbers(tree);
  // Where a cell was read: the section's heading when the document has one,
  // else the clause number its paragraph (or the nearest numbered paragraph
  // above it) starts with — a pasted document carries its headings as
  // numbered paragraphs, and "§ 9.2" is what a reader can find.
  const at = (position: { section_id?: string; paragraph_id?: string } | undefined) => {
    const section = labelOf(position?.section_id) ?? clauseOf(position?.paragraph_id);
    return section ? { section } : {};
  };

  const parties = extracted.parties.slice(0, 12).map((p) => ({
    name: p.name,
    ...(p.role ? { role: p.role } : {}),
    ...(p.jurisdiction_of_formation ? { formation: p.jurisdiction_of_formation } : {}),
    ...at(p.positions[0]),
  }));

  // The defined Effective Date when the document has one; else the date its
  // preamble says it is made, entered into or dated ("made as of June 3, 2026").
  const effective =
    resolveAnchors(extracted, tree).get("effective date") ?? preambleDate(tree, extracted);

  const finding = (id: string) => run.findings.find((f) => f.rule_id === id);
  const renewalFinding = finding("TEMP-004");
  const renewal: AbstractCell | undefined = renewalFinding
    ? {
        value: renewalFinding.title,
        ...(renewalFinding.excerpt.section_label
          ? { section: renewalFinding.excerpt.section_label }
          : {}),
      }
    : undefined;

  const law = extracted.jurisdictions.find((j) => j.clause_kind === "governing-law");
  const venue = extracted.jurisdictions.find(
    (j) => j.clause_kind === "venue" || j.clause_kind === "arbitration-seat",
  );

  const ranRule = (id: string) => run.execution_log.some((e) => e.rule_id === id && e.ran === true);
  const uncapped = finding("RISK-009");
  const noCap = finding("RISK-005");
  const liability_cap: AbstractCell | undefined = uncapped
    ? {
        value: "uncapped",
        ...(uncapped.excerpt.section_label ? { section: uncapped.excerpt.section_label } : {}),
      }
    : noCap
      ? { value: "no cap clause found" }
      : ranRule("RISK-005")
        ? { value: "capped" }
        : undefined;

  const assigned = assignmentSentence(tree);
  const assignment: AbstractCell | undefined = assigned
    ? { value: assigned.sentence, ...at({ paragraph_id: assigned.paragraphId }) }
    : undefined;
  const change_of_control: AbstractCell | undefined =
    assigned && CHANGE_OF_CONTROL.test(assigned.sentence)
      ? { value: "mentioned", ...at({ paragraph_id: assigned.paragraphId }) }
      : undefined;

  const matched = run.playbook_id !== FALLBACK;
  return {
    file: input.file,
    document_type: matched ? run.playbook_id : "unmatched",
    document_type_label: matched ? input.playbookName : "No type matched",
    title: input.title,
    parties,
    ...(effective ? { effective_date: { value: effective } } : {}),
    ...(renewal ? { renewal } : {}),
    ...(law ? { governing_law: { value: law.raw_text, ...at(law.position) } } : {}),
    ...(venue
      ? {
          forum: {
            value:
              venue.clause_kind === "arbitration-seat"
                ? `${venue.raw_text} (arbitration)`
                : venue.raw_text,
            ...at(venue.position),
          },
        }
      : {}),
    ...(liability_cap ? { liability_cap } : {}),
    ...(assignment ? { assignment } : {}),
    ...(change_of_control ? { change_of_control } : {}),
    word_count: flattenText(tree).split(/\s+/).filter(Boolean).length,
    result_hash: run.result_hash,
  };
}

/** The columns, in order, and how each reads a row. Shared by the CSV and the coverage count. */
const COLUMNS: ReadonlyArray<[string, (a: DocumentAbstract) => string]> = [
  ["file", (a) => a.file],
  ["document_type", (a) => a.document_type],
  ["document_type_label", (a) => a.document_type_label],
  ["title", (a) => a.title],
  ["parties", (a) => a.parties.map((p) => (p.role ? `${p.name} (${p.role})` : p.name)).join("; ")],
  ["effective_date", (a) => a.effective_date?.value ?? ""],
  ["renewal", (a) => a.renewal?.value ?? ""],
  ["renewal_section", (a) => a.renewal?.section ?? ""],
  ["governing_law", (a) => a.governing_law?.value ?? ""],
  ["governing_law_section", (a) => a.governing_law?.section ?? ""],
  ["forum", (a) => a.forum?.value ?? ""],
  ["forum_section", (a) => a.forum?.section ?? ""],
  ["liability_cap", (a) => a.liability_cap?.value ?? ""],
  ["assignment", (a) => a.assignment?.value ?? ""],
  ["assignment_section", (a) => a.assignment?.section ?? ""],
  ["change_of_control", (a) => a.change_of_control?.value ?? ""],
  ["word_count", (a) => String(a.word_count)],
  ["result_hash", (a) => a.result_hash],
];

/** Every abstract in title order, the unreadable files, the coverage, and the hash. */
export async function buildInventory(
  abstracts: readonly DocumentAbstract[],
  notAnalyzed: readonly NotAnalyzed[] = [],
): Promise<Inventory> {
  const rows = [...abstracts].sort((a, b) =>
    a.title < b.title ? -1 : a.title > b.title ? 1 : a.file < b.file ? -1 : 1,
  );
  const not_analyzed = [...notAnalyzed].sort((a, b) => (a.file < b.file ? -1 : 1));
  const coverage: Record<string, number> = {};
  for (const [name, read] of COLUMNS) coverage[name] = rows.filter((r) => read(r) !== "").length;
  return {
    statement: ABSTRACT_STATEMENT,
    rows,
    not_analyzed,
    coverage,
    inventory_hash: await sha256Hex(stableStringify({ rows, not_analyzed })),
  };
}

/**
 * The inventory as CSV. Line one is the header, because a spreadsheet and the
 * CLI's stream contract both read it as one. Line two is the only non-data
 * row: what the file is, then how many rows fill each column. Then one row
 * per document, and one per file that could not be read. Every cell goes
 * through the shared formula-injection guard, because a title or a party
 * name is the document's text.
 */
export function buildInventoryCsv(inventory: Inventory): string {
  const n = inventory.rows.length;
  const lines = [
    COLUMNS.map(([name]) => csvField(name)).join(","),
    COLUMNS.map(([name], i) =>
      csvField(
        i === 0 ? `${inventory.statement} Filled, of ${n}:` : String(inventory.coverage[name] ?? 0),
      ),
    ).join(","),
    ...inventory.rows.map((r) => COLUMNS.map(([, read]) => csvField(read(r))).join(",")),
    ...inventory.not_analyzed.map((x) =>
      COLUMNS.map(([name]) =>
        csvField(
          name === "file"
            ? x.file
            : name === "document_type"
              ? "not analyzed"
              : name === "title"
                ? x.reason
                : "",
        ),
      ).join(","),
    ),
  ];
  return lines.join("\r\n") + "\r\n";
}

/** The inventory as JSON, canonical so two renders are byte-identical. */
export function buildInventoryJson(inventory: Inventory): string {
  return JSON.stringify(JSON.parse(stableStringify(inventory)), null, 2) + "\n";
}

/** A paragraph id → the clause number it, or the nearest numbered paragraph above it, starts with. */
function clauseNumbers(
  tree: DocumentTree,
): (paragraphId: string | undefined) => string | undefined {
  const byId = new Map<string, string>();
  const walk = (sections: DocumentTree["sections"]): void => {
    for (const section of sections) {
      let current: string | undefined;
      for (const p of section.paragraphs) {
        const text = p.runs.map((r) => r.text).join("");
        const m =
          /^\s{0,4}(?:(?:Section|Article|Clause)\s+)?(\d{1,3}(?:\.\d{1,3}){0,3})[.)]?\s/i.exec(
            text,
          );
        if (m) current = `§ ${m[1]}`;
        if (current) byId.set(p.id, current);
      }
      walk(section.children);
    }
  };
  walk(tree.sections);
  return (id) => (id ? byId.get(id) : undefined);
}

/** The date the preamble says the document is made, entered into or dated — its first three paragraphs. */
function preambleDate(tree: DocumentTree, extracted: ExtractedData): string | undefined {
  const first = new Set<string>();
  for (const section of tree.sections) {
    for (const p of section.paragraphs) {
      if (first.size >= 3) break;
      first.add(p.id);
    }
    if (first.size >= 3) break;
  }
  const paragraphText = new Map<string, string>();
  for (const section of tree.sections)
    for (const p of section.paragraphs) paragraphText.set(p.id, p.runs.map((r) => r.text).join(""));
  for (const d of extracted.dates) {
    if (d.type !== "absolute" || !d.iso || !first.has(d.position.paragraph_id ?? "")) continue;
    // A position is an offset into the whole document, so the date is found in
    // its own paragraph by its text.
    const text = paragraphText.get(d.position.paragraph_id ?? "") ?? "";
    const at = text.indexOf(d.raw_text);
    if (at < 0) continue;
    const before = text.slice(Math.max(0, at - 60), at);
    if (
      /\b(?:dated|as\s+of|made\s+on|entered\s+into\s+on|effective(?:\s+as\s+of|\s+on)?)\s+(?:this\s+)?$/i.test(
        before,
      )
    )
      return d.iso;
  }
  return undefined;
}

/** The instrument itself — "this Agreement", "the Lease" — as the thing assigned. */
const INSTRUMENT = String.raw`(?:this|the|these)\s+(?:\w+\s+){0,2}?(?:Agreement|Lease|Sublease|Contract|License|Licence|Terms|Note|Guaranty)`;
const ASSIGNS_INSTRUMENT = new RegExp(
  String.raw`\bassign(?:\s+or\s+(?:transfer|delegate))?\s+(?:\w+\s+){0,3}?${INSTRUMENT}\b|\b${INSTRUMENT}[^.]{0,60}\b(?:may|shall|will)\s+not\s+be\s+assigned|\btransfer\s+${INSTRUMENT}\b`,
  "i",
);
/** A sentence that RESTRICTS assignment — the general rule, not a one-sided permission. */
const RESTRICTS =
  /\b(?:may|shall|will|must|can)\s*not\b|\bneither\b|\bno\s+party\b|\bwithout\s+(?:the\s+)?(?:\w+(?:['’]s?)?\s+){0,4}?(?:prior\s+)?(?:written\s+)?(?:consent|approval)\b/i;
const CHANGE_OF_CONTROL =
  /\bchange\s+(?:of|in)\s+control\b|\bmerger\b|\bconsolidation\b|\b(?:sale|transfer)\s+of\s+(?:all\s+or\s+)?substantially\s+all\b/i;

/**
 * The sentence about assigning the instrument: the first that restricts it,
 * else the first that mentions it. Measured over the 363 specimens: 63 have
 * one, 57 of them the restricting rule; the rest are documents with no
 * assignment clause, which is a blank, not a guess.
 */
function assignmentSentence(
  tree: DocumentTree,
): { sentence: string; paragraphId: string } | undefined {
  let first: { sentence: string; paragraphId: string } | undefined;
  const walk = (
    sections: DocumentTree["sections"],
  ): { sentence: string; paragraphId: string } | undefined => {
    for (const section of sections) {
      for (const p of section.paragraphs) {
        const text = p.runs
          .map((r) => r.text)
          .join("")
          .replace(/\s+/g, " ");
        for (const sentence of text.split(/(?<=[.;])\s+(?=[A-Z(])/)) {
          if (!ASSIGNS_INSTRUMENT.test(sentence)) continue;
          const hit = { sentence: cut(sentence.trim(), 220), paragraphId: p.id };
          if (RESTRICTS.test(sentence)) return hit;
          first ??= hit;
        }
      }
      const inner = walk(section.children);
      if (inner) return inner;
    }
    return undefined;
  };
  return walk(tree.sections) ?? first;
}

/** At most `n` characters, cut at a word and marked. */
function cut(text: string, n: number): string {
  if (text.length <= n) return text;
  const at = text.lastIndexOf(" ", n - 1);
  return `${text.slice(0, at > 0 ? at : n - 1)}…`;
}
