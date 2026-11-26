/**
 * Tier-2 firing evidence for `rule-liveness.test.ts` (enforce-rule-liveness).
 *
 * The 363 documents in `tests/fixtures/specimens` are WELL-DRAFTED documents.
 * That is what makes them the right corpus for routing, extraction and the
 * absence rules — and it is exactly why they cannot be the whole liveness
 * corpus: a rule that exists to report a DEFECT has nothing to find in a clean
 * document, so it runs on all 363 and stays silent, which is indistinguishable
 * from being dead. Measured before this file existed: 117 catalog rules fired
 * on no specimen.
 *
 * So tier 2 is a small set of deliberately defective documents — plus, for the
 * handful of rules that read something plain text cannot carry, the gate option
 * or the Word-only formatting they need. Each entry is a CONTEXT THE GUARD
 * RUNS, never a reason: an entry that stops making its rules fire fails the
 * build, which is what keeps this list from drifting into an excuse table.
 */

import { readFile, readdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ingestPaste } from "../../src/ingest/paste.js";
import { normalize, countWords } from "../../src/ingest/normalize.js";
import { extractAll } from "../../src/extract/index.js";
import { loadStarterDkbSync } from "../../src/engine/_test-fixtures.js";
import { COURT_PROFILES } from "../../src/filing/court-profile.js";
import { READABILITY_STANDARDS } from "../../src/readability/standards.js";
import type { DocumentTree } from "../../src/ingest/types.js";
import type { RuleContext } from "../../src/engine/finding.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..", "..");
export const SPECIMEN_DIR = join(REPO_ROOT, "tests", "fixtures", "specimens");
export const LIVENESS_DIR = join(REPO_ROOT, "tests", "fixtures", "liveness");

/**
 * Every opt-in gate asserted at once.
 *
 * The packs are dormant without these — `readFilingOptions` returns undefined
 * and every FILE rule answers `null`, which would read as eight dead rules.
 * Asserting all of them in one bundle is not a realistic run (nobody picks a
 * court profile AND a Florida insurance readability standard), but liveness
 * asks whether an input exists that makes the rule speak, and the gates are
 * independent, so one bundle answers for all of them.
 */
export function allGatesAsserted(word_count: number): Record<string, unknown> {
  return {
    filing: {
      profile: COURT_PROFILES["frap-default"]!,
      brief_kind: "principal" as const,
      word_count,
      source: "paste" as const,
    },
    readability_standard: READABILITY_STANDARDS.find((s) => s.id === "fl"),
    estate_checks_asserted: true,
  };
}

/** A gate bundle with one readability standard swapped in by id. */
export function withReadabilityStandard(
  base: Record<string, unknown>,
  id: string,
): Record<string, unknown> {
  const std = READABILITY_STANDARDS.find((s) => s.id === id);
  if (!std) throw new Error(`no readability standard "${id}"`);
  return { ...base, readability_standard: std };
}

/**
 * Attach Word-only run formatting to every paragraph.
 *
 * `carriesFormatting()` is the bail-out for the TEXT rules: without run
 * formatting every run reports `bold: false`, which is the ABSENCE of the
 * information and not a notice set in regular type, so the rules correctly
 * stand down. A pasted tree never carries it. This decorator is the smallest
 * thing that makes a pasted document answer the question a .docx would.
 */
export function asWordFile(opts: { size_pt?: number; displayed_caps?: boolean } = {}) {
  return (tree: DocumentTree): DocumentTree => {
    const walk = (sections: DocumentTree["sections"]): DocumentTree["sections"] =>
      sections.map((s) => ({
        ...s,
        paragraphs: s.paragraphs.map((p) => ({
          ...p,
          ...(opts.size_pt === undefined ? {} : { min_size_pt: opts.size_pt }),
          ...(opts.displayed_caps === undefined ? {} : { displayed_caps: opts.displayed_caps }),
          runs: p.runs.map((r) => ({ ...r, formatting: { ...(r.formatting ?? {}), bold: false } })),
        })),
        children: walk(s.children),
      }));
    return { ...tree, sections: walk(tree.sections) };
  };
}

export type LivenessFixture = {
  /** File under `tests/fixtures/liveness/`. */
  file: string;
  /** The defect family this document carries, for the failure message. */
  note: string;
  /** Gate options; defaults to {@link allGatesAsserted}. */
  options?: (word_count: number) => Record<string, unknown>;
  /** Tree transform for the Word-only cases. */
  decorate?: (tree: DocumentTree) => DocumentTree;
};

/**
 * Tier-2 documents. Order is irrelevant — a rule is live if ANY of them fires
 * it — but each file is kept to one defect family so a failure names a subject.
 */
export const LIVENESS_FIXTURES: readonly LivenessFixture[] = [
  { file: "defects-structural.txt", note: "numbering, dates, amounts, obligors" },
  { file: "defects-choice-venue.txt", note: "governing law, venue, arbitration" },
  // A SECOND venue clause that contradicts the first. CHOICE-004 and CHOICE-009
  // both read `jurisdictions.find(venue)` — the first venue only — and go quiet
  // when it matches the governing law; CHOICE-012 scans every venue entry, so it
  // is the only rule that sees a later carve-out pointing somewhere else. That
  // is a real drafting defect (an IP or trademark carve-out copied from another
  // template) and it wants its own document, because any fixture where the FIRST
  // venue already mismatches makes CHOICE-004 fire and shadows CHOICE-012 again.
  { file: "defects-multi-venue.txt", note: "a later venue clause contradicts the first" },
  { file: "defects-dark-patterns.txt", note: "consumer dark patterns" },
  { file: "defects-proofreading.txt", note: "typography and proofreading" },
  { file: "defects-commercial.txt", note: "MSA / SOW / DPA / BAA defects" },
  { file: "defects-corporate.txt", note: "governance, equity, M&A" },
  { file: "defects-employment.txt", note: "employment and personnel" },
  { file: "defects-estate.txt", note: "wills, trusts, estate checks" },
  { file: "defects-real-estate.txt", note: "real property and transfer" },
  { file: "defects-regulated.txt", note: "insurance, banking, privacy regimes" },
  { file: "defects-litigation.txt", note: "pleadings, discovery, citations" },
  {
    file: "defects-uncaptioned-consumer.txt",
    note: "consumer agreement with no section captions",
    options: (wc) => withReadabilityStandard(allGatesAsserted(wc), "ny-consumer"),
  },
  {
    file: "defects-mandated-text.txt",
    note: "mandated notices, as a Word file sets them",
    decorate: asWordFile({ size_pt: 6 }),
  },
];

export type BuiltContext = { label: string; ctx: RuleContext };

const dkb = loadStarterDkbSync();

/**
 * A document with a real section OUTLINE.
 *
 * `numbered_label` is read off a section's HEADING (`extract/sections.ts`), and
 * a pasted document has almost no headings: `buildTreeFromText` promotes a line
 * to a heading only on a `#` marker or a Setext underline, and the all-caps
 * fallback runs only for a document with no blank line anywhere. So every
 * committed `.txt` specimen — all 363 — arrives as ONE untitled section, and
 * the rules that compare section numbers to each other have nothing to compare.
 * They are not blind; they are reading a structure that only a .docx or a PDF
 * outline carries.
 *
 * This is that structure, built directly, with the four defects those rules
 * exist to report: a number out of order, a duplicate, a dotted-decimal gap,
 * and a table of contents naming a section that does not exist.
 */
function outlinedDocumentTree(): DocumentTree {
  const section = (heading: string, ...texts: string[]) => ({
    id: "",
    heading,
    level: 1,
    paragraphs: texts.map((text) => ({ id: "", runs: [{ id: "", text, start: 0, end: 0 }] })),
    children: [],
  });
  return normalize({
    type: "document",
    sections: [
      section(
        "TABLE OF CONTENTS",
        "1. Definitions",
        "2. Services",
        "4. Fees",
        "9. Confidentiality",
        "12. Dispute Resolution",
      ),
      section(
        "1. Definitions",
        '"Services" means the services described in each Statement of Work.',
      ),
      section("4. Fees", "Customer shall pay the fees set out in Schedule 1."),
      section("2. Services", "Provider shall perform the Services with reasonable care and skill."),
      section("4. Fees", "Customer shall pay each invoice within thirty days of receipt."),
      section("5.1 Reports", "Provider shall deliver a monthly report."),
      section("5.4 Records", "Provider shall retain the records for seven years."),
      section(
        "6. Execution",
        "This Agreement is executed under seal and acknowledged before a notary public, and is witnessed by two witnesses.",
      ),
    ],
  });
}

/** Build a rule context from document text, the way the pipeline does. */
export async function contextFromText(
  text: string,
  opts: {
    label: string;
    options?: (word_count: number) => Record<string, unknown>;
    decorate?: (tree: DocumentTree) => DocumentTree;
    playbook?: string;
  },
): Promise<BuiltContext> {
  const ingest = await ingestPaste(text);
  const tree = opts.decorate ? opts.decorate(ingest.tree) : ingest.tree;
  const extracted = extractAll(tree, {
    classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
  });
  const buildOptions = opts.options ?? allGatesAsserted;
  return {
    label: opts.label,
    ctx: {
      tree,
      extracted,
      dkb,
      playbook: { id: opts.playbook ?? "generic-fallback", version: "1.0.0" },
      options: buildOptions(ingest.word_count),
    },
  };
}

/** Tier 1 — the committed specimens, every gate asserted. */
export async function tier1Contexts(): Promise<BuiltContext[]> {
  const files = (await readdir(SPECIMEN_DIR)).filter((f) => f.endsWith(".txt")).sort();
  const out: BuiltContext[] = [];
  for (const f of files) {
    const text = await readFile(join(SPECIMEN_DIR, f), "utf8");
    out.push(await contextFromText(text, { label: `specimen:${f}` }));
  }
  return out;
}

/** Build a context around an already-built tree (the synthesized fixtures). */
function contextFromTree(tree: DocumentTree, label: string): BuiltContext {
  const extracted = extractAll(tree, {
    classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
  });
  return {
    label,
    ctx: {
      tree,
      extracted,
      dkb,
      playbook: { id: "generic-fallback", version: "1.0.0" },
      options: allGatesAsserted(countWords(tree)),
    },
  };
}

/** Fixtures that are a tree, not a document — see {@link outlinedDocumentTree}. */
export const SYNTHESIZED_FIXTURES: ReadonlyArray<{ label: string; build: () => DocumentTree }> = [
  { label: "synthesized:outlined-document", build: outlinedDocumentTree },
];

/** Tier 2 — the deliberately defective documents, and the synthesized trees. */
export async function tier2Contexts(): Promise<BuiltContext[]> {
  const out: BuiltContext[] = [];
  for (const fx of LIVENESS_FIXTURES) {
    const text = await readFile(join(LIVENESS_DIR, fx.file), "utf8");
    out.push(
      await contextFromText(text, {
        label: `liveness:${fx.file}`,
        options: fx.options,
        decorate: fx.decorate,
      }),
    );
  }
  for (const fx of SYNTHESIZED_FIXTURES) out.push(contextFromTree(fx.build(), fx.label));
  return out;
}
