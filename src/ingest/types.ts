/**
 * Shared ingest types. The contract between the ingest layer and the
 * extractor layer is the {@link DocumentTree}: a normalized, stable-IDed
 * tree produced from a PDF, DOCX, or pasted-text input.
 *
 * Determinism contract: every node has a stable id derived deterministically
 * from its position in the tree, not from a counter. Character offsets are
 * contiguous within the flat string representation produced by
 * {@link flattenTree}.
 */

export type FormattingHint = {
  bold?: boolean;
  italic?: boolean;
  underline?: boolean;
};

export type Run = {
  /** Stable id, e.g. `s2.p3.r1`. */
  id: string;
  text: string;
  /** Inclusive start offset of this run's text within the flattened document. */
  start: number;
  /** Exclusive end offset. `end - start === text.length`. */
  end: number;
  formatting?: FormattingHint;
};

export type Paragraph = {
  /** Stable id, e.g. `s2.p3`. */
  id: string;
  runs: Run[];
  /**
   * The smallest point size the paragraph's text is set in.
   *
   * From a DOCX only where the file determines it (a run's own size, its
   * character or paragraph style, or the document defaults); from a PDF text
   * layer, the smallest size its text items render at. Absent for pasted text,
   * which carries no sizes at all, and for a DOCX whose style chain never
   * states one.
   */
  min_size_pt?: number;
  /**
   * The file DISPLAYS this paragraph in capitals (`w:caps` / `w:smallCaps`),
   * whatever case its stored text is in.
   *
   * Only a DOCX can answer this. A Word user who applies All Caps formatting —
   * the ordinary way to do it — leaves the stored text mixed case, so a rule
   * reading the text's own case cannot see that the document shows capitals.
   * Absent for pasted text and for a PDF text layer, which carry no such
   * property, and absent for a DOCX paragraph that is not caps-formatted.
   */
  displayed_caps?: boolean;
};

export type Section = {
  /** Stable id, e.g. `s2`. */
  id: string;
  /** Heading text, or `""` for the root / unheaded preamble section. */
  heading: string;
  /** 1..N, where 1 is the top level. The root document has level 0. */
  level: number;
  paragraphs: Paragraph[];
  children: Section[];
};

export type DocumentTree = {
  type: "document";
  /** Top-level sections. The root document itself is implicit. */
  sections: Section[];
};

export type IngestSource = "pdf" | "docx" | "paste";

export type IngestResult = {
  tree: DocumentTree;
  source: IngestSource;
  word_count: number;
  page_count?: number;
  language?: string;
  /** Lowercase hex SHA-256 of the source bytes (or UTF-8 bytes of pasted text). */
  sha256: string;
  warnings: string[];
};

/**
 * Walk a tree in document order and concatenate every run's text. Used by
 * normalize to assign contiguous offsets, and by downstream consumers that
 * need a flat representation.
 */
export function flattenText(tree: DocumentTree): string {
  let out = "";
  const walk = (sections: Section[]): void => {
    for (const s of sections) {
      if (s.heading) out += s.heading + "\n";
      for (const p of s.paragraphs) {
        for (const r of p.runs) out += r.text;
        out += "\n";
      }
      walk(s.children);
    }
  };
  walk(tree.sections);
  return out;
}

/** Stable run id from section / paragraph / run indices. */
export function makeRunId(sectionId: string, paragraphIndex: number, runIndex: number): string {
  return `${sectionId}.p${paragraphIndex}.r${runIndex}`;
}

export function makeParagraphId(sectionId: string, paragraphIndex: number): string {
  return `${sectionId}.p${paragraphIndex}`;
}

export function makeSectionId(path: number[]): string {
  return "s" + path.join(".");
}
