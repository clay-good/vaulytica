/**
 * Deterministic playbook matcher (spec §19, build step 8).
 *
 * The matcher scores the document against every playbook's
 * `match_features` and returns the highest-scoring playbook. If no
 * playbook scores above {@link MATCH_THRESHOLD}, the fallback id
 * (`generic-fallback`) is returned. All matching is case-insensitive
 * and substring-based on whitespace-normalized text.
 *
 * Scoring is referentially transparent: no randomness, no time, no IO.
 */

import type { ClassifiedParagraph, ExtractedData } from "../extract/types.js";
import {
  GENERIC_FALLBACK_ID,
  MATCH_THRESHOLD,
  MATCH_WEIGHTS,
  type Playbook,
  type PlaybookMatchAlternative,
  type PlaybookMatchResult,
} from "./types.js";

/**
 * The title-ish corpus the playbook matcher scores `title_keywords` against.
 *
 * `matchPlaybook` documents this as "the first heading plus the preamble
 * paragraph". The pipeline had been passing only the first section's
 * heading, with `?? file.name` as the fallback — and `??` catches null and
 * undefined, not the **empty string** the tree builder actually produces for
 * a document with no styled heading. Every plain-text or pasted document,
 * and every DOCX whose title is bold body text rather than a Heading style,
 * therefore reached the matcher with an empty title.
 *
 * The consequence was silent and large: title keywords are the single
 * biggest contributor to a playbook score (0.3, against 0.2 per
 * distinguishing phrase), so a document that names itself in its first line
 * lost that entire signal. A short, unambiguous engagement letter scored
 * 0.4 and fell to `generic-fallback`; the same text with the title seen
 * scores 0.7 and routes correctly.
 *
 * The preamble is capped because it is a *title* corpus, not a body one:
 * an unbounded first paragraph would let an incidental mention of another
 * family's title keyword outrank the document's own name.
 */
export const TITLE_PREAMBLE_CHARS = 240;

/**
 * How far into the document a letter's subject line may sit and still be
 * read as its title. A letter reaches its "Re:" line only after the
 * letterhead, the date, a delivery legend, and the recipient's address
 * block — several paragraphs, but always near the top. The bound keeps a
 * "Re:" appearing deep in the body (a quoted piece of correspondence, an
 * exhibit) from being mistaken for the document's own subject.
 */
export const TITLE_SUBJECT_SCAN_PARAGRAPHS = 12;

/**
 * A letter states its title in its subject line, not in a heading.
 *
 * `titleCorpus` reads the first heading plus the first paragraph, which is
 * right for a document whose name is at the top — and exactly wrong for a
 * letter, whose first paragraph is the sender's letterhead. A reservation-
 * of-rights letter reached the matcher as "Meridian Casualty Insurance
 * Company Claims Department 4400 Harbor Point Drive", matched no title
 * keyword of any playbook, scored 0.4 on two distinguishing phrases, and
 * fell to `generic-fallback` — while the line the drafter wrote to say what
 * the document IS, "Re: Reservation of Rights — Claim No. …", was never
 * looked at. Every letter-shaped family has the same hole: the WARN notice,
 * the demand letter, the litigation hold, the preliminary lien notice, the
 * termination-of-representation letter.
 *
 * "Re:" and "Subject:" are the conventions; "In re:" is the caption form.
 * The test is anchored to the start of the paragraph so a mid-sentence
 * "with respect to" or a defined term ending in "re" cannot trigger it.
 */
const SUBJECT_LINE = /^\s*(?:re|subject|in\s+re)\s*:\s*(\S.*)$/is;

/**
 * The document's first lines, in order, bounded and trimmed.
 *
 * A section's heading is emitted ahead of its paragraphs because a filing's
 * caption may arrive either way: pasted or plain text puts the court line in
 * the first paragraph, while a DOCX that styles it reaches the tree as a
 * heading. Both are the document's first line, and the caption walk has to
 * see it in both shapes.
 */
function leadingLines(
  sections: readonly {
    heading?: string;
    paragraphs: readonly { runs: readonly { text: string }[] }[];
  }[],
): string[] {
  const out: string[] = [];
  const push = (text: string): boolean => {
    if (out.length >= TITLE_SUBJECT_SCAN_PARAGRAPHS) return false;
    out.push(text.trim());
    return true;
  };
  for (const section of sections) {
    const heading = (section.heading ?? "").trim();
    if (heading.length > 0 && !push(heading)) return out;
    for (const paragraph of section.paragraphs) {
      if (!push(paragraph.runs.map((r) => r.text).join(""))) return out;
    }
  }
  return out;
}

function subjectLine(
  sections: readonly {
    heading?: string;
    paragraphs: readonly { runs: readonly { text: string }[] }[];
  }[],
): string {
  for (const text of leadingLines(sections)) {
    const m = SUBJECT_LINE.exec(text);
    if (m) return m[1]!.trim().slice(0, TITLE_PREAMBLE_CHARS);
  }
  return "";
}

/**
 * A negotiated agreement wears its legends above its title.
 *
 * "EXECUTION VERSION", "CONFIDENTIAL", "PRIVILEGED AND CONFIDENTIAL —
 * ATTORNEY WORK PRODUCT", "DRAFT — FOR DISCUSSION PURPOSES ONLY": these sit on
 * the first line of a very large share of real deal documents, and the
 * preamble the matcher read was therefore the legend. A **mutual** NDA
 * carrying "EXECUTION VERSION" over "MUTUAL NON-DISCLOSURE AGREEMENT" routed
 * to `unilateral-nda` — the mutual playbook's title keyword never hit, and the
 * unilateral one won on "the Disclosing Party" / "the Receiving Party", which
 * a mutual NDA uses too because each party is both.
 *
 * A legend is recognized as a WHOLE line built only of legend tokens and
 * separators, so a title that merely contains one of the words is untouched:
 * "CONFIDENTIALITY AGREEMENT" is a title, "CONFIDENTIAL" is a legend.
 *
 * A restrictive-securities legend hides it the same way, and is a different
 * shape: not a stamp but a whole uppercase SENTENCE. "THIS NOTE AND THE
 * SECURITIES ISSUABLE UPON CONVERSION HEREOF HAVE NOT BEEN REGISTERED UNDER
 * THE SECURITIES ACT OF 1933 …" opens essentially every note, warrant, SAFE,
 * and stock certificate. It cost a genuine convertible promissory note its
 * routing: `promissory-note` matched the title keyword "note" — from the word
 * "NOTE" inside the legend — while "CONVERTIBLE PROMISSORY NOTE", the line
 * below it, was never read, so every conversion check (valuation cap,
 * discount, qualified financing, change-of-control premium) was skipped. A
 * document title is short and carries no sentence-ending period; a legend
 * paragraph is long and does, so that is the test, and it is applied only to
 * uppercase text so an ordinary mixed-case preamble is untouched.
 *
 * A bare container marker — "EXHIBIT A", "SCHEDULE 1", "ANNEX B" — hides the
 * title the same way, and an agreement attached as an exhibit is one of the
 * commonest things a reviewer drops in. It is dropped only when the marker and
 * its designator are the WHOLE line: "EXHIBIT A — FORM OF MUTUAL NDA" carries
 * the title and is kept. No playbook's title keywords begin with one of these
 * words, so nothing loses a signal.
 */
const LEGEND_TOKEN =
  /execution\s+(?:version|copy)|conformed\s+copy|final\s+(?:version|form)|drafts?|confidential(?:ity)?|privileged|proprietary|trade\s+secrets?|attorney[-\s]work[-\s]product|attorney[-\s]client\s+privileged?|work\s+product|for\s+(?:discussion|settlement|negotiation)\s+purposes\s+only|subject\s+to\s+(?:protective\s+order|review|contract|revision)|confidential\s+treatment\s+requested|do\s+not\s+(?:copy|distribute|file)|not\s+for\s+distribution/;
const LEGEND_LINE = new RegExp(
  String.raw`^[\s\-–—*|/[\]()]*(?:(?:${LEGEND_TOKEN.source})[\s\-–—*|/,;:[\]()]*(?:and[\s\-–—*|/,;:]*)?)+$`,
  "i",
);

/**
 * Longest an uppercase, sentence-punctuated line may be and still be read as a
 * title rather than a legend paragraph. Real titles run well under this even
 * when they are long ("AMENDED AND RESTATED LIMITED LIABILITY COMPANY
 * OPERATING AGREEMENT"), and they do not end in a period.
 */
const LEGEND_SENTENCE_CHARS = 120;

function isLegendSentence(line: string): boolean {
  return (
    line.length > LEGEND_SENTENCE_CHARS &&
    /[.;]$/.test(line) &&
    /[A-Z]/.test(line) &&
    line === line.toUpperCase()
  );
}

const CONTAINER_MARKER =
  /^(?:exhibit|schedule|annex|appendix|attachment)\s+[A-Za-z0-9][A-Za-z0-9.-]*[\s.:—–-]*$/i;

/** Drop the leading legend lines so the document's own title is first. */
function dropLegends(lines: readonly string[]): string[] {
  let i = 0;
  while (
    i < lines.length &&
    (lines[i]!.length === 0 ||
      LEGEND_LINE.test(lines[i]!) ||
      CONTAINER_MARKER.test(lines[i]!) ||
      isLegendSentence(lines[i]!))
  )
    i += 1;
  return lines.slice(i);
}

/**
 * A court filing names itself BELOW its caption.
 *
 * The first paragraph of a filing is the court ("IN THE UNITED STATES
 * DISTRICT COURT FOR THE NORTHERN DISTRICT OF ILLINOIS"), followed by the
 * party block, the docket number, and the judge — and only then the line that
 * says what the document is. So the preamble the matcher reads is the name of
 * a courthouse, which is identical for a complaint, an answer, a motion to
 * compel, and a set of interrogatory responses.
 *
 * The cost is the same as the letterhead's: a defendant's responses and
 * objections to interrogatories matched no title keyword, scored 0.6 on
 * "plaintiff", "venue", and "jury" — three words every filing contains — and
 * routed to `complaint`, which then reported at `critical` that the document
 * had no jurisdictional statement, no demand for relief, and no jury demand.
 * It is a discovery response. It is not supposed to have any of them.
 *
 * The caption's shape is a strong convention, so the scaffolding is skipped
 * rather than the title guessed: a party name (an uppercase line ending in a
 * comma), a bare role designation, and the docket/judge line are each
 * recognizable, and the first paragraph that is none of them is the filing's
 * title. Engaged only when the document opens on a court line, so nothing that
 * is not a filing is touched.
 */
const CAPTION_COURT = /^[^.]{0,160}\bcourt\b[^.]{0,80}$/i;
const CAPTION_ROLE =
  /^\s*(?:v\.|vs\.|-v-|plaintiffs?|defendants?|petitioners?|respondents?|appellants?|appellees?|movants?|debtors?|intervenors?|claimants?|cross-?(?:claimants?|defendants?)|third-?party\s+(?:plaintiffs?|defendants?))\b[\s,.:;)-]*$/i;
const CAPTION_DOCKET =
  /\b(?:case|civil\s+action|index|docket|cause|file)\s+no\b|\bhon\.|\bjudge\b/i;

function captionTitle(paragraphs: readonly string[]): string {
  if (paragraphs.length === 0 || !CAPTION_COURT.test(paragraphs[0]!)) return "";
  for (const text of paragraphs.slice(1)) {
    if (text.length === 0) continue;
    if (CAPTION_ROLE.test(text)) continue;
    if (CAPTION_DOCKET.test(text)) continue;
    // A party name in the caption block. The test used to also require the
    // line to be entirely uppercase, which a caption with more than one party
    // on a side is not: "CORVUS SYSTEMS CORPORATION and MARISOL ANDRADE,"
    // carries a lowercase "and", so the walk stopped there and handed the
    // matcher the defendants' names as the filing's title. A stipulated
    // protective order captioned that way routed to `mutual-nda` at 0.9 and
    // was told it had no governing law, no liability cap, no IP allocation,
    // and no termination-for-cause clause. It is a court order.
    //
    // The comma alone is the test now: a document's title never ends in one,
    // and a party line, a role designation, and an entity descriptor ("ACME
    // CORP., a Delaware corporation,") all do. The walk is engaged only under
    // a court line, and skipping every line still lands on the first line that
    // is not caption scaffolding — the title.
    if (text.endsWith(",")) continue;
    return text.slice(0, TITLE_PREAMBLE_CHARS);
  }
  return "";
}

export function titleCorpus(
  tree: {
    sections: readonly {
      heading?: string;
      paragraphs: readonly { runs: readonly { text: string }[] }[];
    }[];
  },
  fallback: string,
): string {
  const first = tree.sections[0];
  const heading = (first?.heading ?? "").trim();
  const paragraphs = (first?.paragraphs ?? []).slice(0, TITLE_SUBJECT_SCAN_PARAGRAPHS).map((p) =>
    p.runs
      .map((r) => r.text)
      .join("")
      .trim(),
  );
  const preamble = (dropLegends(paragraphs)[0] ?? "").slice(0, TITLE_PREAMBLE_CHARS);
  const subject = subjectLine(tree.sections);
  const caption = captionTitle(dropLegends(leadingLines(tree.sections)));
  const parts = [heading, preamble, subject, caption].filter((p) => p.length > 0);
  return parts.length > 0 ? parts.join(" ") : fallback;
}

export type MatchInput = {
  /**
   * A title-ish corpus drawn from the document — typically the first
   * heading plus the preamble paragraph. Title-keyword features are
   * matched against this string, case-insensitively.
   */
  title?: string;
  /**
   * Distinguishing-phrase and negative-feature features are matched
   * against this whole-document text. If absent, the matcher falls
   * back to the title.
   */
  body_text?: string;
};

type ScoredPlaybook = {
  playbook: Playbook;
  /** Raw additive score before clamping; used for ranking. */
  raw_score: number;
  /** Score clamped to [0, 1] for external display. */
  score: number;
  matched_title_keywords: string[];
  matched_required_clauses: string[];
  matched_distinguishing_phrases: string[];
  matched_negative_features: string[];
};

/**
 * Pick the best playbook for the document.
 *
 * Weights per spec §26 step 8:
 *  - title keyword match: +0.3 each
 *  - required clause match: +0.4 each
 *  - distinguishing phrase match: +0.2 each
 *  - negative feature match: -0.1 each
 *
 * Each contribution is normalized by the count of that feature type on
 * the playbook so a playbook with many required clauses does not
 * automatically outscore one with few. The final score is bounded to
 * [0, 1] after summation, then compared to {@link MATCH_THRESHOLD}.
 *
 * Ties are broken lexicographically by playbook id for determinism.
 */
/**
 * Longest feature string still treated as an ACRONYM for matching purposes.
 * "psa", "eula", "g701", "daca" are the forms a document actually prints; a
 * longer string is a phrase, and a phrase's substring match is what lets
 * "conflicts of interest" find "Conflicts of Interest Policy".
 */
const ACRONYM_MAX_LENGTH = 5;

/**
 * Match a feature string against a corpus.
 *
 * Features are matched as plain substrings, which is right for a phrase and
 * wrong for an acronym: `change-order` listed **"co"**, which appears inside
 * "Company", "Contract", "Counsel", and "Cost", so it collected a title
 * keyword's 0.3 from almost any document. The same shape sits in "sig"
 * (inside "assignment", "signature"), "spa" (inside "space"), "apa" (inside
 * "apartment"), "ccr" (inside "accrue"), and "safe" (inside "safeguard" and
 * "safe harbor") — a class the catalog acquired one acronym at a time.
 *
 * A short feature is therefore matched on word boundaries. "CO" standing
 * alone in a change order's title still matches; "Company" no longer does.
 */
function contains(corpus: string, feature: string): boolean {
  const needle = feature.toLowerCase();
  if (needle.length === 0) return false;
  if (needle.length > ACRONYM_MAX_LENGTH || !/^[a-z0-9][a-z0-9.-]*$/.test(needle)) {
    return corpus.includes(needle);
  }
  const escaped = needle.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(?:^|[^a-z0-9])${escaped}(?![a-z0-9])`, "i").test(corpus);
}

export function matchPlaybook(
  extracted: ExtractedData,
  classified: ClassifiedParagraph[],
  available: readonly Playbook[],
  input: MatchInput = {},
): PlaybookMatchResult {
  const title = (input.title ?? "").toLowerCase();
  const body = (input.body_text ?? input.title ?? "").toLowerCase();
  const present_categories = new Set(classified.map((c) => c.category));
  const defined_terms = new Set(extracted.definitions.entries.map((e) => e.term.toLowerCase()));

  const scored: ScoredPlaybook[] = available.map((playbook) => {
    const f = playbook.match_features;

    const matched_title_keywords = f.title_keywords.filter((kw) => contains(title, kw));
    const matched_required_clauses = f.required_clauses.filter(
      (cat) => present_categories.has(cat) || defined_terms.has(cat.toLowerCase()),
    );
    const matched_distinguishing_phrases = f.distinguishing_phrases.filter((p) =>
      contains(body, p),
    );
    const matched_negative_features = f.negative_features.filter((n) => contains(body, n));

    // Per-match additive scoring, with each feature category capped so
    // playbooks with many keywords don't auto-dominate playbooks with
    // few. Title and required-clause contributions cap at 2x their
    // weight; distinguishing phrases cap at 3x to reward several
    // independent textual hits.
    const tkw_score = Math.min(
      matched_title_keywords.length * MATCH_WEIGHTS.title_keyword,
      MATCH_WEIGHTS.title_keyword * 2,
    );
    const req_score = Math.min(
      matched_required_clauses.length * MATCH_WEIGHTS.required_clause,
      MATCH_WEIGHTS.required_clause * 2,
    );
    const dist_score = Math.min(
      matched_distinguishing_phrases.length * MATCH_WEIGHTS.distinguishing_phrase,
      MATCH_WEIGHTS.distinguishing_phrase * 3,
    );
    const neg_penalty = matched_negative_features.length * MATCH_WEIGHTS.negative_feature;

    const raw = tkw_score + req_score + dist_score + neg_penalty;
    const score = clamp(raw, 0, 1);

    return {
      playbook,
      raw_score: raw,
      score,
      matched_title_keywords,
      matched_required_clauses,
      matched_distinguishing_phrases,
      matched_negative_features,
    };
  });

  scored.sort((a, b) => {
    if (b.raw_score !== a.raw_score) return b.raw_score - a.raw_score;
    // Tiebreak 1: prefer non-deprecated over deprecated. Lets a
    // `*-deep` successor outrank its legacy v2 sibling when both
    // score identically.
    const aDep = a.playbook.deprecated === true;
    const bDep = b.playbook.deprecated === true;
    if (aDep !== bDep) return aDep ? 1 : -1;
    // Tiebreak 2: lexicographic id for determinism.
    return a.playbook.id.localeCompare(b.playbook.id, "en");
  });

  const top = scored[0];
  const alternatives: PlaybookMatchAlternative[] = scored.slice(1, 4).map((s) => ({
    playbook_id: s.playbook.id,
    confidence: round3(s.score),
  }));

  if (!top || top.playbook.id === GENERIC_FALLBACK_ID || top.score < MATCH_THRESHOLD) {
    return {
      playbook_id: GENERIC_FALLBACK_ID,
      confidence: top ? round3(top.score) : 0,
      alternatives: top
        ? scored
            .slice(0, 3)
            .filter((s) => s.playbook.id !== GENERIC_FALLBACK_ID)
            .map((s) => ({ playbook_id: s.playbook.id, confidence: round3(s.score) }))
        : [],
      reasoning: buildFallbackReasoning(top),
    };
  }

  return {
    playbook_id: top.playbook.id,
    confidence: round3(top.score),
    alternatives,
    reasoning: buildReasoning(top),
  };
}

function clamp(n: number, lo: number, hi: number): number {
  if (n < lo) return lo;
  if (n > hi) return hi;
  return n;
}

function round3(n: number): number {
  return Math.round(n * 1000) / 1000;
}

function buildReasoning(s: ScoredPlaybook): string {
  const parts: string[] = [];
  parts.push(`Selected ${s.playbook.id} (score ${round3(s.score)}).`);
  if (s.matched_title_keywords.length > 0) {
    parts.push(`Title matched: ${quote(s.matched_title_keywords)}.`);
  }
  if (s.matched_required_clauses.length > 0) {
    parts.push(`Required clauses present: ${quote(s.matched_required_clauses)}.`);
  }
  if (s.matched_distinguishing_phrases.length > 0) {
    parts.push(`Distinguishing phrases: ${quote(s.matched_distinguishing_phrases)}.`);
  }
  if (s.matched_negative_features.length > 0) {
    parts.push(`Negative features penalized: ${quote(s.matched_negative_features)}.`);
  }
  return parts.join(" ");
}

function buildFallbackReasoning(top: ScoredPlaybook | undefined): string {
  if (!top) {
    return `No playbooks supplied; using ${GENERIC_FALLBACK_ID}.`;
  }
  if (top.playbook.id === GENERIC_FALLBACK_ID) {
    return `Top-scoring entry is the fallback itself (${round3(top.score)}); using ${GENERIC_FALLBACK_ID}.`;
  }
  return `Best score was ${top.playbook.id} at ${round3(top.score)}, below the ${MATCH_THRESHOLD} threshold; using ${GENERIC_FALLBACK_ID}.`;
}

function quote(items: string[]): string {
  return items.map((i) => `"${i}"`).join(", ");
}
