/**
 * Family-gated match-candidate selection (spec-v6 — full-catalog wiring).
 *
 * Wiring the v3 + v4 playbooks into the live pipeline means the matcher
 * could, in principle, route a plain NDA or MSA to one of the ~123
 * specialized playbooks. The sub-domain classifier is only ~70% accurate
 * (build-frontier note), so handing it all ~135 candidates risks
 * regressing today's common-document routing.
 *
 * This module gates the candidate set: the 12 launch playbooks are *always*
 * candidates (today's behavior is preserved when nothing specialized is
 * detected), and a specialized (v3/v4) playbook is admitted **only when the
 * document carries a strong, specific signal for that family** — a title
 * keyword in the title region, or several distinguishing phrases in the
 * body. A document that doesn't clearly belong to a specialized family
 * never sees those playbooks as candidates, so it matches exactly as it
 * does today; a document that clearly does (a "Business Associate
 * Agreement", an "Asset Purchase Agreement", corporate "Bylaws") unlocks
 * that family's deeper rules.
 *
 * Admission is a *gate*, not the final decision: an admitted playbook still
 * has to outscore the launch match in {@link matchPlaybook} to win. The gate
 * only protects against a specialized playbook winning on coincidental,
 * generic signal. Pure function — deterministic, no IO.
 */

import type { ClassifiedParagraph, ExtractedData } from "../extract/types.js";
import type { Playbook } from "../playbooks/types.js";
import { featureMatcher, isAcronymFeature } from "../playbooks/matcher.js";

/**
 * Minimum family-signal strength for a specialized playbook to be admitted
 * as a match candidate. Tuned against the calibration set below:
 *   - one title-keyword hit  → 2 points  (a specific title like
 *     "Business Associate Agreement" is a strong, near-decisive signal)
 *   - one distinguishing-phrase hit → 1 point
 *   - one required-clause/defined-term hit → 1 point
 * Threshold 2 admits on a single specific title keyword, or on two
 * independent body signals — but not on one stray generic phrase.
 */
export const ADMIT_THRESHOLD = 2;
const TITLE_KEYWORD_POINTS = 2;
const DISTINGUISHING_POINTS = 1;
const REQUIRED_CLAUSE_POINTS = 1;

export type CandidateSignals = {
  /** Title-ish corpus (first heading + preamble), used for title-keyword hits. */
  title: string;
  /** Whole-document body text, used for distinguishing-phrase hits. */
  body: string;
  classified: ReadonlyArray<ClassifiedParagraph>;
  extracted: ExtractedData;
};

/**
 * Score how strongly a document signals a given specialized playbook's
 * family. Mirrors the matcher's feature kinds but is used only to decide
 * candidacy, not to rank. Exported for tests.
 */
/**
 * One folded corpus per document, shared by every playbook tested against it.
 *
 * 🚨 Both selectors below used to test a keyword with `title.includes(kw)`.
 * That is not the comparison the matcher makes, and the difference is not
 * cosmetic: a raw substring finds `"co"` inside "company", `"cla"` inside
 * "clause", `"sig"` inside "signature", `"spa"` inside "space" and `"apa"`
 * inside "capacity" — and ONE title hit is enough to declare a family present
 * and run its whole rule pack. Measured over the 312 specimens: **123 of them
 * activated a family on a substring a word-boundary match rejects, producing
 * 465 findings, 389 of them CRITICAL**, about documents of a kind they are
 * not. A commercial Master Services Agreement drew four criticals from
 * `family-msa` — the family-law Marital Settlement Agreement — and three from
 * `change-order`, whose title keyword is `"co"`.
 *
 * `matcher.ts` had solved this long before, in `matchesIn`: an acronym of five
 * characters or fewer is matched at a word boundary, and everything else keeps
 * phrase semantics, on a corpus folded for hyphens, apostrophes and
 * Commonwealth spelling. This file reimplemented the comparison and got it
 * wrong, which is the "a table written twice will disagree with itself"
 * failure in its keyword form. There is one owner now.
 */
type Matchers = {
  inTitle: (feature: string) => boolean;
  inBody: (feature: string) => boolean;
  /** Classifier categories present, and defined terms, folded once per document. */
  categories: ReadonlySet<string>;
  definedTerms: ReadonlySet<string>;
  /** Which of a playbook's features this document matched, by playbook id. */
  hits: Map<string, FeatureHits>;
};

/** The three feature kinds both selectors read, evaluated once per document. */
type FeatureHits = {
  title: readonly string[];
  dist: readonly string[];
  req: readonly string[];
};

/**
 * 🚨 Memoized per `signals` object, and the memo is load-bearing, not a
 * micro-optimization.
 *
 * `familySignalStrength` runs once per playbook in `selectMatchCandidates`
 * (255 of them) and twice per comparison inside `selectSecondaryFamilies`'s
 * sort; `familyIsPresent` runs 255 more times. `featureMatcher` folds the
 * WHOLE document — apostrophes, attachment nouns, instrument nouns,
 * Commonwealth spelling, then two hyphen variants, roughly seven passes over
 * the full body — so building it per call is thousands of full-document regex
 * passes per document where the old `body.toLowerCase()` was one cheap pass.
 *
 * Unmemoized, it roughly doubled the integration suite and pushed the Deploy
 * job (20-minute budget) and the cross-OS matrix (25-minute budget) past their
 * timeouts, which GitHub reports as `cancelled`.
 *
 * A `WeakMap` on the caller's own `signals` object is the right key: both
 * selectors receive one object per document and hand it to every playbook, and
 * nothing outlives the analysis.
 */
const MATCHER_CACHE = new WeakMap<CandidateSignals, Matchers>();

function corpusMatchers(signals: CandidateSignals): Matchers {
  const hit = MATCHER_CACHE.get(signals);
  if (hit) return hit;
  const built: Matchers = {
    inTitle: featureMatcher(signals.title),
    inBody: featureMatcher(signals.body),
    categories: new Set(signals.classified.map((c) => c.category)),
    definedTerms: new Set(signals.extracted.definitions.entries.map((e) => e.term.toLowerCase())),
    hits: new Map(),
  };
  MATCHER_CACHE.set(signals, built);
  return built;
}

/**
 * 🚨 THE RESIDUAL, MEASURED AND DELIBERATELY NOT ACTED ON (2026-09-07).
 *
 * After the acronym, corpus-frequency and collocation fixes, the corpus still
 * carries **943 secondary-family CRITICAL findings across 130 of 312
 * documents**. They are not evenly spread — the top of the list is one domain:
 *
 *     gdpr-notice 35 · privacy-notice-multistate 32 · privacy-notice 31
 *     ropa-art-30 30 · scc-module-3 25 · uk-idta-addendum 22
 *
 * Those families are MUTUALLY EXCLUSIVE DOCUMENT TYPES that share almost all
 * their vocabulary — controller, processor, personal data, data subject,
 * purposes, retention. A privacy notice (given to data subjects) is not a DPA
 * (a controller↔processor contract) is not an Art. 30 register is not an SCC
 * transfer instrument, but each says what the others say. So a GDPR privacy
 * notice is told at CRITICAL, seventeen times over and twice, that it lacks
 * Art. 28(3) processor terms.
 *
 * ## The candidate fix, and why it is not applied here
 *
 * Hypothesis: a family a document genuinely CONTAINS names itself somewhere —
 * an MSA with a DPA exhibit carries the heading "Data Processing Addendum" in
 * its body — while a family it merely DISCUSSES does not. So for phrase-only
 * activation, require a spelled-out title keyword to appear in the BODY, not
 * just in the title corpus.
 *
 * Measured over the 312 specimens: it drops **194 of 322 activations (60%)**,
 * removing **1,736 findings, 777 of them critical**, and keeps 128. Many drops
 * are plainly right (`83b-election` → `secondary-stock-transfer`,
 * `asset-purchase-agreement` → `stock-purchase-agreement`, `baa` →
 * `hipaa-npp`). Some are not obviously right (`board-written-consent` →
 * `board-resolution`).
 *
 * **It is not applied because 60% of a shipped feature's output is not a call
 * to make on a heuristic's say-so.** Confirming that all 194 drops are wrong
 * activations — and that the 128 survivors are the right ones — is a
 * document-by-document legal judgment, not a measurement. The numbers are
 * recorded so that whoever owns that judgment can make it with them in hand,
 * rather than rediscovering the residual from scratch.
 *
 * What ships instead is the caveat (9.514.0): every surface says these families
 * were detected from vocabulary and not confirmed, and that an absence in one
 * may be a clause the document never needed. That is honest about a
 * distinction the engine cannot currently draw. See
 * `tests/integration/family-activation-evidence.test.ts` for why
 * `required_clauses` is not the signal either.
 */

/**
 * A playbook's matched features against one document, computed once.
 *
 * 🥇 `selectMatchCandidates` scores all 255 extended playbooks, then
 * `selectSecondaryFamilies` tests the same 255 against the same document —
 * evaluating every title keyword and distinguishing phrase a second time.
 * Profiled over the 312 specimens the two selectors were **8.3 of 10.3 seconds**,
 * 81% of the per-document pipeline, and half of that was the repeat.
 *
 * Keyed by playbook id inside the per-document cache, so it lives exactly as
 * long as the `signals` object the caller built.
 */
function featureHits(playbook: Playbook, signals: CandidateSignals): FeatureHits {
  const m = corpusMatchers(signals);
  const cached = m.hits.get(playbook.id);
  if (cached) return cached;
  const f = playbook.match_features;
  const built: FeatureHits = {
    title: f.title_keywords.filter(m.inTitle),
    dist: f.distinguishing_phrases.filter(m.inBody),
    req: f.required_clauses.filter(
      (cat) => m.categories.has(cat) || m.definedTerms.has(cat.toLowerCase()),
    ),
  };
  m.hits.set(playbook.id, built);
  return built;
}

export function familySignalStrength(playbook: Playbook, signals: CandidateSignals): number {
  const hits = featureHits(playbook, signals);
  const titleHits = hits.title.length;
  const distHits = hits.dist.length;
  const reqHits = hits.req.length;

  return (
    titleHits * TITLE_KEYWORD_POINTS +
    distHits * DISTINGUISHING_POINTS +
    reqHits * REQUIRED_CLAUSE_POINTS
  );
}

/**
 * Build the match-candidate set: every launch playbook, plus the
 * specialized playbooks whose family the document clearly signals.
 */
export function selectMatchCandidates(
  launch: readonly Playbook[],
  extended: readonly Playbook[],
  signals: CandidateSignals,
): Playbook[] {
  const admitted = extended.filter((p) => familySignalStrength(p, signals) >= ADMIT_THRESHOLD);
  return [...launch, ...admitted];
}

/**
 * Most secondary families surfaced per document. A composite agreement
 * rarely embeds more than a couple of distinct families; the cap bounds the
 * extra engine passes and keeps the "additional checks" section readable.
 *
 * 🚨 **It is a real cap, and "rarely" is not "never".** Measured 2026-09-08
 * over the 312 specimens: **7 of them clearly contain more families than
 * this**, and `uk-idta-addendum.txt` contains **eight** — four more than are
 * scanned. (This said "22 ... and `dpa-controller-processor.txt` contains
 * eight" — both true when written, neither true now: the false-positive work
 * that tightened `familyIsPresent` cut the truncated set by two thirds.
 * `tests/integration/secondary-family-cap-caveat.test.ts` re-measures it.) {@link selectSecondaryFamilies} returns `omitted` alongside the
 * list — SAY the number wherever the list is shown; the paragraph below used
 * to claim "a present family is never silently skipped", which is exactly what
 * a cap does when it bites.
 */
export const MAX_SECONDARY_FAMILIES = 4;

/**
 * What {@link selectSecondaryFamilies} found: the families it will scan, and
 * how many it will not.
 *
 * `omitted` exists so the cap can be STATED. A truncation nobody says out loud
 * reads to the reader as "there were only four" — the same clean-looking output
 * a document with exactly four produces. Every surface that renders `selected`
 * is expected to render `omitted` beside it when it is non-zero.
 */
export type SecondaryFamilySelection = {
  /** The families that will be scanned — at most {@link MAX_SECONDARY_FAMILIES}. */
  selected: Playbook[];
  /** How many families the document clearly contains, before the cap. */
  present: number;
  /** `present` minus `selected.length`: clearly present, never scanned. */
  omitted: number;
};

/**
 * Whether a document *clearly contains* a given family — the **strict**
 * presence bar used to decide multi-family activation (run that family's
 * full rule set as a secondary scan). Stricter than candidate admission:
 * admission only adds a match candidate (the matcher still arbitrates),
 * whereas activation runs a whole checklist of "required clause absent"
 * rules, so it must be confident the family is genuinely present — not
 * merely mentioned in passing. Clear-presence = a specific title keyword,
 * or three or more distinguishing/required-clause hits in the body.
 */
export function familyIsPresent(playbook: Playbook, signals: CandidateSignals): boolean {
  const hits = featureHits(playbook, signals);

  // A document's own NAME is strong evidence it is of that family — but an
  // ACRONYM is not a name, it is a collision waiting to happen. "MSA" is a
  // Master Services Agreement and a Marital Settlement Agreement; "SPA" a
  // stock and a share purchase; "PSA" a purchase-and-sale; "DPA" a data
  // processing agreement and a deferred prosecution agreement. And "co", the
  // catalog's shortest, matches the "Co." in any company's name.
  //
  // Measured: a real commercial Master Services Agreement that calls itself
  // `(this "MSA")` drew FOUR CRITICAL findings from the family-law playbook,
  // and two specimens activated `change-order` on the "Co." in a party's name
  // — 7 findings, 6 of them critical. 9.508.0 made this a word-boundary match
  // instead of a substring, which was necessary and not sufficient: the
  // boundary match here is CORRECT, and the inference from it was wrong.
  //
  // So a full-name title keyword still activates alone; when every title hit
  // is a bare acronym, the family has to earn it the same way a phrase-only
  // candidate does.
  const titleHits = hits.title;
  // The document's own NAME, spelled out, is enough on its own.
  if (titleHits.some((k) => !isAcronymFeature(k))) return true;

  const distHits = hits.dist;
  const reqHits = hits.req;
  // An acronym is not discarded — it is counted as ONE weak signal alongside
  // the phrases. Discarding it throws away real evidence ("MSA" in a document
  // that also says "petitioner" and "spousal support" IS a marital settlement);
  // treating it as a name lets "Co." in a party's name run a whole rule pack.
  if (titleHits.length + distHits.length + reqHits.length < 3) return false;

  // Three BARE COMMON WORDS are not evidence that a document IS this family.
  //
  // An ALL-CAPS guaranty matched `loan-agreement` on "borrower", "lender" and
  // "commitment" — and was then told, at CRITICAL, that it was missing an
  // interest-rate clause and negative covenants. A guaranty has neither; the
  // loan it guarantees does. The same shape put an LLC **operating agreement**
  // into `healthcare-poa` on "principal/agent/incapacity", an SBA **loan
  // agreement** into `revocable-living-trust` on "trustor/trustee/revocable",
  // and an **irrevocable trust** into `deed-of-trust` — a mortgage instrument.
  //
  // Corpus frequency cannot separate these: each of those words sits under
  // `distinguishing-base-rate.test.ts`'s ceiling. They are common within a
  // DOMAIN — every document in a lending package names the borrower and the
  // lender, because that is what they are about — and no threshold over the
  // whole corpus sees that.
  //
  // What does see it is the docs' own test, applied to the ACTIVATION rather
  // than to each phrase: "would I be surprised to find this in a document that
  // is NOT this family". One bare noun, no. One COLLOCATION — a multi-word
  // phrase, or a hyphenated compound like "non-disturbance", "sub-processor",
  // "auto-renew" — yes. So activation on phrases alone requires at least one,
  // or a structural `required_clauses` hit, which is evidence of a different
  // kind.
  //
  // Measured: 14 activations dropped over the 312 specimens, 27 findings and
  // 17 CRITICAL among them, and the hyphen clause is what keeps the genuine
  // ones — `net-lease` really does carry SNDA terms ("non-disturbance",
  // "attornment"), and a word-count-only rule threw those away too.
  return reqHits.length > 0 || distHits.some(isCollocation);
}

/**
 * A phrase specific enough to activate a family on its own evidence: more than
 * one word, or a hyphenated compound (which is a collocation spelled closed).
 */
function isCollocation(phrase: string): boolean {
  return /[\s-]/.test(phrase.trim());
}

/**
 * Select the secondary families to run as additional scans: specialized
 * playbooks the document clearly contains (strict bar), other than the
 * primary matched playbook. Sorted by signal strength (desc) then id for a
 * deterministic order, and capped at {@link MAX_SECONDARY_FAMILIES}.
 *
 * These drive the report's "additional checks from other detected families"
 * section — a composite MSA that embeds a DPA exhibit gets the DPA rule set
 * too, so a genuinely-present family is not skipped for want of looking.
 *
 * ⚠️ Up to {@link MAX_SECONDARY_FAMILIES} of them. This comment used to end
 * "so a genuinely-present family is never silently skipped", which the cap
 * contradicts on 7 of the 312 specimens. So the return carries `present` — the
 * count BEFORE the cap — and `omitted`, the number the reader is not being
 * shown. Returning them together is what makes the truncation sayable without a
 * second full scan: scoring 255 extended playbooks against the document is the
 * expensive part, and a caller that asked for the list and the count separately
 * paid for it twice.
 */
export function selectSecondaryFamilies(
  extended: readonly Playbook[],
  signals: CandidateSignals,
  primaryPlaybookId: string,
): SecondaryFamilySelection {
  const ranked = extended
    .filter((p) => p.id !== primaryPlaybookId && familyIsPresent(p, signals))
    // Score each survivor ONCE. A comparator that recomputes the score does it
    // O(n log n) times, which was free when the score was a substring count
    // and is not now that it folds the document.
    .map((p) => [p, familySignalStrength(p, signals)] as const)
    .sort((a, b) => (a[1] !== b[1] ? b[1] - a[1] : a[0].id.localeCompare(b[0].id, "en")))
    .map(([p]) => p);
  const selected = ranked.slice(0, MAX_SECONDARY_FAMILIES);
  return { selected, present: ranked.length, omitted: ranked.length - selected.length };
}
