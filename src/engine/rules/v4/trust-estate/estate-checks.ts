/**
 * Estate-planning "deepening" checks for the will / revocable-trust /
 * codicil playbooks — jurisdiction-neutral, pure deterministic engine
 * rules (add-estate-planning-pack).
 *
 * Unlike the shipped `EST-0NN` clause-presence rules in `./rules.ts`
 * (playbook-gated, always run when a trust-estate playbook matches),
 * every rule in this file is **also** gated on the `estate-checks`
 * assertion (registered in `src/verticals/registry.ts`). Gating this
 * pack behind an explicit opt-in — rather than only
 * `applies_to_playbooks` — means it cannot change the hash of any
 * already-shipped will/trust run; it only runs when the caller asserts
 * `--estate-checks` (or equivalent).
 *
 * Three families:
 *   - EST-1xx — recital presence (attestation, self-proving affidavit,
 *     notary block, testator signature, witness signatures).
 *   - EST-2xx — share arithmetic (residuary shares summing to 100%).
 *   - EST-3xx — fiduciary / survivorship presence (executor, successor
 *     fiduciary, guardian for minors, survivorship clause).
 */

import {
  makeFinding,
  type Finding,
  type Rule,
  type RuleContext,
  type Severity,
} from "../../../finding.js";
import { fullText, docTop } from "../_helpers.js";
import { forEachParagraph } from "../../../../extract/walk.js";
import { upc } from "./_helpers.js";
import type { SourceCitation } from "../../../../dkb/types.js";
import type { EstateFormalityOverlay } from "../../../../dkb/estate-formalities.js";

const CATEGORY = "estate-checks";
const GATE = "estate-checks";
const PLAYBOOKS = ["last-will-and-testament", "revocable-living-trust", "codicil"] as const;

/** Lower-cased concatenation of every heading + paragraph — case-insensitive matching. */
function fullTextLower(ctx: RuleContext): string {
  return fullText(ctx).toLowerCase();
}

// ────────────────────────────────────────────────────────────────────
// Shared "fires when absent" rule shape used by EST-101..105, EST-301,
// EST-302, and EST-304.
// ────────────────────────────────────────────────────────────────────

type AbsenceSpec = {
  id: string;
  version?: string;
  name: string;
  severity: Severity;
  patterns: RegExp[];
  missingTitle: string;
  missingDescription: string;
  explanation: string;
  recommendation: string;
  citations: SourceCitation[];
};

function absenceRule(spec: AbsenceSpec): Rule {
  return {
    id: spec.id,
    version: spec.version ?? "1.0.0",
    name: spec.name,
    category: CATEGORY,
    default_severity: spec.severity,
    description: spec.name,
    dkb_citations: spec.citations.map((c) => c.id),
    applies_to_playbooks: [...PLAYBOOKS],
    assertion_gate: GATE,
    check(ctx: RuleContext): Finding | null {
      const text = fullTextLower(ctx);
      if (spec.patterns.some((re) => re.test(text))) return null;
      return makeFinding({
        rule: this as Rule,
        title: spec.missingTitle,
        description: spec.missingDescription,
        excerptText: "(clause absent from the document)",
        explanation: spec.explanation,
        recommendation: spec.recommendation,
        position: docTop(ctx),
        source_citations: spec.citations,
      });
    },
  };
}

// ────────────────────────────────────────────────────────────────────
// EST-1xx — recital presence.
// ────────────────────────────────────────────────────────────────────

const SPEC_101: AbsenceSpec = {
  id: "EST-101",
  name: "Attestation clause present",
  severity: "warning",
  patterns: [
    /attestation/,
    /in witness whereof/,
    /subscrib(ed|ing) witnesses/,
    /witness(es)?.{0,40}(presence|request|signed)/,
  ],
  missingTitle: "No attestation clause detected",
  missingDescription:
    "No clause was found reciting that the witnesses attested execution of the will.",
  explanation:
    "UPC § 2-502 requires the will to be signed by at least two witnesses who witnessed the signing or the testator's acknowledgment. An attestation clause is the standard evidence of that formality.",
  recommendation:
    "Add an attestation clause reciting that the witnesses signed in the testator's presence and at the testator's request.",
  citations: [upc("2-502", "execution; witnessed wills")],
};
const EST_101: Rule = absenceRule(SPEC_101);

const EST_102: Rule = absenceRule({
  id: "EST-102",
  name: "Self-proving affidavit present",
  severity: "info",
  patterns: [
    /self.?prov/,
    /affidavit/,
    /under penalty of perjury.{0,120}witness/,
    /sworn.{0,40}before me/,
  ],
  missingTitle: "No self-proving affidavit detected",
  missingDescription: "No self-proving affidavit was found attached to or referenced by the will.",
  explanation:
    "UPC § 2-504 lets a will be made self-proved by a sworn affidavit of the testator and witnesses, so probate does not require locating and calling the witnesses to testify.",
  recommendation:
    "Attach a self-proving affidavit in the statutory form (or the applicable state's equivalent).",
  citations: [upc("2-504", "self-proved wills")],
});

const SPEC_103: AbsenceSpec = {
  id: "EST-103",
  name: "Notary block present",
  severity: "info",
  patterns: [
    /notary public/,
    /acknowledged before me/,
    /my commission expires/,
    /sworn (to )?and subscribed before me/,
  ],
  missingTitle: "No notary block detected",
  missingDescription: "No notarial acknowledgment block was found in the document text.",
  explanation:
    "A self-proving affidavit under UPC § 2-504 must be notarized; a notary block is the concrete evidence of that step.",
  recommendation:
    "Add a notary block (notary public, acknowledgment, commission-expiration recital) alongside the self-proving affidavit.",
  citations: [upc("2-504")],
};
const EST_103: Rule = absenceRule(SPEC_103);

const EST_104: Rule = absenceRule({
  id: "EST-104",
  name: "Testator signature block present",
  severity: "warning",
  patterns: [
    /signature of.{0,20}testator/,
    /testator.{0,30}signature/,
    /_{3,}\s*(the )?testator/,
    /by:?\s*_{3,}/,
  ],
  missingTitle: "No testator signature block detected",
  missingDescription: "No signature block for the testator was found in the document text.",
  explanation:
    "UPC § 2-502 requires the will to be signed by the testator (or by another individual in the testator's conscious presence and at the testator's direction).",
  recommendation: "Add a signature block for the testator (signature line, printed name, date).",
  citations: [upc("2-502")],
});

const SPEC_105: AbsenceSpec = {
  id: "EST-105",
  version: "1.1.0",
  name: "Witness signature blocks present",
  severity: "warning",
  // Presence-only — EST-106 below does the count comparison against the
  // number the will recites (e.g. "two witnesses"). The second pattern
  // guards against testator-side boilerplate: "witnesseth" and "in
  // witness whereof, I sign" must not read as witness-block evidence.
  patterns: [
    /_{3,}\s*witness/,
    /witness(?!eth)(?!\s+whereof).{0,20}(signature|sign|_{3,})/,
    /signature of.{0,20}witness/,
  ],
  missingTitle: "No witness signature blocks detected",
  missingDescription: "No witness signature blocks were found in the document text.",
  explanation:
    "UPC § 2-502 requires at least two witnesses to sign the will. Witness signature blocks are the concrete evidence of that formality.",
  recommendation:
    "Add at least two witness signature blocks (signature line, printed name, address).",
  citations: [upc("2-502")],
};
const EST_105: Rule = absenceRule(SPEC_105);

// ────────────────────────────────────────────────────────────────────
// EST-106 — witness signature blocks vs. the attestation recital's
// count (the "future refinement" EST-105's presence-only v1 noted).
// Internal consistency, deliberately statute-independent: whatever the
// asserted state requires, a will that RECITES N witnesses and shows
// fewer than N witness signature blocks is inconsistent with itself.
// Fires only when at least one block is present — the zero-block case
// is EST-105's finding, and double-reporting it would be noise.
// ────────────────────────────────────────────────────────────────────

const RECITED_WITNESS_RE =
  /\b(one|two|three|1|2|3)\s*(?:\(\s*[123]\s*\))?\s*(?:or more\s+)?(?:credible|competent|attesting|subscribing|adult|disinterested)?\s*witnesses?\b/g;

const WITNESS_COUNT_WORDS: Record<string, number> = {
  one: 1,
  two: 2,
  three: 3,
  "1": 1,
  "2": 2,
  "3": 3,
};

/** The highest witness count the document recites, or undefined when none. */
function recitedWitnessCount(text: string): number | undefined {
  let max: number | undefined;
  for (const m of text.matchAll(RECITED_WITNESS_RE)) {
    const n = WITNESS_COUNT_WORDS[m[1]!];
    if (n !== undefined && (max === undefined || n > max)) max = n;
  }
  return max;
}

/**
 * Count witness signature blocks: paragraphs that carry both a witness
 * token and at least one signature line, counting one block per
 * signature line in the paragraph (two blocks on one line — "Witness:
 * ___ Witness: ___" — count as two).
 */
function witnessSignatureBlockCount(ctx: RuleContext): number {
  let count = 0;
  forEachParagraph(ctx.tree, (p) => {
    // Testator-side boilerplate carries the token without being a witness
    // block: "IN WITNESS WHEREOF, I sign: ___" is the testator's own
    // signature line, and a "WITNESSETH:" preamble is recital prose. Strip
    // those phrases before testing, or the testator's line counts as a
    // witness block (silencing EST-107) and a WITNESSETH paragraph makes
    // the counter disagree with EST-105's presence patterns.
    const t = p.text.toLowerCase().replace(/in witness whereof|witnesseth/g, "");
    if (!/witness/.test(t)) return;
    // Attestation prose ("in the presence of two witnesses") has no
    // signature line; only underscore runs mark a block.
    const lines = t.match(/_{3,}/g);
    if (lines) count += lines.length;
  });
  return count;
}

const EST_106: Rule = {
  id: "EST-106",
  version: "1.1.0",
  name: "Witness signature blocks fewer than the recital",
  category: CATEGORY,
  default_severity: "warning",
  description:
    "The number of witness signature blocks should be at least the witness count the will itself recites.",
  dkb_citations: ["upc-2-502"],
  applies_to_playbooks: [...PLAYBOOKS],
  assertion_gate: GATE,
  check(ctx: RuleContext): Finding | null {
    const recited = recitedWitnessCount(fullTextLower(ctx));
    if (recited === undefined) return null;
    const blocks = witnessSignatureBlockCount(ctx);
    if (blocks === 0 || blocks >= recited) return null;
    return makeFinding({
      rule: this as Rule,
      title: `Will recites ${recited} witnesses but shows ${blocks} witness signature block${blocks === 1 ? "" : "s"}`,
      description: `The document's own text recites ${recited} witnesses, but only ${blocks} witness signature block${blocks === 1 ? " was" : "s were"} detected.`,
      excerptText: "(witness signature blocks fewer than the recited count)",
      explanation:
        "A will that recites more witnesses than it provides signature blocks for is internally inconsistent: either the recital overstates the attestation or a witness signature block is missing. Under UPC § 2-502 at least two witnesses must sign; a probate court compares the recital against the actual signatures.",
      recommendation:
        "Add the missing witness signature block(s) or correct the recited witness count so the recital matches the signature blocks.",
      position: docTop(ctx),
      source_citations: [upc("2-502", "execution; witnessed wills")],
    });
  },
};

// ────────────────────────────────────────────────────────────────────
// EST-2xx — share arithmetic.
// ────────────────────────────────────────────────────────────────────

const RESIDUE_RE = /residue|residuary|rest,? residue and remainder|remainder of my estate/;
const EQUAL_DIVISION_RE = /equal shares|share and share alike|in equal|per stirpes|per capita/;

const PERCENT_RE = /(\d{1,3}(?:\.\d+)?)\s*(?:%|percent)/g;
const WORD_FRACTION_RE =
  /\b(one|two|three|four|five|1|2|3|4|5)[\s-](half|halves|third|thirds|fourth|fourths|quarter|quarters|fifth|fifths)\b/g;
const EXPLICIT_FRACTION_RE = /(\d)\s*\/\s*(\d)/g;

const NUMERATOR_WORDS: Record<string, number> = {
  one: 1,
  two: 2,
  three: 3,
  four: 4,
  five: 5,
  "1": 1,
  "2": 2,
  "3": 3,
  "4": 4,
  "5": 5,
};

const DENOMINATOR_WORDS: Record<string, number> = {
  half: 2,
  halves: 2,
  third: 3,
  thirds: 3,
  fourth: 4,
  fourths: 4,
  quarter: 4,
  quarters: 4,
  fifth: 5,
  fifths: 5,
};

type ShareMatch = {
  index: number;
  end: number;
  value: number;
  kind: "percent" | "word-fraction" | "explicit-fraction";
};

/** Collect every detected share expression, in position order. */
function collectRawShareMatches(text: string): ShareMatch[] {
  const out: ShareMatch[] = [];
  for (const m of text.matchAll(PERCENT_RE)) {
    out.push({
      index: m.index,
      end: m.index + m[0].length,
      value: parseFloat(m[1]!),
      kind: "percent",
    });
  }
  for (const m of text.matchAll(WORD_FRACTION_RE)) {
    const num = NUMERATOR_WORDS[m[1]!];
    const den = DENOMINATOR_WORDS[m[2]!];
    if (num === undefined || den === undefined) continue;
    out.push({
      index: m.index,
      end: m.index + m[0].length,
      value: (num / den) * 100,
      kind: "word-fraction",
    });
  }
  for (const m of text.matchAll(EXPLICIT_FRACTION_RE)) {
    const num = Number(m[1]!);
    const den = Number(m[2]!);
    if (den === 0) continue;
    out.push({
      index: m.index,
      end: m.index + m[0].length,
      value: (num / den) * 100,
      kind: "explicit-fraction",
    });
  }
  return out.sort((a, b) => a.index - b.index);
}

/**
 * De-dupe a word-fraction immediately followed by its own parenthetical
 * restatement — "one-half (50%)" or "one-half (1/2)" — so the pair counts
 * once, preferring the more explicit percent/explicit-fraction value.
 */
function dedupShares(matches: ShareMatch[], text: string): number[] {
  const shares: number[] = [];
  for (let i = 0; i < matches.length; i++) {
    const m = matches[i]!;
    const prev = matches[i - 1];
    const isParenRestatement =
      prev !== undefined &&
      prev.kind === "word-fraction" &&
      (m.kind === "percent" || m.kind === "explicit-fraction") &&
      m.index - prev.end <= 6 &&
      /^\s*\($/.test(text.slice(prev.end, m.index));
    if (isParenRestatement) {
      shares.pop();
      shares.push(m.value);
      continue;
    }
    shares.push(m.value);
  }
  return shares;
}

function formatPercent(n: number): string {
  const rounded = Math.round(n * 10) / 10;
  return Number.isInteger(rounded) ? String(rounded) : rounded.toFixed(1);
}

const EST_201: Rule = {
  id: "EST-201",
  version: "1.0.0",
  name: "Residuary shares do not sum to 100%",
  category: CATEGORY,
  default_severity: "warning",
  description: "Residuary shares expressed as percentages / fractions should sum to 100%.",
  dkb_citations: ["upc-2-604", "upc-2-101"],
  applies_to_playbooks: [...PLAYBOOKS],
  assertion_gate: GATE,
  check(ctx: RuleContext): Finding | null {
    // Scope the share arithmetic to the residuary clause's OWN paragraph(s) —
    // over the whole document an unrelated percentage (e.g. a trustee-fee cap
    // "3% of the estate") was summed into the residuary total (false positive),
    // and an unrelated "per stirpes" bequest suppressed the rule entirely
    // (false negative).
    let text = "";
    forEachParagraph(ctx.tree, (p) => {
      const t = p.text.toLowerCase();
      if (RESIDUE_RE.test(t)) text += " " + t;
    });
    if (!text) return null;
    if (EQUAL_DIVISION_RE.test(text)) return null;

    const shares = dedupShares(collectRawShareMatches(text), text);
    if (shares.length < 2) return null;

    const sum = shares.reduce((a, b) => a + b, 0);
    const rounded = Math.round(sum * 10) / 10;
    if (Math.abs(rounded - 100.0) <= 0.5) return null;

    const list = shares.map((s) => `${formatPercent(s)}%`).join(", ");
    return makeFinding({
      rule: this as Rule,
      title: `Residuary shares sum to ${formatPercent(rounded)}% (not 100%)`,
      description: `Detected residuary shares: ${list}. Total: ${formatPercent(rounded)}% (expected 100%).`,
      excerptText: "(residuary share arithmetic does not sum to 100%)",
      explanation:
        "The residuary clause's stated shares do not add up to the whole estate. Under UPC § 2-604, any unallocated residue fails and passes by intestacy under UPC § 2-101 — likely contrary to the testator's intent — unless the arithmetic is corrected.",
      recommendation:
        "Re-check the residuary shares against the detected percentages / fractions and correct them (or add a clause disposing of any unallocated residue) so they sum to 100%.",
      position: docTop(ctx),
      source_citations: [
        upc("2-604", "failure of testamentary provision"),
        upc("2-101", "intestate estate"),
      ],
    });
  },
};

// ────────────────────────────────────────────────────────────────────
// EST-3xx — fiduciary / survivorship presence.
// ────────────────────────────────────────────────────────────────────

const EST_301: Rule = absenceRule({
  id: "EST-301",
  name: "Executor / personal representative named",
  severity: "warning",
  patterns: [/executor|executrix|personal representative/],
  missingTitle: "No executor / personal representative named",
  missingDescription: "No clause was found naming an executor or personal representative.",
  explanation:
    "Without a nomination, the court appoints from the statutory priority list rather than the testator's chosen fiduciary.",
  recommendation:
    "Add a clause nominating an executor / personal representative (and a successor).",
  citations: [upc("3-703", "general duties")],
});

const EST_302: Rule = absenceRule({
  id: "EST-302",
  name: "Successor fiduciary named",
  severity: "info",
  patterns: [
    /successor (executor|trustee|personal representative)/,
    /alternate (executor|trustee)/,
    /(unable|unwilling|fails?|ceases?) to (serve|act|continue)/,
  ],
  missingTitle: "No successor fiduciary named",
  missingDescription:
    "No successor / alternate fiduciary was found named for when the primary fiduciary cannot serve.",
  explanation:
    "Without a successor, a court must appoint one if the named fiduciary cannot or will not serve, creating delay and a fiduciary the testator did not choose.",
  recommendation: "Name at least one successor / alternate fiduciary.",
  citations: [upc("3-703")],
});

const MINOR_REF_RE = /minor child|minor children|my children.{0,60}(minor|under the age|under age)/;
const GUARDIAN_RE =
  /nominate.{0,20}guardian|appoint.{0,20}guardian|guardian (of|for) (the |my )?(minor|child|person)/;

const EST_303: Rule = {
  id: "EST-303",
  version: "1.0.0",
  name: "Guardian nomination for minor children",
  category: CATEGORY,
  default_severity: "warning",
  description:
    "When the document references minor children, a guardian nomination for those children should also be present.",
  dkb_citations: ["upc-5-202"],
  applies_to_playbooks: [...PLAYBOOKS],
  assertion_gate: GATE,
  check(ctx: RuleContext): Finding | null {
    const text = fullTextLower(ctx);
    if (!MINOR_REF_RE.test(text)) return null;
    if (GUARDIAN_RE.test(text)) return null;
    return makeFinding({
      rule: this as Rule,
      title: "No guardian nomination for minor children detected",
      description:
        "The document references minor children but no clause was found nominating a guardian for them.",
      excerptText: "(clause absent from the document)",
      explanation:
        "UPC § 5-202 recognizes testamentary appointment of a guardian for an unmarried minor child. Without a nomination, the court chooses a guardian from family members based on statutory factors, not the testator's stated preference.",
      recommendation:
        "Add a clause nominating a guardian (and a successor guardian) for the minor children.",
      position: docTop(ctx),
      source_citations: [upc("5-202", "testamentary appointment of guardian")],
    });
  },
};

const EST_304: Rule = absenceRule({
  id: "EST-304",
  name: "Survivorship / simultaneous-death provision present",
  severity: "info",
  patterns: [
    /survivorship|simultaneous death|survive(s)? me by|common disaster|order of death|predecease/,
  ],
  missingTitle: "No survivorship / simultaneous-death provision detected",
  missingDescription:
    "No survivorship or simultaneous-death clause was found in the document text.",
  explanation:
    "UPC § 2-702 requires an individual to survive an event (e.g., the testator's death) by 120 hours to take under the will, absent contrary language. Without an explicit survivorship provision, simultaneous or near-simultaneous deaths can produce unintended results.",
  recommendation:
    "Add a survivorship / simultaneous-death provision (e.g., a 120-hour survival requirement or a stated order-of-death rule).",
  citations: [upc("2-702", "requirement of survival by 120 hours")],
});

// ────────────────────────────────────────────────────────────────────
// Aggregate.
// ────────────────────────────────────────────────────────────────────

export const ESTATE_CHECK_RULES: readonly Rule[] = [
  EST_101,
  EST_102,
  EST_103,
  EST_104,
  EST_105,
  EST_106,
  EST_201,
  EST_301,
  EST_302,
  EST_303,
  EST_304,
];

export const ESTATE_CHECK_RULE_IDS: readonly string[] = ESTATE_CHECK_RULES.map((r) => r.id);

// ────────────────────────────────────────────────────────────────────
// Overlay-aware variants (--state). With a verified state-formalities
// overlay, the recital rules speak the asserted state's law instead of
// the UPC default. Reachable only via the new `--state` assertion, so
// every existing run — including `--estate-checks` without a state —
// keeps its exact rules and hash: no overlay returns ESTATE_CHECK_RULES
// unchanged.
// ────────────────────────────────────────────────────────────────────

/**
 * The estate-checks rule set for an asserted state. Findings stay
 * presence-of-recital observations — the overlay changes what absence
 * *means* under the asserted state's verified statute:
 *
 *   - `witnesses_expected === 0` (PA): a missing attestation clause or
 *     witness blocks is an INFO note citing the state statute, not a
 *     warning — 20 Pa. C.S. § 2502 requires neither for an ordinary
 *     signed will.
 *   - `notarial_testament` (LA): a missing notary block escalates to a
 *     WARNING — the notarial testament requires a notary, two witnesses,
 *     per-page signatures, and the prescribed attestation declaration
 *     (arts. 1576–1577).
 *   - `notarization_alternative` (CO/ND): missing witness blocks keep
 *     their severity but the explanation states the notarized-
 *     acknowledgment alternative, so absence is not read as per-se
 *     non-compliance when a notary block is present.
 *   - `witnesses_expected > 0` (every seeded state but PA): EST-107 is
 *     appended — witness signature blocks counted against the statute's
 *     expected witnesses (under CO/ND, silent when a notarial
 *     acknowledgment is detected — the alternative satisfies the
 *     statute — and a both-paths-missing warning otherwise).
 */
export function estateCheckRulesForOverlay(
  overlay: EstateFormalityOverlay | undefined,
): readonly Rule[] {
  if (!overlay) return ESTATE_CHECK_RULES;

  const stateNote = ` Asserted state: ${overlay.state_name} — ${overlay.headline} (${overlay.citation.source}).`;
  const variants = new Map<string, Rule>();

  if (overlay.witnesses_expected === 0) {
    variants.set(
      "EST-101",
      absenceRule({
        ...SPEC_101,
        severity: "info",
        explanation:
          `${overlay.state_name} does not require attesting witnesses for an ordinary signed will, so an absent attestation clause is not an execution defect under the asserted state's statute. An attestation clause remains useful evidence at probate.` +
          stateNote,
        recommendation:
          "No attestation clause is required under the asserted state's statute; consider one anyway as probate-proof convenience.",
        citations: [...SPEC_101.citations, overlay.citation],
      }),
    );
    variants.set(
      "EST-105",
      absenceRule({
        ...SPEC_105,
        severity: "info",
        explanation:
          `${overlay.state_name} does not require witness signatures for an ordinary signed will (witnesses are required only for a signature by mark or a proxy signature), so absent witness blocks are not an execution defect under the asserted state's statute.` +
          stateNote,
        recommendation:
          "No witness signature blocks are required under the asserted state's statute; witnesses who can prove the signature at probate remain useful.",
        citations: [...SPEC_105.citations, overlay.citation],
      }),
    );
  }

  if (overlay.notarial_testament) {
    variants.set(
      "EST-103",
      absenceRule({
        ...SPEC_103,
        severity: "warning",
        explanation:
          `${overlay.state_name}'s notarial testament requires execution in the presence of a notary AND two competent witnesses, with the testator signing at the end and on each other separate page and the notary and witnesses signing the prescribed attestation declaration — a missing notary block is a formality gap for this form, not an optional extra.` +
          stateNote,
        recommendation:
          "Add the notary's signature block to the prescribed attestation declaration (notary + two witnesses), and confirm the testator signed at the end and on each other separate page.",
        citations: [...SPEC_103.citations, overlay.citation],
      }),
    );
  }

  if (overlay.notarization_alternative) {
    variants.set(
      "EST-105",
      absenceRule({
        ...SPEC_105,
        explanation:
          `${overlay.state_name} accepts EITHER at least two witnesses signing within a reasonable time OR the testator's acknowledgment before a notary public, so absent witness blocks are not per-se non-compliance when a notarial acknowledgment is present.` +
          stateNote,
        recommendation:
          "Add at least two witness signature blocks, or confirm the will carries a notarial acknowledgment — the asserted state accepts notarization in lieu of witnesses.",
        citations: [...SPEC_105.citations, overlay.citation],
      }),
    );
  }

  const rules =
    variants.size === 0
      ? ESTATE_CHECK_RULES
      : ESTATE_CHECK_RULES.map((r) => variants.get(r.id) ?? r);
  if (overlay.witnesses_expected === 0) return rules;
  return [...rules, statuteWitnessCountRule(overlay)];
}

// ────────────────────────────────────────────────────────────────────
// EST-107 — witness signature blocks vs. the asserted state's statute
// (the statute-aware companion to EST-106's internal-consistency check,
// unlocked by the overlay's verified `witnesses_expected`). Exists only
// under a seeded overlay that expects witnesses — the neutral path and
// the PA zero-witness path keep their exact rule lists. Fires when at
// least one block is present (zero blocks stays EST-105's finding) but
// fewer than the statute expects, and stays silent when the will's own
// recital already overstates the blocks — that mismatch is EST-106's
// finding, and double-reporting it would be noise. Under a
// notarization-alternative state (CO/ND) the check is conditional on
// the alternative's own evidence: a detected notarial acknowledgment
// (EST-103's presence patterns) can stand in for the witnesses
// entirely, so the shortfall is silent — but with NO notary language
// either, neither statutory path is evidenced and the shortfall is a
// warning naming both paths.
// ────────────────────────────────────────────────────────────────────

/**
 * Adapt the always-on EST-0NN base rules to the asserted state's overlay
 * (audit finding: under `--state pa`, shipped EST-008 fired a critical
 * "UPC § 2-502 requires at least two competent witnesses" in the same
 * report where the overlay's EST-101/105 said PA requires none — the
 * loudest possible contradiction for an attorney). Under a zero-witness
 * state, EST-008's finding is rewritten to an info note speaking the
 * state's statute. Every other rule object passes through UNTOUCHED, and
 * with no overlay (or a witness-expecting one) the input array is
 * returned as-is — the `--state` path already changes `result_hash`, so
 * only asserted runs can see the rewrite.
 */
export function adaptBaseRulesForOverlay(
  baseRules: readonly Rule[],
  overlay: EstateFormalityOverlay | undefined,
): readonly Rule[] {
  if (!overlay || overlay.witnesses_expected !== 0) return baseRules;
  return baseRules.map((base) => {
    if (base.id !== "EST-008") return base;
    const variant: Rule = {
      ...base,
      version: "1.1.0",
      default_severity: "info",
      check(ctx: RuleContext): Finding | null {
        const f = base.check(ctx);
        if (!f) return null;
        return {
          ...f,
          rule_version: "1.1.0",
          severity: "info",
          explanation:
            `${overlay.state_name} does not require attesting witnesses for an ordinary signed will, so an absent witnesses/notary execution block is not an execution defect under the asserted state's statute — a testator signature block is what matters. Witness and notary blocks remain useful probate-proof convenience.` +
            ` Asserted state: ${overlay.state_name} — ${overlay.headline} (${overlay.citation.source}).`,
          recommendation:
            "No witness or notary block is required under the asserted state's statute; confirm the testator signature block, and consider witness lines anyway as probate-proof convenience.",
          source_citations: [...f.source_citations, overlay.citation],
        };
      },
    };
    return variant;
  });
}

function statuteWitnessCountRule(overlay: EstateFormalityOverlay): Rule {
  const expected = overlay.witnesses_expected;
  const alternative = overlay.notarization_alternative;
  return {
    id: "EST-107",
    version: "1.1.0",
    name: "Witness signature blocks fewer than the asserted state expects",
    category: CATEGORY,
    default_severity: "warning",
    description: `The number of witness signature blocks should be at least the ${expected} the asserted state's statute expects.`,
    dkb_citations: ["upc-2-502", overlay.citation.id],
    applies_to_playbooks: [...PLAYBOOKS],
    assertion_gate: GATE,
    check(ctx: RuleContext): Finding | null {
      const blocks = witnessSignatureBlockCount(ctx);
      if (blocks === 0 || blocks >= expected) return null;
      const text = fullTextLower(ctx);
      const recited = recitedWitnessCount(text);
      if (recited !== undefined && blocks < recited) return null;
      const notaryDetected = alternative && SPEC_103.patterns.some((re) => re.test(text));
      if (notaryDetected) return null;
      return makeFinding({
        rule: this as Rule,
        title: `Will shows ${blocks} witness signature block${blocks === 1 ? "" : "s"}; ${overlay.state_name} expects ${expected}`,
        description: `${blocks} witness signature block${blocks === 1 ? " was" : "s were"} detected, but the asserted state's statute expects at least ${expected} attesting witnesses.`,
        excerptText: "(witness signature blocks fewer than the asserted state's statute expects)",
        explanation:
          (alternative
            ? `${overlay.state_name} accepts EITHER at least ${expected} attesting witnesses OR the testator's acknowledgment before a notary public — and neither path is evidenced here: fewer witness signature blocks were detected and no notarial acknowledgment language was found.`
            : `${overlay.state_name}'s statute expects at least ${expected} attesting witnesses, and fewer witness signature blocks were detected. This is a recital observation, not a determination of invalid execution.`) +
          ` Asserted state: ${overlay.state_name} — ${overlay.headline} (${overlay.citation.source}).`,
        recommendation: alternative
          ? `Add the missing witness signature block(s) or a notarial acknowledgment — ${overlay.state_name} accepts notarization in lieu of witnesses.`
          : `Add the missing witness signature block(s) so the will shows at least ${expected} witness signatures.`,
        position: docTop(ctx),
        source_citations: [upc("2-502", "execution; witnessed wills"), overlay.citation],
      });
    },
  };
}
