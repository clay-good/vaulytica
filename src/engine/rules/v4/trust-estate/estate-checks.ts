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
import { upc } from "./_helpers.js";
import type { SourceCitation } from "../../../../dkb/types.js";

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
    version: "1.0.0",
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

const EST_101: Rule = absenceRule({
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
});

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

const EST_103: Rule = absenceRule({
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
});

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

const EST_105: Rule = absenceRule({
  id: "EST-105",
  name: "Witness signature blocks present",
  severity: "warning",
  // Presence-only in v1 — this does not attempt to count the detected
  // witness signature lines against a number the will recites elsewhere
  // (e.g. "two witnesses"); that comparison is a future refinement.
  patterns: [
    /_{3,}\s*witness/,
    /witness.{0,20}(signature|sign|_{3,})/,
    /signature of.{0,20}witness/,
  ],
  missingTitle: "No witness signature blocks detected",
  missingDescription: "No witness signature blocks were found in the document text.",
  explanation:
    "UPC § 2-502 requires at least two witnesses to sign the will. Witness signature blocks are the concrete evidence of that formality.",
  recommendation:
    "Add at least two witness signature blocks (signature line, printed name, address).",
  citations: [upc("2-502")],
});

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
    const text = fullTextLower(ctx);
    if (!RESIDUE_RE.test(text)) return null;
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
  EST_201,
  EST_301,
  EST_302,
  EST_303,
  EST_304,
];

export const ESTATE_CHECK_RULE_IDS: readonly string[] = ESTATE_CHECK_RULES.map((r) => r.id);
