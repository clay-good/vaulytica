/**
 * PNOT presence rules — generated from the regime content-item data in
 * `src/privacy/regime-data.ts` via the generic `buildPresenceRule` factory
 * (add-privacy-notice-pack). One rule per enumerated content item, per
 * regime; a rule fires when none of the item's `present_patterns` match the
 * notice's heading + paragraph text.
 *
 * Scope: CCPA/CPRA, GDPR Articles 13/14, and the CO/VA/TX/OR state acts.
 * Texas additionally carries two EXACT-WORDING rules for the § 541.102(b)–(c)
 * mandated notice texts: they fire when the document indicates a sale of
 * sensitive/biometric personal data without the verbatim notice ("absent"),
 * or when a near-variant of the notice appears that deviates from the
 * mandated wording ("present but altered", quoting the altered text). A
 * document that never suggests such a sale is silent — the statute mandates
 * the text only for controllers that sell that data.
 *
 * Virginia and Texas additionally carry a CONDITIONAL opt-out disclosure rule
 * each (Va. Code § 59.1-578(D); Tex. Bus. & Com. Code § 541.103): fired only
 * when the notice itself evidences a sale of personal data or targeted-
 * advertising processing (negation-guarded) while never mentioning an
 * opt-out. A notice that does neither is silent.
 */

import type { Finding, Rule, RuleContext } from "../../finding.js";
import { makeFinding } from "../../finding.js";
import { forEachParagraph } from "../../../extract/walk.js";
import type { SourceCitation } from "../../../dkb/types.js";
import {
  buildPresenceRule,
  docTop,
  fullText,
  type PresenceSpec,
  type RegulatedRuleConfig,
} from "../v3/_regulated-rule.js";
import {
  REGIMES,
  TX_BIOMETRIC_SALE_NOTICE,
  TX_SENSITIVE_SALE_NOTICE,
  type ContentItem,
  type Regime,
  type RegimeId,
} from "../../../privacy/regime-data.js";

export const PRIVACY_NOTICE_PLAYBOOK_IDS = ["privacy-notice-us", "privacy-notice-gdpr"] as const;

export type PnotRule = Rule & { regime: RegimeId };

/** Maps a `RegimeId` to the uppercase token used in `PNOT-<TOKEN>-nnn` ids. */
const REGIME_TOKENS: Record<RegimeId, string> = {
  ccpa: "CCPA",
  "gdpr-13": "GDPR13",
  "gdpr-14": "GDPR14",
  co: "CO",
  va: "VA",
  tx: "TX",
  or: "OR",
};

function citeUrlFor(regime: Regime, citation: string): string {
  const item = regime.items.find((i) => i.citation === citation);
  return item?.url ?? regime.authority_url;
}

function specFor(regime: Regime, item: ContentItem, index: number): PresenceSpec {
  const token = REGIME_TOKENS[regime.id];
  const id = `PNOT-${token}-${String(index + 1).padStart(3, "0")}`;
  return {
    id,
    name: item.label,
    description: `${regime.name} requires: ${item.label}.`,
    citation: item.citation,
    missing_title: `${item.label} not found`,
    missing_description: `No language was found addressing "${item.label}," required by ${item.citation}.`,
    explanation: `${regime.name} requires the notice to address: ${item.label} (${item.citation}).`,
    recommendation: `Add a clause or section addressing "${item.label}" as required by ${item.citation}.`,
    present_patterns: item.present_patterns.map((src) => new RegExp(src, "i")),
    default_severity: "warning",
  };
}

function buildRegimeRules(regime: Regime): PnotRule[] {
  const regimeConfig: RegulatedRuleConfig = {
    category: "privacy-notice",
    applies_to_playbooks: [...PRIVACY_NOTICE_PLAYBOOK_IDS],
    cite_for(citation: string) {
      return {
        id: `privacy-item:${citation}`,
        source_url: citeUrlFor(regime, citation),
      };
    },
  };
  return regime.items.map((item, index) => {
    const rule = buildPresenceRule(specFor(regime, item, index), regimeConfig);
    return { ...rule, regime: regime.id };
  });
}

// ---------------------------------------------------------------------------
// Texas § 541.102(b)–(c) exact-wording rules.
// ---------------------------------------------------------------------------

type TxExactSpec = {
  id: string;
  /** "sensitive" | "biometric" — used in names and copy. */
  kind: string;
  citation: string;
  /** The verbatim mandated notice text. */
  mandated: string;
  /** A near-variant of the notice (case-insensitive) — "present but altered". */
  variant: RegExp;
  /** The document indicates this data may be sold — the notice is required. */
  trigger: RegExp;
};

const TX_EXACT_SPECS: TxExactSpec[] = [
  {
    id: "PNOT-TX-007",
    kind: "sensitive",
    citation: "Tex. Bus. & Com. Code § 541.102(b)",
    mandated: TX_SENSITIVE_SALE_NOTICE,
    variant: /sell\s+your\s+sensitive\s+personal\s+data/i,
    trigger:
      /\bs(?:ale|ell(?:s|ing)?)\b[^.]{0,80}\bsensitive\s+(?:personal\s+)?data\b|\bsensitive\s+(?:personal\s+)?data\b[^.]{0,80}\bs(?:ale|ell(?:s|ing)?|old)\b/i,
  },
  {
    id: "PNOT-TX-008",
    kind: "biometric",
    citation: "Tex. Bus. & Com. Code § 541.102(c)",
    mandated: TX_BIOMETRIC_SALE_NOTICE,
    variant: /sell\s+your\s+biometric\s+personal\s+data/i,
    trigger:
      /\bs(?:ale|ell(?:s|ing)?)\b[^.]{0,80}\bbiometric\s+(?:personal\s+)?data\b|\bbiometric\s+(?:personal\s+)?data\b[^.]{0,80}\bs(?:ale|ell(?:s|ing)?|old)\b/i,
  },
];

const normalizeWs = (s: string): string => s.replace(/\s+/g, " ").trim();

// The § 541.102 notices are mandated only for a controller that SELLS the data.
// A document that affirmatively DISCLAIMS selling ("we do not sell …", "we
// never sell or share …") does not owe the notice — treating its disclaimer as
// a sale indication is a false accusation. True when the sentence negates the
// sale/share verb.
const SALE_DISCLAIMED =
  /\b(?:do(?:es)?\s+not|did\s+not|will\s+not|would\s+not|won'?t|shall\s+not|cannot|can'?t|never|not)\b[^.;\n]{0,40}\b(?:sell|sells|selling|sold|sale|share|shares|shared)\b|\bno\s+(?:sale|selling|sharing)\b/i;

/** The single sentence of `text` containing `index`, for the negation check. */
function sentenceAround(text: string, index: number): string {
  const start = Math.max(text.lastIndexOf(".", index), text.lastIndexOf("\n", index)) + 1;
  const relEnd = text.slice(index).search(/[.\n]/);
  const end = relEnd === -1 ? text.length : index + relEnd;
  return text.slice(start, end);
}

function txCite(spec: TxExactSpec): SourceCitation {
  return {
    id: `privacy-item:${spec.citation}`,
    source: spec.citation,
    source_url: REGIMES.tx.authority_url,
    retrieved_at: "2026-07-17T00:00:00Z",
    license: "Public domain or regulator re-use",
    license_url: "https://www.usa.gov/government-works",
  };
}

/**
 * Build one § 541.102(b)/(c) exact-wording rule. Check order: the verbatim
 * notice anywhere (whitespace-normalized, case-sensitive) → silent; else a
 * near-variant paragraph → "present but altered" quoting the altered text;
 * else a sale indication → "absent"; else silent (the notice is mandated only
 * for a controller that sells that data — never a blanket demand).
 */
function buildTxExactRule(spec: TxExactSpec): PnotRule {
  return {
    id: spec.id,
    version: "1.0.0",
    name: `Mandated ${spec.kind}-data sale notice (exact wording)`,
    category: "privacy-notice",
    default_severity: "warning",
    description: `${spec.citation} mandates the exact text "${spec.mandated}" for a controller that sells ${spec.kind} personal data.`,
    dkb_citations: [`privacy-item:${spec.citation}`],
    applies_to_playbooks: [...PRIVACY_NOTICE_PLAYBOOK_IDS],
    regime: "tx",
    check(ctx: RuleContext): Finding | null {
      let exact = false;
      let altered: { text: string; section_id: string; paragraph_id: string } | null = null;
      forEachParagraph(ctx.tree, (p) => {
        if (exact) return;
        if (normalizeWs(p.text).includes(spec.mandated)) {
          exact = true;
          return;
        }
        const vm = !altered ? spec.variant.exec(p.text) : null;
        if (vm && !SALE_DISCLAIMED.test(sentenceAround(p.text, vm.index))) {
          altered = { text: p.text, section_id: p.section.id, paragraph_id: p.paragraph.id };
        }
      });
      if (exact) return null;
      if (altered) {
        const a: { text: string; section_id: string; paragraph_id: string } = altered;
        return makeFinding({
          rule: this as Rule,
          title: `Mandated ${spec.kind}-data sale notice present but altered`,
          description: `Language resembling the ${spec.citation} notice was found, but it does not match the mandated wording exactly. Required: "${spec.mandated}"`,
          excerptText: a.text.slice(0, 280),
          explanation: `${spec.citation} prescribes the notice text verbatim; a paraphrase or altered rendering does not satisfy it.`,
          recommendation: `Replace the altered text with the exact statutory notice: "${spec.mandated}"`,
          position: { section_id: a.section_id, paragraph_id: a.paragraph_id, start: 0, end: 0 },
          source_citations: [txCite(spec)],
        });
      }
      const ft = fullText(ctx);
      const tm = spec.trigger.exec(ft);
      if (tm && !SALE_DISCLAIMED.test(sentenceAround(ft, tm.index))) {
        return makeFinding({
          rule: this as Rule,
          title: `Mandated ${spec.kind}-data sale notice missing`,
          description: `The document indicates ${spec.kind} personal data may be sold, but the exact notice mandated by ${spec.citation} — "${spec.mandated}" — was not found.`,
          excerptText: "(mandated notice absent from the document)",
          explanation: `A controller that sells ${spec.kind} personal data must post the ${spec.citation} notice verbatim.`,
          recommendation: `Add the exact statutory notice: "${spec.mandated}"`,
          position: docTop(ctx),
          source_citations: [txCite(spec)],
        });
      }
      return null;
    },
  };
}

/** The two Texas exact-wording rules, appended after the six presence rules. */
export const TX_EXACT_RULES: readonly PnotRule[] = Object.freeze(
  TX_EXACT_SPECS.map(buildTxExactRule),
);

// ---------------------------------------------------------------------------
// VA § 59.1-578(D) / TX § 541.103 — conditional sale/targeted-advertising
// opt-out disclosure. Both statutes require a controller that sells personal
// data or processes it for targeted advertising to "clearly and conspicuously
// disclose" that processing AND the manner in which a consumer may opt out.
// The obligation is conditional, so a blanket presence rule would falsely
// accuse controllers that do neither; like the § 541.102(b)-(c) exact-wording
// rules, these fire only when the notice ITSELF evidences the condition — it
// says personal data is sold or processed for targeted advertising (negation-
// guarded) — while never mentioning an opt-out.
// ---------------------------------------------------------------------------

type OptOutSpec = {
  id: string;
  regime: RegimeId;
  citation: string;
  statute: string;
};

const OPT_OUT_SPECS: OptOutSpec[] = [
  {
    id: "PNOT-VA-007",
    regime: "va",
    citation: "Va. Code § 59.1-578(D)",
    statute: "the VCDPA",
  },
  {
    id: "PNOT-TX-009",
    regime: "tx",
    citation: "Tex. Bus. & Com. Code § 541.103",
    statute: "the TDPSA",
  },
];

/** The notice affirms a sale of personal data (negation handled separately). */
const SALE_OF_PERSONAL_DATA =
  /\bsell(?:s|ing)?\b[^.]{0,60}\bpersonal\s+(?:data|information)\b|\bsale\s+of\s+personal\s+(?:data|information)\b/i;

const TARGETED_ADS = /\btargeted\s+advertising\b/i;

/** The sentence negates the targeted-advertising processing ("we do not …"). */
const ADS_DISCLAIMED =
  /\b(?:do(?:es)?\s+not|did\s+not|will\s+not|would\s+not|won'?t|shall\s+not|cannot|can'?t|never|not)\b[^.;\n]{0,60}\btargeted\s+advertising\b|\bno\s+targeted\s+advertising\b/i;

function buildOptOutRule(spec: OptOutSpec): PnotRule {
  return {
    id: spec.id,
    version: "1.0.0",
    name: "Sale / targeted-advertising opt-out disclosure",
    category: "privacy-notice",
    default_severity: "warning",
    description: `${spec.citation} requires a controller that sells personal data or processes it for targeted advertising to disclose that processing and how consumers may opt out.`,
    dkb_citations: [`privacy-item:${spec.citation}`],
    applies_to_playbooks: [...PRIVACY_NOTICE_PLAYBOOK_IDS],
    regime: spec.regime,
    check(ctx: RuleContext): Finding | null {
      const ft = fullText(ctx);
      // Any opt-out language satisfies the "manner … to opt out" half; this
      // is a presence check, never a sufficiency conclusion.
      if (/\bopt[- ]?out\b/i.test(ft)) return null;

      const saleMatch = SALE_OF_PERSONAL_DATA.exec(ft);
      const saleEvidenced =
        saleMatch !== null && !SALE_DISCLAIMED.test(sentenceAround(ft, saleMatch.index));
      const adsMatch = TARGETED_ADS.exec(ft);
      const adsEvidenced =
        adsMatch !== null && !ADS_DISCLAIMED.test(sentenceAround(ft, adsMatch.index));
      if (!saleEvidenced && !adsEvidenced) return null;

      const processing = saleEvidenced
        ? adsEvidenced
          ? "selling personal data and processing it for targeted advertising"
          : "selling personal data"
        : "processing personal data for targeted advertising";
      return makeFinding({
        rule: this as Rule,
        title: "Opt-out disclosure missing for sale / targeted advertising",
        description: `The notice indicates ${processing}, but no language describing how a consumer may opt out of that processing was found, as ${spec.citation} requires.`,
        excerptText: "(opt-out disclosure absent from the document)",
        explanation: `Under ${spec.statute}, a controller that sells personal data or processes it for targeted advertising must clearly and conspicuously disclose that processing AND the manner in which a consumer may exercise the right to opt out (${spec.citation}).`,
        recommendation:
          "Add a clearly labeled opt-out disclosure (e.g. how to opt out of the sale of personal data or targeted advertising) alongside the processing disclosure.",
        position: docTop(ctx),
        source_citations: [
          {
            id: `privacy-item:${spec.citation}`,
            source: spec.citation,
            source_url: REGIMES[spec.regime].authority_url,
            retrieved_at: "2026-07-17T00:00:00Z",
            license: "Public domain or regulator re-use",
            license_url: "https://www.usa.gov/government-works",
          },
        ],
      });
    },
  };
}

/** The conditional opt-out disclosure rules (VA + TX), appended per regime. */
export const OPT_OUT_RULES: readonly PnotRule[] = Object.freeze(OPT_OUT_SPECS.map(buildOptOutRule));

export const PNOT_RULES: readonly PnotRule[] = Object.freeze([
  ...(Object.values(REGIMES) as Regime[]).flatMap(buildRegimeRules),
  ...TX_EXACT_RULES,
  ...OPT_OUT_RULES,
]);

/** Filter the full PNOT rule set down to the rules for the given regimes. */
export function pnotRulesForRegimes(regimes: readonly RegimeId[]): Rule[] {
  const wanted = new Set(regimes);
  return PNOT_RULES.filter((r) => wanted.has(r.regime));
}
