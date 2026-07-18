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

export const PNOT_RULES: readonly PnotRule[] = Object.freeze([
  ...(Object.values(REGIMES) as Regime[]).flatMap(buildRegimeRules),
  ...TX_EXACT_RULES,
]);

/** Filter the full PNOT rule set down to the rules for the given regimes. */
export function pnotRulesForRegimes(regimes: readonly RegimeId[]): Rule[] {
  const wanted = new Set(regimes);
  return PNOT_RULES.filter((r) => wanted.has(r.regime));
}
