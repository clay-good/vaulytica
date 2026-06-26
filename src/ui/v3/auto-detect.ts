/**
 * v3 document-type auto-detect (spec-v3.md §60).
 *
 * Layers on top of v2's playbook auto-detect rather than replacing it.
 * The v3 detector returns a v3-family classification (BAA, DPA, SCC, COI,
 * etc.) and a suggested playbook id; it is a pure function from the
 * extracted-data tree (parties, definitions, classified paragraphs) plus
 * the raw body text. No IO, no time, no randomness.
 *
 * The detector intentionally errs toward "unknown" rather than guessing.
 * The UI presents the v3 detection as a *suggestion* the user can accept
 * or override — the v2 match remains authoritative until the user
 * explicitly chooses a v3 playbook.
 */

import type { ExtractedData } from "../../extract/types.js";

export type V3Family =
  | "baa"
  | "dpa-eu"
  | "dpa-us-state"
  | "scc-module-2"
  | "scc-module-3"
  | "uk-idta"
  | "nda-deep"
  | "msa-deep"
  | "coi"
  | "vendor-security"
  | "ai-addendum"
  | "unknown";

/** A single signal in the detection trail. Surfaced to the user as a tooltip / "why this?". */
export type DetectionSignal = {
  source: "definition" | "phrase" | "header" | "annex" | "classified";
  evidence: string;
  weight: number;
};

export type V3Detection = {
  family: V3Family;
  /** Suggested playbook id from `src/playbooks/v3/`. */
  suggested_playbook: string | null;
  /** Confidence in [0, 1]; below 0.4 the suggestion should be presented faintly. */
  confidence: number;
  /** Audit trail for the suggestion. Always non-empty unless family === "unknown". */
  signals: DetectionSignal[];
};

export const FAMILY_TO_PLAYBOOK: Record<V3Family, string | null> = {
  baa: "baa",
  "dpa-eu": "dpa-controller-processor",
  "dpa-us-state": "dpa-ccpa-service-provider",
  "scc-module-2": "scc-module-2",
  "scc-module-3": "scc-module-3",
  "uk-idta": "uk-idta-addendum",
  "nda-deep": "mutual-nda-deep",
  "msa-deep": "msa-vendor-deep",
  coi: "coi",
  "vendor-security": "vendor-security-addendum",
  "ai-addendum": "ai-addendum",
  unknown: null,
};

/**
 * Run every v3 family detector against the document and return the best
 * scoring family. Each detector returns a list of signals; the family
 * with the highest weighted sum wins. Ties resolve by detector order
 * (the order listed below — BAA before DPA before SCC, etc.).
 */
export function detectV3Family(extracted: ExtractedData, body_text: string): V3Detection {
  const text = body_text;
  const candidates: Array<{ family: V3Family; signals: DetectionSignal[] }> = [
    { family: "baa", signals: detectBaa(extracted, text) },
    { family: "dpa-eu", signals: detectDpaEu(extracted, text) },
    { family: "dpa-us-state", signals: detectDpaUsState(extracted, text) },
    { family: "scc-module-2", signals: detectSccModule(extracted, text, 2) },
    { family: "scc-module-3", signals: detectSccModule(extracted, text, 3) },
    { family: "uk-idta", signals: detectUkIdta(extracted, text) },
    { family: "nda-deep", signals: detectNdaDeep(extracted, text) },
    { family: "msa-deep", signals: detectMsaDeep(extracted, text) },
    { family: "coi", signals: detectCoi(extracted, text) },
    { family: "vendor-security", signals: detectVendorSecurity(extracted, text) },
    { family: "ai-addendum", signals: detectAiAddendum(extracted, text) },
  ];

  let best = { family: "unknown" as V3Family, signals: [] as DetectionSignal[], score: 0 };
  for (const c of candidates) {
    const score = c.signals.reduce((s, sig) => s + sig.weight, 0);
    if (score > best.score) best = { family: c.family, signals: c.signals, score };
  }

  if (best.score < 1) {
    return { family: "unknown", suggested_playbook: null, confidence: 0, signals: [] };
  }

  const confidence = Math.min(1, best.score / 4);
  // NDA-deep further splits to mutual vs unilateral by symmetry signal.
  // Both playbooks (mutual-nda-deep, unilateral-nda-deep) live at v1.0.0
  // and carry distinct compliance-matrix columns; routing to the wrong
  // variant means the matrix renders the wrong symmetry column. Keep
  // the family id (nda-deep) stable so existing consumers, fixtures,
  // and the chip label table are unaffected.
  let suggested_playbook = FAMILY_TO_PLAYBOOK[best.family];
  let extraSignals: DetectionSignal[] = [];
  if (best.family === "nda-deep") {
    const ndaResolution = resolveNdaDeepVariant(text);
    suggested_playbook = ndaResolution.playbook;
    extraSignals = ndaResolution.signals;
  }
  return {
    family: best.family,
    suggested_playbook,
    confidence,
    signals: [...best.signals, ...extraSignals],
  };
}

/**
 * Resolve `nda-deep` to either `mutual-nda-deep` or `unilateral-nda-deep`
 * based on textual symmetry signals. Falls back to mutual when signals
 * are absent — mutual is the safer default because mutual rules include
 * a symmetry check the unilateral playbook does not, so a unilateral
 * document analyzed under the mutual playbook produces strictly more
 * findings (a false-positive surface), whereas a mutual document
 * analyzed under the unilateral playbook would miss the symmetry rule
 * entirely (a false-negative surface).
 */
function resolveNdaDeepVariant(text: string): {
  playbook: string;
  signals: DetectionSignal[];
} {
  const signals: DetectionSignal[] = [];
  // Strong mutual markers — explicit title or symmetry vocabulary.
  const mutualHeader =
    /\bmutual\s+(?:non-?disclosure|confidentiality)\b|\btwo-?way\s+(?:non-?disclosure|confidentiality|nda)\b|\bbilateral\s+(?:non-?disclosure|confidentiality|nda)\b/i;
  const mutualPhrase = /\beach\s+party\b|\beither\s+party\b/i;
  // Strong unilateral markers — explicit title or asymmetric role
  // vocabulary that names a single discloser.
  const unilateralHeader =
    /\bunilateral\s+(?:non-?disclosure|confidentiality|nda)\b|\bone-?way\s+(?:non-?disclosure|confidentiality|nda)\b/i;
  const unilateralRoles =
    /\b(?:disclosing\s+party|discloser)\b[\s\S]{0,400}\b(?:receiving\s+party|recipient)\b/i;
  let mutualScore = 0;
  let unilateralScore = 0;
  if (mutualHeader.test(text)) {
    signals.push({ source: "header", evidence: "Mutual / two-way / bilateral NDA", weight: 3 });
    mutualScore += 3;
  }
  if (mutualPhrase.test(text)) {
    signals.push({ source: "phrase", evidence: "Each / either party", weight: 1 });
    mutualScore += 1;
  }
  if (unilateralHeader.test(text)) {
    signals.push({ source: "header", evidence: "Unilateral / one-way NDA", weight: 3 });
    unilateralScore += 3;
  }
  if (unilateralRoles.test(text) && !mutualHeader.test(text)) {
    signals.push({
      source: "phrase",
      evidence: "Discloser → Recipient role framing",
      weight: 1,
    });
    unilateralScore += 1;
  }
  if (unilateralScore > mutualScore) {
    return { playbook: "unilateral-nda-deep", signals };
  }
  return { playbook: "mutual-nda-deep", signals };
}

/* ---------------- detectors ----------------- */

function detectBaa(extracted: ExtractedData, text: string): DetectionSignal[] {
  const out: DetectionSignal[] = [];
  // Strongest signal: "Business Associate" defined term in the definitions
  // map — `extracted.definitions` is keyed by canonical term.
  for (const { term } of extracted.definitions.entries) {
    if (/business\s+associate/i.test(term)) {
      out.push({ source: "definition", evidence: term, weight: 3 });
      break;
    }
  }
  // Citation to 45 CFR § 164.504(e) or 164.314(a).
  if (/\b45\s*C\.?F\.?R\.?\s*§?\s*164\.(?:504|314|410)/i.test(text)) {
    out.push({ source: "phrase", evidence: "45 CFR § 164.504/314/410", weight: 2 });
  }
  // Phrase "Protected Health Information" or "PHI".
  if (/\bprotected\s+health\s+information\b|\bPHI\b/.test(text)) {
    out.push({ source: "phrase", evidence: "PHI / Protected Health Information", weight: 1 });
  }
  if (/\bbusiness\s+associate\s+agreement\b/i.test(text)) {
    out.push({ source: "header", evidence: "Business Associate Agreement", weight: 2 });
  }
  return out;
}

function detectDpaEu(extracted: ExtractedData, text: string): DetectionSignal[] {
  const out: DetectionSignal[] = [];
  let controller = false;
  let processor = false;
  for (const { term } of extracted.definitions.entries) {
    if (/^controller$|\bdata\s+controller\b/i.test(term)) controller = true;
    if (/^processor$|\bdata\s+processor\b/i.test(term)) processor = true;
  }
  if (controller && processor) {
    out.push({ source: "definition", evidence: "Controller + Processor defined", weight: 3 });
  }
  if (/\bGDPR\b|\bGeneral\s+Data\s+Protection\s+Regulation\b/i.test(text)) {
    out.push({ source: "phrase", evidence: "GDPR mentioned", weight: 1 });
  }
  if (/\barticle\s+28\b|\bart\.\s*28\b/i.test(text)) {
    out.push({ source: "phrase", evidence: "Article 28", weight: 2 });
  }
  if (/\bdata\s+processing\s+(?:agreement|addendum)\b/i.test(text)) {
    out.push({ source: "header", evidence: "Data Processing Agreement", weight: 2 });
  }
  return out;
}

function detectDpaUsState(extracted: ExtractedData, text: string): DetectionSignal[] {
  const out: DetectionSignal[] = [];
  let serviceProvider = false;
  for (const { term } of extracted.definitions.entries) {
    if (/service\s+provider/i.test(term)) serviceProvider = true;
  }
  if (serviceProvider) {
    out.push({ source: "definition", evidence: "Service Provider defined", weight: 2 });
  }
  if (/\bCCPA\b|\bCalifornia\s+Consumer\s+Privacy\b/.test(text)) {
    out.push({ source: "phrase", evidence: "CCPA reference", weight: 2 });
  }
  // State statute citations
  if (/\b1798\.140\b|\b1798\.100\b|\b59\.1-579\b|\b6-1-1305\b/.test(text)) {
    out.push({ source: "phrase", evidence: "US state privacy statute cited", weight: 2 });
  }
  return out;
}

function detectSccModule(extracted: ExtractedData, text: string, module: 2 | 3): DetectionSignal[] {
  const out: DetectionSignal[] = [];
  if (/\b(?:standard\s+contractual\s+clauses|SCCs?)\b/i.test(text)) {
    out.push({ source: "phrase", evidence: "Standard Contractual Clauses", weight: 1 });
  }
  if (/\bImplementing\s+Decision\s+\(EU\)\s+2021\/914\b/i.test(text)) {
    out.push({ source: "phrase", evidence: "Implementing Decision (EU) 2021/914", weight: 2 });
  }
  const moduleRe =
    module === 2
      ? /\bmodule\s+(?:two|2|II)\b|\bcontroller\s*-\s*to\s*-\s*processor\b/i
      : /\bmodule\s+(?:three|3|III)\b|\bprocessor\s*-\s*to\s*-\s*processor\b/i;
  if (moduleRe.test(text)) {
    out.push({ source: "phrase", evidence: `Module ${module}`, weight: 2 });
  }
  if (/\bclause\s+(?:1[0-8]|[1-9])\.[0-9]/i.test(text)) {
    out.push({ source: "phrase", evidence: "Numbered SCC clause", weight: 1 });
  }
  void extracted;
  return out;
}

function detectUkIdta(extracted: ExtractedData, text: string): DetectionSignal[] {
  const out: DetectionSignal[] = [];
  if (/\bInternational\s+Data\s+Transfer\s+Agreement\b|\bUK\s+IDTA\b/i.test(text)) {
    out.push({ source: "phrase", evidence: "UK IDTA", weight: 3 });
  }
  if (/\bUK\s+Addendum\b/i.test(text)) {
    out.push({ source: "phrase", evidence: "UK Addendum", weight: 2 });
  }
  if (/\bICO\b|\bInformation\s+Commissioner\b/i.test(text)) {
    out.push({ source: "phrase", evidence: "ICO reference", weight: 1 });
  }
  void extracted;
  return out;
}

function detectNdaDeep(extracted: ExtractedData, text: string): DetectionSignal[] {
  const out: DetectionSignal[] = [];
  if (/\bnon-?disclosure\s+agreement\b|\bconfidentiality\s+agreement\b/i.test(text)) {
    out.push({
      source: "header",
      evidence: "Non-Disclosure / Confidentiality Agreement",
      weight: 2,
    });
  }
  if (/\btrade\s+secrets?\b/i.test(text)) {
    out.push({ source: "phrase", evidence: "Trade secrets", weight: 1 });
  }
  if (/\bDTSA\b|\b18\s*U\.?S\.?C\.?\s*§\s*1833\b/.test(text)) {
    out.push({ source: "phrase", evidence: "DTSA / § 1833 reference", weight: 2 });
  }
  // Defined-term signal. The two playbooks (mutual-nda-deep,
  // unilateral-nda-deep) both list "Confidential Information" as
  // load-bearing and call out either Discloser/Recipient (unilateral)
  // or each-side discloser/receiver roles (mutual). Presence of a
  // formally-defined "Confidential Information" or
  // "Disclosing/Receiving Party" is a strong NDA signal that
  // pattern-matching the body alone may miss when the defined term is
  // introduced in a definitions appendix away from the running text.
  let sawConfidentialInformation = false;
  let sawDiscloserOrRecipient = false;
  for (const { term } of extracted.definitions.entries) {
    if (!sawConfidentialInformation && /\bconfidential\s+information\b/i.test(term)) {
      sawConfidentialInformation = true;
    }
    if (
      !sawDiscloserOrRecipient &&
      /\b(?:disclos(?:ing|er)|recipient|receiving\s+party)\b/i.test(term)
    ) {
      sawDiscloserOrRecipient = true;
    }
  }
  if (sawConfidentialInformation) {
    out.push({ source: "definition", evidence: "Confidential Information defined", weight: 2 });
  }
  if (sawDiscloserOrRecipient) {
    out.push({ source: "definition", evidence: "Discloser / Recipient defined", weight: 1 });
  }
  return out;
}

function detectMsaDeep(extracted: ExtractedData, text: string): DetectionSignal[] {
  const out: DetectionSignal[] = [];
  if (/\bmaster\s+services?\s+agreement\b|\bMSA\b/.test(text)) {
    out.push({ source: "header", evidence: "Master Services Agreement", weight: 2 });
  }
  if (/\border\s+of\s+precedence\b/i.test(text)) {
    out.push({ source: "phrase", evidence: "Order of precedence", weight: 1 });
  }
  if (/\bstatements?\s+of\s+work\b|\bSOWs?\b/i.test(text)) {
    out.push({ source: "phrase", evidence: "Statement(s) of Work", weight: 1 });
  }
  if (/\blimitation\s+of\s+liability\b/i.test(text)) {
    out.push({ source: "phrase", evidence: "Limitation of liability", weight: 1 });
  }
  // Defined-term signal. MSAs almost always introduce "Services" and
  // either "Order Form" or "Statement of Work" as formally-defined
  // terms; "Deliverables" is the third structural definition.
  for (const { term } of extracted.definitions.entries) {
    if (/^services?$/i.test(term)) {
      out.push({ source: "definition", evidence: "Services defined", weight: 1 });
      break;
    }
  }
  for (const { term } of extracted.definitions.entries) {
    if (/^(?:order\s+form|statement\s+of\s+work|sow)$/i.test(term)) {
      out.push({ source: "definition", evidence: "Order Form / SOW defined", weight: 1 });
      break;
    }
  }
  return out;
}

function detectCoi(extracted: ExtractedData, text: string): DetectionSignal[] {
  const out: DetectionSignal[] = [];
  if (/\bACORD\s*25\b|\bcertificate\s+of\s+liability\s+insurance\b/i.test(text)) {
    out.push({
      source: "header",
      evidence: "ACORD 25 / Certificate of Liability Insurance",
      weight: 3,
    });
  }
  if (/\binsurer\b|\bcarrier\b/i.test(text) && /\bcoverage\b/i.test(text)) {
    out.push({ source: "phrase", evidence: "Insurer + Coverage", weight: 1 });
  }
  void extracted;
  return out;
}

function detectVendorSecurity(extracted: ExtractedData, text: string): DetectionSignal[] {
  const out: DetectionSignal[] = [];
  if (/\bvendor\s+security\s+(?:addendum|exhibit|schedule)\b/i.test(text)) {
    out.push({ source: "header", evidence: "Vendor Security Addendum", weight: 3 });
  }
  if (/\bSOC\s*2(?:\s+Type\s*II)?\b|\bISO\s*27001\b/i.test(text)) {
    out.push({ source: "phrase", evidence: "SOC 2 / ISO 27001", weight: 1 });
  }
  // Defined-term signal. Vendor security addenda introduce "Customer
  // Data" (or "Personal Data") and "Security Measures" / "Security
  // Standards" as the two load-bearing definitions.
  for (const { term } of extracted.definitions.entries) {
    if (/\bcustomer\s+data\b|\bpersonal\s+data\b/i.test(term)) {
      out.push({ source: "definition", evidence: "Customer / Personal Data defined", weight: 1 });
      break;
    }
  }
  for (const { term } of extracted.definitions.entries) {
    if (/\bsecurity\s+(?:measures?|standards?|controls?)\b/i.test(term)) {
      out.push({ source: "definition", evidence: "Security Measures defined", weight: 1 });
      break;
    }
  }
  return out;
}

function detectAiAddendum(extracted: ExtractedData, text: string): DetectionSignal[] {
  const out: DetectionSignal[] = [];
  if (/\b(?:AI|artificial\s+intelligence)\s+(?:addendum|exhibit|schedule)\b/i.test(text)) {
    out.push({ source: "header", evidence: "AI Addendum", weight: 3 });
  }
  if (/\blarge\s+language\s+model\b|\bgenerative\s+AI\b/i.test(text)) {
    out.push({ source: "phrase", evidence: "LLM / Generative AI", weight: 1 });
  }
  if (/\bNIST\s+AI\s+RMF\b/i.test(text)) {
    out.push({ source: "phrase", evidence: "NIST AI RMF", weight: 1 });
  }
  // Defined-term signal. AI addenda commonly introduce "Model" /
  // "Foundation Model" and "Training Data" / "Output" as formal
  // definitions; presence is a strong AI-addendum signal even when
  // the title is generic ("Schedule 4: AI Services").
  for (const { term } of extracted.definitions.entries) {
    if (/\b(?:foundation\s+)?model\b|\bllm\b/i.test(term)) {
      out.push({ source: "definition", evidence: "Model / Foundation Model defined", weight: 1 });
      break;
    }
  }
  for (const { term } of extracted.definitions.entries) {
    if (/\btraining\s+data\b|\bmodel\s+output\b|^output$/i.test(term)) {
      out.push({ source: "definition", evidence: "Training Data / Output defined", weight: 1 });
      break;
    }
  }
  return out;
}
