/**
 * Initial cross-document consistency rules (spec-v3.md §27).
 *
 * Coverage:
 *
 *   CC-001  BAA-purpose-no-broader-than-MSA
 *   CC-002  DPA-purpose-matches-MSA-services
 *   CC-003  DPA-data-categories-not-broader-than-MSA
 *   CC-004  BAA-term-matches-MSA-or-is-explicitly-extended
 *   CC-005  Governing-law-alignment
 *   CC-006  Notice-alignment
 *   CC-007  Order-of-precedence-consistency
 *
 * Each rule is pure — no IO, no time, no randomness. Each finding cites both
 * (or all) contributing documents and quotes the conflicting text.
 *
 * The heuristics are intentionally conservative: false negatives are
 * preferred over false positives for cross-document checks, because a
 * spurious "your BAA contradicts your MSA" finding is harder for a
 * compliance officer to dismiss than a missed contradiction is to catch
 * during a regulator-grade review.
 */

import type { ConsistencyRule, ConsistencyFinding, ConsistencyDocument } from "../types.js";
import { findByKind, findParagraph, fullText } from "../_helpers.js";
import { forEachParagraph } from "../../../extract/walk.js";
import { paragraphExcerpt, textExcerpt, makeConsistencyFinding } from "./_finding.js";

const RULE_VERSION = "1.0.0";

/* -------------------- CC-001 BAA-purpose-no-broader-than-MSA ----- */

export const CC_001_BAA_PURPOSE: ConsistencyRule = {
  id: "CC-001",
  version: RULE_VERSION,
  name: "BAA permitted uses no broader than MSA purpose",
  category: "consistency",
  default_severity: "critical",
  description:
    "Under 45 CFR § 164.504(e)(2)(i)(A) the BAA's permitted uses cannot exceed the covered entity's own permitted uses. The MSA's service description bounds those permitted uses; if the BAA grants 'any purpose' or 'any business purpose' use of PHI it is broader than the MSA contemplates.",
  requires: ["msa", "baa"],
  check(ctx): ConsistencyFinding[] {
    const msa = findByKind(ctx.documents, "msa");
    const baa = findByKind(ctx.documents, "baa");
    if (!msa || !baa) return [];

    // Detect open-ended permitted-uses language in the BAA. The gap is a
    // tempered token that stops at a "not": a clause that *restricts* PHI use
    // ("may NOT use … for any purpose OTHER THAN the Services") contains the
    // substring "any purpose" but is the opposite of open-ended, so it must not
    // trip a false-positive critical cross-doc finding. (bounded → no ReDoS.)
    const baaBroad = findParagraph(
      baa,
      /(?:permitted\s+uses?(?:(?!\bnot\b)[^.\n]){0,80}|business\s+associate\s+may(?:(?!\bnot\b)[^.\n]){0,80})\b(any\s+(?:business\s+)?purpose|any\s+lawful\s+purpose|any\s+purpose\s+permitted|for\s+any\s+reason)\b/i,
    );
    if (!baaBroad) return [];

    // Locate the MSA's services / purpose anchor.
    const msaServices =
      findParagraph(
        msa,
        /\b(scope\s+of\s+services|the\s+services|services\s+description|purpose\s+of\s+(?:this|the)\s+agreement)\b/i,
      ) ?? findParagraph(msa, /\bservice(?:s)?\s+to\s+be\s+provided\b/i);
    if (!msaServices) return [];

    return [
      makeConsistencyFinding({
        rule: CC_001_BAA_PURPOSE,
        title: "BAA permitted uses are broader than the MSA's service scope",
        description:
          "The BAA grants open-ended use of PHI ('any business purpose' or equivalent) while the MSA defines a specific service scope. The BAA's grant cannot exceed the covered entity's own permitted uses.",
        explanation:
          "HHS guidance under 45 CFR § 164.504(e) prohibits the business associate from using PHI other than as the covered entity itself could. An MSA that scopes services to (for example) claims processing cannot anchor a BAA permitting 'any business purpose' use of PHI.",
        recommendation:
          "Narrow the BAA's permitted-uses clause to the services described in the MSA (or to a defined Permitted Purpose that mirrors the MSA's scope).",
        excerpts: [paragraphExcerpt(baa, baaBroad), paragraphExcerpt(msa, msaServices)],
        source_citations: [hipaa504e()],
      }),
    ];
  },
};

/* -------------------- CC-002 DPA-purpose-matches-MSA-services ---- */

export const CC_002_DPA_PURPOSE: ConsistencyRule = {
  id: "CC-002",
  version: RULE_VERSION,
  name: "DPA processing purpose matches MSA services description",
  category: "consistency",
  default_severity: "warning",
  description:
    "GDPR Art. 28(3) requires the DPA to state the subject-matter and purpose of processing. That purpose must be tethered to the MSA's services; an open-ended 'any purpose authorized by Controller' grant defeats Art. 28(3).",
  requires: ["msa", "dpa"],
  check(ctx): ConsistencyFinding[] {
    const msa = findByKind(ctx.documents, "msa");
    const dpa = findByKind(ctx.documents, "dpa");
    if (!msa || !dpa) return [];

    // Tempered gap (stops at "not") for the same reason as CC-001: a clause
    // that tethers processing ("shall NOT extend to any purpose OTHER THAN the
    // Services") is Art. 28(3)-compliant, not open-ended, so it must not fire.
    const dpaBroad = findParagraph(
      dpa,
      /\b(?:processing\s+(?:purposes?|shall\s+be|will\s+be)|purpose\s+of\s+the\s+processing)\b(?:(?!\bnot\b)[^.\n]){0,120}\b(any\s+purpose|any\s+lawful\s+purpose|as\s+(?:the\s+)?controller\s+(?:may\s+)?direct|any\s+purpose\s+authori[sz]ed)\b/i,
    );
    if (!dpaBroad) return [];

    const msaServices =
      findParagraph(msa, /\b(scope\s+of\s+services|the\s+services|services\s+description)\b/i) ??
      findParagraph(msa, /\bservice(?:s)?\s+to\s+be\s+provided\b/i);
    if (!msaServices) return [];

    return [
      makeConsistencyFinding({
        rule: CC_002_DPA_PURPOSE,
        title: "DPA processing purpose is open-ended relative to the MSA",
        description:
          "The DPA states the processor will act 'for any purpose authorized by the Controller' (or equivalent), while the MSA scopes services concretely. Art. 28(3) requires the purpose to be specified.",
        explanation:
          "Art. 28(3) GDPR requires the DPA to set out 'the subject-matter and duration of the processing, the nature and purpose of the processing, the type of personal data and categories of data subjects'. A controller-discretion clause is not a stated purpose.",
        recommendation:
          "Replace 'any purpose authorized by Controller' with the MSA's services description (or a derived defined term), and pin the DPA's Annex I.B to it.",
        excerpts: [paragraphExcerpt(dpa, dpaBroad), paragraphExcerpt(msa, msaServices)],
        source_citations: [gdpr28()],
      }),
    ];
  },
};

/* -------------------- CC-003 DPA-data-categories-not-broader ---- */

const SENSITIVE_CATEGORY_TERMS: Array<{ term: RegExp; label: string }> = [
  {
    term: /\b(health(?:care)?\s+data|medical\s+(?:data|records)|health\s+information)\b/i,
    label: "health data",
  },
  { term: /\b(biometric\s+data|biometric\s+identifiers?)\b/i, label: "biometric data" },
  { term: /\bgenetic\s+data\b/i, label: "genetic data" },
  { term: /\b(racial|ethnic)\s+origin\b/i, label: "racial or ethnic origin" },
  { term: /\b(religious|philosophical)\s+beliefs?\b/i, label: "religious beliefs" },
  { term: /\b(political\s+opinions?)\b/i, label: "political opinions" },
  { term: /\b(trade[-\s]?union\s+membership)\b/i, label: "trade-union membership" },
  {
    term: /\b(sex(?:ual)?\s+life|sexual\s+orientation)\b/i,
    label: "sex life / sexual orientation",
  },
  {
    term: /\b(children'?s?\s+data|data\s+(?:of|concerning)\s+children|minors?'?\s+data)\b/i,
    label: "children's data",
  },
  {
    term: /\b(financial\s+account\s+numbers?|payment\s+card\s+(?:data|numbers?)|bank\s+account\s+(?:numbers?|details))\b/i,
    label: "financial account / payment card data",
  },
  {
    term: /\b(government[-\s]?issued\s+identifier|social\s+security\s+number|passport\s+number|driver'?s?\s+licen[cs]e\s+number)\b/i,
    label: "government-issued identifiers",
  },
];

export const CC_003_DPA_CATEGORIES: ConsistencyRule = {
  id: "CC-003",
  version: RULE_VERSION,
  name: "DPA data categories not broader than the MSA's services require",
  category: "consistency",
  default_severity: "warning",
  description:
    "The DPA's listed categories of personal data must be no broader than the MSA's services require. Categories of personal data appearing in the DPA but with no plausible basis in the MSA's scope are a Schrems-II-grade red flag.",
  requires: ["msa", "dpa"],
  check(ctx): ConsistencyFinding[] {
    const msa = findByKind(ctx.documents, "msa");
    const dpa = findByKind(ctx.documents, "dpa");
    if (!msa || !dpa) return [];

    const msaText = fullText(msa).toLowerCase();
    const findings: ConsistencyFinding[] = [];

    // For each sensitive category mentioned in the DPA, check the MSA for any
    // anchoring keyword. If absent, the DPA is unilaterally widening scope.
    forEachParagraph(dpa.tree, (p) => {
      for (const { term, label } of SENSITIVE_CATEGORY_TERMS) {
        const m = p.text.match(term);
        if (!m || m.index === undefined) continue;
        if (term.test(msaText)) continue;
        // Skip an explicit EXCLUSION — "the DPA does not process biometric
        // data", "excludes biometric identifiers". A stated exclusion means the
        // DPA is NARROWER than the MSA's scope, not broader; flagging it as
        // unauthorized scope-creep is a confident false conflict (the opposite
        // of what this rule detects).
        const before = p.text.slice(Math.max(0, m.index - 60), m.index);
        if (
          /\b(?:do(?:es)?\s+not\s+(?:process|include|collect|contain|cover|store|use|involve|handle)|(?:shall|will)\s+not\s+(?:process|include|collect|contain|cover|store|use)|excludes?|excluding|(?:contain|include|collect|process|store)s?\s+no)\b/i.test(
            before,
          )
        )
          continue;
        findings.push(
          makeConsistencyFinding({
            rule: CC_003_DPA_CATEGORIES,
            title: `DPA lists ${label} but the MSA does not contemplate it`,
            description: `The DPA names ${label} as a category of personal data processed, while the MSA's services description contains no anchor for it.`,
            explanation:
              "Art. 28(3) requires the DPA's type-of-personal-data section to reflect what the services actually involve. A DPA that grants the processor a broader category set than the MSA scopes is unenforceable as a scope cap and may itself be a GDPR violation.",
            recommendation: `Remove ${label} from the DPA's Annex I.B unless the MSA's services description is updated to make the basis explicit.`,
            excerpts: [
              paragraphExcerpt(dpa, p),
              {
                doc_id: msa.doc_id,
                source_file_name: msa.source_file_name,
                text: "[MSA services description contains no reference to " + label + "]",
                start_offset: 0,
                end_offset: 0,
              },
            ],
            source_citations: [gdpr28()],
          }),
        );
        // Only emit one finding per category per DPA paragraph.
        break;
      }
    });

    return findings;
  },
};

/* -------------------- CC-004 BAA-term-matches-MSA --------------- */

export const CC_004_BAA_TERM: ConsistencyRule = {
  id: "CC-004",
  version: RULE_VERSION,
  name: "BAA term aligns with MSA term (or extension is explicit)",
  category: "consistency",
  default_severity: "warning",
  description:
    "The BAA must end when the MSA ends (with HIPAA-required return/destruction obligations surviving), unless the BAA explicitly anchors its term to a different schedule. Silent divergence is a coverage gap.",
  requires: ["msa", "baa"],
  check(ctx): ConsistencyFinding[] {
    const msa = findByKind(ctx.documents, "msa");
    const baa = findByKind(ctx.documents, "baa");
    if (!msa || !baa) return [];

    // Skip if the BAA explicitly cross-references the MSA's term — common
    // and correct drafting ("this BAA is co-terminous with the Master
    // Services Agreement").
    const baaText = fullText(baa);
    if (
      /\b(co-?terminous|coextensive)\s+with\s+(?:the\s+)?(?:master\s+services?\s+agreement|msa|underlying\s+agreement|services\s+agreement)\b/i.test(
        baaText,
      )
    ) {
      return [];
    }
    if (
      /\bterm[s]?\s+of\s+(?:this\s+)?baa\s+(?:shall\s+)?(?:run|continue|remain)\s+(?:co-?incident|in\s+effect)\s+with\s+(?:the\s+)?(?:msa|services\s+agreement)\b/i.test(
        baaText,
      )
    ) {
      return [];
    }
    // A tie stated in different wording is still an explicit tie — "matching
    // the term of the Master Services Agreement", "the same term as the MSA",
    // "tied to / aligned with the MSA term". The two patterns above are only a
    // narrow phrase allowlist; without this, a correctly-drafted alignment is
    // reported as a silent divergence (a false "independent term" conflict).
    if (
      /\b(?:matching|tied\s+to|aligned\s+with|coincident\s+with|co-?terminous\s+with|coextensive\s+with|(?:the\s+)?same\s+(?:term\s+)?as|identical\s+to)\s+(?:the\s+)?(?:term\s+of\s+)?(?:the\s+)?(?:master\s+services?\s+agreement|msa|underlying\s+agreement|services\s+agreement)\b/i.test(
        baaText,
      )
    ) {
      return [];
    }

    // Find independent term language in the BAA.
    const baaTermPara =
      findParagraph(
        baa,
        /\bthis\s+(?:agreement|baa)\s+shall\s+(?:commence|be\s+effective|remain\s+in\s+effect)\b[^.\n]{0,200}\b(?:until\s+terminated|in\s+perpetuity|for\s+a\s+term\s+of\s+\d|until\s+\w+\s+\d{4})\b/i,
      ) ?? findParagraph(baa, /\beffective\s+date\b[^.\n]{0,80}\b\d{1,2}\/\d{1,2}\/\d{2,4}\b/i);
    if (!baaTermPara) return [];

    const msaTermPara =
      findParagraph(
        msa,
        /\bthis\s+agreement\s+shall\s+(?:commence|be\s+effective|remain\s+in\s+effect)\b/i,
      ) ?? findParagraph(msa, /\b(initial\s+term|term\s+of\s+this\s+agreement)\b/i);
    if (!msaTermPara) return [];

    return [
      makeConsistencyFinding({
        rule: CC_004_BAA_TERM,
        title: "BAA term is set independently of the MSA",
        description:
          "The BAA states its own term without referring to the MSA. If the MSA terminates first, the BAA leaves the business associate's PHI obligations dangling; if the BAA terminates first, PHI exchange under the MSA loses coverage.",
        explanation:
          "Standard drafting makes the BAA co-terminous with the MSA, with HIPAA-required return/destruction (and breach-notification) obligations surviving. The current BAA divergence is silent rather than explicit, which causes interpretation risk under 45 CFR § 164.504(e).",
        recommendation:
          "Either add 'this BAA shall be co-terminous with the Master Services Agreement' (preserving survival clauses) or, if the term is intentionally different, add a recital that says so and aligns the data-handling tail.",
        excerpts: [paragraphExcerpt(baa, baaTermPara), paragraphExcerpt(msa, msaTermPara)],
        source_citations: [hipaa504e()],
      }),
    ];
  },
};

/* -------------------- CC-005 Governing-law-alignment ------------- */

export const CC_005_GOVERNING_LAW: ConsistencyRule = {
  id: "CC-005",
  version: RULE_VERSION,
  name: "Governing law aligned across documents",
  category: "consistency",
  default_severity: "warning",
  description:
    "Cross-document governing-law conflict (e.g., the MSA picks Delaware, the DPA picks Ireland) creates interpretation and choice-of-forum risk. Some divergence is intentional (an EU DPA under EU law beneath a US-law MSA) but it must be explicit.",
  requires: [],
  check(ctx): ConsistencyFinding[] {
    if (ctx.documents.length < 2) return [];
    const seen = new Map<
      string,
      { doc: ConsistencyDocument; raw: string; start: number; end: number; section_id?: string }
    >();

    for (const doc of ctx.documents) {
      const law = extractGoverningLaw(doc);
      if (!law) continue;
      seen.set(doc.doc_id, {
        doc,
        raw: law.raw,
        start: law.start,
        end: law.end,
        section_id: law.section_id,
      });
    }
    if (seen.size < 2) return [];

    // Normalize: compare canonicalized jurisdiction strings.
    const buckets = new Map<
      string,
      Array<{
        doc: ConsistencyDocument;
        raw: string;
        start: number;
        end: number;
        section_id?: string;
      }>
    >();
    for (const entry of seen.values()) {
      const key = canonicalizeJurisdiction(entry.raw);
      const list = buckets.get(key) ?? [];
      list.push(entry);
      buckets.set(key, list);
    }
    if (buckets.size < 2) return [];

    // Pick the lexicographically first non-matching pair for a single
    // deterministic finding (rather than O(n²) findings).
    const keys = [...buckets.keys()].sort();
    const aEntries = buckets.get(keys[0]!)!;
    const bEntries = buckets.get(keys[1]!)!;
    const a = aEntries[0]!;
    const b = bEntries[0]!;

    return [
      makeConsistencyFinding({
        rule: CC_005_GOVERNING_LAW,
        title: "Governing-law clauses disagree across the bundle",
        description: `Different documents pick different governing laws: "${a.raw.trim()}" vs "${b.raw.trim()}".`,
        explanation:
          "Cross-document governing-law conflict creates forum-selection ambiguity and complicates breach-notification, audit, and indemnification interpretation. If the divergence is intentional (e.g., an EU DPA under Member State law beneath a US-law MSA), it should be stated in a recital that explains the carve-out.",
        recommendation:
          "Pick one governing law for both documents, or add an explicit recital naming the divergence and tying each clause to a jurisdiction.",
        excerpts: [
          textExcerpt(a.doc, a.raw, a.start, a.end),
          textExcerpt(b.doc, b.raw, b.start, b.end),
        ],
      }),
    ];
  },
};

/* -------------------- CC-006 Notice-alignment -------------------- */

export const CC_006_NOTICE: ConsistencyRule = {
  id: "CC-006",
  version: RULE_VERSION,
  name: "Notice addresses and methods aligned across documents",
  category: "consistency",
  default_severity: "info",
  description:
    "Cross-document notice clauses with different addresses, addressees, or accepted channels create operational gaps — a breach notice mailed to the MSA address may be 'received' weeks after the DPA's 72-hour clock has started.",
  requires: [],
  check(ctx): ConsistencyFinding[] {
    if (ctx.documents.length < 2) return [];
    const buckets = new Map<
      string,
      Array<{
        doc: ConsistencyDocument;
        raw: string;
        start: number;
        end: number;
        section_id?: string;
      }>
    >();
    for (const doc of ctx.documents) {
      const n = extractNoticeBlock(doc);
      if (!n) continue;
      const key = canonicalizeNotice(n.raw);
      const list = buckets.get(key) ?? [];
      list.push({ doc, raw: n.raw, start: n.start, end: n.end, section_id: n.section_id });
      buckets.set(key, list);
    }
    if (buckets.size < 2) return [];

    const keys = [...buckets.keys()].sort();
    const a = buckets.get(keys[0]!)![0]!;
    const b = buckets.get(keys[1]!)![0]!;

    return [
      makeConsistencyFinding({
        rule: CC_006_NOTICE,
        title: "Notice clauses do not align across the bundle",
        description:
          "The notice clauses across documents specify different addresses or methods. A notice valid under one document may be ineffective under the other.",
        explanation:
          "Operationally, this matters most for breach notification: HIPAA's 60-day clock and GDPR's 72-hour clock both turn on when notice is 'received'. Misaligned addresses turn a compliant sender into a non-compliant one.",
        recommendation:
          "Unify the notice clauses (single addressee, single physical and email address, identical accepted channels) or explicitly cross-reference one clause from the other documents.",
        excerpts: [
          textExcerpt(a.doc, a.raw, a.start, a.end),
          textExcerpt(b.doc, b.raw, b.start, b.end),
        ],
      }),
    ];
  },
};

/* -------------------- CC-007 Order-of-precedence ----------------- */

export const CC_007_ORDER_OF_PRECEDENCE: ConsistencyRule = {
  id: "CC-007",
  version: RULE_VERSION,
  name: "Order-of-precedence consistent with where operative terms live",
  category: "consistency",
  default_severity: "warning",
  description:
    "When the MSA names itself as controlling over its subordinate documents, operative commercial terms (indemnity, liability cap, IP allocation, warranties) belong in the MSA — not the subordinate. If they appear in a subordinate document instead, the stated order of precedence is inverted in practice.",
  requires: ["msa"],
  check(ctx): ConsistencyFinding[] {
    const msa = findByKind(ctx.documents, "msa");
    if (!msa) return [];
    if (ctx.documents.length < 2) return [];

    const msaText = fullText(msa);
    // Locate a precedence anchor (heading or operative phrase), then look
    // within a ~400-char window for the controlling-document declaration.
    // We allow newlines so the anchor (often a heading) and the operative
    // text (often the paragraph below) compose into one span.
    const anchor = msaText.match(
      /\b(?:in\s+the\s+event\s+of\s+(?:any\s+)?conflict|order\s+of\s+precedence)\b/i,
    );
    if (!anchor || anchor.index === undefined) return [];
    const window = msaText.slice(anchor.index, anchor.index + 400);
    const msaControls =
      /\b(msa|master\s+services?\s+agreement|this\s+agreement)\s+(?:shall\s+)?(?:controls?|govern[s]?|prevails?|takes?\s+precedence)\b/i.test(
        window,
      );
    if (!msaControls) return [];

    // Look for operative-terms language in non-MSA subordinate docs.
    const operativePatterns: Array<{ pattern: RegExp; subject: string }> = [
      {
        pattern:
          /\bindemnif(?:y|ication|ies)\b.{0,200}\b(losses?|claims?|damages?|liabilit(?:y|ies))\b/is,
        subject: "indemnification",
      },
      {
        pattern:
          /\b(aggregate\s+(?:cap|liability)|limitation\s+of\s+liability|liability\s+cap)\b[^.\n]{0,200}\b(?:exceed|capped|limited)\b/i,
        subject: "aggregate liability cap",
      },
      {
        pattern:
          /\b(?:intellectual\s+property|work\s+product|deliverables?)\b[^.\n]{0,200}\b(?:owns?|assigns?|ownership|title)\b/i,
        subject: "IP ownership allocation",
      },
      {
        pattern:
          /\b(warrants?|warranty|warranties)\b[^.\n]{0,200}\b(?:workmanlike|conform|free\s+of\s+defects)\b/i,
        subject: "warranty",
      },
    ];

    const findings: ConsistencyFinding[] = [];
    const precedenceText = window;
    const precedenceStart = anchor.index;

    for (const sub of ctx.documents) {
      if (sub.doc_id === msa.doc_id) continue;
      for (const { pattern, subject } of operativePatterns) {
        const hit = findParagraph(sub, pattern);
        if (!hit) continue;
        // Skip a carve-out that DEFERS to the MSA rather than placing operative
        // terms in the subordinate — "this SOW does not modify the
        // indemnification obligations, which are governed exclusively by the
        // MSA", "no indemnification obligations arise under this SOW". Such
        // language AFFIRMS the precedence order; flagging it inverts the
        // clause's actual meaning into a false conflict.
        if (
          /\b(?:do(?:es)?\s+not\s+(?:modify|restate|create|impose|alter|contain|include|govern|apply|supersede)|governed\s+(?:solely\s+|exclusively\s+)?by\s+(?:the\s+)?(?:msa|master\s+services?\s+agreement)|no\s+\w+(?:\s+\w+)?\s+obligations?\s+arise|shall\s+not\s+(?:apply|create|impose|modify|supersede))\b/i.test(
            hit.text,
          )
        )
          continue;
        findings.push(
          makeConsistencyFinding({
            rule: CC_007_ORDER_OF_PRECEDENCE,
            title: `Operative ${subject} terms live in the subordinate document but the MSA states MSA controls`,
            description: `The MSA names itself as controlling in conflicts, yet ${subject} terms appear in the subordinate ${sub.playbook_id} document. If the MSA is silent on those terms, "MSA controls" reads as "no ${subject}".`,
            explanation:
              "Order-of-precedence clauses only work when the controlling document contains the operative terms. Subordinate-only operative terms are either nullified by the precedence clause or — more often — read as a tacit carve-out, which is litigation-bait.",
            recommendation: `Either move the ${subject} terms into the MSA, or amend the order-of-precedence clause to carve out ${subject} (e.g., "except for indemnification, which is governed by [DOC]").`,
            excerpts: [
              textExcerpt(
                msa,
                precedenceText,
                precedenceStart >= 0 ? precedenceStart : 0,
                precedenceStart >= 0
                  ? precedenceStart + precedenceText.length
                  : precedenceText.length,
              ),
              paragraphExcerpt(sub, hit),
            ],
          }),
        );
        break; // one finding per (subject × subordinate doc) pair, keep deterministic
      }
    }

    return findings;
  },
};

/* -------------------- Citation builders --------------------------- */

function hipaa504e() {
  return {
    id: "hipaa-164.504e",
    source: "45 CFR § 164.504(e)",
    source_url: "https://www.ecfr.gov/current/title-45/section-164.504",
    retrieved_at: "",
    source_published_at: "",
    license: "Public domain (US government work)",
    license_url: "https://www.usa.gov/government-works",
  };
}

function gdpr28() {
  return {
    id: "gdpr-art-28",
    source: "Regulation (EU) 2016/679 (GDPR), Article 28",
    source_url: "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32016R0679",
    retrieved_at: "",
    source_published_at: "",
    license: "EUR-Lex reuse: © European Union 1998-present; reuse permitted",
    license_url: "https://eur-lex.europa.eu/content/legal-notice/legal-notice.html",
  };
}

/* -------------------- Internal extraction helpers ---------------- */

function extractGoverningLaw(
  doc: ConsistencyDocument,
): { raw: string; start: number; end: number; section_id?: string } | null {
  // Prefer the v2 extracted jurisdictions when available.
  for (const j of doc.extracted.jurisdictions) {
    if (j.clause_kind === "governing-law") {
      return {
        raw: j.raw_text,
        start: j.position.start,
        end: j.position.end,
        section_id: j.position.section_id,
      };
    }
  }
  const p = findParagraph(
    doc,
    /\bgovern(?:ed|ing)\s+(?:by\s+)?(?:and\s+construed\s+in\s+accordance\s+with\s+)?the\s+laws?\s+of\b/i,
  );
  if (!p) return null;
  return { raw: p.text, start: p.start, end: p.end, section_id: p.section.id || undefined };
}

function canonicalizeJurisdiction(raw: string): string {
  return raw
    .toLowerCase()
    .replace(
      /\b(governed|construed|in\s+accordance\s+with|the\s+laws?\s+of|state\s+of|commonwealth\s+of|by)\b/g,
      " ",
    )
    .replace(/[^a-z]+/g, " ")
    .trim();
}

function extractNoticeBlock(
  doc: ConsistencyDocument,
): { raw: string; start: number; end: number; section_id?: string } | null {
  const p =
    findParagraph(
      doc,
      /\b(any\s+)?notices?\s+(?:required|permitted)\s+(?:under|by)\s+this\s+agreement\b/i,
    ) ??
    findParagraph(doc, /\bnotices?\s+(?:shall\s+)?(?:be\s+)?(?:in\s+writing|sent|delivered)\b/i) ??
    findParagraph(
      doc,
      /\battention\s*[:.]?\s*(?:general\s+counsel|legal\s+department|chief\s+(?:executive|legal)\s+officer)\b/i,
    );
  if (!p) return null;
  return { raw: p.text, start: p.start, end: p.end, section_id: p.section.id || undefined };
}

function canonicalizeNotice(raw: string): string {
  return raw
    .toLowerCase()
    .replace(/[^a-z0-9@]+/g, " ")
    .replace(
      /\b(notice|notices|shall|be|in|writing|sent|delivered|to|the|of|and|or|attention|attn|by)\b/g,
      " ",
    )
    .replace(/\s+/g, " ")
    .trim();
}

/* -------------------- Registry ----------------------------------- */

export const CONSISTENCY_RULES: ConsistencyRule[] = [
  CC_001_BAA_PURPOSE,
  CC_002_DPA_PURPOSE,
  CC_003_DPA_CATEGORIES,
  CC_004_BAA_TERM,
  CC_005_GOVERNING_LAW,
  CC_006_NOTICE,
  CC_007_ORDER_OF_PRECEDENCE,
];
