/**
 * v3 audit-rights / inspection-clause detector (spec-v3.md §23).
 */

import type { DocumentTree } from "../../ingest/types.js";
import type {
  AuditCostAllocation,
  AuditMethod,
  AuditRights,
} from "./types.js";
import { forEachParagraph, posInParagraph } from "../walk.js";

const AUDIT_RX =
  /\b(?:audit|inspect|inspection)[^.]{0,400}\./i;

const FREQUENCY_RX =
  /\b(?:once|twice|(\d{1,2})\s*times?)\s+(?:per|a)\s+(?:year|calendar year)\b/i;

const NOTICE_RX =
  /\b(?:upon |with )?(?:no less than |at least |minimum |no fewer than )?(\d{1,3})\s+(?:business days?|calendar days?|days?)['’]?\s+(?:prior )?(?:written )?notice\b/i;

const METHOD_RX: { rx: RegExp; method: AuditMethod }[] = [
  { rx: /\bonsite\b|\bon[- ]site\b|\bon premises\b/i, method: "onsite" },
  { rx: /\bremote\b/i, method: "remote" },
  { rx: /\bquestionnaire\b/i, method: "questionnaire-only" },
  { rx: /\bSOC\s*2\b/i, method: "soc2-substitution" },
  { rx: /\bthird[- ]party auditor\b|\bindependent auditor\b/i, method: "third-party-auditor" },
];

const COST_RX: { rx: RegExp; cost: AuditCostAllocation }[] = [
  { rx: /\bat (?:vendor|processor|supplier)'?s? (?:own )?expense\b/i, cost: "auditee" },
  { rx: /\bat (?:customer|controller|covered entity)'?s? (?:own )?expense\b/i, cost: "auditor" },
  { rx: /\bcost(?:s)? (?:shall be )?borne by the (?:audited|audit) party (?:if|when|where) (?:material )?(?:findings|non-compliance)/i, cost: "cost-shift-on-findings" },
];

export function extractAuditRights(tree: DocumentTree): AuditRights[] {
  const out: AuditRights[] = [];
  forEachParagraph(tree, (ctx) => {
    const m = AUDIT_RX.exec(ctx.text);
    if (!m) return;
    const window = m[0];

    const freqMatch = FREQUENCY_RX.exec(window);
    let frequency: number | null = null;
    if (freqMatch) {
      if (freqMatch[1]) frequency = Number(freqMatch[1]);
      else if (/twice/i.test(freqMatch[0])) frequency = 2;
      else frequency = 1;
    }

    const noticeMatch = NOTICE_RX.exec(window);
    const notice = noticeMatch ? Number(noticeMatch[1]) : null;

    const methods: AuditMethod[] = [];
    for (const mm of METHOD_RX) if (mm.rx.test(window)) methods.push(mm.method);

    const cost = COST_RX.find((c) => c.rx.test(window))?.cost ?? ("unspecified" as AuditCostAllocation);

    const scope = /\bproduction\b/i.test(window)
      ? "production"
      : /\ball systems\b/i.test(window)
        ? "all-systems"
        : /\bin[- ]scope\b/i.test(window)
          ? "in-scope-systems"
          : "unspecified";

    out.push({
      frequency_per_year: frequency,
      notice_days: notice,
      scope_phrase: scope,
      methods,
      cost_allocation: cost,
      confidentiality_required: /\bconfidentialit/i.test(window),
      third_party_auditor_permitted: /\bthird[- ]party auditor\b|\bindependent auditor\b/i.test(window),
      raw_text: window,
      position: posInParagraph(ctx, m.index, m.index + window.length),
    });
  });
  out.sort((a, b) => a.position.start - b.position.start);
  return out;
}
