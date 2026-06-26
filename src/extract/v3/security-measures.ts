/**
 * v3 security-measures inventory extractor (spec-v3.md §21).
 *
 * Recognizes both structured schedules and prose narration. Each measure
 * carries a cadence and scope inferred from neighboring text.
 */

import type { DocumentTree } from "../../ingest/types.js";
import type {
  SecurityMeasure,
  SecurityMeasureCadence,
  SecurityMeasureScope,
  SecurityMeasureSlug,
} from "./types.js";
import { forEachParagraph, posInParagraph } from "../walk.js";

type MeasureDef = { slug: SecurityMeasureSlug; rx: RegExp };

const MEASURE_CATALOG: MeasureDef[] = [
  {
    slug: "encryption-at-rest",
    rx: /\bencryption (?:at|of data at) rest\b|\bencrypted at rest\b/i,
  },
  {
    slug: "encryption-in-transit",
    rx: /\bencryption in transit\b|\bencrypted in transit\b|\bTLS\b/i,
  },
  { slug: "mfa", rx: /\bmulti[- ]?factor authentication\b|\bMFA\b|\b2FA\b/i },
  { slug: "sso", rx: /\bsingle sign[- ]?on\b|\bSSO\b|\bSAML\b/i },
  { slug: "vulnerability-scanning", rx: /\bvulnerability scan(?:s|ning)?\b/i },
  { slug: "penetration-testing", rx: /\bpenetration test(?:s|ing)?\b|\bpen[- ]?test(?:s|ing)?\b/i },
  { slug: "security-training", rx: /\bsecurity (?:awareness )?training\b/i },
  { slug: "bcp-dr", rx: /\bbusiness continuity\b|\bdisaster recovery\b|\bBCP\b|\bDR plan\b/i },
  { slug: "incident-response", rx: /\bincident response\b/i },
  {
    slug: "access-controls-rbac",
    rx: /\brole[- ]based access control\b|\bRBAC\b|\baccess controls?\b/i,
  },
  { slug: "logging-audit", rx: /\baudit log(?:s|ging)?\b|\blogging and monitoring\b/i },
  { slug: "network-segmentation", rx: /\bnetwork segmentation\b/i },
  { slug: "hardware-tokens", rx: /\bhardware tokens?\b|\bsecurity keys?\b|\bYubiKey\b/i },
  { slug: "secure-development-lifecycle", rx: /\bsecure development lifecycle\b|\bSDLC\b/i },
  { slug: "third-party-audits-soc2-t2", rx: /\bSOC\s*2\b(?:\s+Type\s*(?:II|2))?/i },
  { slug: "third-party-audits-iso-27001", rx: /\bISO\s*\/?\s*IEC\s*27001\b|\bISO\s*27001\b/i },
  { slug: "third-party-audits-hitrust", rx: /\bHITRUST\b/i },
];

const CADENCE_RX: { rx: RegExp; cadence: SecurityMeasureCadence }[] = [
  { rx: /\bannual(?:ly)?\b|\b(?:once )?per year\b/i, cadence: "annual" },
  { rx: /\bbiennial(?:ly)?\b|\bevery two years\b/i, cadence: "biennial" },
  { rx: /\bcontinuous(?:ly)?\b|\bongoing\b/i, cadence: "continuous" },
  { rx: /\bupon (?:any )?incident\b|\bon[- ]incident\b/i, cadence: "on-incident" },
];

const SCOPE_RX: { rx: RegExp; scope: SecurityMeasureScope }[] = [
  { rx: /\bproduction (?:systems|environments)\b/i, scope: "production" },
  { rx: /\ball systems\b/i, scope: "all-systems" },
  { rx: /\bin[- ]scope systems\b|\bin scope\b/i, scope: "in-scope-systems" },
];

function inferCadence(text: string): SecurityMeasureCadence {
  for (const c of CADENCE_RX) if (c.rx.test(text)) return c.cadence;
  return "unspecified";
}

function inferScope(text: string): SecurityMeasureScope {
  for (const s of SCOPE_RX) if (s.rx.test(text)) return s.scope;
  return "unspecified";
}

export function extractSecurityMeasures(tree: DocumentTree): SecurityMeasure[] {
  const seen = new Set<string>();
  const out: SecurityMeasure[] = [];
  forEachParagraph(tree, (ctx) => {
    for (const m of MEASURE_CATALOG) {
      const match = m.rx.exec(ctx.text);
      if (!match) continue;
      const key = `${m.slug}|${ctx.paragraph.id}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({
        slug: m.slug,
        raw_text: match[0],
        cadence: inferCadence(ctx.text),
        scope: inferScope(ctx.text),
        position: posInParagraph(ctx, match.index, match.index + match[0].length),
      });
    }
  });
  out.sort((a, b) =>
    a.position.start !== b.position.start
      ? a.position.start - b.position.start
      : a.slug < b.slug
        ? -1
        : a.slug > b.slug
          ? 1
          : 0,
  );
  return out;
}
