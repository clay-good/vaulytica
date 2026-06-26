/**
 * v3 role classifier (spec-v3.md §18).
 *
 * Pure: classifies parties into one or more legal roles by priority —
 * definition > recital > clause-usage. Deterministic ordering by document
 * position, then (party_id, role) lexicographic for ties.
 */

import type { DocumentTree } from "../../ingest/types.js";
import type { Party, DocPosition } from "../types.js";
import type { Role, RoleAssignment, RoleEvidence } from "./types.js";
import { forEachParagraph, posInParagraph } from "../walk.js";

const ROLE_PHRASES: { role: Role; phrases: string[] }[] = [
  { role: "covered-entity", phrases: ["covered entity"] },
  { role: "business-associate", phrases: ["business associate"] },
  { role: "subcontractor", phrases: ["subcontractor"] },
  { role: "joint-controller", phrases: ["joint controller", "joint controllers"] },
  { role: "controller", phrases: ["data controller", "controller"] },
  { role: "sub-processor", phrases: ["sub-processor", "subprocessor", "sub processor"] },
  { role: "processor", phrases: ["data processor", "processor"] },
  { role: "third-party", phrases: ["third party", "third-party"] },
  { role: "service-provider-ccpa", phrases: ["service provider"] },
  { role: "contractor-ccpa", phrases: ["contractor"] },
  { role: "service-recipient", phrases: ["service recipient", "recipient"] },
  { role: "service-supplier", phrases: ["service supplier", "supplier", "vendor"] },
];

function matchRole(label: string): Role | null {
  const lower = label.toLowerCase().trim();
  // Longest phrase first (already by order above for some, but search by length).
  let best: { role: Role; len: number } | null = null;
  for (const { role, phrases } of ROLE_PHRASES) {
    for (const phrase of phrases) {
      if (lower === phrase || new RegExp(`\\b${escapeRx(phrase)}\\b`).test(lower)) {
        if (!best || phrase.length > best.len) best = { role, len: phrase.length };
      }
    }
  }
  return best?.role ?? null;
}

function escapeRx(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const QUOTED_DEFINITION_RX =
  /["“”']([A-Z][A-Za-z][A-Za-z\s/-]{2,40})["“”']\s+(?:means|shall mean|is defined as|refers to)/g;

const PARENS_ROLE_RX =
  /\b([A-Z][A-Za-z0-9&.,'’-]+(?:\s+[A-Z][A-Za-z0-9&.,'’-]+)*)\s*\(\s*(?:hereinafter\s+)?(?:the\s+)?["“”']?\s*([A-Za-z][A-Za-z\s-]{2,40}?)["“”']?\s*\)/g;

const RECITAL_RX =
  /\b(Controller|Processor|Covered Entity|Business Associate|Customer|Service Provider)\s+(?:wishes|desires|agrees|engages|appoints|retains|has engaged)\s+(?:to\s+)?(?:engage|retain|appoint|act as|provide)/i;

const CCPA_CLAUSE_RX = /\bas\s+(?:a|the)\s+([A-Za-z][A-Za-z\s-]{2,40})\s+under\s+the\s+CCPA\b/i;

function partyForName(parties: Party[], name: string): { id: string; name: string } {
  const trimmed = name.trim();
  const lower = trimmed.toLowerCase();
  for (const p of parties) {
    if (p.name.toLowerCase() === lower) return { id: p.id, name: p.name };
  }
  for (const p of parties) {
    const pn = p.name.toLowerCase();
    if (pn.includes(lower) || lower.includes(pn)) return { id: p.id, name: p.name };
  }
  return { id: `role:${lower.replace(/\s+/g, "-")}`, name: trimmed };
}

export function classifyRoles(tree: DocumentTree, parties: Party[] = []): RoleAssignment[] {
  const seen = new Set<string>();
  const out: RoleAssignment[] = [];

  const push = (
    role: Role,
    party: { id: string; name: string },
    confidence: number,
    evidence: RoleEvidence,
    position: DocPosition,
    raw_text: string,
  ): void => {
    const key = `${party.id}|${role}|${evidence}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({
      party_id: party.id,
      party_name: party.name,
      role,
      confidence,
      evidence,
      position,
      raw_text,
    });
  };

  forEachParagraph(tree, (ctx) => {
    for (const m of ctx.text.matchAll(QUOTED_DEFINITION_RX)) {
      const term = m[1] ?? "";
      if (!term) continue;
      const role = matchRole(term);
      if (role) {
        const party = partyForName(parties, term);
        push(
          role,
          party,
          1.0,
          "definition",
          posInParagraph(ctx, m.index ?? 0, (m.index ?? 0) + m[0].length),
          m[0],
        );
      }
    }

    for (const m of ctx.text.matchAll(PARENS_ROLE_RX)) {
      const entity = m[1] ?? "";
      const alias = m[2] ?? "";
      if (!alias) continue;
      const role = matchRole(alias);
      if (role) {
        const party = partyForName(parties, entity);
        push(
          role,
          party,
          1.0,
          "definition",
          posInParagraph(ctx, m.index ?? 0, (m.index ?? 0) + m[0].length),
          m[0],
        );
      }
    }

    const recital = RECITAL_RX.exec(ctx.text);
    if (recital && recital[1]) {
      const phrase = recital[0];
      const token = recital[1];
      const role = matchRole(token);
      if (role) {
        const party = partyForName(parties, token);
        push(
          role,
          party,
          0.75,
          "recital",
          posInParagraph(ctx, recital.index, recital.index + phrase.length),
          phrase,
        );
      }
    }

    const ccpa = CCPA_CLAUSE_RX.exec(ctx.text);
    if (ccpa && ccpa[1]) {
      const token = ccpa[1];
      const role = matchRole(token);
      if (role) {
        const party = partyForName(parties, token);
        push(
          role,
          party,
          0.7,
          "clause-usage",
          posInParagraph(ctx, ccpa.index, ccpa.index + ccpa[0].length),
          ccpa[0],
        );
      }
    }
  });

  out.sort((a, b) => {
    if (a.position.start !== b.position.start) return a.position.start - b.position.start;
    if (a.party_id !== b.party_id) return a.party_id < b.party_id ? -1 : 1;
    return a.role < b.role ? -1 : a.role > b.role ? 1 : 0;
  });
  return out;
}
