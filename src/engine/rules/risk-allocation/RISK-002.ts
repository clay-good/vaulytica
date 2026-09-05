import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, allMatches, topPosition } from "../_helpers.js";

/** RISK-002 — Indemnity mutuality (warning). */
export const rule: Rule = {
  id: "RISK-002",
  version: "1.4.0",
  name: "Indemnity mutuality",
  category: "risk-allocation",
  default_severity: "warning",
  description: "Compares each party's indemnity scope; flags significant asymmetry.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const parties = ctx.extracted.parties;
    if (parties.length < 2) return null;
    const lines = allMatches(ctx, /[A-Z][^.]*\bindemnif[^.]*\./);
    if (lines.length === 0) return null;
    // Only the parties that BEAR the agreement. The extractor also records
    // the natural persons who SIGN it — "Rosalind Achterberg", "Emeka
    // Villanueva" — and seeding them at zero drags `min` to 0, so a perfectly
    // ordinary two-versus-one indemnity clears the `max - min >= 2` threshold
    // on the strength of two signature lines. A master purchase agreement
    // where each side indemnifies the other was reported as one-sided for
    // exactly that reason.
    //
    // A signatory is the party entry carrying neither a defined ROLE nor an
    // entity type. An individual who is genuinely a party — an Executive, an
    // Employee, a Guarantor — is introduced with a role and is kept.
    const bearing = parties.filter((p) => p.role ?? p.entity_type);
    const counted = bearing.length >= 2 ? bearing : parties;
    if (counted.length < 2) return null;
    const counts = new Map<string, number>();
    for (const p of counted) counts.set(p.name.toLowerCase(), 0);
    for (const line of lines) {
      const sentence = line.match[0].toLowerCase();
      const idx = sentence.indexOf("indemnif");
      if (idx < 0) continue;
      // A sentence about indemnification "under the Purchase Agreement" (or
      // any other named instrument) describes a PARENT deal's allocation, not
      // an indemnity of this document — an escrow agreement securing
      // "Seller's indemnification obligations under the Purchase Agreement"
      // was scored as Seller-heavy asymmetry. "under this Agreement" is this
      // document and still counts.
      // The named instrument is one word as often as three — "under the
      // Purchase Agreement", "under the Stock Purchase Agreement", "under the
      // Asset Purchase and Contribution Agreement" — and the single-word
      // window read only the first of those. (The text is already lowercased,
      // so the capitalization of the title is not available here; the word
      // count is what bounds it. "under this Agreement" is this document and
      // still counts, because "this" is not admitted.)
      if (/indemnif[^.]{0,60}\bunder\s+the\s+(?:[a-z]+\s+){1,4}agreement\b/.test(sentence))
        continue;
      // THE PASSIVE INVERTS THE PARTIES, and this rule reads direction.
      //
      // "Seller shall indemnify Buyer" and "Buyer shall be indemnified by
      // Seller" are the same allocation, but the party standing before the
      // verb is the indemnitOR in one and the indemnitEE in the other. Taking
      // the nearest surface before the verb in the passive credits the wrong
      // side — so a one-sided indemnity drafted that way was not merely
      // missed, it was scored BACKWARDS, and the report named the protected
      // party as the one bearing the risk.
      //
      // The passive is ordinary drafting, not an edge case: "each Indemnitee
      // shall be indemnified and held harmless by the Company" is how a
      // charter, an LLC agreement and a construction contract write it. Not
      // one of the 312 specimens uses it, which is exactly why no rewriting
      // of the corpus could find this — it had to be injected.
      const passive = /\bbe\s+indemnified\b/.exec(sentence);
      const byAt = passive ? sentence.indexOf(" by ", passive.index) : -1;
      // In the passive the indemnitor follows "by"; everything before the verb
      // is the party being protected.
      const before = byAt >= 0 ? sentence.slice(byAt) : sentence.slice(0, idx);
      // Count the INDEMNITOR, not every party the sentence happens to name.
      // "Customer shall indemnify Vendor" names both, so tallying any mention
      // scored them equally and the asymmetry cancelled itself out. The
      // indemnitor is the surface form closest before the verb.
      //
      // Surface forms include the party's defined ROLE, because contracts
      // overwhelmingly write "Vendor shall indemnify …" rather than the legal
      // name — matching names alone left this rule inert on ordinary drafting.
      let best: { key: string; at: number } | null = null;
      for (const p of parties) {
        const key = p.name.toLowerCase();
        for (const surface of [key, ...(p.role ? [p.role.toLowerCase()] : [])]) {
          // Active: the indemnitor is the surface CLOSEST to the verb, so the
          // last one in the run-up. Passive: `before` is the tail beginning at
          // "by", and the indemnitor is the FIRST surface in it.
          const at = byAt >= 0 ? before.indexOf(surface) : before.lastIndexOf(surface);
          if (at >= 0 && (!best || (byAt >= 0 ? at < best.at : at > best.at))) best = { key, at };
        }
      }
      if (!best) continue;
      // A JOINT indemnity ("Buyer and Seller shall jointly and severally
      // indemnify the Escrow Agent") is every named indemnitor's obligation —
      // crediting only the surface closest to the verb scored it as
      // one-sided. Credit each party named in the joint subject.
      const subject = before.slice(Math.max(0, best.at - 60));
      const credited = new Set<string>([best.key]);
      if (/\bjointly\b/.test(subject) || /\w+\s+and\s+\w+/.test(subject)) {
        for (const p of parties) {
          const key = p.name.toLowerCase();
          for (const surface of [key, ...(p.role ? [p.role.toLowerCase()] : [])]) {
            if (subject.includes(surface)) credited.add(key);
          }
        }
      }
      for (const key of credited) counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    const values = [...counts.values()];
    const max = Math.max(...values);
    const min = Math.min(...values);
    if (max === 0 || max - min < 2) return null;
    return emit(ctx, rule, {
      title: "Indemnity appears asymmetric",
      description: `Indemnity sentence counts by party: ${[...counts.entries()].map(([k, v]) => `${k}=${v}`).join(", ")}.`,
      excerpt: lines[0]!.match[0].slice(0, 200),
      explanation:
        "One party appears to bear materially more indemnity scope than the other. Confirm the asymmetry is intentional and reciprocated by other consideration (e.g., a fee discount).",
      recommendation:
        "Confirm the asymmetry is intentional. A one-way indemnity is normal where one party controls the risk (a vendor's IP indemnity, a licensee's use indemnity); where it is not, state what the indemnifying party gets in return, or make it reciprocal for the claims both parties can cause.",
      position: lines[0]?.position ?? topPosition(ctx),
    });
  },
};
