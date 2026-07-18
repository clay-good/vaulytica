import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/**
 * RISK-017 — One-way attorneys'-fees clause (warning).
 *
 * Detects asymmetric fee-shifting language: the contract awards
 * attorneys' fees only to one party — typically the drafter / vendor /
 * licensor — without a reciprocal right for the counterparty. In most
 * US jurisdictions one-way fee shifters are enforceable as written
 * (the "American rule" defaults to each-side-bears-own-costs;
 * contracts may override). A small minority of states (e.g.
 * California Civ. Code § 1717, Florida Stat. § 57.105(7), Oregon ORS
 * 20.096, Washington RCW 4.84.330) impose a reciprocity rule that
 * automatically converts one-way fee provisions into mutual ones —
 * which is itself notable because it tells you the drafting is
 * understood as inherently uneven.
 *
 * Detection: look for "attorneys' fees" / "legal fees" / "reasonable
 * attorneys fees" awarded to "Vendor", "Provider", "Company",
 * "Licensor", "we", "us", "Indemnitee" without a reciprocal clause
 * naming the other party in the same paragraph (or nearby).
 */
export const rule: Rule = {
  id: "RISK-017",
  version: "1.0.0",
  name: "One-way attorneys'-fees clause",
  category: "risk-allocation",
  default_severity: "warning",
  description:
    "Flags attorneys'-fees awards running only to one party, without a reciprocal right for the counterparty.",
  dkb_citations: ["stat-ca-civ-1717"],
  check(ctx: RuleContext): Finding | null {
    // Match a paragraph that awards fees to a named party.
    const m = firstParagraphMatch(
      ctx,
      /(?:reimburse|recover|entitled\s+to|shall\s+pay|pay\s+all\s+of|pay\s+(?:the\s+)?(?:other\s+)?(?:party'?s|prevailing\s+party'?s)?)[\s\S]{0,40}\b(?:reasonable\s+)?(?:attorneys?'?\s*fees|legal\s+fees|counsel\s+fees|attorney\s+fees)\b[\s\S]{0,200}/i,
    );
    if (!m) return null;

    const para = m.text;
    // "Prevailing party" is the canonical balanced framing — exclude
    // it entirely. Same for "each party shall pay its own" formulas.
    if (/\bprevailing\s+party\b/i.test(para)) return null;
    if (/\beach\s+party\s+shall\s+(?:pay|bear)\s+its\s+own\b/i.test(para)) return null;

    // Look for an obviously asymmetric award: fees run to a single
    // named drafter-party with no counterparty reciprocity in the
    // same paragraph.
    const DRAFTER_NAMES =
      "Vendor|Provider|Company|Licensor|Seller|Service\\s+Provider|Counterparty|Indemnitee|Disclosing\\s+Party|Receiving\\s+Party";
    const ASYM_TO = new RegExp(
      `(?:to|in\\s+favor\\s+of|for)\\s+(${DRAFTER_NAMES}|the\\s+(?:Vendor|Provider|Company|Licensor|Seller|Indemnitee))\\b`,
      "i",
    );
    const ASYM_SUBJECT = new RegExp(
      `\\b(${DRAFTER_NAMES})\\b[\\s\\S]{0,80}\\b(?:shall\\s+be\\s+entitled\\s+to\\s+recover|may\\s+recover|is\\s+entitled\\s+to)\\b[\\s\\S]{0,80}\\b(?:reasonable\\s+)?(?:attorneys?'?\\s*fees|legal\\s+fees|counsel\\s+fees)\\b`,
      "i",
    );
    const asymHit = ASYM_TO.exec(para) ?? ASYM_SUBJECT.exec(para);
    const COUNTERPARTY =
      /(?:to|in\s+favor\s+of|for)\s+(Customer|Client|Buyer|Licensee|Tenant|Employee|Contractor|Subscriber|End\s+User)\b/i;
    // Also recognize the counterparty as the SUBJECT of its own fees-recovery
    // grant (a reciprocal second sentence: "Customer shall likewise be entitled
    // to recover its attorneys' fees from Vendor"). Without this, a fully mutual
    // two-sentence clause was misread as one-way.
    const COUNTER_SUBJECT =
      /\b(Customer|Client|Buyer|Licensee|Tenant|Employee|Contractor|Subscriber|End\s+User)\b[\s\S]{0,80}\b(?:shall\s+(?:likewise\s+)?be\s+entitled\s+to\s+recover|may\s+recover|is\s+entitled\s+to\s+recover)\b[\s\S]{0,80}\b(?:reasonable\s+)?(?:attorneys?'?\s*fees|legal\s+fees|counsel\s+fees)\b/i;
    const counterHit = COUNTERPARTY.exec(para) ?? COUNTER_SUBJECT.exec(para);

    // Reciprocal? Same paragraph awards fees to a counterparty as
    // well. Not asymmetric.
    if (asymHit && counterHit) return null;

    // The clearest signal: only one party named in the fees clause.
    if (!asymHit && !counterHit) {
      // Try a second pattern: "Customer shall reimburse Vendor's
      // attorneys' fees" — the obligor is the customer, payee is
      // the vendor.
      const ALT =
        /\b(Customer|Client|Buyer|Licensee|Tenant|Employee|Contractor|Subscriber|End\s+User)\b[\s\S]{0,80}(?:shall\s+(?:pay|reimburse|indemnify)|agrees\s+to\s+pay)[\s\S]{0,80}\b(Vendor|Provider|Company|Licensor|Seller|Indemnitee)(?:'?s)?[\s\S]{0,40}\b(?:reasonable\s+)?(?:attorneys?'?\s*fees|legal\s+fees|counsel\s+fees)\b/i;
      const altHit = ALT.exec(para);
      if (!altHit) return null;
      return emit(ctx, rule, {
        title: `Asymmetric attorneys'-fees clause (${altHit[1]} → ${altHit[2]})`,
        description: altHit[0],
        excerpt: para.slice(Math.max(0, altHit.index - 30), altHit.index + 280),
        explanation:
          "An attorneys'-fees award flowing in only one direction is enforceable in most US jurisdictions but is widely recognized as an unbalanced drafting choice. A small group of states (California Civ. Code § 1717, Florida Stat. § 57.105(7), Oregon ORS 20.096, Washington RCW 4.84.330) automatically convert one-way fee clauses into mutual ones, which itself tells you the asymmetry is broadly viewed as unfair.",
        recommendation:
          "Replace with a 'prevailing party' formulation: 'The prevailing party in any action arising out of or relating to this Agreement shall be entitled to recover its reasonable attorneys' fees and costs.' Or remove the fee-shifting clause entirely and rely on the American rule.",
        position: m.position,
      });
    }

    if (asymHit) {
      return emit(ctx, rule, {
        title: `Asymmetric attorneys'-fees award (only to ${(asymHit[1] ?? "").replace(/^the\s+/i, "")})`,
        description: m.match[0],
        excerpt: para.slice(Math.max(0, m.match.index - 30), m.match.index + 280),
        explanation:
          "An attorneys'-fees award flowing in only one direction is enforceable in most US jurisdictions but is widely recognized as unbalanced drafting. A handful of states (California Civ. Code § 1717, Florida Stat. § 57.105(7), Oregon ORS 20.096, Washington RCW 4.84.330) statutorily convert one-way clauses into mutual ones — a sign that the legislative consensus treats one-way fee shifters as inherently unfair.",
        recommendation:
          "Use a 'prevailing party' clause: fees flow to whichever side wins, regardless of which side started the action. Or strike the fee-shifting clause entirely and rely on the American rule (each side pays its own).",
        position: m.position,
      });
    }

    return null;
  },
};
