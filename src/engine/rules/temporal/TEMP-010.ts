import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit } from "../_helpers.js";
import { forEachParagraph } from "../../../extract/walk.js";

/** TEMP-010 — Specific dates near or after expiry (info). */
export const rule: Rule = {
  id: "TEMP-010",
  version: "1.4.0",
  name: "Specific dates after expiry",
  category: "temporal",
  default_severity: "info",
  description: "Flags absolute dates that fall after a stated expiration date.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    // The expiration date was matched with an ISO-only regex, so the rule never
    // fired on the "December 31, 2026" / "31 December 2026" / "12/31/2026" forms
    // real contracts actually use — it worked only on ISO dates, which are rare.
    // Anchor on the "expires / expiration date" keyword, then take the
    // expiration date from the extracted-date stream (which already resolves
    // every supported format to ISO) by finding the absolute date that sits
    // just after the keyword in the same paragraph.
    // 1.2.0 — the expiration was taken from the FIRST paragraph naming one,
    // and an amendment recites the expiry it is replacing before it states the
    // new one: "The Term of the Lease is scheduled to expire on August 31,
    // 2026, and the parties wish to extend the Term" is a recital, and the
    // operative section two paragraphs later reads "commencing September 1,
    // 2026 and expiring August 31, 2031". The rule took the recited date as
    // the contract's expiration and reported every date in the extension —
    // including the new commencement date — as falling after it, which is a
    // false statement about the document. Every stated expiration is now
    // collected and the LATEST governs, which is the one that actually does.
    //
    // "expiring" is admitted alongside "expires": it is how an operative term
    // clause is written ("commencing ... and expiring ..."), and without it
    // the only expiration such a document states is the recited one.
    const EXPIRY_KEYWORD = /\b(?:expires?|expiring|expiration\s+date)\b/gi;
    // An OFFER's expiry is the deadline to ACCEPT it, not the term of anything.
    // "This offer expires on August 10, 2026" sits at the foot of every offer
    // letter, quotation and proposal, above a start date or a delivery date
    // weeks later — and an offer letter was told its September start date
    // falls after its own expiration. The same is true of a notary's
    // commission, which is why that guard was written.
    const NON_CONTRACT_EXPIRY =
      /\b(?:commission|notar\w*|licen[sc]e|registration|permit|passport|offer|quotation|proposal)\b[^.]{0,40}$/i;
    const expiryIsos: string[] = [];
    forEachParagraph(ctx.tree, (p) => {
      EXPIRY_KEYWORD.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = EXPIRY_KEYWORD.exec(p.text)) !== null) {
        // Not every "expires" in a document is the DOCUMENT's expiration. A
        // notarial certificate ends "My commission expires: October 31, 2028",
        // and it sits at the bottom of every recorded deed, mortgage, will,
        // and affidavit in the country. A deed of trust securing a note that
        // matures in 2036 was reported as containing a date after its own
        // expiration in 2028 — the notary's, not the instrument's. Licenses,
        // registrations, permits, and passports are named for the same reason.
        if (NON_CONTRACT_EXPIRY.test(p.text.slice(0, m.index))) continue;
        const afterKeyword = p.text.slice(m.index);
        const ref = ctx.extracted.dates.find((d) => {
          if (d.type !== "absolute" || !d.iso) return false;
          const at = afterKeyword.indexOf(d.raw_text);
          return at >= 0 && at < 60;
        });
        if (ref?.iso) expiryIsos.push(ref.iso);
      }
    });
    if (expiryIsos.length === 0) return null;
    const expiryDate = expiryIsos.reduce((a, b) => (a > b ? a : b));
    const expiryRef = ctx.extracted.dates.find((d) => d.iso === expiryDate)!;
    const later = ctx.extracted.dates.find(
      (d) =>
        d.type === "absolute" && d.iso && d.iso > expiryDate && d.raw_text !== expiryRef.raw_text,
    );
    if (!later) return null;
    return emit(ctx, rule, {
      title: `Date ${later.iso} appears after expiration ${expiryDate}`,
      description: `Reference to ${later.iso} occurs in a contract that expires ${expiryDate}.`,
      excerpt: later.raw_text,
      explanation:
        "A date later than the expiration of the contract may signal a survival clause, a forward-looking commitment, or a drafting error.",
      position: later.position,
    });
  },
};
