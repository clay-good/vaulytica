import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, enclosingSentence, isPresenceDisclaimed } from "../_helpers.js";
import { forEachParagraph } from "../../../extract/walk.js";

/**
 * RISK-015 — Indemnification present without an aggregate cap
 * (warning).
 *
 * Fires when the document contains indemnification language (`shall
 * indemnify`, `hold harmless`, `defend and indemnify`) but no clause
 * caps the aggregate indemnity exposure. An uncapped indemnity can
 * be the single largest financial risk a contract carries. RISK-009
 * already catches the explicit `unlimited liability` framing; this
 * rule fires when the *absence* of a cap is the problem — there's
 * an indemnification clause but no `subject to the limitations of
 * Section X`, no `not to exceed`, no `cap on indemnification`
 * language anywhere.
 *
 * Conservative: a generic limitation-of-liability clause that does
 * NOT explicitly exclude indemnification from its scope is treated
 * as sufficient (the rule stays silent). Many MSAs structure caps
 * this way.
 */
/**
 * Statutory D&O indemnification (charter/bylaws under DGCL § 145 and its
 * analogues) is DESIGNED to be uncapped and unconditioned — "to the fullest
 * extent permitted by the General Corporation Law" is the operative promise,
 * made to a person "by reason of the fact that" they hold corporate office.
 * Demanding an aggregate cap or commercial claims-procedure mechanics on it
 * tells the drafter to break the corporate form. Scoped to the
 * corporate-office context: a commercial indemnity that merely says "to the
 * fullest extent permitted by law" still requires its cap.
 */
export function isStatutoryDandOIndemnity(text: string): boolean {
  return (
    /\bby\s+reason\s+of\s+the\s+fact\s+that\b[^.]{0,120}?\b(?:director|officer|trustee)\b/i.test(
      text,
    ) ||
    /\bfullest\s+extent\s+permitted\s+by\s+the\b[^.]{0,60}?\bcorporation\s+(?:law|act)\b/i.test(
      text,
    ) ||
    // The LLC / partnership analogue: an entity indemnifying its own Manager,
    // Member, or Partner "to the fullest extent permitted by the Act" is the
    // same statutory, uncapped-by-design indemnification, just under the LLC or
    // partnership statute rather than the DGCL. The governance-role indemnitee
    // is the discriminator — a commercial "indemnify Customer to the fullest
    // extent permitted by law" carries no such role and still requires its cap.
    /\bindemnif\w+[^.]{0,80}?\b(?:Managers?|Members?|Partners?|Directors?|Officers?|Trustees?)\b[^.]{0,80}?\bfullest\s+extent\s+permitted\b/i.test(
      text,
    ) ||
    // The same statutory indemnity written WITHOUT the "fullest extent"
    // formula, which is how an LP or LLC agreement usually puts it: "The
    // Partnership shall indemnify the GENERAL PARTNER and its officers,
    // directors, members, and employees against any loss arising out of the
    // Partnership's business, EXCEPT a loss resulting from FRAUD, WILLFUL
    // MISCONDUCT, GROSS NEGLIGENCE, or a knowing violation of law." The
    // governance-role indemnitee plus the statutory carve-out is the
    // discriminator: a commercial indemnity carries neither.
    // The ENTITY is the indemnitor — that is what makes this a governance
    // indemnity rather than a commercial one. "Owner shall indemnify Manager
    // ... other than a claim arising from Manager's gross negligence" is a
    // property-management indemnity between two businesses, and it still needs
    // its cap; "The Partnership shall indemnify the General Partner" does not.
    /\b(?:the\s+)?(?:Partnership|Company|Corporation|Trust|LLC|Limited\s+Liability\s+Company)\s+(?:shall|will|must|agrees\s+to)\s+indemnif\w+[^.]{0,100}?\b(?:General\s+Partner|Managing\s+Member|Manager|Managers|Members?|Directors?|Officers?|Trustees?)\b[^.]{0,200}?\b(?:fraud|willful\s+misconduct|gross\s+negligence|knowing\s+violation\s+of\s+law)\b/i.test(
      text,
    ) ||
    // The THIRD-PARTY RELIANCE indemnity of a personal instrument, which is
    // statutory and uncapped by design. "Any person who in good faith accepts
    // this instrument without actual knowledge that it is void may rely on it.
    // I agree to indemnify any such person for claims arising from that
    // good-faith reliance" — that is UPOAA § 119, and every durable power of
    // attorney in the country carries it. A well-drafted POA was told at
    // `warning` that its indemnity had no aggregate cap, in a document that has
    // no liability cap because a power of attorney is not a bargain: the
    // family already declines RISK-001 and RISK-005 for exactly that reason.
    //
    // The discriminator is the pair — a FIRST-PERSON or fiduciary-role
    // indemnitor and GOOD-FAITH RELIANCE on the instrument as the trigger. A
    // commercial indemnity has neither.
    /\b(?:I|the\s+(?:principal|grantor|settlor|declarant|trustor))\s+(?:hereby\s+|agrees?\s+to\s+|shall\s+|will\s+)*indemnif\w+[^.]{0,160}?\b(?:good[-\s]faith|reliance|relies|relying|accepts?\s+this\s+(?:instrument|power))\b/i.test(
      text,
    ) ||
    /\b(?:good[-\s]faith|accepts?\s+this\s+(?:instrument|power))\b[^.]{0,160}?\b(?:I|the\s+(?:principal|grantor|settlor|declarant|trustor))\s+(?:hereby\s+|agrees?\s+to\s+|shall\s+|will\s+)*indemnif\w+/i.test(
      text,
    )
  );
}

export const rule: Rule = {
  id: "RISK-015",
  version: "1.8.0",
  name: "Indemnification without aggregate cap",
  category: "risk-allocation",
  default_severity: "warning",
  description:
    "Flags contracts that contain indemnification language but no clause caps the indemnity exposure.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    type Hit = { sectionId: string; start: number; end: number; raw: string };
    let indemnityHit: Hit | null = null;
    let hasCap = false;
    let capCarvesOutIndemnity = false;

    const INDEMNITY =
      /\b(?:shall|will|agrees?\s+to)\s+indemnify|\bhold\s+\w+\s+harmless|\bdefend\s+and\s+indemnify\b|\bindemnification\s+obligations?\b/i;
    // "Each party's total liability under this Agreement shall not exceed
    // the Contract Price" — the dominant aggregate-cap sentence — matched no
    // branch ("not to exceed" is not "shall not exceed", and the adjective is
    // "total", not "aggregate"), so the rule reported an indemnity as
    // uncapped in the same run where RISK-003 reported its cap.
    // "NEITHER party's aggregate indemnification liability shall exceed the
    // Purchase Price" carries its negation in the subject — no "not" ever
    // appears, so every branch missed this cap form too.
    // The M&A indemnity cap is stated as "subject to a[n] (aggregate) cap equal
    // to 20% of the Purchase Price" / "cap of $1,000,000", and the indemnity
    // itself is often the subject — "the indemnification obligations shall not
    // exceed the Escrow Amount". The liability-anchored branches above missed
    // all three forms. "cap table" / "cap rate" do not match (the cap must be
    // "of"/"equal to"/"ped at" a limit, or "subject to a … cap").
    // The negation of a cap is as often a PHRASE as the word "not": "In no event
    // shall either party's liability exceed the fees", "under no circumstances
    // shall the Vendor's liability exceed $1,000,000", "the Vendor's liability
    // shall in no event exceed the fees". None carry "not", so the "not exceed"
    // branches missed them and the rule reported a capped indemnity as uncapped.
    // Both orderings are admitted, each requiring "liability … exceed" so a
    // non-liability limit ("in no event shall the term exceed") stays inert.
    // The cap noun and its verb are almost never adjacent: "EACH PARTY'S TOTAL
    // LIABILITY UNDER THESE API TERMS IS LIMITED TO …", "Vendor's aggregate
    // liability arising out of or relating to this Agreement shall be capped
    // at …". The first branch required "liability … is limited" with nothing
    // between, so a contract with an explicit total-liability cap in the same
    // section as its indemnity was reported as having an uncapped indemnity.
    // The gap is bounded to one sentence, and the "not exceed" branches
    // already read the same shape the other way.
    const CAP_PRESENT =
      /\b(?:liabilit(?:y|ies)\b[^.]{0,80}?\b(?:shall|will|is|are|may)?\s*(?:be\s+)?(?:limited|capped)|aggregate\s+liability.*?(?:not\s+exceed|cap(?:ped)?)|not\s+to\s+exceed|liability\b[^.]{0,80}?\bnot\s+exceed|neither\s+part(?:y|ies)(?:['’]s)?[^.]{0,60}?\bliabilit(?:y|ies)\b[^.]{0,60}?\bexceed|cap\s+on\s+(?:liability|indemnification)|limited\s+to\s+(?:twelve|six|three|\d+)\s+months|subject\s+to\s+(?:an?\s+)?(?:aggregate\s+|indemnification\s+|maximum\s+|per-claim\s+(?:and\s+aggregate\s+)?)?cap\b|cap(?:ped\s+at|\s+equal\s+to|\s+of)\b|indemnif\w+[^.]{0,80}?\b(?:shall\s+not\s+exceed|not\s+to\s+exceed)|(?:in\s+no\s+event|under\s+no\s+circumstances)[^.]{0,80}?\bliabilit(?:y|ies)\b[^.]{0,40}?\bexceed\b|\bliabilit(?:y|ies)\b[^.]{0,60}?(?:in\s+no\s+event|under\s+no\s+circumstances)[^.]{0,30}?\bexceed\b)/i;
    // The stem is `indemni(f|t)`: a carve-out names the "indemnity
    // obligations" as often as the verb, and `indemnif` matches none of them.
    const CARVE_OUT_INDEMNITY =
      /\b(?:except\s+(?:for|with\s+respect\s+to)|excluding|other\s+than|not\s+including|carve[-\s]out\s+for)\s+[^.]{0,80}\bindemni(?:f|t)/i;

    // The same carve-out written as its OWN sentence, pointing back at the
    // limits it excepts: "These limits do not apply to a party's indemnity
    // obligations under Section 10." That is the ordinary drafting of a
    // limitation-of-liability section, and the connector-led pattern above
    // reads none of it. This branch needs no cap phrase in its own sentence,
    // because its subject — "these limits" / "the foregoing limitations" — IS
    // the reference to the cap.
    //
    // It must BEGIN a sentence. A back-reference tucked inside the
    // consequential-damages sentence — "Neither party shall be liable for
    // indirect damages, except that this limitation does not apply to
    // Contractor's indemnification obligations" — excepts the WAIVER, not the
    // cap that follows in the next sentence, and the indemnity there is
    // capped (`risk-allocation-guards.test.ts`).
    const CARVE_OUT_BACKREFERENCE =
      /(?:^|[.;]\s+)(?:these|those|the\s+foregoing|the\s+preceding|this)\s+(?:limits?|limitations?|caps?|exclusions?|restrictions?)\b[^.]{0,60}?\b(?:do|does|shall|will)\s+not\s+apply\s+to\b[^.]{0,140}?\bindemni(?:f|t)/i;

    forEachParagraph(ctx.tree, (p) => {
      if (!indemnityHit) {
        const m = INDEMNITY.exec(p.text);
        // The `indemnification obligation(s)` branch is a bare noun phrase that
        // also matches its own disclaimer ("there is no indemnification
        // obligation") — a false accusation. Suppress a disclaimed match; the
        // verb branches ("shall indemnify") never match a negated "shall not
        // indemnify", so this only affects the noun-phrase form.
        // Statutory D&O indemnification is uncapped by design — see
        // isStatutoryDandOIndemnity.
        if (m && !isPresenceDisclaimed(p.text, m.index) && !isStatutoryDandOIndemnity(p.text)) {
          indemnityHit = {
            sectionId: p.section.id,
            start: p.start + m.index,
            end: p.start + m.index + m[0].length,
            raw: m[0],
          };
        }
      }
      if (CAP_PRESENT.test(p.text)) hasCap = true;
      // A carve-out only uncaps the indemnity when it modifies the CAP. A
      // limitation-of-liability paragraph routinely carves indemnity out of
      // its CONSEQUENTIAL-DAMAGES waiver ("neither party is liable for
      // indirect damages, except … indemnification obligations") and then
      // states an unqualified aggregate cap in the next sentence — reading
      // the paragraph-level carve-out against that cap accused a capped
      // indemnity of being uncapped. The carve-out must share a sentence
      // with a cap phrase.
      const carve = CARVE_OUT_INDEMNITY.exec(p.text);
      if (carve && CAP_PRESENT.test(enclosingSentence(p.text, carve.index))) {
        capCarvesOutIndemnity = true;
      }
      if (CARVE_OUT_BACKREFERENCE.test(p.text)) capCarvesOutIndemnity = true;
    });

    if (!indemnityHit) return null;
    if (hasCap && !capCarvesOutIndemnity) return null;

    const hit: Hit = indemnityHit;
    return emit(ctx, rule, {
      title: hasCap
        ? "Indemnification carved out of liability cap"
        : "Indemnification without aggregate cap",
      description: hasCap
        ? `Indemnification language is present (\`${hit.raw}\`) and the liability cap explicitly carves it out — indemnity exposure is uncapped.`
        : `Indemnification language is present (\`${hit.raw}\`) but no clause caps the aggregate exposure.`,
      excerpt: hit.raw,
      explanation:
        "An indemnity carved out of (or simply not subject to) the liability cap can be the largest single financial risk a contract carries. A third-party IP infringement claim, a data-breach notification cost, or a regulatory fine can dwarf the contract value many times over. Confirm the carve-out is deliberate and proportionate to the indemnifying party's solvency.",
      recommendation:
        "Either subject indemnification to a per-claim and aggregate cap, or confirm the carve-out is a deliberate trade for higher pricing / different insurance.",
      position: { section_id: hit.sectionId, start: hit.start, end: hit.end },
    });
  },
};
