import type { Rule, RuleContext, Finding } from "../../finding.js";
import { amendsParentAgreement, emit, firstParagraphMatch, topPosition } from "../_helpers.js";

/** IPDATA-001 — IP ownership clause present (warning). */
export const rule: Rule = {
  id: "IPDATA-001",
  version: "1.9.0",
  name: "IP ownership clause present",
  category: "ip-and-data",
  default_severity: "warning",
  description: "Detects IP-ownership / assignment / work-for-hire language; fires when absent.",
  dkb_citations: ["stat-17-usc-101", "stat-17-usc-201"],
  check(ctx: RuleContext): Finding | null {
    // An amendment does not restate what the parent agreement already
    // says. Its ratification clause — "Except as expressly modified by
    // this Amendment, the Lease remains in full force and effect" — is
    // the drafting convention for saying exactly that, and reporting
    // this clause as absent has no answer short of restating the parent
    // inside its own amendment.
    if (amendsParentAgreement(ctx)) return null;
    // The assignment alternation requires an IP object within the clause
    // (fix-rule-detection-fidelity): a bare `hereby assigns` anywhere —
    // receivables, a lease, a security interest — used to silently satisfy
    // this presence check. Recognized IP objects: inventions, works (of
    // authorship), work product, copyrights, patents, trademarks, trade
    // secrets, deliverables, intellectual property, moral rights, IP.
    if (
      firstParagraphMatch(
        ctx,
        // `hereby assigns` also has to tolerate the adverb every assignment
        // clause carries — "Employee hereby IRREVOCABLY assigns to the Company
        // all right, title, and interest in any and all inventions" is the
        // standard invention-assignment sentence, and requiring the two words
        // to be adjacent made the rule report that the contract "does not
        // allocate ownership of intellectual property".
        // The adverb slot also has to hold a VERB SERIES, because a
        // conveyance instrument never uses one verb: "Each Assignor hereby
        // irrevocably SELLS, ASSIGNS, TRANSFERS, AND CONVEYS to Assignee all
        // of that Assignor's entire right, title, and interest in and to the
        // Patents" is the operative sentence of a patent assignment, and on a
        // single-adverb slot it did not match — so a document whose entire
        // purpose is to allocate IP ownership was told it allocates none.
        // "hereby" is conventional, not required: "Executive ASSIGNS TO the
        // Company all inventions conceived during employment" is a complete
        // assignment, and an executive employment agreement writes it that way
        // as often as not. The "to" is what keeps the plural NOUN ("successors
        // and assigns") out.
        // A LICENSE allocates ownership by RESERVING it — "the Licensed
        // Works are and remain the sole property of Licensor", "a license,
        // not a transfer of copyright ownership", "all rights not expressly
        // granted are reserved" — and none of the assignment-side branches
        // read that register, so a copyright license with a dedicated
        // Ownership section was told it does not allocate IP ownership.
        // The reservation is as often ACTIVE — "Licensor reserves all rights
        // not expressly granted", "Licensee acquires no ownership interest" —
        // and a trademark license allocates ownership through goodwill
        // inurement ("all goodwill … inures solely to the benefit of
        // Licensor"), so those registers are recognized too.
        // A license also allocates ownership by STATING it — "the Licensor
        // owns the Licensed Patents", "each party owns the improvements it
        // makes". Anchored on an IP object so a bare "owns 10% of the
        // company" is not read as an IP-ownership clause.
        // Ownership stated with the IP object FIRST and the verb after —
        // "all Work Product shall belong to the Customer", "the Deliverables
        // shall be owned by Customer" — which the owner-first / owns-object
        // branches did not read. Anchored on an IP object so a generic "the
        // company is owned by its shareholders" / "the parties belong to the
        // association" is not mistaken for an IP-ownership clause.
        // Ownership stated by RETENTION ("Licensor retains all right, title,
        // and interest" / "retains ownership"), by RETAINING RIGHTS IN a named
        // object — "You retain all rights in the images and other material you
        // upload" is how consumer terms allocate ownership of user content,
        // and the retention branch read only "retains ownership" / "retains
        // all right, title", so a terms page with a dedicated Your Content
        // section was told it allocates no IP at all — by TITLE VESTING ("Title to all
        // Inventions shall vest in the Employer"), by naming the OWNER ("the
        // sole and exclusive owner of all Work Product"), by the "is the
        // exclusive property of" form (no "and remain"), and by "own … Data /
        // IP / Work Product" (objects the assignment-anchored branch lacked).
        /\b(?:work(?:s)?\s+made\s+for\s+hire|intellectual\s+property|IP\s+ownership|copyright\s+ownership|retains?\s+(?:all\s+)?(?:ownership\b|right,?\s+title\b|rights?\s+(?:in|to)\b[^.]{0,80}?\b(?:content|material|images?|photographs?|submissions?|works?|intellectual\s+property)\b)|title\s+(?:to|in)\b[^.]{0,60}?\bvest(?:s|ed)?\s+in\b|(?:sole\s+and\s+exclusive|exclusive|sole)\s+owner\s+of\b|(?:owns|owned|(?:shall|will|hereby|to|must)\s+own)\b[^.]{0,40}?\b(?:data|IP\b|work\s+product)\b|(?:are|is|shall\s+be)\s+the\s+(?:sole\s+)?(?:and\s+exclusive\s+)?property\s+of|(?:is|are|shall\s+be)\s+the\s+(?:sole\s+(?:and\s+exclusive\s+)?|exclusive\s+)property\s+of|all\s+rights\s+not\s+expressly\s+granted\s+are\s+reserved|reserves\s+all\s+(?:its\s+)?rights|acquires?\s+no\s+(?:ownership|right|title)|own(?:s|ed|ership\s+of)?\b[^.]{0,40}?\b(?:licensed\s+)?(?:patents?|copyrights?|trademarks?|inventions?|improvements?|intellectual\s+property|trade\s+secrets?|works?\s+of\s+authorship|deliverables?)\b|goodwill\b[^.]{0,60}?\binures?\s+(?:solely\s+)?to\s+the\s+benefit\s+of|(?:hereby\s+(?:[\w-]+[,\s]+){0,6}?assigns?|assigns?\s+(?:and\s+transfers?\s+)?to\b)[^.]{0,120}?\b(?:inventions?|work\s+product|works?\s+of\s+authorship|copyrights?|patents?|trademarks?|trade\s+secrets?|deliverables?|intellectual\s+property|moral\s+rights?|IP)\b|(?:work\s+product|deliverables?|inventions?|copyrights?|patents?|trademarks?|trade\s+secrets?|works?\s+of\s+authorship|intellectual\s+property|moral\s+rights?)\b[^.]{0,60}?\b(?:belongs?\s+to|owned\s+by)\b)/i,
      )
    )
      return null;
    return emit(ctx, rule, {
      title: "No IP-ownership clause detected",
      description: "The contract does not allocate ownership of intellectual property.",
      excerpt: "(no IP-ownership clause)",
      explanation:
        "Without an IP-ownership clause, default copyright and patent rules apply: under 17 U.S.C. § 201, copyright vests in the author/employee unless work-for-hire or assignment applies.",
      position: topPosition(ctx),
    });
  },
};
