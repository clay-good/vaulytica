/**
 * What a contract calls ITSELF.
 *
 * The sibling of {@link ATTACHMENT_KIND}, and the same argument one level up:
 * an American vendor deal is an Agreement, the same instrument in a
 * construction file is a Contract, in a property file a Lease or a Deed, and
 * in a procurement file an Order or a Statement of Work. The rights they grant
 * are identical, and a recognizer that names only one of the nouns reads only
 * one of the files.
 *
 * Found twice by the same probe — rename the instrument throughout and diff
 * the findings:
 *
 *  - **TERM-009** named only `this\s+Agreement` as the object of "terminate",
 *    and because that group was OPTIONAL the clause did not fall back to
 *    matching without it: "this Contract " sits between "terminate" and "at
 *    any time" and nothing consumes it. A lease granting the identical
 *    one-sided convenience right was read as granting none.
 *  - **DPA-045** accepted `term\s+of\s+(this\s+)?agreement` alongside
 *    "termination"/"terminate", which looks like ample cover until you meet a
 *    sub-processing agreement that never uses the word "terminate" at all —
 *    the corpus has one, with zero occurrences. Renamed, it was told it has no
 *    term or termination clause.
 *
 * Kept as ONE list so the next rule does not carry a narrower copy: three
 * separate hand-written subsets of this vocabulary already existed in
 * `_helpers.ts` alone, agreeing with each other only loosely.
 *
 * Deliberately NOT here: "Policy" and "Plan" on their own. Both are ordinary
 * nouns in a contract's own prose — an insurance policy, a benefit plan, a
 * data-retention policy — and admitting them would let "the Plan" in a
 * document ABOUT a plan stand in for the instrument itself.
 */
export const INSTRUMENT_NOUN =
  "Agreement|Contract|Subcontract|Sub-Contract|Lease|Sublease|Deed|Indenture|Instrument|" +
  "Order Form|Order|Note|Statement of Work|SOW|Addendum|Amendment|Rider|Memorandum";

/**
 * The same list, lower-cased, for a recognizer that already carries the `i`
 * flag. Written out rather than `.toLowerCase()`d at each use so the cost is
 * paid once and a reader sees exactly what is matched.
 */
export const INSTRUMENT_NOUN_I = INSTRUMENT_NOUN.toLowerCase();

/**
 * The party on the RECEIVING side of a one-sided term.
 *
 * Four rules carried four different hand-written versions of this list and no
 * two of them agreed — TERM-009, DARK-003, DARK-006 and CHOICE-010 — which is
 * the "six lists with five different answers" shape that `ATTACHMENT_KIND` was
 * written to end one level down. Not one of the four contained **Client**, so
 * a professional-services agreement whose Client may terminate only for
 * material breach, while the Vendor may terminate at will, was read as
 * symmetric. "Client" is what an agency, a law firm and a consultancy call
 * their customer, and the asymmetry is identical.
 *
 * The union of the four, plus Client. `you` is deliberately NOT here: it is
 * DARK-003's consumer-terms voice and belongs to that rule's own framing, not
 * to a shared vocabulary of role NOUNS.
 */
export const COUNTERPARTY_ROLE =
  "Customer|Client|Licensee|Recipient|Receiving Party|Employee|Tenant|Lessee|Contractor|" +
  "Consumer|User|Subscriber|Buyer|Purchaser|Borrower|Guarantor";
