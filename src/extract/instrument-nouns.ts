/**
 * The nouns an instrument calls ITSELF.
 *
 * "This Agreement", "this Addendum", "this Statement of Work" — the word a
 * document uses for its own kind. Two very different questions are answered
 * from this one list, and they must be answered from the SAME one:
 *
 *   - Does this document say it is issued under a parent? (`_helpers.ts`'s
 *     `ISSUED_UNDER_PARENT` / `amendsParentAgreement` — a vocabulary gap there
 *     was six confident false accusations per ancillary document in 9.638.0.)
 *   - Is a captured date anchor over-extended into a document self-reference?
 *     ("the Effective Date **of this Agreement**" is the Effective Date; "the
 *     end **of the Term**" is not a self-reference and must survive.)
 *
 * It lives in the extract layer because that is the lower one: the rules import
 * from `src/extract`, never the other way. `shared-vocabulary.test.ts` names
 * this file as the single owner.
 *
 * A document is as often a Contract or a Deed as an Agreement — the
 * defined-term rename relation said so by bringing six findings back when a DPA
 * was renamed from Agreement to Contract.
 */
export const SELF_NAMED_INSTRUMENT_NOUNS = [
  "Statement of Work",
  "SOW",
  "Order Form",
  "Order",
  "Rider",
  "Amendment",
  "Letter",
  "Agreement",
  "Annexure",
  "Annex",
  "Appendix",
  "Appendices",
  "Addendum",
  "Schedule",
  "Exhibit",
  "Attachment",
  "Contract",
  "Deed",
] as const;

/** The list as a regex alternation, in both the plain and shouted spellings. */
export const SELF_NAMED_NOUN_ALT = SELF_NAMED_INSTRUMENT_NOUNS.flatMap((n) => [n, n.toUpperCase()])
  .map((n) => n.replace(/ /g, String.raw`\s+`))
  .join("|");
