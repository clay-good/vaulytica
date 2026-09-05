import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, topPosition } from "../_helpers.js";
import { forEachParagraph } from "../../../extract/walk.js";

/**
 * An obligation whose action is DISCLAIMED — "Vendor shall **not have any
 * reciprocal indemnification obligation**". The extractor records the obligor
 * and the action verbatim, so counting it as that party bearing the obligation
 * inverts the clause's meaning and hides the very asymmetry this rule exists to
 * report.
 */
const NEGATED_ACTION = /^(?:not|never)\b/i;

/**
 * A negation that governs a NOUN LIST: "shall make **no** representations,
 * warranties, or guarantees". A single leading "no" disclaims every item, but a
 * fixed 12-character look-back only caught the first noun — the second and third
 * ("warranties", "guarantees") were read as borne obligations, inverting the
 * clause. Anchored to end at the keyword, this matches the negation plus a
 * comma/"or"/"and"-separated run of noun items right up to it. It deliberately
 * does NOT span a verb ("…with no cap, and warrants X" keeps the genuine
 * warranty), because a list item is at most two words followed by a separator.
 */
const NEGATED_LIST =
  /\b(?:makes?\s+no|(?:shall|will|must)\s+not\s+make(?:\s+any)?|without|no)\s+(?:\w+(?:\s+\w+)?[,]\s*|\w+\s+(?:or|and)\s+)*$/i;

/**
 * The obligations that are mutual by default, each with the name a reader
 * would use for it. The label is not decoration: the finding's title and
 * excerpt used to interpolate the pattern itself, so every OBLI-002 finding
 * this tool has ever emitted read "Asymmetric obligation under
 * '\bconfidential'" and "Obligation kind matching /\bconfidential/i" —
 * engine internals printed at an attorney.
 */
const RECIPROCAL_PATTERNS = [
  { label: "confidentiality", pattern: /\bconfidential/i },
  { label: "indemnification", pattern: /\bindemnif/i },
  // The CONTRACTUAL sense only. A bare `\brepresentation` also matches being
  // REPRESENTED — "the exclusive bargaining representative", "a joint safety
  // committee with equal representation", "union representation at any
  // investigatory interview" — and on a collective bargaining agreement, where
  // representation is the subject matter of the whole instrument, that read as
  // the Employer bearing a one-sided warranty. Same defect the warranty
  // pattern below was narrowed for, and the same shape of fix: the verb with
  // its "that", or the noun beside "warranties".
  {
    label: "representations",
    pattern:
      /\brepresents?\s+(?:and\s+warrants?\s+)?that\b|\brepresentations?\s+and\s+warrant(?:y|ies)\b|\brepresentations?\s+(?:made|contained|set\s+forth)\b/i,
  },
  // The WARRANTY sense only. A bare `\bwarrant` also matches the SECURITY —
  // and on a warrant agreement every operative sentence names it: "the Company
  // shall issue a replacement warrant", "the Warrant Shares shall be
  // proportionately adjusted". Not one of them is a warranty, and the document
  // was told its warranties ran one way.
  { label: "warranties", pattern: /\bwarrant(?:y|ies)\b|\bwarrants?\s+that\b|\bwarranted\b/i },
] as const;

/**
 * Role labels that name a POSITION either party can occupy, not a specific
 * party — a mutual NDA / BAA defines "Receiving Party" so that each side is the
 * Receiving Party when it holds the other's information. An obligation written
 * to such a role ("the Receiving Party shall keep it confidential") is mutual
 * by construction: both parties bear it. Counting the single role label as one
 * obligor and reporting "only the Receiving Party bears this" is a false
 * asymmetry — and even in a UNILATERAL NDA the Receiving Party's confidentiality
 * duty is the expected shape, not an imbalance worth surfacing. Party-specific
 * roles (Vendor, Customer, Employee, Landlord, Licensor) are deliberately NOT
 * here: a one-sided indemnity from the Vendor alone is a genuine asymmetry.
 */
const RECIPROCAL_ROLES = new Set([
  "receiving party",
  "receiving parties",
  "recipient",
  "disclosing party",
  "discloser",
  "each party",
  "either party",
  "both parties",
  "the parties",
]);

/**
 * A MUTUAL statement of the same obligation, written with a subject that
 * occupies both sides: "EACH PARTY represents that it is not suspended,
 * debarred, …". The obligation extractor triggers on "shall"/"will", not on
 * the bare present-tense "represents", so a whole section headed
 * REPRESENTATIONS in which each party represents produced NO obligation at
 * all — while a single "Subcontractor will furnish … and represents that the
 * information it furnishes is current" produced one, and the document was told
 * its representations run one way. `mutualByRole` cannot see what the
 * extractor never recorded, so the document text is consulted directly.
 */
function statedMutually(ctx: RuleContext, pattern: RegExp): boolean {
  const near = new RegExp(
    String.raw`\b(?:each|either|both)\s+part(?:y|ies)\b[^.;]{0,120}?(?:${pattern.source})`,
    "i",
  );
  let found = false;
  forEachParagraph(ctx.tree, (p) => {
    if (!found && near.test(p.text)) found = true;
  });
  return found;
}

/** OBLI-002 — Reciprocity asymmetry (info). */
export const rule: Rule = {
  id: "OBLI-002",
  version: "1.6.0",
  name: "Reciprocity asymmetry",
  category: "obligations",
  default_severity: "info",
  description: "For typically-mutual obligations, flags when only one party bears the obligation.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const parties = ctx.extracted.parties;
    if (parties.length < 2) return null;
    // Obligations name the party by whichever surface form the drafter used,
    // and contracts overwhelmingly write the ROLE ("Employee shall …", "the
    // Company shall …") rather than the legal name. Matching on `name` alone
    // silently dropped every role-phrased obligor, so a genuinely one-sided
    // clause went unreported whenever the document used its own defined roles.
    const partySet = new Set(
      parties.flatMap((p) => [p.name.toLowerCase(), ...(p.role ? [p.role.toLowerCase()] : [])]),
    );
    for (const { label, pattern } of RECIPROCAL_PATTERNS) {
      const seenObligors = new Set<string>();
      /**
       * The subset of `seenObligors` that are party CLASSES. A class occupies
       * every side at once, exactly as "each party" does, so a class standing
       * ALONE is mutual by construction — a joint venture whose only
       * confidentiality duty reads "Each Member shall keep confidential" binds
       * both members, and reporting that "only each member bears" it is both
       * false and unreadable. Standing beside a party-specific obligor it is a
       * genuine second side, which is why it is counted at all.
       */
      const classObligors = new Set<string>();
      let mutualByRole = false;
      for (const o of ctx.extracted.obligations) {
        const m = pattern.exec(o.action);
        if (!m) continue;
        if (NEGATED_ACTION.test(o.action.trim())) continue;
        // The keyword may be DISCLAIMED — directly ("reconvey the Property
        // WITHOUT WARRANTY", "makes no representation") or as a later member of a
        // negated noun list ("make NO representations, warranties, or
        // guarantees"). The look-back anchors a negation + comma/or-separated
        // noun run ending right at the keyword, so every item the single "no"
        // governs is skipped, not just the first.
        const lead = o.action.slice(0, m.index);
        if (NEGATED_LIST.test(lead)) continue;
        const o2 = o.obligor.toLowerCase().trim();
        // A generic reciprocal subject ("the parties", "each party") bearing the
        // obligation makes it mutual by construction — and such a subject is NOT
        // a party name/role, so it never lands in `partySet`. Left uncounted, a
        // genuinely-mutual "the parties shall keep it confidential" could not
        // offset a stray party-specific mention (e.g. a mis-segmented "Buyer
        // shall … and each party shall return Confidential Information"), and the
        // rule reported a false asymmetry. Flag the pattern mutual instead.
        if (RECIPROCAL_ROLES.has(o2)) {
          mutualByRole = true;
          continue;
        }
        if (partySet.has(o2)) {
          seenObligors.add(o2);
          continue;
        }
        // A CLASS of counterparties — "Each Investor shall keep confidential
        // …", "Each Member shall indemnify …". The class is not a signatory
        // the party extractor can register (the Investors sign a schedule), so
        // it never lands in `partySet`, and the duty it plainly bears went
        // uncounted: an investor rights agreement that binds the Company and
        // every Investor alike was reported as binding only the Company.
        //
        // Narrow on purpose: "each"/"every", up to two lower-case adjectives
        // ("Each SELLING Investor shall indemnify …"), and a capitalized
        // noun. That is a party class, not a noun phrase — "Warrant Shares and
        // the Exercise Price" is a subject too, and is not a side. Written
        // without the `i` flag on purpose: the trailing `[A-Z][a-z]+` is what
        // makes this a party class rather than any two words, and under `i`
        // that matches lower-case prose.
        if (/^(?:[Ee]ach|[Ee]very)\s+(?:[a-z]+\s+){0,2}[A-Z][a-z]+$/.test(o.obligor.trim())) {
          seenObligors.add(o2);
          classObligors.add(o2);
        }
      }
      if (mutualByRole) continue;
      if (seenObligors.size === 1 && partySet.size >= 2) {
        // A generic reciprocal role occupies both sides, so a single-role
        // obligation is symmetric, not one-sided — skip it and keep checking the
        // remaining reciprocal patterns for a genuinely party-specific asymmetry.
        if (RECIPROCAL_ROLES.has([...seenObligors][0]!)) continue;
        if (classObligors.has([...seenObligors][0]!)) continue;
        if (statedMutually(ctx, pattern)) continue;
        return emit(ctx, rule, {
          title: `Asymmetric ${label} obligation`,
          description: `Only ${[...seenObligors][0]} bears this typically-mutual obligation.`,
          excerpt: `${label} obligation`,
          explanation:
            "Obligations like confidentiality, indemnity, and representations are usually mutual. A one-sided version is sometimes intentional but worth confirming.",
          position: topPosition(ctx),
        });
      }
    }
    return null;
  },
};
