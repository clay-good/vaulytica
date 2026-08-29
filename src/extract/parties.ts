import type { DocumentTree } from "../ingest/types.js";
import type { Party, DocPosition } from "./types.js";
import { forEachParagraph, trimEdges, trimEnd } from "./walk.js";

/**
 * Extract contracting parties from the document preamble and signature
 * blocks. Heuristics, in order:
 *
 * 1. Preamble pattern: `between X and Y` / `by and between X, … and Y, …`,
 *    looked up in the first 25% of the document.
 * 2. Defined-role pattern: `X, a Delaware corporation ("Provider")`. The
 *    quoted label is the role; the leading entity name is the party.
 * 3. Signature-block pattern: lines containing `By: ___` near the end of
 *    the document anchor the canonical party names. Names from signature
 *    blocks are unioned with preamble matches.
 *
 * Conservative: when no clean match is found, an empty array is returned.
 * Downstream rules (STRUCT-001) catch the absence.
 */

const ENTITY_TYPES = [
  "corporation",
  "company",
  "inc\\.?",
  "llc",
  "l\\.l\\.c\\.",
  "ltd\\.?",
  "limited liability company",
  "limited partnership",
  "partnership",
  "trust",
  "individual",
  "sole proprietorship",
  "professional corporation",
  "pllc",
  "gmbh",
  "ag",
  "plc",
];

const US_STATE =
  "(?:Alabama|Alaska|Arizona|Arkansas|California|Colorado|Connecticut|Delaware|Florida|Georgia|Hawaii|Idaho|Illinois|Indiana|Iowa|Kansas|Kentucky|Louisiana|Maine|Maryland|Massachusetts|Michigan|Minnesota|Mississippi|Missouri|Montana|Nebraska|Nevada|New Hampshire|New Jersey|New Mexico|New York|North Carolina|North Dakota|Ohio|Oklahoma|Oregon|Pennsylvania|Rhode Island|South Carolina|South Dakota|Tennessee|Texas|Utah|Vermont|Virginia|Washington|West Virginia|Wisconsin|Wyoming|District of Columbia|D\\.C\\.)";

// `g` only (not `gi`) — the case-insensitive flag would defeat the
// capitalized-word name pattern and let the engine slurp lowercase
// connectives like `is`, `made`, `between`, `and` into the captured
// name. Entity-type tokens in the text are lowercase by convention
// ("a Delaware corporation"); the `ENTITY_TYPES` list mirrors that.
const PARTY_DECL = new RegExp(
  // Each name token is BOUNDED (`{0,80}`, not `*`): the name is followed by a
  // REQUIRED entity-type suffix, so an unbounded token matches a long letter
  // run, fails to find the suffix, and backtracks the run from every start
  // position — O(n²) on a hostile uppercase run (a ReDoS hang, spec-v8 §5). No
  // real name token exceeds 80 chars, so this is byte-identical and now linear.
  // The entity-type group needs a non-letter boundary on BOTH sides. Without a
  // trailing one the short types match the START of ordinary words — `inc` in
  // "including", `ag` in "agreement". Without a leading one they match the END
  // of a longer word: `corporation` sits inside "In·corporation", so a heading
  // "EU SCC Incorporation" yielded the party "EU SCC In". Either way a junk
  // name is manufactured, and it is not harmless — rules that compare a phrase
  // against the party set (STRUCT-006) treat it as real and party-tallying
  // rules (RISK-002) report counts against it.
  String.raw`([A-Z][\w&.,'’-]{0,80}(?:\s+[A-Z][\w&.,'’-]{0,80}){0,6})\s*,?\s*(?:a|an)?\s*(?:(${US_STATE})\s+)?(?<![A-Za-z])(${ENTITY_TYPES.join("|")})(?![A-Za-z])` +
    // A QUALIFIER may sit between the entity type and the role parenthetical:
    // "Sonoran Crest Management, Inc., an Arizona corporation HOLDING ARIZONA
    // REAL ESTATE BROKER LICENSE NUMBER BR-558214 (\"Manager\")". Requiring the
    // parenthetical to follow the type immediately dropped the role — and
    // `BETWEEN_RE` cannot supply it either, because its capture terminates at
    // the comma before "an Arizona corporation". A party with no role is
    // invisible to every rule that compares an obligor against the party set,
    // so OBLI-002 reported a MUTUAL indemnity as one-sided.
    //
    // The gap refuses to cross "and", so it cannot reach past this party's
    // clause into the next party's role, and the leading period is admitted
    // only as an ABBREVIATION period — one not followed by a capital across a
    // space — so it cannot run past the end of the sentence.
    // The gap and the parenthetical are ONE optional group: with the gap
    // optional and non-greedy on its own, the engine always matched it empty
    // and the role was never reached.
    String.raw`(?:(?:\.(?!\s+[A-Z]))?\s*(?:(?!\band\b)[^.;()]){0,120}?\s*\(\s*["“”']([^"”'’\)]+)["“”']\s*\))?`,
  "g",
);

/**
 * The suffix forms a legal name carries after a comma ("Globex Industries,
 * Inc."). Shared by `BETWEEN_RE`'s terminator and `BARE_ENTITY_SUFFIX` so the
 * two cannot disagree about what counts as a suffix.
 */
const LEGAL_SUFFIX = String.raw`l\.?p\.?|l\.?l\.?c\.?|inc\.?|corp\.?|corporation|co\.?|ltd\.?|limited|llp|pllc|gmbh|a\.?g\.?|plc|s\.?a\.?|sarl|n\.?v\.?|b\.?v\.?|pty`;

/**
 * A comma does NOT end the second party when it is the comma that separates a
 * legal name from its own suffix. Stopping there captured "Globex Industries"
 * out of "…and Globex Industries, Inc., a New York corporation", which
 * registered under a different key than the full name `PARTY_DECL` captures —
 * so one company became TWO parties, the second roleless. Party-tallying rules
 * (RISK-002) count that phantom.
 */
const BETWEEN_RE = new RegExp(
  String.raw`\bbetween\s+(.+?)\s+and\s+(.+?)(?:[.;]|,(?!\s*(?:${LEGAL_SUFFIX})(?![A-Za-z]))|$)`,
  "gi",
);

/**
 * A THREE-OR-MORE party preamble is introduced with "among", not "between":
 * "by and among X, Y, and Z". `BETWEEN_RE` only ever reads two parties, so a
 * shareholders' / merger / JV agreement that names its parties in an
 * "among"-list left every party but the entity-typed ones (which `PARTY_DECL`
 * catches independently) unread — and an all-individual "among" preamble
 * ("by and among Alice Walker, Bob Marley, and Carol King") reported "no
 * parties" outright. The captured list runs to the sentence terminator and is
 * split into its members below. Gated by the same `PREAMBLE_LEAD` as `between`,
 * so "allocated among the members" / "shared among the parties" in ordinary
 * prose is not read as a preamble.
 *
 * The list body absorbs an in-abbreviation period rather than treating it as
 * the sentence terminator — the corpus writes its "among" lists with
 * abbreviated entity types ("Alpha Inc., Beta Corp., and Gamma Ltd.", "Acme
 * Inc. ("Buyer"), …"), so a non-greedy `.+?` stopped at the FIRST period
 * ("Alpha Inc") and dropped every party but the first. A period is in-word when
 * it is NOT followed by whitespace/end (`Inc.,` `L.P.` `Ltd`) OR when a role
 * parenthetical or an "and" connector follows across a space (`Inc. ("Buyer")`,
 * `Corp. and Gamma …`). Those two arms are the only period-space contexts a
 * party list opens; anything else after a period-space — a new capitalized word
 * (a fresh sentence "…Z. This Agreement …", a middle initial "Alice B. Walker")
 * or the end of the paragraph — terminates the list, so the capture never runs
 * past the preamble sentence. The three arms are mutually exclusive (a char is a
 * non-period, a period with no following space, or a period with a following
 * space), so the `+` is unambiguous — no backtracking (spec-v8 §5). Kept
 * case-insensitive so an ALL-CAPS preamble ("BY AND AMONG …") still reads.
 */
const AMONG_RE = /\bamong\s+((?:[^.;\n]|\.(?!\s|$)|\.(?=\s+(?:and\s|["“(])))+)(?:[.;]|$)/gi;

// A member that is nothing but an entity-type suffix — produced when an "among"
// list separates the suffix from the name with a comma ("Alpha Holdings, L.P.")
// and `AMONG_SEP` splits on that comma. The name (e.g. "Alpha Holdings") is kept
// on its own; the bare "L.P." / "LLC" fragment is not a party.
const BARE_ENTITY_SUFFIX = new RegExp(`^(?:${LEGAL_SUFFIX})$`, "i");

/**
 * Split an "among" party list into members. Consumes the Oxford / non-Oxford
 * comma and the trailing "and" as ONE separator ("X, Y, and Z" and "X, Y and
 * Z" both yield three). Each member is name-cleaned downstream, and
 * `cleanPartyName` rejects a lowercase-leading entity descriptor ("a Delaware
 * corporation") on its own, so a mixed list of names and descriptors keeps only
 * the names. Case-insensitive so an ALL-CAPS preamble's "… AND …" join is
 * consumed as a separator, not left glued to the last member ("AND GAMMA LTD").
 */
const AMONG_SEP = /\s*,\s*(?:and\s+)?|\s+and\s+/i;

/**
 * `between X and Y` names the contracting parties only inside an actual
 * preamble. The same three words are everywhere in ordinary drafting — "the
 * difference **between** Gross Revenue and Net Revenue", "any conflict
 * **between** this MSA and any Statement of Work" — and reading those as a
 * preamble invents parties named "Gross Revenue" and "Net Revenue for the
 * applicable period". A junk party is not inert: STRUCT-006 treats it as a
 * real name and stops reporting the term as undefined, and every rule that
 * tallies by party (RISK-002) reports a count against it.
 *
 * So the phrase must be introduced the way a preamble introduces it. The
 * corpus writes exactly three forms:
 *   1. `… by and between X and Y`;
 *   2. `… is made / entered into / executed / dated … between X and Y`;
 *   3. `This Statement of Work is between X and Y` — the instrument names
 *      ITSELF as the sentence's subject, so the lead-in is anchored to the
 *      start of the sentence and must end on the copula. That anchor is what
 *      keeps a fee sentence out: "The Service Fee **is the difference**
 *      between Gross Revenue and Net Revenue" opens the same way but does not
 *      end on `is`, and "**Fees payable** under this Agreement are …" does not
 *      open with the instrument at all.
 * A bare instrument noun immediately before the word also reads (`the Master
 * Services Agreement between X and Y` — an SOW naming its parent contract).
 * Anything else is prose that merely contains the word.
 *
 * The `\.(?!\s)` alternative keeps each lead-in window inside one sentence
 * while tolerating an in-word period, so a statutory citation in the recital
 * ("entered into pursuant to 45 CFR § 164.504(e) between …") still reads. The
 * window is 160 chars because a real recital runs long: the DPA corpus writes
 * 114 chars of statutory citation between "entered into" and "between".
 */
const INSTRUMENT =
  "(?:agreement|contract|amendment|addendum|lease|deed|indenture|memorandum|mou|nda|msa|sow|dpa|baa|eula|guaranty|note|assignment|release|licence|license)";
const SAME_SENTENCE = String.raw`(?:[^.;\n]|\.(?!\s))`;
/**
 * How much front matter the preamble window covers when the paragraph count
 * is small — about a page, which is where a preamble lives in any layout.
 */
const PREAMBLE_CHAR_FLOOR = 2500;

/** The number of leading paragraphs whose text totals at least `chars`. */
function paragraphsCovering(paragraphs: ReadonlyArray<{ text: string }>, chars: number): number {
  let total = 0;
  let n = 0;
  while (n < paragraphs.length && total < chars) {
    total += paragraphs[n]!.text.length;
    n += 1;
  }
  return n;
}

const PREAMBLE_LEAD = new RegExp(
  "(?:" +
    String.raw`\bby\s+and\s+` +
    "|" +
    `\\b${INSTRUMENT}\\s+` +
    "|" +
    String.raw`(?:^|[.;]\s)\s*(?:this|the)\s+${SAME_SENTENCE}{0,80}\b(?:is|are|was|were)\s+` +
    "|" +
    String.raw`\b(?:made|entered\s+into|executed|dated|effective)\b${SAME_SENTENCE}{0,160}` +
    ")$",
  "i",
);

/**
 * A LABELED party line: "Data Exporter: Globex EU SARL, a French société à
 * responsabilité limitée, 15 rue Lafayette, 75009 Paris, France".
 *
 * The SCC annexes, the UK IDTA tables and certificates of insurance name their
 * parties this way — no preamble, no "between", and often a foreign entity
 * type the declaration pattern does not know. Without this path STRUCT-001
 * reported "Vaulytica could not identify the parties to this Agreement" about
 * a document naming them under a "Parties" heading.
 *
 * The label must open the line and the name must be capitalized, so a
 * descriptive sentence ("Recipient: the party receiving Confidential
 * Information") is not read as a party name.
 */
/** The role labels a party line or a role-first preamble uses. */
const PARTY_ROLE_LABEL = String.raw`Data\s+Exporter|Data\s+Importer|Exporter|Importer|Discloser|Disclosing\s+Party|Recipient|Receiving\s+Party|Covered\s+Entity|Business\s+Associate|Controller|Processor|Sub-?processor|Service\s+Provider|Subcontractor|Sublicensee|Sublessee|Landlord|Tenant|Lessor|Lessee|Licensor|Licensee|Buyer|Seller|Purchaser|Vendor|Supplier|Provider|Customer|Client|Company|Employer|Employee|Contractor|Consultant|Borrower|Lender|Guarantor|Trustee|Grantor|Settlor|Named\s+Insured|Insured|Insurer|Party\s+[AB]`;

const LABELED_PARTY = new RegExp(
  // The name body absorbs an in-abbreviation period — one followed by a
  // non-space ("J.P.", "N.A.") or by a Capitalized continuation ("J.P. Morgan")
  // — but stops at a sentence period (followed by a space + lowercase word, or
  // end). Without this, a name whose first token is an initialed abbreviation
  // ("Lender: J.P. Morgan Chase Bank") failed the `{2,80}` minimum at the first
  // period and was dropped entirely, so a labeled-only document (SCC annex,
  // IDTA table) reported STRUCT-001 "could not identify the parties".
  String.raw`(?:^|\n)\s*(${PARTY_ROLE_LABEL})\s*:\s*(?!\s)([A-Z](?:[^\n,;.]|\.(?!\s|$)|\.(?=\s+[A-Z])){2,80})`,
  "g",
);

/**
 * The role labels of a ONE-SIDED instrument, whose preamble names its parties
 * as "<Name> (the \"<Role>\")" with no entity-type suffix — an individual
 * guarantor, a trust settlor, an insured. PARTY_DECL requires an entity type,
 * so those parties went uncaptured and STRUCT-001 reported "no parties" about
 * a guaranty / security agreement / trust / insurance summary that names them
 * plainly ("by Harold Vance (the \"Guarantor\") in favor of … (the
 * \"Lender\")").
 *
 * Deliberately EXCLUDES the reciprocal roles (Receiving Party, Recipient,
 * Discloser, Disclosing Party) a MUTUAL agreement uses: an obligation stated
 * on "the Receiving Party" is borne by whichever party is receiving, so
 * surfacing that role as a single party would make OBLI-002 read the
 * role-based mutuality as a one-sided (asymmetric) obligation. These
 * one-sided roles denote a fixed position only one party holds.
 */
// A power of attorney names its two sides "<Name> (the \"Principal\")" and
// "<Name> (the \"Agent\"/\"Attorney-in-Fact\")" with no entity-type suffix, so
// PARTY_DECL missed both and STRUCT-001 reported "no parties" on a plainly
// captioned POA. "Agent"/"Principal" are quote-anchored on both sides here, so
// a credit agreement's "Administrative Agent" (a space, not a quote, precedes
// "Agent") is untouched.
const ONE_SIDED_ROLE = String.raw`Guarantor|Grantor|Grantee|Settlor|Trustor|Trustee|Beneficiary|Debtor|Secured\s+Party|Creditor|Mortgagor|Mortgagee|Pledgor|Pledgee|Assignor|Assignee|Surety|Maker|Payee|Borrower|Lender|Insured|Insurer|Named\s+Insured|Indemnitor|Indemnitee|Principal|Attorney-in-Fact|Agent`;
// The paren may carry more than the one role — a revocable trust names one
// person as both settlor and trustee: "Margaret Okafor (the \"Grantor\" and
// initial \"Trustee\")" — so allow trailing content (no nested close paren)
// after the role before the paren closes.
const ROLE_LABELED_PARTY = new RegExp(
  String.raw`([A-Z][\w&.,'’-]{0,80}(?:\s+[A-Z][\w&.,'’-]{0,80}){0,5})\s*\(\s*(?:the\s+)?["“”'](${ONE_SIDED_ROLE})["“”'][^)]{0,60}\)`,
  "g",
);

/**
 * The same shape in an ALL-CAPS instrument.
 *
 * Old-form guaranties, bonds, and powers of attorney are set in capitals from
 * the caption to the signature: `BY MARTIN R. ODEGAARD … (THE "GUARANTOR"), IN
 * FAVOR OF NORTHLAND MERCANTILE BANK, N.A. (THE "LENDER")`. The pattern above
 * is case-SENSITIVE — its lead-in "the" and its Title-Case role names — so an
 * all-caps document registered no parties at all and STRUCT-001 reported "could
 * not identify the parties" about a preamble that names both.
 *
 * Used ONLY when the document offers no case contrast, and the NAME capture is
 * restricted to all-caps, so nothing a mixed-case document produces can change.
 */
const ROLE_LABELED_PARTY_CAPS = new RegExp(
  String.raw`([A-Z][A-Z&.,'’\d-]{0,80}(?:\s+[A-Z][A-Z&.,'’\d-]{0,80}){0,5})\s*\(\s*(?:THE\s+)?["“”'](${ONE_SIDED_ROLE})["“”'][^)]{0,60}\)`,
  "gi",
);

/** True when the text offers no case contrast, so capitalization is not evidence. */
function isAllCapsText(text: string): boolean {
  return /[A-Z]/.test(text) && text === text.toUpperCase();
}

/**
 * A role-first preamble names the party as `<Role>, <Legal Name>`: "between
 * Covered Entity, Acme Health LLC, a Delaware limited liability company
 * (\"Covered Entity\"), and Business Associate, Globex Services Inc." The
 * label is not part of the name, and keeping it produced parties literally
 * named "Covered Entity, Acme Health LLC" — a string that appears nowhere else
 * in the document, so every rule matching a party surface against the text
 * missed it. The comma is required, so a company whose name simply starts with
 * a role word ("Trustee Services LLC") is untouched.
 */
const LEADING_ROLE = new RegExp(String.raw`^(${PARTY_ROLE_LABEL})\s*,\s*(?=[A-Z])`, "i");

/**
 * A lead-in that DISCLAIMS the very relationship its "between" names —
 * "does not constitute a contract between", "creates no partnership between",
 * "nothing herein forms a joint venture between". Scoped to the tail of the
 * lead-in so an earlier unrelated negation in the paragraph does not suppress
 * a real preamble.
 */
const NEGATED_PREAMBLE =
  /\b(?:not|no|nothing|never|neither)\b(?:[^.;\n](?!\bbetween\b)){0,80}(?:constitute|create|form|imply|establish|give\s+rise\s+to|amount\s+to)\w*(?:[^.;\n](?!\bbetween\b)){0,40}$/i;

/**
 * The signature-block labels whose VALUE is a person's name. All four of
 * "By:", "Name:", "Title:" and "Date:" mark a signature-block line, but only
 * the first two carry a name after them.
 * Stripping any of the four and registering what followed turned the
 * execution date of a signed form into a party: a contributor license
 * agreement ending in "Date: May 14, 2026" reported one party, named
 * "May 14, 2026" — which also masked the true finding that the form names
 * no parties the extractor can read.
 */
const SIGNATURE_NAME_LINE = /^(?:By|Name)\s*:?\s*/i;

/**
 * Every "By:" / "Name:" segment in a signature paragraph, not just the
 * leading one. Two-column e-signature blocks flatten to one line with
 * both parties' "By:"/"Name:" fields; capturing each segment recovers
 * the second party the leading-anchored regex drops. (v7 §7.)
 */
const SIGNATURE_FIELD =
  /\b(?:By|Name)\s*:\s*(?:\/s\/\s*)?([A-Z][\w.'’-]*(?:\s+[A-Z][\w.'’-]*){0,4}?)(?=\s+(?:By|Name|Title|Date|its)\b|[,;]|\t|\s{2,}|$)/g;

/**
 * "doing business as" / "d/b/a" operating name following a legal name.
 * Capture both names; the operating name becomes the party's `dba`.
 */
const DBA_RE =
  /\b(?:d\/b\/a|d\.b\.a\.|dba|doing business as)\s+["“”']?([A-Z][\w&.,'’-]*(?:\s+[A-Z][\w&.,'’-]*){0,5})/gi;

export function extractParties(tree: DocumentTree): Party[] {
  const partyMap = new Map<string, Party>();
  const allText: { text: string; pos: (start: number, end: number) => DocPosition }[] = [];

  forEachParagraph(tree, (ctx) => {
    allText.push({
      text: ctx.text,
      pos: (start, end) => ({
        section_id: ctx.section.id,
        paragraph_id: ctx.paragraph.id,
        start: ctx.start + start,
        end: ctx.start + end,
      }),
    });
  });

  // Determine the preamble: first 25% by paragraph count.
  // A purely proportional window collapses on short documents: a four-paragraph
  // agreement scans only paragraph 1 — usually the title — so a preamble
  // sitting in paragraph 2 is never read and the document reports "could not
  // identify the parties" while naming them in plain sight. The preamble is a
  // fixed feature of the front matter, not a proportion of the body, so give it
  // a floor of the first few paragraphs.
  //
  // A paragraph COUNT is a fact about the layout, not about the document. The
  // same option-grant notice arrives as twenty-one paragraphs with its blank
  // lines and as six without them — a PDF copy-paste, where each numbered
  // section runs into its heading — and a quarter of six is one paragraph
  // past the preamble. The grant reported "No parties identified" while
  // naming the company, its state, and its defined role in plain sight. So
  // the window is also floored in CHARACTERS: enough paragraphs to cover the
  // front matter however the text happens to be chunked.
  const preambleCount = Math.max(
    3,
    Math.ceil(allText.length * 0.25),
    paragraphsCovering(allText, PREAMBLE_CHAR_FLOOR),
  );

  for (let i = 0; i < preambleCount && i < allText.length; i += 1) {
    const { text, pos } = allText[i]!;
    PARTY_DECL.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = PARTY_DECL.exec(text)) !== null) {
      // Every other extraction path runs its captured name through
      // cleanPartyName; this one did not, so the name char-class baked a
      // trailing comma in ("Acme Corp,") and the same entity registered twice —
      // once dirty here, once cleanly from the `between` preamble, since
      // registerParty keys on the lowercased name.
      const name = cleanPartyName(m[1] ?? "");
      const state = m[2];
      const entity = m[3];
      const role = m[4];
      if (!name || isBoilerplateName(name)) continue;
      registerParty(partyMap, name, {
        role,
        entity_type: entity,
        jurisdiction_of_formation: state,
        position: pos(m.index, m.index + m[0].length),
      });
    }
    const roleLabeled = isAllCapsText(text) ? ROLE_LABELED_PARTY_CAPS : ROLE_LABELED_PARTY;
    roleLabeled.lastIndex = 0;
    let rm: RegExpExecArray | null;
    while ((rm = roleLabeled.exec(text)) !== null) {
      const name = cleanPartyName(rm[1] ?? "");
      const role = rm[2];
      if (!name || isBoilerplateName(name)) continue;
      registerParty(partyMap, name, {
        role,
        position: pos(rm.index, rm.index + rm[0].length),
      });
    }
    DBA_RE.lastIndex = 0;
    let dm: RegExpExecArray | null;
    while ((dm = DBA_RE.exec(text)) !== null) {
      const dba = cleanPartyName(dm[1] ?? "");
      if (!dba) continue;
      // Attach to the party whose declaration ends nearest before the
      // d/b/a phrase (the legal name it operates under).
      const before = text.slice(0, dm.index);
      PARTY_DECL.lastIndex = 0;
      let pm: RegExpExecArray | null;
      let legal = "";
      while ((pm = PARTY_DECL.exec(before)) !== null) {
        // Must match how the party was REGISTERED above (cleaned), or this
        // partyMap lookup misses and the d/b/a silently fails to attach.
        const cand = cleanPartyName(pm[1] ?? "");
        if (cand && !isBoilerplateName(cand)) legal = cand;
      }
      const target = legal ? partyMap.get(legal.toLowerCase()) : undefined;
      if (target && !target.dba) target.dba = dba;
    }
    // Take the first `between` in the paragraph that a preamble lead-in
    // introduces — not simply the first one, or a fee sentence sitting above
    // the real preamble would consume the paragraph's only reading.
    BETWEEN_RE.lastIndex = 0;
    let betweenMatch: RegExpExecArray | null;
    while ((betweenMatch = BETWEEN_RE.exec(text)) !== null) {
      const lead = text.slice(0, betweenMatch.index);
      // A DISCLAIMED relationship is the opposite of a preamble: "THIS
      // CERTIFICATE DOES NOT CONSTITUTE A CONTRACT BETWEEN THE ISSUING
      // INSURER(S) … AND THE CERTIFICATE HOLDER" names the two roles precisely
      // to say they are NOT contracting parties. Reading it as a preamble
      // registered both as parties.
      if (NEGATED_PREAMBLE.test(lead)) continue;
      if (PREAMBLE_LEAD.test(lead)) break;
    }
    if (betweenMatch) {
      const { name: a, role: roleA } = splitNameAndRole(betweenMatch[1] ?? "");
      const { name: b, role: roleB } = splitNameAndRole(betweenMatch[2] ?? "");
      if (a) {
        registerParty(partyMap, a, {
          ...(roleA ? { role: roleA } : {}),
          position: pos(betweenMatch.index, betweenMatch.index + (betweenMatch[1]?.length ?? 0)),
        });
      }
      if (b) {
        registerParty(partyMap, b, {
          ...(roleB ? { role: roleB } : {}),
          position: pos(
            betweenMatch.index + (betweenMatch[1]?.length ?? 0) + 5,
            betweenMatch.index + betweenMatch[0].length,
          ),
        });
      }
    }
    // A three-or-more party "among" preamble, introduced the same way a
    // preamble introduces "between". Each list member is registered; entity
    // descriptors and boilerplate fall out in cleanPartyName / isBoilerplateName.
    AMONG_RE.lastIndex = 0;
    let amongMatch: RegExpExecArray | null;
    while ((amongMatch = AMONG_RE.exec(text)) !== null) {
      const lead = text.slice(0, amongMatch.index);
      if (NEGATED_PREAMBLE.test(lead)) continue;
      if (!PREAMBLE_LEAD.test(lead)) continue;
      const listStart = amongMatch.index + amongMatch[0].indexOf(amongMatch[1] ?? "");
      for (const member of (amongMatch[1] ?? "").split(AMONG_SEP)) {
        const { name, role } = splitNameAndRole(member);
        if (!name || isBoilerplateName(name) || BARE_ENTITY_SUFFIX.test(name)) continue;
        const at = text.indexOf(member, listStart);
        registerParty(partyMap, name, {
          ...(role ? { role } : {}),
          position: at >= 0 ? pos(at, at + member.length) : pos(amongMatch.index, amongMatch.index),
        });
      }
      break; // one preamble per paragraph
    }
  }

  // Labeled party lines, anywhere in the document — an SCC annex or an IDTA
  // table has no preamble to scan, and its "Parties" block may sit well past
  // the first quarter.
  for (const { text, pos } of allText) {
    LABELED_PARTY.lastIndex = 0;
    let lm: RegExpExecArray | null;
    while ((lm = LABELED_PARTY.exec(text)) !== null) {
      const role = (lm[1] ?? "").replace(/\s+/g, " ").trim();
      const name = cleanPartyName(lm[2] ?? "");
      if (!name || isBoilerplateName(name)) continue;
      registerParty(partyMap, name, {
        role,
        position: pos(lm.index, lm.index + lm[0].length),
      });
    }
  }

  // Signature blocks: last 15% of paragraphs.
  const sigStart = Math.floor(allText.length * 0.85);
  for (let i = sigStart; i < allText.length; i += 1) {
    const { text, pos } = allText[i]!;
    if (SIGNATURE_NAME_LINE.test(text)) {
      // Only the FIRST label is stripped, so on a two-column block the rest of
      // the line — including the second signer's own "By:" field — came along
      // and registered as one party named "Jane Roe By: John Doe". Cut at the
      // next label so this path yields just its own column's name. That also
      // recovers a signer whose name is too long for `SIGNATURE_FIELD`'s
      // five-word cap, which otherwise skipped the column entirely.
      const after = text
        .replace(SIGNATURE_NAME_LINE, "")
        .replace(/\s+(?:By|Name|Title|Date)\s*:.*$/i, "")
        .trim();
      if (after && /[A-Z]/.test(after) && !/^_+$/.test(after)) {
        const name = cleanPartyName(after);
        if (name) {
          registerParty(partyMap, name, { position: pos(0, text.length) });
        }
      }
    }
    // Two-column / tabular signature blocks: pick up every "By:"/"Name:"
    // field on the line, including the second party's column.
    SIGNATURE_FIELD.lastIndex = 0;
    let sm: RegExpExecArray | null;
    while ((sm = SIGNATURE_FIELD.exec(text)) !== null) {
      const name = cleanPartyName(sm[1] ?? "");
      if (name && !isBoilerplateName(name)) {
        registerParty(partyMap, name, {
          position: pos(sm.index, sm.index + sm[0].length),
        });
      }
    }
  }

  // A role-first preamble ("between Covered Entity, Acme Health LLC, …, and
  // Business Associate, Globex Services Inc.") also matches the `between` path
  // at the comma, so the ROLE registers as if it were a second party. Fold any
  // party whose whole name is another party's role into that party — a
  // two-party BAA reports two parties, not four.
  for (const [key, p] of [...partyMap]) {
    const owner = [...partyMap.values()].find(
      (q) => q !== p && q.role && q.role.toLowerCase() === p.name.toLowerCase(),
    );
    if (!owner) continue;
    owner.positions.push(...p.positions);
    partyMap.delete(key);
  }

  // Resolve alias / role chains: a short form, an upper-cased variant,
  // the defined role, and any d/b/a name all point at one entity.
  for (const party of partyMap.values()) {
    const aliases = computeAliases(party);
    if (aliases.length > 0) party.aliases = aliases;
  }

  // Record every additional occurrence of each known party name.
  for (const party of partyMap.values()) {
    const needle = new RegExp(`\\b${escapeRegExp(party.name)}\\b`, "g");
    for (const { text, pos } of allText) {
      needle.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = needle.exec(text)) !== null) {
        party.positions.push(pos(m.index, m.index + m[0].length));
      }
    }
    // Deduplicate by start offset.
    const seen = new Set<number>();
    party.positions = party.positions.filter((p) => {
      if (seen.has(p.start)) return false;
      seen.add(p.start);
      return true;
    });
  }

  return [...partyMap.values()];
}

function registerParty(
  map: Map<string, Party>,
  name: string,
  extras: {
    role?: string;
    entity_type?: string;
    jurisdiction_of_formation?: string;
    position?: DocPosition;
  },
): void {
  const key = name.toLowerCase();
  const existing = map.get(key);
  if (existing) {
    existing.role = existing.role ?? extras.role;
    existing.entity_type = existing.entity_type ?? extras.entity_type;
    existing.jurisdiction_of_formation =
      existing.jurisdiction_of_formation ?? extras.jurisdiction_of_formation;
    if (extras.position) existing.positions.push(extras.position);
    return;
  }
  map.set(key, {
    id: `party-${map.size + 1}`,
    name,
    role: extras.role,
    entity_type: extras.entity_type,
    jurisdiction_of_formation: extras.jurisdiction_of_formation,
    positions: extras.position ? [extras.position] : [],
  });
}

/**
 * Build the alternate surface forms that refer to the same entity:
 * a short form (the leading distinctive word of a multi-word legal
 * name), an all-caps variant, the defined role, and the d/b/a name.
 * Excludes the canonical name itself and dedupes.
 */
function computeAliases(party: Party): string[] {
  const out: string[] = [];
  const add = (s: string | undefined): void => {
    if (!s) return;
    const v = s.trim();
    if (v && v.toLowerCase() !== party.name.toLowerCase() && !out.includes(v)) out.push(v);
  };
  if (party.role) add(party.role);
  if (party.dba) add(party.dba);
  // Short form: leading word(s) before a corporate suffix, tolerant of
  // trailing punctuation ("Acme Corp.," → "Acme"; "Globex International
  // Ltd." → "Globex International").
  const base = trimEnd(party.name, /[\s.,;]/);
  const short = base.replace(
    // Bounded leading separator (`{1,8}`, not `+`): a `[\s,]+…$` trim backtracks
    // O(n²) on a long comma/whitespace run that does not reach the suffix (a
    // ReDoS on a hostile party name); no real name has > 8 separator chars
    // before its corporate suffix, so this is byte-identical and now linear.
    /[\s,]{1,8}(?:Corp|Corporation|Inc|LLC|L\.L\.C\.|Ltd|Limited|Co|Company|GmbH|AG|PLC|LP|LLP|PLLC)\b\.?$/i,
    "",
  );
  if (short && short !== base && /\s/.test(base)) {
    add(short);
    const firstWord = short.split(/\s+/)[0];
    if (firstWord && firstWord.length >= 3) add(firstWord);
  }
  // All-caps variant ("ACME") when the name is mixed-case single-token-ish.
  const upper = party.name.toUpperCase();
  if (upper !== party.name && party.name.length <= 24) add(upper);
  return out;
}

/** A trailing defined-role parenthetical: `Alex Smith ("Employee")`. */
const ROLE_PAREN = /\(\s*["“”']([^"”'’)]+)["“”']\s*\)\s*$/;

/**
 * Words that mark a descriptive phrase as naming a PARTY rather than an
 * instrument — "the individual or entity accepting this EULA" versus "any
 * Statement of Work".
 */
const PARTY_DESCRIPTOR =
  /\b(?:individual|entity|person|persons|company|corporation|partnership|party|parties|undersigned|customer|client|purchaser|buyer|seller|licensee|licensor|employee|contractor|subscriber|user)\b/i;

/**
 * Split a preamble party phrase into its name and its defined role.
 *
 * `PARTY_DECL` already captures the role for entities, because it anchors on an
 * entity-type suffix ("a Delaware corporation"). A natural person has no such
 * suffix, so `Alex Smith ("Employee")` only ever reached the `between` path,
 * which kept the whole parenthetical inside the name — yielding a party literally
 * named `Alex Smith ("Employee")` and losing the role that identifies them.
 */
function splitNameAndRole(raw: string): { name: string; role?: string } {
  const trimmed = raw.trim();
  const m = ROLE_PAREN.exec(trimmed);
  if (!m) return { name: cleanPartyName(trimmed) };
  const role = m[1]?.trim();
  const name = cleanPartyName(trimmed.slice(0, m.index));
  // A counterparty is often identified ONLY by role, with no usable name —
  // `… and the individual or entity accepting this EULA ("End User")`. The
  // descriptive phrase is not a name (cleanPartyName rejects it), but the
  // document plainly does name that party: "End User". Dropping the whole
  // party left its role looking like an undefined term to STRUCT-006 and left
  // its obligations unattributable.
  //
  // The phrase must actually DESCRIBE A PARTY, though. `between` also matches
  // ordinary prose about documents — "any conflict between this MSA and any
  // Statement of Work ("SOW")" — and taking the parenthetical there invents a
  // party named "SOW", which then skews every rule that tallies by party.
  if (!name && role && PARTY_DESCRIPTOR.test(trimmed)) return { name: role, role };
  return { name, ...(role ? { role } : {}) };
}

function cleanPartyName(raw: string): string {
  let n = trimEdges(raw.trim(), /["“”'’\s]/);
  // Strip a role label the preamble put in FRONT of the legal name.
  n = n.replace(LEADING_ROLE, "");
  // Strip trailing entity descriptor like ", a Delaware corporation".
  n = n.replace(/,\s*(?:a|an)\s+.+$/i, "");
  n = trimEnd(n, /[.,;]/);
  if (n.length < 2 || n.length > 80) return "";
  if (!/[A-Z]/.test(n.charAt(0))) return "";
  return n;
}

function isBoilerplateName(name: string): boolean {
  const lower = name.toLowerCase();
  return (
    lower === "agreement" ||
    lower === "parties" ||
    lower === "preamble" ||
    lower.startsWith("the agreement") ||
    lower === "effective date"
  );
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
