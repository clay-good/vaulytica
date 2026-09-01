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
  // The CANONICAL capitalizations of the abbreviations, added exactly (not by
  // making the whole alternation case-insensitive — the name capture is
  // anchored on `[A-Z]`, and under `i` that matches lower-case and starts
  // manufacturing parties out of ordinary prose). Without these, a party named
  // the way American contracts actually name one — "Harbor Point Ventures LLC
  // (the \"Company\")" — was invisible to this path, and the role it declares
  // in the same breath was lost with it.
  "LLC",
  "L\\.L\\.C\\.",
  "LLP",
  "PLLC",
  "gmbh",
  "ag",
  "plc",
  // The rest of the canonical capitalizations — the ones an American legal
  // name is actually written with. The LLC family was added when a party
  // named "Harbor Point Ventures LLC" turned out to be invisible here, but
  // the far commoner suffixes were left in their lower-case-only form, so
  // 'Vertex Systems, Inc. ("Vendor")' was invisible in exactly the same way:
  // `inc\.?` never matched "Inc." at all, this pattern being case-SENSITIVE
  // by design. The party and — worse — the role it declares in the same
  // breath were both lost, and a party with no role is invisible to every
  // rule that compares an obligor against the party set. The only reason it
  // ever appeared to work is the descriptive appositive: "…, Inc., a Delaware
  // CORPORATION" matched on the lower-case long form. Drop the appositive, as
  // a short-form agreement does, and the document reported no parties.
  // "Corp." was missing in BOTH cases — the list has never held any form of
  // it, only the spelled-out "corporation".
  // ONLY the abbreviations are added in title case. The title-case LONG forms
  // are not legal-name suffixes so much as DEFINED TERMS and STATUTE NAMES:
  // bylaws say "the Corporation" in every section and an operating agreement
  // says "the Company", which sentence-initially reads as the name "The"
  // followed by an entity type (the probe duly manufactured parties named
  // "The" and "Each Parent"); and "the Delaware LIMITED LIABILITY COMPANY Act,
  // 6 Del. C. § 18-101" — the citation every Delaware operating agreement
  // carries in its formation section — manufactured a party named "Delaware",
  // which then stood beside the real member and made RISK-002 read the
  // indemnity as one-sided. The abbreviations carry no such double life.
  // Written WITHOUT the abbreviation period, unlike their lower-case twins.
  // The period after "Inc" is also a sentence period, and consuming it here
  // blinds the role gap's abbreviation guard — the one that refuses to cross
  // "…and Beta Corp. The Services are described in Exhibit A (\"Services\")"
  // and hand Beta the role "Services". Leaving the period in the text lets
  // that guard read it: a period followed by a capital ends the clause, a
  // period followed by anything else is an abbreviation and is stepped over.
  "Inc",
  "Corp",
  "corp",
  "Ltd",
  // And the ALL-CAPS forms, for the instrument set in capitals from the
  // caption to the signature. `BETWEEN_RE` reads such a preamble's NAMES, but
  // its second capture terminates at the first sentence period — which is the
  // one inside "INC." — so the second party's role parenthetical fell outside
  // the capture and the party was registered roleless. In mixed case
  // `PARTY_DECL` supplies that role from the same sentence; in capitals it
  // could not see the suffix at all.
  "INC",
  "CORP",
  "LTD",
  "L\\.P\\.",
  "LP",
  "GmbH",
  "PLC",
];

const US_STATE =
  "(?:Alabama|Alaska|Arizona|Arkansas|California|Colorado|Connecticut|Delaware|Florida|Georgia|Hawaii|Idaho|Illinois|Indiana|Iowa|Kansas|Kentucky|Louisiana|Maine|Maryland|Massachusetts|Michigan|Minnesota|Mississippi|Missouri|Montana|Nebraska|Nevada|New Hampshire|New Jersey|New Mexico|New York|North Carolina|North Dakota|Ohio|Oklahoma|Oregon|Pennsylvania|Rhode Island|South Carolina|South Dakota|Tennessee|Texas|Utah|Vermont|Virginia|Washington|West Virginia|Wisconsin|Wyoming|District of Columbia|D\\.C\\.)";

// `g` only (not `gi`) — the case-insensitive flag would defeat the
// capitalized-word name pattern and let the engine slurp lowercase
// connectives like `is`, `made`, `between`, `and` into the captured
// name. Entity-type tokens in the text are lowercase by convention
// ("a Delaware corporation"); the `ENTITY_TYPES` list mirrors that.
/**
 * The adjectives that may sit between the formation state and the entity type
 * — "a Pennsylvania NONPROFIT corporation", "a Delaware PUBLIC BENEFIT
 * corporation". A closed vocabulary, not "any lower-case word": an open run
 * bridges a name to an unrelated type straight across the verb, and
 * "Nothing in this Agreement creates a partnership between Acme and Globex"
 * then manufactures parties out of a sentence written to deny the
 * relationship.
 */
/**
 * An entity suffix immediately followed by a comma ENDS a name. The name run
 * admits commas and periods inside a token so "Acme Widgets, Inc." and
 * "Skadden, Arps, Slate, Meagher & Flom LLP" stay whole — but once the type
 * has been written the next comma separates two DIFFERENT parties, and the run
 * walked straight through it: an "among" preamble listing "Acme Inc., Beta
 * LLC, and Gamma Ltd." produced a party named "Acme Inc., Beta". Written in
 * both cases — including the ALL-CAPS one, where the case-mixed entries
 * ("[Cc]orp", "[Ll]td") silently did not apply and an "among" list of three
 * uppercase parties yielded a fourth named "BETA CORP., AND GAMMA".
 */
const ENTITY_SUFFIX_BEFORE_COMMA = String.raw`\b(?:[Ii][Nn][Cc]|[Ll][Ll][Cc]|L\.L\.C|[Ll][Tt][Dd]|[Cc][Oo][Rr][Pp]|[Ll][Ll][Pp]|L\.L\.P|LLLP|LP|L\.P|[Pp][Ll][Ll][Cc]|P\.C|PC|N\.A|S\.A|[Cc][Oo])\.?,`;

const ENTITY_QUALIFIERS =
  "(?:non-?profit|not-for-profit|limited|liability|professional|public|benefit|close|mutual|general|private|registered|statutory|business|cooperative|stock|joint|domestic|foreign|municipal|charitable)";

const PARTY_DECL = new RegExp(
  // Each name token is BOUNDED (`{0,80}`, not `*`): the name is followed by a
  // REQUIRED entity-type suffix, so an unbounded token matches a long letter
  // run, fails to find the suffix, and backtracks the run from every start
  // position — O(n²) on a hostile uppercase run (a ReDoS hang, spec-v8 §5). No
  // real name token exceeds 80 chars, so this is byte-identical and now linear.
  // A name may not begin immediately after the indefinite article, and a firm
  // name is joined by an AMPERSAND. Both guard the qualifier run below: it
  // admits "a Pennsylvania NONPROFIT corporation" and "a Pennsylvania LIMITED
  // LIABILITY partnership", which the state slot alone could not hold — so
  // neither party of an owner-architect agreement carried a role, and a role
  // is what every rule comparing an obligor to the party set matches on. But
  // without the article guard the same run let a match START at a nationality
  // adjective ("Stark Cloud Ireland Ltd., an IRISH private limited company"
  // registered a party named "Irish"), and without the ampersand the run broke
  // at the "&" ("Vessel & Roark Architects LLP" registered twice, once as
  // "Roark Architects LLP"). The article guard is written in BOTH cases and on
  // BOTH sides of the name's first character: a cover block sets the entity
  // descriptor on its own line — "Alderbrook Instruments, Inc." over "A
  // Delaware corporation" — where the article is capitalized and is itself the
  // first thing the name run can anchor on, so a lower-case-only look-BEHIND
  // let the whole descriptor through and registered a party named "A
  // Delaware". No legal name opens with an indefinite article — nor CONTAINS
  // one as a whole token, which is the same guard one token to the right:
  // `ingestPaste` joins a block's lines with SPACES, so that cover block
  // arrives as "Alderbrook Instruments, Inc. A Delaware corporation Adopted by
  // the Board …" and the name run walked from the legal name straight through
  // the article into the descriptor. The article SEPARATING the name from its
  // descriptor is matched in both cases for the same reason — on its own line
  // the descriptor is capitalized, and reading "Pemberton Ridge Land
  // Conservancy / A Colorado nonprofit corporation" as a party is the whole
  // point of the pattern. A capitalized article only ever precedes a real
  // entity descriptor here, because the state, the qualifiers and the type
  // that follow it are all closed vocabularies.
  // The entity-type group needs a non-letter boundary on BOTH sides. Without a
  // trailing one the short types match the START of ordinary words — `inc` in
  // "including", `ag` in "agreement". Without a leading one they match the END
  // of a longer word: `corporation` sits inside "In·corporation", so a heading
  // "EU SCC Incorporation" yielded the party "EU SCC In". Either way a junk
  // name is manufactured, and it is not harmless — rules that compare a phrase
  // against the party set (STRUCT-006) treat it as real and party-tallying
  // rules (RISK-002) report counts against it.
  String.raw`(?<!\b(?:[Aa]|[Aa][Nn])\s)(?![Aa]n?\s)([A-Z][\w&.,'’-]{0,80}(?:(?<!${ENTITY_SUFFIX_BEFORE_COMMA})\s+(?:&\s+)?(?![Aa]n?\s)[A-Z][\w&.,'’-]{0,80}){0,6})\s*,?\s*(?:[Aa]n?)?\s*(?:(${US_STATE})\s+)?(?:${ENTITY_QUALIFIERS}\s+){0,3}(?<![A-Za-z])(${ENTITY_TYPES.join("|")})(?![A-Za-z])` +
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
    // The parenthetical usually carries an ARTICLE before the quoted role —
    // `(the "Company")`, `(collectively, "Sellers")` — and requiring the quote
    // to open the parenthesis dropped the role on the most common form there
    // is.
    // The gap and the parenthetical are ONE optional group: with the gap
    // optional and non-greedy on its own, the engine always matched it empty
    // and the role was never reached.
    String.raw`(?:(?:\.(?!\s+[A-Z]))?\s*(?:(?!\band\b)[^.;()]){0,120}?\s*\(\s*(?:(?:the|each|collectively(?:,)?|together|individually)\s+){0,2}["“”']([^"”'’\)]+)["“”']\s*\))?`,
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
/**
 * The terminator comma must not fire INSIDE a parenthetical. A collective role
 * is written with one — `and the party purchasing the Shares (each, a
 * "Purchaser")` — and the capture stopped at it, losing the role and with it
 * the only handle a descriptor-named party has.
 *
 * `(?![^()]*\))` reads: from here, a ")" is not reachable without crossing a
 * paren. Inside a parenthetical the next paren character IS ")", so the
 * lookahead fails and the comma is passed over; outside one it is "(" (or
 * there is none), so the comma terminates as before.
 */
const BETWEEN_RE = new RegExp(
  String.raw`\bbetween\s+(.+?)\s+and\s+(.+?)(?:[.;]|,(?!\s*(?:${LEGAL_SUFFIX})(?![A-Za-z]))(?![^()]*\))|$)`,
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

/**
 * The instrument's own title, where a cover block puts it in front of the
 * party's name: "OPERATING AGREEMENT OF Harbor Point Ventures LLC", "DEED OF
 * TRUST OF ...". Anchored at the start of the captured name and requiring the
 * "of", so an entity whose name merely contains one of these words is
 * untouched.
 */
const TITLE_BEFORE_NAME = new RegExp(
  String.raw`^(?:this\s+)?(?:[A-Za-z]+\s+){0,2}${INSTRUMENT}\s+of\s+`,
  "i",
);

/**
 * The preamble's own lead-in, where an ALL-CAPS instrument puts it in front of
 * the party's name. `PARTY_DECL` tells a name from prose by capitalization, and
 * an all-caps preamble offers no contrast at all: every word of "THIS AGREEMENT
 * IS ENTERED INTO BY AND BETWEEN VERTEX SYSTEMS LLC" starts with a capital, so
 * the name run walked back through the whole lead-in and registered a party
 * named "ENTERED INTO BY AND BETWEEN VERTEX SYSTEMS" — with the real party's
 * role attached, standing beside the real party that `BETWEEN_RE` reads from
 * the same sentence. Two parties became four, and every rule that tallies by
 * party (RISK-002, STRUCT-017, OBLI-002) counted the phantoms.
 *
 * Stripped only from the FRONT of the captured name, and only as whole words
 * followed by a space, so a name that CONTAINS one of these words keeps it
 * ("SMITH AND WESSON", "BANK OF AMERICA") and a name that merely starts with
 * the same letters is untouched ("AT&T" is not "AT ").
 */
const PREAMBLE_LEADIN_BEFORE_NAME = new RegExp(
  String.raw`^(?:(?:this|that|the|and|or|by|between|among|with|is|are|be|made|make|entered|enter|into|dated|as|of|effective|on|hereby|witnesseth|now|therefore|whereas|to|for|in|at|it|${INSTRUMENT})\s+)+`,
  "i",
);

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
 * A TITLE that shares the preamble's paragraph.
 *
 * A flat paste — a PDF copy, a blank-line-stripped export — merges the title
 * line into the paragraph below it, so "This Lease is between Landlord …" no
 * longer STARTS the paragraph and `PREAMBLE_LEAD`'s start anchor fails. Every
 * party in the document was lost with it: a triple net lease whose parties
 * extract cleanly in the normal layout extracted NONE once its blank lines
 * were stripped.
 *
 * Case-SENSITIVE by design, and deliberately not folded into `PREAMBLE_LEAD`,
 * which carries the `i` flag: a title is capitalized, and the run must stop at
 * the first lowercase word. That is what keeps an ordinary sentence —
 * "Landlord shall provide notice of the difference and the amount is …" — from
 * reading as a title followed by a preamble.
 */
const TITLE_BEFORE_PREAMBLE = /^(?:[A-Z(][^\s.;]*\s+){1,12}(?=(?:This|The)\s)/;

/** `PREAMBLE_LEAD`, tolerating a title line merged in front of the preamble. */
/**
 * The lead-ins that only a PREAMBLE carries. `PREAMBLE_LEAD` also accepts a
 * bare instrument noun ("Agreement between …"), which a document title carries
 * too, so the two are distinguished here rather than conflated.
 */
const STRONG_PREAMBLE_LEAD = new RegExp(
  "(?:" +
    String.raw`\bby\s+and\s+` +
    "|" +
    String.raw`(?:^|[.;]\s)\s*(?:this|the)\s+${SAME_SENTENCE}{0,80}\b(?:is|are|was|were)\s+` +
    "|" +
    String.raw`\b(?:made|entered\s+into|executed|dated|effective)\b${SAME_SENTENCE}{0,160}` +
    ")$",
  "i",
);

/**
 * A standalone document title: a short line, no terminal sentence punctuation,
 * and no lower-case sentence body — either ALL CAPS or Title Case.
 */
function isDocumentTitleLine(text: string): boolean {
  const line = text.trim();
  if (line.length === 0 || line.length > 120) return false;
  if (/[.;:!?]$/.test(line)) return false;
  const letters = line.replace(/[^A-Za-z]/g, "");
  if (letters.length === 0) return false;
  const allCaps = letters === letters.toUpperCase();
  const titleCase = line
    .split(/\s+/)
    .every((w) => !/^[a-z]/.test(w) || TITLE_CASE_MINOR_WORD.test(w));
  return allCaps || titleCase;
}

/** The words a Title Case line is allowed to leave lower-case. */
const TITLE_CASE_MINOR_WORD =
  /^(?:a|an|the|and|or|nor|but|for|of|to|in|on|at|by|with|from|as|per)$/i;

function hasPreambleLead(lead: string): boolean {
  if (PREAMBLE_LEAD.test(lead)) return true;
  const withoutTitle = lead.replace(TITLE_BEFORE_PREAMBLE, "");
  return withoutTitle !== lead && PREAMBLE_LEAD.test(withoutTitle);
}

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
  String.raw`(?:^|(?<=[\s\n]))(${PARTY_ROLE_LABEL})\s*:\s*(?!\s)([A-Z](?:[^\n,;.]|\.(?!\s|$)|\.(?=\s+[A-Z])){2,80})`,
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
// The CONVEYANCE, TENANCY, and EMPLOYMENT pairs belong here by the same test
// the paragraph above states: a seller is never also the buyer, a landlord
// never also the tenant. They were missing, and the form that names parties
// this way is not a rarity — a Texas One to Four Family Residential Contract
// opens "The seller, Thomas Aurelio Harper and Eleanor Marguerite Harper (the
// \"Seller\"), agrees to sell and convey to the buyer, Nadia Harper Okonkwo
// (the \"Buyer\")", which is a numbered PARTIES section rather than a
// "between" preamble. It reported STRUCT-001 "No parties identified" about a
// contract whose first numbered paragraph is headed PARTIES.
//
// Licensor / Licensee and Discloser / Recipient stay OUT: a cross-licence and
// a mutual NDA put both parties in both roles, and surfacing one of them as a
// single party would make OBLI-002 read a role-stated mutual obligation as
// one-sided.
const ONE_SIDED_ROLE = String.raw`Guarantor|Grantor|Grantee|Settlor|Trustor|Trustee|Beneficiary|Debtor|Secured\s+Party|Creditor|Mortgagor|Mortgagee|Pledgor|Pledgee|Assignor|Assignee|Surety|Maker|Payee|Borrower|Lender|Insured|Insurer|Named\s+Insured|Indemnitor|Indemnitee|Principal|Attorney-in-Fact|Agent|Seller|Buyer|Purchaser|Landlord|Tenant|Lessor|Lessee|Sublessor|Sublessee|Sublandlord|Subtenant|Franchisor|Franchisee|Employer|Employee`;
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
/**
 * A disclaimer of the relationship, tested against everything before the
 * candidate name. `NEGATED_PREAMBLE` is the same idea for `BETWEEN_RE`, but it
 * deliberately refuses to cross the word "between" — there the lead ends
 * before it. Here the names sit AFTER the connective, so the lead contains it.
 */
const DISCLAIMED_RELATIONSHIP =
  /\b(?:not|no|nothing|never|neither)\b[^.;\n]{0,120}?\b(?:constitute|create|form|imply|establish|give\s+rise\s+to|amount\s+to)\w*/i;

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

/**
 * The first-person self-declaration that opens a PERSONAL INSTRUMENT.
 *
 * "I, Eleanor Marguerite Harper, of 412 Sycamore Lane, Columbus, Ohio, being
 * of sound mind and memory, make, publish, and declare this to be my Last Will
 * and Testament." Every will, codicil, affidavit, declaration under penalty of
 * perjury, power of attorney, self-proving affidavit, and acknowledgment opens
 * this way, and the extractor recognized none of them: a document with one
 * party and no "between" reported **no party at all**.
 *
 * The consequence is not a missing row in a table. STRUCT-006 subtracts the
 * PARTY NAMES from its undefined-Title-Case candidates, so a well-drafted will
 * was told that its executor and its residuary beneficiary — "Thomas Aurelio
 * Harper", "Nadia Harper Okonkwo" — are terms it forgot to define. Every rule
 * that reasons about who the parties are was reading an empty list.
 *
 * The declaration VERB is required, and the list is the operative-language
 * one: an "I" that merely narrates ("I understand that…", "I have reviewed…")
 * is not a party declaration. The name is bounded to four words and must be
 * Title-Case, and the address clause that usually follows is skipped by
 * allowing an "of …" run before the verb.
 */
const SELF_DECLARATION_VERB = String.raw`make|makes|made|publish|declare|declares|hereby\s+declare|revoke|nominate|appoint|constitute|give|devise|bequeath|certify|state|depose|swear|affirm|acknowledge|being\s+(?:first\s+)?duly\s+sworn|being\s+of\s+sound\s+mind`;
const SELF_DECLARATION = new RegExp(
  String.raw`(?:^|[.;]\s+)I,\s+([A-Z][\w.'’-]*(?:\s+[A-Z][\w.'’-]*){1,3}),` +
    String.raw`(?:[^.;]{0,240}?)\b(?:${SELF_DECLARATION_VERB})\b`,
  "m",
);

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
      // A COVER BLOCK opens with the instrument's own title, and the name
      // run walks straight through it: "OPERATING AGREEMENT OF HARBOR POINT
      // VENTURES LLC / a Delaware limited liability company" registered a
      // party literally named "OPERATING AGREEMENT OF HARBOR POINT VENTURES
      // LLC" — which then stood beside the real party and made RISK-002 read
      // the indemnity as running one way.
      const name = cleanPartyName(
        (m[1] ?? "").replace(TITLE_BEFORE_NAME, "").replace(PREAMBLE_LEADIN_BEFORE_NAME, ""),
      );
      const state = m[2];
      const entity = m[3];
      const role = m[4];
      if (!name || isBoilerplateName(name)) continue;
      // A DISCLAIMED relationship names the entities precisely to say they are
      // NOT in one: "Nothing in this Agreement creates a partnership among
      // Acme Corp, Beta LLC, and Gamma Inc." `BETWEEN_RE` has always been
      // guarded this way; this path never was, because it could not read an
      // upper-case entity abbreviation at all and so never reached such a
      // sentence.
      if (DISCLAIMED_RELATIONSHIP.test(text.slice(0, m.index))) continue;
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
      // The pattern needs its `i` flag for the case-varying "d/b/a" marker,
      // which also weakens the capture's leading `[A-Z]` to "any letter" — so
      // "doing business as a regional carrier" would register "a regional
      // carrier" as an operating NAME. Restore the anchor explicitly.
      if (!dba || !/^[A-Z]/.test(dba)) continue;
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
    let weakMatch: RegExpExecArray | null = null;
    // A document TITLE names the two ROLES, never the two parties: "AGREEMENT
    // BETWEEN OWNER AND ARCHITECT FOR DESIGN SERVICES" is the AIA B101 title,
    // and reading it as the party clause registered "OWNER" and "ARCHITECT FOR
    // DESIGN SERVICES" as the contracting entities. A title is a short
    // standalone line closing with no sentence punctuation; a preamble is a
    // sentence and ends in a period, so this cannot swallow one.
    if (isDocumentTitleLine(text)) continue;
    while ((betweenMatch = BETWEEN_RE.exec(text)) !== null) {
      const lead = text.slice(0, betweenMatch.index);
      // A DISCLAIMED relationship is the opposite of a preamble: "THIS
      // CERTIFICATE DOES NOT CONSTITUTE A CONTRACT BETWEEN THE ISSUING
      // INSURER(S) … AND THE CERTIFICATE HOLDER" names the two roles precisely
      // to say they are NOT contracting parties. Reading it as a preamble
      // registered both as parties.
      if (NEGATED_PREAMBLE.test(lead)) continue;
      if (!hasPreambleLead(lead)) continue;
      // A bare INSTRUMENT NOUN before "between" is the shape of a TITLE, and
      // the title is commonly restated at the head of the preamble sentence:
      // "This Agreement Between Owner and Architect (this \"Agreement\") is
      // made as of April 6, 2026 between Harrowgate ... and Vessel & Roark
      // ...". That restatement beat the REAL party clause later in the very
      // same sentence and published a party named 'Architect (this
      // "Agreement") is made as of April 6'.
      //
      // So a weak lead is remembered but not taken: if a later `between` in
      // the paragraph carries a full preamble lead ("by and between", "is made
      // as of ... between"), that one is the party clause. Only when none does
      // is the weak reading used, which is the "This Agreement between X and Y
      // is dated ..." form it was added for.
      if (STRONG_PREAMBLE_LEAD.test(lead)) break;
      if (!weakMatch) weakMatch = betweenMatch;
    }
    if (!betweenMatch) betweenMatch = weakMatch;
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
      if (!hasPreambleLead(lead)) continue;
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
    // The first-person self-declaration a personal instrument opens with, and
    // that a self-proving affidavit repeats at the end — so every paragraph is
    // scanned, not just the preamble window.
    const selfDecl = SELF_DECLARATION.exec(text);
    if (selfDecl) {
      const name = cleanPartyName(selfDecl[1] ?? "");
      if (name && !isBoilerplateName(name)) {
        registerParty(partyMap, name, {
          position: pos(selfDecl.index, selfDecl.index + selfDecl[0].length),
        });
      }
    }
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

  // "Harrowgate Finishing Systems, Inc." and "Harrowgate Finishing Systems"
  // are one party. Two branches captured the preamble name with and without
  // its corporate suffix, and every rule that TALLIES BY PARTY — RISK-002's
  // indemnity symmetry among them — read the bare form as a third party with
  // no obligations. Collapse only when one form carries a suffix and the other
  // carries none; "Acme Holdings, Inc." and "Acme Holdings LLC" stay distinct.
  const byBare = new Map<string, Party>();
  for (const party of partyMap.values()) {
    const bare = bareEntityName(party.name);
    if (bare === party.name.toLowerCase()) continue;
    byBare.set(bare, party);
  }
  for (const [key, party] of [...partyMap.entries()]) {
    const suffixed = byBare.get(key);
    if (!suffixed || suffixed === party) continue;
    suffixed.role = suffixed.role ?? party.role;
    suffixed.entity_type = suffixed.entity_type ?? party.entity_type;
    suffixed.jurisdiction_of_formation =
      suffixed.jurisdiction_of_formation ?? party.jurisdiction_of_formation;
    suffixed.positions.push(...party.positions);
    partyMap.delete(key);
  }

  return [...partyMap.values()];
}

/** The party name with its trailing corporate suffix removed, lower-cased. */
function bareEntityName(name: string): string {
  return name
    .toLowerCase()
    .replace(
      /,?\s+(?:inc|incorporated|llc|l\.l\.c|ltd|limited|corp|corporation|co|company|lp|l\.p|llp|plc|gmbh|pllc|pc|na|n\.a)\.?$/,
      "",
    )
    .trim();
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
/**
 * The quoted role at the END of a preamble party phrase. The article before
 * the quote is the ordinary form and was not admitted, so `and the undersigned
 * subscriber (the "Subscriber")` yielded no party at all: a securities
 * subscription agreement had only one of its two sides, and OBLI-002 reported
 * that only the Company indemnified — in a section where each side indemnifies
 * the other, sentence by sentence.
 */
const ROLE_PAREN =
  /\(\s*(?:(?:the|a|an|each|collectively(?:,)?|together|individually)\s+){0,2}["“”']([^"”'’)]+)["“”']\s*\)\s*[,;]?\s*$/;

/**
 * The COLLECTIVE parenthetical: `Antonia Pike (each, a "Principal" and
 * together, the "Principals")`. `ROLE_PAREN` requires the quoted role to be the
 * whole parenthetical, so this shape fell through to `cleanPartyName`, whose
 * ", a …" descriptor strip cut the phrase mid-parenthesis and registered a
 * party named `Antonia Pike (each`. The role is the FIRST quoted term.
 */
const ROLE_PAREN_COLLECTIVE =
  /\(\s*(?:each|collectively|together)\b[^"“”'’)]{0,20}?["“”'’]([^"”'’)]+)["“”'’]/;

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
  const m = ROLE_PAREN.exec(trimmed) ?? ROLE_PAREN_COLLECTIVE.exec(trimmed);
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
  // A name never carries an UNMATCHED open parenthesis. The descriptor strip
  // above can cut inside a parenthetical it did not open.
  if ((n.match(/\(/g) ?? []).length > (n.match(/\)/g) ?? []).length) {
    n = n.slice(0, n.lastIndexOf("(")).trim();
  }
  n = trimEnd(n, /[.,;]/);
  if (n.length < 2 || n.length > 80) return "";
  if (!/[A-Z]/.test(n.charAt(0))) return "";
  return n;
}

/**
 * A bare DETERMINER is never a party name. The multi-word entity types
 * ("Limited Partnership") can be written sentence-initially about the entity
 * rather than to name it — "The Limited Partnership shall maintain books" —
 * and the name run then captures the article alone.
 */
const DETERMINER_ONLY = /^(?:the|a|an|this|that|each|any|all|such|its|our|their|no)$/i;

function isBoilerplateName(name: string): boolean {
  const lower = name.toLowerCase();
  return (
    DETERMINER_ONLY.test(lower) ||
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
