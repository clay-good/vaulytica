import type { Rule, RuleContext, Finding } from "../../finding.js";
import { makeFinding } from "../../finding.js";
import { forEachParagraph } from "../../../extract/walk.js";

/**
 * STRUCT-013 — Unfilled template placeholders (critical).
 *
 * Catches the most common drafting accident: a templated bracket
 * survived into the final document. Patterns flagged:
 *
 *   - `[insert <anything>]`
 *   - `[<anything> name]` ("[Counterparty name]", "[Customer Name]")
 *   - `[TBD]`, `[TBA]`, `[REDACTED]`, `[PENDING]`
 *   - Bare underscore runs `____________` of three or more (signature
 *     blanks are usually longer than 10, but anything three-plus is a
 *     placeholder candidate)
 *   - `<<...>>` and `{{...}}` mustache-style placeholders
 *   - `XXX` / `XXXX` of three or more uppercase Xs
 *
 * These patterns are intentionally narrow — a bare bracketed quotation
 * like `[1]` or `[note]` is not flagged, and `[and]` mid-sentence is
 * not flagged. False positives are avoided by requiring either an
 * uppercase Title-Case word, "insert", a "TBD"-family token, or a
 * multi-character placeholder marker.
 *
 * Cites: standard contract-drafting hygiene; no external statute.
 */

/**
 * Common field-label suffixes inside bracketed placeholders. Catching
 * `[Premises Address]`, `[Effective Date]`, `[Customer Number]`,
 * `[Lease Term]` — bracket-wrapped fields that drafters routinely
 * leave for an electronic-signature workflow to fill in but that may
 * still ship as bracketed text. Avoids `[See Section 5.1]` and
 * similar legitimate bracket usages by requiring all words inside the
 * brackets be Title-Case alphabetic.
 */
const FIELD_LABEL_SUFFIXES =
  "Name|Date|Address|City|State|Zip|Country|Title|Code|Number|Amount|Value|Reference|Period|Term|Field|ID|Information|Details|Info|Description|Phone|Email|Sum|Fee|Rate|Price";

/**
 * The ALL-CAPS field placeholders a template ships. The bracket patterns above
 * assume Title-Case ("[Effective Date]"), so an all-caps template field
 * ("[DATE]", "[COMPANY NAME]", "[CUSTOMER NAME]") — every bit as common —
 * slipped through. Anchored to the WHOLE bracket content and restricted to a
 * closed vocabulary of unambiguous field words, so a bracketed acronym or list
 * marker ("[EU]", "[SIC]", "[A]", "[IV]", "[EXHIBIT A]") is never mistaken for
 * one.
 */
const ALLCAPS_FIELD_PLACEHOLDER =
  "NAME|DATE|ADDRESS|CITY|STATE|ZIP|COUNTRY|AMOUNT|COMPANY|CUSTOMER|CLIENT|VENDOR|EMAIL|PHONE|PRICE|EFFECTIVE\\s+DATE|COMPANY\\s+NAME|CUSTOMER\\s+NAME|CLIENT\\s+NAME|COUNTERPARTY\\s+NAME|PARTY\\s+NAME|LEGAL\\s+NAME";

const PATTERNS: Array<{ re: RegExp; label: string }> = [
  { re: /\[insert[^\]]{0,80}\]/gi, label: "[insert …] placeholder" },
  { re: /\[[A-Z][A-Za-z\s/&'’-]{1,60}\s+[Nn]ame\]/g, label: "[Title-Case name] placeholder" },
  {
    re: new RegExp(
      `\\[[A-Z][a-zA-Z]+(?:\\s+[A-Z][a-zA-Z]+){0,3}\\s+(?:${FIELD_LABEL_SUFFIXES})\\]`,
      "g",
    ),
    label: "[Field Name] bracketed placeholder",
  },
  {
    re: new RegExp(`\\[(?:${ALLCAPS_FIELD_PLACEHOLDER})\\]`, "g"),
    label: "[FIELD] placeholder",
  },
  // A bracket wrapping only a fill-in blank ("[___]", "[ __ ]") or a lone
  // bullet glyph ("[●]", "[•]") is never a legitimate reference — a draft left
  // the reader a hole to fill. Bare "[ ]" / "[5.1]" / "[A]" are untouched.
  { re: /\[[ \t]*_+[ \t_]*\]/g, label: "[___] fill-in blank" },
  { re: /\[[ \t]*[•●◦‣⁃∙][ \t]*\]/g, label: "[•] placeholder" },
  {
    re: /\[(?:TBD|TBA|REDACTED|PENDING|PLACEHOLDER|FILL\s*IN|TODO)\b[^\]]{0,60}\]/gi,
    label: "[TBD]-family placeholder",
  },
  { re: /\{\{[^}]{1,80}\}\}/g, label: "{{mustache}} placeholder" },
  { re: /<<[^>]{1,80}>>/g, label: "<<placeholder>>" },
  { re: /\bX{3,}\b/g, label: "XXX placeholder" },
  { re: /_{10,}/g, label: "underscore-line placeholder" },
];

export const rule: Rule = {
  id: "STRUCT-013",
  version: "1.10.0",
  name: "Unfilled template placeholders",
  category: "structural",
  default_severity: "critical",
  description:
    "Flags bracketed / mustache / XXX / underscore-line placeholders that survived from the template into the signed document.",
  dkb_citations: [],

  check(ctx: RuleContext): Finding | null {
    type Hit = { raw: string; label: string; sectionId: string; start: number; end: number };
    const hits: Hit[] = [];
    // The printed names of the signatories. A personal / estate instrument
    // (prenup, will, affidavit, POA) signs with a bare name — "____ Alexandra
    // Reyes" — not the "By:/Name:/Title:" grid, so those underscore rules read
    // as placeholders unless the printed party name (or a notary / witness
    // line) is recognized as a signature affordance.
    const partyNames = ctx.extracted.parties
      .map((p) => p.name)
      .filter((n): n is string => typeof n === "string" && n.trim().length >= 4);
    forEachParagraph(ctx.tree, (p) => {
      for (const { re, label } of PATTERNS) {
        re.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = re.exec(p.text)) !== null) {
          // Skip underscore runs that are part of a signature-line
          // context (the "By: ____ Name: ____ Title: ____ Date: ____"
          // grid that electronic-signature platforms render). Those
          // aren't unfilled template placeholders — they're signature
          // affordances. The original heuristic mis-classified them as
          // critical placeholder findings on every contract.
          if (
            label === "underscore-line placeholder" &&
            (isSignatureContext(p.text) || isBareNameSignature(p.text, partyNames))
          ) {
            continue;
          }
          hits.push({
            raw: m[0],
            label,
            sectionId: p.section.id,
            start: p.start + m.index,
            end: p.start + m.index + m[0].length,
          });
        }
      }
    });
    if (hits.length === 0) return null;
    const first = hits[0]!;
    const list = hits
      .slice(0, 6)
      .map((h) => `"${h.raw}"`)
      .join(", ");
    const extra = hits.length > 6 ? `, …(${hits.length - 6} more)` : "";
    return makeFinding({
      rule,
      title: `Unfilled template placeholders: ${hits.length}`,
      description: `Found ${hits.length} placeholder${hits.length === 1 ? "" : "s"} that look${hits.length === 1 ? "s" : ""} like unfilled template content: ${list}${extra}.`,
      excerptText: first.raw,
      explanation:
        "A bracketed placeholder, mustache token, or XXX run that survived into the final document is almost always a drafting accident — the contract is meant to be filled in. A placeholder where a counterparty name belongs makes the agreement legally questionable; a placeholder elsewhere makes the agreement embarrassing.",
      recommendation:
        "Replace every flagged placeholder with the intended content, or remove the bracket if the content is no longer needed.",
      position: { section_id: first.sectionId, start: first.start, end: first.end },
      source_citations: [],
    });
  },
};

/**
 * A signature line that names its signatory by office rather than by a
 * "By:/Name:/Title:" grid — "____________  Jordan Ellis, Director",
 * "/s/ Morgan Lee, Chief Financial Officer". Board / member / partner
 * consents, resolutions, and certificates sign this way: an underscore rule
 * (or `/s/`) followed by a person's name and a signatory office. The blank is
 * a place to sign, not an unfilled template field. Anchoring on an underscore
 * run + name + office keeps this off an inline prose blank.
 */
const SIGNATURE_LINE_BY_OFFICE =
  /(?:_{4,}|\/s\/)\s*(?:\/s\/\s*)?[A-Z][A-Za-z.'’-]+(?:\s+[A-Z][A-Za-z.'’-]+){0,3},?\s+(?:Director|President|Vice\s+President|Secretary|Treasurer|Chief\s+[A-Za-z]+\s+Officer|CEO|CFO|COO|CTO|Manager|Managing\s+Member|Member|Trustee|Grantor|Settlor|General\s+Partner|Partner|(?:Sole\s+)?Incorporator|Testat(?:or|rix)|Principal|Execut(?:or|rix)|Personal\s+Representative|Attorney-in-Fact|Patient|Participant|Authorized\s+Signatory|Its\b)\b/;

// A signatory office that stands alone on a signature line, no personal name
// attached — "____ Notary Public", "____ Witness". These are signature
// affordances in wills, affidavits, and acknowledgments.
const STANDALONE_SIGNATORY_ROLE =
  /\b(?:Notary\s+Public|Notary|Witness|Affiant|Declarant|Grantor|Settlor|Trustee|Testat(?:or|rix)|Execut(?:or|rix)|Personal\s+Representative|Attorney-in-Fact|Patient|Participant)\b/i;

/**
 * True if an underscore-line paragraph is a bare-name signature line: an
 * underscore rule followed by the printed name of a known signatory party
 * ("____ Alexandra Reyes") or a standalone signatory role ("____ Notary
 * Public"). Requiring an actual extracted party name (or an explicit role)
 * keeps this off a genuine "____ [Insert Party Name]" placeholder, whose text
 * is not a party the document defines.
 */
function isBareNameSignature(text: string, partyNames: string[]): boolean {
  if (!/_{6,}/.test(text)) return false;
  const after = text.replace(/_{6,}/g, " ").replace(/\/s\//g, " ").trim();
  if (!after) return false;
  if (STANDALONE_SIGNATORY_ROLE.test(after)) return true;
  // A signature line labeled by role beneath the rule — "____ Signature of
  // Subject", "____ Signed by Applicant", "____ Print Name of Witness" — as a
  // consent form, affidavit, or application signs. A genuine "[Insert
  // Signature]" placeholder starts with the bracket / "Insert", not the label.
  if (/^(?:signature|signed|print(?:ed)?\s+name)\s+(?:of|by)\b/i.test(after)) return true;
  // A bare underscore rule beneath a printed personal name — "________ Jonathan
  // Pierce" — is a signature line even when that individual is named only in the
  // signature block: a multi-signatory operating agreement, member/partner
  // consent, or deed lists its signatories here, not as defined parties, so the
  // party-name anchor below never sees them. Require the remainder to be a clean
  // 2–4-word personal name (each word Title-Case, no field-label / template
  // token) so a genuine "____ [Party Name]" / "____ Company Name" / "____ Print
  // Name" placeholder is not suppressed.
  if (isPersonalName(after)) return true;
  const lower = after.toLowerCase();
  return partyNames.some((n) => {
    // A party is often extracted with its role parenthetical attached —
    // 'Karen Whitfield (the "Petitioner")'. The printed signature line is the
    // bare name, so compare against the name before the "(".
    const nl = n
      .toLowerCase()
      .replace(/\s*\(.*$/, "")
      .trim();
    if (nl.length < 4) return false;
    return lower === nl || lower.startsWith(`${nl},`) || lower.startsWith(`${nl} `);
  });
}

// A template / field-label token that must NOT appear in a string we would
// accept as a printed personal name — "____ Company Name", "____ Insert Party",
// "____ Print Name" are placeholders, not signatures.
const NON_NAME_TOKEN =
  /\b(?:Name|Date|Address|City|State|Zip|Country|Title|Code|Number|Amount|Value|Reference|Period|Term|Field|Information|Details|Description|Phone|Email|Sum|Fee|Rate|Price|Insert|Sign|Signature|Print(?:ed)?|Company|Corporation|Entity|Party|Here|TBD|TBA)\b/i;

// A professional / courtesy honorific that can precede a printed signatory
// name — "Dr. Helena Vasquez", "Prof. Alan Reyes". Stripped before the
// name test so the title's trailing period does not break the Title-Case run.
const HONORIFIC_PREFIX =
  /^(?:Dr|Mr|Mrs|Ms|Mx|Prof(?:essor)?|Hon|Rev|Sir|Dame|Fr|Sr|Capt|Col|Gen|Lt|Sgt|Rabbi|Pastor|Judge)\.?\s+/i;

/**
 * True if `s` is a bare printed personal name — 2–4 Title-Case words, each with
 * a lowercase tail (so ALLCAPS markers like "TBD"/"XXX" are excluded), and no
 * field-label / template token. A trailing ", Role" clause is dropped first
 * ("Jonathan Pierce, Manager"), and a leading honorific ("Dr.") is stripped,
 * leaving the name to test.
 */
function isPersonalName(s: string): boolean {
  const t = s.replace(/,.*$/, "").trim().replace(HONORIFIC_PREFIX, "");
  if (NON_NAME_TOKEN.test(t)) return false;
  return /^[A-Z][a-z]+(?:\s+[A-Z][a-z.'’-]+){1,3}$/.test(t);
}

/**
 * True if the paragraph text looks like a signature-block context.
 * Triggered by ≥2 of (By, Name, Title, Date, Signature, Signed) in
 * the same paragraph, the paragraph being formatted as a table-row
 * "By: __ | Name: __ | Title: __ | Date: __" line, OR a signature line
 * that names its signatory by office ("____ Jordan Ellis, Director").
 */
function isSignatureContext(text: string): boolean {
  if (SIGNATURE_LINE_BY_OFFICE.test(text)) return true;
  const tokens = (
    text.match(
      /\b(By|Name|Title|Date|Signature|Signed|Print(?:ed)?\s+Name|Authorized\s+Signatory)\b\s*:?/gi,
    ) ?? []
  ).length;
  return tokens >= 2;
}
