/**
 * NDA-deep ruleset — 25 rules (spec-v3.md §32 / Step 27).
 *
 * Covers DTSA whistleblower-immunity notice (18 U.S.C. § 1833(b)),
 * confidentiality definition completeness, term separation, return /
 * attestation, injunctive relief, permitted-use scope, governing law,
 * non-solicitation carve-outs, residuals flagging, and the mutual /
 * unilateral symmetry checks called out in §32. Every rule scopes to
 * the NDA-deep playbooks via `applies_to_playbooks`.
 */

import type { Rule } from "../../../finding.js";
import {
  buildNdaCompoundRule,
  buildNdaLanguageRule,
  buildNdaPresenceRule,
  dtsaCite,
  genericNdaCite,
  utsaCite,
  type NdaCompoundSpec,
  type NdaLanguageSpec,
  type NdaPresenceSpec,
} from "./_helpers.js";

const presence = (s: NdaPresenceSpec): Rule => buildNdaPresenceRule(s);
const language = (s: NdaLanguageSpec): Rule => buildNdaLanguageRule(s);
const compound = (s: NdaCompoundSpec): Rule => buildNdaCompoundRule(s);

export const NDA_DEEP_RULES: Rule[] = [
  // ────────────────────────────────────────────────────────────────
  // DTSA notice — 18 U.S.C. § 1833(b)
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "NDA-D-001",
    name: "DTSA whistleblower-immunity notice present",
    description:
      "NDAs with employees, contractors, or consultants must contain the DTSA notice of immunity for confidential disclosure of trade secrets to government or in court filings.",
    citation: dtsaCite(),
    missing_title: "DTSA whistleblower-immunity notice missing",
    missing_description: "No 18 U.S.C. § 1833(b) immunity notice was detected in the agreement.",
    explanation:
      "Under 18 U.S.C. § 1833(b), an employer that does not include the immunity notice in agreements with employees, contractors, or consultants cannot recover exemplary damages or attorneys' fees in a DTSA action against that individual.",
    recommendation:
      "Add the DTSA immunity notice (or cross-reference an HR policy that contains it) covering immunity for disclosure to government officials or in a sealed court filing.",
    present_patterns: [
      /18\s*U\.?S\.?C\.?\s*§?\s*1833/i,
      /(immunity|immune)\s+from\s+liability.{0,80}(trade\s+secret|disclosure)/is,
      /defend\s+trade\s+secrets\s+act/i,
    ],
  }),

  compound({
    id: "NDA-D-002",
    name: "DTSA notice substantively complete",
    description:
      "The DTSA notice must cover (a) immunity, (b) disclosure to a government official or attorney, and (c) sealed court filing — all three elements per § 1833(b).",
    citation: dtsaCite(),
    required_patterns: [
      /(immunity|not\s+be\s+held\s+(criminally\s+or\s+civilly\s+)?liable)/i,
      /(government\s+official|federal,\s+state|attorney|law\s+enforcement)/i,
      /(under\s+seal|sealed\s+filing|sealed\s+court|sealed\s+complaint)/i,
    ],
    min_match: 3,
    missing_title: "DTSA notice is incomplete",
    missing_description:
      "A DTSA-style notice was detected but does not include all three required components (immunity, government / attorney disclosure, and sealed-filing carve-out).",
    explanation:
      "Without the full statutory recital, the employer loses the exemplary damages and attorneys' fees remedy under 18 U.S.C. § 1833(b)(3)(C). Vaulytica looks for: immunity language, a government-official-or-attorney prong, and a sealed-court-filing prong.",
    recommendation:
      "Use the full 18 U.S.C. § 1833(b)(3) statutory notice text verbatim, or paraphrase including all three elements explicitly.",
    default_severity: "critical",
  }),

  // ────────────────────────────────────────────────────────────────
  // Confidentiality term and term separation — §32
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "NDA-D-003",
    name: "Confidentiality term clause present",
    description:
      "NDA must state how long confidentiality obligations endure — either a definite term, perpetual for trade secrets, or both.",
    citation: utsaCite(),
    missing_title: "Confidentiality term clause missing",
    missing_description:
      "No clause was found defining the duration of confidentiality obligations.",
    explanation:
      "Industry consensus and UTSA practice require an explicit confidentiality term. Without one, the duration is ambiguous and may not be enforceable in some jurisdictions.",
    recommendation:
      "Add a clause stating either a definite term (e.g., 5 years from disclosure) or, preferably, a definite term for confidential information plus a perpetual term for trade secrets.",
    present_patterns: [
      /\b(\d{1,2}|two|three|four|five|seven|ten)\s*\(?\d?\)?\s*years?\b.{0,80}(confidential|disclos)/is,
      /(confidential|disclos).{0,80}\b(\d{1,2}|two|three|four|five|seven|ten)\s*\(?\d?\)?\s*years?\b/is,
      /period\s+of\s+\d+\s+years/i,
    ],
  }),

  presence({
    id: "NDA-D-004",
    name: "Trade-secret perpetual carve-out present",
    description:
      "Best practice: trade-secret obligations should continue for as long as the information qualifies as a trade secret, not be cut off by a fixed term.",
    citation: utsaCite(),
    missing_title: "Trade-secret perpetual carve-out missing",
    missing_description:
      "No clause was found extending the confidentiality obligation for trade secrets beyond the fixed term.",
    explanation:
      "If the NDA imposes a flat 3- or 5-year confidentiality term with no carve-out for trade secrets, the discloser loses statutory protection once the term lapses — defeating the purpose of UTSA / DTSA.",
    recommendation:
      "Add: 'With respect to trade secrets, the obligations of confidentiality shall continue for as long as the information qualifies as a trade secret under applicable law.'",
    present_patterns: [
      /trade\s+secret.{0,120}(as\s+long\s+as|so\s+long\s+as|in\s+perpetuity|perpetual|qualifies\s+as)/is,
      /(perpetual|in\s+perpetuity).{0,80}trade\s+secret/is,
    ],
    default_severity: "warning",
  }),

  presence({
    id: "NDA-D-005",
    name: "Confidential Information defined",
    description: "NDA must define 'Confidential Information' (or equivalent capitalized term).",
    citation: genericNdaCite(),
    missing_title: "Definition of Confidential Information missing",
    missing_description: "No defined-term definition for 'Confidential Information' was detected.",
    explanation:
      "Without an explicit definition, the scope of the obligation is ambiguous and may be construed narrowly against the disclosing party.",
    recommendation:
      "Add a 'Definitions' section defining 'Confidential Information' (or 'Proprietary Information') with the scope of marked, oral, and observable information.",
    present_patterns: [
      /confidential\s+information["”’']?\s*(means|shall\s+(mean|have))/i,
      /["“]?confidential\s+information["”]?\s+is\s+defined/i,
      /proprietary\s+information["”’']?\s*(means|shall\s+(mean|have))/i,
    ],
  }),

  presence({
    id: "NDA-D-006",
    name: "Exclusion: publicly available information",
    description:
      "The Confidential Information definition should exclude information that is or becomes publicly available through no breach.",
    citation: genericNdaCite(),
    missing_title: "'Publicly available' exclusion missing",
    missing_description:
      "Confidential-Information definition lacks the standard 'publicly available' exclusion.",
    explanation:
      "All four standard NDA exclusions (public domain, prior knowledge, third-party-lawfully, independently developed) should appear. The 'publicly available' exclusion is the most common.",
    recommendation:
      "Add: 'Confidential Information does not include information that is or becomes generally available to the public other than as a result of a breach of this Agreement.'",
    present_patterns: [
      /(publicly|generally)\s+(available|known)/i,
      /(public\s+domain|in\s+the\s+public)/i,
    ],
  }),

  presence({
    id: "NDA-D-007",
    name: "Exclusion: previously known to the recipient",
    description:
      "Confidential Information should exclude information already known to the receiving party prior to disclosure.",
    citation: genericNdaCite(),
    missing_title: "'Already known' exclusion missing",
    missing_description:
      "Confidential-Information definition lacks an exclusion for information previously known to the receiving party.",
    explanation:
      "Without a 'previously known' carve-out, the receiver risks breaching the NDA by using information they already possessed.",
    recommendation:
      "Add: 'Confidential Information does not include information already known to Receiving Party prior to disclosure, as evidenced by its written records.'",
    present_patterns: [
      /(already\s+known|prior\s+to\s+disclos|previously\s+known|in\s+the\s+possession\s+of)/i,
    ],
  }),

  presence({
    id: "NDA-D-008",
    name: "Exclusion: third party lawfully obtained",
    description:
      "Confidential Information should exclude information lawfully received from a third party without breach.",
    citation: genericNdaCite(),
    missing_title: "'Third party lawfully obtained' exclusion missing",
    missing_description:
      "Confidential-Information definition lacks a 'lawfully obtained from a third party' carve-out.",
    explanation:
      "Without this exclusion the receiver could be in breach for using identical information obtained legitimately from another source.",
    recommendation:
      "Add: 'Confidential Information does not include information received from a third party not under an obligation of confidentiality to Disclosing Party.'",
    present_patterns: [
      /(third\s+party).{0,80}(without\s+(breach|restriction)|lawfully|not\s+(under|subject\s+to))/is,
      /(received|obtained)\s+from\s+a\s+third\s+party/i,
    ],
  }),

  presence({
    id: "NDA-D-009",
    name: "Exclusion: independently developed",
    description:
      "Confidential Information should exclude information independently developed by the receiver without reference to the Confidential Information.",
    citation: genericNdaCite(),
    missing_title: "'Independently developed' exclusion missing",
    missing_description:
      "Confidential-Information definition lacks an 'independently developed' carve-out.",
    explanation:
      "Without this exclusion, ordinary R&D by the receiver may incidentally be captured. Common Paper, ACC, and ABA practice notes all include this carve-out.",
    recommendation:
      "Add: 'Confidential Information does not include information independently developed by Receiving Party without use of or reference to Disclosing Party's Confidential Information.'",
    present_patterns: [
      /independently\s+(developed|derived|created)/i,
      /without\s+(use\s+of|reference\s+to)\s+(the\s+)?confidential/i,
    ],
  }),

  language({
    id: "NDA-D-010",
    name: "Residuals clause flagged for awareness",
    description:
      "Residuals clauses permit the receiver to use general knowledge retained in memory. Not inherently wrong but consequential for the discloser.",
    citation: genericNdaCite(),
    bad_title: "Residuals clause present — review for the discloser's position",
    bad_description:
      "A 'residuals' clause was detected. Such clauses allow the receiver's personnel to use general knowledge retained in unaided memory.",
    explanation:
      "Residuals clauses are a known carve-out that materially weakens NDA protection for the disclosing party. Vaulytica flags presence so the discloser can make a deliberate choice; it does not assert wrongness.",
    recommendation:
      "If you are the disclosing party, consider deleting the residuals clause or narrowing it to non-trade-secret information explicitly.",
    bad_patterns: [/\bresiduals?\b/i, /(retained\s+in.{0,40}(unaided\s+)?memory)/is],
    default_severity: "info",
  }),

  language({
    id: "NDA-D-011",
    name: "Permitted-use scope is too broad",
    description:
      "Permitted use of Confidential Information should be limited to the specific Purpose; 'any business purpose' is overbroad.",
    citation: genericNdaCite(),
    bad_title: "Permitted-use scope is overbroad",
    bad_description:
      "The agreement permits use of Confidential Information for 'any business purpose' or similarly unbounded scope.",
    explanation:
      "A best-practice NDA limits use to a defined Purpose (e.g., 'to evaluate a potential business relationship'). 'Any business purpose' effectively allows the receiver to use the information for unrelated revenue lines.",
    recommendation:
      "Restate the permitted use as: 'solely for the Purpose described in Section [X], and for no other purpose.'",
    bad_patterns: [
      /(for\s+any\s+(business\s+)?purpose|any\s+lawful\s+purpose)/i,
      /(unrestricted\s+use|any\s+use)\s+of\s+(the\s+)?confidential/is,
    ],
    // "for any purpose OTHER THAN the Purpose" is the narrow best-practice
    // framing NDA-D-012 checks for — the exact opposite of the unbounded grant
    // this rule targets.
    exclude_if: [/\bpurpose\s+other\s+than\b/i],
  }),

  presence({
    id: "NDA-D-012",
    name: "Permitted-use 'to evaluate the Purpose' framing present",
    description:
      "Best practice: a narrow 'to evaluate the Purpose' (or equivalent) framing of permitted use.",
    citation: genericNdaCite(),
    missing_title: "Narrow 'to evaluate the Purpose' framing missing",
    missing_description:
      "No clause was found limiting use of Confidential Information to a defined Purpose.",
    explanation:
      "A defined Purpose narrows the field of permitted use and creates a contractual basis for objecting to unrelated downstream use.",
    recommendation: "Define 'Purpose' and require use 'solely for the Purpose.'",
    present_patterns: [
      /solely\s+(for|to)\s+(the\s+)?purpose/i,
      /to\s+(evaluate|assess|consider)\s+(a\s+)?(potential|the)\s+(business|transaction)/i,
      /\bpurpose\b.{0,40}(means|defined)/i,
    ],
    default_severity: "warning",
  }),

  // ────────────────────────────────────────────────────────────────
  // Return-or-destruction with attestation — §32
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "NDA-D-013",
    name: "Return-or-destruction clause present",
    description:
      "NDA should require return or destruction of Confidential Information upon request or termination.",
    citation: genericNdaCite(),
    missing_title: "Return-or-destruction clause missing",
    missing_description:
      "No clause was found requiring return or destruction of Confidential Information.",
    explanation:
      "Without this clause the discloser has no contractual hook to recover or wipe disclosed material once the relationship ends.",
    recommendation:
      "Add a return-or-destruction clause triggered by termination of the NDA or upon written request by Disclosing Party.",
    present_patterns: [
      /(return\s+or\s+destroy|destruction\s+of\s+confidential|destroy\s+all\s+copies)/i,
    ],
  }),

  presence({
    id: "NDA-D-014",
    name: "Return-or-destruction attestation requirement",
    description:
      "Return-or-destruction clauses should require a written certification or attestation of destruction.",
    citation: genericNdaCite(),
    missing_title: "Return-or-destruction attestation missing",
    missing_description:
      "Return-or-destruction language was detected but does not require written certification of destruction.",
    explanation:
      "Without an attestation requirement, the discloser has no proof that destruction actually occurred — a real-world enforcement gap.",
    recommendation:
      "Add: 'Receiving Party shall provide a written certification, signed by an officer, attesting to compliance with this Section within thirty (30) days.'",
    present_patterns: [
      /(certif(y|ication)|attest(ation)?|written\s+confirmation).{0,80}(destroy|destruction|return)/is,
      /(destroy|destruction|return).{0,80}(certif(y|ication)|attest(ation)?|written\s+confirmation)/is,
    ],
    default_severity: "warning",
  }),

  // ────────────────────────────────────────────────────────────────
  // Injunctive relief — §32
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "NDA-D-015",
    name: "Injunctive-relief / irreparable-harm clause present",
    description:
      "NDA should acknowledge that breach causes irreparable harm and that injunctive relief is appropriate.",
    citation: genericNdaCite(),
    missing_title: "Injunctive-relief clause missing",
    missing_description:
      "No clause was found acknowledging irreparable harm or entitlement to injunctive relief.",
    explanation:
      "Without an irreparable-harm acknowledgment, a court may require the discloser to prove inadequate-remedy-at-law from scratch, slowing emergency relief in a leak scenario.",
    recommendation:
      "Add: 'The parties agree that monetary damages would be an inadequate remedy for any breach of this Agreement and that the non-breaching party shall be entitled to seek injunctive or other equitable relief, in addition to any other available remedies.'",
    present_patterns: [
      /irreparable\s+(harm|injury)/i,
      /injunctive\s+(relief|remedy)/i,
      /equitable\s+relief/i,
    ],
  }),

  presence({
    id: "NDA-D-016",
    name: "Waiver-of-bond language present",
    description:
      "Best-practice NDAs waive the requirement to post a bond when seeking injunctive relief.",
    citation: genericNdaCite(),
    missing_title: "Waiver-of-bond language missing",
    missing_description: "Injunctive-relief clause does not include a waiver of bond.",
    explanation:
      "Many courts require a movant to post a bond as a condition of preliminary injunctive relief. A contractual waiver smooths the emergency-motion path.",
    recommendation:
      "Add: 'The party seeking injunctive relief shall be entitled to such relief without the need to post a bond or other security.'",
    present_patterns: [
      /(without|waive[sd]?).{0,40}(bond|security|surety)/is,
      /(no\s+bond|posting\s+of\s+a\s+bond.{0,40}waived)/is,
    ],
    default_severity: "warning",
  }),

  // ────────────────────────────────────────────────────────────────
  // Governing law — §32
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "NDA-D-017",
    name: "Governing-law clause present",
    description: "NDA should specify the governing law of the agreement.",
    citation: genericNdaCite(),
    missing_title: "Governing-law clause missing",
    missing_description: "No governing-law clause was detected.",
    explanation:
      "Without a chosen governing law, default conflict-of-laws rules apply and may produce an unintended jurisdiction.",
    recommendation:
      "Add a governing-law clause naming a viable jurisdiction (Delaware, New York, California, Texas, England & Wales, etc.).",
    present_patterns: [
      /(governing\s+law|governed\s+by\s+the\s+laws|laws\s+of\s+the\s+(State\s+of|country\s+of))/i,
    ],
  }),

  presence({
    id: "NDA-D-018",
    name: "Governing law from a viable jurisdiction",
    description:
      "Governing law should be chosen from a list of generally viable jurisdictions (Delaware, New York, California, Texas, England & Wales, Massachusetts, Illinois, Washington).",
    citation: genericNdaCite(),
    missing_title: "Governing law not from a typical viable jurisdiction",
    missing_description:
      "Governing-law clause is present but the chosen jurisdiction is unusual; consider whether it was chosen deliberately.",
    explanation:
      "Unusual jurisdictions can produce unpredictable outcomes for NDA enforcement. Vaulytica only flags this as a soft warning; small-state choice may be deliberate.",
    recommendation:
      "Consider whether a more conventional jurisdiction (Delaware, New York, California, Texas) better serves the parties.",
    present_patterns: [
      /laws\s+of\s+(the\s+(State\s+of\s+)?)?(Delaware|New\s+York|California|Texas|Massachusetts|Illinois|Washington|England|United\s+Kingdom)/i,
    ],
    default_severity: "info",
  }),

  // ────────────────────────────────────────────────────────────────
  // No-precedent / non-solicit / non-circumvention / no-license
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "NDA-D-019",
    name: "No-precedent / no-MFN clause",
    description:
      "NDA may state that signing does not create most-favored-nation obligations or precedent for future terms.",
    citation: genericNdaCite(),
    missing_title: "No-precedent / no-MFN clause missing",
    missing_description:
      "No clause was found stating that the NDA does not establish precedent for future agreements.",
    explanation:
      "A no-precedent clause prevents the receiver from arguing that prior NDAs control subsequent commercial-deal drafting. Optional but common.",
    recommendation:
      "Add: 'This Agreement is not intended to create, and shall not be construed as creating, a precedent for any future agreement between the parties.'",
    present_patterns: [
      /(no\s+precedent|not\s+(create|constitute)\s+a\s+precedent|most\s+favored\s+nation)/i,
    ],
    default_severity: "info",
  }),

  language({
    id: "NDA-D-020",
    name: "Non-solicitation lacks general-solicitation carve-out",
    description:
      "If a non-solicitation clause is present, it should carve out general solicitations not targeted at the other party's personnel.",
    citation: genericNdaCite(),
    bad_title: "Non-solicit lacks general-solicitation carve-out",
    bad_description:
      "A non-solicitation clause was detected, but no carve-out for general solicitations / public job postings was found in the same paragraph.",
    explanation:
      "Without a general-solicitation carve-out, ordinary recruiting (LinkedIn posts, conference recruiters) becomes a contractual breach risk. The standard fix is a general-solicitation safe harbor.",
    recommendation:
      "Carve out: 'Nothing in this clause shall restrict general solicitations of employment not specifically directed at employees of the other party.'",
    bad_patterns: [/(non[- ]solicit|shall\s+not\s+solicit|will\s+not\s+solicit)/i],
    // Was a forward-only negative lookahead, so a carve-out drafted BEFORE the
    // trigger ("Notwithstanding the foregoing, this Section shall not restrict
    // general solicitations ... each party shall not solicit ...") went unseen.
    // The guard reads the whole paragraph, in both directions.
    exclude_if: [/(general\s+solicitation|not\s+specifically\s+directed|general\s+advertis)/i],
    default_severity: "warning",
  }),

  presence({
    id: "NDA-D-021",
    name: "No-license / no-ownership-transfer clause",
    description:
      "NDA should state that disclosure does not transfer ownership or grant a license in the Confidential Information.",
    citation: genericNdaCite(),
    missing_title: "No-license clause missing",
    missing_description:
      "No clause was found stating that disclosure does not grant a license or ownership interest.",
    explanation:
      "Without a no-license clause, an aggressive receiver could argue an implied license arose from disclosure. The fix is a one-line denial.",
    recommendation:
      "Add: 'No license or other right is granted to Receiving Party in or to the Confidential Information except as expressly set forth in this Agreement.'",
    present_patterns: [
      /no\s+license/i,
      /(does\s+not\s+(grant|convey|transfer)|shall\s+not\s+be\s+construed.{0,40}license)/is,
    ],
  }),

  presence({
    id: "NDA-D-022",
    name: "Authority / no-conflicting-obligation representation",
    description:
      "NDA may include a representation that each party has authority to sign and that no conflicting obligations exist.",
    citation: genericNdaCite(),
    missing_title: "Authority / no-conflicting-obligation representation missing",
    missing_description:
      "No representation of authority or absence of conflicting obligations was found.",
    explanation:
      "An authority representation is a low-cost addition that closes off a defensive argument later. Common Paper includes it.",
    recommendation:
      "Add: 'Each party represents that it has full authority to enter into this Agreement and that doing so does not conflict with any other obligation.'",
    present_patterns: [
      /(full\s+(power\s+and\s+)?authority|authority\s+to\s+(enter|execute))/i,
      /no\s+conflicting\s+(obligation|agreement)/i,
    ],
    default_severity: "warning",
  }),

  presence({
    id: "NDA-D-023",
    name: "Successors-and-assigns with consent",
    description: "Assignment should require consent and bind successors.",
    citation: genericNdaCite(),
    missing_title: "Successors-and-assigns / consent-to-assignment missing",
    missing_description: "No successors-and-assigns clause with consent-to-assignment was found.",
    explanation:
      "Without a consent-to-assignment clause, an acquirer of the receiving party could inherit access to Confidential Information without the discloser's approval.",
    recommendation:
      "Add: 'This Agreement shall bind and inure to the benefit of the parties and their successors and permitted assigns. Neither party may assign this Agreement without the prior written consent of the other party.'",
    present_patterns: [
      /successors\s+and\s+assigns/i,
      /(may\s+not\s+assign|shall\s+not\s+assign|without.{0,40}consent)/i,
    ],
    default_severity: "warning",
  }),

  // ────────────────────────────────────────────────────────────────
  // Mutual / Unilateral symmetry — §32
  // ────────────────────────────────────────────────────────────────
  language({
    id: "NDA-D-024",
    name: "Mutual NDA — symmetry: receiver-only obligation detected",
    description:
      "In a mutual NDA, obligations should bind both parties equally. Receiver-only phrasing breaks symmetry.",
    citation: genericNdaCite(),
    scope: "mutual",
    bad_title: "Mutual NDA contains a receiver-only / one-sided obligation",
    bad_description:
      "Detected language imposing an obligation solely on the 'Receiving Party' (or one named party) in what should be a mutual agreement.",
    explanation:
      "Mutual NDAs are typically drafted with each party as both Disclosing and Receiving Party. Asymmetric drafting suggests either (a) the wrong template was used, or (b) one party is silently advantaged.",
    recommendation:
      "Rewrite the obligation as bilateral: 'Each party shall ...' rather than 'Receiving Party shall ...'.",
    bad_patterns: [/^(?=.*receiving\s+party)(?!.*each\s+(party|of\s+the\s+parties)).{0,300}$/im],
    default_severity: "warning",
  }),

  presence({
    id: "NDA-D-025",
    name: "Unilateral NDA — only discloser/receiver framing present",
    description:
      "In a unilateral NDA, exactly one party should bear the receiver obligations. Mutual / bilateral phrasing in a unilateral template signals a template mismatch.",
    citation: genericNdaCite(),
    scope: "unilateral",
    missing_title: "Unilateral NDA missing discloser / receiver role framing",
    missing_description:
      "Could not detect a clear unilateral 'Disclosing Party' / 'Receiving Party' role framing.",
    explanation:
      "Unilateral NDAs should clearly name one party as the Disclosing Party and the other as Receiving Party, with obligations running only against the receiver.",
    recommendation:
      "Restate the parties as 'Disclosing Party' and 'Receiving Party' and run all obligations against the Receiving Party only.",
    present_patterns: [
      /disclosing\s+party.{0,200}receiving\s+party/is,
      /receiving\s+party.{0,200}disclosing\s+party/is,
    ],
    default_severity: "warning",
  }),
];

if (NDA_DEEP_RULES.length !== 25) {
  throw new Error(`NDA-deep ruleset must export exactly 25 rules; got ${NDA_DEEP_RULES.length}`);
}
