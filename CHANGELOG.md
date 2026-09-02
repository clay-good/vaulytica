# Changelog

All notable changes to this project will be documented in this file. Format adapted from [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [9.375.0] — 2026-09-02

### Added
- **DARK-015 — Waiver of non-waivable Article 9 debtor protections (critical).**
  Closes the gap Step 294 filed. U.C.C. § 9-602 lists the debtor protections a
  security agreement may not waive — the breach-of-the-peace limit on self-help
  repossession, commercial reasonableness of the disposition, notification of
  the disposition, the right to redeem, and the deficiency calculation — and
  nothing reported a clause purporting to waive them, because BNK-143 is a
  PRESENCE check for "default, acceleration, and disposition of collateral" and
  those are the words the waiving clause is made of. A presence check reading an
  unlawful waiver as compliance needs a rule that reports the waiver, not a
  suppression on the rule the waiver satisfied. The catalog holds 1,825 rules;
  the always-on launch set is 121.

  The compliant drafting does not fire, and an existing specimen is why: a
  clause taking possession "without judicial process **if it can do so without a
  breach of the peace**" is quoting § 9-609(b)(2) rather than escaping it, and a
  disposition made "as Article 9 of the Uniform Commercial Code requires" names
  the article by its full title. The first form of the rule reported both, and
  both are now pinned.

## [9.374.0] — 2026-09-02

### Fixed
- **A lease states its payment term in the active voice, and FIN-005 read only
  the passive.** "Lessee shall pay rent of $4,180.00 per month in advance on the
  first day of each month" is a payment term; the recurring-due-date branch
  leads on "due / payable / paid", so every lease written this way was told it
  references fees and states none. The new branch's window admits a period only
  when a digit follows it — a plain `[^.]` window dies at the decimal inside the
  amount, which stands between the verb and the due date in exactly this
  drafting, and an unbounded one runs past the end of the sentence and reads a
  monthly REPORTING obligation as a payment term.
- **A document titled EQUIPMENT FINANCE LEASE tied two families and won by the
  alphabet.** `equipment-lease` spent three of its nine phrase slots on
  "lessor", "lessee" and "the equipment" — the genus every equipment lease
  carries, invisible to `distinguishing-base-rate` because the base rate that
  matters is across the SIBLINGS competing for the document. Dropping them
  settles the tie on the merits.

### Added
- A sixty-month equipment finance lease with a $1 buyout as the 310th specimen.
  Its § 6 waives "any right to notice, hearing, or redemption" and lets the
  lessor repossess "without notice or legal process" — Article 9 Part 6
  protections that cannot be waived — and nothing reports it: BNK-143 finds the
  words "default" and "repossess" and reads the clause as compliant. Filed on
  the specimen, not fixed; a presence check reading an unlawful waiver as
  compliance needs its own rule, not a suppression.

## [9.373.0] — 2026-09-02

### Fixed
- **A two-party signature block that carries nothing but `By:` lines read as
  unsigned.** STRUCT-003 de-duplicates the label words so one signer's
  "By: ___ Name: ___ Title: ___" is not counted as three signers — and it
  collapsed two signers into one signal against a floor of two, because the
  commonest commercial block writes nothing else. Where there are more anchored
  rules than distinct labels, the rules are now the count.
- **IPDATA-004 reported data ownership unaddressed on a section headed
  "Customer Data" that allocates it.** The right-title-and-interest branch
  required the qualified term as its object where the drafting writes the bare
  noun — "Customer retains all right, title and interest in data Customer
  submits to the Service". Eleven golden fixtures carried the false finding,
  including one whose section heading is "Data Ownership".
- **TERM-009 missed the asymmetry it exists to catch, on a word order.** The
  counterparty's cure gate is written with the adverb on either side of the
  verb, and only "may only terminate for" was read; "may terminate only for" —
  at least as common, and preferred by drafters who do not split the verb —
  produced no finding at all on a document whose provider may walk at any time.
- **`saas-vendor` stopped claiming "master services agreement".** That is
  `msa-general`'s own name, `msa-general` already won both spellings, and
  `saas-vendor` keeps "msa for software" for the case it covers. Two entries off
  the `title-keyword-reach` ratchet.

### Added
- A thin cloud services agreement, customer-side, as the 309th specimen — the
  document all three rule defects above were found on.

## [9.372.1] — 2026-09-02

### Fixed
- **The new packaging guard failed on Windows**, and it was the guard's own bug:
  `files` globs are POSIX and `path.relative` is not, so every path came back
  with backslashes, no prefix matched, and it reported the entire import graph as
  unshipped. Paths are normalized to `/` before comparison. Same lesson as the
  two releases before it — a check verified in one environment is not verified.

## [9.372.0] — 2026-09-02

### Fixed
- **The workflow snippet in the README and the CI guide named a tag that does
  not exist.** Both told a reader to paste `uses: clay-good/vaulytica@v8`; the
  repository carried exactly one tag, `v6.0.0`, so every reader who copied it
  got "unable to resolve action clay-good/vaulytica, unable to find version v8"
  before a document was read. The three references now name `v9`, and the moving
  major tag is published alongside this release.

### Added
- `tests/integration/action-ref-drift.test.ts` — the snippet is prose, and prose
  does not fail a build, which is how the number stayed two majors stale. The
  guard pins the two facts that drifted: the major in the snippet is the major
  we ship, and every snippet agrees.

## [9.371.0] — 2026-09-02

### Fixed
- **The launcher could not find `tsx` from anywhere but the install root.**
  `bin/vaulytica.mjs` spawns `node --import tsx …`, and the child resolves that
  bare specifier against ITS OWN working directory. `tsx` sits beside the
  package, so it resolved only where the two coincided: the GitHub Action, which
  runs from the consumer's `github.workspace` while the tool lives in
  `github.action_path`, failed on every run, as did `npx vaulytica` from any
  directory but the one it was installed into. The launcher now resolves `tsx`
  from itself and hands the child an absolute URL, which no working directory
  can affect.

### Added
- `published-package.test.ts` now runs the launcher end to end from a temporary
  working directory — the same shape the Action gives it — and was confirmed to
  fail with the bare specifier put back.

## [9.370.0] — 2026-09-02

### Fixed
- **`npx vaulytica` could never have worked.** Two defects in the gap between a
  checkout and an install, each fatal on the first command, and neither visible
  from inside the repository — where the working directory and the package root
  are the same directory and every path resolves whichever way you write it.
  `tools/dkb/resolve.ts` was missing from `files` although
  `tools/accuracy/pipeline.ts` imports it, so `analyze` died with
  ERR_MODULE_NOT_FOUND before parsing an argument; and the DKB artifact root was
  `join(process.cwd(), "dkb", "dist")`, which is the user's own directory rather
  than the package that ships `dkb/dist/v0.0.1-starter/`, so it then died with
  "no DKB artifact found". The resolver now falls back to the package's own
  tree, keeping the working directory's artifact first so a checkout still runs
  its own. Verified the way it should have been all along: `npm pack`, install
  the tarball into an empty directory, and analyze a document.

### Added
- `tests/integration/published-package.test.ts` — the two assertions that stand
  in for an install without running one. Every local module reachable from the
  CLI entry must fall inside a `files` entry, and the default DKB root must
  resolve to a real artifact from a working directory that has none.

## [9.369.0] — 2026-09-02

### Fixed
- **The linter said one thing twice, on 26 specimens and 72 golden fixtures.**
  A presence note whose sibling audits the very clause it noted is that
  sibling's opening words restated at the same severity on the same sentence.
  "Survival clause present" (TEMP-006) sat directly above "Survival list may be
  missing categories: indemnity, governing law" (TEMP-007); "Cure period: 90
  days" (TEMP-008) directly above "Cure period of 90 days is unusual"
  (TEMP-009). Each presence rule now defers on its sibling's OWN exported
  predicate — `survivalListGaps`, `isUnusualCurePeriod` — so the deference and
  the finding cannot drift apart, and each keeps every case the sibling cannot
  see: a survival list with no gap, a cure period inside the customary 10–60
  day band. TEMP-006 still fires on 23 specimens and TEMP-008 on 14.

### Added
- `tests/integration/redundant-findings.test.ts` — the mechanical form of the
  question Step 288 asked by hand. It sweeps all 308 specimens for two
  DIFFERENT rules reporting overlapping spans at the same severity, and pins
  the result as a ratchet in both directions. Nine pairs overlap on purpose
  (a limitation of liability has both a carve-out count and a damages waiver in
  it) and each carries its reason; one is a real duplicate filed rather than
  fixed, because the suppression that removes it removes the rule.

## [9.368.0] — 2026-09-02

### Fixed
- **Three title keywords that are not titles.** "generative ai" is a TOPIC and
  both AI families claimed it, each of which also declares its own name
  ("generative ai policy", "ai addendum"); "waiver and release" is the genus a
  participant release is called, while a lien waiver is called "waiver and
  release OF LIEN" and declares four names of its own. Each was a live
  collision on `title-keyword-reach`, and the ratchet is three entries shorter.
  A fourth candidate, "bylaws of", stays: a nonprofit's bylaws really are
  titled "BYLAWS OF PEMBERTON RIDGE LAND CONSERVANCY", and dropping it cost
  that document its family outright — the collision is live because the
  ambiguity is.

### Added
- A FAR/DFARS flowdown addendum to an Air Force subcontract and a secured
  Oregon promissory note with a usury savings clause. Both were clean, and both
  are pinned as the clean case for packs that had one specimen apiece. 309
  specimens.

## [9.367.0] — 2026-09-02

### Fixed
- **RISK-004 and RISK-015 reported the same clause, at `warning`, in the same
  words.** "Indemnity carved out of the liability cap" and "Indemnification
  carved out of liability cap", on the same sentence of five specimens and a
  golden fixture — a linter that says one thing twice at its second-highest
  severity is spending the reader's attention on its own bookkeeping. Where the
  CAP ITSELF excepts the indemnity it is RISK-004's finding, and RISK-015 now
  stands down. RISK-015 keeps what RISK-004 cannot see: the carve-out written
  from the indemnity's side, and the indemnity with no cap anywhere — both
  still pinned.

### Added
- A regulatory-affairs consulting agreement with an individual consultant —
  work-made-for-hire plus assignment, a background-IP licence back, a debarment
  representation, and a cap with the usual carve-outs. It is the document that
  showed the duplication, because it is well drafted and the pair was the whole
  top of its report. 307 specimens.

## [9.366.0] — 2026-09-02

### Fixed
- **A statement of work that numbers itself reached none of the subordination
  machinery.** "This Statement of Work No. 4 (\"SOW\") is entered into under and
  subject to the Master Services Agreement dated March 9, 2024" — and the
  issued-under reader's window is `[^.;]`, which stops at the period in "No.".
  It now steps over an abbreviation period, as its siblings do. The SOW had been
  told it has no governing law, no IP allocation, no liability cap, no venue and
  no effect-of-termination clause: five clauses of the MSA it names in its first
  sentence.
- **The parent named by its ACRONYM was not a named parent.** "Capitalized
  terms used but not defined in this SOW have the meanings given in the MSA"
  wanted a multi-word instrument title. The acronym list `ISSUED_UNDER_PARENT`
  already carries belongs here for the same reason — and it took five false
  absences off ten vendor-security-addendum golden fixtures as well.
- **The order-of-precedence clause is written with the VERB as often as the
  noun.** "If this SOW conflicts with the MSA, the MSA controls" reached no
  branch of a reader that wanted "in the event of any conflict".
- **A colon stands in for the determiner in a header block.** TEMP-002's
  referenced-instrument exclusion wanted "the"/"a"/"that certain" before the
  instrument, and a SOW states its parent as "MSA Reference: Master Services
  Agreement dated March 9, 2024", where no determiner is grammatical.
- **`sow` listed "Services" among its `expected_defined_terms`**, a term a SOW
  takes from the master agreement along with everything else it does not
  restate.

### Added
- A numbered statement of work under a municipal-utility MSA, with a header
  block, five dated deliverables and a change-control clause. 306 specimens.

## [9.365.0] — 2026-09-02

### Fixed
- **PERS-001 and PERS-005 read a state-law non-compete DISCLAIMER as a
  non-compete.** "The Company is not asking you to agree to any noncompetition
  covenant, and none is a condition of this offer" is a sentence offer letters
  in Washington, Colorado, California and Minnesota increasingly carry, and the
  disclaimer guard knew only the incoming-obligations shape ("you are not
  subject to any…").
- **STRUCT-006 asked an offer letter to define the job it offers.** "the
  position of Staff Mechanical Engineer" is a role, and there is no drafting
  change that answers the finding. The introduction is the test rather than a
  vocabulary list; a bare "as" is deliberately not one of them, because it
  reads "as Settlor and initial Trustee" in every estate instrument.
- **TEMP-010 read an offer's acceptance deadline as the agreement's
  expiration.** "This offer expires on August 10, 2026" sits at the foot of
  every offer letter, above a start date weeks later, and the letter was told
  its September start date falls after its own expiry. The same shape as the
  notary's commission the guard was written for.
- **`offer-letter` was asked for a governing-law clause** while skipping the
  venue check beside it.

### Added
- A Seattle staff-engineer offer letter — option grant, EFAA-carved
  arbitration clause, RCW 49.44.140 invention carve-out. 305 specimens.

## [9.364.0] — 2026-09-02

### Fixed
- **The SPECIFIC privacy families got less review than the generic linter.**
  ADDENDA-020 — the baseline check that the enumerated disclosures are present
  — was scoped to `privacy-policy-lint` alone, while `privacy-notice-us` and
  `privacy-notice-gdpr` carry only the PNOT content checks, which are
  assertion-gated on `--regime` because which law applies is the attorney's
  call. A privacy notice rich enough to route to one of the specific families
  therefore reported nothing at all unless a regime was asserted. ADDENDA-020
  opines on no regime question, so it is the right floor under all three.
- **A privacy policy was told at `critical` that it has no signature block.**
  Nobody signs one, and both sibling notice families had always skipped
  STRUCT-003; `privacy-policy-lint` was the one that did not.

### Added
- Two privacy notices for the same fictional company: a well-drafted
  multi-state consumer notice (clean) and the thin version a startup actually
  ships — no retention periods, no rights section, no opt-out mechanism, "any
  other purpose we consider appropriate". The thin one routes to
  `privacy-policy-lint` by design: the other two families carry the disclosures
  themselves as distinguishing phrases, so the policy that makes none of them
  lands there, which is why the PNOT pack lists that family. 304 specimens.

## [9.363.0] — 2026-09-02

### Fixed
- **STRUCT-017 told a subtenant it had no signature line while standing in its
  signature block.** A block labels its signatory the way the preamble named it
  — "PELLWORTH & KIRUNA DESIGN LLC, an Illinois limited liability company" —
  and that is 68 characters against a 60-character label bound, so the label
  fell outside the block and the "By:" line named only the human signing. The
  bound is now 140, filtered by a finite-verb test rather than by length alone:
  a label line is a name, a sentence has a verb. The block also reads a RUN of
  label lines, because a party-labeled block puts the role on one line
  ("SUBTENANT:") and the legal name on the next.
- **STRUCT-017 asked the prime landlord to sign the sublease.** A sublease
  names it in the recitals as a party to the PRIME LEASE — fully declared,
  entity-typed, role-bearing, and never a signatory; it consents separately.
  The same shape carries the escrow agent named in a purchase agreement and the
  senior lender named in an SNDA. A party first named in a sentence saying
  whose agreement it is a party to is no longer reconciled against this
  document's signature block.
- **STRUCT-017 counted a street name as a signature.** The extractor registers
  "FULTON" alongside "FULTON MARKET REALTY III LLC", and a signature block that
  states the signatory's address — "1130 West Fulton Market, Chicago" —
  reconciled the landlord as having signed. One-word truncations of a party's
  own name are no longer surfaces; a signature block names a party by its full
  legal name, and one-word ROLES are kept.
- **RISK-015 asked a leasehold indemnity for an aggregate cap.**
  `lease-assignment` — the nearest sibling — has skipped that check since it
  was written, and `sublease-agreement` carried a single override.

### Added
- A Chicago office sublease with a prime-landlord consent condition. 302
  specimens.

## [9.362.0] — 2026-09-02

### Fixed
- **A cross-border party was invisible.** `ENTITY_TYPES` is a US list with
  three European strays (GmbH, AG, PLC), and a mutual NDA between a Delaware
  corporation and "Vantablack Therapeutics AS" reported ONE party — a party
  that is invisible takes its role with it, and every rule that compares an
  obligor against the party set then reads a mutual agreement as one-sided. A
  new reader takes the Nordic, Benelux, Iberian, Italian, French, German,
  Japanese and Singapore/Malaysia forms. They cannot go in `ENTITY_TYPES`,
  where the role parenthetical is optional: "AS", "SA", "BV", "NV", "SL" and
  "KK" are ordinary words, and an ALL-CAPS instrument would manufacture a party
  out of every "SUCH AS". Requiring the parenthetical to follow the suffix
  immediately is what makes them safe.

### Added
- A mutual NDA in LETTER form — a letterhead, a "Re:" line, a salutation, and
  a countersignature block — between a US corporation and a Norwegian AS. 301
  specimens.

## [9.361.0] — 2026-09-02

### Fixed
- **MNA-052 asked an escrow agreement for a "Tax Reporting" section and could
  not read a "Tax Matters" one.** The clause it wants fixes the OWNER of the
  escrow income for tax purposes and names the reporting mechanic; a bank's own
  form does both without ever writing "tax reporting", "1099", "tax owner" or
  "grantor trust". Both of those things are now read.
- **RISK-011 audited the clause that protects the escrow agent.** The carve-out
  for a neutral stakeholder's fiduciary indemnity wanted "indemnify and hold
  harmless the Escrow Agent" adjacently, and the three-verb form — "indemnify,
  DEFEND, and hold harmless" — is at least as common. The escrow agreement was
  told its agent controls no defense and requires no settlement consent.
- **A defined term that TRAILS its definition was invisible.** "The Escrow
  Amount, together with all interest and earnings on it, is the 'Escrow Fund'"
  defines the central term of the document, and the inline-copula matcher wants
  the quoted term before the verb — the shape a term defined by a single value
  takes. A term defined by aggregating things already named takes this one. The
  matcher also leaves the sentence's own period out of the term: American style
  puts it inside the quotation, and a joint development agreement was being
  told that "Parties." is defined and never used.

### Added
- A second M&A escrow agreement, drafted the way a bank's own form is. 300
  specimens.

## [9.360.0] — 2026-09-02

### Fixed
- **An assignment of a lease was told that Base Rent, Additional Rent and
  Retail Lease are terms it forgot to define.** An assignment steps one party
  into another's place and uses the assumed instrument's vocabulary without
  redefining a word of it — there is no drafting change that answers the
  finding short of restating the lease inside its own assignment.
  `borrowsParentVocabulary` now reads the assumption clause, and it wants both
  halves: the ROLE the assuming party did not hold and the INSTRUMENT it held
  it under. An asset purchase agreement's "shall not assume any other
  liabilities of the Seller" is the role without the instrument, and it stays
  a standalone document that defines its own vocabulary.
- **Four referenced instruments dated a document that merely names them.**
  TEMP-002 excludes another instrument's date, and the determiner is the
  discriminator — but the list admitted only "the", "a" and "an", so "THAT
  CERTAIN Retail Lease dated August 14, 2021" was read as 1,659 days of
  back-dating on the assignment reciting it. The noun list also gained
  "amendment", "trust", "will", "deed", "mortgage" and "guaranty": a recital
  names an instrument and its amendments in one breath, and a codicil, a trust
  amendment and a forbearance agreement each recite an instrument older than
  themselves because that is what those documents are. Three specimens carried
  the finding, one of them pinned as fair.

### Added
- A two-party retail lease assignment, where the landlord consents on a
  separate exhibit rather than signing. It reaches `lease-assignment` for the
  first time in 9.358.0. 299 specimens.

## [9.359.0] — 2026-09-02

### Fixed
- **A conflict waiver was told it has no governing law, no forum, and no
  payment term.** A consent letter under Model Rule 1.7 has none of the three,
  and the engagement letter it references sets the fees. The specimen had been
  carrying two of them as known-false since it was written;
  `joint-representation-waiver` now skips all three, and the engagement and
  fee families — which really do state a payment term — are untouched.
- **PERS-001 and PERS-005 read the sentence WARNING two clients about a
  non-compete as a non-compete.** The guard for an advice letter already knew
  the shape where the covenant will be SIGNED elsewhere; a waiver more often
  lists it among the terms the clients are opposed on — "the vesting schedule,
  the buy-sell price, … and the scope of any non-competition covenant are all
  provisions on which what is favorable to one of you is unfavorable to the
  other". A sentence whose verb says the matched thing IS a provision, a term,
  or an issue is describing it; an operative covenant never says that about
  itself.

### Added
- A founders' joint-representation waiver, the second posture of that family —
  two people forming an LLC, opposed on the operating agreement's own terms
  rather than on an existing dispute. 298 specimens.

## [9.358.0] — 2026-09-02

### Fixed
- **Seven documents were routed by PART of their own title.** Where two
  families both matched — one on the whole name, one on a shorter name inside
  it — both earned the proper-name double credit, both scored 0.6, and the tie
  went to the alphabet. "ASSIGNMENT AND ASSUMPTION OF LEASE" went to
  `assignment-and-assumption-agreement` on "assignment and assumption",
  "RESIDENTIAL PURCHASE AND SALE AGREEMENT" to `real-estate-psa`,
  "INTERNATIONAL DATA TRANSFER AGREEMENT" to `data-sharing-agreement`, "BA
  SUBCONTRACTOR AGREEMENT" to the construction `subcontractor-agreement`, and
  "CONFLICT OF INTEREST WAIVER" — a waiver two clients sign — to `coi-policy`,
  a company's own conflicts policy. A name that sits inside a longer name is
  not the document's name: nested matches within a family now count once, and
  a keyword another family's matched keyword strictly contains does not earn
  the second credit.
- **A recorded instrument's own name no longer sits behind the recorder's
  block in the title corpus.** The recording-block, court-caption and
  subject-line walks each recover the name a document states somewhere other
  than its first line, and all three appended it after the scaffolding — so
  the scaffolding held the opening position, where a title keyword earns the
  second credit. A Washington quitclaim deed reached the matcher as "Recording
  requested by and when recorded return to: Calder & Vance, PLLC 615 Second
  Avenue … QUITCLAIM DEED". A document that already leads with a styled
  heading is untouched.
- **`saas-tos` no longer claims "terms of use".** A document titled exactly
  that is a website's terms of use, and `website-terms-of-use` lost every one
  of them to the SaaS family on the alphabet. A SaaS ToS titled "Terms of Use"
  still reaches `saas-tos` on its own register (subscription, billing,
  auto-renew).

### Added
- **`title-keyword-reach.test.ts` — does a document titled exactly one of a
  family's DECLARED names reach it?** `bare-title-reach` asks the question of
  the family's display name, and a display name is a catalog label rather than
  a title anyone writes: half its standing worklist is the slash, the em-dash
  and the parenthetical ("Mutual / General Release", "MSA — Vendor-Side Deep
  Analysis", "Privacy Policy Linter"). The new sweep asks it of all 1,000-odd
  declared names instead, one at a time, and is a ratchet in both directions
  over two lists: families no declared name reaches, and names a different
  family takes.

## [9.304.0] — 2026-09-01

### Fixed
- **Nine more families could not recognise a thin instance of themselves**,
  drawn from the `bare-title-reach` worklist rather than from guesswork —
  nine of the ten sampled failed. `bill-of-sale`, `warranty-deed`,
  `mutual-release`, `tolling-agreement`, `warn-notice`, `media-release`,
  `arbitration-demand` and `factoring-agreement` each listed only
  well-drafted vocabulary; `warn-notice` demanded the § 639.7(d) contents
  from the notice whose defect is omitting them.
- **`meeting-minutes` could not be reached by board minutes.** All four of its
  title keywords begin "minutes of the meeting / annual meeting", and board
  minutes are headed "MINUTES OF THE BOARD OF DIRECTORS" — it scored 0.0, not
  0.3. "minutes of the board" added.

## [9.303.0] — 2026-09-01

### Added
- **`bare-title-reach.test.ts` — can a family recognise a document titled
  exactly its own name and saying nothing else?** 135 of 266 cannot. The
  existing self-reachability sweep builds each family's probe document from
  that family's own distinguishing phrases, so it is blind by construction to
  a family whose distinguishing list is the vocabulary of a well-drafted
  instance — the defect behind the last three releases. The new guard is a
  ratchet in both directions: the list may not grow, and a family that has
  been fixed must be removed from it.

## [9.302.0] — 2026-09-01

### Fixed
- **EMP-027 reported "Geographic scope clause missing" on a covenant that
  states its geographic scope.** "worldwide" and "anywhere in the United
  States" are deliberately not present patterns — an open-ended scope is the
  abuse the rule catches — but the wording then asserted absence. It now reads
  "Geographic scope not bounded" and names both shapes.
- **Five more families could not recognise a thin instance of themselves:**
  `union-cba`, `change-order`, `commission-plan`, `litigation-hold` and
  `option-to-purchase-real-estate`. Each listed only the vocabulary of a
  well-drafted instance and reached 0.3 — its own title, below the threshold.
  A litigation hold notice saying only "keep all documents, do not delete
  anything" now routes and reports its missing triggering event, preservation
  scope, custodian list and privilege reminder.

## [9.301.0] — 2026-09-01

### Fixed
- **The jurisdiction overlays never reached the CLI's JSON report.**
  `buildJsonReport` builds `jurisdiction_overlays` from the governing-law
  clauses in its `extracted` argument and the CLI passed `undefined`, so the
  field could not appear for any document. A standalone California non-compete
  reported thirteen findings and said nothing about Cal. Bus. & Prof. Code
  § 16600, which voids it. Now threaded, and asserted by a guard.
- **EMP-025 reported "Non-compete duration missing" on the sentence stating
  the duration.** Every branch required digits, so a duration spelled out in
  words ("for five years") was invisible; and the same-clause window `[^.]`
  died at the employer's own "Inc.", which stands between the duration and the
  restriction verb.
- **A standalone non-competition agreement reached no family at all.** Its
  title is a keyword of both `employment-restrictive-covenant` and
  `ma-restrictive-covenant`, so each scored 0.3 and neither cleared the
  threshold. `subscription-agreement` and `teaming-agreement` failed the same
  way, listing only Regulation D and FAR vocabulary respectively.

### Known
- EMP-027 reports "Geographic scope clause missing" on "anywhere in the United
  States". The logic is intended — an unbounded scope is the abuse the rule
  exists to catch — but the wording states something false about the document.
  A finding-title problem, tracked separately.

## [9.300.0] — 2026-08-31

### Fixed
- **A bare party role is not a distinguishing phrase.** `data-license-agreement`
  listed "licensor", "licensee", "the licensor" and "the licensee" — the two
  role words of every licence in the catalog, each counted twice — and beat
  `trademark-license` 0.4 to 0.3 on a document titled "TRADEMARK LICENSE
  AGREEMENT". The four are replaced by phrases in the family's own register.
- **Four families could not recognise a thin instance of themselves**, because
  every phrase they listed was a protection such an instance omits:
  `trademark-license` (naked-licensing apparatus), `grant-agreement`,
  `lease-assignment` and `nonprofit-bylaws`. Each now also claims the operative
  vocabulary a bare instance does have.
- **`nonprofit-bylaws` lost its own document to `bylaws-corporation`.** The two
  were separated only by "501(c)(3)", "tax-exempt" and "no part of the net
  earnings" — claimed by one and negated by the other — so bylaws reciting the
  § 501(c)(3) organizational test in the IRS's own words ("organized exclusively
  for charitable and educational purposes") were audited as a stock
  corporation's. That wording now separates them.

### Known
- An on-premises enterprise "SOFTWARE LICENSE AGREEMENT" routes to `eula` at
  0.5. There is no enterprise software-licence family; `eula` is the nearest
  available, not the right one. Catalog gap, not a matcher defect.

## [9.299.0] — 2026-08-31

### Fixed
- **The deep NDA families did not cover their predecessors' shorter titles.**
  `mutual-nda` claims "mutual non-disclosure" and "mutual confidentiality";
  `mutual-nda-deep` claimed only the longer forms ending in "agreement", so a
  document titled "MUTUAL NON-DISCLOSURE" or "MUTUAL CONFIDENTIALITY" could not
  reach the successor and the promotion could not fire. Same for
  `unilateral-nda`'s "one-way confidentiality", "one-way non-disclosure" and
  "unilateral non-disclosure".

### Known
- The predecessors also claim the two NEUTRAL titles — "non-disclosure
  agreement" and "confidentiality agreement" — which their mutual successor
  deliberately does not: those belong to `unilateral-nda-deep`, because a
  plainly-titled NDA is more often one-way and "mutual" is the distinguishing
  word. Adding them to `mutual-nda-deep` made it shadow its sibling on both,
  which `catalog-routing`'s sweep caught. So "a successor must cover its
  predecessor's vocabulary" is not a rule that can be mechanised: the coverage
  is sometimes correctly provided by a sibling instead.

## [9.298.0] — 2026-08-31

### Fixed
- **A severance agreement and a SaaS order form reached no family**, and a
  certificate of insurance and a deed of trust reached their own at the
  threshold. `separation-agreement` claimed "21 days", "45 days", "seven days",
  "revocation" and "adea" — the entire OWBPA apparatus, which is precisely what
  a deficient severance agreement omits. `saas-customer` and `saas-vendor` had
  no "order form" title keyword at all, so an order form reached them only
  through SaaS body vocabulary.
- **A RECIPROCAL confidentiality agreement was not a mutual NDA.**
  `mutual-nda-deep` listed "mutual non-disclosure agreement", "two-way nda" and
  "bilateral nda" but not "reciprocal" — so the successor could not clear the
  threshold, the deprecated `mutual-nda` was not promoted, and the document got
  the legacy family's ten findings instead of the deep family's twenty-four.
- The `order-form.txt` specimen's declared TIE with `saas-vendor` is preserved:
  the title keyword went on both sides. Which of the two you want is `--role`,
  not the document's, and breaking that tie is a product decision.

## [9.297.0] — 2026-08-31

### Fixed
- **CROSS-DEFTERM-001 compared a preceding-text slice, not a definition.** For
  a PARENTHETICAL term the extractor's `definition` field is the text that
  precedes the parenthetical, cut back to the last sentence break — for a
  preamble, an arbitrary run of the preamble itself. Two documents that both
  name a Buyer and a Seller in their preambles therefore always "disagreed",
  and the finding quoted two garbage strings at the reader. A stock purchase
  agreement and the covenant ancillary to it produced four, one of which
  compared an EMPTY definition against a slice beginning mid-word, and one of
  which reported that "Agreement" is defined differently in two contracts —
  which it is, in every pair of contracts ever written. The rule now compares
  express definitions only, and skips a pair where either side is empty.

## [9.296.0] — 2026-08-31

### Added
- One specimen — a downstream (subcontractor) BAA, the 245th, and the first for
  `baa-subcontractor`.

### Fixed
- **An INVERTED critical: the tool reported that the agreement disclaims the
  flow-down, on the sentence that requires it.** BAA-005 read § 6.1 — "shall
  not engage a further subcontractor that will create, receive, maintain or
  transmit PHI without a written agreement that binds that subcontractor to the
  same restrictions", which is the drafting 45 C.F.R. § 164.502(e)(1)(ii) asks
  for — as an express denial. `expressDenial`'s conditional-tail guard, the one
  that keeps "may not engage a subcontractor WITHOUT a written contract" out,
  allowed only 40 characters between the topic and the connective, and the
  HIPAA definition spelled out inline is 52.
- **The BAA pack assumes the counterparty is the Covered Entity.** In a
  downstream BAA it is the Business Associate, and the subcontractor has no
  relationship with the covered entity at all. BAA-004 wanted "report to the
  Covered Entity" from a section headed REPORTING AND BREACH NOTIFICATION;
  BAA-026 wanted covered-entity audit rights where the audit right runs
  upstream.
- **Three more wanted a noun phrase where the document uses the verb.** BAA-031
  wanted "workforce training" and could not read "shall train each member of
  its workforce"; BAA-034 wanted "sanctions policy" as an adjacent bigram and
  could not read "shall apply its written sanctions policy to any member of its
  workforce"; BAA-040 wanted "notice shall be" and could not read "a notice is
  given in writing to the address on the signature page". BAA-035 and BAA-038
  are fixed for the downstream forms of the same clauses.
- `baa-subcontractor` gains the profile the other annex families have: a BAA
  allocates no IP, states no indemnity, caps no liability and names no venue,
  because the underlying services agreement does all four.

## [9.295.0] — 2026-08-31

### Added
- **A recommendation on the remaining fourteen launch-wave warnings.** Every
  WARNING-severity rule in the launch wave now tells the reader what to do:
  DARK-001..004 (the unilateral amendment right, the buried renewal window, the
  one-way fee-shifting, the arbitration-plus-class-waiver pairing), PERS-003,
  PERS-004, RISK-002, RISK-004, RISK-008, TEMP-003..005, TERM-003 and TERM-008.
  What is left without one is forty `info`-level statements of fact —
  "Auto-renewal clause present", "Survival clause present" — where the finding
  IS the fact and advice would be noise.

## [9.294.0] — 2026-08-31

### Added
- **A recommendation on the thirteen absence warnings that had none.** Half the
  rules that fire were emitting findings with an empty `recommendation`, and
  the fix-list and CSV exports both carry a column for it. The gap was entirely
  in the LAUNCH wave, which predates the convention every later wave follows —
  v3, v4 and v5 presence rules all take a required recommendation. These
  thirteen are the ones where the tool tells an attorney a clause is missing,
  so the next step is the whole value of the finding: CHOICE-001, CHOICE-002,
  CHOICE-004, CHOICE-005, CHOICE-007, FIN-003, FIN-005, IPDATA-001, IPDATA-002,
  RISK-001, RISK-005, TERM-002 and TERM-005.

## [9.293.0] — 2026-08-31

### Added
- One specimen — a well-drafted consulting agreement, the 244th, and the first
  for `consulting-agreement`, one of the ten families the product launched
  with. Its rules came back clean: nine findings, every one a fact about the
  document rather than an accusation.

### Fixed
- **Two defined terms in one parenthetical, and NEITHER was found.** `(each, an
  "SOW", and the services under all SOWs, the "Consulting Services")` defines
  two terms without a collective connective between them, and all three
  parenthetical patterns missed it: the plain one needs its quote closed by
  `)`, the trailing-prose one's run cannot cross the first quote, and the pair
  one requires "collectively / together / individually / each / severally".
  Both names were then reported by STRUCT-006 as terms the document forgot to
  define, on the sentence that defines them.
- `msa-general` now names the consulting specialisation. A consulting agreement
  that works through statements of work carries the MSA vocabulary, and the two
  families tied at 0.9.

## [9.292.0] — 2026-08-31

### Fixed
- **A closing letter and a privilege log reached no family at all**, and
  requests for admission, a limited-scope agreement and interrogatories reached
  their own at or near the threshold. `termination-of-representation` claimed
  "representation has concluded" as an adjacent bigram, and a real letter says
  "our representation OF YOU IN THE WRENFIELD MATTER has concluded";
  `requests-for-admission` claimed "deemed admitted" and "genuineness of the
  document", which appear in the RESPONSE, not the request; `privilege-log`
  claimed "log of documents withheld" and "bates" and not the sentence a log
  opens on. All six now route at 0.6 or better.

## [9.291.0] — 2026-08-31

### Added
- One specimen — a sale-of-business non-competition and non-solicitation
  covenant, the 243rd, and the first for `ma-restrictive-covenant`.

### Fixed
- **9.269.0's title-keyword fix for the employment covenant had taken this
  family's documents.** "Non-competition and non-solicitation" and
  "non-solicitation agreement" both matched a sale-of-business covenant, the
  employment family scored two title keywords, and an M&A covenant was audited
  as an employment one. Both sides are corrected: the M&A family gains the
  conjoined titles and the sale-of-business vocabulary, and the employment
  family names the sale-of-business context as a negative feature.
- **Three M&A covenant rules could not read a covenant.** A covenant is drafted
  as a PROHIBITION, not as a noun. MNA-077 and MNA-078 wanted "non-solicit" or
  "not to solicit" and could not read "Seller shall not solicit any customer of
  the Company" — the commonest drafting there is. MNA-079 wanted the nouns
  "blue-pencil" or "reformation" and could not read "the court shall reform it
  to the narrowest terms that are enforceable".

## [9.290.0] — 2026-08-31

### Fixed
- **A SHAREHOLDERS agreement reached no family at all.**
  `stockholders-agreement` listed "stockholders agreement" and "stockholders'
  agreement" and not the other spelling of the same instrument — the one a
  British or British-trained drafter uses, and the commoner one outside
  Delaware. It drew three generic findings; it now draws eighteen.
- **A gym waiver reached no family either.** `hold-harmless-agreement` listed
  "waiver and release" and "participant release" but not "release and waiver",
  "waiver of liability" or "release of liability" — the three commonest
  headings on the document itself.
- `guaranty` and `quitclaim-deed` were reaching their own bad documents at 0.5
  and 0.6, both because their phrases were the formal recitals a complete
  instrument carries ("continuing guaranty", "absolute and unconditional",
  "does hereby remise, release and quitclaim").

## [9.289.0] — 2026-08-31

### Fixed
- **Four force-majeure and termination checks that required the term of art.**
  A force-majeure clause is as often drafted without the Latin — "a failure to
  perform caused by an event beyond its reasonable control" is the same clause,
  and is the usual formulation in consumer and UK drafting — and COMM-111,
  COMM-176 and COMM-244 all required the literal words. COMM-138 required
  "terminate this agreement" and could not read "either party may terminate if
  the other party breaches".
- **EMP-032 could not read "may not disclose" or "shall protect from
  disclosure"**, two of the standard formulations of a confidentiality
  obligation, because its modal list stopped at will/shall/agree-to and its
  verb list at disclose/keep/maintain.

## [9.288.0] — 2026-08-31

### Fixed
- **The fifth and sixth rulesets carrying their own narrower copy of the
  governing-law clause.** A sweep of every v4 and v5 presence rule for one that
  reads "governed by the laws of the State of Delaware" but not "Delaware law
  governs this Agreement" found GOV-042 and EQT-009, after CHOICE-001,
  NDA-D-017/018, MNA-019 and DPA-046. Both now use a single shared
  `GOVERNING_LAW_PRESENT` set, so the seventh copy is that one — and its
  doc-comment points a rule that only needs to know whether the clause is
  present at `ctx.extracted.jurisdictions`, which has read the adjectival form
  and ten others since v1.

## [9.287.0] — 2026-08-31

### Fixed
- **A plainly-drafted motion to compel could not be format-linted at all.**
  `trial-motion`'s distinguishing phrases were the formal components of a filed
  motion — "points and authorities", "declaration in support", "proposed
  order", "memorandum in support", "wherefore" — so a motion that simply states
  what it wants scored its title and nothing else and fell to
  `generic-fallback`. `--court` scopes the filing format lint to three
  families, so no invocation could reach it. The same motion now routes at 0.7
  and `--court frap-default` draws all eight FILE checks.

### Changed
- Checked the other two flag-gated packs for the same "second, invisible gate".
  The estate pack is sound: a bare will routes to `last-will-and-testament` and
  `--estate-checks --state OH` draws eight EST findings including the missing
  attestation clause and the missing witness blocks.

## [9.286.0] — 2026-08-31

### Fixed
- **An attorney who asserted `--regime ccpa` on a deficient privacy policy got
  one warning.** The 27-rule privacy-notice pack fires only when a regime is
  asserted AND the document routed to `privacy-notice-us` or
  `privacy-notice-gdpr` — and both of those families carry the disclosures
  themselves as distinguishing phrases ("categories of personal information",
  "do not sell or share", "right to opt-out", "legal basis", "right to
  erasure"). A policy that makes none of them scores nothing on either and
  lands on `privacy-policy-lint`, which runs one rule. That is exactly the
  policy the pack exists for. `privacy-policy-lint` is now the third
  privacy-notice family, and the same document with `--regime ccpa` draws the
  eight CCPA disclosure findings. The pack still fires only on an asserted
  regime, so a run without `--regime` is byte-identical.

## [9.285.0] — 2026-08-31

### Added
- One specimen — a vendor DPA that defines its own term for the regulated data
  ("Customer Personal Data"), which is how every major vendor DPA is drafted.
  The 242nd, written to test whether the CCPA pack's object-noun defect was
  systemic.

### Fixed
- **It was systemic. A textbook Article 28(3) DPA drew SIX false criticals from
  the GDPR pack.** DPA-004 wanted "types of personal data" where the document
  says "the types of Customer Personal Data"; DPA-024 anchored the breach
  notice on the word "controller" where the document names that party by its
  role ("shall notify Customer"); DPA-002 wanted "duration of the processing"
  where a DPA ties the duration to the agreement's term; DPA-029 wanted
  "Article 35" where the Regulation's own range is "Articles 32 to 36"; and
  DPA-046 could not read "Irish law governs this DPA" — the fourth ruleset
  found carrying its own narrower copy of a clause the jurisdictions extractor
  has read since v1, after CHOICE-001, NDA-D-017 and MNA-019.
- One corpus fixture was repaired rather than the rule loosened around it:
  `dpa-controller-processor-missing-dpia-assistance-fail.txt` promised
  assistance with "Articles 32 to 36", and Article 35 is the DPIA — so the
  document it was built to prove a point about did not have the gap. It now
  promises Article 32 only.
- One broadening was reverted for the opposite reason: DPA-016 was widened to
  accept a thirty-day notice of an intended sub-processor change as the
  Article 28(2) objection right, and the corpus fixture is right that notice is
  not objection. The specimen states the objection right instead.

## [9.284.0] — 2026-08-31

### Added
- One specimen — a model CCPA service-provider addendum, the 241st, and the
  first for `dpa-ccpa-service-provider`.

### Fixed
- **THIRTEEN criticals against a model CCPA addendum, eleven of them false.**
  The systemic cause is one sentence: the pack requires the literal object
  "personal information", and a real addendum defines its own term for it.
  `"Covered Data" means Personal Information the Business discloses` and then
  "shall not Sell or Share Covered Data" matched nothing at all. USDPA-002 and
  USDPA-015 now read a defined-term object, case-SENSITIVELY — the capital is
  what makes it a defined term.
- **Seven more wanted a template's phrase where the statute has its own.**
  USDPA-001 wanted "specific business purpose" where § 1798.140(ag)(1) says
  "for any purpose other than"; USDPA-004 read only the plural "other sources"
  where the regulation says "another source"; USDPA-005 wanted "the same level
  of privacy protection" where a flow-down says "the same restrictions this
  Addendum imposes"; USDPA-011 wanted "processing instructions" where an
  addendum says "on the Business's instruction"; USDPA-012 wanted the conjoined
  "nature and purpose"; USDPA-017 wanted "reasonable assessments" where
  § 1798.140(ag)(1)(E)'s own words are "reasonable and appropriate steps"; and
  USDPA-019 wanted "demonstrate compliance" where an addendum offers a SOC 2
  Type II report.
- **USDPA-003 required the literal "cross-context behavioral advertising"** from
  a document that says "shall not Sell or Share" — which is the prohibition the
  Act's own verb states, since § 1798.140(ah) defines Share as exactly that.

## [9.283.0] — 2026-08-31

### Added
- One specimen — a well-drafted SBA 7(a) loan agreement, the 240th, and the
  first for `sba-loan-agreement`.

### Fixed
- **FIN-009 read a loan's own interest rate as a late-payment penalty.** "The
  Loan bears interest at the prime rate plus 2.75%" is the price of the money,
  not a charge for paying late, and the rule reported the 2.75% margin as a
  periodless penalty. Narrowing it then MOVED the finding rather than removing
  it — `firstParagraphMatch` found the next paragraph, "an ownership interest
  of less than two percent (2%) in a publicly traded company" — so the branch
  now states positively what a money interest looks like: interest AT a rate,
  ON an amount, THEREON, or one that ACCRUES. Every ownership sense falls
  outside that without being enumerated.
- **FIN-005 told a loan repayable in 120 monthly installments that it states no
  payment term**, because it wanted "Net 30". Every note, credit agreement and
  equipment lease in the catalog states its term as an amortization schedule.
- **RISK-016 told an SBA loan that hazard insurance "for at least its full
  replacement cost" states no coverage minimum**, because it wanted a dollar
  figure. Replacement cost is the minimum every secured lender requires, and
  property and hazard policies state it as a standard rather than a number.

## [9.282.0] — 2026-08-31

### Added
- One specimen — a well-drafted private-target stock purchase agreement, the
  239th, and the first for `stock-purchase-agreement`.

### Fixed
- **MNA-018 could not read the stockholder representative a private SPA
  defines.** Its pattern was `stockholder.s?\s+representative`, where the `.`
  was meant to be an optional apostrophe — and a `.` must match a character, so
  the pattern required "Stockholders' Representative" with both the apostrophe
  and a space. The plain "Stockholder Representative" read as absent. It now
  also reads the securityholder, equityholder and member forms, and
  "representative of the Sellers".
- **STRUCT-005 reported a term as never used, on the clause that uses it three
  times.** The "definition talking about itself" suppression ran to the end of
  the PARAGRAPH rather than the end of the definition's own SENTENCE, so
  `"Closing Working Capital" means current assets less current liabilities. The
  Purchase Price assumes Closing Working Capital of $3,100,000. If Closing
  Working Capital exceeds the Target …` counted zero uses. A repetition inside
  the definition's own sentence — '"Residual Knowledge" means …, but Residual
  Knowledge does not include …' — is still a self-reference.

## [9.281.0] — 2026-08-31

### Fixed
- **A transportation agreement, a data licence and a board resolution could not
  reach their own families.** `freight-transportation-agreement` claimed the
  bill of lading, the Carmack amendment, cargo liability and detention and
  demurrage; `data-license-agreement` claimed derived data, redistribution and
  the machine-learning restriction; `board-resolution` claimed the quorum and
  the unanimous written consent. Each is what a complete instrument carries.
  All three now route at 0.8 or better.

### Known
- Four more document types have no family at all and score 0.0 or fall to
  `generic-fallback`: a charitable gift agreement, a power purchase agreement,
  a student enrollment agreement, and (from the previous sweep) a commercial
  general liability policy and a subpoena duces tecum. These are catalog
  coverage gaps rather than routing defects.

## [9.280.0] — 2026-08-31

### Fixed
- **Seven everyday documents reached their family at or below the threshold.**
  A statement of work, an offer of employment, an employee handbook, an escrow
  agreement, a subcontract, a reseller agreement and a supply agreement — the
  documents a reviewer sees weekly. `manufacturing-supply-agreement` reached
  nothing at all: its phrase is "purchase orders", plural, and a supply
  agreement says "against a purchase order from time to time". The rest each
  scored their title and one phrase, because the others were the delivery
  schedule, the conforming goods and the lead time; the joint written
  instruction and the interpleader; the FMLA policy and the acknowledgment of
  receipt; the pay-when-paid and the prime contract. All seven now route at 0.7
  or better.

## [9.279.0] — 2026-08-31

### Fixed
- **Five more families reached nothing on their own bad document, including a
  launch family.** A Software as a Service Agreement fell to
  `generic-fallback`: `saas-customer` spells its title keyword
  "software-as-a-service", with hyphens, and its six phrases are the hosted
  service, the subscription term, the uptime and the service level — the terms
  a good SaaS contract carries. `consulting-agreement`, `equipment-lease`,
  `gsa-schedule-contract` and `real-estate-psa` failed the same way, and
  `api-terms`, `medical-director-agreement` and `privacy-policy-lint` reached
  their own at the threshold. All ten now route at 0.7 or better and are pinned
  in `catalog-routing`, which now covers 23 bad documents across 23 families.

## [9.278.0] — 2026-08-31

### Fixed
- **Four bare instruments reached no family at all**, and a fifth reached its
  own at the threshold. An engagement letter, a demand note, a settlement
  agreement and release, a will, and a general power of attorney — each stating
  its subject and none of the protections its family checks for.
  `engagement-letter` claimed "scope of the representation", "conflicts of
  interest" and "trust account"; `promissory-note` claimed "maker", "payee" and
  "maturity"; `confidential-settlement` claimed "no admission" and "protected
  rights"; `last-will-and-testament` claimed "residue", "devise" and "codicil";
  `durable-poa-financial` claimed "incapacity", "hot powers" and "third-party
  reliance". All five now route at 0.7 or better and are pinned in
  `catalog-routing`, which now covers thirteen bad documents.
- `promissory-note` now names the convertible note as a negative feature. The
  three type phrases it needed — "promises to pay", "principal sum", "for value
  received" — are all things a convertible promissory note says too, and it
  immediately tied the `convertible-note` specimen at 0.9.

### Known
- A commercial general liability policy reaches no family and scores 0. The
  catalog has `cyber-insurance-policy`, `insurance-endorsement` and
  `insurance-policy-summary` but no general-liability form; so does a subpoena
  duces tecum, which has no family either. Both are catalog coverage gaps, not
  routing defects.

## [9.277.0] — 2026-08-31

### Fixed
- **Three families reached their own bad document at exactly 0.5** — the
  threshold, one negative feature from falling to `generic-fallback`. Same
  cause each time: the routing phrases were the protections the ruleset checks
  for. `clinical-trial-agreement` claimed the IRB, the informed-consent form,
  subject injury and Form FDA 1572; `convertible-note` claimed the maturity
  date and subordination; `safe-yc` claimed the valuation cap and discount
  rate. A document with none of them scored its title and one phrase. All three
  now route at 0.7 and are pinned in `catalog-routing`.

### Changed
- Ten more high-stakes families swept with deliberately bad documents — a BAA
  letting the business associate use PHI for its own analytics, a DPA with
  unrestricted sub-processing, a franchise agreement terminable at the
  franchisor's sole discretion, a separation agreement with no OWBPA period, a
  residential lease with a three-month deposit and no notice of entry. Seven
  routed with margin; the three above did not.

## [9.276.0] — 2026-08-31

### Fixed
- **Eight deliberately bad documents, five families that could not recognise
  their own.** Each document states its subject and none of the protections its
  family checks for — which is the document that most needs the family, and the
  one the family's vocabulary was least able to reach.
  - `baa-subcontractor`: its phrases were the flow-down terms 45 C.F.R.
    § 164.504(e)(5) requires, so the general `baa` took a document whose title
    says subcontractor and audited it as the upstream agreement. `baa` now
    names the specialisation as a negative feature.
  - `dpa-ccpa-service-provider`: a service provider addendum that lets the
    service provider use the personal information for its own products — the
    paradigm CCPA violation — reached no family at all. Its title keywords were
    written as exact full titles and did not include "service provider
    addendum".
  - `sba-loan-agreement`: "sba 7(a)", "sop 50 10", "unconditional guarantee" —
    all things a compliant SBA loan carries — so the general `loan-agreement`
    took it and the SBA ruleset never ran.
  - `secondary-stock-transfer`: right of first refusal, the company's consent,
    Rule 144, § 4(a)(7) — the four things a compliant secondary transfer
    carries. A bare transfer drew two findings.
  - `ma-restrictive-covenant`: routed at exactly 0.5, the threshold, one
    negative feature from falling off.

  All five are pinned by a bad-document routing table in `catalog-routing`.

## [9.275.0] — 2026-08-31

### Fixed
- **A bare stock purchase agreement drew one generic finding.** All five of
  `stock-purchase-agreement`'s distinguishing phrases — "purchase and sale",
  "working capital", "material adverse effect", "indemnification", "survival" —
  are the deal-protection terms MNA-010..019 check for, so an SPA that states
  the sale and the price and nothing else scored 0.3 on its title and fell to
  `generic-fallback`. It now routes and draws seven of the M&A criticals,
  including the missing reps article and the missing MAE definition. Fourth
  demonstrated instance of a family routed on its own compliance.
- **MNA-010 could not read the sale stated buyer-first.** "Seller sells to
  Buyer all of the outstanding shares of the Company for $42,000,000" is the
  plainest statement of the sale there is, and both sentence branches read only
  the seller-shares-buyer order.
- **MNA-019 could not read "Delaware law governs".** The third ruleset found
  carrying its own narrower copy of a form the jurisdictions extractor has read
  since v1, after NDA-D-017 and CHOICE-001.
- `channel-referral-agreement` routed its own document at exactly the 0.5
  threshold — four of its six phrases are clauses COMM-014..033 require. Three
  type phrases added; it now routes at 0.7.

## [9.274.0] — 2026-08-31

### Added
- One specimen — a well-drafted unilateral NDA, the 238th, and the first for
  `unilateral-nda-deep`, a family that was unreachable by auto-routing until
  the previous release.

### Fixed
- **Three NDA rules could not read a well-drafted NDA.** "Nothing in this
  Agreement grants Recipient any LICENCE or ownership interest" is the textbook
  no-licence clause — the negation is on "nothing", not on the verb, and the
  noun is spelled with a c in every UK and Commonwealth NDA (NDA-D-021).
  "Indefinitely for any Confidential Information that is a trade secret" is the
  carve-out written as a tail on the term sentence, and "indefinitely" was in
  neither branch (NDA-D-004). And "Discloser"/"Recipient" is the other standard
  role pair — the one `mutual-nda` itself lists as distinguishing phrases — so
  an NDA that defines both in its preamble was told it states no role framing
  at all (NDA-D-025).
- **IPDATA-001 could not read a plain-English ownership allocation.** "All
  rights remain with Discloser" and "all materials Contractor produces belong
  to Client" both name the owner; neither matched.
- **`unilateral-nda-deep` penalized its own document.** It carried "each party"
  and "either party" as NEGATIVE features, meaning "this is not mutual" — and
  both are ordinary boilerplate in a unilateral NDA ("Each party represents
  that it has the authority…", "amended only by a writing signed by either
  party"). Replaced with markers that actually mean mutual: "each party may
  disclose", "both parties may disclose", "each party's confidential
  information".
- **`mutual-nda-deep` claimed "either party" as a distinguishing phrase**,
  which matches 67 of 238 specimens. The matcher's own comments already blamed
  that phrase for taking a trademark coexistence agreement.

### Changed
- `mutual-nda-deep` and `unilateral-nda-deep` inherit the rule profile their
  deprecated predecessors already carried — the six FIN skips, the four PERS
  skips, RISK-001 at `info` — plus RISK-005, TERM-002 and TERM-005, which an
  NDA does not carry by design. They shipped with an empty `rule_overrides`,
  which only mattered once the promotion put them on the auto-routed path.

## [9.273.0] — 2026-08-31

### Changed
- **A deprecated playbook no longer beats its own successor.** `mutual-nda` and
  `unilateral-nda` have carried `"deprecated": true` with `"superseded_by"`
  since the deep families landed, and `docs/adding-a-playbook.md` says that
  metadata exists so "a successor playbook … outranks its legacy v2 sibling".
  The whole of the mechanism was a TIEBREAK, and it never fired: the legacy
  family carries `required_clauses`, worth 0.4 each against a title keyword's
  0.3, and its successor carries none — so `mutual-nda` scored 1.0 against
  `mutual-nda-deep`'s 0.9 on every NDA and won outright. **The consequence was
  not a label. NDA-D-001..023 are scoped to the `*-deep` families, so the most
  common contract there is received no NDA-specific analysis at all on the
  auto-routed path**: a deliberately deficient mutual NDA — no exclusions, no
  defined "Confidential Information", an obligation that "lasts forever" — drew
  seven findings, none of them about any of that, and now draws eleven
  criticals that are all on the page. The promotion is conservative: it applies
  only when the named successor is itself a candidate clearing the threshold on
  its own merits. Both legacy families remain reachable by an explicit
  `--playbook` and by a golden's sidecar pin, and the v2 launch-only corpus is
  unaffected because the deep families are not among its candidates.

### Fixed
- **NDA-D-017 and NDA-D-018 could not read "New York law governs".** Both
  wanted "the laws OF X" and neither read the adjectival form, so an NDA whose
  last sentence picks New York was told it picks no governing law — and then
  told that the jurisdiction it could not read was an unusual one. The
  extractor has read both forms since v1; these rules carried their own
  narrower copy.
- **NDA-D-007's window was two characters too short for the standard
  exclusion.** "Was rightfully known to the Receiving Party without restriction
  before disclosure" puts 42 characters between "known" and "before" against a
  40-character cap. Widened to 80 and bounded at a semicolon as well as a
  period, so the wider window cannot pair one lettered carve-out's "known" with
  the next one's "prior to disclosure".

## [Unreleased]

### Known
- **`expected_clauses` and `expected_defined_terms` reach no consumer.** 267
  playbooks declare them with per-item severities; the engine's `Playbook` type
  carries `id`, `version` and `rule_overrides` and nothing else, so they are
  stripped at the boundary and no rule can see them. A deliberately deficient
  mutual NDA — no exclusions, no defined "Confidential Information", an
  obligation that "lasts forever" — draws no finding for either of the two
  expectations `mutual-nda` marks `critical`. The casing corroborates it: the
  ~120 declarations mix kebab-case categories with Title-Case prose ("Order of
  Precedence"), because nothing ever rejected one. Filed rather than wired:
  wiring it adds findings to every document in the corpus and is a product
  decision. See BUILD_PROGRESS Step 255.

## [9.272.0] — 2026-08-31

### Added
- One specimen — a work-made-for-hire agreement for commissioned illustration,
  animation and score, the 237th, and the first for `work-for-hire-agreement`.

### Fixed
- **A BACKWARDS negative feature.** `work-for-hire-agreement` carried "royalty"
  as a negative feature, and every work-for-hire agreement licenses the
  contractor's pre-existing material "royalty-free" — so the family lost 0.1 on
  the standard clause it exists to read. Narrowed to "royalty rate" and
  "royalties payable", which are the true licence-deal markers.
- **The sibling steal runs the other way.** `independent-contractor`'s three
  required clauses — ip-ownership, term, termination-for-convenience — are
  clauses a work-for-hire agreement necessarily has, so it took the document at
  1.0 and the § 101 ruleset never ran. It now names the work-for-hire markers
  ("work made for hire", "specially ordered", "specially commissioned", "backup
  assignment") as negative features. `specimen-routing-margin` caught the first
  attempt, which only produced a 0.9 tie decided by a lexicographic id
  comparison.
- **RISK-011 could not read the British spelling of a defence.** "gives
  Contractor control of the defence" is the textbook clause in a UK or
  Commonwealth indemnity, and this repo already reads "licence" beside
  "license" for the same reason.

## [9.271.0] — 2026-08-31

### Added
- One specimen — a founder restricted stock purchase agreement, the 236th, and
  the first for `rspa`.

### Fixed
- **A defective founder RSPA drew ZERO findings.** Four of the family's five
  distinguishing phrases — "repurchase right", "83(b)", "stock power", "escrow"
  — are the clauses EQT-036..042 require. An agreement that takes a promissory
  note for the purchase price and states no 83(b) advisory, no escrow, no stock
  power, no right of first refusal, no restricted-securities legend and no
  lock-up scored 0.3 on its title — an exact title keyword — and fell to
  `generic-fallback`. It now routes at 0.9 and draws five findings, three of
  them critical. The standalone § 83(b) election FORM is excluded by negative
  feature so it keeps its own family.
- **EQT-041 could not read the textbook lock-up.** A market stand-off is
  written as a covenant, not a heading: "Purchaser shall not sell any Share
  during the one hundred eighty (180) days following the effective date of the
  Company's initial public offering, if the managing underwriter so requests."
  It uses neither term of art, and the `180\s+days` branch could not read the
  numeral where every American agreement puts it — inside the parenthetical
  after the spelled number.
- `rspa` shipped with an empty `rule_overrides`, so a stock purchase was told
  it states no payment terms, allocates no intellectual property, states no
  indemnity, caps no liability, and gives no path to terminate for cause.

## [9.270.0] — 2026-08-31

### Added
- One specimen — a model automatic-renewal page, the 235th, and the first for
  `auto-renewal-terms`.

### Fixed
- **The ROSCA checks were written in the regulator's words; a compliant page is
  written in the subscriber's.** COMM-231 required "clearly and conspicuously"
  or "before obtaining billing information" — the statute's phrases, which a
  page required to be understandable has every reason to avoid — and read the
  adverb only before the verb. A page that says "your subscription renews
  automatically" and "before you pay, we show you" drew a `critical` for a
  disclosure that is its entire first section.
- **COMM-233's two pillars were joined by an OR**, so the bare word "cancel"
  satisfied "Simple cancellation mechanism" — and the page its own rationale
  calls the paradigm violation ("to cancel, call our support line and speak to
  a retention specialist; cancellations by email or through the website are not
  accepted") passed it clean. The name states a conjunction: cancellation AND
  simplicity. The second pillar now also reads the subscriber's words ("one
  step", "in your account", "the same means you used to buy it"), and
  deliberately does not read a phrase naming the CHANNEL — the paradigm
  violation names the same channel to refuse it.
- **A second family routed on its own compliance.** `auto-renewal-terms`
  claimed "cancel at any time", "renewal price", "before the renewal date" and
  "cancellation instructions" — phrases a compliant page carries and an
  abusive one does not. A page that renews automatically, cancels by telephone
  only and refuses refunds scored 0.3 on its title alone and fell to
  `generic-fallback`, so none of the six ROSCA checks ran on it. It now routes
  at 0.7 and draws five of them, two at `critical`.
- `auto-renewal-terms` shipped with an empty `rule_overrides`, so a published
  terms page forming part of a subscriber agreement was told it has no
  signature block, no governing law, no venue, no payment terms, no IP
  allocation, no indemnity, no liability cap and no termination clause.

## [9.269.0] — 2026-08-31

### Added
- One specimen — a Colorado non-competition and non-solicitation covenant, the
  234th, and the first for `employment-restrictive-covenant`.

### Fixed
- **NINE CRITICALS about an NDA the document is not.** A covenant headed
  NON-COMPETITION AND NON-SOLICITATION AGREEMENT routed to `mutual-nda-deep`
  and was told it defines no Confidential Information, states no
  publicly-available exclusion, and requires no return or destruction — because
  the family's title keywords were written as exact full titles ("non-compete
  agreement", "non-competition agreement") and the words "and
  non-solicitation" sit between them. The EMP-024..031 ruleset never ran.
- **EMP-027 accepted `worldwide` as evidence of a bounded geographic scope**,
  on a rule whose own explanation reads "open-ended geographic scope is
  unenforceable". The paradigm case of the abuse satisfied the check. The
  alternatives it stood beside were no better: bare `scope` is in "the scope of
  this Agreement" and bare `state`, with no word boundary, is inside "the State
  of Delaware" in every governing-law clause and inside "reSTATEment".
- **EMP-025 reported a three-year worldwide non-compete as having no duration,
  at `critical`.** Every duration pattern wanted the word "non-compete" within
  80 characters, and a standalone covenant agreement writes that word in its
  title and nowhere else. It now reads the duration where a covenant states it
  — in the restriction sentence: "During the three (3) years following the
  termination of Employee's employment …, Employee shall not …".
- `employment-restrictive-covenant` shipped with an empty `rule_overrides`, so
  a restrictive covenant was told it allocates no intellectual property, states
  no indemnity, caps no liability, and gives no path to terminate for cause.
  A covenant does none of those things by design; it survives termination.

## [9.268.0] — 2026-08-31

### Added
- One specimen — an executed UK IDTA, the 233rd, and the first for
  `uk-idta-addendum`.

### Fixed
- **The adoption sentence is written in either order.** The Commission's
  wording puts the verb first — "the parties adopt the standard contractual
  clauses … in full" — and the ICO's puts the form's name first — "The
  Mandatory Clauses are incorporated in full and without amendment". A single
  ordered pattern read one and not the other, so yesterday's fix reached the
  EU form and not the UK one. The three parts (the form's name, an adoption
  verb, an in-full qualifier) are now required in one sentence, in any order.
- **The vocabulary a regulator's form defines was reported as terms the
  document forgot to define.** An executed IDTA drew STRUCT-006 for six
  Title-Case terms — Appropriate Safeguards, Approved Addendum, General
  Authorisation, Information Commissioner among them — every one of which is
  defined in the Mandatory Clauses it adopts. `borrowsParentVocabulary()` knew
  about a commercial form named in title case ("the IAB Standard Terms and
  Conditions") and not about a regulator's.
- **References INTO the adopted form were reported as references the document
  broke.** An IDTA is Part 1's four tables and Part 2's Mandatory Clauses, and
  it points into those clauses by bare section number: "as set out in Section
  19", "as Section 18 permits". It has no Sections of its own for them to
  resolve against. Same shape as the GDPR-article exemption STRUCT-007 already
  carries.
- **A VERSION STRING is not an attachment designator.** "the template Addendum
  B.1.0 issued by the Information Commissioner" appears in every executed IDTA,
  and STRUCT-018 reconciled a reference to "Addendum B" the document never
  makes. A letter designator followed immediately by a dotted number is a
  version; an ordinary sentence break ("Exhibit A. 3 copies shall be
  delivered") is not.
- `uk-idta-addendum` now also skips CHOICE-001 and CHOICE-003: Section 17 of
  the Mandatory Clauses fixes the governing law and the forum, and an addendum
  never states them itself.

## [9.267.0] — 2026-08-31

### Added
- One specimen — an executed EU SCC Module Two set, the 232nd, and the first
  for `scc-module-2`.

### Fixed
- **THIRTEEN CRITICAL false accusations against a correctly executed EU form.**
  An SCC Module Two set is a cover page, a list of option selections, and three
  completed annexes. Clause 8's documented-instructions obligation, Clause 8.5's
  deletion-or-return, Clause 8.6's breach notification, Clause 9's sub-processor
  flow-down and the rest of Article 28(3) live in the Commission Implementing
  Decision the document adopts in full — and Clause 2 (invariability) is why a
  well-drafted set does not restate them. The Article 28(3) ruleset, which this
  family exists to re-run *by reference*, found none of the words and reported
  ten of the clauses missing at `critical`, alongside three per-clause SCC
  checks. `adoptsStandardFormInFull()` is the `amendsParentAgreement()` of that
  relationship, and it is applied **per rule**: the checks for Annex II and
  Annex III still fire on a set that arrives without them, which is the whole
  point of the family. The recognizer needs an adoption verb, the form's name,
  and an in-full qualifier in the same sentence — a DPA that merely says the
  parties "will enter into the SCCs if a transfer occurs" is excused nothing.
- **The Article 28(3) introductory clauses could not read the annex that
  carries them.** Annex I.B is headed "DESCRIPTION OF TRANSFER" and states the
  duration as "Period for which the personal data will be retained" and the
  nature and purpose under separate headings. DPA-001, DPA-002 and DPA-003
  wanted "subject-matter of the processing", "duration of the processing" and
  the single conjoined "nature and purpose of the processing", so all three
  fired at `critical` on a completed annex.
- **A completed form states its choices as labelled selections.** "Clause 17
  (Governing law): the law of Ireland" has no verb for any governing-law
  pattern to anchor on, so CHOICE-001 reported no governing law on a document
  whose Clause 17 names one, and CHOICE-003 no venue on one whose Clause 18(b)
  names the courts. Two corpus fixtures write it the same way in an ordinary
  contract — "Term. This Agreement continues for two (2) years. Governing Law:
  Delaware."
- `scc-module-2`, `scc-module-3` and `uk-idta-addendum` shipped with an empty
  `rule_overrides`, so a data-transfer annex was told it allocates no
  intellectual property, states no indemnity, caps no liability, and gives no
  path to terminate for cause. None of the five is part of an SCC set; the
  liability and termination terms are Clause 12 and Clause 16 of the form.

## [9.265.0] — 2026-08-31

### Added
- One specimen — a university exclusive technology-transfer licence, the 231st,
  and the first for `technology-transfer-agreement`.

### Fixed
- **A family whose routing was its own compliance checks.** Six of
  `technology-transfer-agreement`'s seven distinguishing phrases were the
  Bayh-Dole clauses its own checks require — "bayh-dole", "march-in rights",
  "government license rights", "substantially manufactured in the united
  states", "diligence milestones", "sponsored research". A university licence
  that recites none of them scored 0.5 on its title and the one remaining
  phrase, lost to `patent-license` at 0.6, and IPL-123 — the CRITICAL check for
  the government's retained licence in a federally funded invention — could
  only fire on a document that had already recited it. The phrases that
  identify a university licence whatever it says ("board of trustees", "office
  of technology", "sublicense income", "principal investigator", "research
  foundation") now carry the routing, and the same document draws the critical
  finding it should always have drawn. Checked across all 255 playbooks: no
  other family is routed on regulatory recitals this way.
- **A sovereign was reported as a term the document forgot to define.** A
  Title-Case phrase whose LEAD WORD is a state ("Ohio Public Records Act") has
  always been skipped, but `PLACE_NAMES` holds "United States" and "New York"
  as two words, so only their lead word — "United", "New" — was ever compared,
  and it matches nothing. STRUCT-006 told a university licence that the United
  States Government is undefined, and a patent assignment that the United
  States Patent and Trademark Office is — the office the assignment exists to
  be recorded with.

## [9.264.0] — 2026-08-31

### Fixed
- **An ALL-CAPS preamble turned two parties into four.** `PARTY_DECL` tells a
  name from prose by capitalization, and an instrument set in capitals from the
  caption to the signature offers no contrast at all: every word of "THIS
  AGREEMENT IS ENTERED INTO BY AND BETWEEN VERTEX SYSTEMS LLC" starts with a
  capital, so the name run walked back through the lead-in and registered a
  party named "ENTERED INTO BY AND BETWEEN VERTEX SYSTEMS" — carrying the real
  party's role — standing beside the real party that `BETWEEN_RE` read from the
  same sentence. Every rule that tallies by party counted the phantoms. The
  lead-in is now stripped from the front of the captured name, as whole words,
  so a name that CONTAINS one of them ("SMITH AND WESSON", "BANK OF AMERICA")
  keeps it.
- **An ALL-CAPS "among" list produced a party named "BETA CORP., AND GAMMA".**
  The guard that ends a name at the comma after its own suffix listed `[Cc]orp`
  and `[Ll]td` — neither of which matches "CORP" or "LTD" — so it silently did
  not apply to the case it was written for.
- **The second party of an ALL-CAPS preamble had no role.** `BETWEEN_RE`'s
  second capture terminates at the first sentence period, which is the one
  inside "INC.", so the role parenthetical fell outside it. In mixed case
  `PARTY_DECL` supplies the role from the same sentence; in capitals it could
  not see the suffix at all, and a roleless party is invisible to every rule
  that compares an obligor against the party set.
- **OBLI-002 read being REPRESENTED as making a representation.** A collective
  bargaining agreement is about representation from its first sentence — "the
  exclusive bargaining representative", "a joint safety committee with equal
  representation", "union representation at any investigatory interview" — and
  a bare `\brepresentation` matched all of them, telling the employer its
  warranties run one way. It now requires the contractual sense, the same
  narrowing the warranty pattern already carries. A distribution agreement lost
  the same false positive: its only "representation" was inside the indemnity,
  and it meant the distributor's sales talk to a customer.
- **OBLI-002 reported an asymmetry the document states mutually.** The
  obligation extractor triggers on "shall"/"will", so a section headed
  REPRESENTATIONS in which "Each Party represents that …" produced no
  obligation at all — while one sentence combining a duty with a representation
  produced one, and the teaming agreement was told its representations run one
  way. The rule now consults the document text for a reciprocal subject beside
  the same keyword before reporting.

## [9.263.0] — 2026-08-31

### Fixed
- **A party named the way American contracts name one was invisible.**
  `PARTY_DECL` — the pattern that reads `X, a Delaware corporation ("Provider")`
  and is the only path that captures a party's ROLE alongside its name — is
  case-sensitive by design, and every entity type in its list was written in
  lower case. Only the period-free abbreviations (`LLC`, `LLP`) had ever been
  added in their canonical capitalization, so `Vertex Systems, Inc. ("Vendor")`
  matched nothing at all, and `Corp.` was not in the list in any case. A
  short-form agreement — one that names its parties without the "a Delaware
  corporation" appositive to fall back on — reported no parties, and a party
  with no role is invisible to every rule that compares an obligor against the
  party set. This was filed rather than forced last release because the
  abbreviation period bled the role into the next sentence; the fix is to add
  the abbreviations WITHOUT it (`Inc`, not `Inc\.?`), which leaves the period in
  the text for the role gap's existing sentence guard to read.
- **"A Delaware corporation" was read as a party named "A Delaware".** The
  guard that stops a name from starting at the indefinite article matched only
  the lower-case article, and a cover block sets the entity descriptor on its
  own line, capitalized. `ingestPaste` joins those lines with a space, so
  "Alderbrook Instruments, Inc. A Delaware corporation Adopted by the Board …"
  arrived as one paragraph and the name run walked from the legal name straight
  through the article into the descriptor. The article is now matched in both
  cases, both before the name and between its tokens — and, where it separates
  the name from a real entity descriptor, read as the separator it is, so a
  policy's cover block now yields its subject and its state of formation.

### Changed
- Three specimens and two demo contracts gained an `info` OBLI-002, and one
  specimen a `STRUCT-017`, because the second party of each finally became
  visible: OBLI-002 compares sides and does nothing at all until it has two.
  Each is on the page — a Vendor-only IP indemnity in the AI addendum, a
  Vendor-only confidentiality duty in the security exhibit, a Kestrel-only one
  in the side letter, a Customer-only indemnity in the bad-MSA demo, and an
  assignment that declares a Counterparty and gives it no signature line.
- RISK-002 stopped listing signatories among its party tallies on the
  bad-SaaS-vendor demo. It has always dropped party entries carrying neither a
  role nor an entity type, but only once at least two entries survive the
  filter — and until the second party carried either, none did.

## [9.262.0] — 2026-08-30

### Added
- One specimen — a national trust company's BSA/AML compliance policy — the
  229th, and the first for `aml-policy`.

### Changed
- **The suite's default test timeout is 30s, not vitest's 5s.** Three kinds of
  test here cannot promise to finish inside five seconds when the whole suite
  runs at full parallelism: the ones that spawn the CLI as a subprocess, the
  ones that walk and scan every source file, and the ones that run every rule
  in the catalog against a probe document. Eight different tests were seen to
  time out across four loaded runs, each passing comfortably on its own — a
  false failure that says nothing about the code and costs a re-run to
  diagnose. A ceiling on a known-slow path, not a budget: a test that genuinely
  hangs still fails, thirty seconds later.

### Fixed
- **A third CRITICAL false accusation against model text.** POL-012 told a
  national trust company that it has no five-pillar AML program, on a policy
  whose §2 is headed "THE FOUR PILLARS AND THE FIFTH" and enumerates all five
  with the citation. The officer pillar read "compliance officer" and "AML
  officer" but not **BSA Officer** — the industry title in every US bank's
  program, and the regulation itself asks only for "a designated individual".
- **A REGULATORY INSTRUMENT read as an undefined term.** The Code of Federal
  Regulations names the Suspicious Activity Report; the policy does not define
  it because it does not have to. Keyed on the instrument noun and a federal
  citation in the same paragraph, so an ordinary "Annual Report" is untouched.

## [9.261.0] — 2026-08-30

### Added
- One specimen — a social media and external communications policy for a
  clinical-stage biotech — the 228th, and the first for
  `social-media-policy`. It reports nothing.

### Fixed
- **"Code ANNOTATED" is still a code name.** Half the states trail theirs that
  way — "Tennessee Code Annotated section 50-1-1003" — and the guard added in
  9.251.0 for the chapter-first citation style required the code word to be
  the last one before the section. A policy citing the Tennessee
  password-protection statute was told it points at a "section 50" it does not
  have.

## [9.260.0] — 2026-08-30

### Added
- One specimen — a flat-fee engagement letter for a startup formation and seed
  financing — the 227th, and the first for `flat-fee-agreement`.

### Fixed
- **A CRITICAL false accusation against a letter whose first section is headed
  THE CLIENT.** ENG-002 told a flat-fee engagement letter that it does not
  identify its client, on "Our client is Chandrasekaran Robotics, LLC only. We
  do not represent you individually, and we do not represent any **other
  member**, officer, employee, or investor of the company." The disclaimer
  pillar wanted the constituent noun immediately after "any" and in the plural,
  and it read the client-naming form only when "only" came first. A disclaimer
  of the individual alone — "we do not represent you individually" — is now
  read too.
- **The flat-fee checks never ran on a flat-fee letter.** It routed to
  `engagement-letter` on "legal services agreement" in its title, so
  earned-on-receipt, the refund of the unearned portion, and the out-of-scope
  list all went unchecked. The flat-fee family's title keywords were three
  exact full titles; "flat fee" and "fixed fee" now sit beside them, and the
  letter routes at 1.0.

## [9.259.0] — 2026-08-30

### Added
- Two specimens — a nonprofit conflict-of-interest policy adopted from the
  IRS's own model text and a Delaware plan of dissolution and winding up — the
  225th and 226th, and the first for `coi-policy` and `dissolution-plan`.

### Fixed
- **A CRITICAL false accusation against the IRS's own model policy.** POL-034
  told a land conservancy that it has no annual disclosure clause, on a policy
  whose Article VI is headed "ANNUAL STATEMENTS" and reads "Each director,
  principal officer, and member of a committee … shall **annually sign a
  statement** which affirms …". That is the wording in the Form 1023
  instructions, which nearly every nonprofit adopts verbatim, and the check
  wanted the nouns "annual disclosure" or "annual certification".
- **The bare siblings of a declared code section read as broken
  references.** A plan of dissolution ties one section to the code — "as
  section 275 of the General Corporation Law of the State of Delaware
  requires" — and then cites its siblings bare: "as section 277 requires",
  "Under section 278", "the procedure of sections 280 and 281(a)". Five read
  as broken references to sections a ten-section plan does not have. The
  declaration matcher also required the label capitalized, and a plan writes
  it mid-sentence.
- **A single capital letter heads a phrase exactly as an acronym does.**
  "Series B Preferred Stock" — the Title-Case run needs a lower-case letter
  after the capital, so it breaks at the designator, and "Preferred Stock"
  arrived as a term the plan had supposedly forgotten to define. "A" and "I"
  are excluded: they are English words, not designators.
- **An instruction is not a promise.** FIN-007 reported an MFN clause on
  "terminate all leases and contracts on the most favorable terms REASONABLY
  AVAILABLE" — what the officers should get, not what anyone is promised. The
  qualifier is the discriminator: "Customer shall receive the most favorable
  terms available" is still an MFN.
- **A phrase followed by an IDENTIFYING NUMBER is an instrument**, so "Purchase
  Orders 44117, 44219, and 44320" no longer reads as an undefined term.

## [9.258.0] — 2026-08-30

### Added
- One specimen — a first set of FRCP 34 requests for production — the 224th,
  and the first for `document-requests`. It reports nothing.

### Fixed
- **A request set that defines its own Relevant Period was told it stated no
  time period.** DISC-003's second pillar wanted a scoping phrase — "unless
  otherwise stated", "these requests cover" — which is one way to bound a
  period and not the way a definitions section does it. What the pillar is
  actually for is that the period is BOUNDED, and `"Relevant Period" means
  January 1, 2023 THROUGH THE DATE of production` is bounded.
- **A phrase followed by an IDENTIFYING NUMBER read as an undefined term.**
  "Purchase Orders 44117, 44219, and 44320" is the sentence that says exactly
  which orders are meant; the Title-Case run stops at the digits, so the noun
  arrived on its own and the request set was told it uses a term "Purchase
  Orders" it never defined. Three digits or more, so an ordinal after a term
  is untouched.

## [9.257.0] — 2026-08-30

### Fixed
- **A term defined by its COMPOSITION read as undefined.** "The Contract
  Documents consist of the prime contract between Contractor and Owner, the
  drawings and specifications listed in Exhibit B, and all addenda and change
  orders" is the definition — and a subcontract puts that sentence in its
  scope-of-work article, where the unquoted definition matcher deliberately
  does not run. The subcontract was told it uses a term "Contract Documents"
  it never defined. "Consist of" and "comprise" are unmistakably definitional,
  which is what makes them safe to read outside a Definitions section;
  "means" is not read there, for the same reason it never was.

## [9.256.0] — 2026-08-30

### Fixed
- **An addendum was asked for the clauses that live in its parent.** Every
  HIPAA business associate agreement, data processing addendum, and security
  addendum opens the same way — "It **supplements** the Revenue Cycle Services
  Agreement between the parties dated January 12, 2026" — and none of them
  allocates intellectual property, caps liability, names an indemnity, or
  states a venue, because all four live in the parent.
  `amendsParentAgreement` knew the ratification recital ("remains in full
  force and effect"), the incorporation recital, and the borrowed-definitions
  recital, but not this one. Narrow in the same way as its siblings: the
  parent must be a NAMED, capitalized instrument, so "this Agreement
  supplements the parties' prior understanding" still names nothing and an
  ordinary contract that attaches an exhibit is untouched.

## [9.255.0] — 2026-08-30

### Added
- One specimen — a Minnesota marital settlement agreement — the 223rd, and the
  first for `family-msa`.

### Fixed
- **A divorce settlement was audited as a commercial contract.** `family-msa`
  carried an empty `rule_overrides`, so a marital settlement agreement was
  told it allocates no intellectual property, states no limitation of
  liability, caps no indemnity, names no procedure for the hold-harmless on a
  car loan, states no path to terminate for material breach, and states no
  effect of termination. It now carries the `cohabitation-agreement` profile —
  the fullest family-law profile in the catalog — plus TEMP-012, because a
  survival clause that enumerates indemnification is a commercial convention
  and a marital settlement survives as an independent contract instead.
- **Personal health coverage is not a coverage requirement.** RISK-016 read
  "Wife shall maintain health and dental insurance for the Children through
  her employer while it is available at reasonable cost" as an insurance
  requirement with no stated minimum — a minimum no health-coverage clause has
  ever carried. Fixed at the rule level rather than skipped for the family,
  because the same sentence appears in every employment and physician
  agreement. A clause naming a liability policy beside a health policy is a
  commercial requirement and still reports.
- **A commercial lease titled "COMMERCIAL REAL ESTATE LEASE" scored no title
  weight.** It still routed, at 0.6 — one feature from the 0.5 cliff below
  which a document reaches no family at all.

## [9.254.0] — 2026-08-30

### Added
- Two specimens — a data licence with an explicit machine-learning restriction
  and a relocation assistance and repayment letter — the 221st and 222nd, and
  the first for `data-license-agreement` and `relocation-agreement`. The data
  licence was clean on arrival.

### Fixed
- **A relocation letter routed to `offer-letter`.** The offer-letter family won
  on three phrases every relocation letter carries — "start date", "base
  salary", "at-will" — and the document was then asked for the
  pre-employment-check and plan-subject clauses an offer letter carries. The
  relocation family's title keywords were four exact full titles ("relocation
  assistance agreement", "relocation repayment agreement"), and a real
  document combines two of them: "RELOCATION ASSISTANCE AND REPAYMENT
  AGREEMENT" matched none, so it scored no title weight at all. It now routes
  at 1.0.
- **"Any amount you owe … is due within sixty (60) days" read as no payment
  term.** FIN-005's subject alternation held "amount due" and "amount owed"
  but not the amount a PERSON owes, and the branch that needs no subject
  requires the deadline to run from an invoice or a receipt.
- **`relocation-agreement` carried an empty `rule_overrides`**, so a
  relocation letter was asked for an IP-ownership clause, an indemnity, a
  limitation of liability, and an effect-of-termination clause. It now carries
  the `remote-work-agreement` profile, its nearest sibling.

## [9.253.0] — 2026-08-30

### Added
- **The boilerplate-satisfaction guard now covers the v4 rules too.** A
  `V4_PRESENCE_SPECS` registry mirrors `PACK_SPECS`, so the same probe reaches
  all 740 v4 presence rules as well as the 621 v5 columns. The skeleton is
  deliberately neutral — a preamble, a definitions cross-reference, and an
  intent recital — because every extra phrase in it is a phrase some rule is
  right to read.

### Fixed
- **Twenty-two v4 presence rules were satisfied by a document that says
  nothing.** All of them are multi-pillar checks named for a conjunction, and
  in each one a single over-generic pillar carried the whole check:
  - **A missing word boundary.** `cap` matched inside "**Cap**italized"
    (MNA-059, BNK-008, BNK-024); `end` inside "int**end**" (SET-022); `sec`
    inside "**Sec**tion" (POL-023, POL-025, POL-031); `pi` inside
    "Ca**pi**talized" (HC-007); `give` inside "**give**n" (EST-005); `term`
    inside "**term**s" (IPL-022); `capitaliz` matching "Capitalized terms" on a
    trademark-usage check (IPL-016); `on 1` inside "Secti**on 1**" (HC-014);
    and a bare `to` (INS-002), which matches every document ever written.
  - **A pillar that is not a signal at all.** HC-020 ("Date of receipt") and
    INS-009 ("Effective date of endorsement") each listed `\d` — so any
    document containing a digit scored clean.
  - **A locator that every document carries.** MNA-043 wanted "Section 1" and
    "Schedule 1"; the decimal is the discriminator, because a disclosure
    schedule keyed to an SPA's representations numbers itself "Schedule 3.12".
    INS-008 and PRV-012 became conjunctions for the same reason — a year alone
    is not an effective date.
- **A policy section is numbered with a ROMAN numeral.** Tightening INS-008's
  locator to require a digit would have reported "Section II — Who Is An
  Insured is amended" as identifying nothing.

## [9.252.0] — 2026-08-30

### Added
- **A guard against a check that cannot fail.** The existing reachability
  guards ask whether a rule can FIRE at all — title vacuity,
  self-reachability. `boilerplate-satisfaction.test.ts` asks the other
  direction, which is where the quieter failure lives: a check whose patterns
  are matched by the skeleton every contract carries is silent on every
  document, and a silent check reads to an attorney exactly like a clause that
  is present and correct. It probes patterns directly through `PACK_SPECS`, so
  a conditional column ("Crummey withdrawal rights where applicable") is still
  free to stay silent.

### Fixed
- **Eight compliance-matrix columns were satisfied by a document that says
  nothing** — a preamble, a definitions cross-reference, and a signature
  block. Two causes:
  - A pillar with no word boundary. MNA-105 ("Indemnity, caps, baskets, and
    survival") and SET-139 ("Proceeds waterfall and return cap") both listed
    the bare word "cap", which matches inside "**Cap**italized terms have the
    meanings given in Section 1" — so a purchase agreement with no cap, no
    basket and no survival period passed on the strength of its definitions
    cross-reference.
  - A LOCATOR pillar joined by an OR. "Arbitration clause quoted AND located"
    (SET-123), "Background IP identified AND licensed" (IPL-116), "Amount or
    percentage AND valuation date" (EST-420), "Amended provisions restated in
    full" (EST-416), "Nunc pro tunc effective date" (IPL-104) — each names two
    things, and each had its second pillar written as something every document
    carries: a section number, a date, the word "identified". `pat` defaults
    to an OR, so the locator alone scored every document clean. Six are now
    conjunctions; MNA-108 keeps its OR, because a singly-named "Assigned
    Contract" identifies what moved just as a schedule does, and its generic
    pillar was tightened instead.
- **IPL-104 now reads retroactivity in SUBSTANCE.** A patent assignment writes
  it as the reach-back itself — "effective as of the earlier of the date of
  execution and the date each Assignor conceived or first reduced the
  inventions to practice" — and under the new conjunction, reading only the
  word "retroactive" and a literal date would have reported that assignment as
  having no nunc pro tunc date at all.

## [9.251.0] — 2026-08-30

### Added
- One specimen — an FLSA primary-beneficiary internship agreement — the 220th,
  and the first for `internship-agreement`.

### Fixed
- **A for-cause path stated as ENUMERATED GROUNDS was read as no path at
  all.** A regulated-services agreement does not write "material breach"; it
  names the grounds — "Hospital may terminate immediately upon: (a) suspension,
  revocation, or restriction of Medical Director's license or DEA registration
  … (d) failure to maintain the insurance required by Section 10". Every
  branch of TERM-002 wanted the noun "breach" or the phrase "for cause", so a
  medical director agreement with a full Termination section was told it states
  no path to terminate for material breach. The enumeration is what separates
  this from a convenience clause, which still reports.
- **"End the internship" was not a termination verb.** The list held "end the
  membership" alone, so an internship agreement's §7.2 cause clause was
  invisible.
- **A subsection number in a survival list stopped the effect-of-termination
  window.** TERM-005 scans one sentence with `[^.]`, and "On the end of the
  internship for any reason, Sections 4, 5, 7.3, and 8 continue in effect, the
  Intern returns Company property" stops dead at the period inside "7.3". A
  period followed by a DIGIT is a decimal or a subsection number, never the end
  of a sentence.
- **The consequence verbs had no inflections.** `return`, `destroy`, `delete`,
  `purge`, `transition`, `export`, `refund` and `discontinue` were listed bare,
  so "the Intern RETURNS Company property" did not match while "shall return"
  did — and a GDPR DPA whose §11 is the Article 28(3)(g) clause ("the Processor
  DELETES OR RETURNS all Personal Data … after the END of the provision of
  services") was told it states no effect of termination. "End" is now a
  termination trigger alongside "termination" and "expiration".
- **A statute cited CHAPTER-FIRST read as a broken internal reference.**
  "Massachusetts General Laws chapter 149, section 24L" puts a division between
  the code's name and the section, and the leading-code guard wanted them
  adjacent — so an internship agreement citing the Massachusetts ban on
  noncompetes with a student was told it points at a section it does not have.
  New York and Texas cite the same way.
- **`internship-agreement` carried an empty `rule_overrides`**, so an
  internship agreement was asked for an indemnity and a limitation of
  liability. Narrowly scoped to those two: an internship agreement with no IP
  assignment or no termination terms is still worth reporting.

## [9.250.0] — 2026-08-30

### Added
- Two specimens — a bank's business continuity and disaster recovery plan and
  a Regulation D Rule 506(b) subscription agreement for seed preferred — the
  218th and 219th, and the first for `business-continuity-plan` and
  `subscription-agreement`. The continuity plan is the first specimen that
  reports nothing at all.

### Fixed
- **A party named only by a DESCRIPTOR was lost, because its role
  parenthetical carried an article.** `ROLE_PAREN` required the quote to open
  the parenthesis, so "and the undersigned subscriber (the \"Subscriber\")"
  yielded no party: a subscription agreement had one of its two sides, and
  OBLI-002 reported that only the Company indemnified — in a section where each
  side indemnifies the other, sentence by sentence.
- **A comma INSIDE a parenthetical ended the preamble capture.** A collective
  role is written with one — "(each, a \"Purchaser\")" — and the capture
  stopped at the comma, losing the role and with it the only handle a
  descriptor-named party has.
- **A CITY was reported as a term the document forgot to define.** A continuity
  plan names its alternate site once in full — "the co-location facility in
  Sioux Falls, South Dakota" — and twice more bare, so skipping only the
  qualified occurrence left the other two to clear the two-occurrence floor.
  A place is now dropped wherever it appears, as a signatory and a case name
  already were.
- **A department named after the person who LEADS it was reported the same
  way.** "The head of Corporate Communications" puts a lower-case noun before
  the "of", so it is not part of the Title-Case run and the unit's name arrived
  as its own candidate.
- **A body the document CONSTITUTES was reported as undefined.** A plan that
  says "The Crisis Management Team is chaired by the Chief Operating Officer
  and includes …" has constituted the body, not left a term undefined — the
  same case as an office. "Committee" was already excluded; "Team", "Panel",
  "Task Force", "Working Group" and "Subcommittee" now sit beside it.
- **`subscription-agreement` carried an empty `rule_overrides`.** A one-time
  purchase that CLOSES was told it states no path to terminate for material
  breach, no effect of termination, no payment term, no IP allocation, and no
  limitation of liability. It now carries the `secondary-stock-transfer`
  profile, whose five skips are exactly those five accusations.

## [9.249.0] — 2026-08-30

### Added
- Two specimens — a university technology transfer licence on Bayh-Dole
  architecture and a UCC Article 2 master purchase agreement for machined
  goods — the 216th and 217th, and the first for `master-purchase-agreement`.

### Fixed
- **The tail of an organizational unit's name was reported as a term the
  document forgot to define.** The Title-Case run breaks at a lower-case "of",
  so a licence signed by its "Office of Technology Transfer" was told it uses
  "Technology Transfer" without defining it, and a WARN notice issued by an
  "Office of Economic Development" and copied to a "Director of Human
  Resources" was told the same of both. The existing rules-citation guard
  already handled "Ohio Rules of Professional Conduct"; the organizational
  nouns now sit beside it. A document TITLE after "of" — "Statement of Base
  Services" — is still reported, because that is a title the drafter left
  undefined rather than the name of a body.
- **COMM-107 could not read the price terms its own recommendation asks
  for.** The check's `fix` says to "attach a price schedule and state the
  adjustment mechanism … annual negotiation with a cap"; a master purchase
  agreement drafted to exactly that was told no clause addressed "price, price
  adjustment, and payment", because the patterns wanted the NOUNS "price list",
  "price schedule" and "price adjustment". Its own sibling COMM-102 already
  read "unit price" and "the price set forth"; the two vocabularies now agree,
  and the adjustment branch reads the verb as well as the noun.
- **A signatory was counted as a party bearing indemnity.** RISK-002 seeded
  its tally from every extracted party, so the natural persons who SIGN sat at
  zero and dragged `min` down until an ordinary two-versus-one split cleared
  the `max - min >= 2` threshold. A master purchase agreement in which each
  side indemnifies the other was reported as one-sided, and a staffing
  services agreement's genuine 2:1 — inside the rule's own tolerance — was
  reported for the same reason. An individual who is genuinely a party is
  introduced with a role and is still counted.
- **Sixteen families penalized the independent-contractors clause that every
  commercial agreement carries.** `employment` was listed as a negative
  feature, and "nothing in this Agreement creates a partnership, joint
  venture, agency, or employment relationship" is boilerplate, not a signal
  that the document is an employment agreement. Narrowed to "employment
  agreement" across all sixteen; only one had a specimen able to expose it.

## [9.248.0] — 2026-08-30

### Added
- Two specimens — an AI acceptable use policy written to the NIST AI RMF and
  the EU AI Act, and an owner-architect agreement on AIA B101 architecture —
  the 214th and 215th, and the first for `ai-aup-policy` and
  `architect-agreement`. Between them they surfaced every fix below.

### Fixed
- **A phrase headed by an acronym was reported as a term the document forgot
  to define.** The Title-Case scanner cannot cross an all-caps word, so a
  capture that begins immediately after one is the tail of a longer phrase —
  and naming it names something the document never wrote. An AI policy that
  maintains an "AI Tool Register" was told it uses "Tool Register" without
  defining it. This had been patched for a fixed list of OFFICE abbreviations
  (`VP`, `CISO`); the shape is general, and every domain has its own acronyms
  (`IT Service Desk`, `HR Business Partner`, `FDA Advisory Committee`).
- **A sentence-initial connective was read as the head of a defined term.**
  "After", "Before", "During", "Upon" and "Notwithstanding" were all treated
  as connectives and "Following" was not, so an owner-architect agreement that
  paces each phase on "Following Owner's written approval …" was told it uses
  an undefined term "Following Owner". Twenty-five siblings added with it.
- **A reservation of copyright was not read as an allocation of IP
  ownership.** IPDATA-001's retention branch wanted "retains all rights IN
  <object>" adjacent. The standard American owner-architect sentence — "the
  Architect and its consultants retain all common law, statutory, and other
  reserved rights, including copyright, in the Instruments of Service" — puts
  the adjectives and an appositive in between, so an agreement whose §7 is
  titled Instruments of Service was told it allocates no IP at all.
- **"To the fullest extent permitted by law," was not a recognized fronted
  adverbial**, though "to the extent" was. It is the opening of nearly every
  indemnity clause written in the United States, and the obligor of the
  sentence came out as "fullest extent permitted by law, Architect" — which
  matches no party, so OBLI-002 reported that only the Owner indemnified, on
  the very sentence where the Architect indemnifies the Owner.
- **A document TITLE was read as the party clause.** "AGREEMENT BETWEEN OWNER
  AND ARCHITECT FOR DESIGN SERVICES" is the AIA B101 title and names two
  ROLES, never two parties; it registered "OWNER" and "ARCHITECT FOR DESIGN
  SERVICES" as the contracting entities. The same title restated at the head
  of the preamble also beat the real party clause later in the same sentence,
  publishing a party named `Architect (this "Agreement") is made as of April
  6`. A cover block does the same thing vertically, and registered a party
  named "OPERATING AGREEMENT OF HARBOR POINT VENTURES LLC".
- **An adjective between the formation state and the entity type dropped the
  party's ROLE.** "A Pennsylvania NONPROFIT corporation" and "a Pennsylvania
  LIMITED LIABILITY partnership" did not match, so the role parenthetical that
  follows was never reached — and a party with no role is invisible to every
  rule that compares an obligor against the party set.
- **A party whose entity type is written `LLC` or `LLP` was found with no
  role, or not at all.** The declaration pattern is case-sensitive and every
  entity type in it was lower case, so it could only ever find a party trailed
  by a lower-case long-form descriptor. The canonical capitalizations of the
  period-free abbreviations are now listed exactly. (The abbreviations that
  end in a period — `Inc.`, `Corp.`, `Ltd.` — remain outstanding; they
  interact with the sentence-boundary guard on the role parenthetical.)
- **A firm name broke at its ampersand.** "Vessel & Roark Architects LLP"
  registered twice, once whole with no role and once as "Roark Architects LLP"
  with the role.
- **A role parenthetical introduced by an article was dropped.** The quote had
  to open the parenthesis, so `(the "Company")` — the most common form there
  is — did not attach.
- **The warrant INSTRUMENT was read as a warranty.** OBLI-002's warranty
  pattern was a bare `\bwarrant`, and on a warrant agreement every operative
  sentence names the security: the document was told its warranties ran one
  way.
- **A CLASS of counterparties was not counted as a side.** "Each Investor
  shall keep confidential …" names a party the extractor cannot register (the
  Investors sign a schedule), so an investor rights agreement binding the
  Company and every Investor alike was reported as binding only the Company. A
  class standing ALONE is mutual by construction, as "each party" already was.
- **A distinguishing phrase matched inside a word.** "Annex I", "Annex II" and
  "Annex III" all matched the single phrase "Annex III", so an AI policy
  citing Annex III of the EU AI Act collected three transfer-clause signals
  out of one sentence and tied the SCC Module 2 family. A phrase may still
  extend inside its own last word — that is how "stenographic" finds
  "stenographically" — but not when that token is too short to inflect.
- **A privilege log was identified by two phrases that do not distinguish
  one.** "Attorney-client privilege" and "work product" appear in every
  litigation hold, every engagement letter, and every AI policy that forbids
  pasting privileged material. Replaced with phrases only a LOG carries.

## [9.247.0] — 2026-08-30

### Added
- Five specimens — an FCPA/UKBA anti-bribery policy, a trademark coexistence
  agreement settling a TTAB opposition, a Delaware director indemnification
  agreement, a motor carrier transportation agreement, and an export control
  and trade sanctions policy — the 209th through 213th, and the first for
  `anti-bribery-policy`, `trademark-coexistence-agreement`,
  `director-indemnification-agreement`, `freight-transportation-agreement`, and
  `export-control-policy`.

### Fixed
- **Two playbooks that scored the same were not ranked the same.** Match scores
  are sums of decimal tenths, and three distinguishing phrases
  (`0.2 × 3 = 0.6000000000000001`) are not equal to two title keywords
  (`0.3 × 2 = 0.6`). A trademark coexistence agreement lost to `mutual-nda-deep`
  — on "each party", "either party", "irreparable harm" — by one part in 10^16,
  and was told at `critical` that it defined no Confidential Information, listed
  no exclusions, and had no return-or-destruction clause: nine criticals, none of
  which any coexistence agreement carries. Both scores were reported to the user
  as 0.6, and every tiebreak written for exactly this case was unreachable.
  Ranking now compares at the precision the scores are displayed in, and a new
  tiebreak prefers the family the document's **title** named over one that
  matched only body phrases.
  The coexistence family's own register was the deeper cause and is fixed too:
  it listed "shall not oppose" and "consent to registration", where the
  instrument says "will not oppose, petition to cancel" — so it now beats its
  runner-up on merit rather than on a tiebreak.
- **A term used in lowercase is used.** The defined-term use scan was
  case-sensitive, so a term the document writes in the other case — an
  anti-bribery policy that defines `"Government official"` and then says
  "a government official" throughout — was reported by STRUCT-005 as never used
  at all, while STRUCT-009 separately reported the same term as inconsistently
  capitalized. Both could not be true. A lowercase occurrence *before* the
  definition is still the ordinary noun a parenthetical is carved out of
  ("the premises located at 100 Building Way (the \"Premises\")"), and does not
  count.
- **POL-010 could not read the Act it is named for.** The rule matched
  `uk bribery act` with a space, which the American rendering "U.K. Bribery Act"
  never has, and required one of "failure to prevent", "cross-border", or
  "adequate procedures" — none of which appears in the rule's own recommendation
  ("apply the stricter standard"). A comprehensive FCPA/UKBA policy that names
  the Act in its first section was told it addressed neither.
- **IPL-113 reported the consent missing on a document that is the consent.** It
  looked for "consents to registration" adjacently and for "shall not oppose",
  where a coexistence agreement says "consents to Cellars' use and registration
  of the Cellars Mark" and "will not oppose, petition to cancel".
- **GOV-142 read the undertaking only as a noun.** "Indemnitee undertakes to
  repay the amounts advanced" is the ordinary § 145(e) drafting, and only
  "undertaking to repay" matched.
- **FIN-005 led on `shall`.** "Shipper will pay undisputed amounts within thirty
  days after receiving a complete invoice" is a plainly stated payment term, and
  both active-voice branches required `shall`.
- **FIN-008 quoted the sentence denying the clause it reported.** "This Agreement
  does not commit Shipper to tender any minimum volume" was read as a
  minimum-commitment clause: the shared clause-absence guard knew "does not
  obligate" but not "does not commit".
- **Three families shipped with an empty rule profile.**
  `trademark-coexistence-agreement`, `director-indemnification-agreement`, and
  `freight-transportation-agreement` were asked for clauses their instruments
  never carry — an IP-ownership allocation in a carriage contract, a liability
  cap in a director indemnity, a mutual indemnity in a consent agreement.

## [9.246.0] — 2026-08-30

### Added
- Five specimens — a HIPAA business associate agreement, a GDPR Article 28 data
  processing agreement, a federal prime/subcontractor teaming agreement, a
  corporate acceptable-use policy, and a post-closing transition services
  agreement — the 204th through 208th, and the first for `baa`,
  `dpa-controller-processor`, `teaming-agreement`, `acceptable-use-policy`, and
  `transition-services-agreement`.

### Fixed
- **A GDPR DPA is not a CCPA contract.** The US-state privacy ruleset was scoped
  to `dpa-controller-processor` — a family whose own name is "DPA — Controller
  to Processor (EU/UK)", whose `regulator_frame` is GDPR, and whose 55 rules all
  cite an Article of the GDPR. A textbook Article 28 agreement between a German
  controller and an Irish processor was told, at `critical`, that it was missing
  the CCPA purpose-limitation clause, the no-sale prohibition, the cross-context-
  advertising prohibition, and seven more — ten criticals no compliant EU DPA
  could ever clear. A DPA that really does cover both regimes belongs in
  `dpa-multi-state-us`, which the EU/UK family now names as a companion.
- **Incorporation by reference is not absence.** TRANSFER-001..016 read the
  Standard Contractual Clauses CLAUSE BY CLAUSE, which is the right check for a
  document that IS the SCCs and the wrong one for a commercial DPA that
  incorporates them in a sentence. Six more criticals on the same document. The
  clause-text rules now run only on `scc-module-2` and `scc-module-3`; the
  cross-cutting transfer rules — adequacy fallback, transfer impact assessment,
  onward transfer — still run on the commercial DPA families, where they read on
  text those documents actually contain.
- **Article 28(3) names five things in one breath, and so does the drafter.**
  DPA-001 and DPA-002 required "subject-matter" and "duration" to sit ADJACENT to
  "of the processing", so the one form every commercial DPA uses — the heading
  "SUBJECT MATTER, DURATION, NATURE AND PURPOSE" and the sentence under it —
  was the one form that could not match. DPA-007 read "instructions FROM the
  Controller" but not the equally standard possessive, "only on the Controller's
  documented instructions".
- **A teaming agreement routed to `eula`.** The family named for it matched its
  title exactly and still scored 0.3 against a 0.5 threshold, because all six of
  its distinguishing phrases were unreachable: four carried a leading "the" or
  were whole sentence fragments ("if the prime is awarded"), and none appears in
  a teaming agreement as anyone drafts one. `eula` won at 0.6 on "license to
  use", "non-exclusive", and "software". The phrases are now the register a
  federal teaming agreement is actually written in.
- **A policy states its adoption as a labelled field.** STRUCT-003 already knew a
  policy is ADOPTED rather than signed, but read the adoption only as a sentence
  ("Approved by the Board of Directors on August 15, 2026"). A policy header
  writes it as "Approved by: the Information Security Steering Committee on
  December 18, 2025" — one colon between a clean policy and a `critical` "no
  signature block".
- **A TSA heads its schedule "SCHEDULE A - SERVICES".** MNA-055 read "Schedule of
  Services" and "services schedule" but not the lettered form every transaction
  document uses, so a transition services agreement carrying a five-line
  Schedule A — a service period and a monthly fee against each service — was
  told its scope schedule was missing, at `critical`, by the rule whose own
  recommendation asks for exactly what it had.
- **An EU DPA was one coin flip from the US catalog.** `dpa-multi-state-us`
  listed "personal data", "controller", and "processor" as its distinguishing
  phrases — the vocabulary of the GDPR family it sits beside, not of a US
  multi-state DPA — so it tied the EU/UK family at 0.9 on a document written in
  German-controller/Irish-processor terms, and which of the two won was a
  lexicographic comparison of their ids. Its phrases are now the US register:
  personal information, service provider, business purpose, sell or share,
  cross-context behavioral advertising, deidentified, and the four statute
  cites.
- **A BAA states its term from the other end.** BAA-038 read "terminates WHEN all
  PHI is destroyed" but not "continues UNTIL … all PHI is returned or
  destroyed", which is how a supplementing BAA states the same § 164.504(e)
  term. BAA-012 read "fails to cure" and "cure is not feasible" but not the
  thirty-day "has not cured … or immediately if cure is not possible" that a BAA
  actually drafts.

## [9.245.0] — 2026-08-29

### Added
- An exclusive right to sell listing agreement — the 203rd specimen, and the
  first for `listing-agreement`. RE-118..122 are all satisfied: the listing type
  with its period, the commission with a ready-willing-and-able trigger and the
  negotiability disclosure, the ninety-day protection period limited to a
  written registered-prospect list, the Idaho agency disclosure with informed
  written dual-agency consent, and the MLS and marketing authorizations with an
  Internet opt-out.

### Fixed
- **`listing-agreement` carried an empty `rule_overrides`.** A residential
  broker listing was told it does not allocate ownership of intellectual
  property and has no indemnity or limitation-of-liability clause. It now
  carries `residential-purchase-agreement`'s profile.

## [9.244.0] — 2026-08-29

### Added
- An enterprise information security policy — the 201st specimen, and the first
  for `information-security-policy`. POL-101..107 are all satisfied and the
  document is clean.
- A security incident response plan — the 202nd specimen, and the first for
  `security-incident-response-plan`. POL-126..132 are all satisfied: the NIST
  SP 800-61r3 lifecycle, a four-level severity matrix, the Incident Commander
  and counsel roles, evidence preservation with chain of custody, the GDPR /
  HIPAA / state / SEC notification clocks each with a named owner, vendor
  incident coordination, and the post-incident review.

  Both are clean because of 9.236.0: a policy is adopted, not signed, and each
  carries the adoption recital that stands STRUCT-003 down.

## [9.243.0] — 2026-08-29

### Added
- A petition for a writ of certiorari — the 200th specimen, and the first for
  `petition`.

### Fixed
- **A seventh thing above the title: the DOCKET NUMBER.** "No. 26-1147" opens
  an appellate caption and the court is named on the next line, so the caption
  reader — which required the court on the FIRST line — threw the whole caption
  away, and a petition whose own title keyword is exactly "petition for a writ
  of certiorari" fell to `generic-fallback`.
- **A federal statute cited WITHOUT the section sign read as a malformed case.**
  "28 U.S.C. 1254(1)" is the form the Supreme Court's own rules prescribe. Three
  fixes: the sign is now optional; a reporter token is never a BARE NUMBER (so
  two sign-less cites joined by the paste path no longer stitch into "volume 28
  of a reporter called U.S.C. 1254, page 42"); and "U.S.C." and "C.F.R." are
  code titles, never reporters.
- **A COURT is an institution the document names, not a term it defines.** A
  cert petition describing a circuit split writes "the Second, Third, Sixth, and
  Tenth Circuits" in every section that discusses it, and "Tenth Circuits" was
  reported as a term the petition forgot to define.
- **A letter closing after a SENTENCE END.** Stripping a document's blank lines
  merges the whole filing into one paragraph, so "Respectfully submitted,
  DEVARSHI NANDAKUMAR" no longer starts a line and the petition reported itself
  unsigned, at `critical`.

## [9.242.0] — 2026-08-29

### Added
- A § 423 employee stock purchase plan — the 199th specimen, and the first for
  `employee-stock-purchase-plan`. EQT-108..113 are all satisfied: the § 423
  qualification election with its Non-423 Component, the equal-rights and
  eligibility conditions, the $25,000 annual accrual limit, the 85% lookback
  price, the five-percent shareholder exclusion with § 424(d) attribution, and
  the withdrawal and termination rules.

### Fixed
- **A lettered statutory SUBSECTION read as a broken internal reference.** The
  plan cites § 423 with "of the Internal Revenue Code" attached and then cites
  §§ 414(q) and 424(d) bare, because in that document the Code is the only thing
  called a Section. A contract's own outline is decimal or roman; it is the
  statutes that number a bare three-digit section and split it with a letter.
  Corroborated on the document naming a code, so a contract that numbers its own
  sections 101, 102 and writes "Section 101(a)" is untouched unless it also
  names one.
- **A lowercase use INSIDE its own definition is the definition doing its job.**
  `"Common Stock" means the Company's common stock, par value $0.0001 per share`
  states what the term refers to, in the ordinary noun the term is built from.
  Every ESPP, charter, and note defines its stock that way, and STRUCT-014 asked
  the drafter to capitalize the words inside their own definition.

## [9.241.0] — 2026-08-29

### Added
- A first codicil to a will — the 198th specimen, and the first for `codicil`.

### Fixed
- **A codicil's references to the WILL's articles read as broken.** "I revoke
  Article VII of my Will in its entirety" cites the parent instrument, which
  this codicil does not contain — three of a clean codicil's cross-references
  reported as unresolved. Wills, codicils, and testaments join the
  external-instrument nouns.
- **And not always adjacently.** "every provision of my Will remains in full
  force and effect, including the tax-apportionment clause in Article VIII and
  the no-contest clause in Article IX" qualifies both articles by the sentence's
  subject. The corroboration is within ONE SENTENCE and deliberately confined to
  the testamentary instruments: an amendment to an ordinary agreement keeps the
  adjacency requirement, so a genuinely broken "Section 14.9" in it still
  reports.

## [9.240.0] — 2026-08-29

### Added
- A Form D narrative supplement — the 196th specimen, and the first for
  `form-d-narrative`. REG-001..007 are all satisfied: issuer identification
  with its jurisdiction, the Rule 506(b) exemption, accredited-investor
  representations with the verification contrast against 506(c), the
  general-solicitation prohibition, the Rule 506(d) bad-actor inquiry over
  every covered person, the offering amount with a minimum investment, and the
  NSMIA-preempted state notice filings.
- A digital advertising insertion order — the 197th specimen, and the first for
  `advertising-insertion-order`. COMM-168..172 are all satisfied.

### Fixed
- **The sixth half of `amendsParentAgreement()`: a named STANDARD FORM is a
  parent.** An insertion order says "This Insertion Order incorporates the IAB
  Standard Terms and Conditions for Internet Advertising … Version 3.0", and
  the standard form is where the governing law, the IP allocation, the
  indemnity, the liability cap, and the termination rights live. The IO drew
  six findings for clauses it deliberately does not restate. Case-SENSITIVE on
  the form's NAME, which is what keeps an ordinary "subject to the
  specifications set out in the attached schedule" out.

## [9.239.0] — 2026-08-29

### Added
- An irrevocable trust — the 194th specimen, and the first for
  `irrevocable-trust`. EST-401..407 are all satisfied: the express
  irrevocability recital, the three-pillar spendthrift provision, the HEMS
  ascertainable standard with its beneficiary-trustee limit, trustee powers
  with succession and removal, Crummey rights with notice and a 5-or-5 hanging
  power, the § 675(4)(C) substitution power with an Independent Trustee tax
  reimbursement, and situs with decanting.
- An FY2027 sales commission plan — the 195th specimen, and the first for
  `commission-plan`. EMP-109..114 are all satisfied.

### Fixed
- **A cover block may open with the company name.** A plan, a policy, and an
  order form open on a block of "Label: value" lines, and the cover-block
  reader required the FIRST label to open the paragraph — so "Halbrook
  Robotics, Inc. Plan Year: February 1, 2026 …" was not read as one, and
  STRUCT-006 reported "Plan Year" as a term the plan forgot to define, on the
  plan whose header defines it. The prefix must be a run of CAPITALIZED tokens,
  tested case-sensitively, which is what keeps the prose sentence this guard
  was written against ("… in accordance with the Wire Instructions: …") out —
  its first lowercase word ends the run.

## [9.238.0] — 2026-08-29

### Added
- A GSA Multiple Award Schedule contract — the 193rd specimen, and the first
  for `gsa-schedule-contract`. COMM-163..167 are all satisfied: the
  basis-of-award customer with its discount relationship and the GSAR 552.238-81
  Price Reductions clause, the industrial funding fee with quarterly sales
  reporting, Trade Agreements Act country of origin, FAR 8.4 ordering with
  order-level materials, and the FAR 52.217-9 option periods.

### Fixed
- **`gsa-schedule-contract` and `far-subcontract-flowdown` carried an empty
  `rule_overrides`.** A federal Schedule contract was told it has no governing
  law, no venue, no payment terms, no IP allocation, no indemnity, no liability
  cap, and no effect-of-termination clause. None of those belongs in a
  government contract: the Contract Disputes Act supplies the forum, the
  Anti-Deficiency Act forbids the indemnity, and FAR 52.212-4 supplies the
  termination terms by reference.
- **A REGULATION CLAUSE NAME read as an undefined defined-term.** "GSAR clause
  552.238-81, Price Reductions" and "FAR clause 52.225-5, Trade Agreements"
  name the regulation's clauses, not terms the drafter forgot to define, and a
  federal contract cites the same clause in several sections. The
  dotted-hyphenated FAR/GSAR/DFARS number is distinctive enough not to collide
  with a contract's own "Section 2.1".

## [9.237.0] — 2026-08-29

### Fixed
- **The adoption recital added in 9.236.0 matched nothing.** Its verb and its
  adopting-body alternations were spelled in lowercase in a case-SENSITIVE
  pattern, so "Adopted by the Board of Directors … on January 21, 2026" — the
  form every policy actually uses — never matched, and the conflict-of-interest
  policy fixture still drew a `critical` "no signature block". The pattern is
  now `i`-flagged with the month name in a case-sensitive lookahead, which is
  the only part that must stay case-sensitive. The STRUCT-003 test gained its
  load-bearing half: the same policy with the recital REMOVED still reports.
- The conflict-of-interest policy fixture added in 9.233.0 became entirely
  clean once the recital matched, which the v4 sanity guard rejects — a fixture
  must exercise something. It is now
  `compliance-coi-policy-missing-sanctions-fail.txt`, drawing POL-036, in the
  pass/fail shape the rest of the corpus uses.

## [9.236.0] — 2026-08-29

### Added
- An audit committee charter — the 191st specimen, and the first for
  `committee-charter`. GOV-051..060 are all satisfied: purpose, composition and
  independence under Rule 10A-3, the § 301 auditor-oversight authority, the
  complaint procedures with confidential anonymous submission, funding for
  advisors, at-least-quarterly meetings, the annual self-evaluation, regular
  reporting to the Board, and the annual charter review.
- A records retention and destruction policy — the 192nd specimen, and the
  first for `document-retention-policy`. POL-028..032 are all satisfied.

### Fixed
- **A POLICY is ADOPTED, not signed.** STRUCT-003 reported a `critical` "no
  signature block" on a records-retention policy — a finding with no answer,
  since nobody signs one. "Approved by the Audit Committee on March 2, 2026"
  names the BODY that executed it and the date it did so, and that is a
  corporate policy's whole execution. Narrow to an adopting body plus a date,
  deliberately: a bare "Effective Date:" appears on plenty of SIGNED contracts,
  and accepting that alone would silence the finding on a genuinely unsigned
  agreement.
- **STRUCT-009's attributive head nouns now cover the role and program forms.**
  A retention policy defines "Record" and then names the records MANAGER, the
  records LOG, and records TRAINING — none of which is the defined Record.

## [9.235.0] — 2026-08-29

### Fixed
- **A flat paste lost every party in the document.** Two independent causes,
  both found by running the format-invariance axes over the golden fixtures:
  - A PDF copy-paste merges the TITLE line into the paragraph below it, so
    "This Lease is between Landlord, REIT Holdings LLC, and Tenant …" no longer
    STARTS the paragraph and the preamble lead-in's start anchor failed. A
    triple net lease whose parties extract cleanly in the normal layout
    extracted none once its blank lines were stripped. The title prefix is now
    tolerated, matched CASE-SENSITIVELY and deliberately outside the
    case-insensitive `PREAMBLE_LEAD` — a title is capitalized, and the run must
    stop at the first lowercase word, which is what keeps "Landlord shall
    provide notice of the difference and the amount is …" from reading as a
    title followed by a preamble.
  - An SCC annex names its parties ONLY as "Data Exporter: …" labels, and the
    paste path joins a block's lines with SPACES, so the line-anchored label
    was unreachable and the annex extracted no parties at all. A whitespace
    boundary is the same boundary in that layout; the label whitelist and the
    capitalized-name requirement are what keep ordinary prose out.

## [9.234.0] — 2026-08-29

### Fixed
- **An EFFECTIVE-DATE recital read as a signature field.** "Effective Date:
  January 1, 2026." is a contract term, not an execution line. Flattening a
  document's blank lines — what a PDF copy-paste produces — merges that recital
  with the prose after it, and the tokens "Date" plus a stray "by" reached
  STRUCT-003's two-token floor. Four golden fixtures engineered to LACK a
  signature block went silent in that layout, including a BAA that says in
  terms that it contains "no separate execution lines, witness lines, or
  attestation blocks".

  Found by running the format-invariance axes over the 327 golden fixtures,
  which the specimen-only guard does not reach.

## [9.233.0] — 2026-08-29

### Added
- **A golden fixture must route to the family it was written for.** Every
  golden fixture carries a `.playbook` sidecar that FORCES its family, so the
  matcher never runs on it and a mis-routing can hide there indefinitely.
  Routing the same 327 fixtures without the sidecar is a free matcher corpus
  three times the size of the specimen set. Perspective variants — a
  `msa-vendor-deep` review of an `msa-general` document — are declared with the
  reason they are not defects.
- A conflict-of-interest policy fixture, so POL-033..036 have a document of
  their own family to run on.

### Fixed
- **A certificate of insurance had been audited as a CONFLICT OF INTEREST
  POLICY.** `insurance-coi-minimal.txt` was pinned to `coi-policy`, and its
  golden recorded four findings about recusal, annual certification, and
  related-party review against an ACORD-25-style certificate. The sidecar was
  wrong, not the matcher.
- **`subcontractor-agreement`'s title keyword "subcontract" is a SUBSTRING of
  "Subcontractor Business Associate Agreement"**, so a HIPAA downstream BAA
  routed to a construction subcontract at 1.00.
- **`baa-subcontractor` listed the BASE RATE of every HIPAA document** —
  "protected health information", "covered entity", "business associate", "phi"
  — as distinguishing phrases, so a patient's authorization form scored 0.6
  there. What distinguishes a DOWNSTREAM BAA is the flow-down, not the subject
  matter.
- **`phi-authorization` did not list its own statutory caption**,
  "Authorization for Use and Disclosure of Protected Health Information"
  (45 C.F.R. § 164.508).
- **"UK International Data Transfer Addendum to the EU Standard Contractual
  Clauses" title-matches both families head-on.** The EU SCC modules now carry
  the counter-signal; the EU clauses are not issued by the UK Information
  Commissioner.
- **`coi` won a policy SUMMARY**, on the four generic insurance words a summary
  shares with a certificate. The summary family gained the vocabulary that
  points back at what it summarizes — the binder, the declarations page, the
  coverage parts.

## [9.232.0] — 2026-08-29

### Added
- The self-penalizing-features guard now also runs against the **golden
  fixtures**, which reach forty families the specimen corpus does not. Each
  fixture carries a `.playbook` sidecar naming the family it was written for,
  so a negative feature appearing in one is a penalty the family charges its
  own document — the specimen check, over a corpus three times the size.

### Fixed
- **Six families penalized their own vocabulary**, every one of them naming the
  instrument the family exists ALONGSIDE rather than a rival family's document:
  - `revocable-living-trust` penalized "last will and testament", which its own
    pour-over rule requires it to name;
  - `loan-agreement` penalized "security agreement" and "promissory note",
    which a secured loan names in its collateral clause;
  - `safe-yc` penalized the bare word "interest", which appears in "does not
    bear interest" and in every "membership interest";
  - `baa-subcontractor` and `dpa-processor-subprocessor` penalized "Master
    Services Agreement" and "Statement of Work", the instruments they are
    appended to;
  - `insurance-policy-summary` penalized "certificate holder", which a policy
    summary names in its additional-insured line.

  Each was narrowed to the form the OTHER document states in terms — "this
  security agreement", "declare this to be my last will", "certificate of
  liability insurance".

## [9.231.0] — 2026-08-29

### Added
- A code of business conduct and ethics — the 190th specimen, and the first for
  `code-of-conduct`. POL-001..005 are all satisfied: the scope over directors,
  officers, and employees; the SOX § 406 honest-and-ethical and
  full-fair-accurate-disclosure elements; the waiver mechanism with its
  four-business-day Form 8-K disclosure; reporting with a helpline and
  non-retaliation; and compliance with laws.

### Fixed
- **A SUBSECTION of an external instrument read as a broken internal
  reference.** "Section 303A.10 of the NYSE Listed Company Manual" reaches the
  external-instrument test as the label "303A" with ".10 of …" still ahead of
  it, so the lookahead never matched and a code of conduct reported a broken
  reference to its own Section 303A.
- **`code-of-conduct` penalized its own vocabulary.** Its non-retaliation
  section names the whistleblower award programs and its compliance section
  names anti-bribery law, yet "whistleblower", "anti-bribery", and "aml" were
  negative features. They are meant to catch the standalone POLICIES, which say
  so in their own titles.

## [9.230.0] — 2026-08-29

### Added
- A motion to compel in the Circuit Court of Cook County — the 189th specimen,
  and the first for `trial-motion`. Clean but for the exhibits, which travel
  with the supporting declaration.

### Fixed
- **An IDENTIFIER NUMBER read as a case citation.** A motion's signature block
  runs the phone number into the attorney registration number — "(312)
  555-0192 / ARDC No. 6318842" — and "0192 ARDC No. 6318842" parsed as volume,
  reporter, and page, drawing a malformed-citation finding against a filing
  that has none. Two independent tells, either decisive: a reporter
  abbreviation never ends in "No.", and a volume never carries a leading zero.

## [9.229.0] — 2026-08-29

### Added
- A durable financial power of attorney — the 188th specimen, and the first for
  `durable-poa-financial`. EST-031..037 are all satisfied: principal and agent
  with a successor, durability that survives incapacity, the general
  subject-matter grant, the seven "hot powers" that require an express grant,
  the agent's fiduciary duties with an accounting, third-party reliance
  protection, and a notarial acknowledgment with recording.

### Fixed
- **A POSSESSIVE determiner made a new defined term.** A power of attorney is
  written in the first person and calls the defined "Agent" "My Agent"
  throughout, which STRUCT-006 reported as a term the instrument forgot to
  define. "My", "Our", "Its", "Their", "His", and "Her" now behave like a
  leading article. "Your" is deliberately absent — a consumer ToS commonly
  defines "Your Content" as a term in its own right.
- **`durable-poa-financial` penalized its own vocabulary.** It listed "trust"
  as a negative feature, but a POA's hot powers include the power to create,
  amend, revoke, or terminate an inter vivos trust. Narrowed to what a trust
  instrument states in terms: "declaration of trust", "revocable living trust",
  "the trust estate".

## [9.228.0] — 2026-08-29

### Added
- An assignment and assumption agreement — the 187th specimen, and the first
  for `assignment-and-assumption-agreement`. MNA-108..112 are all satisfied:
  the schedule of assigned contracts, assumed versus excluded liabilities, the
  third-party consent carve-out, an effective time of 12:01 a.m. on the Closing
  Date, and further assurances with a power of attorney.

### Fixed
- **Two more families carried an empty `rule_overrides`** —
  `assignment-and-assumption-agreement` and `secondary-stock-transfer`. A
  closing deliverable was told it states no payment terms; both now carry
  `assignment-of-claim`'s profile plus FIN-005.

## [9.227.0] — 2026-08-29

### Added
- A postnuptial agreement — the 186th specimen, and the first for
  `postnuptial-agreement`. EST-046..052 are all satisfied: the during-marriage
  recital, consideration beyond the marriage itself, heightened fiduciary
  disclosure with schedules, transmutation of two specific assets, a support
  waiver with a limited carve-out, independent counsel with a review period,
  and a notarial acknowledgment.

### Fixed
- **`postnuptial-agreement` and `cohabitation-agreement` carried an empty
  `rule_overrides`.** The postnup drew seven generic contract findings: no
  payment terms, no IP allocation, no indemnity, no liability cap, no
  termination-for-cause, no effect-of-termination, and no venue clause. Both
  families now carry `prenuptial-agreement`'s profile, extended with RISK-001
  and CHOICE-003 — a marital agreement has no indemnity, and states its
  governing law without a forum.

## [9.226.0] — 2026-08-29

### Added
- A profits-interest award in an LLC — the 184th specimen, and the first for
  `profits-interest-award`. EQT-114..119 are all satisfied: the threshold
  amount set at grant-date liquidation value, the Rev. Proc. 93-27 and 2001-43
  recitals, the § 83(b) direction with its 30-day deadline, vesting with
  forfeiture allocations under Treas. Reg. § 1.704-1(b)(4)(x), the
  capital-account book-up, and the partner-not-employee warning.
- An option to purchase real property — the 185th specimen, and the first for
  `option-to-purchase-real-estate`. RE-123..127 are all satisfied:
  non-refundable independent option consideration, strict exercise mechanics
  with time of the essence, a price with an appraisal formula, a recordable
  memorandum of option, and a perpetuities savings clause.

### Fixed
- **Two more families carried an empty `rule_overrides`.** An equity award was
  told it has no payment-term clause; a land option was told it does not
  allocate ownership of intellectual property, has no limitation-of-liability
  clause, and states no path to terminate for material breach.
  `profits-interest-award` takes the `rsu-grant` profile and
  `option-to-purchase-real-estate` takes `easement-agreement`'s — an interest
  in land is not a services bargain.

## [9.225.0] — 2026-08-29

### Added
- A foundation grant award — the 183rd specimen, and the first for
  `grant-agreement`. GOV-133..138 are all satisfied: award amount and period of
  performance, restricted purpose with a budget-deviation threshold, narrative
  and financial reporting deadlines, return of unexpended funds and repayment
  on demand, the § 4945 lobbying and political-activity restrictions, and
  records retention with audit access.

### Fixed
- **`grant-agreement` and `fiscal-sponsorship-agreement` carried an empty
  `rule_overrides`.** A charitable grant was told it does not allocate
  ownership of intellectual property and has no indemnity or
  limitation-of-liability clause. None of the three belongs in a one-way
  funding instrument.
- **TEMP-007 reported categories the document does not HAVE.** The grant has no
  confidentiality clause and no indemnity, and was told its survival list omits
  both — a defect with no answer short of adding two clauses the instrument
  does not want. Only a category the document states somewhere is now audited,
  which also cleared the same false positive on five earlier specimens and on
  one golden fixture — where the engineered defect, a missing governing-law
  clause, is still reported by CHOICE-001, the rule that owns it.

## [9.224.0] — 2026-08-29

### Added
- A pre-suit demand letter on unpaid invoices — the 182nd specimen, and the
  first for `demand-letter`. Clean once the two defects below were fixed:
  SET-011..014 are satisfied by the statement of facts, the specific demand
  with a deadline, the absence of abusive language, and the reservation of
  rights.

### Fixed
- **SET-015's "(if applicable)" was in the rule's NAME and nowhere in its
  logic.** With no gate, it fired on every demand letter that is not a PAGA
  notice, and an Illinois UCC collection letter was told its PAGA notice
  elements were missing. The gate is a California wage-and-hour claim,
  deliberately broader than the present patterns, so a California wage letter
  that never says "PAGA" or "LWDA" still reports.
- **`demand-letter` penalized its own vocabulary.** It listed "release" as a
  negative feature, meant to catch a signed release — but every demand letter's
  reservation of rights says "nothing in this letter is a waiver, release, or
  modification of any right". Narrowed to the forms a release states in terms:
  "releases and forever discharges", "general release of all claims", "mutual
  release".
- **A section of ANOTHER commercial instrument read as a broken internal
  reference.** "the fee-shifting provision in section 11 of the terms of sale"
  cites the seller's standard terms, not the letter. The external-instrument
  nouns covered agreements, leases, notes, and deeds but not the ones a
  commercial letter names: terms, orders, statements of work, guaranties,
  warranties, rules, manuals, handbooks, and schedules.

## [9.223.0] — 2026-08-29

### Added
- An appellate brief in the Ninth Circuit — the 181st specimen, and the first
  for `appellate-brief`. Entirely clean once the defect below was fixed: the
  filing-format pack is dormant without `--court`, and the family's 53-rule
  contract-lint skip profile does the rest.

### Fixed
- **A party to a CITED CASE was reported as a term the drafter forgot to
  define.** The brief's table of authorities and argument name "Celotex Corp.",
  "Sanderson Plumbing Prods.", and "Entek Int'l" several times each, and
  STRUCT-006 listed all of them. The "v." is the whole signal — a phrase on
  either side of it is half a case name — and, like a signatory, a case name is
  dropped wherever it appears, because a brief cites the same case in its table
  of authorities, its standard of review, and its argument.

## [9.222.0] — 2026-08-29

### Added
- Amended and restated bylaws of a Delaware corporation — the 180th specimen,
  and the first for `bylaws-corporation`. GOV-001..012 are all satisfied and
  the exclusive-forum bylaw carves out the Exchange Act, so the document is
  clean but for one `info`.

### Fixed
- **A bylaws heading with NO period after its section number registered as no
  section at all**, and was then re-read as a broken reference to itself. The
  specimen drew 28 unresolved cross-references on a document that has none:
  `LEADING_SECTION_RE` requires "Section 1.1." with the period, and
  `LEADING_SUBSECTION_RE` anchors on the bare number, so "Section 1.1
  Registered Office." — the way a Delaware corporation's bylaws are almost
  always numbered — fell between them. The "Section" keyword is required in the
  new pattern, so a paragraph opening "5 Business Days after the Closing" still
  does not register.
- The same heading MID-PARAGRAPH, for the flattened layouts a PDF copy-paste
  produces. Without a period after the number, a heading is told apart from a
  reference by what follows it: a short Title-Case clause title that itself
  ends in a period. "in accordance with Section 232 of the General Corporation
  Law" is not preceded by a sentence end, "This Section 9.9 does not apply"
  continues in lowercase, and "See Section 2.3 for notice requirements." never
  closes a Title-Case run — none of them register.

## [9.221.0] — 2026-08-29

### Added
- A revolving credit agreement on LSTA architecture — the 179th specimen, and
  the first for `revolving-credit-agreement`. The whole BNK-101..108 pack is
  silent on one that covers every column: commitment and borrowing base, the
  SOFR benchmark-replacement waterfall, financial covenants with testing dates
  and an equity cure, conditions to each borrowing, events of default with cure
  and cross-default, the collateral and guarantor package, agent authority with
  assignment and participation, and prepayment with breakage, increased costs,
  and the tax gross-up.

### Fixed
- **Three lending families carried an empty `rule_overrides`** —
  `revolving-credit-agreement`, `sba-loan-agreement`, and
  `intercreditor-agreement`. A credit agreement was told it does not allocate
  ownership of intellectual property and has no limitation-of-liability clause,
  because nobody had given the families the profile their siblings
  (`convertible-note`, `promissory-note`) already carry.
- **STRUCT-009 read an ATTRIBUTIVE use as a miscapitalized defined term.** A
  credit agreement defines "Commitment" and then charges an "unused commitment
  fee" — the fee, not the Commitment. The head nouns are enumerated rather than
  inferred, because an open "followed by any lowercase word" test would swallow
  the ordinary sentences where the term is the subject and the next word is its
  verb.

## [9.220.0] — 2026-08-29

### Added
- An asset purchase agreement — the 178th specimen, and the first for
  `asset-purchase-agreement`. The whole MNA-020..028 pack is silent on one that
  covers every column: purchased and excluded assets, assumed and excluded
  liabilities, the bulk-sales waiver with its own indemnity, the § 1060
  allocation and Form 8594 consistency covenant, the required-consents and
  non-assignment mechanics, the WARN Act allocation, and the bill of sale.

### Fixed
- **A party name swallowed an unmatched open parenthesis.** `Antonia Pike
  (each, a "Principal" …)` registered as a party named `Antonia Pike (each`:
  the preamble list splits on commas, so the name and its role parenthetical
  landed in different members, and the ", a …" entity-descriptor strip cut
  inside a parenthesis it had not opened. A name never carries an unmatched
  "(".
- **The same entity registered twice, with and without its corporate suffix.**
  "Harrowgate Finishing Systems, Inc." and "Harrowgate Finishing Systems" were
  two parties, and every rule that TALLIES BY PARTY — RISK-002's indemnity
  symmetry among them — read the bare form as a third party with no
  obligations. Collapsed only when one form carries a suffix and the other
  carries none, so "Acme Holdings, Inc." and "Acme Holdings LLC" stay distinct.
- **A collective alias could not name what it collects.** `(each employee who
  accepts, a "Transferred Employee")` and `(each such meeting, a "Review
  Meeting")` were not read as definitions, because the parenthetical's lead-in
  allowed only bare determiners between "each" and the quoted term. The term
  then showed up in STRUCT-006's undefined-term list on the document that
  defines it.
- The preamble role parenthetical now also reads the collective form
  `(each a "Principal" and together, the "Principals")`.

## [9.219.0] — 2026-08-29

### Added
- A broker's summary of insurance — the 177th specimen.

### Fixed
- **`insurance-policy-summary` listed "endorsement" as a NEGATIVE feature**, but
  every policy summary lists its key endorsements. The document said in terms
  that it "is not a certificate of insurance" and routed to `coi` anyway, which
  matched four generic insurance words. Widened the family's title keywords
  ("summary of insurance", "insurance summary", "summary of coverage"), replaced
  the negative features with the ones a certificate actually carries ("acord
  25", "certificate holder"), and narrowed the distinguishing phrases to
  summary-only vocabulary so the family does not tie `cyber-insurance-policy`.
- **STRUCT-003 read a COVER BLOCK as a signature block.** "Prepared for: …
  Prepared by: … Date prepared: …" at the top of the summary yielded the
  distinct tokens "by" and "date" in one paragraph — enough to reach the
  two-token floor and stand the check down on a document nobody had signed. The
  cover-page labels are stripped before counting; "approved by" and "reviewed
  by" are deliberately left in, because an approval block *is* an execution
  affordance (the DPIA specimen relies on it).
- Found by the format-invariance guard from both directions: the double-spaced
  layout reported STRUCT-003 and the normal layout did not, because the cover
  block's tokens only share a paragraph when the lines are not split.

## [9.218.0] — 2026-08-29

### Added
- A Regulation D private placement memorandum — the 176th specimen. Clean: the
  whole REG-025..032 pack is silent on a memorandum that covers every column —
  the § 4(a)(2) / Rule 506(b) legend, the no-approval legend, use of proceeds,
  risk factors, manager compensation, transfer restrictions, suitability
  standards, and the Rule 502(b) investor-access undertaking.

## [9.217.0] — 2026-08-29

### Added
- An omnibus equity incentive plan — the 175th specimen. Clean: the whole
  EQT-101..114 pack is silent on a plan that covers every column — share
  reserve, evergreen, capitalization adjustment, the no-repricing covenant,
  § 409A, the § 422(d) $100,000 ISO limit, change-in-control treatment,
  clawback, and the amendment triggers that need stockholder approval.

### Fixed
- **`equity-incentive-plan` listed "vesting commencement date" as a NEGATIVE
  feature**, meant to distinguish a grant NOTICE from the plan — but a plan's
  default vesting schedule references the same date. Narrowed to the
  field-label form, "vesting commencement date:", which only a grant notice
  carries. (Caught by `self-penalizing-features.test.ts` the moment the
  specimen existed.)

## [9.216.0] — 2026-08-29

### Added
- A public design-build agreement with a guaranteed maximum price — the 174th
  specimen. Clean: it routes at 1.0 and its own pack, including the
  single-point-of-responsibility check, is silent on a compliant one.

### Changed
- `design-build-agreement` skips RISK-005, as `construction-contract` does: a
  guaranteed-maximum-price contract caps the price, not liability.

IPDATA-001 stays and is real — Section 7.4 grants Owner a LICENCE to the design
documents but never says who owns them, and in design-build that is the IP
question.

## [9.215.0] — 2026-08-29

### Added
- A Clean Water Act consent judgment — the 173rd specimen.

### Fixed
- **It fell to `generic-fallback`.** The family's five distinguishing phrases
  were verbatim sentences — "judgment is hereby entered", "the court retains
  jurisdiction", "stipulate and agree" — that a real consent judgment does not
  say. It now reads the register one uses: "ORDERED, ADJUDGED, AND DECREED",
  "SO ORDERED", stipulated penalties, lodging, public comment.
- **SET-103 reported no admission recital on a document whose second WHEREAS
  is one.** The pack's text source STRIPS RECITALS by default, and a consent
  judgment states "this Consent Judgment is not an admission of liability"
  nowhere else — so the rule could not see the sentence it exists to find. It
  now reads recitals, and knows the two forms the recital takes ("not an
  admission", "deny the allegations").
- **SET-105 wanted a satisfaction of judgment.** A consent decree is
  discharged by a MOTION TO TERMINATE after a stated compliance period.
- **STRUCT-006 reported "Consent Judgment"** — the document's own name. The
  court-order nouns join the named-instrument suppression; "Order" is
  deliberately absent, because a contract may genuinely define a Change Order.

## [9.214.0] — 2026-08-29

### Added
- A remote work agreement — the 172nd specimen.

### Fixed
- **It routed correctly but only just — 0.5, exactly at the threshold.** The
  family's distinguishing phrases were HEADINGS rather than register ("work
  hours and availability", "the employee's home office"), so one of six
  matched, and it had a single title keyword. It now reads the phrases such an
  agreement carries.
- **`remote-work-agreement` shipped with no rule profile**, so an employment
  addendum that says in terms that it does not change Employee's status was
  told it allocates no IP, provides no indemnity, caps no liability, and states
  no termination path.

## [9.213.0] — 2026-08-29

### Added
- **`tests/integration/inert-case-anchor.test.ts`** — a permanent guard for a
  defect this codebase has grown five separate times: **an `[A-Z]` inside a
  case-INSENSITIVE regex is inert.** `/"([A-Z][\w\s]{1,80}?)"\s*means\b/gi`
  reads as "a quoted term that starts with a capital" and is not.

  The flag is usually load-bearing — the defining verb, the marker, or the
  document itself varies in case — so the fix is normally an explicit
  `/^[A-Z]/` check at the consumer rather than dropping the flag. Every
  remaining instance is declared with the reason it is safe, and a second
  assertion fails if a declared entry stops applying, so the list cannot
  outlive the code.

### Fixed
- **A d/b/a capture could read "doing business as A REGIONAL CARRIER" as an
  operating NAME.** Same defect, same repair.

## [9.212.0] — 2026-08-29

### Fixed
- **Five more quoted-term patterns shared the defect fixed in 9.211.0.** Each
  needs its `i` flag for a case-varying defining verb — "means", "refers to",
  "is defined as", "shall commence", "when" — and each anchors its capture on
  `[A-Z]`, which the flag makes inert. A quoted LOWERCASE phrase could
  register as a defined term through any of them, and then be reported as
  defined-but-never-used.

  Found by sweeping every case-insensitive regex in `src/` for an `[A-Z]`
  class: 30 hits, of which the six in `definitions.ts` were all the same bug.
  The anchor is restored explicitly at each consumer rather than by dropping
  the flag, which would lose every ALL-CAPS definition.

## [9.211.0] — 2026-08-29

### Added
- A second amendment to a revocable living trust — the 171st specimen. Clean
  once routed.

### Fixed
- **It routed to `revocable-living-trust`** and was told it states no
  pour-over reference and no spendthrift clause. A two-page amendment restates
  neither, because both are in the trust it amends. The amendment family's own
  title keywords could not match "SECOND AMENDMENT TO THE HARROWGATE FAMILY
  REVOCABLE LIVING TRUST" — they read "trust amendment" and "first amendment
  to the trust" — and its distinguishing phrases were verbatim sentences. It
  now reads the register an amendment uses (deleted in its entirety, ratified
  and confirmed, as amended by), and the trust family treats those as
  negatives, which they are.
- **An inline definition registered a LOWERCASE quoted phrase as a term.**
  `DEFINITION_INLINE` needs its `i` flag for the case-varying defining verb,
  which also weakens its leading `[A-Z]` to "any letter" — so `All references
  in the Trust to "this Trust" MEAN the Trust as amended` yielded a term named
  "this Trust", reported as defined and never used. The anchor is restored
  explicitly rather than by dropping the flag, which would lose every ALL-CAPS
  definition.

## [9.210.0] — 2026-08-29

### Added
- A mutual employment arbitration agreement drafted around the Ending Forced
  Arbitration Act — the 170th specimen.

### Fixed
- **CHOICE-001 reported no governing-law clause on an FAA-governed
  agreement.** "This Agreement is governed by the FEDERAL ARBITRATION ACT,
  9 U.S.C. §§ 1–16" is the governing-law clause of every employment
  arbitration agreement in the United States; every pattern wanted "the laws
  of <place>", and this one names a federal statute instead. The sovereign is
  the United States.
- **`arbitration-agreement-employment` shipped with no rule profile**, so a
  four-page arbitration agreement was told it allocates no IP, provides no
  indemnity, caps no liability, states no payment term and states no
  termination path.

DARK-005 stays and is the point: the class-action waiver is the central term a
reviewer must see. CHOICE-003 and CHOICE-006 are right that the seat is stated
only by reference ("the county where Employee last worked").

## [9.209.0] — 2026-08-29

### Added
- A warehousing and third-party logistics agreement (clean) and a venue rental
  agreement — the 168th and 169th specimens.

### Fixed
- **A venue rental routed to `lease-residential-us`** and drew DARK-012, a
  residential security-deposit dark-pattern rule, on a non-refundable EVENT
  booking deposit — on a document that says in terms that it "creates no
  leasehold estate, tenancy, or other interest in real property". The venue
  family's own distinguishing phrases were HOTEL vocabulary ("room block",
  "attrition", "food and beverage minimum") that a conservatory hire does not
  use, so it had one title keyword to stand on.
- **COMM-243 reported no cancellation schedule on a clause that sets one out
  in tiered day windows.** It wanted the words "cancellation fee"; a real one
  reads "If Renter cancels MORE THAN one hundred twenty (120) DAYS before the
  Event, Renter FORFEITS the booking deposit only."
- **`venue-rental-agreement` shipped with no rule profile.**

## [9.208.0] — 2026-08-29

### Added
- An equipment finance agreement — the 167th specimen. A loan secured by the
  equipment, which the document says in terms: "This Agreement is a loan
  secured by the Equipment and is NOT A LEASE."

### Fixed
- **It routed to `loan-agreement`**, the syndicated-credit family, so its own
  BNK-139..143 pack never ran. The equipment-finance family's distinguishing
  phrases were verbatim sentences: "grants a security interest in the
  equipment" (with the indirect object removed — a real one reads "Borrower
  grants LENDER a first-priority security interest in the Equipment") and
  "title to the equipment passes", which a loan never says because title never
  moves. It now carries the register a real one uses, and a second title
  keyword.
- **`equipment-finance-agreement` shipped with no rule profile.** A secured
  loan does not terminate for cause — it accelerates — and allocates no IP.

## [9.207.0] — 2026-08-29

### Added
- A title-sponsorship agreement for a road race — the 166th specimen.

### Fixed
- **COMM-175 reported no trademark licence or approval right** on a document
  with a section headed "USE OF MARKS" and another headed "Approvals". It
  wanted the noun phrase in one order ("marks license") and "prior written
  approval" verbatim, where the document says "Each party shall APPROVE the
  other's USE of its marks in advance".
- **FIN-005 could not read "payable $425,000 on JANUARY 31 and $425,000 on
  JUNE 30 of each year."** The amount sits between the verb and the date, and
  the date carries no year because it recurs; the branch required both to be
  absent.
- **`sponsorship-agreement` shipped with no rule profile**, so it was told it
  allocates no IP ownership — a sponsorship licenses marks, it does not
  allocate ownership.

## [9.206.0] — 2026-08-29

### Changed — the matcher
- **`required_clauses` now cap at ONE clause's weight, not two.**

  They are classifier CATEGORIES — "term", "termination-for-cause",
  "indemnification", "confidentiality-obligation", "ip-ownership" — and the
  generic commercial families list three apiece. At a two-clause cap, any
  agreement with a confidentiality section, a term and a statement of work
  collected **0.8**: the largest single block in the score, and enough on its
  own to beat a specialised family that matched its own title and three
  phrases of its own register.

  That is how `independent-contractor` took an FTC endorsement agreement
  (9.205.0), how `consulting-agreement` and then `mutual-nda`, `msa-general`
  and `sow` took a joint development agreement (9.203.0), how `msa-general`
  took a copyright licence (9.185.0), and how `employment-at-will-us` came
  level with a pharmaceutical supply agreement (9.195.0) — each fixed by hand,
  one negative feature at a time, before the cause was measured.

  The change was run against the whole suite before it was made: **all 166
  specimens still route to the family they are pinned to, all 365 golden
  fixtures are unchanged, and every one of 10,284 tests passes.** The second
  required clause was contributing nothing correct anywhere.

## [9.205.0] — 2026-08-29

### Added
- An FTC-compliant influencer endorsement agreement — the 165th specimen.

### Fixed
- **An endorsement agreement written to 16 C.F.R. Part 255 routed to
  `independent-contractor`**, so the whole endorsement pack never ran. The
  contractor family reaches 1.4 on three required clauses (0.8) plus
  "independent contractor", "not an employee" and "1099" — words an influencer
  agreement carries as a matter of course. Fixed on both sides: "influencer"
  and "endorsement" are title keywords of the family whose documents carry
  them, and the endorsement markers ("sponsored content", "material
  connection", "#ad") are negatives of the contractor family, which never
  carries them.

## [9.204.0] — 2026-08-29

### Added
- An OEM agreement — the 164th specimen. An OEM incorporates the components;
  it does not resell them.

### Fixed
- **An OEM agreement routed to `distribution-agreement`** and drew five
  `critical` findings from the distribution pack — three of them on clauses
  the document carries under those very headings ("Appointment", the
  trademark licence, the post-termination sell-off). The OEM family's own
  distinguishing phrases were **verbatim sentences nobody writes** ("embedded
  in the oem product", "under the oem's brand", "support tiers"), so it
  matched none of them and had a single title keyword to stand on. It now
  carries the register a real one uses — OEM Products, last-time buy, private
  label, epidemic failure — and "oem" as a second title keyword.
- **COMM-237 wanted "under THE oem's brand"** where the document says "under
  OEM's OWN brand" — no article before the party name, and "own" between the
  possessive and the noun.

## [9.203.0] — 2026-08-29

### Added
- A cross-border joint development agreement — the 163rd specimen.

### Fixed
- **A JOINT DEVELOPMENT AGREEMENT routed to `consulting-agreement`, then to
  `mutual-nda`, then to `msa-general`, then to `sow`.** Four causes, one
  shape: the JDA family's own distinguishing phrases were the SPELLED-OUT
  forms ("background intellectual property"), and every real one writes
  "Background IP"; `consulting-agreement` was leaning on "Consultant" and
  "expertise"; and `mutual-nda`, `msa-general` and `sow` all reach 0.9–1.0 on
  required clauses any agreement with a confidentiality section, a term and a
  statement of work satisfies.

  The durable fix was to give the family a **second title keyword its own
  document carries** — "joint development" beside "joint development
  agreement" — rather than another negative feature on each rival. Once the
  distinguishing-phrase cap is reached, title keywords are the only lever.
  ("Foreground IP" and "joint steering committee" are also now negatives of
  the NDA and MSA families, which is correct on its own terms.)
- **STRUCT-006 reported "Joint Foreground"** — the front half of "Joint
  Foreground IP", cut because the Title-Case run needs a lowercase tail on
  every word and "IP" has none.

## [9.202.0] — 2026-08-29

### Added
- A public-health limited-data-set data sharing agreement — the 162nd
  specimen.

### Fixed
- **TERM-005's trigger read "(up)on termination" only**, and the standard
  data-return clause is written "within thirty (30) days **AFTER** expiration
  or termination" or "**FOLLOWING** the effective date of expiration or
  termination". It was reporting "the contract does not state what happens
  upon termination" on **25 corpus fixtures** that state it in terms —
  including one whose section is headed "Data Deletion on Termination" and
  whose next words are "Vendor shall securely delete or destroy all Customer
  Data … and shall certify such deletion in writing".
- **IPDATA-008 reported a cross-border transfer missing its Article 46
  safeguard on a data-LOCALIZATION clause.** "Recipient shall store and
  process the Shared Data ONLY WITHIN the United States and SHALL NOT TRANSFER
  it outside the United States without Provider's prior written consent" is a
  prohibition, not an authorization. The negation sits directly on the verb
  the match begins with, which the existing disclaimer scan — which looks for
  a disclaimer FRAME — does not read.
- **`data-sharing-agreement` shipped with an empty rule profile.**

## [9.201.0] — 2026-08-29

### Added — a new document family
- **`venture-stock-purchase-agreement`** (EQT-131..136, 6 checks). The catalog
  carried the whole NVCA suite — the investors' rights agreement, the voting
  agreement, the ROFR and co-sale agreement, the SAFE, the convertible note —
  but not **the document that closes the round**. A Series B preferred stock
  purchase agreement routed to `stock-purchase-agreement`, which is the ABA
  private-target M&A SPA, and was checked for sandbagging, a stockholder
  representative, and selling-stockholder restrictive covenants, none of which
  a primary financing has.

  The six columns are the ones an investor's counsel actually reads it for:
  the restated certificate filed as a closing condition (`critical` — the
  preferred stock does not exist until it is on file); the capitalization
  representation and its disclosure schedule (`critical`); authorization and
  valid issuance; the purchasers' private-placement representations
  (`critical` — the Regulation D exemption is their status and intent);
  the ancillary agreements as closing deliverables; and survival of the
  representations, which in a financing is the investor's only post-closing
  recourse.

  `stock-purchase-agreement` now carries the issuance markers as negative
  features, so the M&A family stands down for a financing.

  Catalog: **1,824 rules across 267 document types**.

## [9.200.0] — 2026-08-29

### Added
- An NVCA Series B preferred stock purchase agreement — the 161st specimen.

### Fixed
- **The name of another INSTRUMENT the document references was reported as an
  undefined term** — "the Investors' Rights Agreement", "the Voting
  Agreement", "the Master Services Agreement", "the Stock Purchase Agreement".
  A document that names another agreement is not defining a term, and whether
  that instrument is attached is STRUCT-018's question. Across the whole
  corpus this suppresses exactly two distinct terms, on 43 fixtures.

### Recorded, not fixed — a CATALOG GAP
- The catalog carries the whole NVCA suite — the investors' rights agreement,
  the voting agreement, the ROFR and co-sale agreement, the SAFE, the
  convertible note — but **not the STOCK PURCHASE AGREEMENT that closes the
  round**. `stock-purchase-agreement` is the ABA private-target M&A SPA, so a
  Series B financing routes there and is checked for sandbagging, a
  stockholder representative, and selling-stockholder restrictive covenants,
  none of which a financing has.

  Narrowing the M&A family with negatives an issuance carries ("accredited
  investor", "Restated Certificate", "Investors' Rights Agreement") takes it
  to 0.6 — still over the threshold — and makes the family penalize the
  specimen pinned to it, so that half-measure was reverted. The fix is a new
  family with its own pack. The specimen and its current finding set are
  pinned so the gap stays visible.

## [9.199.0] — 2026-08-29

### Added
- An NVCA-style right of first refusal and co-sale agreement — the 160th
  specimen.

### Fixed
Four of its own checks fired on the drafting they exist to require, three at
`critical`:
- **EQT-064 and EQT-065 wanted the defined phrase adjacent to the party in ONE
  order**, and the operative clauses never repeat it: the section is headed
  "RIGHT OF FIRST REFUSAL" and the clauses read "The COMPANY MAY ELECT TO
  PURCHASE …" and "Each INVESTOR MAY THEN ELECT TO PURCHASE …". Either order,
  and the operative forms, are now read.
- **EQT-066 required BOTH "co-sale" and "tag-along"** — the same right under
  two names, the US venture form saying the first and the European form the
  second — so no compliant document could satisfy it. The conjunction was also
  doing a second job by accident: the bare word "co-sale" sits in this family's
  own TITLE, so an OR of the two bare spellings would be satisfied by the title
  alone. The repair REPLACES the vacuous spelling rather than simply OR-ing it.
- **EQT-069 wanted the word "terminate" beside the offering**, where the term
  clause reads "continues until … a firm-commitment underwritten public
  offering". Same repair as GOV-041 in 9.174.0.
- **`rofr-co-sale` shipped with an empty rule profile.**

## [9.198.0] — 2026-08-29

### Added
- A staffing services agreement and an NVCA-style investors' rights agreement
  — the 158th and 159th specimens. The staffing agreement is clean: every
  finding on it is real.

### Fixed
- **EQT-053 reported no information-rights clause at `critical`** on a section
  headed "INFORMATION AND INSPECTION RIGHTS" that delivers four sets of
  statements. Its pillars wanted "information rights" adjacent, and a
  cadence-first phrase with "financial" required — so "unaudited MONTHLY
  financial statements", "unaudited QUARTERLY STATEMENTS" and "AUDITED ANNUAL
  STATEMENTS" all failed it.
- **EQT-054 wanted the NVCA model's own heading.** A large share of investors'
  rights agreements head the same right "PREEMPTIVE RIGHTS", and others call
  it a pro rata or participation right.
- **`investor-rights-agreement` shipped with an empty rule profile.**

## [9.197.0] — 2026-08-29

### Fixed
- **The last entry on `format-invariance`'s debt list comes off.** An SEC
  risk-factor heading has no number to anchor on: stripping the blank lines
  glued "Risks Related to Our Business and Industry" to the paragraph beneath
  it, the Title-Case run stopped at the lowercase "to", and "Risks Related"
  arrived as a candidate three times over and reported as an undefined term —
  so the finding set depended on the FORMAT of the upload.

  The signal that settled it is linguistic rather than positional, and it was
  not one of the three recorded as tried and rejected: **no document defines a
  term whose last word is a RELATIONAL PARTICIPLE** — Related, Relating,
  Regarding, Concerning, Pertaining, Arising, Attributable, Associated,
  Connected, Applicable, Subject. They are all prepositional heads waiting for
  an object.

  All 158 specimens now report the same finding set under all five format
  axes, with no declared exceptions.

## [9.196.0] — 2026-08-29

### Fixed
- **Three families were leaning on words that name a CLAUSE TYPE rather than a
  register.** `msa-general` listed "Provider" and "Customer"; `msa-customer-deep`
  and `msa-vendor-deep` listed "limitation of liability" and "indemnification".
  Any document that discusses contracts contains those — which is how a
  copyright licence routed to `msa-general` (9.185.0), how a managed-care
  provider agreement tied it (9.177.0), and how a 10-K RISK FACTORS section
  came level with the deep MSA families. Each keeps the vocabulary that is
  actually its own.
- **`10-k-risk-factors` had no title keyword its own document carries.** "ITEM
  1A. RISK FACTORS" is the heading of every one; both are now title keywords,
  which is the only lever available once the distinguishing-phrase cap is
  reached.

## [9.195.0] — 2026-08-29

### Added
- A pharmaceutical contract-manufacturing and supply agreement — the 157th
  specimen.

### Fixed
Three findings inverted what the document says:
- **COMM-024 reported no title / lien warranty at `critical`** on a warranty
  that the Products are "free of ANY LIEN" — the singular, behind a determiner
  the pattern did not admit.
- **RISK-006 reported ZERO limitation-of-liability carve-outs on a clause that
  carves out four.** Its window stopped at the "8.1" of a section citation, and
  the `indemnif` stem does not match the noun "indemnity". The window now
  absorbs an in-number period.
- **TERM-005 reported no effect-of-termination clause on a transition
  obligation stated as a TRANSFER** — "On expiration or termination, Supplier
  shall … TRANSFER the manufacturing process and all Customer-owned tooling".
- **`employment-at-will-us` listed "exempt" as a distinguishing phrase**, which
  matches "exemption certificate". With three required clauses at 0.8, that put
  an employment playbook level with the manufacturing family on a pharma supply
  agreement. Narrowed to "exempt employee".

COMM-025 and COMM-040 stay and are real: the specimen states no exclusive
remedy and does not address the UCC implied warranties either way.

## [9.194.0] — 2026-08-29

### Added
- A Delaware limited partnership agreement — the 156th specimen.

### Fixed
- **RISK-015 and RISK-011 demanded commercial indemnity machinery of an
  entity's indemnity of its own fiduciary** — an aggregate cap, a notice
  provision, defense control — on "The Partnership shall indemnify the GENERAL
  PARTNER … except a loss resulting from FRAUD, WILLFUL MISCONDUCT, GROSS
  NEGLIGENCE, or a knowing violation of law". That indemnity is uncapped by
  design; the existing statutory guard wanted the "fullest extent permitted"
  formula, which an LP or LLC agreement usually does not use.

  The ENTITY as indemnitor is what makes an indemnity a governance one. "Owner
  shall indemnify … Manager … other than a claim arising from Manager's gross
  negligence" reads like the same carve-out but runs between two businesses,
  and still needs its cap.
- **`partnership-agreement` shipped with an empty rule profile.**

### Changed
- `operating-agreement.txt` no longer reports RISK-015 / RISK-011: an LLC
  agreement's indemnity of its Manager and Members is the same statutory
  indemnity, and the guard now reaches it.

## [9.193.0] — 2026-08-29

### Added
- A three-party subordination agreement and an AAA demand for arbitration —
  the 154th and 155th specimens. The subordination agreement is clean: it
  routes at 1.0 and its own pack is silent on a well-drafted one.

### Fixed
Three names a document INVOKES rather than defines were reported as undefined
Title-Case terms:
- a **VESSEL name behind its prefix** — "the M/V Bayou Sentinel";
- a **fragment of a compound instrument name** — "the Vessel Refit AND
  SERVICES AGREEMENT", where the Title-Case run stops at the lowercase "and",
  the same shape as the `Act` / `Code` / `Law` lookahead already in place;
- the **name of a RULE SET** — "the Commercial Arbitration Rules". A body's
  published rules are an external authority, like a statute.

## [9.192.0] — 2026-08-29

### Added
- A bankruptcy trade-claim purchase — the 153rd specimen.

### Fixed
- **An ASSIGNMENT OF CLAIM routed to `ip-assignment`** and drew two `critical`
  findings about assigned INTELLECTUAL PROPERTY scope and a power of attorney.
  There is no IP. `assignment-of-claim`'s own distinguishing phrases were
  verbatim sentences nobody writes ("hereby assigns all right, title and
  interest in the claim", "no warranty of collectability"), and `ip-assignment`
  was leaning on "assignor" / "assignee" — the two words in every assignment of
  anything, the same defect fixed in `lease-assignment` at 9.168.0.
- **CHOICE-003 reported no forum on a clause that names two.** "…submits to the
  exclusive jurisdiction of the BANKRUPTCY COURT in the Case and, if that court
  lacks jurisdiction, the state and federal courts located in New York County,
  New York": the first court carries no geography, so every trigger-anchored
  branch failed on it and none reached the second. The subject-matter courts
  (bankruptcy, tax, probate, family, surrogate's, housing, land) are now court
  names, and a fallback-forum branch runs when nothing else in the paragraph
  named a forum.
- **SET-115 read a title warranty written as a VERB SERIES as warranting
  nothing.** "Assignor is the SOLE LEGAL AND BENEFICIAL OWNER of the Claim and
  HAS NOT SOLD, ASSIGNED, PLEDGED, OR ENCUMBERED it" is the warranty; the
  pillar read only noun phrases.
- **STRUCT-002 could not see the EXECUTION RECITAL that dates an instrument at
  its foot** — "IN WITNESS WHEREOF, the parties have executed this Assignment
  of Claim as of November 12, 2026". The branch reads the EXTRACTED date, so
  the corpus's `bad-nda`, dated "as of February 30, 2026", still reports.
- **`assignment-of-claim` shipped with an empty rule profile.**

## [9.191.0] — 2026-08-29

### Added
- A one-step cash merger agreement — the 152nd specimen.

### Fixed
- **OBLI-004 reported an agreement that deliberately chose "REASONABLE best
  efforts" as using the unqualified standard** — the opposite of what its
  drafters did. "Reasonable best efforts" is the middle standard, and OBLI-008
  already surfaces it as an undefined efforts standard. "Commercially
  reasonable best efforts" and "good faith best efforts" are excluded for the
  same reason; a bare "best efforts" still fires.
- **MNA-035 demanded § 228 written consents and drag-along letters of a merger
  approved at a stockholder MEETING on a proxy statement.** The rule's own
  title, description and explanation scope it to PRIVATE targets, which have
  no meeting and no proxy; it is now gated to them.
- **`merger-agreement` shipped with an empty rule profile.**

## [9.190.0] — 2026-08-29

### Fixed
- **A party's ROLE was lost whenever a qualifier stood between its entity type
  and its role parenthetical.** "Sonoran Crest Management, Inc., an Arizona
  corporation HOLDING ARIZONA REAL ESTATE BROKER LICENSE NUMBER BR-558214
  (\"Manager\")" — `PARTY_DECL` wanted the parenthetical immediately after the
  type, and `BETWEEN_RE` cannot supply it either, because its capture
  terminates at the comma before "an Arizona corporation". A party with no role
  is invisible to every rule that compares an obligor against the party set, so
  OBLI-002 reported a MUTUAL indemnity as one-sided.

  The gap refuses to cross "and", so a party cannot borrow the next party's
  role, and the leading period is admitted only as an ABBREVIATION period — one
  not followed by a capital across a space — so it cannot run past the end of
  the sentence. (The gap and the parenthetical are one optional group: left
  optional and non-greedy on its own, the gap always matched empty.)

### Changed
- Reading those roles made OBLI-002 visible where it had been silent. On five
  specimens the new finding is real and stays — a copyright, patent or
  trademark licence, a clinical trial agreement, and a medical director
  agreement each carry a genuinely one-sided indemnity, which is what the rule
  exists to surface.
- **`dpa-controller-processor` and `baa-subcontractor` now skip OBLI-002.** In
  a processor-side agreement the confidentiality obligation is one-sided by
  design — the processor holds the controller's data — so the finding is
  structural, not a drafting signal. Without the skip the fix would have added
  it to 54 corpus fixtures.

## [9.189.0] — 2026-08-29

### Added
- A tenant work letter and a residential property management agreement — the
  150th and 151st specimens. The work letter is clean: it routes on its own
  title, its family's checks are silent, and the always-on absence checks
  stand down because "This Tenant Work Letter is attached to and made a part
  of the Office Lease" is now read as a subordination recital.

### Fixed
- **FIN-005 could not read a fee "payable from the Operating Account on the
  TENTH (10TH) DAY of the following month."** The payment SOURCE sits between
  the verb and the date, and the ordinal is spelled with the numeral in a
  parenthetical; the ordinal-day branch read neither.
- **`property-management-agreement` shipped with an empty rule profile.**

### Known limitation, recorded
- **OBLI-002 reports a MUTUAL indemnity as one-sided** on the property
  management agreement. Only the first party's ROLE is extracted: the second
  party's role parenthetical sits behind a long qualifier ("an Arizona
  corporation holding Arizona real estate broker license number BR-558214
  (\"Manager\")"), and a party with no role is invisible to every rule that
  compares an obligor against the party set. Widening `PARTY_DECL`'s window
  does not fix it — these parties come from the `BETWEEN` path, whose
  `ROLE_PAREN` is anchored to the end of the segment. The signal tried is
  written into the specimen's pin so the next attempt starts from it.

### Not changed
- A static "does each presence rule's own recommendation satisfy its own
  patterns" sweep over all 1,306 rules with patterns was built and discarded:
  its string extraction cannot read a multi-line `fix:` value, so its 121
  single-pattern "failures" were mostly artifacts. Two spot-checks (RE-109,
  RE-150) were false alarms, and the work-letter specimen — which exercises
  both — is silent. The specimen method already covers this class with better
  evidence.

## [9.188.0] — 2026-08-29

### Added
- A 99-year ground lease with leasehold-mortgage protections — the 149th
  specimen.

### Fixed
Four checks fired on the drafting they exist to require:
- **RE-022, at `critical`, on a section headed "Escalation."** It knew CPI and
  "fair market rent" but not the commonest escalation of all — a flat periodic
  step ("Base Rent INCREASES BY ten percent (10%) on the fifth
  anniversary") — nor "fair market GROUND rent", where the qualifier sits
  between the words.
- **RE-023 on a section headed "ASSIGNMENT AND TRANSFER."** It wanted the
  bigram "assignment and sublet"; a ground lease grants the two rights in
  separate sentences ("Tenant MAY ASSIGN this Lease…"; "Tenant may SUBLEASE
  any portion of the Improvements").
- **RE-024 on "a memorandum of THIS Lease."**
- **TERM-005 on the REVERSION, which is the whole economic point of a ground
  lease** — "On expiration or earlier termination of this Lease, title to the
  Improvements VESTS IN Landlord automatically … and Tenant shall DELIVER the
  Improvements in good condition." Neither verb was in the consequence list.
  Both count only when they follow a termination trigger inside one sentence,
  so "Landlord shall deliver possession" and an equity vesting schedule are
  untouched.

## [9.187.0] — 2026-08-29

### Added
- A single-tenant ABSOLUTE net lease — the 148th specimen.

### Fixed
- **Three lease families were leaning on "Landlord", "Tenant" and
  "Premises"** — the three words every lease contains — as distinguishing
  phrases, so a net lease routed first to `lease-commercial-multitenant` and
  then to `lease-residential-us`. Each family keeps only the vocabulary that
  is actually its own (Tenant's Proportionate Share / Common Area / CAM for
  the multitenant lease; security deposit / no smoking / pets for the
  residential one).
- **`net-lease`'s own distinguishing phrases were the MULTITENANT
  vocabulary** — "common area maintenance" and "CAM", which no single-tenant
  net lease carries. Replaced with "absolute net", "without abatement",
  "single-tenant", "tenant shall pay all real estate taxes".
- **RE-001 conjoined a CAM / operating-expense pillar onto a family named
  "Single-Tenant Net Lease"**, at `critical`. An absolute net lease has no
  common area and no landlord-billed expense pool — the tenant pays every cost
  directly and says so — so the rule was unsatisfiable by the very document it
  exists for. The cost CATEGORIES are the allocation, whoever bills them.
- **RE-004 wanted "maintenance and repair" adjacent**, and a net lease writes
  the verb series: "Tenant shall MAINTAIN, REPAIR, AND REPLACE every part of
  the Premises", under a section headed "MAINTENANCE, REPAIR, AND
  REPLACEMENT". Reported missing at `critical`.
- **A DECIMAL-numbered run-in heading was not registered as a heading.** In
  "3.1 Base Rent. Tenant shall pay annual Base Rent of $674,800" the period
  belongs to the number, not after it, so every subsection heading in a
  decimal-numbered agreement went unregistered and the lease was told it uses
  Base Rent without defining it. A bare integer still needs its delimiter, so
  a sentence opening on a year is not mistaken for a heading.

## [9.186.0] — 2026-08-29

### Added
- **`npm run golden:churn`** (`tools/golden-churn.mjs`) — after a golden
  regen, prints only the fixtures whose FINDING-ID SET actually changed, and
  what came off or on.

  A regen rewrites every golden, so `git diff` shows hundreds of files whose
  only change is `result_hash` and the rule versions. Filtering that by
  grepping the diff for non-hash lines works on the pretty-printed v3 goldens
  and is **blind to the v4 ones, which are a single line of JSON** — a rule
  that stopped firing on a v4 fixture looked exactly like a version bump. That
  is how 9.185.0's removal of IPL-021 from `ip-licensing-copyright-minimal`
  first read as zero churn.

### Documentation
- `docs/adding-a-rule.md` gains "4c. Read the golden churn properly".

## [9.185.0] — 2026-08-29

### Added
- A book publishing copyright license — the 147th specimen.

### Fixed
- **IPL-021 demanded a CITATION to 17 U.S.C. § 106, at `critical`.** No real
  copyright license carries one: a publishing agreement grants "the exclusive
  right to reproduce, distribute, publicly display and create derivative
  works" and never names the statute. Neither does the rule's own
  recommendation. It was firing on this family's own **minimal-PASS
  fixture** — a rule no compliant document could satisfy, sitting in the
  golden corpus. Read as a conjunction the two pillars now mean "names the
  reproduction right AND at least one other § 106 right (or cites the
  section)", which is what an enumerated grant looks like. The fixture built
  to fail it still fails it.
- **`copyright-license` routed to `msa-general`** — the family listed
  "patent", "trademark" and "assignment" as NEGATIVE features, and a copyright
  license reserves patent and trademark rights in terms and says in its own
  Ownership section that it "is a license and not a transfer of copyright
  ownership, and nothing in it constitutes an ASSIGNMENT of the copyright".
  The fourth self-penalizing family found by writing the document.

## [9.184.0] — 2026-08-29

### Added
- A university exclusive patent license, Bayh-Dole subject — the 146th
  specimen.

### Fixed
- **A patent license routed to `eula`** — an end-user licence for consumer
  software — and was told it states no EU consumer-law minimums under the
  Digital Content Directive. The family listed "trademark", "copyright" and
  "assignment" as NEGATIVE features, and a patent license reserves trademark
  and copyright rights in terms ("No license is granted under any copyright,
  trademark, or know-how of Licensor") and has an assignment clause. Three
  penalties on its own standard drafting, and the third self-penalizing family
  found this way after `trademark-license` and `construction-contract`.

## [9.183.0] — 2026-08-29

### Documentation
- `docs/adding-a-rule.md` gains **"4b. Write the document, then run the CLI on
  it"** — the method that found every rule defect fixed in the last four
  sessions, the four symptom classes to read the output for, and the two traps
  (probe position-dependent rules through the CLI, and check the
  engineered-to-fail fixture before broadening a pattern).
- README: the suite floor is now `10,000+ passing tests`.

## [9.182.0] — 2026-08-29

### Added
- An ASF-style individual contributor license agreement — the 145th specimen.

### Fixed
- **A definition whose alias is PARENTHESIZED registered NEITHER term.**
  `"You" (or "Your") means …` is how every CLA defines its two pronouns; the
  alias pattern wanted `"You" or "Your" means`, so the definition was lost
  entirely and "Your Contributions" was reported as never defined.
- **The EXECUTION DATE of a signed form was not read as its effective date.**
  A CLA, a consent, an acknowledgment and an offer letter all put their only
  date on the "Date:" line the signer fills in, at the bottom of the page —
  nowhere near the first quarter STRUCT-002 looks at. The date must FOLLOW the
  label, so an unsigned template's "Date: ____________" still reports.
- **The execution date was registered as a PARTY.** All four of "By:",
  "Name:", "Title:" and "Date:" mark a signature-block line, but only the
  first two carry a name — so a CLA ending in "Date: May 14, 2026" reported
  one party, named "May 14, 2026". That also masked the true finding that the
  form names no parties the extractor can read.
- **`contributor-license-agreement` listed "royalty" as a NEGATIVE feature**,
  and every CLA grants a ROYALTY-FREE license. It also shipped with no rule
  profile, so a one-way copyright grant was told it provides no indemnity,
  caps no liability, and states no termination path.

### Changed
- `bad-employment` and `bad-saas` no longer report "No Effective Date found".
  Both are signed and dated on the signature line ("Date: January 1, 2026"),
  which is an identifiable starting point — the finding was a false positive
  on them. This is the intended consequence of the STRUCT-002 change above and
  the only substantive golden churn.

## [9.181.0] — 2026-08-29

### Added
- An AIA-style owner-contractor agreement — the 144th specimen. All seven
  CON-001..007 checks are silent on a compliant one.

### Fixed
- **`construction-contract` listed the four things every construction contract
  is made of as NEGATIVE features** — "subcontractor", "lien waiver",
  "performance bond", "change order" — so an OWNER-CONTRACTOR AGREEMENT
  routed to `independent-contractor` and none of its own checks ran, including
  the anti-indemnity screen the family exists for.
- **CON-006 read the ANTI-INDEMNITY CARVE-OUT as a denial of the indemnity, at
  `critical`.** "This indemnity … does not require Contractor to indemnify any
  party for that party's own negligence" is the drafting the state
  anti-indemnity statutes demand, and the drafting CON-006's own
  recommendation asks for. `expressDenial` now refuses a causative followed by
  an object and an INFINITIVE — "does not require X TO indemnify", "shall not
  permit any subprocessor TO use" — while a denial with a DIRECT object ("does
  not require OFAC screening") still reads as one. (This replaces the blanket
  causative blocklist added in 9.167.0, which was too broad.)
- **CON-005 read only the PLURAL and only one word order.** A contract states
  the rule one condition at a time — "a differing site CONDITION … entitles
  Contractor to an equitable adjustment", "DIFFERS MATERIALLY from the
  conditions indicated" — and the clause that uses the term of art three times
  was reported missing.
- **`independent-contractor` scored 0.9 on a construction contract** on the
  title keyword "contractor agreement", which "Owner-Contractor Agreement"
  contains. "substantial completion" and "the Architect" — which no
  independent-contractor agreement carries — now separate them.

## [9.180.0] — 2026-08-29

### Added
- A trademark license — the 143rd specimen. All six IPL-013..018 checks
  (quality control, goodwill inurement, no-challenge, proper use) are silent
  on a compliant one.

### Fixed
- **`trademark-license` penalized its own standard drafting three times over.**
  It listed "patent", "copyright" and "assignment" as NEGATIVE features — and
  every trademark license reserves patent and copyright rights in terms ("No
  license is granted under any patent, copyright, or trade secret") and has an
  assignment clause. The three penalties cost it 0.3, so a document titled
  TRADEMARK LICENSE AGREEMENT routed to `msa-general` and none of its own
  checks ran. Replaced with the title-shaped phrases that do distinguish:
  "patent license agreement", "copyright license agreement", "assignment of
  the marks".

## [9.179.0] — 2026-08-29

### Fixed
- **IPDATA-001 could not read the bare VESTING sentence.** "ALL RIGHT, TITLE,
  AND INTEREST IN AND TO THE WORK PRODUCT vests in Customer upon creation" is
  the standard allocation; the title-vesting branch wanted "title TO" / "title
  IN", and here the phrase reads "title, and interest in". Anchored on an IP
  object, so an assignment of "all right, title and interest in and to the
  Assigned Contract" is still not read as an IP allocation.
- **RISK-001 did not know "SAVE harmless" or "KEEP harmless"** — the older
  forms, still used in leases and construction contracts: "the Lessee shall
  SAVE the Lessor HARMLESS from all claims arising out of use of the
  Premises".

Ten governing-law, eight IP-allocation and eight indemnity shapes were written
out and run against CHOICE-001, IPDATA-001 and RISK-001. CHOICE-001 read all
ten; the two above were the only misses.

## [9.178.0] — 2026-08-29

### Fixed
- **Two liability-cap shapes RISK-005 could not read.** Eleven ways a contract
  caps liability were written out and run against the rule; two ordinary ones
  were missed, and each made the rule report "No limitation-of-liability
  clause detected" on a contract that caps it in terms:
  - the ADJECTIVE rather than the noun — "In no event shall the Escrow Agent
    be LIABLE FOR MORE THAN the fees it received under this Agreement";
  - the cap stated as an EQUATION — "The maximum liability of the Supplier
    under this Agreement IS THE purchase price of the affected Goods".

  A consequential-damages exclusion and a sole-and-exclusive-remedy clause
  still report: neither is a cap on the amount.

## [9.177.0] — 2026-08-29

### Added
- A managed-care participating provider agreement — the 142nd specimen. All
  six HC-121..126 checks are silent on a compliant one.
- `PlaybookMatchResult` and its alternatives now carry `raw_confidence`, the
  score BEFORE clamping to [0, 1] — which is what actually decides the
  ranking. Two families can both display 1 while one outscores the other by a
  wide margin.

### Fixed
- **The routing-margin guard called a 1.2-vs-1.0 win a coin flip**, because it
  compared the CLAMPED confidence. It now compares what the matcher sorts on.
- **`mutual-nda` listed "each party", "either party" and "both parties" as
  distinguishing phrases** — mutuality words that appear in nearly every
  bilateral contract, and the reason an NDA scored 1.0 on a managed-care
  provider agreement. Replaced with the NDA's own register: "disclosing
  party", "receiving party", "each party may disclose". Three entries come off
  the `KNOWN_BROAD` debt list in `distinguishing-base-rate.test.ts`.
- **`payer-provider-agreement` shipped with an empty rule profile**, and was
  told it allocates no IP and caps no liability. Neither belongs in a provider
  agreement — nor in an equipment lease, a credit agreement, or a factoring
  agreement, whose pins each carried an `IPDATA-001` no such contract can
  answer.

## [9.176.0] — 2026-08-29

### Added
- A third-party litigation funding agreement — the 141st specimen. All six
  SET-138..143 checks are silent on a compliant one.

### Fixed
- **CHOICE-011 told a Delaware LP and a Massachusetts corporation that their
  New York governing law is void as to a California worker.** There is no
  worker: the funder's ADDRESS is in San Francisco. Cal. Lab. Code § 925 is a
  rule about employment contracts, and v1.1.0 had already removed the
  state-of-incorporation branch for exactly this reason — the address branches
  added later reopened the same hole from the other side. The rule now
  requires an employment relationship before it looks for a California worker.
- **FIN-005 could not read "shall FUND each conforming draw within fifteen
  (15) business days."** A funder funds, a lender advances, an escrow agent
  disburses, an employer reimburses; each is a payment term, and the branch
  led only on "shall pay".
- **`litigation-funding-agreement` shipped with an empty rule profile** and
  was told it allocates no IP, provides no indemnity and caps no liability.

## [9.175.0] — 2026-08-29

### Added
- A North Carolina residential purchase and sale contract — the 140th
  specimen. The eight RE-138..145 residential checks are silent on a compliant
  one.

### Fixed
- **A family home sale routed to the COMMERCIAL `real-estate-psa`** and was
  told at `warning` to add a § 1031 like-kind-exchange cooperation clause, and
  at `critical` that it states no closing conditions and no seller
  representations. The residential family's title keywords did not include
  "residential purchase AND SALE agreement", and nothing distinguished the two
  families in the other direction — so `lead-based paint`, a disclosure
  federal law requires only of a pre-1978 dwelling and which no commercial PSA
  carries, is now a negative feature of the commercial one.
- **RE-009 reported "Legal property description missing" at `critical` on a
  paragraph that sets one out.** "legally described as Lot 17, Block 4,
  Fernbank Estates, Plat Book 42, Page 118" is a textbook lot-and-block
  description; every pattern wanted the literal words "legal description" or
  a reference to an exhibit. Lot-and-block, plat book, deed book, the public
  land survey, and metes and bounds are now read directly.
- **`residential-purchase-agreement` shipped with an empty rule profile** and
  was told it allocates no IP, provides no indemnity and caps no liability.
- **An ALL-CAPS run-in heading was not read as a heading** — "4. ESCROW AGENT.
  The Escrow Agent is Fernbank Title & Trust, LLC" — and the ARTICLE was not
  stripped before the heading was looked up, so the section's own title was
  reported as a term the contract forgot to define. Every run-in heading in a
  paragraph is now registered, not just the leading one: with blank lines
  stripped the ingest joins a document into one paragraph, and a `^`-anchored
  test made the finding set depend on the format of the upload.
- **An entity name with an AMPERSAND** — "Fernbank Title & Trust, LLC",
  "Grantham & Boyle LLP" — stopped the name run at the first word, so
  "Fernbank Title" was reported as an undefined term.

## [9.174.0] — 2026-08-29

### Added
- An amended and restated NVCA-style stockholders' agreement — the 139th
  specimen.

### Fixed
- **A section headed VOTING AGREEMENT was reported at `critical` as containing
  no voting agreement.** GOV-040 wanted "vote in favor" adjacently, and every
  real voting agreement puts the OBJECT between them: "each Stockholder shall
  vote ITS SHARES in favor of the transaction", "shall vote ALL SHARES OF
  CAPITAL STOCK OVER WHICH IT HAS VOTING CONTROL so that the Board consists of
  seven directors".
- **GOV-041 reported the IPO-termination clause missing on the NVCA term
  clause**, which ends the agreement without ever using the word: "continues
  until the earliest of (a) the closing of a Sale of the Company, (b) the
  closing of a firm-commitment underwritten public offering".
- **A drag-along's CARVE-OUT was reported as a non-compete, twice.** "No
  Stockholder shall be required, AS A CONDITION OF THE DRAG-ALONG, to agree to
  any non-competition covenant" promises that none will be imposed. PERS-005's
  disclaimer test wanted "required to" adjacently and could not reach past the
  parenthetical; PERS-001 did not consult that test at all, and now shares it.
- **A covenant about the CHARTER's indemnification provisions was read as an
  indemnity of this document.** "The Company shall not amend the
  indemnification provisions of its certificate of incorporation" made
  TEMP-012 report the survival clause silent on an indemnification that is not
  there — as did the drag-along's limit, "shall not be required to indemnify
  beyond its pro rata share".
- **`stockholders-agreement` listed "bylaws" as a negative feature**, and a
  stockholders' agreement references the company's bylaws as a matter of
  course. Narrowed to "these bylaws", which only a set of bylaws says of
  itself. (Caught by `self-penalizing-features.test.ts` the moment the
  specimen existed.)

## [9.173.0] — 2026-08-29

### Fixed
- **An E-SIGNED contract reported "No signature block detected" at
  `critical`.** Thirteen ways a document can be executed were written out and
  run against STRUCT-003; the platform e-signature was the one it could not
  read. A contract signed through DocuSign, Adobe Sign, or Dropbox Sign
  carries the platform's stamp and a typed name beside a timestamp — "By: Dana
  Reyes (Aug 4, 2026 14:02 EDT)" — with no "Name:"/"Title:" grid beneath it.
  That is ONE weak token against a two-token floor, so the executed copy of an
  enormous share of modern contracts was accused of not being signed. The
  stamp is never ordinary prose, so it is self-sufficient, like a conformed
  "/s/".

## [9.172.0] — 2026-08-29

### Added
- A franchise disclosure document, cover page through the receipt — the 138th
  specimen. The six FTC Franchise Rule checks are silent on a compliant one.

### Fixed
- **A person named with their OFFICE in apposition was reported as an
  undefined term.** "Renata Kowalczyk, Chief Executive Officer" is how an FDD
  names its officers in Item 2 — and an FDD signs nothing, so the
  signature-line and notarial sources of person names found nothing and the
  CEO was flagged as a Title-Case term the document forgot to define. The
  office list is closed, so an ordinary "Acme Holdings, Inc." or a defined
  term followed by a common noun is not swept in.

## [9.171.0] — 2026-08-29

### Added
- An expert witness retention letter — the 137th specimen.

### Fixed
- **`expert-witness-retention` shipped with an empty rule profile** while its
  sibling `engagement-letter` already had the right one. A retention letter
  from counsel to a forensic engineer was told at `warning` that it allocates
  no IP, provides no indemnity, caps no liability and states no path to
  terminate for cause. A retention letter carries none of those.
- **RISK-002's parent-instrument guard read only a ONE-word title.** An
  indemnity "under the Purchase Agreement" describes a parent deal's
  allocation rather than an indemnity of this document, and that is what the
  guard exists to exclude — but "under the Stock Purchase Agreement" fell
  straight through, so an escrow securing the seller's obligations under it
  was scored as seller-heavy asymmetry. "under this Agreement" is still this
  document and still counts.

## [9.170.0] — 2026-08-29

### Fixed
- **The definitions half of `amendsParentAgreement()` could never fire on the
  drafting it was written for.** The test has no `i` flag — by design, because
  the parent must be a NAMED instrument — and its leading literal is
  lowercase, so "**C**apitalized terms used but not defined in this Addendum
  have the meanings given in the Purchase Agreement" matched nothing. That is
  how every one of them is written. Case-folded by hand, exactly as
  `PARENT_CONTROLS` folds its own leading phrase.
- **An addendum, a rider and a work letter say what an exhibit says** — "This
  Artificial Intelligence Addendum is incorporated into and forms part of the
  Master Services Agreement dated August 4, 2023" — and none was recognized.
  They now have their own half, kept OUT of `isIncorporatedExhibit` because
  that test also answers "is this document separately executed", and they are:
  suppressing the signature and party checks on them would be wrong.
- **"This Data Processing Schedule FORMS PART OF the Master Subscription
  Agreement"** was missed because the incorporation test required a copula
  before the verb.

The twenty subordination recitals such documents actually open on were written
out and run against the helper; seven were missed. All twenty now pass, and
five negatives — a standalone agreement, an agreement incorporating its own
exhibits, an agreement defining its own terms, a mere mention of another
agreement, and a DPA incorporating the SCCs — still return false. The table is
pinned in `_helpers.test.ts`.

## [9.169.0] — 2026-08-29

### Added
- A vendor information-security exhibit — the 136th specimen.

### Fixed
- **An exhibit that names ITSELF was not recognized as subordinate to its
  parent.** "This INFORMATION SECURITY Exhibit is attached to and incorporated
  into the Master Services Agreement dated October 12, 2024" is the recital
  every such document opens on, and `amendsParentAgreement()` saw neither
  half of it: the test required the bare noun immediately after "This", and
  admitted "incorporated into" only when it followed "is" directly. An
  exhibit carries no ratification clause — it changes nothing — so this
  recital is all it has, and without it the document was reported as having
  no governing law, no venue, no IP allocation, no indemnity, no liability
  cap and no termination clause. All six live in the agreement it is attached
  to. This is the highest-leverage helper in the engine; the fix reaches every
  rule that consults it.

### Verified, not changed
- The nine `ADDENDA-001..009` security checks are silent on a well-drafted
  information-security exhibit, and the family's empty `rule_overrides` is
  correct: the always-on absence checks already stand down for an addendum
  through `amendsParentAgreement()`, so no skip profile is needed.

## [9.168.0] — 2026-08-29

### Added
- A general assignment and assumption of a services contract — the 135th
  specimen.

### Fixed
- **An assignment of a freight contract routed to `lease-assignment`** at 0.9
  and was told at `critical` that it has no LANDLORD-CONSENT clause, plus that
  it addresses neither the security deposit nor recording. There is no lease
  and no landlord. Two causes, both base-rate: that family listed **"assignor"
  and "assignee"** as distinguishing phrases — the two words in every
  assignment of anything — and claimed the bare title keyword **"assignment
  and assumption"**, which is the other family's own name. Replaced with
  "assignment of the lease" and "the premises"; the lease specimen still
  routes on "assignment and assumption OF LEASE" and is unchanged.
- **MNA-108 demanded a SCHEDULE of assigned contracts, at `critical`, from a
  document that names the one contract it assigns.** The pattern read only the
  plural, so "that certain Transportation Services Agreement dated May 8, 2023
  … (the 'Assigned Contract')" — which identifies exactly what moved, the
  thing the rule exists to require — satisfied nothing.

## [9.167.0] — 2026-08-29

### Added
- An AI addendum to a master services agreement — the 134th specimen.

### Fixed
- **A CAUSATIVE was read as an express denial.** "Vendor shall not PERMIT any
  subprocessor or model provider to use Customer Data to train any model" is a
  negative covenant about what a subprocessor may do; ADDENDA-015 read it as
  the addendum stating that its subprocessors are NOT disclosed, and said so
  at `warning` — in a document whose very next clause promises to identify
  each model provider on request. `expressDenial`'s word gap now refuses to
  cross permit / allow / authorize / cause / enable, the same way it already
  refuses to cross a conditional or a scope verb: a causative makes the topic
  the subject of an embedded clause, not the object of the negation. This is
  a shared helper, so every rule that uses `denied_if` is corrected.
- **ADDENDA-015 did not know the phrase "model provider"** — the current term
  of art for OpenAI / Anthropic / Google. It is matched as a disclosure
  OBLIGATION rather than a bare noun, because an addendum that says "the
  parties have elected not to include a schedule identifying the third-party
  model providers" names them only to say it does not list them.
- **IPDATA-004 could not read the standard ownership formulation.** "Customer
  owns all right, title, and interest in and to Customer Data" is how a
  contract ordinarily allocates data ownership, and the `owns … data` branch
  could not reach it: after "owns all" comes "right", not "data".

### Deliberately not changed
- **RISK-015 on an addendum.** Unlike the absence checks that consult
  `amendsParentAgreement()`, RISK-015 is about a NEW obligation the addendum
  itself creates — an added indemnity whose cap is left to the parent. That
  is worth a reviewer's eye, so the warning stands.

## [9.166.0] — 2026-08-29

### Added
- A non-binding lease letter of intent, countersigned — the 133rd specimen.

### Fixed
- **`letter-of-intent-lease` shipped with an empty rule profile** while its
  M&A sibling `loi-term-sheet` already carried the right one. A term sheet
  whose own text says it is non-binding was told at `warning` that it states
  no IP ownership, no indemnity, no limitation of liability and no
  termination for cause — four clauses a letter of intent is not supposed to
  carry, and none of which the definitive lease's absence makes a defect.
  The sibling's eight-skip profile is now copied onto it.
- **A term that titles its own RUN-IN heading was reported as undefined.**
  Occurrences inside the heading segment were already discounted, but the
  heading's own words were never registered AS a heading, so every use in the
  paragraph beneath counted: "4. Base Rent. Base Rent shall be $34.50 per
  rentable square foot ..." was reported as using Base Rent without defining
  it. Standalone heading lines had been registered since the discovery-
  response fix; run-in headings, which is how most numbered agreements are
  written, had not.

## [9.165.0] — 2026-08-29

### Added
- A three-party technology escrow agreement, the 132nd specimen. The escrow
  pack (IPL-129..133) is silent on it, and it exposed three false positives
  that had nothing to do with escrow.

### Fixed
- **A survival clause that names its sections BY NUMBER was read as naming
  nothing**, because the section-reference expander required a `.` or `)`
  right after the clause number. `6.3 Confidentiality.` — number, space,
  heading — is the dominant modern form, so in such a document no paragraph
  was ever incorporated and "Sections 6, 7 and 8.2 survive" was reported as
  silent on both the confidentiality section and the indemnity it names.
  TEMP-012's own recommendation says standard drafting names each sticky
  section "by number or category"; the rule accepted only the category. A
  reference to Section 6 now also reaches 6.1 through 6.3 — the survival
  clause names the SECTION, and the obligations live in its subsections.
  (TEMP-007 shares the helper and was wrong the same way.)
- **FIN-005 could not read a fee "payable IN ADVANCE on each anniversary of
  the Effective Date."** The `in advance` / `in arrears` interstitial was
  admitted only by the ordinal-day-of-each-month branch, so the branch that
  knows "each anniversary" could not reach past it.
- **CHOICE-006 reported "seat not specified" on a clause that seats the
  arbitration in terms.** In the ordinary institutional form — "under the
  Commercial Arbitration Rules of the American Arbitration Association,
  seated in New York, New York" — the rules and the body sit between the
  arbitration noun and the participle, so neither the participle branch
  (which wants "arbitration seated in") nor the institution branch (which
  wants a bare "in" right after the provider) could reach the seat.

## [9.164.0] — 2026-08-29

### Added
- An amended and restated Delaware certificate of incorporation, the 131st
  specimen.

### Fixed
- **GOV-027 demanded an incorporator clause of a RESTATED charter**, at
  `critical`. The incorporator signs the ORIGINAL certificate; a restatement is
  executed by an officer under DGCL § 245. Every Series A charter there is was
  being accused of omitting a clause it is not supposed to carry.
- **GOV-031 could not read the blank-check authority in Article IV** because
  "by resolution" sits between the words it wanted — "to fix BY RESOLUTION the
  designation, powers, preferences" — and "may be issued" between the others:
  "the Preferred Stock MAY BE ISSUED in one or more series".

## [9.163.0] — 2026-08-29

### Added
- **`specimen-routing-margin.test.ts`** — a specimen must BEAT its runner-up,
  not tie it. The existing regression test asserts the family and a 0.6 floor,
  and says nothing about the gap to the next family; a tie is decided by a
  lexicographic comparison of the two ids, which is arbitrary. That is how the
  voting agreement and the Rule 26(f) report both went wrong. Four ties are
  declared as real choices rather than defects — the two SaaS perspectives, the
  privacy-lint lens, and a credit agreement that is both a term loan and a
  revolver shaped.

### Fixed
- **A factoring agreement tied the SaaS packs at 0.9.** Three of
  `saas-customer`'s six distinguishing phrases were "the Service", "the
  Software", and "Subscription Term", and `saas-vendor` also carried "Vendor"
  and "Provider" — words in every services contract written. A factoring
  agreement was one lexicographic accident from being audited as a SaaS
  subscription.
- **"Subscription Agreement" is genuinely two documents** — the commonest title
  a SaaS agreement carries, and the name of the securities subscription
  agreement. Both SaaS packs claim it again, declared as an ambiguity the
  phrases decide.

## [9.162.0] — 2026-08-29

### Added
- An insider trading policy (already clean) and a proxy statement's
  Compensation Discussion and Analysis. One hundred and thirty specimens.

### Fixed
- **A proxy statement's CD&A routed to `executive-employment`** and drew five
  `critical` findings — that it had no § 409A clause, no § 280G clause, no
  restrictive covenants, and no signature block. Three of that family's six
  distinguishing phrases were "chief executive officer", "chief financial
  officer", and "named executive officer", which a CD&A names on every page and
  so does every board consent and officer's certificate. They are replaced by
  phrases only an employment agreement carries: "good reason", "base salary",
  "employment period".
- **A Compensation Discussion and Analysis is a proxy statement section**, and
  is now a title keyword of the family that owns it — along with the
  Compensation Committee Report.

## [9.161.0] — 2026-08-29

### Added
- **`family-owns-its-name.test.ts`** — a family may not claim another family's
  own name as a title keyword. The catalog-routing sweep cannot see this: it
  builds its probe from the family's own keywords AND its distinguishing
  phrases, so the phrases carry the family past its impostor. The collision
  only bites a real document, which may carry none of them — which is exactly
  what happened to the voting agreement.

### Fixed
- Five more families claimed a sibling's identity:
  - `piia` claimed "ip assignment"; a PIIA is never titled that.
  - `rspa` claimed the bare "stock purchase agreement".
  - `stockholders-agreement` claimed "investor rights agreement" and
    "investors rights agreement".
  - `saas-customer` and `saas-vendor` claimed "subscription agreement", which
    is the SECURITIES subscription agreement — a Regulation D document, not a
    SaaS one.
  - `employment-at-will-us` claimed "offer letter".

  Three claims are declared ambiguities rather than mistakes, each with its
  reason: the two deep-and-launch NDA pairs, a D&O indemnification agreement
  titled exactly "Indemnification Agreement", and "Separation Agreement", which
  in family law IS the marital settlement agreement.

## [9.160.0] — 2026-08-29

### Added
- An NVCA-style voting agreement, the 128th specimen.

### Fixed
- **A voting agreement routed to `stockholders-agreement`** and was told at
  `critical` that it had no tag-along, no right of first refusal, and no
  voting-agreement clause — on a document whose Article 1 is one. The
  stockholders family listed "voting agreement" among its OWN title keywords; a
  document titled "Voting Agreement" is a voting agreement.
- **EQT-057 could not read the covenant it exists for.** `\belect\b` cannot
  match "elected", which is how it is written: "each Stockholder shall vote its
  Shares so that one director IS ELECTED by the holders of Series A Preferred
  Stock". The covenant is also framed by RESULT as often as by the verb —
  "shall vote all Shares so that the Board consists of five directors".
- **A drag-along's PROTECTION was reported as a non-compete** (PERS-005). "No
  Stockholder is required to accept a covenant not to compete" is a promise
  that none will be imposed.

## [9.159.0] — 2026-08-29

### Added
- **`required-clauses-live.test.ts`** — a `required_clauses` entry must name a
  category the shipped classifier can emit.

### Fixed
- **The largest weight in the matcher was partly dead.** `required_clause` is
  worth 0.4 each, capped at 0.8, against 0.3 for a title keyword and 0.2 for a
  distinguishing phrase — and nine of the twelve launch playbooks named a
  category the classifier never produces, seven of them the same one
  (`payment-terms`). Each such entry is worth zero forever, and nothing said
  so. The dead entries are gone, and `employee-ip-assignment` is now
  `ip-ownership`, which the classifier does emit.

  The pipeline passes an EMPTY vocab — `{ vocab: { vocab: {} }, patterns:
  dkb.classifier.patterns }` — so only the classifier's twenty-one pattern
  categories are live; the vocab's ninety-odd are not, and the guard says so.

## [9.158.0] — 2026-08-29

### Changed
- **The pillar-vacuity debt list is empty.** Every conjunction in the catalog
  whose pillar its family's own title satisfies now carries the clause a
  compliant document writes, and the assertion that the rule is silent on it —
  thirty-three rows in all. A new collapsed conjunction fails the guard unless
  it is proved the same way.

### Fixed
- Two of the last seventeen were not merely collapsed but unsatisfiable:
  - `COMM-237` wanted "rebrand" or "under the OEM's brand" from a clause that
    grants the right plainly: "OEM may brand the OEM Products with its own
    marks."
  - `PRV-102` wanted the phrase "specific purpose" from a BIPA form that states
    the purpose the way § 15(b)(1) asks for it: "We collect and use the template
    for one purpose: to identify you when you clock in and out."

## [9.157.0] — 2026-08-29

### Changed
- **Eight more collapsed conjunctions proved.** Each now carries the clause a
  compliant document writes, and the assertion that the rule is silent on it:
  `DISC-001`, `DISC-007`, `DISC-020`, `PLDG-009`, `PLDG-012`, `EMP-101`,
  `EMP-150`, `HC-127`. Seventeen remain unproved.

## [9.156.0] — 2026-08-29

### Changed
- **The two conjunction guards are wired together.** A collapsed conjunction —
  one whose pillar its family's own title satisfies — is ACCEPTABLE once its
  surviving pillars have been proved against a hand-written compliant clause,
  which is what `compliant-conjunctions.test.ts` is for. Its table moved to a
  shared fixture module, and `pillar-vacuity.test.ts` reads it: an entry leaves
  the debt list either by being proved there or by having its vacuous pillar
  replaced. Six were already proved; twenty-five remain.

## [9.155.0] — 2026-08-29

### Fixed
- **Three conjunctions taken off the pillar-vacuity debt list**, each by
  replacing the pillar its family's own title satisfied:
  - `DISC-036` conjoined "notice of deposition" — the family's title — with the
    time-and-place test, so the whole check was the second pillar. The
    OPERATIVE sentence ("PLEASE TAKE NOTICE", "will take the deposition of") is
    what a notice carries and a title never does.
  - `PLDG-006` had the bare word "damages" as a pillar, and `complaint`'s title
    keywords include "petition for damages". The relief has to be DEMANDED with
    a verb now — awarded, recovered, entered — which a title never does.
  - `EST-401` conjoined "irrevocab", which is an Irrevocable Trust's whole
    name, with the recital that makes the trust irrevocable. The recital is the
    check; the word in the title is not.

  Thirty-one conjunctions remain on the list.

## [9.154.0] — 2026-08-29

### Added
- **`pillar-vacuity.test.ts`** — a conjunction may not rest on a pillar the
  family's own TITLE satisfies. The existing title-vacuity guard asks whether a
  WHOLE rule is satisfied by its family's title; a conjunction never is, because
  the other pillars fail, so that guard cannot see the failure one level down.
  A pillar met by the title contributes nothing and the check silently collapses
  onto whatever pillars are left — which is where three of the worst defects
  this catalog has had were hiding (`GOV-071`, `EMP-032`, `MNA-055`). Thirty-four
  conjunctions are in that state; the list is debt and may only shrink.

### Fixed
- `ENG-027` wanted the words "will perform" from a limited-scope agreement that
  LISTS the tasks — "The lawyer will draft the petition … the client will gather
  and provide bank statements" — while its other pillar was met by the family's
  own title, so the whole check rested on words nobody writes.

## [9.153.0] — 2026-08-29

### Added
- A California proprietary-information and inventions agreement, the 127th
  specimen.

### Fixed
- **EMP-032 told a PIIA at `critical` that it had no confidentiality clause**,
  on a document whose first two sections are one and whose TITLE names it. The
  check conjoined "proprietary information" — the family's own title, so it
  could never fail — with "non-disclosure", which the agreement never uses. It
  states the OBLIGATION instead: "I will hold Proprietary Information in
  confidence … and not disclose it to anyone outside the Company."
- **EMP-036 wanted "power of attorney" or "coupled with an interest"** from a
  clause that says "I appoint the Company as my ATTORNEY-IN-FACT for that
  limited purpose".
- **IPDATA-002 read the pre-existing-IP carve-out only in the assignment's own
  paragraph.** The carve-out is almost always its own section — "Limited
  Exclusion", "Prior Inventions" — sitting after the assignment it qualifies.
- `piia` no longer demands an indemnity, a liability cap, a termination clause,
  a venue, or a stated Effective Date of a unilateral employee agreement whose
  date is its signature date.

## [9.152.0] — 2026-08-29

### Added
- An OWBPA-compliant separation agreement and general release, the 126th
  specimen.

### Fixed
- **EMP-019 demanded the § 626(f)(1)(H) decisional-unit disclosure of an
  INDIVIDUAL separation.** The statute asks for it only in a group termination
  program, so every ordinary release was accused of omitting a disclosure the
  law does not ask it for. The check is gated on a group-termination signal
  now.
- **EMP-022 wanted the words "over and above"** from an agreement that makes
  the same statement structurally: the earned wages are paid "whether or not
  the Employee signs", and the severance only "if the Employee signs".
- **The head of a statute's name was reported as an undefined term.** "Age
  Discrimination in Employment Act" captures as "Age Discrimination", because
  the Title-Case run stops at the lowercase "in" — and every OWBPA release
  names that Act.
- `separation-agreement` no longer demands an IP-ownership allocation, a
  liability cap, or a termination clause of a document that IS the termination.

## [9.151.0] — 2026-08-29

### Added
- An answer with affirmative defenses, a Rule 41(a)(1)(A)(ii) stipulation of
  dismissal, and an open-source compliance policy. One hundred and twenty-five
  specimens. The two pleadings were already clean and are pinned so they stay
  that way.

### Fixed
- **A policy adopted by an OFFICER was told at `critical` that it had no
  signature block** (STRUCT-003). An engineering, security, or records policy
  is adopted by the officer who owns it — "Adopted by the Chief Technology
  Officer on March 9, 2026" — not by a board resolution, and demanding one is
  the same false positive the board form was added to answer.
- **`oss-compliance` penalized its own document for "contributor license"**, a
  term an open-source compliance policy necessarily discusses, and its title
  keywords did not include the spelling with "software" in it — so the policy
  matched at 0.5, one feature from the routing cliff. Found by the
  self-penalizing guard the moment the family had a specimen.

## [9.150.0] — 2026-08-29

### Added
- A Rule 30(b)(6) deposition notice, the 122nd specimen.

### Fixed
- **DISC-037 wanted Rule 30(b)(1)'s own vocabulary — "the name of the deponent
  is" — which no compliant notice contains.** A notice NAMES the person: this
  one names the organization three times, in its title, in its opening
  sentence, and in its designation paragraph. The name run is case-SENSITIVE,
  since under the `i` flag `[A-Z]` would match any word at all.

## [9.149.0] — 2026-08-29

### Added
- A joint Rule 26(f) report and discovery plan, the 121st specimen.

### Fixed
- **A Rule 26(f) joint report routed to `complaint`** and was told at
  `critical` that it demanded no relief and no jury trial. Four of
  `complaint`'s seven distinguishing phrases were "plaintiff",
  "jurisdiction", "venue", and "jury" — the words of every commercial
  contract's own governing-law and dispute clauses, and of every filing in
  every case. They are replaced by phrases only a complaint carries:
  "wherefore", "cause of action", "complains of", "demand for jury trial",
  "prays for judgment".
- **A one-paragraph caption threw its filing's title away.** Stripping a
  filing's blank lines merges the whole caption into one paragraph, with the
  docket and the judge MID-line and the title after them — and the walk skipped
  the line because it mentioned a docket. The report re-routed to
  `litigation-hold` and a stipulated protective order to `mutual-nda-deep`. The
  walk now reads past the docket, the judge, and a party-role designation,
  wherever each sits.
- **The federal venue line's "FOR THE" lead** — "FOR THE NORTHERN DISTRICT OF
  ILLINOIS" — was unreadable to a pattern that allowed one word before
  "district of".
- `DISC-035` wanted "discussed" or "prospects" from a report that states its
  posture by what the parties DID: "exchanged settlement positions … did not
  resolve the case … request a settlement conference".

## [9.148.0] — 2026-08-29

### Changed
- **STRUCT-016 no longer reports a MISSING attachment; STRUCT-018 owns that.**
  Eleven of the corpus's fourteen STRUCT-016 findings came with a STRUCT-018
  finding saying the same thing about the same exhibit, in the same words — one
  drafting fact, two `warning`s. On three more the two rules DISAGREED, and
  STRUCT-018 was right: its anchor search reads the exhibit's cover line
  whether the file styles it as a heading or leaves it as a paragraph, and
  STRUCT-016's was heading-scoped, so "Exhibit A — Stock Option Agreement" at
  the foot of an option grant read as an exhibit that is not there.

  What STRUCT-016 keeps is the fact STRUCT-018 cannot see: an exhibit that IS
  attached and has nothing in it. Its URL-incorporation pass — the risk that
  operative terms live on a page the vendor can edit — is untouched, and is
  what the rule is named for.

## [9.147.0] — 2026-08-29

### Fixed
- **STRUCT-006 is the most frequent warning in the catalog — it fired on 35 of
  the 120 specimens — so its false positives cost more than any other rule's.**
  Three classes came off:
  - **The names a privilege log is made of.** "Author: Dana Okwuosa",
    "Recipients: Peter Vance", "cc: Renata Silva" — a privilege log is a table
    of exactly those, and every name in one was reported as a term the log
    forgot to define. The labels sit mid-paragraph, where the cover-block test
    could not see them. One specimen went from eight reported terms to three.
  - **Named public bodies.** "Illinois Attorney General", "Nevada Governor",
    "Oregon Health Authority". A term a contract defines does not begin with
    the name of a state.
  - **Organizations.** "Cascade Valley Hospital", "Fairhaven Trust Company",
    "Commercial Lending Group" — a phrase ending in an organization noun is a
    name. (The single-word "Company" and "Trust", which are ordinary defined
    terms, never reach the multi-word candidate list.)
  - Counsel offices: "Associate General Counsel", "Outside Counsel". The office
    list knew the bare "General Counsel" only.

## [9.146.0] — 2026-08-29

### Fixed
- **A set of discovery responses drew three `critical` findings, two of them
  false.** Undertaking to serve a PRIVILEGE LOG is the Rule 26(b)(5)(A)
  withholding statement — it says responsive material is being held back and on
  what basis, in the form the rule prescribes for it — and DISC-018 and
  DISC-019 could not read it.
- **A phrase that names one of the document's OWN SECTION HEADINGS was reported
  as an undefined term.** A response set headed "GENERAL OBJECTIONS" whose
  answers say "subject to the General Objections above" is cross-referencing
  itself. Same reasoning as the numbered-heading test: a term whose section is
  headed with it has been addressed by that section.

## [9.145.0] — 2026-08-29

### Fixed
- **One drafting fact was reported twice in the same words.** PERS-001 and
  PERS-005 both emitted the title "Non-compete clause present" over the same
  span, on three specimens — one at `info`, one at `warning`. PERS-005 owns the
  presence finding and the jurisdiction analysis; PERS-001 now surfaces what
  its own description has always promised, the SCOPE: "Non-compete scope: For
  twelve (12) months, within fifteen (15) miles". Where the scope is not in the
  clause it prompts rather than accuses — the trigger matches the section
  heading ("14. Covenant Not to Compete.") as readily as the covenant, and the
  scope is then in the paragraph beneath it.

## [9.144.0] — 2026-08-29

### Added
- **`excerpt-is-evidence.test.ts`** — an excerpt with a span must be text the
  document contains. A finding carries three things a reader acts on: a title,
  a span the report highlights, and an excerpt printed beside it. An absence
  finding is zero-width and its excerpt is a marker; every other finding points
  at a range and must quote from it. The sweep runs the whole specimen corpus.

### Fixed
- **STRUCT-005 printed a comma-joined list of every unused defined term as its
  excerpt**, while pointing at the paragraph that defines the first one — so
  the report quoted a passage the document does not contain, and sent the
  reader to a range that does not say it. The excerpt is the first unused term
  now, which is text in the span; the full list stays in the description, where
  it already was. (STRUCT-006 already read this way.)

## [9.143.0] — 2026-08-29

### Added
- **A family must be reachable by its own DISPLAY NAME**, not only by its
  keyword list (`catalog-routing.test.ts`). A family's keywords and its name are
  written separately and drift apart: `healthcare-poa` listed the closed
  spelling only — "healthcare power of attorney" — while its name, and every
  document of the kind, is "Health Care Power of Attorney". A document so
  titled fell to `generic-fallback` and not one of the family's checks ran on
  it. All 254 families pass, with one declared perspective pair.

## [9.142.0] — 2026-08-29

### Added
- A COPPA direct notice to parents and a North Carolina health care power of
  attorney. One hundred and twenty specimens.

### Fixed
- **A COPPA direct notice routed to `cookie-notice`.** 16 CFR 312.4(b)'s own
  name for the document — "direct notice to parents" — was not a title keyword,
  and three of its family's six distinguishing phrases were spellings a real
  notice does not use.
- **PRV-110 wanted "parent may review" from a notice that addresses the parent
  as "you"** — which is what 16 CFR 312.4(c) asks the notice to do.
- **A health care power of attorney fell to `generic-fallback`** because its
  family's title keywords carried the CLOSED spelling only, "healthcare power
  of attorney", and the document is titled with the spaced one. Its family also
  listed "advance directive" as disqualifying, which a health care power of
  attorney routinely cross-references.
- **EST-027 wanted "takes effect upon" and "incapacity"** from the ordinary
  springing clause: "my agent's authority BEGINS when my attending physician
  determines in writing that I LACK THE CAPACITY to make or communicate my own
  health care decisions".
- IPDATA-005 now reads COPPA spelled out, and with a straight apostrophe.

## [9.141.0] — 2026-08-29

### Added
- An Illinois BIPA § 15(b) consent and a blank 45 C.F.R. § 164.508
  authorization for release of protected health information. One hundred and
  eighteen specimens.

### Fixed
- **A BIPA consent that recites the statute's own elements was told at
  `critical` that it obtained no written release** (PRV-101). The rule wanted
  "written release" or "I consent to"; the form says "I give my written consent
  … to that collection, storage, and use", which is the § 15(b)(3) release.
- **Five of a blank HIPAA authorization's own fields were reported as unfilled
  template content** (STRUCT-013, `critical`). A form marks a field with prose
  as readily as with a colon — "for the period ______ through ______",
  "expires on ______". Four or more labeled fields and a clear majority now
  settle that the document is a form and every blank in it is a field; two
  labeled fields and one the drafter forgot still report.
- **A HIPAA authorization was reported as citing no data regime**
  (IPDATA-005). The redisclosure warning § 164.508(c)(2)(iii) requires — "may
  then no longer be protected by the federal privacy regulations" — names it.

## [9.140.0] — 2026-08-29

### Added
- A research informed-consent form, the 116th specimen.

### Fixed
- **The consent form 21 CFR 50.25 asks for was told at `critical` that it
  stated neither its purpose nor its duration** (HC-001). The regulation asks
  for a PLAIN-LANGUAGE explanation, and a well-drafted form gives one: "WHY
  THIS STUDY IS BEING DONE" and "you will have four visits over eighteen
  months" say both without using either word.
- **A person introduced by an honorific was reported as an undefined term.**
  "Dr. Ingrid Vasconcelos-Amaru" is a person, and a consent form names its
  principal investigator that way twice — in the header block and in the
  contact section.

## [9.139.0] — 2026-08-29

### Fixed
- `DISC-034` wanted the word "deadline" from a Rule 26(f) report that states
  its schedule by the events themselves — "fact discovery closing December 18,
  2026; dispositive motions due February 12, 2027; trial-ready June 7, 2027".
- `SET-025` wanted the past participle and could not read the present tense a
  litigation hold notice is written in: "the Company reasonably ANTICIPATES
  litigation".

## [9.138.0] — 2026-08-29

### Fixed
- **Six more columns could not read the clause they ask for.** Every one is the
  same shape: the rule knows one grammatical form of the sentence and a drafter
  wrote another.
  - `DISC-030` wanted "subjects on which discovery" from a Rule 26(f) report
    that states its plan as deadlines: "fact discovery closing December 18,
    2026".
  - `ENG-031` wanted "upon delivery" or "closing letter" from "the
    representation ends when the transaction closes … we will confirm the end
    of the representation in writing".
  - `ENG-032` wanted the adjacent "representation has ended" from a closing
    letter that puts the scope between the noun and the verb — "our
    representation OF YOU IN THIS MATTER has ended".
  - `GOV-144` wanted the noun phrase "determination of entitlement" and could
    not read the sentence run the other way: "Entitlement to indemnification IS
    DETERMINED by the disinterested directors".
  - `GOV-146` wanted the hyphenated "non-exclusive" and not DGCL § 145(f)'s own
    wording, "are NOT EXCLUSIVE of any other rights".
  - `GOV-147` wanted the verb forms and not the nominal one: "survive the
    CESSATION OF the Indemnitee's service".

## [9.137.0] — 2026-08-29

### Fixed
- **Three more discovery columns could not read a compliant response.**
  - `DISC-004` knew the passive voice only — "produced in native format" — and
    a production instruction is written in the imperative: "Produce
    electronically stored information in single-page TIFF images with a
    document-level load file."
  - `DISC-017` wanted "on the ground that" from an objection written the way
    practitioners write one: "objects to this request as overbroad BECAUSE it
    seeks documents from 2011, six years before the parties first did
    business."
  - `DISC-018` wanted the passive withholding statement and could not read the
    active one: "Defendant is withholding documents responsive to this request
    on the basis of the attorney-client privilege."

## [9.136.0] — 2026-08-29

### Added
- **`compliant-conjunctions.test.ts`** — for each repaired conjunction, the
  clause its own recommendation asks for, and the assertion that the rule is
  silent on it. Fourteen rows, every one of which was a real defect.

### Fixed
- **A sweep of every `require_all_present` / `all: true` conjunction in the
  catalog**, ranked by whether the rule's own recommendation text satisfies its
  own patterns, then confirmed by writing the compliant clause by hand. Eight
  more columns could not be satisfied by the drafting they exist to bless:
  - `ENG-002` wanted the adjacent "our client is", which a letter opening more
    than one matter never writes ("our client IN THIS MATTER is").
  - `SET-106` knew the covenant-side characterization and not its mirror: a
    settlement agreement says "this is a general release, not a covenant not to
    sue".
  - `COMM-231` wanted the adverb — "renews for a further term of one year
    unless you cancel" carries the renewal without it, and TEMP-011 already
    reads it that way.
  - `COMM-146` wanted "business of the venture" and never the possessive "the
    Venture's business is"; and "shall not compete" and never "may not pursue".
  - `MNA-055` conjoined THREE spellings of one fact, the first of which is the
    family's own title ("transition services") and so could never fail.
  - `RE-001` wanted the words "triple net" from an additional-rent clause,
    which never carries them — only the lease's title might.
  - `PRV-040` wanted the singular "state attorney general"; the plural is what
    everyone writes.
  - `DISC-019` could not read the Rule 34(b)(2)(C) withholding statement in its
    plainest form ("is withholding documents on the basis of the
    attorney-client privilege").

## [9.135.0] — 2026-08-29

### Added
- **Two specimens**: an Article 35 data protection impact assessment (already
  clean) and a California contingency fee agreement. One hundred and fifteen.

### Fixed
- **A document that defines both its parties in its first sentence was
  reported as having no defined terms at all.** `("the Firm")` and `("the
  Client")` put the article INSIDE the quotes — the dominant convention in UK
  drafting and common in US practice — and the parenthetical-definition pattern
  required the quote to open on a capital. The article is not part of the term:
  the body writes "the Firm", and the term is "Firm".
- **An exclusion written as a promise was invisible** (ENG-012). "The Firm will
  not represent the Client on appeal, in a bankruptcy, or in any other matter
  unless the parties sign a separate agreement" is the ordinary drafting, and
  it carried none of the labels the column wanted.

## [9.134.0] — 2026-08-29

### Added
- **Two specimens**: a credit union's whistleblower and non-retaliation policy
  (already clean) and a joint-representation conflict waiver. One hundred and
  thirteen.

### Fixed
- **A joint-representation waiver was told at `critical` that it did not
  identify its clients** (ENG-021) and did not say what happens if a conflict
  develops (ENG-023). A letter identifies its clients by ADDRESSING them — the
  address block, the salutation, the consent signature blocks — and almost
  never says "the clients are"; and the section headed "What happens if a
  conflict becomes actual" was invisible to a rule that wanted "if a conflict
  arises".
- **A covenant the document merely DESCRIBES was reported as one it imposes**
  (PERS-001, PERS-005). The same waiver letter tells its clients that "the
  scope and duration of the non-competition covenants each of you will sign"
  may affect them differently — a topic it raises about another instrument, not
  a restriction it creates.

## [9.133.0] — 2026-08-29

### Added
- **Two specimens**: a California Civil Code § 8132 conditional lien waiver on
  progress payment, in the statutory wording the form must use verbatim, and a
  blank HIPAA acknowledgment of receipt. One hundred and eleven.

### Fixed
- **A blank acknowledgment form was told at `critical` that it had no date of
  receipt** (HC-020) and that its own fields were unfilled template content
  (STRUCT-013). The form prints "Date: ______" beside the signature line —
  that IS the date-of-receipt line — and carries no digits at all until a
  patient fills it in. Two or more labeled blanks anywhere in a document now
  make it a form: whether the second shares a line with the first or sits
  three paragraphs below is a fact about the layout, not about the document.
- **A fragment of a document's own all-caps caption was reported as an
  undefined term.** The Title-Case run cuts "NOTICE OF PRIVACY PRACTICES" at
  the lowercase "of" wherever the body uses it, and the caption test only
  suppressed a phrase sitting on the caption LINE.
- **A professional corporation's suffix was only recognized with its periods.**
  "Ridgeway Valley Pediatric Associates, PC" is how a medical, legal, or
  accounting practice writes itself as often as "P.C.".
- **`construction-lien-waiver` penalized its own statutory form.** "change
  order" sat in its negative features, and § 8132's text says "pursuant to a
  written change order that has been fully executed by the parties". Found by
  the self-penalizing guard the moment the family had a specimen.
- **The golden-regeneration loops had no timeout.** Each rewrites every golden
  inside ONE `it`, and against vitest's 5-second default it was cut off partway
  — so a regen run left some goldens rewritten and the rest stale, and the next
  full run failed on exactly the ones it had not reached. That reads as flaky
  non-determinism and is neither.

## [9.132.0] — 2026-08-29

### Added
- **Five specimens**: an FCRA stand-alone disclosure and authorization, a
  CTIA-standard SMS program disclosure, an ISO additional-insured endorsement,
  a tenant estoppel certificate, and a UK cookie notice. One hundred and nine.

### Fixed
- **Two FCRA columns could not be satisfied by a COMPLIANT document.** A lawful
  stand-alone disclosure does not describe itself as stand-alone (EMP-148) and
  does not announce that it carries no liability waiver (EMP-149) — it simply
  carries neither. Both reported at `critical` on the very form they exist to
  bless, and EMP-148's own recommendation failed its own patterns. EMP-148 now
  reads the § 604(b) disclosure statement itself; EMP-149 is gated on a release
  actually being present, which is what it always meant.
- **An SMS program disclosure fell to `generic-fallback`.** Its family's title
  keywords and three of its six distinguishing phrases were spellings nobody
  uses — "reply stop to opt out" for "Reply STOP to cancel", "consent is not a
  condition of purchase" for "Consent is not a condition of any purchase".
  PRV-113 then wanted the first-person "I agree to receive" from a page that
  addresses the reader as "you", and PRV-115 wanted "autodialer" from a program
  that says "recurring automated marketing text messages" — the CTIA-standard
  wording, and the word almost everyone uses after Facebook v. Duguid.
- **An ISO additional-insured endorsement routed to `coi`** because
  "declarations" sat in its own family's NEGATIVE features, and an endorsement
  references the Declarations by definition. Its references into the policy's
  divisions — "Section II — Who Is An Insured is amended", "added to Section
  III — Limits Of Insurance" — read as broken internal cross-references; both
  number against the policy, not against the endorsement, which has no sections
  of its own.

## [9.131.0] — 2026-08-29

### Added
- **Four specimens from families that had none**: an SEC Form 10-K Item 1A, a
  HIPAA notice of privacy practices, the disclosure schedules to a stock
  purchase agreement, and the bylaws of a North Carolina nonprofit. One hundred
  and four specimens.

### Fixed
- **Nonprofit bylaws routed to `bylaws-corporation`** and were told at
  `critical` that they had no annual stockholders meeting and no stock
  certificate clause, and at `warning` that they did not acknowledge the DGCL
  § 220 inspection right — on a corporation with no members and no stock. The
  corporate family now carries the nonprofit vocabulary as disqualifying.
- **A set of nonprofit bylaws was told it had no § 501(c)(3) purpose recital**
  (GOV-071, `critical`), on a document whose Section 1.2 carries the textbook
  one. The rule conjoined THREE spellings of one fact, and its own
  recommendation failed its own conjunction. The bare citation is not one of
  the alternatives: this family's title is "Nonprofit Bylaws (501(c)(3))", so a
  pattern matching it alone could never fail — the citation counts when it is
  cited.
- **A well-drafted set of disclosure schedules was told it had no
  introduction** (MNA-039, `critical`) because the rule wanted the literal
  heading "General Notes", and **no materiality disclaimer** (MNA-042) because
  it wanted the negator "not" and the noun "admission" — while the two
  sentences every set carries are "Nothing disclosed here is an admission that
  the matter is material" and "The inclusion of any dollar amount is not a
  representation that the amount is material".
- **A filer's cybersecurity risk factor went unread** (REG-022) because the
  rule wanted the word "cybersecurity" from a section headed "Risks Related to
  Data Privacy and Security". "Security incident" is what the SEC's own Form
  8-K Item 1.05 calls the event.
- **A HIPAA notice of privacy practices was reported as citing no data
  regime** (IPDATA-005). It is the instrument 45 C.F.R. § 164.520 requires,
  written for patients, and it speaks HIPAA's vocabulary throughout —
  "designated record set", "unsecured protected health information",
  "psychotherapy notes" — without ever using the acronym. Its family's
  distinguishing phrases were the acronyms too, so it matched at 0.5, one
  feature from falling off the routing cliff.
- **A run-in section heading was only ever registered at a paragraph's start**.
  Stripping a document's blank lines merges a whole article into one paragraph,
  so every heading but the first sits mid-paragraph — and a clean set of
  bylaws drew fourteen broken-reference findings against headings printed in
  itself. The trailing period after the number is what separates a heading from
  a reference: "Section 3.4. Vacancies." declares, "under Section 3.4" refers.
- Skip profiles: `hipaa-npp` no longer demands a signature block, and
  `10-k-risk-factors` no longer demands a retention period, a data-ownership
  allocation, or an indemnity cap from a narrative disclosure section, nor
  reads its "we may not" sentences as covenants.

### Known
- `10-k-risk-factors.txt` is the one specimen whose findings still move when
  its blank lines go: an unnumbered run-in heading glues to the paragraph
  beneath it and the Title-Case run stops at the lowercase "to". The signals
  tried and rejected are recorded in `format-invariance.test.ts`.

## [9.130.0] — 2026-08-29

### Added
- **Four more specimens from families that had none**: a Washington quitclaim
  deed, a performance improvement plan, an AIA-style construction change order,
  and a California set of requests for admission. One hundred specimens now.

### Fixed
- **A quitclaim deed was told at `critical` that it lacked the granting words
  it is written in** (RE-128). The statutory short form is "conveys and
  quitclaims to" — RCW 64.04.050 and its siblings — with no "hereby" anywhere
  in it, and the rule required one. The quitclaim VERB is the signal now,
  recognized by what follows it, which is also what keeps the check off the
  document's own title.
- **A textbook performance improvement plan fell to `generic-fallback`**, so
  not one of the six PIP checks ran on it. Its family's distinguishing phrases
  were "30 days", "60 days", and "90 days", which distinguish nothing. Two of
  those checks then turned out to be unreachable anyway: EMP-040 did not know
  the "Expected Standards" heading, and EMP-044's acknowledgment window was
  forty characters when the ordinary sentence is longer than that ("My
  signature below acknowledges that this plan was discussed with me and that I
  received a copy. It does not indicate that I agree with its contents.").
- **A change order was told it had forgotten to define Contract Sum and
  Contract Time** — the two terms the AIA contract it modifies exists to
  define. STRUCT-006 now also stands down for a document that RATIFIES a named
  parent, not only one that says its terms are defined there.
- **A ruled writing space was reported as unfilled template content**
  (STRUCT-013, `critical`). "EMPLOYEE COMMENTS" over a rule is a line the
  reader fills in; a placeholder replaces something inside a sentence, and a
  rule that is the whole paragraph has no sentence to be part of.
- **A proof of service is a certificate of service** (DISC-006/011/016/023).
  "Certificate of service" is federal practice; California and New York say
  "Proof of Service", and a served California set of requests for admission was
  told at `critical` that it had none.
- **A hyphenated word is one word.** "Dmitri Sokolov-Reyes" captured as "Dmitri
  Sokolov" — a name matching nothing else in the document, so every
  signature-block and person guard missed it and the employee named on a
  performance improvement plan was reported as a term it forgot to define.
  "Non-Disclosure Agreement" read as "Disclosure Agreement" for the same
  reason.
- **Three more citations read as broken internal cross-references**: a
  construction specification's MasterFormat number ("Section 09 51 00"), a code
  named with an "of" phrase ("Code of Civil Procedure section 2033.010" — the
  commonest citation form in the largest state's practice), and the statute
  name that follows it ("Civil Procedure", reported as a term the filing forgot
  to define).
- **A recorded instrument's index fields stopped the recorder-block walk** —
  "Reference number of related document: 20190412000733" carries no ZIP and no
  street suffix, so the address test could not see it, and a quitclaim deed
  whose lines each had their own paragraph fell to `generic-fallback`.

## [9.129.0] — 2026-08-29

### Added
- **Four specimens for documents that are not agreements at all**: an Article
  30 record of processing activities, a completed vendor security
  questionnaire, an ACORD-style certificate of liability insurance, and a
  Washington state set of interrogatories. Ninety-six specimens now, and every
  defect below came out of running the CLI on one of the four.

### Fixed
- **A record of processing activities drew seventy-five findings, none of them
  about a register.** It routed to `dpa-controller-processor` and was told at
  `critical` that it had no documented-instructions clause, no subprocessor
  terms, no SCC Clause 1, and thirty-six more. Its family's title keyword was
  the PLURAL "records of processing" — the heading of Article 30 itself — and
  a controller titles its own document "Record of Processing Activities".
- **A state court's caption swallowed its filing's title** (four separate
  ways). The venue line is written "IN AND FOR KING COUNTY" or "COUNTY OF LOS
  ANGELES", the docket bare as "No. 26-2-04188-1 SEA", the versus mark alone
  as "v.", and the party block ends ", Defendant." on the same line as the
  docket. Each stopped the caption walk, so a set of interrogatories routed to
  `document-requests` and was told at `critical` that it stated no form of
  production for electronically stored information. (The `\b` after the versus
  mark could never match: a period has no word character after it.)
- **A GDPR citation read as a broken internal cross-reference** (STRUCT-007),
  twice over. A lettered sub-reference — "Article 6(1)(b)", "Section 4(a) of
  the Act" — stopped the external-citation run at the first lettered level,
  because the group required a digit. And the guard for a document that cites
  the regulation looked only for the nickname: the formal citation is
  "Regulation (EU) 2016/679", which is how any document drafted by a European
  lawyer names it.
- **A term defined WITH its article was reported both unused and undefined** —
  '"The Berth Agreement" means …' used as "the Berth Agreement" thereafter drew
  a STRUCT-005 saying the term is never used and a STRUCT-006 saying the same
  term is never defined. Two findings that contradict each other, about one
  term.
- **A cover block's field value and an abbreviated office were reported as
  undefined terms** — "Requesting organisation: Thornbury Federal Credit Union"
  states a fact, and "VP Information Security" is a job (the capture begins one
  word in, because a Title-Case run cannot include the all-caps abbreviation).
- **A "Last reviewed:" stamp is a publication stamp** (STRUCT-003), the same as
  "Last updated" — a register and a standing policy stamp the review, not the
  edit, and were told at `critical` that they had no signature block.
- Skip profiles: `ropa-art-30` no longer demands a signature block, and
  `vendor-security-questionnaire` no longer demands a data-retention period or
  an IP-ownership allocation from a question-and-answer form.

## [9.128.0] — 2026-08-29

### Changed
- **Format is no longer load-bearing anywhere.** All ninety-two specimens now
  report identically under all five format transforms — blank lines stripped,
  double-spaced, CRLF, hard-wrapped, smart-quoted — with no exceptions. The
  debt lists the guard carried are both empty. Five of the eight remaining
  entries were false NEGATIVES in the normal case, not false positives in the
  reformatted one.

### Fixed
- **Two documents reported themselves unsigned at `critical`** (STRUCT-003).
  The conformed-signature anchor listed the punctuation that may precede the
  mark — "^", ":", ",", "." — and left out the commonest thing of all, a
  SPACE, so an 83(b) election dated on the line above its signature was
  unsigned as soon as its blank lines went. And a signature label was anchored
  at the start of its paragraph, so a release whose four rules and four labels
  arrive as one paragraph could only ever be read for the first of them. Each
  segment that follows an underscore rule is read now.
- **An advance directive's witness lines were reported as unfilled template
  placeholders**, at `critical` (STRUCT-013). The prose that PRECEDES an
  underscore rule is not part of the signature line, and blanking the rules in
  place left the witness attestation glued to the label beneath it.
- **A stock option grant reported "No parties identified"** while naming the
  company, its state, and its defined role in plain sight (STRUCT-001). The
  preamble window was a quarter of the PARAGRAPH COUNT, which is a fact about
  the layout: the same notice arrives as twenty-one paragraphs with its blank
  lines and as six without them, and a quarter of six stops one paragraph short
  of the preamble. The window is floored in characters now.
- **An indemnity carved out of a liability cap went unreported whenever the cap
  was named in the section HEADING** (RISK-004) — "13. Limitation of
  Liability." over "Neither party is liable … This limitation does not apply to
  Seller's indemnification obligations". A set of purchase order terms and a
  set of SaaS terms each carve their cap in exactly that shape. The heading is
  read together with the clause, whether the file styles it as one or leaves it
  as the short line above.
- **An auto-renewal clause was read for its section heading and no further**
  (TEMP-011). "3. Billing and Automatic Renewal." matches the trigger and
  carries no notice window, so the clause beneath it was never examined. The
  same rule also read the provider's own courtesy reminder — "we will send you
  an email reminder at least 7 days before an annual renewal" — as a
  seven-day cancellation window, and reported a set of terms for the thing
  ROSCA asks them to do.
- The catalog-shadowing sweep had no timeout despite the comment promising one,
  and failed against vitest's 5-second default at its true 6-second runtime.

## [9.127.0] — 2026-08-29

### Fixed
- **Three documents were told their own subjects are terms they forgot to
  define.** Each was found by reading a format diff in the direction that
  indicates a false positive in the NORMAL case.
  - A trust's settlor. The paste path joins a signature block's two lines, so
    "/s/ Adaeze Chinelo Oduya" and the printed name beneath it arrive as one
    doubled string. The person collector's capture stops at four words, so a
    THREE-word name doubled runs to six and the halving that undoubles it
    compared "adaeze chinelo" against "oduya adaeze" and found no repetition.
    The doubling is read with a backreference now, which is indifferent to how
    many words the name has.
  - A cease-and-desist letter's addressee. Half the corporate suffixes are
    Title-Case words rather than initialisms, so the candidate phrase includes
    the suffix — "Meridian Optics Corp" — which no prefix of "Meridian Optics"
    matches.
  - A purchase agreement's "Due Diligence Materials", on a document whose
    section 4 is headed with it. A section heading ends with a period as often
    as not, and the standalone-heading test required an unpunctuated line. The
    terminal period is forgiven now when a section number is present, which is
    what distinguishes a heading from a Title-Case sentence.
  - Also the title of an attachment on its label line — "Schedule A — Trust
    Property" — which the heading test only caught while the label had a
    paragraph to itself.
- **A broad license grant went unread whenever a narrow one preceded it**
  (IPDATA-010). Only the first grant in the document was examined, and it was
  matched as a four-hundred-character clause from the grant word, which
  swallowed the operative grant sitting behind the run-in heading that
  announces it: "1. Grant of Rights. I grant … the irrevocable, perpetual,
  worldwide, royalty-free right …". Every grant is examined now, anchored on
  the verb. A desktop EULA's perpetual, irrevocable, royalty-free Feedback
  license — the exact clause the rule exists for — had never been reported.

### Changed
- **The double-spaced format-debt list is empty.** Double-spacing a document
  changes nothing the engine says about it, for all ninety-two specimens. The
  blank-lines-stripped list is down from eight entries to five.

## [9.126.0] — 2026-08-28

### Fixed
- **A phrase the document SIGNS is a person wherever else it appears.** A trust
  names its settlor three times — in the preamble, under the conformed
  signature, and in the notary acknowledgment — and none of the three is a term
  the drafter forgot to define. 9.125.0 skipped the signed OCCURRENCE, which
  left the other two to reach the two-occurrence threshold on their own; the
  whole term is dropped now. One more specimen came clean.

## [9.125.0] — 2026-08-28

### Fixed
- **A signatory named in a signature block was reported as an undefined
  defined-term.** "By: /s/ Ignatius Mbeki" over "Name: Ignatius Mbeki" names
  the same person twice, which is what a signature block is for — and nine
  specimens were told their own signatories are Title-Case phrases the drafter
  forgot to define.

  This was recorded as a known limitation in 9.103.0 on the reasoning that the
  shape of a personal name is not distinguishable from the shape of a defined
  term. That is true, and it is the wrong thing to look at: a defined term is
  never introduced by a signature label. The occurrence is skipped rather than
  the term, so a name that also appears in the body still reaches the
  two-occurrence threshold on its body uses and reports.

### Changed
- **The double-spaced format-debt list is down from fourteen to one.** Every
  entry that came off it came off because the double-spaced reading was the
  correct one and the normal case held a false positive.

## [9.124.0] — 2026-08-28

### Fixed
- **Only the first entry of an attachment list counted as attached.** An
  easement that ends

      Exhibit A — Legal Description of the Servient Estate
      Exhibit B — Depiction of the Easement Area

  was told Exhibit B is referenced but not attached, and so were six other
  specimens — a prenuptial agreement with two schedules of assets, a deposit
  account control agreement with three, an escrow agreement, a covenant not to
  sue, a patent assignment, and a written consent. The presence scan was
  anchored to the start of a paragraph and ran once, so it saw whichever entry
  the ingest happened to put first.

  The entry shape carries the discrimination on its own: an em or en dash
  directly after the id, followed by a Title-Case name. A body reference —
  "described on Exhibit B, being a strip twenty feet wide" — has a comma there,
  not a dash, so the scan needs no anchor and finds the list wherever the
  ingest puts it. **Seven false "not attached" findings, and both format-debt
  lists shrank as a consequence: fourteen to eight, and fourteen to nine.**

## [9.123.0] — 2026-08-28

The mirror of the PDF paste: a blank line between every line.

Where stripping the blank lines makes a document ONE paragraph, double-spacing
makes every line its own — so a construct laid out over two lines arrives
split. Sixty-eight of ninety-two specimens survived it, with two mis-routed.
It is now **seventy-eight of ninety-two, and the routing is invariant for all
ninety-two**.

### Fixed
- **A signature line and the name under it are one construct.** STRUCT-003 and
  STRUCT-013 read the underscore rule and the printed name only when they
  shared a paragraph — but whether they do is a fact about the file, not about
  the document: a DOCX styles them as separate paragraphs too. Both now read
  the rule together with the line that follows it, and both readings are tried,
  because appending the next line can spoil a clean printed name as easily as
  it can supply one.
- **The recorder's block must be PASSED before the title is taken.** Where each
  line of the return-to address is its own paragraph, the first title-shaped
  line is the title company's NAME — "Ashfield Title Company" carries no ZIP
  and no street suffix, so nothing else recognized it — and a general warranty
  deed was handed its escrow agent as its own name.
- **A caption's party line continued onto the next line carries a conjunction,
  not a comma.** "CORVUS SYSTEMS CORPORATION and" / "MARISOL ANDRADE," — the
  comma test let the first through, and the walk handed the matcher a
  defendant's name as the filing's title. No document title ends in "and".

### Added
- The double-spaced axis, making five: blank lines stripped, CRLF, hard
  wrapping, smart quotes, and double spacing. **Routing is invariant under
  every one of them for every specimen, with no exceptions.** Two axes carry a
  finding-set exception list; both may only shrink.
- Three more axes were swept and needed no repair: a leading byte-order mark,
  non-breaking spaces, and soft hyphens are all lossless across the corpus.

## [9.122.0] — 2026-08-28

Three more format axes, swept the same way.

Every specimen was run again through three transforms that change no word of
the document. Two of them moved findings.

### Fixed
- **A Windows document took the PDF-paste fallback.** A CRLF blank line is
  `\r\n\r\n` — a carriage return sits between the two newlines — and the
  blank-line test added in 9.121.0 read the RAW text, so a CRLF document
  reported having no blank lines at all. A general warranty deed lost its title
  to that and fell to `generic-fallback`. Line endings are now normalized once
  and every line-shape test reads the same string.
- **A line broken AT a hyphen was rejoined with a space through it.** A mail
  client, a legacy export, or a justified PDF column wraps "month-to-month"
  across two lines, and the join produced "month-to- month" — so TEMP-004
  stopped reading the holdover renewal of a hard-wrapped equipment lease. A
  line ending in a hyphen now joins without the space, which also keeps a soft
  hyphenation ("agree-" + "ment") as one token for the matcher's hyphen
  normalization to read.

### Added
- The guard is now `format-invariance.test.ts` and covers four axes: blank
  lines stripped, CRLF line endings, hard wrapping at 62 columns, and Word
  smart quotes. **All ninety-two specimens are identical under three of them,
  with no exceptions**; the blank-line axis holds routing for all ninety-two
  and findings for all but fourteen.

  Smart quotes were already lossless and are pinned so they stay that way.

## [9.121.0] — 2026-08-28

The same documents, pasted out of a PDF.

Text copied from a PDF keeps its line breaks and loses its blank lines, and it
is one of the commonest things a reviewer pastes in. Paragraphs in the paste
path were separated by blank lines ALONE, so such a document arrived as ONE
paragraph: a mutual release that reads as thirty-five paragraphs became a
single six-thousand-character block.

Run every specimen that way and **only twenty-seven of ninety-two came back
unchanged**. Two were mis-routed outright — an all-caps guaranty to `complaint`,
a GDPR privacy notice to `dpa-controller-processor` with eighty-three findings.
It is now **seventy-eight of ninety-two, and the routing is invariant for all
ninety-two**.

### Fixed
- **A blank-line-free paste is segmented at its clause markers.** A line that
  opens a numbered clause starts a paragraph; an all-caps heading gets one of
  its own. Engaged only where the alternative is a single block, so a document
  that separates its paragraphs normally is untouched — and gated on the
  document having case contrast, because in an all-caps instrument every line
  is an "all-caps heading".
- **A letter's "Re:" line is found anywhere in the opening block.** Both
  subject readers were anchored to the start of a paragraph, and a letterhead,
  addressee, subject line, and salutation arrive as one paragraph. "Re" is
  matched case-sensitively and must carry a colon; the capture stops at the
  salutation.
- **The document's identity can be three lines deep.** "HALCYON INSTRUMENTS,
  INC." / "2026 EQUITY INCENTIVE PLAN" / "NOTICE OF STOCK OPTION GRANT" —
  reading only the second line lost the grant notice's own name and routed it
  to the Plan.
- **A caption's court block runs over several lines** and only the first names
  a court, so the caption walk stopped on "NORTHERN DISTRICT OF CALIFORNIA" and
  handed the matcher a venue as the filing's title.
- **A street address is not a title.** "Ashfield Title Company, 1900 Wazee
  Street, Suite 500, Denver, Colorado 80202" is Title Case throughout and
  carries no terminal punctuation — it read as a title to every other test, and
  it is the line directly above the name of every recorded instrument and below
  the letterhead of every letter.

### Added
- A guard: **stripping a document's blank lines must not change what the engine
  says about it.** Routing is asserted for every specimen with no exceptions;
  the finding set is asserted for all but fourteen, and that list may only
  shrink.

## [9.120.0] — 2026-08-28

The same guaranty, in capitals.

An old-form guaranty, bond, or power of attorney is set in CAPITALS from the
caption to the signature. Running one through the engine beside its mixed-case
twin — the same document, the same words — produced **eight extra findings**.
Every one was a case-sensitive recognizer, and each is fixed:

### Fixed
- **The parenthetical-definition lead-in was lowercase-only.** `(THE
  "GUARANTOR")` registered nothing, so an all-caps instrument had NO defined
  terms at all and STRUCT-004 reported none on a guaranty that defines six. The
  uppercase spellings of the lead-in words are admitted; the term capture is
  unchanged, so nothing a mixed-case document produces can change.
- **The role-labeled party pattern was case-sensitive** in both its lead-in and
  its role names, so STRUCT-001 reported "could not identify the parties" about
  a preamble that names both. The all-caps variant is used only where the
  document offers no case contrast, and its NAME capture is restricted to
  all-caps.
- **The conformed signature `/S/` did not match.** STRUCT-003 reported no
  signature block at `critical`.
- **The named-parent tests lost their signal.** "UNDER A LOAN AND SECURITY
  AGREEMENT DATED AS OF SEPTEMBER 30, 2026" is the recital that says the
  guaranty is subordinate, and the capitalization that identifies a NAMED
  instrument carries no information in a document that capitalizes everything.
  Four findings followed — no IP allocation, no indemnity, no
  termination-for-cause path, no effect-of-termination clause — all of which
  live in the loan agreement it guarantees.
- **A statute named immediately before its section read as a broken internal
  reference.** "MINNESOTA STATUTES SECTION 582.30" — the plainest citation form
  there is, and the two existing guards need either a connector ("under",
  "pursuant to") or a trailing "of the … Code".
- **`guaranty` listed "loan agreement" and "security agreement" as negative
  features** — the instruments every guaranty exists to guarantee, and names in
  its first recital. Replaced with the operative clauses only the underlying
  instrument carries.

The principle behind four of the six: **capitalization is evidence only where
the document offers case contrast.**

### Added
- One specimen, bringing the set to ninety-two — the same guaranty as
  `guaranty.txt`, in capitals, so the pair fails if any recognizer starts
  depending on case again.

## [9.119.0] — 2026-08-28

A notification, recourse accounts-receivable factoring facility.

### Fixed
- **TERM-005 could not read the active voice of release.** "On termination,
  Factor shall release its security interest and file a termination statement
  within ten (10) days" is the wind-down clause of every secured facility, and
  the consequence list held only the passive "is released". The same repair
  takes TERM-005 off the executive employment specimen, which has a full
  severance clause and was being told it does not state what happens on
  termination.
- **BNK-124 wanted a determiner-free "notify the account debtor".** A
  notification facility writes "authorizes Factor to notify ANY account debtor
  of the assignment" and "directing the account debtor to PAY FACTOR" — without
  the preposition the second pillar required. A facility whose Section 2 is
  headed "Notification" and says so in its first sentence matched neither.

### Added
- One specimen, bringing the set to ninety-one.

## [9.118.0] — 2026-08-28

A nonprofit's photograph, video, and voice release.

### Fixed
- **A blank the reader is meant to fill in was reported at `critical` as
  unfilled template content.** "Program: ______  Date of event: ______" is the
  top of every consent form, release, application, and intake sheet, and the
  "By:/Name:/Title:" grid the signature test knows is only one shape of it. The
  label is what makes the difference: a placeholder stands alone where content
  belongs, and a form field is announced by the words that say what to write
  there. Two or more labeled blanks in a row are a form; one is left to the
  signature tests, so "Signed: ______" is unchanged.
- **A bare field label under a signature rule had the same problem.** "______
  Printed name" carries one signature token where the test wants two.
- **`media-release` knew only the COMMERCIAL model-release register** — "in all
  media now known or hereafter devised", "irrevocably grants". The commonest
  release there is, a nonprofit's consent form, matched none of it and scored
  0.2. It now routes at 0.9 on the language a real release uses.

### Added
- One specimen, bringing the set to ninety.

## [9.117.0] — 2026-08-28

An earnout agreement ancillary to a membership interest purchase.

### Fixed
- **A companion document that borrows its VOCABULARY from a named parent was
  audited as though it were the whole deal.** "Capitalized terms used but not
  defined in this Agreement have the meanings given in the Purchase Agreement"
  is the recital every earnout, escrow, side letter, and ancillary carries, and
  it says exactly what the other three parent tests say: the parent supplies
  what this document does not. The earnout was reported for having no IP
  allocation, no liability cap, no termination-for-cause path, and no
  effect-of-termination clause — all four live in the purchase agreement whose
  definitions it borrows. Four findings, one recital.

  A standalone contract never says this of itself: it defines its own terms.
  The parent must be NAMED, which keeps this off an ordinary internal
  cross-reference.

### Added
- One specimen, bringing the set to eighty-nine.

## [9.116.0] — 2026-08-28

Colorado articles of organization, filed electronically.

### Fixed
- **A state code's section number carries more than one hyphen.** "Section
  7-80-204 of the Colorado Limited Liability Company Act" — the leading-suffix
  skip took exactly one hyphen group, so every Colorado, Georgia, Maryland, and
  Utah statutory cite stopped at the second hyphen and read as a broken
  internal reference.
- **A division cited under a Title is part of the citation.** "C.R.S. Title 7,
  Article 80" appears on the first page of every Colorado charter filing and
  was reported as a broken internal reference to an "Article 80".
- **GOV-105 wanted the word "organizer".** Colorado's form says "the true name
  and mailing address of the PERSON FORMING the limited liability company", and
  its perjury notice names "the INDIVIDUAL CAUSING this document to be
  delivered" — a correctly prepared certificate carried neither spelling the
  pillar knew.
- **`articles-of-organization` and `charter-incorporation` carried the policy
  skip profile without STRUCT-003.** A charter delivered to a Secretary of
  State is not signed in the By:/Name:/Title: sense, and GOV-105 owns the
  organizer-signature question for those families anyway.

### Added
- One specimen, bringing the set to eighty-eight.

## [9.115.0] — 2026-08-28

A senior/subordinated intercreditor agreement.

### Fixed
- **A statutory cite's SUBSECTION is part of its label but not part of its
  number.** "Section 1111(b)(2) of the Bankruptcy Code" declares the label
  "1111"; a later bare heading — "9.2 Section 1111(b)." — arrives as "1111(b)"
  and missed the corroboration lookup entirely, so STRUCT-007 reported a broken
  internal reference to a section the agreement never has. The four-digit
  statutory test had the same blind spot: "Section 4999" was statutory and
  "Section 4999(a)" was not. One stripped label now serves the corroboration
  test, the flat-number test, and the outline lookup.

### Added
- One specimen, bringing the set to eighty-seven.

## [9.114.0] — 2026-08-28

A restaurant franchise agreement.

### Fixed
- **A renewal OPTION was reported as an auto-renewal.** "Franchisee MAY RENEW
  for one additional term of ten (10) years if, not less than nine months
  before the initial term expires, Franchisee gives written notice" requires
  the party to act — it is the opposite of a clause that renews without anyone
  doing anything. TEMP-004 now refuses a permissive modal.
- **TEMP-004 could not read the commonest holdover renewal there is.** "If
  Lessee gives no notice, the Schedule renews on a month-to-month basis" — its
  period list had only successive / additional / annual, and the negator search
  read the "no", which belongs to the CONDITION, not to the main clause. Both
  are fixed; the negation trim is scoped so a negation that governs the main
  clause ("shall not, if Customer gives notice, automatically renew") is
  untouched. Zero finding-level golden churn across the whole corpus.
- **CHOICE-006 read an institution's NAME as an arbitration clause.** A
  franchise agreement whose dispute clause sends the parties to MEDIATION
  "administered by the American Arbitration Association" and then to court was
  reported as having an arbitration clause with the seat not specified — a
  drafting fix for a clause it does not contain. A paragraph that names the
  institution AND agrees to arbitrate still fires, on its other token.

### Added
- One specimen, bringing the set to eighty-six.

## [9.113.0] — 2026-08-28

A master equipment lease that routed to `complaint`.

### Fixed
- **An equipment lease was audited as a civil complaint.** It scored 0.6 on
  "jurisdiction", "venue", and "jury" — the three words of its own
  governing-law section — and was told at `critical` that it has no caption, no
  jurisdictional statement, no numbered paragraphs, and no demand for relief.
  Two things did it, and both are fixed:
  - **`equipment-lease` penalized its own vocabulary.** It listed "real
    property" and "landlord" as negative features; a lease of goods says
    "remains personal property regardless of how it is attached to real
    property" and "Lessee shall obtain a landlord's waiver" — the fixture
    clause and the landlord-waiver covenant every such lease carries.
  - **`complaint` could not recognize a contract preamble.** Its negative
    feature was the literal "this agreement is entered into", which no real
    preamble writes — the instrument names itself first. It is now "by and
    between", which appears in essentially every contract and in no filing.
- **Every UCC Article 2A and Article 9 citation read as a broken internal
  reference.** "Sections 2A-508 through 2A-522 of the Uniform Commercial Code"
  carries the hyphen on both sides of the connective, and "Section
  2A-103(1)(g)" runs its sub-reference to two levels; the leading-suffix skip
  took a single paren group and the connective run took no hyphen at all.
- **TERM-002 could not read "On a default, Lessor may terminate".** That is the
  remedies sentence of every equipment lease and secured-lending document, and
  the fronted-condition branch had only if / upon / in the event of.

### Added
- One specimen, bringing the set to eighty-five.

## [9.112.0] — 2026-08-28

A first-party supplemental needs trust.

### Fixed
- **EST-408 wanted "shall not supplant" as three adjacent words.** A
  first-party (d)(4)(A) trust writes "the Trustee shall not make any
  distribution that would supplant, reduce, or replace any benefit the
  Beneficiary receives", so a trust whose section is headed "Supplemental, Not
  Substitute" drew a `critical` for having no supplemental-needs language at
  all. The window is bounded to one sentence and must land on a benefits
  object, which keeps it off an unrelated prohibition.

### Changed
- **Two tests were load-sensitive, not wrong.** The clause-scan performance
  bound moves from 10 to 12 and takes the minimum over nine rounds rather than
  five: a quadratic scan's BEST case is ~16x, so the bound only has to sit
  between 4 and 16, and a full-suite run at six times its usual wall clock read
  10.56 where an unloaded one reads 4.0. The bundle production-QA cases move
  from a fixed 30s to 120s — they are correctness tests that run the whole
  browser pipeline over four members, and nothing in them measures elapsed
  time.

### Added
- One specimen, bringing the set to eighty-four.

## [9.111.0] — 2026-08-28

A telehealth consent, addressed to the patient as "you".

### Fixed
- **HC-132 required "in THE state where THE PATIENT".** A patient-facing
  consent addresses the reader as "you" and names the state with the
  indefinite article: "your provider may treat you by telehealth only when you
  are physically located in a state where the provider is licensed", "tell your
  provider where you are physically located". A consent whose Section 5 IS the
  licensure recital was reported at `critical` as having none.
- **`telehealth-consent` matched on one phrase.** Five of its six
  distinguishing phrases were formulations nobody writes ("the limitations of a
  remote evaluation", "the location of the patient"), so a well-formed consent
  routed at exactly 0.5 — one negative feature from the cliff. It now routes at
  0.9 on the language a real consent uses.

### Added
- One specimen, bringing the set to eighty-three.

## [9.110.0] — 2026-08-28

The same defect the apostrophe had, in the hyphen.

### Fixed
- **A hundred and thirty-six catalog features carry a hyphen, and each could
  match exactly one of its three spellings.** The hyphen is optional in legal
  English and every family carries a compound written all three ways:
  "non-disclosure agreement", "nondisclosure agreement", "non disclosure
  agreement"; "anti-money-laundering" and "anti-money laundering";
  "attorney-in-fact" and "attorney in fact"; "by-laws" and "bylaws"; "form
  10-K" and "form 10K". The matcher now compares a feature against the
  hyphenated, closed, and spaced spellings of the document, and maps every
  Unicode dash to a plain hyphen first.

  Spaces are never removed — only hyphens — so no comparison can join two words
  the document keeps apart. That is what keeps a feature like "a lien" from
  matching "alien". The corpus variants are built once per document rather than
  once per feature, so a 250-family catalog costs three normalizations, not
  seven hundred.

### Added
- A guard: **every hyphen-bearing feature must match the hyphenated, spaced,
  closed, and non-breaking-hyphen spellings of itself.** Proven load-bearing —
  without the normalization it reports 544 failures across the catalog.

## [9.109.0] — 2026-08-28

A California preliminary notice — and thirty catalog features Word could not
match.

### Fixed
- **Thirty catalog match features carry a straight apostrophe and none of them
  can match a Word document.** "investors' rights agreement", "attorneys' eyes
  only", "finder's fee", "defendant's answer" — Word writes U+2019, and a
  playbook's features are plain substrings, so `apostrophe-tolerance`'s regex
  sweep never looked at them. A second spelling problem hid in the same place:
  the possessive is optional in the drafter's own vocabulary. California's lien
  statute and the statutory notice it prescribes both write "mechanics lien";
  Texas writes "mechanic's lien". Only one of the two could match. The matcher
  now drops apostrophes on both sides before comparing, which settles both.
- **`preliminary-lien-notice` matched almost nothing a real notice says.** Its
  phrases were generic-form-shaped, so a California preliminary notice carrying
  the statutory NOTICE TO PROPERTY OWNER block verbatim scored 0.4 and fell to
  `generic-fallback`. It now routes at 0.9 on the statutory language itself.

### Added
- A guard over the whole shipped catalog: **every apostrophe-bearing feature
  must match the curly, straight, and bare spellings of its own apostrophe.**
  Proven load-bearing — without the normalization it reports all thirty.
- One specimen, bringing the set to eighty-two.

## [9.108.0] — 2026-08-28

An internal litigation hold memorandum — and a seventh thing above the title.

### Fixed
- **A memorandum's RE: line was unreachable.** A memo states its title in "RE:"
  like a letter, but at the bottom of a four-line TO/FROM/DATE/RE block. Plain-
  text and pasted ingest joins the lines of a block with spaces, so the whole
  header arrives as ONE paragraph beginning "TO:" and the subject-line reader,
  anchored to the start of the paragraph, never reaches it. A litigation hold
  notice scored 0.4 and fell to `generic-fallback`, where it was told at
  `critical` that it has no signature block. Every memo-shaped family had the
  hole. It now routes at 0.7.
- **`litigation-hold` listed "release" as a negative feature** — what a hold
  says about itself ("until I notify you in writing that it has been
  released"). Narrowed to "release of all claims".
- **`litigation-hold` carried the policy skip profile without STRUCT-003.** A
  memorandum is not signed. Same omission as the nine filings before it.

### Added
- One specimen, bringing the set to eighty-one.

## [9.107.0] — 2026-08-28

A board resolution — and a check that was reading a text its own subject had
been removed from.

### Fixed
- **GOV-106, "Recitals establishing the purpose", could never fire clean.** The
  default rule input strips non-operative text, which is right for almost every
  column — a whereas clause is background, not a term of the deal — and exactly
  wrong for a column whose SUBJECT is the recitals. It was checking for
  `/whereas/i` in a text the filter had already removed every whereas clause
  from, and reported "no recitals establishing the purpose" on a resolution
  whose second paragraph is one. Not a weak check: an impossible one.

### Added
- `recitals: true` on a compliance-matrix column, and a guard: **no column may
  recognize a recital marker while reading operative text only.** Mechanical,
  and a ratchet — it keeps the next column from acquiring the defect.
- One specimen, bringing the set to eighty.

## [9.106.0] — 2026-08-28

### Fixed
- **Two template checks accused every issued breach letter.** PRV-035 wants an
  approximate number of affected records and PRV-040 wants a state-AG
  notification threshold. Both belong in the organization's notification
  template or incident-response plan, not in the letter it sends to one
  affected person — which has neither and is not supposed to. Both are now
  gated off a document that names its addressee ("Dear Ms. Mainwaring:"); a
  template carries a placeholder there and is still measured against both.

## [9.105.0] — 2026-08-28

A breach notification letter and a physician employment agreement.

### Fixed
- **The commonest breach-notification document there is scored 0.1.** A HIPAA /
  state-law notice to an affected individual is written to five model headings
  every state attorney general recommends — "What Happened", "What Information
  Was Involved", "What We Are Doing", "What You Can Do", "For More
  Information". `incident-notification`'s whole vocabulary was GDPR Article 33
  ("nature of the incident", "likely consequences", "72 hours"), so the letter
  matched nothing and fell to `generic-fallback`. It now routes at 0.9.
- **An arbitration seat named in the bare locative went unread.** "submitted to
  binding arbitration before a single arbitrator in Spokane County,
  Washington, administered by the American Arbitration Association" is how a US
  employment or commercial arbitration clause is ordinarily written: the place
  comes right after the arbitrator and before the provider. Every branch wanted
  either a participle ("seated in") or the provider first, so CHOICE-006
  reported "seat not specified" and CHOICE-003 reported no forum at all. The
  bare "in" excludes cross-references, containers, and languages explicitly —
  a wrong seat reconciles against the venue clause and is worse than a missing
  one.
- **`physician-employment-agreement` shipped with an empty `rule_overrides`.**
  It now carries the profile of its nearest sibling, `executive-employment`:
  an employment agreement has no liability cap, and the indemnity a group
  gives its physicians is uncapped by design.

### Added
- Two specimens, bringing the set to seventy-nine.

## [9.104.0] — 2026-08-28

A UCC-1 financing statement on the national form.

### Fixed
- **BNK-045 could not read § 9-503 in the form's own words.** The national UCC1
  form prints the requirement above box 1a — "Provide only one Debtor name …
  Do not omit, modify, or abbreviate any part of the Debtor's name" — over a
  box labeled "ORGANIZATION'S NAME". None of that is the phrase "exact legal
  name", so a correctly prepared form was told it states none.
- **`ucc-1-financing-statement` listed "security agreement" and "loan
  agreement" as negative features** — what a collateral description routinely
  names ("more fully described in the Loan and Security Agreement dated …").
  They are replaced by the granting clause and the default section, which a
  security agreement has and a financing statement never does; the security
  agreement specimen still routes to its own family.

### Changed
- **BNK-049 is `info` rather than `warning`.** No UCC1 form has a box for a
  lapse date and no realistic filing carries one: the § 9-515 calendar lives in
  the filer's docketing system, which is what the rule's own description
  ("UCC-1 *documentation* should reference …") and recommendation ("so the
  filing party tracks calendar deadlines") are about. At `warning` it accused
  every correctly prepared form of a defect it cannot cure.

### Added
- One specimen, bringing the set to seventy-seven.

## [9.103.0] — 2026-08-28

A privilege log and a Form ADV Part 2A brochure.

### Fixed
- **Eight disclosure filings carried the policy skip profile, which never
  needed STRUCT-003.** A policy escapes the signature-block check on its dated
  adoption recital ("Approved by the Board on August 15, 2026"); a filing has
  no such recital and nobody signs it. A well-formed Form ADV brochure drew a
  `critical` for having no signature block, and `form-d-narrative`,
  `10-k-risk-factors`, `s-1-risk-factors`, `ppm-narrative`,
  `reg-a-plus-circular`, `proxy-statement-narrative`, and
  `franchise-disclosure-document` all had the same omission. Same defect found
  in `sweepstakes-official-rules` in 9.98.0.

### Added
- Two specimens, bringing the set to seventy-six.

### Known limitation
- STRUCT-006 reports a repeated personal name as an undefined Title-Case term.
  A privilege log names its custodians in every entry, so it draws ten. The
  shape of a person's name is not distinguishable from the shape of a defined
  term ("Base Rent", "Marcus Bell"), so this is recorded rather than papered
  over.

## [9.102.0] — 2026-08-28

A FAR flowdown exhibit — one of the commonest things a reviewer uploads on its
own.

### Fixed
- **An exhibit incorporated into a named parent was audited as though it were
  the whole contract.** "This Exhibit is incorporated into and forms part of
  the Subcontract dated May 4, 2026" is the recital every exhibit opens on. It
  carries no ratification clause, because it changes nothing, and it is not
  "issued under" its parent, because it is part of it — so neither half of the
  parent-agreement test saw it. A FAR/DFARS flowdown exhibit was reported for
  having no governing law, no venue, no IP allocation, no indemnity, no
  liability cap, no termination-for-cause path, no effect-of-termination
  clause, no payment term, no parties, and no signature block. Every one of
  those lives in the subcontract the exhibit is attached to. Ten findings, one
  recital.

  The document must call ITSELF the exhibit: an agreement that incorporates its
  own exhibits says "each Exhibit is incorporated into **this** Agreement",
  where the parent is "this" rather than a named instrument, and is untouched.
- **"the Subcontract" was not in either cross-instrument vocabulary.** A
  reference to "Section 14 of the Subcontract" read as a broken internal
  reference, and the parent-agreement recital did not recognize its own parent.

### Added
- One specimen, bringing the set to seventy-four.

## [9.101.0] — 2026-08-28

A recorded declaration of covenants, conditions, and restrictions.

### Fixed
- **A pair of decimal-numbered statutory sections read as a broken internal
  reference.** Texas, California, and Florida number their statutes with a
  decimal and documents cite them in pairs — "Sections 202.010 and 202.007 of
  the Texas Property Code". The connective run in the external-citation trailer
  admitted only whole numbers, so the second section stopped the run, the "of
  the … Code" qualifier was never reached, and STRUCT-007 reported the citation
  as pointing at a section the declaration does not have.
- **"Every" was missing from the leading-stopword set.** It sits beside "Each"
  in every drafter's vocabulary, so "Every Owner is a member of the
  Association" was reported as a use of an undefined term "Every Owner" — on a
  declaration that defines "Owner" in its first article. "Certain", "Several",
  "Various", "Most", and "Many" are added for the same reason.
- **FIN-005 could not read an installment schedule with named due dates.**
  "payable in two equal installments due on January 15 and July 15 of each
  year" is how every homeowners-association assessment is stated: the cadence
  branch needs "monthly"/"quarterly" and the due-date branches need an ordinal
  day of a recurring period, so between them this read as no payment term.
- **`ccrs` shipped with an empty `rule_overrides`.** A declaration is not a
  bargain between two parties — the declarant subjects land to covenants that
  bind whoever buys it — and it drew six findings for having no indemnity, no
  liability cap, no IP allocation, no venue, and no termination clause.

### Added
- One specimen, bringing the set to seventy-three.

## [9.100.0] — 2026-08-28

A general warranty deed — and the sixth thing that sits above a title.

### Fixed
- **The recorder's block hid the title of every recorded instrument.** A deed,
  a deed of trust, an easement, a lien, and a release all open on the same
  scaffolding: who requested the recording, where to mail the instrument back,
  an escrow or parcel number, and the reserved white space. The matcher read
  the title company's address as the document's name, so a general warranty
  deed — the commonest recorded instrument there is — matched no title keyword
  of any playbook, scored 0.2, and fell to `generic-fallback`. Not one deed
  check ran on it. It now routes to `warranty-deed` at 0.9.

  This is the sixth shape of one defect. The letterhead, the court caption,
  the execution stamp, the exhibit marker, and the securities legend each hid
  a title the same way. Like the caption walk, this one engages only when the
  document OPENS on a recording line, and skips only lines it can recognize as
  scaffolding.

### Added
- One specimen, bringing the set to seventy-two.

## [9.99.0] — 2026-08-28

Developer-facing API terms — and the liability cap the engine could not read.

### Fixed
- **RISK-015 required the cap noun and its verb to be adjacent.** "EACH
  PARTY'S TOTAL LIABILITY UNDER THESE API TERMS IS LIMITED TO …" is the
  dominant cap sentence, and the words "under these API Terms" sit between
  them, so a contract with an explicit total-liability cap in the same section
  as its indemnity was reported as having an uncapped indemnity.
- **RISK-015 could not read a carve-out written as its own sentence.** "These
  limits do not apply to a party's indemnity obligations under Section 10" is
  the ordinary drafting of a limitation-of-liability section; the carve-out
  pattern read only connector-led forms ("except for …", "other than …") and
  only the verb stem `indemnif`, which does not match the noun "indemnity".
  Documents whose indemnity is carved out of the cap now say so, instead of
  being reported for having no cap at all. The back-reference must BEGIN a
  sentence: one tucked inside the consequential-damages sentence excepts the
  waiver, not the cap that follows it.
- **`api-terms` listed the bare word "merger" as a negative feature** — what
  the assignment clause of every agreement says ("we may assign them in
  connection with a merger or sale of assets"). It penalized its own document
  and dropped the family's match confidence from 0.9 to 0.8.

### Added
- One specimen, bringing the set to seventy-one.

## [9.98.0] — 2026-08-28

Sweepstakes official rules, and the published-terms cohort behind them.

### Fixed
- **TERM-002 could not read a termination path written in the consumer
  register.** A card agreement, a rewards program, and a subscription page do
  not "terminate this Agreement" — they close the account, end the membership,
  cancel the subscription. Every branch keyed on `terminat\w+`, so a Default
  section that plainly states a for-cause path was reported as stating none.
- **TERM-002 also could not read the FRONTED condition.** "If you are in
  default, we may close the Account" — every conditional branch read left to
  right from the termination verb, so the condition-first form, as ordinary as
  the trailing one, matched nothing.
- **`sweepstakes-official-rules` carried the policy skip profile, which never
  needed STRUCT-003.** A policy carries a dated adoption recital; official
  rules do not, so a well-formed set of rules drew a `critical` for having no
  signature block.
- **`api-terms` and `loyalty-program-terms` shipped with empty
  `rule_overrides`.** Published terms name one operator and "you"; a points
  program allocates no intellectual property and nobody signs it.

### Changed
- **The clause-scan performance guard no longer flakes under a full-suite
  run.** It compared a fixed-size batch at two input sizes, so the larger
  batch was exposed to scheduler interruption four times as long and the ratio
  drifted upward on a loaded machine (it failed at 20.0 against a bound of 10
  while passing in isolation). The batch size now scales inversely with the
  input, so both measurement windows are the same length, and the comparison
  is per-iteration cost. The bound is unchanged.

### Added
- One specimen, bringing the set to seventy.

## [9.97.0] — 2026-08-28

An advance health care directive, a bank forbearance agreement, and a consumer
cardholder agreement.

### Fixed
- **`advance-directive` listed "agent" and "power of attorney" as NEGATIVE
  features** — the vocabulary of the document's own Part 1, which appoints a
  health care agent and revokes any prior health care power of attorney. The
  family scored 0.5 on a textbook directive, fell below the routing threshold,
  and went to `generic-fallback`: none of the directive's checks ran on a
  directive. It now routes at 0.7.
- **A governing-law clause that names federal law first read as no clause at
  all.** "This Agreement is governed by federal law and, to the extent state
  law applies, by the laws of the State of Minnesota" is how every national
  bank writes it. The state is named only after an intervening clause, so the
  `governed by … the laws of X` anchor never reached it, and the compact
  adjectival form reads "federal law" and correctly rejects it. CHOICE-001
  reported no governing-law clause on a cardholder agreement that names one.
- **`credit-card-agreement` shipped with an empty `rule_overrides`.** A
  consumer card agreement is not a bilateral commercial bargain: it drew eight
  findings for having no indemnity, no liability cap, no IP allocation, no
  venue, no parties, and no termination clause — none of which a cardholder
  agreement has or should have.

### Added
- Three specimens, bringing the set to sixty-nine.

## [9.96.0] — 2026-08-28

A public website's terms of use and a consumer SaaS terms of service — two
documents that share a title register and belong to different families.

### Fixed
- **The website terms of use routed to `saas-tos`.** That playbook leaned on
  "you agree", "we may modify", and "your account", none of which distinguish a
  subscription service from any consumer terms page; `website-terms-of-use`
  meanwhile listed phrases a real terms page does not carry. Both now match
  their own register, and the pair of specimens pins the boundary in both
  directions.
- **COMM-201 reported a terms page that opens with its assent mechanism as
  stating none**, at `critical`. It wanted "you agree to these terms" or "by
  using the site"; a terms page writes "By accessing or using the website …
  you agree to be bound by these Terms of Use" — a compound verb, an inserted
  "be bound by", and the noun "website".
- **COMM-202 could not read the same sentence with one adverb in it.** "We may
  also change these Terms" did not match `we may change these terms`.
- **RISK-011 read the notice element only as a noun.** "We will notify you of
  any such claim" is the notice term, and an indemnity that spells the
  obligation out was told it states no notice procedure.
- **IPDATA-001 could not read ownership allocated by retention of a named
  object.** "You retain all rights in the images and other material you upload"
  is how consumer terms allocate user content; the retention branch read only
  "retains ownership" and "retains all right, title", so a terms page with a
  dedicated Your Content section was told it allocates no IP at all.
- **FIN-005 could not read a subscription's payment term.** Every branch leads
  on due / payable / paid; a subscription is *billed* — "Subscription fees are
  billed in advance, monthly or annually".
- **`saas-tos` and `website-terms-of-use` shipped with empty
  `rule_overrides`.** Published terms name one entity and "you", so both drew a
  warning for having no parties.

### Added
- Two specimens, bringing the set to sixty-six.

## [9.95.0] — 2026-08-28

Five documents that are not two-party bargains: a QDRO, board minutes, a
§ 83(b) election, a sublease, and a set of buyer-form purchase order terms.

### Fixed
- **A signature line labeled by office alone read as an unfilled template
  placeholder.** A proposed order leaves the bench a rule and a label —
  `_______________  Judge        Date` — with no name to print until the judge
  signs. STRUCT-013 suppressed the by-office form only when a personal name
  came first, so every such order drew a `critical` placeholder finding on its
  own signature line.
- **A statutory citation inside an ALL-CAPS caption read as a broken internal
  reference.** The external-citation trailer was case-sensitive, so `OF THE`
  never matched `of the`, and a § 83(b) election's own caption — "PURSUANT TO
  SECTION 83(b) OF THE INTERNAL REVENUE CODE" — was reported as pointing at a
  section the election does not have. Titles are all-caps too often for that to
  be an edge case.
- **A reference into a companion governance instrument did the same.** Minutes
  recite notice given "in accordance with Section 3.6 of the Company's
  bylaws"; an option grant points at "Section 5.2 of the Plan". The
  cross-instrument vocabulary listed only the commercial agreements, and did
  not admit a lowercase or possessive qualifier. `of this Agreement` and `of
  these Bylaws` stay internal, and a broken reference in one still reports.
- **EST-425 wanted a court-entry phrase most orders do not write.** A QDRO's
  entry line is the bare `ENTERED:` above the judge's signature. An order that
  recited its own entry, named the plan administrator, and retained
  jurisdiction to amend was still reported at `critical` for having none of
  the three.
- **EQT-043 required both spellings of one fact.** "Section 83(b)" AND the
  phrase "83(b) election" — so the caption the rule's own recommendation asks
  the drafter to add did not satisfy the rule. The second spelling was also
  answered by the family's own name ("§ 83(b) Election Form"), so it is
  replaced rather than merely OR-ed: both alternatives now carry operative
  text the title does not.
- **RE-102 read only the bare adjacency "Landlord's consent".** No sublease
  writes it that way — it asks for the landlord's *prior written* consent, or
  conditions itself on "the written consent of Master Landlord". A sublease
  with a section headed "Consent of Master Landlord" was reported as having no
  such clause at all.
- **`purchase-order-terms` shipped with an empty `rule_overrides`.** Standing
  terms are published, not executed: nobody signs them and they name one party
  and a class. They drew `critical` for having no signature block and a
  warning for having no parties.
- **"dated" is not a distinguishing phrase.** `trust-amendment` leaned on it;
  it matches eighteen of the sixty-four specimens. It now uses the recital a
  trust amendment actually carries, "trust dated".

### Added
- Five specimens, bringing the set to sixty-four.

## [9.94.0] — 2026-08-28

A recreational-use hold harmless and indemnity agreement.

### Fixed
- **TEMP-012 could not read the commonest survival drafting there is.**
  "Sections 2 through 5 and Section 7 survive termination indefinitely", whose
  Section 2 is headed "Indemnity", was reported as a survival clause that does
  not name the indemnity. Two things defeated it: the enumeration expander read
  only the first endpoint of a RANGE ("2 through 5", "9-12"), and the indemnity
  test used the stem `indemnif`, which does not match the word a section is
  actually headed with — "Indemnity".
- **"release" is not a distinguishing phrase.** It appears in seventeen of the
  fifty-nine specimens: an escrow releases funds, an easement releases itself
  on abandonment, a covenant not to sue says it is not a release, a security
  agreement releases its termination statement. `escrow-agreement`,
  `hold-harmless-agreement`, and `separation-agreement` all leaned on it, and
  each now uses its own register instead.
- **`hold-harmless-agreement` listed "endorsement" as a negative feature** —
  what its own insurance covenant requires the indemnitor to furnish. Caught by
  the specimen guard added in 9.90.1, on the first document written for that
  family.
- **`hold-harmless-agreement` shipped with an empty `rule_overrides`.** The
  document IS the indemnity: it allocates no IP, and its own Section 5 is
  headed "No Cap".

### Added
- One specimen, bringing the set to fifty-nine.

## [9.93.0] — 2026-08-28

An assignment and assumption of a commercial lease, with the landlord's
consent and estoppel statements.

### Fixed
- **It routed to `estoppel-certificate`.** That playbook's distinguishing
  phrases were "no default", "full force and effect", and "security deposit" —
  what every lease amendment, SNDA, and assignment consent says about the lease
  it touches. Replaced with the certificate's own register: "estoppel", "the
  undersigned certifies", "may be relied upon by".
- **`lease-assignment` did not know its own title.** Its title keywords were
  "assignment of lease" and "lease assignment"; the title a real one carries is
  "Assignment and Assumption of Lease", which contains neither. Its
  distinguishing phrases had the same problem — "landlord consent" and
  "assumption of obligations" for a document that says "Landlord consents" and
  "assumes and agrees to perform".
- **RE-057 reported the continuing-liability clause missing** on a section
  headed "Assignor's Continuing Liability" that says "Assignor is not released
  … Assignor **remains liable** to Landlord". The recognizers wanted "release
  of assignor" or "assignor continuing liable" and knew neither the noun form
  nor "remains liable".
- **`lease-assignment` shipped with an empty `rule_overrides`.** RISK-002 is
  skipped with it: a three-party assignment in which the landlord never
  indemnifies will always read as asymmetric, however the cross-indemnity is
  drafted.

### Added
- One specimen, bringing the set to fifty-eight.

## [9.92.1] — 2026-08-28

### Added
- **A routing-margin floor on every specimen.** Routing correctly is not the
  same as routing safely: a family that wins by a hair is one negative feature
  away from falling below the 0.5 threshold, and when that happens the document
  goes to `generic-fallback` and NONE of the family's checks run — which is
  exactly what `covenant-not-to-sue` was doing, at 0.3, on a document titled
  COVENANT NOT TO SUE. Every specimen clears 0.6 today; the floor makes a
  change that erodes a margin fail here rather than silently.

## [9.92.0] — 2026-08-28

A patent covenant not to sue — and the first family this method has found that
could not reach its own checks at all.

### Fixed
- **`covenant-not-to-sue` fell below the matching threshold on its own
  document.** Its distinguishing phrases were written as verbatim sentences
  nobody writes — "this is a covenant not to sue and not a release", "shall not
  institute any action" — so a document titled COVENANT NOT TO SUE scored 0.3
  against a 0.5 threshold, routed to `generic-fallback`, and none of its five
  SET-106..110 checks ran. Replaced with the family's actual register:
  "covenantor", "covenantee", "not to sue", "will not sue".
- **SET-106 knew only the not-a-RELEASE characterization.** The commonest
  covenant not to sue is a patent one, and its operative characterization is
  "this Covenant is a covenant not to sue and is not a **license**". Same
  column — which instrument this is and which it is not — reported missing at
  `critical` on the section that states it.
- **SET-107 wanted "claims arising from" adjacent.** The drafting puts the
  subject matter in between ("any claim, demand, or cause of action **for
  infringement of the Patents** arising from the manufacture …"), and the time
  boundary is as often the conduct window ("whether such acts occurred before
  or occur after the date of this Covenant") as the "known and unknown" formula
  a release uses.
- **`covenant-not-to-sue` shipped with an empty `rule_overrides`.** A one-way
  promise that is irrevocable and perpetual by design was told it stated no
  termination for cause and no effect of termination.

### Added
- One specimen, bringing the set to fifty-seven.

## [9.91.0] — 2026-08-28

A Series B side letter — a document whose whole job is to point at another
one.

### Fixed
- **A reference into a parent document was reported as broken.** The crossref
  extractor already reads "Section 3.7 of the Agreement", and the three-letter
  forms the catalog happened to list (MSA, SPA, DPA, BAA), as references into
  another instrument's numbering. It could not read a short name the document
  itself invents — and after 'the Amended and Restated Investors' Rights
  Agreement of even date (the "IRA")', "Section 3.5 of the IRA" was reported by
  STRUCT-007 as a broken reference to a section this letter never had. Every
  side letter, amendment, statement of work, order form, guaranty, and SNDA
  cites its parent that way. The extractor now collects instrument short names
  the same way it already collects statute acronyms.
- **MNA-128 wanted "only BY a writing".** The standard drafting is "amended
  only **in** a writing **signed by** the Company and Kestrel", and a side
  letter carrying the clause was told it had none. "Written **agreement**
  signed" is deliberately still excluded: that is the entire-agreement
  boilerplate every document carries, and admitting it makes the check unable
  to fire at all — which the boilerplate-reachability guard caught on the
  first attempt at this fix.

### Added
- One specimen, bringing the set to fifty-six.

## [9.90.1] — 2026-08-28

### Added
- **The self-penalizing guard now reaches the families that have no
  specimen.** Fifty-five of the two hundred sixty-six families have a
  hand-written document; the rest do not. A playbook still describes itself in
  four other places — its prose description, the terms it expects the document
  to define, the clauses it expects to find, and its compliance-matrix columns
  — and a negative feature drawn from any of them is self-contradictory for
  the same reason one drawn from its title keywords is. It passes today: a
  ratchet, not a discovery, keeping the next family from acquiring the defect
  where the other two guards cannot look.

## [9.90.0] — 2026-08-28

Three more instruments: a UCC § 9-104 deposit account control agreement, a
venture-lender warrant, and a trademark assignment. All three routed
correctly — what they found was the last of the empty `rule_overrides` in
their cohort.

### Fixed
- **`deposit-account-control-agreement`, `warrant-agreement`, and
  `trademark-assignment` shipped with an empty `rule_overrides`.** A
  three-party control agreement, a unilateral equity instrument, and a
  completed conveyance were each told they allocated no IP, capped no
  liability, and could not be terminated for cause.

  RISK-005 on the control agreement is the interesting one: the Bank excludes
  its liability except for gross negligence and waives consequential damages,
  and the rule deliberately does not read a bare consequential-damages waiver
  as a monetary cap. That is right as a general rule and wrong for this
  family, because no bank's control agreement states a dollar cap — so it is
  skipped here rather than loosened everywhere.

### Added
- Three specimens, bringing the set to fifty-five.

## [9.89.0] — 2026-08-28

### Added
- **The guard for the half of the self-penalizing class that reading a
  playbook cannot reveal.** The substring test added in 9.82.0 catches a
  negative feature drawn from the playbook's own features. It cannot catch one
  drawn from the family's own BOILERPLATE — and seven of the eight fixed by
  hand were that kind. The specimens make it mechanical: each is a realistic
  document of a known family, so a negative feature appearing in one is by
  definition a penalty the family charges itself.

  It found seven more on its first run, and one is the substring bug again:
  `easement-agreement` listed **"lease"**, which is inside "**re**lease", and
  an easement releases itself on abandonment.

### Fixed
- `mutual-nda` listed **"shall not disclose"** — a mutual NDA's own operative
  covenant — and "employee", which appears in every NDA's permitted-recipients
  clause. Removing them cost the tie-break that had been separating a one-way
  NDA, so `mutual-nda` now distinguishes on MUTUALITY ("each party", "either
  party", "both parties") rather than on "Recipient" and "Confidential
  Information", which every NDA and every protective order contains. That is
  the same magnet that pulled a stipulated protective order into `mutual-nda`
  in 9.82.0, removed at the source.
- `deed-of-trust` listed the promissory note and loan agreement it secures;
  `promissory-note` listed the security agreement and deed of trust securing
  it; `ip-assignment` listed "license", which appears in an assignment's own
  "Assignor retains no … license" clause; `last-will-and-testament` listed
  "trust", and almost every will creates a testamentary one; `union-cba`
  listed "merger", which is the entire-agreement clause every contract carries.
- **`ip-assignment` no longer claims the specific families' titles.** It
  listed "patent assignment" and "trademark assignment" as title keywords,
  which took a patent assignment away from the dedicated `patent-assignment`
  family and its five 35 U.S.C. § 261 checks.

## [9.88.0] — 2026-08-28

An M&A indemnity escrow and an Idaho payment and performance bond.

### Fixed
- **A bond states its incorporation clause in the WHEREAS, and recitals are
  stripped.** `fullText` — which every v4 and v5 presence rule reads — drops
  recitals, and rightly: a recital that says what the parties INTEND must not
  answer for the operative clause. But a surety bond is built out of recitals,
  and "WHEREAS, the Principal has entered into a written contract with the
  Obligee dated August 3, 2026 …, **which Contract is incorporated by
  reference and made a part of this bond**" is the incorporation clause, in
  the only place a bond ever puts it. CON-023 reported at `critical` that a
  bond incorporating its contract incorporates nothing. Presence rules can now
  opt in with `include_recitals`, which only a rule that knows its family's
  drafting convention should do.
- **CON-021 wanted a name no bond prints.** Its second pillar was "AIA A312",
  "Miller Act", or "Little Miller" — but a statutory bond cites the enacting
  state's code by section ("given pursuant to Idaho Code §§ 54-1925 through
  54-1930"), and "Little Miller Act" is a commentator's name for those
  statutes, not a drafter's. Conjoined with the bond-type pillar, that made
  the check impossible to satisfy on any real state bond, and it fired at
  `critical` on a document titled "PAYMENT AND PERFORMANCE BOND".
- **A state trial court named for its judicial district registered no venue.**
  "The District Court of the Fourth Judicial District of the State of Idaho,
  in and for Ada County" and "the Circuit Court of the Ninth Judicial Circuit
  in and for Orange County, Florida" are how state courts are named in the
  states that number their districts. The capture after the court requires an
  uppercase start, and this form puts a lowercase "the" there, so the whole
  clause went unextracted and CHOICE-003 reported "no forum clause".
- **Two more playbooks penalized their own vocabulary.** `escrow-agreement`
  listed "stock purchase agreement" — the agreement every M&A escrow names in
  its first recital as the one it secures — and `payment-performance-bond`
  listed "subcontract", which is what a payment bond's statutory claimant
  notice is written for.
- **RISK-002 on an escrow agreement.** A three-party escrow indemnifies its
  agent one way and always has; the asymmetry is the design.
- **`escrow-agreement` and `payment-performance-bond` shipped with an empty
  `rule_overrides`.**

### Added
- Two specimens, bringing the set to fifty-two.

## [9.87.0] — 2026-08-28

A permanent utility easement and a tolling agreement.

### Fixed
- **RE-028 maintains only what it was told to look for.** The object of an
  easement's maintenance covenant is whatever the easement exists for, and a
  utility easement maintains its **facilities** — "Grantee shall maintain the
  facilities in good repair at its sole expense". The recognized objects were
  "easement / premises / property / area / improvements / surface", so a
  section headed "Maintenance and Standard of Work" was reported missing, at
  `critical`. The pipeline, the road, the system, and the "in good repair"
  formulation are all recognized now.
- **TERM-005 did not know the plainest consequence there is.** "On
  termination, the Tolling Period **ends** and any applicable limitations
  period **resumes** running" is a textbook effect-of-termination clause, and
  the recognized-consequence list held return / destroy / surrender / survive
  but not "ends". Admitted only after the trigger, so "This Agreement ends upon
  expiration of the Initial Term" still reads as a term definition rather than
  an effect clause.
- **`easement-agreement` and `tolling-agreement` shipped with an empty
  `rule_overrides`.** A recorded conveyance and a two-page standstill were each
  told they allocated no IP, capped no liability, and stated no termination for
  cause.

### Added
- Two specimens, bringing the set to fifty.

## [9.86.0] — 2026-08-28

A patent assignment and a subordination, non-disturbance and attornment
agreement. Both are conveyancing instruments, and both found rules that could
not read the family's own operative sentence.

### Fixed
- **A conveyance never uses one verb.** IPDATA-001's assignment branch allowed
  a single adverb between "hereby" and "assigns", so "Each Assignor hereby
  irrevocably **sells, assigns, transfers, and conveys** to Assignee all of
  that Assignor's entire right, title, and interest in and to the Patents" —
  the operative sentence of a patent assignment — did not match, and a
  document whose entire purpose is to allocate IP ownership was told it
  allocates none.
- **RE-047, the N in SNDA, reported the non-disturbance covenant missing** at
  `critical` on the section headed "Non-Disturbance". The covenant is written
  actively and as an enumerated list — "Lender shall not (a) name Tenant as a
  defendant …, (b) terminate or **disturb** Tenant's leasehold estate or
  Tenant's **possession**, use, and quiet enjoyment" — and every branch wanted
  the passive "shall not be disturbed" or the two words adjacent. The survival
  sentence with foreclosure named last was invisible for the same reason.
- **RE-051 missed the no-prepayment covenant** in both the places an SNDA
  states it: inside the enumerated list of things the tenant may not do
  without the lender's consent, and in the lender's mirror of it ("bound by
  any rent … paid more than one month in advance").
- **`patent-assignment` penalized itself out of its own family.** It listed
  "trademark" as a negative feature, which is inside the name of the office
  every patent assignment asks to record it — the United States Patent and
  Trademark Office — and its distinguishing phrases were written without the
  serial comma and in forms drafters do not use ("the entire right, title and
  interest", "is hereby authorized to record"). It scored 0.4, lost to the
  general `ip-assignment`, and its five 35 U.S.C. § 261 checks never ran.
- **`patent-assignment` and `snda` shipped with an empty `rule_overrides`.**
  A completed conveyance and a three-party lender instrument were each told
  they stated no payment terms, allocated no IP, indemnified nobody, capped no
  liability, and could not be terminated for cause.

### Added
- Two specimens, bringing the set to forty-eight.

## [9.85.0] — 2026-08-28

### Added
- **The DGCL § 145 director-and-officer indemnification agreement.** Every
  VC-backed company signs one per director, and it is the document a director
  reads before joining a board — yet the catalog had no family for it. The
  family it did have, `indemnification-agreement`, is the COMMERCIAL
  anti-indemnity one (NY Gen. Oblig. § 5-322.1, Cal. Civ. Code § 2782, Tex.
  Ins. Code ch. 151) and applies the construction Type I / II / III taxonomy:
  a real D&O agreement routed there and was told to add a recital identifying
  its indemnity Type.

  New family `director-indemnification-agreement`, ten checks (`GOV-139..148`),
  one per compliance-matrix column:

  | Column | Authority |
  | --- | --- |
  | Fullest extent permitted, and the standard of conduct it is measured against | DGCL § 145(a) |
  | Mandatory indemnification on success on the merits | § 145(c) |
  | Advancement of expenses before final disposition (`critical`) | § 145(e) |
  | Undertaking to repay — unsecured, and without regard to ability to pay | § 145(e) |
  | Derivative-proceeding limit and the court's saving determination | § 145(b) |
  | Determination of entitlement, and Independent Counsel after a change in control | § 145(d) |
  | Presumption of entitlement and burden of proof | practice |
  | Non-exclusivity, and D&O liability insurance | § 145(f), (g) |
  | Survival after service ends and against a later charter amendment | practice |
  | Notice, defense, and settlement-consent procedure | practice |

  Advancement is the only `critical`: defense costs are incurred for years
  before any determination of entitlement, so a director who must fund them
  personally is unprotected in the only period that matters.

  265 → 266 document types; 1,808 → 1,818 rules. Additive by construction —
  every check is gated to the new family alone, and all 365 golden fixtures
  are byte-identical in their findings.

### Fixed
- **The new pack's own advancement check could not read a real clause.** Its
  deadline window was `within \w+ days`, and every real clause writes "within
  twenty (20) days after receipt of a written request", so GOV-141 reported the
  advancement clause missing — at `critical`, on the paragraph that grants it.
  Found on the specimen's first run, which is what the specimen is for.

### Added (tests)
- All ten checks pinned in both directions in `behavior.test.ts`. The "fires"
  direction hands each check a document carrying the other nine clauses, so it
  is proven to discriminate its own column rather than responding to an empty
  document.
- One specimen, bringing the set to forty-six.

## [9.84.0] — 2026-08-28

A restricted stock unit agreement and a director indemnification agreement.
The RSU award was the third unilateral equity grant shipping with an empty
`rule_overrides`; the indemnification agreement found three defects and one
gap in the catalog itself.

### Fixed
- **A venue capture ran past the place name into the sentence.** The capture
  can only stop at punctuation, so a forum clause with no comma before its
  period took the tail with it: "submit to the exclusive jurisdiction of the
  Court of Chancery of the State of Delaware **for any dispute arising under
  this Agreement**" registered a venue of "Delaware for any dispute arising
  under this Agreement", and CHOICE-004, CHOICE-009, and CHOICE-012 each
  reported that Delaware governing law and that venue "name different
  jurisdictions". Trimming to the last capitalized token is not enough — "this
  Agreement" ends on one — so the place name now ends at the first lowercase
  word that is not an internal connective ("of", "the", "and").
- **Arbitration named in a definition is not an arbitration clause.**
  '"Proceeding" means any threatened, pending, or completed action, suit,
  **arbitration**, alternative dispute resolution proceeding, administrative
  hearing, or investigation' enumerates the forums a claim might take; it does
  not agree to any of them. Every indemnification agreement, D&O policy, and
  litigation-hold notice carries that list, and each was reported as having an
  arbitration clause "with the seat not specified".
- **INS-017 wanted nouns nobody writes.** Its notice pillar matched "notice"
  but not "notify", and its settlement pillar wanted the phrase "consent to
  settle" or "right to control" — so a document saying "Indemnitee shall
  notify the Company in writing" and "The Company shall not settle any
  Proceeding … without Indemnitee's prior written consent" was told it
  established no notice, tender, or cooperation procedure at all.
- **`rsu-grant` shipped with an empty `rule_overrides`** and now carries the
  unilateral-instrument profile its two siblings use.

### Added
- `firstUnnegatedParagraphMatch` takes an optional `skip` predicate. Returning
  the first hit and testing it afterwards is a trap: a document whose first
  mention is a definitional aside then hides every real occurrence behind it.
  CHOICE-006 is the first caller.
- One specimen, bringing the set to forty-five.

### Known gap
- The catalog has no **DGCL § 145 director-and-officer indemnification
  agreement**. `indemnification-agreement` is the commercial / anti-indemnity
  family (NY § 5-322.1, CA § 2782, TX § 151) and applies the construction
  Type I/II/III taxonomy, which a D&O agreement has nothing to do with.

## [9.83.0] — 2026-08-28

Five more specimens, this time in families that are not bilateral commercial
bargains: a stock option grant notice, a mutual release, an Article 9 security
agreement, a premarital agreement, and an employment offer letter. Four of the
five were routed to the wrong playbook.

### Fixed
- **A plan header hid every equity award's own title.** "HALCYON INSTRUMENTS,
  INC. 2026 EQUITY INCENTIVE PLAN" sits above "NOTICE OF STOCK OPTION GRANT",
  and the corpus read only the first line — so a grant notice routed to
  `equity-incentive-plan` and was checked against the Plan's compliance
  matrix: no share reserve (critical), no evergreen, no capitalization
  adjustment, no change-in-control treatment, no amendment triggers, no
  clawback hook. Those are provisions of the Plan. The header is not a legend
  to drop, because the Plan document opens on the identical line, so the
  corpus now reads a second line when that line is title-SHAPED — short, no
  sentence punctuation, caps or Title Case. A body sentence contributes
  nothing.
- **Two more playbooks penalized their own vocabulary.** `prenuptial-agreement`
  listed "during the marriage", which is what a premarital agreement is about
  and appears in every property, debt, and support section of one; penalized
  on its own subject matter it scored 0.4 and routed to `family-msa`, a
  DIVORCE settlement, which reported at `critical` that it stated no date of
  separation. `security-agreement` listed "promissory note" and "loan
  agreement" — the instruments every security agreement names in its first
  recital as the obligations it secures.
- **A mutual release lost to `mutual-nda-deep` and collected ten criticals
  about NDA provisions.** Its playbook's phrases were written in a register
  real releases do not use: "known and unknown" for "known or unknown", "no
  admission of liability" for a section headed "No Admission". Its negative
  feature "demand" fires on the release's own operative words, "claims,
  demands, causes of action".
- **An offer letter titled "Offer of Employment" was not an offer letter.**
  The standard phrasing of the Re: line was not among the title keywords.
- **PERS-005 read the incoming-obligations representation as a non-compete.**
  "You represent that you are not subject to any employment, confidentiality,
  non-competition, or other agreement that would prevent you from accepting
  this position" is a promise the candidate is NOT bound by someone else's
  covenant — the opposite of imposing one — and it was reported at `warning`
  as a non-compete clause present. The rule also now scans every hit rather
  than the first, so a document that opens with the representation and imposes
  a real covenant later is no longer silenced by testing the wrong paragraph.
- **A state court named for its county registered no venue.** "The Circuit
  Court for Dane County", "the Superior Court for the County of Los Angeles",
  "the District Court for Harris County" — the commonest way an American state
  court is written. The forum patterns admitted a bare "court(s)" plus an
  "of / in / located in / sitting in" connector, and neither the court's type
  nor the "for" connector was among them, so CHOICE-003 reported "no forum
  clause" on a document that names one.
- **FIN-005 could not read a deadline written before the verb.** "Within ten
  (10) business days after the Effective Date, Kanaan shall pay Pelagic
  $265,000" is as conventional as the trailing form, and every branch read
  left to right from the verb.
- **Five more families shipped with an empty `rule_overrides`** —
  `stock-option-grant`, `mutual-release`, `security-agreement`,
  `prenuptial-agreement`, and `offer-letter`. A unilateral equity grant, a
  release, a security instrument, a prenup, and an at-will offer letter were
  each told they allocated no IP, capped no liability, indemnified nobody, and
  stated no termination for cause. Each now carries the profile its nearest
  sibling already uses.

### Added
- Five specimens, bringing the set to forty-four.

## [9.82.0] — 2026-08-28

Five more hand-written specimens — a stipulated protective order, a board's
written consent, a Series B term sheet, a WARN Act plant-closing notice, and a
revocable living trust — and the eleven defects they found. As in every prior
wave, none was reachable from the suite.

### Fixed
- **A court caption with two defendants hid the filing's title.** The caption
  walk skipped a party line only when it was entirely uppercase, and
  "CORVUS SYSTEMS CORPORATION and MARISOL ANDRADE," carries a lowercase "and".
  The walk stopped there and handed the matcher the defendants' names as the
  document's title, so a stipulated protective order routed to `mutual-nda` at
  0.9 and was told it had no governing law, no liability cap, no IP
  allocation, and no termination-for-cause clause. The trailing comma is the
  test now: a title never ends in one, and a party line, a role designation,
  and an entity descriptor ("ACME CORP., a Delaware corporation,") all do.
- **A judge's signature line was an "unfilled template placeholder" at
  `critical`.** The offices a signature line may name did not include the
  bench, so every order, judgment, and writ reported its own execution block
  as a drafting accident.
- **Four playbooks penalized their own vocabulary.** `irrevocable-trust`
  listed the negative feature "revocable", which is inside "irrevocable" —
  every irrevocable trust took the penalty on its own name, printed on every
  page. `loi-term-sheet` listed "definitive agreement" as both a
  distinguishing phrase and a negative feature. `trademark-assignment` listed
  "patent" while its own longest distinguishing phrase names the United States
  Patent and Trademark Office. `deed-of-trust` listed "security agreement",
  which is inside its own title keyword "mortgage and security agreement".
  `written-consent` listed "bylaws" — the recital every DGCL § 141(f) consent
  opens on.
- **A term sheet titled "Summary of Terms" was not a term sheet.** The
  standard title of a venture financing term sheet matched no title keyword,
  so a Series B summary lost to `mutual-nda`. Added the titles the family
  actually carries, including "Summary of Principal Terms", "Memorandum of
  Understanding", and "Heads of Terms".
- **MNA-004 knew only the M&A price vocabulary.** A financing term sheet
  never says "purchase price"; it states the round size, the pre-money
  valuation, and the per-share price. A Series B term sheet stating its price
  three ways was told at `critical` that it stated none.
- **EMP-147 recognized a state mini-WARN statute in four states.** A Nevada
  plant-closing notice reciting "Nevada Revised Statutes Chapter 613" was told
  at `critical` that it addressed no state overlay. The two conjoined pillars
  were never independent — the bare `state` pillar carried nothing the
  citation pillar did not — so the check is one tightened pillar that reads a
  state code by its own name.
- **EMP-146 wanted the word, not the contact.** 20 C.F.R. § 639.7(d)(4)
  requires the name and telephone number of a company official; the check
  required the word "contact" or "telephone" from a notice that names its HR
  director and gives her number.
- **IPDATA-005 could not read HIPAA cited in full.** An estate instrument
  writes "the Health Insurance Portability and Accountability Act of 1996 and
  45 C.F.R. Parts 160 and 164" and never the acronym. Neither the spelled-out
  act nor the Part range was recognized, so the paragraph citing HIPAA twice
  was reported as citing no regime at all.
- **`revocable-living-trust` shipped with an empty `rule_overrides`** while
  its two nearest siblings — the will and the irrevocable trust — share an
  identical eleven-skip estate profile. A trust instrument was told it had no
  payment terms, no IP allocation, no indemnity, no liability cap, and nothing
  to terminate for cause. Six corpus fixtures lose nine false findings each
  and keep every real one.
- **`loi-term-sheet` shipped with an empty `rule_overrides`** too. A
  non-binding term sheet allocates no IP, caps no liability, indemnifies
  nobody, and has nothing to terminate for cause.
- **`real-estate-psa` listed "closing" as a distinguishing phrase**, which
  appears in a third of the specimen corpus. Replaced with the family's own
  register: "close of escrow", "closing statement", "permitted exceptions".

### Added
- Five specimens, bringing the set to thirty-nine, each pinned to the exact
  finding set it may produce.
- `tests/integration/self-penalizing-features.test.ts` — a playbook may not
  list a negative feature drawn from its own name, title keywords,
  distinguishing phrases, or required clauses. Mechanical, and needs no
  judgment: whatever a playbook offers as evidence for itself cannot also be
  evidence against.

## [9.65.0] — 2026-08-27

### Fixed
- **A flat late charge was reported as a rate with no stated period.** A note
  writes its numeral in a parenthetical — "a late charge equal to five percent
  **(5%)** of the overdue installment" — and the closing paren sat between the
  "%" and the "of", so the one-time-fee branch missed it. The period pattern in
  the same rule already carried that allowance; now both do. The finding turns
  from "Late-payment rate of 5% has no stated period" into "One-time late fee
  of 5% (not annualized)", which is what the clause says.
- **`promissory-note` now skips the venue check too.** A note states its
  governing law and names no forum; that is the instrument, not an omission.

### Added
- A fixed-rate promissory note specimen, bringing the set to thirty.

## [9.64.1] — 2026-08-27

### Fixed
- **`bill-of-sale` had empty `rule_overrides`.** A bill of sale is a one-time
  conveyance executed by the seller alone: it allocates no IP, caps no
  liability, has nothing to terminate, names no forum, and its operative date
  is the execution date at the foot rather than an Effective Date recital at
  the head. Ten findings became four, and all four are real — the schedules are
  not attached, and the tax indemnity is one-sided, uncapped, and has no
  procedure.

### Added
- A bill of sale specimen, bringing the set to twenty-nine.

## [9.64.0] — 2026-08-27

### Fixed
- **Excerpts cut mid-word.** The excerpt is what a reader actually sees — in
  the fix list, the HTML report, and the DOCX — and a raw
  `slice(index - 30, index + 280)` cuts whatever happens to be at the edge.
  Sweeping the twenty-eight banked specimens found it on nine of them: "**n**
  (11) paid holidays per contract year", "**perty** in the ordinary course",
  "**ter** requires, and we will use reasonable efforts", "**al** Statements.
  The Financial Statements attached as Schedule". The committed fixtures had
  shipped the same defect for as long as they have existed — "**ay** terminate
  this Agreement", "**ll** disputes shall be resolved on an individual basis".
  A finding that quotes half a word reads as a broken tool, whatever it says
  next.
  - Thirty-one slicing sites across twenty-seven rules now share one
    `excerptWindow` helper that snaps each edge outward to the nearest word
    boundary, bounded so a pathological unbroken run cannot drag the window.
    The window is widened, never narrowed, so no matched text is lost. Every
    golden that moved moved only its excerpt text — no title, rule id, or
    severity changed anywhere.

## [9.63.0] — 2026-08-27

### Fixed
- **A fronted adverbial was swallowed into the subject.** "Within five (5)
  business days after the Effective Date, **Seller** shall file the
  stipulation", "For three (3) years after the Closing, **each Seller** shall
  not compete", "Until the expiration of four (4) years after the furnishing of
  the Services, **Medical Director** shall make the records available" — the
  subject capture reaches back to the start of the clause, so the whole
  adverbial came with it, and the obligor was published as "days after the
  Effective Date, Seller". Across the twenty-eight specimens that produced
  **24 wrong obligors on 8 documents**, in the findings and in the
  critical-dates register. Keyed on the opening subordinator, so a genuinely
  comma-bearing subject ("Seller, Buyer, and the Company shall") is untouched.
- **The register published guesses as parties.** `resolveObligor` falls back to
  the last few words of the subject when it matches no party and no role —
  reasonable as an input to a rule, bad to print: "AND FITNESS FOR A PARTICULAR
  PURPOSE", "effective each January 1, and we", "in Section 2 end and You",
  "the determination". A party's name is short, carries no comma, and ends on a
  capitalized word; anything else, and the register now says nothing. Across
  the specimens: 62 rows, 36 named, every name a real party, zero anomalies.

## [9.62.0] — 2026-08-27

### Fixed
- **The critical-dates register named the wrong party.** When no obligation's
  clause overlapped a date, it fell back to the FIRST obligation in the date's
  section. That is fine for a DOCX with real headings and wrong for everything
  else: a pasted or plain-text document is a **single section**, so the section
  filter admits the whole document and every unmatched date is attributed to
  whatever the document happens to say first. A credit agreement's equity cure
  — "the Borrower may cure … within ten (10) Business Days" — was published as
  owed by "**Each Lender severally**", a fragment of the revolving-commitment
  sentence many paragraphs earlier. The fallback is now the *nearest*
  obligation, and only within 400 characters; beyond that the register says
  nothing, which the type already contemplates.
- **And it published prepositional fragments as parties.** "the Administrative
  Agent may, and **at the direction of the Required Lenders** shall, declare
  the Obligations due" yields an obligor of "the direction of the Required
  Lenders" — the object of "at the direction of", not the party who owes
  anything. The register is an attorney-facing artifact; a wrong name in it is
  worse than no name.

## [9.61.1] — 2026-08-27

### Fixed
- **An ICC seat stated in the participle went unread.** "finally resolved by
  arbitration under the Rules of Arbitration of the International Chamber of
  Commerce by three **arbitrators seated in** London, England" names the
  arbitrators rather than the arbitration and carries no modal, and the
  verb-first branch wants "the arbitration shall be seated in". CHOICE-006
  reported "seat not specified" and CHOICE-003 reported no forum.
- **A regime cited by its number was read as no citation at all.** A European
  distribution agreement writes "shall comply with **EU Regulation 2016/679**"
  and never says "GDPR", so IPDATA-005 reported that a contract naming the
  governing regime precisely cites none. The UK GDPR, the Data Protection Act
  2018, and the e-Privacy Directive join the alternation for the same reason.

### Added
- A cross-border exclusive distribution agreement specimen, bringing the set to
  twenty-eight.

## [9.61.0] — 2026-08-27

### Fixed
- **An acronym feature matched inside ordinary words.** Match features are
  plain substrings, which is right for a phrase and wrong for an acronym:
  `change-order` lists **"co"**, which appears inside "Company", "Contract",
  "Counsel", and "Cost", so it collected a title keyword's 0.3 from almost any
  document. The catalog acquired the shape one acronym at a time — "sig"
  (inside "assignment", "signature"), "spa" (inside "space"), "apa" (inside
  "apartment"), "ccr" (inside "accrue"), "safe" (inside "safeguard"). A feature
  of five characters or fewer is now matched on word boundaries; "CO" standing
  alone in a change order's title still matches, "Company" no longer does, and
  a multi-word phrase keeps its substring behaviour — that is what lets
  "conflicts of interest" find "Conflicts of Interest Policy".
  - On the corpus it removed exactly one hit, and it was false:
    `msa-general`'s negative feature "lease" was matching inside **"release"**,
    penalizing a SaaS vendor agreement 0.1 for a word it does not contain. Same
    playbook, same twelve findings, 0.8 → 0.9.

### Added
- A SaaS order form specimen — issued under a named master subscription
  agreement, so it exercises the subordinate-document path end to end —
  bringing the set to twenty-seven.

## [9.60.0] — 2026-08-27

### Fixed
- **RISK-009 read only the modal, not the present tense.** "Guarantor's
  liability **is not limited** in amount" is the operative sentence of every
  unlimited guaranty, and of any agreement that declines to cap; the branch
  matched only "shall not be limited". The carve-out guard added in 9.54 still
  holds, so an M&A fraud exception is not swept in.
- **`guaranty` had empty `rule_overrides`.** A guaranty states no payment term
  of its own — the credit agreement it guarantees does — and being uncapped is
  the point of it, so the uncapped-liability finding is downgraded to `info`
  rather than suppressed: worth seeing on the instrument, not worth a critical.

### Added
- A continuing guaranty specimen, bringing the set to twenty-six.

## [9.59.1] — 2026-08-27

### Fixed
- **A time zone is not a defined term.** Every deadline in a purchase
  agreement, a discovery response, and a notice clause is stated in one — "5:00
  p.m. **Eastern Time** on the forty-fifth day" — and the Title-Case run picked
  it up as a phrase the document uses twice and never defines. Same class as
  the street-suffix and place-name guards beside it.
- **`real-estate-psa` had empty `rule_overrides`.** A purchase and sale
  agreement allocates no intellectual property, and it closes or the deposit is
  retained rather than terminating for cause.

### Added
- A commercial real estate purchase and sale agreement specimen, bringing the
  set to twenty-five.

## [9.59.0] — 2026-08-27

### Fixed
- **An executive employment agreement routed to the generic at-will
  playbook.** It matched `executive-employment`'s own name **and** four of its
  own distinguishing phrases (409A, 280G, CFO, CEO) — and still lost, because
  `employment-at-will-us` collects 0.8 from `required_clauses`, a feature kind
  worth 0.4 per hit against a phrase's 0.2 that only the twelve launch
  playbooks carry. `confidentiality-obligation`, `employee-ip-assignment`, and
  `term` are in every executive agreement ever written. Fixed the way
  `docs/adding-a-playbook.md` recommends — with negative features rather than
  by inflating the other side's keywords: an at-will offer letter does not
  mention Section 409A, Section 280G, Good Reason, or a Change of Control. The
  three offer-letter fixtures route unchanged, with unchanged findings.
- **IPDATA-001 required the word "hereby".** "Executive **assigns to** the
  Company all inventions conceived during employment" is a complete
  assignment, and the rule reported that the agreement does not allocate
  ownership of intellectual property. The "to" is what keeps the plural noun
  ("successors and assigns") out.
- **The arbitration seat sat behind a named rule set.** "under the JAMS
  **Employment Arbitration** Rules in Columbus, Ohio" — the institution-first
  branch admitted only a bare "Rules" immediately after the provider, so
  CHOICE-006 reported "seat not specified" on a clause that specifies one and
  CHOICE-003 reported no forum at all.
- **`executive-employment` had empty `rule_overrides`**: an employment
  agreement caps no liability, and the company's indemnity of its officer is
  uncapped by design.

### Added
- An executive employment agreement specimen, bringing the set to twenty-four.

## [9.58.1] — 2026-08-27

### Fixed
- **`operating-agreement-llc` had empty `rule_overrides`.** An LLC operating
  agreement is a governance instrument, not a commercial bargain: it allocates
  no IP, caps no liability between members (the indemnity in favour of the
  managers is the mechanism, and it is uncapped by design), and it dissolves
  rather than terminating for cause. Those three are skipped and the
  uncapped-indemnity note is downgraded to `info`. Eight findings became five.

### Added
- A Delaware LLC operating agreement specimen, bringing the set to
  twenty-three.

## [9.58.0] — 2026-08-27

### Fixed
- **A quoted phrase is a quotation, not a miscapitalized defined term.** Every
  EULA sold to the US government recites FAR 12.212: the Software is
  `"commercial computer software"` — the regulation's own defined phrase,
  written in lowercase and in quotation marks *because it is being quoted*.
  STRUCT-009 read the "software" inside it as a lowercase use of the
  agreement's defined "Software" and reported an inconsistency the drafter
  cannot fix without misquoting the regulation. The check is bounded to a
  single quoted span near the match, so an ordinary paragraph that happens to
  contain a quotation elsewhere is unaffected, and a genuine lowercase use
  still reports.
- **`eula` had empty `rule_overrides`.** A consumer or desktop end-user licence
  contains no indemnity — the licensor does not indemnify the user, and asking
  the user to indemnify is a term the tool flags elsewhere as a dark pattern.

### Added
- A desktop EULA specimen, pinned clean, bringing the set to twenty-two.

## [9.57.1] — 2026-08-27

### Fixed
- **A venue in a named federal court went unread.** "Any action to enforce this
  Agreement shall be brought exclusively in the **United States District Court
  for the Northern District of Illinois**" names its forum in the ordinary way,
  and was reported as naming none: the court-name run did not admit the
  sovereign before the court type, and the locality preposition set had no "for
  the … District of".
- **The judicial district inside that court's name was read as an undefined
  term.** The Title-Case run stops at the lowercase "of", so "Northern
  District" arrived as its own candidate — in a document that names one in
  every recital.
- **`confidential-settlement` had empty `rule_overrides`.** A settlement and
  mutual release allocates no IP, contains no indemnity (each party releases
  the other), caps no liability, and does not terminate — it is performed and
  done. Nine findings became two, and both are real: no tax allocation of the
  payment, and the negative covenants.

### Added
- A confidential settlement agreement specimen, bringing the set to
  twenty-one.

## [9.57.0] — 2026-08-27

### Fixed
- **A roman-numbered SECTION was invisible to itself.** `LEADING_SECTION_RE`
  requires an arabic number followed by a period ("Section 2.1. Annual
  Meeting"), and an insurance policy writes "SECTION VI — NOTICE": roman, no
  period, an em dash. Every one of those headings was **both** unregistered and
  re-read as a broken reference to itself, and the real "Section VI" in the
  body failed too — eleven findings on one cyber policy. That is exactly the
  defect the ARTICLE declaration comment describes, left unfixed for the
  sibling keyword.
  - And a roman section label normalized into the **article** namespace, so it
    could not have matched even once indexed — and in a document with an
    Article VI it would have linked to the wrong one. `normalizeLabel` now has
    a section branch, and the call site passes the keyword's namespace for
    `Section`, `Sections`, and `§` as it already did for `Article`.

### Added
- A cyber liability policy specimen, bringing the set to twenty.

## [9.56.1] — 2026-08-27

### Fixed
- **One hyphen hid a payment term.** FIN-005's active-voice branch lets the
  run-up between "shall pay" and the deadline contain letters, digits, commas,
  parentheses, currency and quote marks — but not a hyphen, and hyphenated
  words are everywhere in that run-up. "Sponsor shall pay Institution in
  accordance with the budget attached as Exhibit A, on a **per-subject** basis
  upon completion and monitoring of each visit, within forty-five (45) days
  after receipt of a proper invoice" is a plainly stated term, reported as
  none.
- **A survival clause spread over two paragraphs was read from the wrong one.**
  `expandSurvivalSectionRefs` took the FIRST section list in the survival text,
  and the earlier paragraph carried an unrelated cross-reference — "Nothing in
  this Section limits the publication rights in **Section 11**" — which became
  the whole incorporated list. The operative enumeration ("Sections 5, 6, 9,
  10, 11, 12 … survive") was never read, so TEMP-012 reported the indemnity as
  unnamed in a clause that names it by number. Every list is now unioned.

### Added
- A clinical trial agreement specimen, bringing the set to nineteen.

## [9.56.0] — 2026-08-27

### Fixed
- **Every reference to an arabic-numbered article was reported as broken.**
  "Article 9" reached the label normalizer as the bare number "9", which
  normalizes to `section:9` and can never match the `article:9` the
  declaration indexed — only the roman form ("Article II") took the article
  branch, because it is recognizable without its keyword. That is the numbering
  a union contract, a policy, and most EU-style instruments use. Where the
  document also had a Section 9, the reference linked to the **wrong entity**
  instead of failing, which is the same class the Exhibit/Schedule guard exists
  to prevent. The keyword is known at the call site; it is now passed.
- **`union-cba` had empty `rule_overrides`.** A collective bargaining agreement
  states no governing law (LMRA § 301 supplies it), no venue (the grievance
  procedure ends in arbitration), no IP allocation, no liability cap, and no
  payment terms, and it expires rather than terminating for cause. Fifteen
  findings became seven.

### Added
- A union collective bargaining agreement specimen, bringing the set to
  eighteen.

## [9.55.0] — 2026-08-27

### Fixed
- **A will's bond waiver was reported as a bond requirement.** EST-004's second
  express-denial frame carried no negation guard, unlike its sibling, so the
  standard waiver — "**No** fiduciary serving under this Will shall be required
  to post bond in any jurisdiction" — was read as a will that affirmatively
  requires bond, the reverse of what it says. The subject carries the negation
  here, so the lookbehind has to scan back past it.
- **EST-104 and EST-105 recognized only ruled signature lines.** A will that is
  pasted, typed, or e-signed carries the conformed signature instead — "/s/
  Dermot Aloysius Halloran" over "Dermot Aloysius Halloran, Testator", and an
  attestation clause reciting that the witnesses "subscribed our names as
  witnesses" — so a properly executed will was told nobody had signed it and
  that it had no witnesses. STRUCT-003 learned the same lesson in 9.42. The
  pre-existing `witnesseth` / `witness whereof` guard still holds: "IN WITNESS
  WHEREOF, I have signed" is the testator signing, and EST-105 still fires.
- **A will names its family throughout, and has no parties.** "My wife Priya
  Raghunathan Halloran", "my son Emil Halloran", "my brother Cormac Halloran" —
  natural persons, reported as Title-Case terms the will forgot to define,
  because the party extractor finds no parties in a will for the person-name
  filter to use. A relationship-introduced name is now collected as a person,
  which also covers the bare list form. And "Last Will" — the front half of the
  document's own title, split at the lowercase "and" — is what the instrument
  *is*, not a term it defines.

### Added
- An Ohio will specimen with an attestation clause and a self-proving
  affidavit, pinned clean, bringing the set to seventeen.

## [9.54.1] — 2026-08-27

### Fixed
- **A venue laid in a borough, city, or county went unread.** The forum
  scaffold accepted only "the **State**/Commonwealth of" ahead of the locality,
  and the capture requires a capital letter, so the lowercase "the" in "the
  state and federal courts sitting in **the Borough of** Manhattan, City of New
  York" stopped the clause dead — as it did for "the City of Chicago,
  Illinois", "the County of Cook, Illinois", and the consent form. Four of five
  real phrasings failed, and a New York credit agreement with a textbook
  forum-selection clause was told it did not state where disputes must be
  brought.
  - Widening it alone traded one false finding for **four**: the venue resolved
    to a bare city, and the law-versus-venue comparisons then reported
    "Manhattan" as a different jurisdiction from the governing law, with
    CHOICE-005 calling it a foreign forum with no enforceability treaty. The
    state can sit behind a civil-division preposition of its own — "the Borough
    of Manhattan, **City of New York**" names New York — so the locality
    resolver consumes the division word before reading the state. The
    preposition is widened for venue only; a governing law is a state or a
    country.

### Added
- A syndicated credit agreement specimen, bringing the set to sixteen.

## [9.54.0] — 2026-08-27

### Fixed
- **A carve-out from the cap is not the absence of one.** "The Sellers'
  aggregate liability shall not exceed the Escrow Amount, **except that**
  liability for Fraud is unlimited" is the single most standard sentence in M&A
  indemnification — every professional purchase agreement, buyer-favorable and
  seller-favorable alike, carves fraud, wilful misconduct, and the indemnity
  out of the cap — and RISK-009 reported the presence of a cap as its absence,
  at `critical`. The test is what the unlimited language is *about*: an
  exception connective plus a named carve-out subject in the same clause. A
  clause that really does leave liability uncapped names no exception, and
  still fires.
- **MNA-106 could not read the covenant its own `fix` text asks for.** A
  sale-of-business covenant states its scope between the modal and the verb —
  "each Seller shall not, **within the states in which the Company conducted
  business as of the Closing**, engage in a business competitive with the
  Business, or solicit for employment any employee" — and both pillars required
  the verb to sit immediately after "shall not".
- **STRUCT-016 named a "Schedule 2" the agreement never mentions.** Its number
  bound stopped at the first digit of "Schedule 2.3", the numbering every
  purchase agreement uses to tie a schedule to the representation it qualifies.
  STRUCT-018 named it correctly two findings below.
- **The copula definition window was forty characters, and the value is often
  spelled before it is figured.** `The "Escrow Amount" is One Million Eight
  Hundred Thousand Dollars ($1,800,000)` puts the first digit forty-three
  characters past the copula, so the agreement's own defined term was reported
  as undefined.

### Added
- A membership interest purchase agreement specimen, bringing the set to
  fifteen.

### Changed
- The README's suite-size floor now reads 7,000+ (the suite is 7,050); it had
  drifted 350 behind.

## [9.53.0] — 2026-08-27

### Fixed
- **A GDPR notice's legal bases are plural, and the item read only the
  singular.** Every GDPR notice has more than one legal basis, so its section
  is headed "Purposes and Legal **Bases**" and cites Article 6(1)(b), (c), (f),
  and (a) — and `legal basis` matched none of it. Article 14(1)(d)'s categories
  item had the neighbouring gap: a notice lists them under "Personal Data We
  Process", because the word "categories" is the regulation's, not the
  drafter's.
- **`STRUCT-007` reported a bare GDPR article as a broken internal reference.**
  "Processors acting on our instructions under Article 28 agreements" cites the
  regulation; `crossrefs.ts` already reads "Article 32 GDPR" and "Article 28 of
  the Regulation" as external, but the bare form carries no qualifier to read,
  and every GDPR notice and DPA writes it that way. Narrow on both sides: only
  in a document that names the regulation, and only for an arabic article
  number — an agreement's own divisions are "Article III", and a broken
  reference to one still reports.
- **The corporate-suffix guard knew only US forms.** A European controller is
  named "Halewood Data Systems **B.V.**" in the notice that names it, and every
  use of the name was reported as a Title-Case term the document forgot to
  define. B.V., N.V., A.G., PLC, LLP, PLLC, L.P., S.p.A., Pty, Pte, and SARL
  join the list.
- **A privacy notice is signed by nobody.** STRUCT-003 reported the absent
  signature block at `critical` on both notice playbooks, which now skip it —
  the handbook's self-declaring "is not a contract" signal does not reach a
  notice, which never says that about itself.

### Added
- An EEA/UK privacy notice specimen, pinned clean under both GDPR article
  regimes, bringing the set to fourteen.

## [9.52.1] — 2026-08-27

### Fixed
- **Nine more state-act content items the same compliant notice could not
  satisfy.** Two item types repeat in every state act with their own pattern
  arrays copied four times over, and both had the CCPA gap: a notice states its
  **purposes** under a heading reading "How We Use Personal Information" and
  names its **recipients** by category ("service providers that perform
  hosting, payment processing, email delivery, and analytics on our behalf"),
  using neither "purpose" nor "third party". Oregon's third-party item asks for
  more detail than the others — what kind of entity each is and how it may
  process the data — and the notice gives more detail, by naming the functions;
  it too reported the disclosure as absent.
- **`\b(inc\.|llc|ltd\.?|corporation)\b` could not match any real notice.** The
  trailing `\b` sits after a literal period, so it demands a word character
  immediately next — and a company name ends "Inc." at a comma, a newline, or a
  sentence end every time. Oregon's controller-identity item was blind to
  exactly the names it exists to find.
- The specimen now scores clean under all five US regimes at once
  (`--regime ccpa,co,va,tx,or`). All fourteen items are pinned in both
  directions.

## [9.52.0] — 2026-08-27

### Fixed
- **Five CCPA content items a compliant privacy notice could not satisfy.**
  Two were negated away: the PNOT pack is family-wide `negation_guarded`, which
  is right for "nothing here limits your right to …" and wrong when the
  negation **is** the disclosure. The regulation asks for the categories of
  sensitive personal information collected, and a business that collects none
  says "we do not collect or process sensitive personal information" — the
  complete answer, thrown away and reported as unaddressed. The Do-Not-Sell
  link is required of a business that sells or shares; one that does neither
  says so. Both are now matched by patterns anchored at "do", the same shape
  the "sold/shared, or none" item already uses.
  - The other three were narrow rather than negated. A notice discloses its
    **sources** by naming them ("we collect these directly from you", "from our
    payment processor", "automatically through cookies"), its **purposes**
    under a heading reading "How We Use Personal Information", and its
    **recipients** by category ("service providers that perform hosting,
    payment processing, and analytics on our behalf") — none of which uses the
    words "sources", "purpose", or "third party". A hand-written, compliant
    notice scored five warnings; it now scores none.
- **`privacy-notice-us` and `privacy-notice-gdpr` skipped 49 rules and not one
  STRUCT rule.** Their four siblings — `cookie-notice`, `hipaa-npp`,
  `childrens-privacy-notice`, `sms-consent-disclosure` — all carry
  STRUCT-001/002/004 in the standard eleven-skip profile, and a notice has no
  parties, no effective-date recital, and no defined-terms glossary either.
  `privacy-notice-us` also skips IPDATA-008: a US notice saying it stores data
  in the United States is making a disclosure, not authorizing a cross-border
  transfer without safeguards.

### Added
- A US privacy notice specimen, pinned clean — a compliant notice must produce
  nothing — bringing the set to thirteen. Both directions are guarded for all
  five CCPA items, because a widened recognizer's failure mode is an item that
  can no longer fire at all.

## [9.51.1] — 2026-08-27

### Fixed
- **A handbook was told it had no acknowledgment page, on the page that
  acknowledges it.** EMP-050 read the noun form ("acknowledgment **of**
  receipt") and the past participle ("acknowledge … **received** … handbook"),
  but not the ordinary phrasing of the section itself: "Employees are asked to
  acknowledge receipt of this Handbook."
- **A document that says it is not a contract does not have a signature
  block.** "This Handbook is not a contract of employment and does not create
  contractual rights of any kind" is the first substantive sentence of nearly
  every employee handbook, and it is there precisely because nobody signs it —
  the acknowledgment of receipt is a separate page. STRUCT-003 reported the
  absent signature block at `critical`, a finding with no answer: adding one
  would contradict the disclaimer. The signal is self-declaring, so it needs no
  playbook to be attached to, and it matches nothing in the corpus.
- **A SAFE was measured as a bilateral bargain.** `safe-yc` had empty
  `rule_overrides`, so an instrument with no IP, no indemnity, no liability
  cap, no fees, and nothing to terminate for cause drew seven always-on
  warnings. Skipped by name, as `convertible-note` and `promissory-note` were.
  Eleven findings became four.

### Added
- Two more specimens — a post-money SAFE and an employee handbook — bringing
  the pinned set to twelve.

### Changed
- The three sweeps added today (playbook self-reachability, boilerplate
  reachability, and the specimen set) carry explicit 120-second budgets. Each
  is seconds rather than milliseconds by construction — 265 playbooks against
  every one of their title keywords, 662 rules against a document, twelve full
  analyses — and slower again under coverage instrumentation, which is close
  enough to the 5-second default to flake on a loaded runner.

## [9.51.0] — 2026-08-27

### Added
- **Ten hand-written documents, and the findings each is allowed to produce.**
  Every routing and rule defect fixed today was found the same way: write a
  realistic document, run the CLI on it, and read what comes back. None was
  reachable from the suite — the fixtures are shorter, cleaner, and more
  cooperative than anything a lawyer would actually drop in. A letter puts its
  title in a "Re:" line; a filing puts it under a caption; a negotiated
  agreement stamps "EXECUTION VERSION" above it; an amendment defines nothing
  and points at its parent; a discovery response carries the name of the
  request it answers. `tests/integration/specimen-regression.test.ts` pins the
  playbook and the exact rule ids for each, in both directions — a new false
  finding fails, and so does a real one that stops firing — which makes the
  method permanent instead of a session's worth of throwaway probes. The
  specimens themselves live in `tests/fixtures/specimens/`: a state-court
  complaint, a convertible note, a law-firm engagement letter, responses and
  objections to interrogatories, a lease amendment, a mutual NDA, a medical
  director agreement, a reservation-of-rights letter, a statement of work, and
  a construction subcontract.

## [9.50.1] — 2026-08-27

### Fixed
- **A statement of work is subordinate the same way an amendment is.** An SOW
  adds rather than changes, so it carries no ratification clause — but it opens
  "This Statement of Work is entered into **under and subject to** the Master
  Services Agreement dated February 12, 2024", and where the two disagree,
  "the MSA controls". The parent supplies governing law, the liability cap, the
  indemnity, the IP allocation, and the termination machinery, and the child
  says so. A hand-written SOW drew the same five always-on absence warnings the
  lease amendment did; `amendsParentAgreement` now reads both halves of the
  shape. Nine findings became three.
  - Both halves require a **named** parent: a capitalized instrument title, or
    an order-of-precedence clause in which the other document controls. A
    standalone contract never says another agreement governs it. Probed across
    all 355 corpus fixtures before shipping — the seventeen it matches are SOWs,
    order forms, addenda, and companion agreements, every one of them genuinely
    subordinate, and exactly one changed: `bad-sow`, which loses six always-on
    absence findings and keeps its nine real ones (unfilled placeholders, no
    payment terms, a 24%/year late fee, "best efforts"). Its first sentence
    reads "This SOW is entered into under the Master Agreement dated [TBD]".

## [9.50.0] — 2026-08-27

### Fixed
- **An amendment was measured as though it were the whole agreement.** A
  hand-written third amendment to an office lease drew eight warnings, five of
  them the always-on absence checks reporting that it had no governing law, no
  venue, no indemnity, no liability cap, no termination-for-cause, no
  effect-of-termination, and no IP allocation. It has none of those because the
  Lease has all of them, and its Section 13 says so: "Except as expressly
  modified by this Amendment, the Lease remains in full force and effect and is
  ratified and confirmed." That sentence is the drafting convention for saying
  it, and the findings it drew had no answer — the only change that would
  satisfy them is restating the parent agreement inside its own amendment.
  CHOICE-001, CHOICE-003, RISK-001, RISK-005, TERM-002, TERM-005, and
  IPDATA-001 now consult a shared `amendsParentAgreement` helper. Twelve
  findings became five, and every one that remains is answerable.
  - The signal is deliberately narrow. It is **not** "the document mentions
    another agreement" — every commercial contract incorporates its exhibits by
    reference and a DPA incorporates the Standard Contractual Clauses, and
    matching those would switch these checks off across the catalog. It is the
    ratification sentence specifically, which only an amending document
    carries. No corpus fixture contains one, and no committed finding changed.

## [9.49.0] — 2026-08-27

### Fixed
- **An amendment was told its own terms were undefined.** "Capitalized terms
  used and not defined in this Amendment have the meanings given in the Lease"
  is the standard incorporation clause, and it appears in every amendment,
  addendum, statement of work, side letter, and order form — documents whose
  whole point is that the parent defines the vocabulary. A third amendment to
  an office lease was told that Base Rent, Base Year, Proportionate Share, Fair
  Market Rental Value, and Security Deposit were undefined, in a document whose
  Section 1 says exactly where they are defined, and there is no drafting
  change that would answer it short of restating the parent lease. STRUCT-006
  now recognizes the clause on its two load-bearing halves — capitalized terms
  not defined **here**, and their meanings given **there** — so a sentence that
  merely mentions defined terms does not switch the check off.
- **TEMP-010 read the expiry an amendment replaces as the one that governs.**
  It took the first paragraph naming an expiration, and an amendment recites
  the old date before stating the new one: "The Term of the Lease is scheduled
  to expire on August 31, 2026, and the parties wish to extend the Term" is a
  recital, and the operative section two paragraphs later reads "commencing
  September 1, 2026 and expiring August 31, 2031". Every date in the extension
  — including its own commencement date — was reported as falling after the
  contract's expiration. Every stated expiration is now collected and the
  latest governs, and "expiring" is admitted alongside "expires" because that
  is how an operative term clause is written.

## [9.48.2] — 2026-08-27

### Fixed
- **A construction subcontract was reviewed as a code of conduct.**
  `code-of-conduct` listed four bare nouns as distinguishing phrases —
  "directors", "officers", "employees", "waiver" — and all four appear in the
  indemnity clause of essentially every commercial contract, so it reached 0.6
  with **no title match at all**. `subcontractor-agreement` scored 0.7 on its
  own title and vocabulary and then lost 0.1 to a negative feature that is
  backwards: "lien waiver", which a subcontract almost always contains. The
  0.6 tie went to the alphabet, and the subcontract was told at `critical` that
  it was missing its SOX § 406 elements clause and its non-retaliation channel.
  Third instance of the same class today, after `employment-at-will-us`'s
  "Employee" and `promissory-note`'s "note".

### Added
- **The mirror of the self-reachability sweep: no family may claim a document
  that is nobody's.** Self-reachability asks whether a family can win its OWN
  document; it cannot see the opposite failure, a family whose "distinguishing"
  phrases are so common it wins somebody else's. The new guard scores every
  playbook against a document that names no family and carries only the clauses
  every commercial agreement has — indemnity, insurance, notices, entire
  agreement, governing law, severability, execution — and fails if anything
  reaches the 0.5 threshold. Proven by restoring `code-of-conduct`'s old
  phrases and watching it name them.

## [9.48.1] — 2026-08-27

### Fixed
- **Nine v3/v4 presence rules whose own sentence asserted a conjunction the
  code did not enforce.** The same shape as the 21 pack rules one release
  earlier, found in a catalog that needed a different signal: most v3/v4
  multi-pattern presence rules are deliberate synonym sets, and their own
  `missing_description` says so ("No signature / date / statutory-form recital
  was found"). Nine said **"and"** instead — "stating position, start date,
  **and** base compensation", "identifying the testator **and** domicile",
  "identifying the assignor **and** assignee" — while any one pattern satisfied
  the check. Each was satisfied by a document made of nothing but execution
  boilerplate: the "Title: ____" line of a signature block answered the offer
  letter's position/start-date/compensation check, "State of Delaware" in a
  governing-law clause answered the will's domicile check, and the word
  "parties" in any recital answered the assignment's assignor/assignee check.
  The rest were left alone deliberately — widening a real synonym set invents
  findings.
- **Two recognizers the conjunction exposed.** Making the pillars mandatory
  immediately produced false positives on compliant clauses, which is the
  reason both directions are pinned: a security agreement's ownership
  representation is as often in the verb form ("Debtor **represents that** it
  owns the Collateral") as under a "Representations and Warranties" heading,
  and "**free and clear of** all liens" — the standard phrase — did not match
  `free of liens`. A will almost never uses the word "testator" about its own
  maker; it opens "**I, Dermot Halloran**, a resident of …".

### Added
- **`conjunction-guards.test.ts`** pins all three directions for the nine:
  silent when every pillar is present, firing when one is missing, and firing
  on execution boilerplate alone. Zero finding changed anywhere in the corpus —
  only the version hashes moved.

## [9.48.0] — 2026-08-27

### Fixed
- **Twenty-one checks could not fire on any realistic document.** Each was a
  rule whose own name states a conjunction — "Fee schedule attached **and**
  amendment notice", "Written, signed agreement **with** a one-year minimum
  term" — written as a synonym **OR**, so one generic alternative satisfied the
  whole check. `amend` is in every amendment clause, `notice` in every notices
  clause, `state of <x>` in every governing-law clause; and `signed`,
  `authoriz`, `represent`, `present`, `witness`, and `author` are all inside
  words a signature block and an execution clause already contain — "authorized
  representatives" alone satisfies four of them. Eighteen are now conjunctions;
  three that were already conjunctions had both pillars satisfied by
  boilerplate and were tightened instead.
- **HC-108 read the literal minimum instead of a term that meets it.** "The
  term of this Agreement is three (3) years" — the commonest way a medical
  directorship is written — was reported at `critical` as having no one-year
  minimum term. Any stated term of a year or more now satisfies the pillar,
  tethered to the word "term" within the sentence so the four-year
  records-access period every such agreement carries under 42 U.S.C.
  § 1395x(v)(1)(I) cannot stand in for the term. Its writing pillar also reads
  the *evidence* of a signed writing: an agreement closing "IN WITNESS WHEREOF,
  the parties have executed this Agreement" over two "/s/" blocks is one, and
  never says "signed".

### Added
- **A boilerplate-reachability guard.** The title-vacuity probe builds a
  document that is a family's title plus execution boilerplate and asserts
  every ungated check fires — but that boilerplate is **sterile in a way no
  real document is**: no entire-agreement clause, no notices clause, no
  governing law, no "IN WITNESS WHEREOF". A check satisfied by ordinary
  execution language passed it and was still dead in the field. The new guard
  runs the same sweep against realistic boilerplate; it found all 21. Both
  directions are pinned — a companion table checks each tightened rule stays
  silent on a compliant clause written the way its own `fix` text says to write
  it, because a check that fires on a compliant document is worse than one that
  never fires at all.

## [9.47.2] — 2026-08-27

### Added
- **`docs/adding-a-playbook.md` now says what `title_keywords` are matched
  against.** The guide explained the weights and the tiebreaks but never the
  input — and the input is no longer obvious: it is a short title corpus built
  from the top of the document, and today it learned four new ways to find a
  title, because **the first line of a real document is very often not its
  title**. The new section names all five shapes that produce that (letterhead,
  court caption, legend stamp, exhibit tab, securities legend) and tells an
  author to write the phrases a real document puts on that line, not the
  internal name of the playbook. Two drift guards pin it: the preamble cap and
  the subject-line scan depth must match the constants, and the shape table
  must have a row for every shape the matcher skips.

## [9.47.1] — 2026-08-27

### Added
- **A self-reachability sweep over all 265 playbooks.** The three routing
  defects fixed today were each a family that could not be reached — an
  engagement letter beaten by an employment playbook, a convertible note beaten
  by `promissory-note`, a discovery response beaten by the request it answers —
  and each was found by hand, one document at a time. This is the mechanical
  version: for every playbook, and for **every one of its title keywords**, a
  document titled with that keyword whose body carries three of the playbook's
  own distinguishing phrases. If that does not reach it, some sibling is taking
  its documents. Deliberately a weak document, because the point is the floor:
  a family that cannot win on its own vocabulary cannot win on a real one.
  Six perspective pairs are recorded as legitimate exceptions with their
  reasons — a document does not say which SIDE of it you are on, or whether you
  want the launch pack or its deep successor. Proven by restoring
  `promissory-note`'s old title keywords and watching the sweep name the
  convertible note.
  - Testing only the FIRST title keyword was not enough: `convertible-note`
    reaches itself under "convertible note" and loses under "convertible
    promissory note", because the longer title is the one that also contains a
    sibling's keyword. That near-miss is why the sweep iterates all of them.

## [9.47.0] — 2026-08-27

### Fixed
- **The restrictive-securities legend hid the title, and "note" was a title
  keyword.** "THIS NOTE AND THE SECURITIES ISSUABLE UPON CONVERSION HEREOF HAVE
  NOT BEEN REGISTERED UNDER THE SECURITIES ACT OF 1933 …" opens essentially
  every note, warrant, SAFE, and stock certificate. It is a whole uppercase
  *sentence* rather than a stamp, so the legend-line rule did not catch it, and
  it cost a genuine convertible promissory note its routing twice over: the
  preamble was the legend, and `promissory-note` carried the bare title keyword
  **"note"**, which matches inside the word NOTE in that legend and inside
  every sibling's title. The note routed to `promissory-note` and every
  conversion check — valuation cap, discount, qualified financing,
  change-of-control premium, the accredited-investor representation — was
  skipped. A title is short and carries no sentence-ending period; a legend
  paragraph is long and does, and the test is applied only to uppercase text so
  an ordinary mixed-case preamble is untouched. `promissory-note` now lists the
  specific forms it means (promissory / demand / term / secured / installment
  note) instead of the bare word. Same class as `employment-at-will-us`'s
  "Employee", one release earlier.
- **A promissory note was measured as a bilateral bargain.** A note is signed
  by its maker; nobody indemnifies, nobody caps liability, there is no IP, and
  it does not "terminate". `convertible-note` and `promissory-note` had empty
  `rule_overrides`, so the always-on packs raised five warnings on every one.
  Skipped by name, per the fourth row of the profile table in
  [`docs/adding-a-playbook.md`](docs/adding-a-playbook.md).
- **`convertible-note`'s "safe" negative feature was a bare four-letter
  substring** that would fire on "safe harbor" or "safeguard" in any note.
  Replaced with the phrases a SAFE actually uses.
- **A term defined by a copula and a value went unregistered.** `The "Valuation
  Cap" is $12,000,000`, `The "Discount Rate" is twenty percent (20%)`, `The
  "Cure Period" shall be ten (10) business days` — ordinary drafting for a term
  whose definition is a single number, seen by none of the "means" / "refers
  to" / "is defined as" matchers, so STRUCT-006 reported the convertible note's
  own "Valuation Cap" as used-but-undefined. Gated three ways so a quoted usage
  is not swept in: the term is quoted, introduced by "The", and a number has to
  follow within a short window.

## [9.46.2] — 2026-08-27

### Fixed
- **A bare container marker hides the title exactly as a legend does.** An
  agreement attached as an exhibit is one of the commonest things a reviewer
  drops in, and "EXHIBIT A" over "MUTUAL NON-DISCLOSURE AGREEMENT" cost the
  same mis-route to `unilateral-nda` that "EXECUTION VERSION" did. "EXHIBIT",
  "SCHEDULE", "ANNEX", "APPENDIX", and "ATTACHMENT" are dropped only when the
  marker and its designator are the WHOLE line — "EXHIBIT A — FORM OF MUTUAL
  NDA" carries the title and is kept. No playbook's title keywords begin with
  one of these words, so nothing loses a signal.

## [9.46.1] — 2026-08-27

### Fixed
- **A negotiated agreement wears its legends above its title, and the legend is
  what the matcher scored.** "EXECUTION VERSION", "CONFIDENTIAL", "PRIVILEGED
  AND CONFIDENTIAL — ATTORNEY WORK PRODUCT", "DRAFT — FOR DISCUSSION PURPOSES
  ONLY" sit on the first line of a very large share of real deal documents. A
  **mutual** NDA stamped "EXECUTION VERSION" over "MUTUAL NON-DISCLOSURE
  AGREEMENT" routed to `unilateral-nda`: the mutual playbook's title keyword
  never hit, and the unilateral one won on "the Disclosing Party" / "the
  Receiving Party" — which a mutual NDA uses too, because each party is both.
  This is the launch families' own routing, so it is the widest of the three
  title-corpus holes found today (the letterhead and the court caption were the
  other two). A legend is recognized as a WHOLE line built only of legend
  tokens and separators, so a title that merely contains one of the words is
  untouched: "CONFIDENTIAL" is a legend, "CONFIDENTIALITY AGREEMENT" is a
  title. The legends are dropped before the caption walk too, so a filing
  stamped "CONFIDENTIAL — SUBJECT TO PROTECTIVE ORDER" still has its title
  found.

## [9.46.0] — 2026-08-27

### Fixed
- **A court filing names itself below its caption, and the matcher only ever
  read the courthouse.** The first paragraph of a filing is the court, then the
  party block, the docket number, and the judge; only then the line saying what
  the document is. So the preamble the matcher scored was "IN THE UNITED STATES
  DISTRICT COURT FOR THE NORTHERN DISTRICT OF ILLINOIS" — identical for a
  complaint, an answer, a motion to compel, and a set of interrogatory
  responses. A hand-written set of responses and objections matched no title
  keyword, scored 0.6 on "plaintiff", "venue", and "jury" — three words every
  filing contains — and routed to `complaint`, which then reported at
  `critical` that it had no jurisdictional statement, no demand for relief, and
  no jury demand. It is a discovery response. It is not supposed to have any of
  them. The caption's scaffolding is now skipped rather than the title guessed:
  a party name (an uppercase line ending in a comma), a bare role designation,
  and the docket/judge line are each recognizable, and the first line that is
  none of them is the filing's title. Engaged only when the document opens on a
  court line, and the court line is read whether it arrives as a paragraph
  (pasted text) or a styled heading (DOCX).
- **A discovery response was routed to the request it answers.** With the
  caption title read, the responses went to `interrogatories` instead — the
  propounding family, whose title keywords ("interrogatories", "first set of
  interrogatories") are a literal substring of every response's title, and
  whose Rule 33 checks then reported a missing response deadline on a document
  that *is* the response. `interrogatories`, `document-requests`, and
  `requests-for-admission` now carry the response-only language as negative
  features: no set of interrogatories contains "subject to and without
  waiving", "without waiving the foregoing", "general objections", or "objects
  to this request".
- **PLDG-002 and PLDG-003 could only read a federal complaint.** Every
  alternative in the jurisdiction pillar was federal (28 U.S.C. §§ 1331/1332,
  diversity, federal question, amount in controversy) and every alternative in
  the venue pillar named § 1391 or a "district" — while most complaints in the
  United States are filed in state court, where jurisdiction is pleaded under a
  long-arm statute and venue in a county. "This Court has jurisdiction over
  Defendant because Defendant transacted business within Illinois …, pursuant
  to 735 ILCS 5/2-209" is Rule 8(a)(1)'s short and plain statement, and it was
  reported missing at `critical`. The state-court form is admitted only *with*
  its grounds (because / pursuant to / under / by virtue of), so a bare "This
  Court has jurisdiction." — the conclusion without the grounds, which is what
  the rule exists to catch — still flags.

## [9.45.6] — 2026-08-27

### Fixed
- **A letter's subject line is its title, and the matcher never read it.**
  `titleCorpus` reads the first heading plus the first paragraph, which is
  right for a document whose name is at the top and exactly wrong for a
  letter, whose first paragraph is the sender's letterhead. A hand-written
  reservation-of-rights letter reached the matcher as "Meridian Casualty
  Insurance Company Claims Department 4400 Harbor Point Drive", matched no
  playbook's title keyword, scored 0.4 on two distinguishing phrases, and fell
  to `generic-fallback` — while "Re: Reservation of Rights — Claim No. …", the
  line the drafter wrote to say what the document IS, sat four paragraphs down
  and was never looked at. It now routes to `reservation-of-rights-letter` at
  0.7. Every letter-shaped family had the same hole: the WARN notice, the
  demand letter, the litigation hold, the preliminary lien notice, the
  termination-of-representation letter. "Re:", "Subject:", and "In re:" are
  read, anchored to the start of a paragraph and bounded to the first twelve,
  so a quoted piece of correspondence deep in the body is not mistaken for the
  document's own subject. A document with no subject line is byte-identical —
  no committed golden moved.
- **An alphanumeric instrument number was read as an undefined defined term.**
  "Policy No. CGL-4471982" captures as "Policy No"; the guard that recognizes
  a numbered-instrument fragment tested for digits only, so a policy, claim,
  docket, or purchase-order number with a letter prefix slipped through and
  every insurance letter was told it had forgotten to define "Policy No". A
  short letter run is now admitted before the digits, which are still
  required — so a sentence continuing after the abbreviation ("No. The
  parties …") is not swallowed.

## [9.45.5] — 2026-08-27

### Fixed
- **A law-firm engagement letter was reviewed as an employment offer.** The
  letter matched five of `engagement-letter`'s own distinguishing phrases —
  "our fees", "conflicts of interest", "attorney-client", "hourly rate",
  "trust account" — which caps at 0.6. `employment-at-will-us` reached exactly
  0.6 too, on one ubiquitous classifier category (`confidentiality-obligation`,
  worth 0.4) plus the bare word "Employee", which the letter used once in a
  boilerplate list of the people the firm is **not** representing. The tie fell
  to the lexicographic tiebreak, and "employment-at-will-us" sorts before
  "engagement-letter". Every ENG check was skipped and the always-on contract
  packs raised six warnings about a document nobody signs as a counterparty.
  The fix is the phrase, not the scoring: a single common noun that appears in
  NDAs, leases, policies, and engagement letters does not distinguish an
  employment offer, and the playbook's seven remaining phrases ("at-will",
  "base compensation", "your position", "FLSA", …) all genuinely do. The three
  employment fixtures route identically with identical findings; only the
  confidence and the reasoning string moved.
  - A tiebreak preferring the playbook with MORE matched features was written
    first and **rejected**: it rewards the sibling with the longer keyword
    list, and it flipped a controller-to-processor DPA to
    `dpa-processor-subprocessor` and a covered-entity BAA to
    `baa-subcontractor`. Recorded here because the wrong fix looked more
    principled than the right one.
- **Two ENG rules read only one shape of the clause they ask for.** ENG-001's
  boundary pillar took the limitation with a demonstrative ("**this**
  engagement is limited to") but not a possessive ("**Our** representation is
  limited to the Matter"), and read the exclusion only as "we will not
  represent", not as the undertaking not taken on ("we **are not undertaking**
  to advise you on tax, accounting, or regulatory matters"). ENG-002 had the
  mirror gap in its constituent disclaimer. Both are Rule 1.2(c) / 1.13
  drafting; both were reported at `critical` as the clause's absence.
- **A forum clause reached through a conjoined governing-law verb went
  unread.** "Any dispute … will be governed by Ohio law **and resolved**
  exclusively in the state or federal courts sitting in Franklin County, Ohio"
  states law and forum in one sentence, which is how a great many clauses are
  written. `VENUE_RESOLVED_IN`'s doublet slot required the two verbs to be
  adjacent ("filed and maintained"), so the intervening "by Ohio law" broke it
  and CHOICE-003 reported "the document does not state where disputes must be
  brought". "governed" is not, and must not become, a forum verb in its own
  right, so the lead-in is a bounded run before the "and" and every other
  anchor — a real forum verb, the "in/before/by … courts" scaffold, a
  capitalized place — still has to hold.
- **The tail of a rules citation was reported as an undefined defined term.**
  "Ohio Rules of Professional Conduct" breaks into two Title-Case runs at the
  lowercase "of". The first, "Ohio Rules", was already excluded as a citation;
  the second, "Professional Conduct", was not — so every engagement letter,
  conflicts waiver, and ethics policy that cites the body twice was told it had
  forgotten to define it. Gated on the authority noun before the "of"
  (Rules/Regulations/Canons), so an ordinary "Statement of Base Services" still
  flags. "Procedures of" is deliberately excluded from the list: it names an
  internal process at least as often as an authority.

### Added
- **A routing guard that can see the launch playbooks.** `catalog-routing`
  matched against `playbooks/extended.json` alone — the 253 specialized
  families — so a specialized family losing to one of the twelve launch
  playbooks was invisible to it, which is how the engagement letter shipped
  mis-routed. The new case builds the candidate set the live pipeline builds
  and passes the DKB classifier patterns **with their flags**, since dropping
  the flag is what keeps the deciding category from appearing at all.

## [9.45.4] — 2026-08-27

### Fixed
- **A cross-OS matrix flake on Windows.** `runProductionQa reconciles a
  directory production set` carried a 30-second timeout and a comment
  explaining why it needed one — pdfjs worker init is far slower on a cold
  Windows runner. Thirty seconds stopped being enough: the members that test
  writes are deliberately INVALID PDFs (the byte string `"doc"`), which sends
  pdfjs down its recovery path — "Warning: Indexing all PDF objects" — three
  times over, and windows-latest went past sixty seconds. Raised to 120s, which
  is a ceiling on a known-slow path rather than a budget: nothing there should
  take two minutes, and if it starts to, that is worth seeing as a failure.

### Added
- **A guard on the README's spec table.** The table is the README's index of
  what the tool does and when each part landed, and it is the only place a
  reader looks for "what is v46?" — but it is maintained by hand, so it drifted:
  it ended at v44 while v45, v46, and v47 had shipped, which meant the three
  waves that took the catalog from 145 document families to 265 were absent
  from the one place that lists them. Every count in the README already had a
  guard and all of them were current. The table had none, which is exactly why
  it was the thing that drifted. The new check is deliberately shallow — a row
  exists and links its own spec — because the row's prose is a judgment no test
  can make; what a test can do is refuse to let a spec ship without one. Proven
  by deleting a row and watching it fail.

## [9.45.3] — 2026-08-27

### Fixed
- **Three more document-reading regexes outside the swept trees.** The
  apostrophe sweep covered `src/engine/rules/**` and `src/extract/**`, and two
  places that read the document live elsewhere: the cross-document consistency
  rules (`children'?s?\s+data`, `minors?'?`) and the critical-dates scanner
  that finds the defined date a deadline hangs off. Both are now tolerant, and
  the guard covers them.

  The two regexes it still does not cover are the point of the widening:
  `src/report/html.ts` and `negotiation-sheet.ts` each carry a bare `/'/g` that
  ESCAPES an apostrophe on the way OUT. Widening those would be wrong, so the
  guard names the trees it walks and the one extra file, rather than sweeping
  `src/` and hoping.

## [9.45.2] — 2026-08-27

### Fixed
- **The apostrophe guard passed vacuously on Windows.** It listed its inputs
  with `git ls-files` and single-quoted globs; `cmd.exe` does not strip single
  quotes, so git received them literally and returned nothing, and the guard
  asserted an empty list contained no offenders. Its own "more than 50 files"
  floor is what turned that into a red cross-OS matrix rather than a silent
  pass — which is the entire reason such a floor belongs in a guard that
  enumerates its own inputs. It now walks the two source trees with `readdirSync`,
  which needs no shell. The walk is also strictly more complete: a `**`
  pathspec does not match a file sitting directly in the named directory, so
  the original sweep never looked at `src/engine/rules/_helpers.ts` or
  `index.ts` at all. Both are clean.

## [9.45.1] — 2026-08-27

### Fixed
- **A policy approved by its board reported itself unsigned.** STRUCT-003
  treats a dated adoption recital as a governance instrument's execution —
  policies and charters are adopted by resolution, not signed by parties — but
  the recital had to read "adopted by the board". A board approves or ratifies
  at least as often as it adopts, and a committee acts at least as often as the
  full board: an acceptable-use policy headed "Approved by the Board of
  Directors on August 15, 2026" drew the `critical` finding. `approved` and
  `ratified` join `adopted`, and the audit, compensation, nominating,
  governance, risk, executive, and finance committees join the board. The date
  is still required, so an amendment clause's "may be approved by the Board"
  still does not count. Version 1.23.0.
- **A statute title longer than the capture window read as an undefined term.**
  `TITLE_CASE_PHRASE` caps at five words, so "New York Limited Liability
  Company Law" captures as "New York Limited Liability Company" and the
  `Act`/`Code`/`Law` suffix test cannot see the word that makes it a law. Every
  set of New York articles of organization names it twice, which is the
  threshold for reporting. The guard now also looks at what FOLLOWS the phrase.

## [9.45.0] — 2026-08-27

### Fixed
- **Eighty-two recognizers could not read the apostrophe a Word document
  actually contains.** Word inserts U+2019 (the curly apostrophe) by default,
  and the ingest layer does not fold it: `normalize()` collapses whitespace and
  strips zero-width characters, deliberately leaving the drafter's own
  punctuation alone so a finding's excerpt is the drafter's text. So
  `landlord'?s?\s+consent` — an entirely ordinary recognizer — cannot match
  "Landlord’s consent is required", which is what a real DOCX contains.

  The failure is silent in the way this repo keeps rediscovering: every fixture
  is hand-typed with straight quotes, so no test could see it, while every
  document from Word carries the other character. Eighty-two recognizers across
  forty-one files were affected, including the landlord's consent, the
  manufacturer's warranty, workers' compensation, attorneys' fees, the
  employee's election, the seller's disclosure, the sponsor's fee, and days'
  notice. `['’]` costs nothing, and a new guard reads every regex in
  `src/engine/rules/**` and `src/extract/**` through the TypeScript scanner and
  fails on any that admits only the straight form.

  The scanner matters. A first pass that found regex literals with a regex over
  the source mistook the slashes in an ordinary string — "(e.g., '#ad' / 'paid
  partnership')" — for delimiters and rewrote a user-visible recommendation
  into `['’]#ad['’]`. Two goldens caught it, which is what they are for.

  No corpus finding moved: the fixtures are straight-quoted, which is precisely
  why the defect survived this long.

## [9.44.0] — 2026-08-27

### Fixed
- **Seventy-six compounds across the catalog could not recognize their own
  hyphen.** A QDRO says "This is a separate-interest order". EST-422's
  recognizer was `separate\s+interest`, so the hyphen — the ordinary spelling
  when a compound is used as an adjective, and the spelling the rule's OWN NAME
  uses — did not match, and the check reported the method missing at
  `critical` on the document that had stated it.

  The rule name turns out to be a good oracle: an author who writes
  "Separate-interest or shared-payment method" has already decided the compound
  is hyphenated. Probing every pack rule for a compound its name hyphenates
  that its patterns cannot match found **97 patterns across 76 distinct
  compounds** — prime-lease, safe-harbor, restricted-party, material-connection,
  working-capital, hold-harmless, third-party, dual-agency, tail coverage's
  siblings, and seventy more. `[-\s]+` costs nothing, because a compound means
  the same thing hyphenated or spaced, and the probe is now a permanent guard
  beside the title-vacuity one. No corpus finding moved.
- **Every court order reported itself unsigned.** A court order is signed by an
  OFFICE, never by a name: a QDRO, a consent judgment, and a stipulated order
  all close with "SO ORDERED … \_\_\_\_ Justice of the Supreme Court".
  STRUCT-003's standalone-signatory list covered the notary, the witness, and
  the testator but no judicial office, so each of them drew "No signature block
  detected" at `critical`. The `_{4,}` rule prefix is what keeps the words
  safe — "the Court" and "the Clerk" are everywhere in a pleading's body and
  never after a signature line. Version 1.22.0.
- **A sublease's prime-lease date read as back-dating.** TEMP-002 excludes a
  date belonging to a referenced instrument, and required the definite article
  before it. A sublease introduces its prime lease as "under **a** lease dated
  June 1, 2023" — the instrument has not been named yet, so the definite
  article would be wrong English — and an assignment, an SNDA, and an estoppel
  certificate all do the same. The indefinite article now qualifies;
  "**this** Agreement, dated …" still does not, which is the whole point of
  the discriminator. The specimen that found it was off by 1,219 days.
  Version 1.6.0.

## [9.43.4] — 2026-08-27

### Fixed
- **A discovery response that stated its production completion date was told at
  `critical` that it had not.** DISC-020's date pillar read only
  "by &lt;Month&gt; &lt;D&gt;, &lt;YYYY&gt;", and the formulation a response
  actually uses is "on or before" (or "no later than"): "Defendant will
  complete its production of responsive documents on or before December 15,
  2026" is the Rule 34(b)(2)(B) date stated exactly as the rule asks. Both join
  the pillar. A bare "before" is deliberately not admitted — "documents created
  before January 1, 2026" is a relevant-period bound, and the rule's first
  pillar is satisfied by every discovery response ever written, so the date
  pillar carries the whole check. Version 1.0.1.
- **`Schedule K-1` was reconciled as a missing attachment.** STRUCT-018 sweeps
  every Exhibit / Schedule / Annex reference and reports the ones the document
  does not contain. Its designator capture stopped at the first word boundary,
  so "reporting the Participant's distributive share on Schedule K-1" — which
  every LLC, partnership, and profits-interest agreement says — was read as a
  reference to a "Schedule K" that was missing. The IRS partnership forms are
  now recognized as forms rather than attachments, and the capture takes the
  hyphenated suffix with the designator, so "Exhibit A-1" is one attachment
  rather than a reference to "Exhibit A". Version 1.3.0.
- **`Revenue Procedure 93-27` was reported as an undefined Title-Case term.**
  The citation guard added in 9.42.3 covered `Rule`; the same shape appears
  with `Procedure`, `Regulation`, `Ruling`, `Bulletin`, `Notice`, and
  `Circular`, and a section symbol counts as the citation shape alongside a
  digit or "of &lt;Capital&gt;" — "Treasury Regulation § 1.704-1". A document
  that genuinely defines a "Program Rule" or a "Special Procedure" still gets
  flagged.

## [9.43.3] — 2026-08-27

### Fixed
- **The published accuracy scoreboard named an engine three releases old.**
  `tools/accuracy/SCOREBOARD.md` is a trust artifact whose whole claim is that
  the same `(corpus, dkb, engine)` triple reproduces the same
  `scoreboard_hash` — and it was published naming engine `9.42.0` while
  `9.43.2` shipped. The guard that keeps it current pinned the rule and
  playbook counts and deliberately left everything else alone, on the reasoning
  that the remaining fields "legitimately move with the corpus". The engine
  version does not: it moves with the release, it is deterministic, and it is
  one third of the reproducibility triple the artifact asserts. It is now
  pinned to `package.json` in both the JSON and the Markdown, with the same
  one-line fix the counts have — `npm run accuracy`. Proven by de-syncing the
  artifact and watching the guard fail.
- **The legal-basis review queue was stale for the same reason**, and its guard
  — which compares the whole committed file against a fresh generation — caught
  it as soon as a release moved the engine version. Regenerated. Two published
  artifacts carry the engine version; only one of them had a guard that could
  see it go stale.
- **The clause-scan timing test flakes no more.** Best-of-five over single
  scans was still not enough: the 47k measurement takes a fraction of a
  millisecond, so most of it is timer quantization. Each side now times a batch
  of twenty identical scans — the same batch on both sides, so the ratio is
  unchanged — which puts every reading in the milliseconds, and takes the best
  of three batches, since scheduling noise only ever adds time.

## [9.43.2] — 2026-08-27

### Fixed
- **A purchase order that said what termination costs was told it said
  nothing.** TERM-005 recognizes an effect-of-termination clause through a
  dozen branches, and buyer-side PO terms state the effect in the same sentence
  as the right: "Buyer may terminate this order for convenience on written
  notice, in which case Buyer pays for conforming goods delivered and Seller's
  reasonable unavoidable costs." No branch admitted it — "pays for goods
  delivered" is not a wind-down verb, and `pay` is deliberately outside the
  consequence set so a failure-to-pay TRIGGER cannot read as an effect. The
  connective does the work instead: "in which case" introduces a consequence
  and nothing else, so pairing it with a termination word in the same sentence
  is specific without enumerating the verb at all. No corpus finding
  disappeared. Version 1.9.0 → 1.10.0.
- **The mutation job runs two test-runner children, not four.** Three complete
  runs on August 17 took about seven minutes each; both runs since were killed
  part-way — SIGTERM at four minutes on the 24th, a runner cancel at nineteen
  on the 27th — with nothing in the repo to explain it. Four test-runner
  children plus the Stryker parent on a four-core hosted runner is the resource
  pressure that fits. Concurrency changes only how long a run takes, never what
  it measures, and reliability is worth more than wall time on a weekly job off
  the push path. Local runs keep the config default.

## [9.43.1] — 2026-08-27

### Fixed
- **A weekly workflow had been red since August 24 and nobody could have seen
  it.** The scheduled mutation-testing run was killed by the runner four
  minutes in — `The runner has received a shutdown signal`, exit 143 — and
  reported as a plain job failure. Nothing distinguished that from the one
  failure the job exists to report, a mutation score below the `break`
  threshold, and `gh run list` shows push workflows first, so a workflow that
  runs only on a schedule sits red unnoticed. The header comment had claimed
  since it was written that transient infra should not fail the job and the
  score gate is the signal; nothing implemented it. Now the step reads the exit
  code: 1 (and anything else) fails with an annotation naming the score floor;
  130, 137, and 143 — the signal deaths, 137 being the shape an OOM takes —
  annotate the run as unfinished and let it pass, because a red job nobody can
  act on is a red job nobody looks at. The job also carries an explicit
  `timeout-minutes: 120` — generous on purpose, since complete runs in August
  took about seven minutes and one on August 27 took over fifty on the same
  scope: the bound exists to stop a hang, not to police duration.
- **A Rule 34 request that stated its deadline was told at `critical` that it
  had not.** DISC-001 requires a deadline AND a response word, and its response
  pillar read only `respond`, `response`, and `answer`. Rule 34 asks for
  PRODUCTION, and that is the verb the requests themselves use — "produce the
  following documents for inspection and copying within 30 days of service"
  states exactly the deadline the rule wants and contains none of the three.
  `produce` and `production` join them; a request with no day count at all
  still fires. Version 1.0.1.
- **A timing-ratio test flaked under load.** `_helpers.test.ts` guards the
  shared clause scan against a quadratic regression it once had by
  comparing one measurement at 47k characters against one at 190k. A ratio of
  two single samples is a ratio of two worst cases — vitest runs files in
  parallel, so either sample can be interrupted — and one unlucky small sample
  read a linear scan as 39x. Each side is now the BEST of five runs, which
  estimates the algorithm's own cost (scheduling noise only ever adds time)
  without weakening the signal: a quadratic scan's best case is still ~16x its
  best case at a quarter of the input.

## [9.43.0] — 2026-08-27

### Added
- **Express-denial frames on thirteen more catalog columns**, reaching the
  sub-domains 9.42.5 did not: a property manager's segregated trust account,
  the agency and dual-agency disclosure, the seller's property-condition
  disclosure, a licensee's product-liability insurance, the spendthrift clause,
  a trust amendment's notarization, the cohabitation agreement's independent
  counsel and financial disclosure, a fiscal sponsor's variance power, the
  UCC-1 filing, the incident-response chain of custody and regulatory
  notification clocks, a medical director's time records, and an
  investigator's publication rights. Twenty-seven columns now report a
  disclaimer AS a disclaimer.

### Fixed
- **A negated withholding verb was read as a denial.** "Sponsor shall not
  withhold publication rights beyond the stated review window" GRANTS the
  rights — it is the clause HC-118 exists to bless — and the frames read it as
  a disclaimer of them. The frames match a negation and then the topic; they
  cannot see the verb in between, which is why the gap already refuses to cross
  `without`, `unless`, `prevent`, `preclude`, `restrict`. `withhold`, `deny`,
  `refuse`, `impair`, `delay`, `obstruct`, and `interfere` join them: negating a
  verb that BLOCKS the term is an affirmation of it.
- **An instrument could not deny carrying a clause.** The verb set was written
  for a party denying conduct ("performs no OFAC screening"). An instrument
  denies differently — "this trust contains no spendthrift provision" — and
  that matched nothing. `contain` and `include` join the set.

  Both changes are to the shared helper, so they reach the 27 v4 rules wired in
  9.31.0 as well. No corpus finding moved.

## [9.42.5] — 2026-08-27

### Fixed
- **The catalog read an express disclaimer as compliance.** A clause-presence
  check fires when none of its patterns match, so a document that
  AFFIRMATIVELY DISCLAIMS the term — "the Company performs no restricted-party
  screening", "IRB approval is not required before enrollment", "an online
  cancellation mechanism is not provided" — is silent: every topic word is
  present, and the column scores as satisfied. That is backwards. An omission
  may be an oversight; a disclaimer is a decision, and it is the one the check
  must not miss.

  `expressDenial()` was built for exactly this in 9.31.0 and wired into 27 v4
  rules. **None of the 697 rules the v5/v6 shorthand builds used it**, though
  `pack()` has accepted a `denied` field since the wave shipped. Fourteen
  columns now do: BIPA's written release and retention schedule, COPPA's
  verifiable parental consent, the TCPA's prior express written consent and
  STOP/HELP opt-out, malpractice tail coverage, IRB approval, restricted-party
  screening, the auto-renewal cancellation mechanism, the influencer
  material-connection disclosure, employer payment of arbitration costs, the
  FCRA written authorization and pre-adverse-action notice, and an architect's
  professional liability insurance. A column whose required clause is ITSELF a
  negation or ban is disqualified and left alone — PRV-114
  (consent-not-a-condition-of-purchase) and HC-123 (balance-billing ban) are
  checked by their absence, and a "denial" of them is unreadable.

  `pack()` now generates the denial's own title and description, so a
  disclaimer reports as "— expressly disclaimed" rather than "— not found".
  The title is what reaches the findings index, the compliance matrix, and the
  execution log, where the description never does.

  Both directions are pinned, and the adversarial half is load-bearing: every
  decoy is compliant drafting that puts the topic words inside a negation.
  EMP-103 broke on the first attempt — "the employee shall not be required to
  bear arbitration costs beyond a court filing fee" is the clause the rule
  exists to bless, and a bare "arbitration costs" topic read it as a denial,
  because the frames cannot see WHOSE obligation is negated. The topic is now
  the employer's undertaking (paying), not the cost.

## [9.42.4] — 2026-08-27

### Fixed
- **A preliminary lien notice and a warranty deed were both read as
  back-dated.** TEMP-002 flags the earliest absolute date in a document when it
  sits more than 30 days before the next one and apart from the rest — the
  shape a back-dated contract has. It never checks that the earliest date IS
  the document's effective date, so it grew a list of guards for dates that
  belong to something else: a referenced instrument, a stated period, a
  birthdate, a case citation, a regulation. Two more shapes were missing, and
  each is definitional to the document it appears in, not incidental:
  - a **reported past event** — "FIRST DATE LABOR OR MATERIALS WERE FURNISHED:
    August 18, 2026" on a notice served October 2. A preliminary lien notice
    exists to state that work began before the notice was served; the 45-day
    gap is what the statute requires, not an anomaly;
  - a **recorded instrument** — "Lot 14 of the Cedar Ridge Subdivision as shown
    on a map filed in the Tompkins County Clerk's Office on June 3, 1998". Every
    deed's legal description cites a decades-old subdivision map or a prior
    liber-and-page, so an ordinary conveyance read as back-dated by
    twenty-eight years.

  The suppression is checked in both directions: a contract whose own effective
  date sits a year before every other date in it still fires, and no corpus
  finding disappeared — every golden diff is a one-line hash replacement.
  Version 1.4.0 → 1.5.0.

## [9.42.3] — 2026-08-27

### Fixed
- **A street address, a lawyer's name, and a rule citation were each reported
  as a Title-Case term the document forgot to define.** STRUCT-006 reads the
  extractor's `undefined_capitalized` list, which already excludes place
  names, statute titles, officer titles, entity names, party names, and street
  addresses. Three shapes slipped past, and all three showed up the first time
  a WARN notice, a privilege log, and a stipulated protective order were run:
  - the street-suffix guard listed nine suffixes and not the ones a modern
    address uses, so "88 Harbor Way" was reported. `Way`, `Place`, `Court`,
    `Terrace`, `Circle`, `Plaza`, `Square`, `Trail`, `Row`, `Turnpike`, and
    `Crossing` join it — which also takes "Superior Court" and "District
    Court" out, correctly;
  - a privilege log, a certificate of service, and a signature block all name
    people who are **not parties**, so the party extractor never sees them and
    every such name used twice was reported as undefined. A name carrying the
    post-nominal ("Marcus Field, Esq.") is now recognized as a natural person;
  - "Federal Rule of Civil Procedure 26(c)" was reported as an undefined
    "Federal Rule". `Act`, `Code`, and `Law` were already excluded by suffix;
    `Rule` now is too, but only when the citation shape follows it (`of` plus
    a capital, or a digit), because a document may genuinely define a
    "Program Rule" — and one that does still gets flagged.

  Known limitation, deliberately not fixed: a person introduced by an unquoted
  role parenthetical ("Ana Duarte (General Counsel)") is still reported. Every
  test that separates it from a genuine defined-term shorthand ("Grantor") also
  separates a real defined term from itself, and personal-name detection by
  shape alone would swallow "Contract Sum".

## [9.42.2] — 2026-08-27

### Fixed
- **A warranty deed was told it lacked quitclaim granting words.** Two matcher
  defects met on the same document. `warranty-deed`'s distinguishing phrases
  were each written as one rigid clause a real deed conjugates differently —
  "does hereby grant, bargain, sell and convey" against "grants, bargains,
  sells, and conveys"; "warrant and defend the title" against "WARRANTS AND
  WILL DEFEND the title"; "free and clear of all encumbrances" against "free
  from all encumbrances" — so an ordinary warranty deed matched **none** of
  them and scored 0.3, its title alone. `quitclaim-deed` meanwhile listed
  "grantor", "grantee", and "notary public", which every deed ever written
  carries: three generic words are 0.6, above the 0.5 routing threshold, with
  no title match at all. The warranty deed routed to `quitclaim-deed` and was
  told at `critical` that it was missing quitclaim granting words and a
  no-warranty recital — the two things it exists not to have. Both lists are
  rewritten around what actually distinguishes the two instruments, and a
  routing test pins each specimen to its own family.
- **Five families could not be reached by the title their own name gives
  them.** A title keyword is worth 0.3, more than half the routing threshold
  and more than any other single signal, and it is scored by plain substring.
  The family called "WARN Act Notice" listed "warn notice" and "notice of
  plant closing", neither of which is a substring of "WARN Act Notice", so a
  specimen titled exactly that scored 0.4, fell to `generic-fallback`, and
  none of its six checks ran; with the keyword present it scores 0.7 and
  routes. Same for "Telehealth Informed Consent", "Biometric Data Consent",
  "Expert Witness Retention Agreement", and the hyphenated
  "Hold-Harmless Agreement". A new guard asserts that a curated list of
  families — the ones whose `name` IS the natural title of the document, as
  against display labels like "MSA — Customer-Side Deep Analysis" — each
  recognize a document titled with their own name.
- **An engagement letter that drew the scope boundary was told it had not.**
  ENG-001's exclusion pillar read only the affirmative framings ("this
  engagement is limited to", "matters not covered"). The commonest drafting
  states it negatively — "We will not represent the Company in any appeal, in
  any tax matter, or in any other matter" — so a letter that drew the boundary
  exactly as Model Rule 1.2(c) contemplates was told at `critical` that it had
  drawn none. ENG-002's naming pillar likewise read "we represent" but not
  "we will represent", which is how a letter written before the work begins
  says it. Both are 1.0.1.
- **A lawyer's engagement letter was asked for a malpractice liability cap.**
  The five v6 engagement families keep the contract rules — an engagement
  letter IS an agreement — except the five that do not belong in one. A law
  firm's engagement carries no IP-ownership clause and no indemnity; its
  termination column is owned by ENG-008 in the vocabulary the Model Rules use
  (withdrawal, discharge, file return) rather than "termination for cause";
  and the liability cap is the one clause the governing rule RESTRICTS —
  Model Rule 1.8(h)(1) forbids a lawyer to limit malpractice liability
  prospectively unless the client is independently represented in making the
  agreement. Measured on a full specimen, the letter goes from twelve findings
  to six, three of which are its own ENG checks reporting terms genuinely
  absent.

## [9.42.1] — 2026-08-27

### Fixed
- **A well-formed civil complaint scored worse than any contract in the
  catalog.** Run one through the CLI — proper caption, jurisdiction and venue
  allegations, numbered paragraphs, counts, prayer for relief, jury demand,
  Rule 11 signature block — and the report was eleven findings, one of them
  `critical`, none of them about the complaint: no governing-law clause, no
  indemnity, no liability cap, no IP-ownership clause, no
  termination-for-cause clause, no defined-term glossary, no "Effective Date".
  A pleading has none of those because a pleading is not an agreement.
  Meanwhile all eight `PLDG` checks passed silently, so the one document shape
  the family exists to bless read as the catalog's worst.

  The repo already knew the answer. Fifty v3/v4 playbooks carry an
  eleven-rule `rule_overrides` block for instruments nobody signs as a
  counterparty — wills, codicils, powers of attorney, corporate policies,
  statutory notices, one-sided consents, demand letters — and three court
  filings carry a wider fifty-three. The v5 catalog and the v6 law-practice
  packs then shipped 135 families with `rule_overrides: {}`, and the existing
  guard could not see it: it asserts what is IN the cohort and has no way to
  know what should have been. Forty-seven families join a profile — fourteen
  litigation papers on the filing profile, thirty-three policies, plans,
  deeds, trusts, statutory notices, consents, disclosure documents, and
  letters on the non-agreement one. The criterion is one question: does
  anybody sign this as a counterparty accepting terms? A WARN notice does
  not, and is not missing its limitation of liability. The complaint goes
  from eleven findings to none; a Rule 34 document request from fourteen to
  four, all of them its own `DISC` checks reporting terms genuinely absent.
  The guard now derives the filing profile from `trial-motion` and asserts it
  identical across all sixteen members, so a new member cannot be admitted
  with fifty-two of the fifty-three.
- **Every pasted letter and court filing reported itself unsigned, at
  `critical`.** STRUCT-003 grew two escape hatches for documents not signed on
  a `By:/Name:/Title:` grid — the conformed `/s/ Dana Reyes` of a court
  filing, and the valediction that closes correspondence. Both were anchored
  to the start or end of a LINE, and neither anchor survives the ingest path
  most likely to carry them: `ingestPaste` reconstructs a paragraph by joining
  its lines with SPACES, so a three-line signature arrives as one block with
  no line breaks in it, `^` means the start of that whole block, and `$` its
  end. All twelve existing fixtures hand the rule one line per paragraph —
  what a DOCX produces and what `buildTree` makes — so no unit test could see
  it; it surfaced by running `bin/vaulytica.mjs analyze` on a plain-text
  letter and complaint written for the occasion. The conformed mark is now
  recognized after a valediction comma or a sentence period too (still
  anchored against a URL path), and the valediction is matched by words with
  what follows it — end of line, or the capital letter beginning the signer's
  name — checked separately in code. That last part is the trap inside the
  trap: spelling the requirement as `(?:$|[A-Z])` inside the existing
  case-insensitive pattern matches a lowercase letter too, and admitted
  "Respectfully submitted, this motion should be granted" as a signature.
- **A properly numbered complaint was told to number its paragraphs.**
  `pack()`'s `all: true` conjunction composed its pillar patterns into one
  anchored lookahead regex, which cannot carry per-pattern flags. The loss is
  silent for a pattern whose flags do not change what it matches — true of 691
  of the 697 pack patterns, false of exactly three. PLDG-004 recognizes a
  numbered pleading paragraph with `/^\s*\d+\.\s/m`; without `m`, `^` is the
  start of the DOCUMENT, and paragraph 1 of a real complaint is never the
  first character of the file. The check fired at `critical` on precisely the
  complaints it exists to bless. DISC-005 and DISC-013 carried the same
  recognizer behind an alternation that could still match "Request No. 1", so
  they misread only the requests numbered "1." alone. The conjunction is now
  evaluated pattern by pattern (`require_all_present` on the presence
  builder), so no rewriting step exists to lose a flag in. Three guards
  followed: the title-vacuity probe now covers v6 as well as v5, a gated
  rule's recognizers are read straight out of its spec (reaching past the
  closed gate that made the gated set a blind spot its own size), and the flag
  contract itself is pinned.

## [9.42.0] — 2026-08-25

### Fixed
- **The playbook matcher never saw the document's title on a plain-text or
  unstyled document.** Title keywords are the single largest contributor to a
  playbook score — 0.3, against 0.2 per distinguishing phrase — and three
  production call sites (the browser pipeline, the bundle pipeline, and the
  Node/CLI pipeline) plus the parity test that simulates the browser path had
  each built that input as `sections[0]?.heading ?? filename`. `??` catches null
  and undefined, not the **empty string** the tree builder produces for a
  document with no styled heading, so every pasted or plain-text document — and
  every DOCX whose title is bold body text rather than a Heading style — reached
  the matcher with an empty title, and not even the filename fallback fired. The
  observable effect: a short, unambiguous engagement letter scored 0.4 against
  the 0.5 threshold, fell to `generic-fallback`, and none of its family's checks
  ran. With the title seen it scores 0.7 and routes. The corpus documents all
  carry proper headings, so the repair is hash-neutral — every golden is
  byte-identical — while the signal it restores applies to every one of the 265
  families. `titleCorpus` now lives beside `matchPlaybook`, which is the only
  reason a fifth copy of that line cannot appear.
- **Lighthouse CI was red on `main`.** The byte-level `unused-css-rules` audit
  (inherited at `error` from the `lighthouse:no-pwa` preset) began failing on the
  previous commit's front-page rewrite and stayed red. It is now `warn`,
  alongside `unused-javascript` and `unminified-css`, which were already
  downgraded for the identical structural reason: the landing page is a single
  self-contained file that inlines all 55 KB of its CSS so it paints with zero
  network requests, and most of that CSS styles content below the fold or inside
  a `<details>` disclosure — which is, by definition, unused at first paint. It
  is not removable either: the selectors that look unreferenced (`np-*`, `pm-*`,
  `pc-*`, `delivery-*`) are composed at runtime from template strings. Every
  budget that describes what a user actually waits for stays at `error` and
  stays passing: performance ≥ 0.85, accessibility ≥ 0.95, FCP ≤ 1800 ms, LCP
  ≤ 2000 ms, TTI ≤ 2000 ms, TBT ≤ 200 ms, CLS ≤ 0.1.
- **Two vacated FTC rules were being cited as governing law
  ([`spec-v47.md`](docs/spec-v47.md)).** A deterministic linter's whole claim is
  that every finding cites a real authority, and the failure mode that claim is
  most exposed to is a citation that *was* good law and is not any more —
  invisible in a diff, invisible in the goldens, and reading to an attorney as
  confident, sourced advice. The FTC's 2024 "click-to-cancel" amendments to the
  Negative Option Rule were vacated in their entirety in July 2025, never took
  effect, and 16 C.F.R. Part 425 has been recodified to its pre-2024
  prenotification-plans text — but six surfaces still presented it as governing
  a SaaS subscription, including a rule *named* "FTC Click-to-Cancel alignment".
  Separately, the M&A restrictive-covenant playbook still framed itself on the
  FTC Non-Compete Clause Rule's § 910.2(a)(2), which was set aside nationwide
  and removed from the CFR. Every affected check keeps its logic and gets the
  authority that actually imposes the obligation — ROSCA (15 U.S.C. § 8403) and
  the state automatic-renewal laws for cancellation parity, the state
  sale-of-business goodwill doctrine for seller covenants. Rule versions bumped
  and 340 goldens regenerated, because the report text genuinely changed. The
  DKB entry for Part 425 now carries the vacatur note inline the way the Part
  910 entry already did.
- **Three v5 patterns that would have flagged compliant drafting.** The
  variance-power check (`GOV-129`) recognized "sole discretion" but not
  "complete discretion and control", which is the standard fiscal-sponsorship
  formulation; the permitted-exceptions check (`RE-134`) did not recognize a
  deed excepting matters by reference to the title commitment's Schedule B; and
  the FCRA stand-alone disclosure check (`EMP-148`) did not recognize a form
  that says "stand-alone disclosure" rather than "clear and conspicuous".

### Added
- **End-to-end catalog routing coverage
  ([`catalog-routing.test.ts`](tests/integration/catalog-routing.test.ts)).**
  Every other guard on the two new waves is structural — the rules exist, they
  are gated, they fire on an empty document, they stay silent on a compliant
  clause. None proved the thing a user actually depends on: that dropping the
  document in front of them **reaches** the new family at all. A playbook whose
  match features never win is 605 checks that never run, and adding 120
  playbooks to a matcher that scores every playbook against every document is
  exactly how a new family loses to an older sibling on a document that is
  plainly its own. The test drops a short realistic instance of a representative
  family from each wave, requires the matcher to pick it with a real margin above
  its own 0.5 floor, and separately asserts that every playbook the v5/v6 rules
  are gated to actually made it into the served bundle — because a playbook
  missing from `playbooks/extended.json` leaves its whole ruleset dead in the
  deployed product while every unit test still passes.
- **A vacated-authority drift guard
  ([`vacated-authority.test.ts`](tests/integration/vacated-authority.test.ts)).**
  Every drift guard in this repo compares the repo against itself, and an
  authority going stale is a change in the world that no self-consistency check
  can see. This one holds a registry of vacated authorities and asserts that no
  rule name, description, or citation — and no line of the repaired prose files
  — names one without a disclaimer nearby. It cannot know what gets vacated
  next; its value is that a repair cannot be silently undone, and that the next
  discovery has one obvious place to land. `spec-v47.md` records the repair
  pattern and the per-release re-verification cadence.

### Added
- **The lawyer's own documents: engagement letters, discovery, and pleadings
  ([`spec-v46.md`](docs/spec-v46.md)).** Every wave through v5 reads a document
  the lawyer's *client* is a party to. v6 turns the same engine on the documents
  the **practice itself** produces — 15 families and 92 checks across three new
  packs. `ENG` reads engagement letters, contingency and flat fee agreements,
  joint-representation waivers, limited-scope agreements, and closing letters
  against the ABA Model Rules, concentrating on the enumerated requirements
  (Model Rule 1.5(c)'s four contingent-fee elements; Rule 1.15(c) advance-fee
  trust handling; Rule 1.16(d) file return and refund of the unearned portion)
  rather than the evaluative ones. `DISC` reads requests, responses, privilege
  logs, Rule 26(f) reports, and deposition notices against the FRCP, with its
  center of gravity on the 2015 amendments practice has been slow to absorb:
  objections stated with specificity, the Rule 34(b)(2)(C) statement of whether
  responsive material is being withheld, the "subject to and without waiving"
  formulation, and a stated production completion date. `PLDG` reads complaints
  and answers for the structural elements Rules 8, 9, 10, 11, and 38 require,
  concentrating on the four omissions that cannot be cured later — the jury
  demand, the Rule 8(c) affirmative defenses, the Rule 12(h)(1) defenses, and
  the Rule 8(b)(5) formulation. Totals: **265 document types** and **1,808
  single-document rules**.
- **Two caveats rendered into the citation, not a footnote.** These are the first
  packs whose governing text mostly does not bind, so both caveats travel with
  the finding onto every report surface. Every ABA Model Rule citation reads
  "(model text; each state adopts its own version)" — a finding says a term the
  Model Rules contemplate was not found, never that the lawyer's jurisdiction
  requires it. Every discovery and pleading scope statement lists local rules and
  standing orders under *not reviewed for*, because they routinely displace the
  national rule on response formats, privilege-log contents, caption format, and
  jury-demand placement. A guard test asserts that no rule name in the wave
  contains a professional-duty conclusion word.

- **The US catalog: 105 more American document families, 605 more checks
  ([`spec-v45.md`](docs/spec-v45.md)).** v4 took the catalog from "contracts" to
  "every logically-operative legal document" across sixteen sub-domains, and
  stopped one layer short of what a US practice handles all day. v5 goes deep
  inside those same sixteen: the purchase order and the master purchase
  agreement under the UCC, the franchise agreement and its FDD, the FAR
  flow-down rider, the sublease and the work letter, the WARN notice and the
  FCRA background-check disclosure, the stipulated protective order and its
  Rule 502(d) clawback, the QDRO, the first- and third-party special needs
  trust, the preliminary lien notice, the D&O and cyber policies, the deposit
  account control agreement, and the incident response plan. Every family is
  US, and every check cites US law — the UCC as the states enacted it, an FTC
  trade regulation rule, the FAR, ERISA, Bayh-Dole, a state mechanic's lien
  statute — or says plainly that it rests on customary drafting practice
  rather than a rule that compels the clause. The catalog was authored
  **column-first**: each family's compliance matrix is the design, and each
  column ships as exactly one check, with a guard test asserting the two never
  diverge. Totals: **250 document types** and **1,716 single-document rules**,
  up from 145 and 1,111.
- **A title-vacuity guard for presence rules
  ([`title-vacuity.test.ts`](src/engine/rules/v5/title-vacuity.test.ts)).** A
  clause-presence rule fires when *none* of its patterns match, so a rule whose
  pattern is a word from its own document family's title can never fire — a
  column the compliance matrix shows as reviewed that reports nothing on any
  document, forever. The new probe hands every ungated check the emptiest
  document its family admits (the title plus execution boilerplate) and
  requires it to fire. It caught **27 real instances** on first run, including
  the irrevocability recital satisfied by the words "Irrevocable Trust", the
  UCC § 9-104 control language satisfied by the word "Control" in "Deposit
  Account Control Agreement", and the FCRA written authorization satisfied by
  the word "signature" in an ordinary signature block. Rules carrying an
  applicability gate are excluded, and the gated set is *derived* rather than
  hand-maintained so a stale id cannot widen the exclusion.

### Changed
- **Three new bundle chunks (`v5-rules-corp`, `v5-rules-reg`, `v6-rules`).** The v5 catalog is
  ~285 KB raw; left in the shared `rules-core` chunk it pushed that chunk to
  883 KB, past the 600 KB per-chunk cap. It now splits on the same
  corporate/regulatory line v4 uses. The v6 law-practice packs are ~45 KB and
  ship as one chunk. Nothing moves onto the first-paint path.

### Added
- **Production-QA now works in the browser bundle, not just the CLI.** Drop a
  privilege-log `.csv` alongside the produced documents (multi-file or folder
  drop) and the bundle report reconciles Bates numbering (from the document
  filenames) and the log against the produced set — the same
  `buildProductionQaReport` core the `vaulytica analyze <dir> --production-qa`
  mode uses. The result rides in the bundle JSON export as a `production_qa`
  block with its own `production_qa_hash`, and as a **Production QA section** in
  the consolidated bundle DOCX report (and the "everything" ZIP) — a findings
  table with the honest scope of review. A privilege log is metadata about the
  production, not a document with its own `result_hash`, so it is held outside
  `bundle_fingerprint`: a bundle of the same documents fingerprints identically
  whether or not a log rode along. A lone `.csv` is still rejected (a privilege
  log is only meaningful next to the documents it describes). The bundle-complete
  screen also shows a "Production QA" card summarizing the reconciliation with the
  honest scope note. The privilege log is picked up from either input path — a
  multi-file/folder drop or a `.zip` bundle (the archive extractor now inflates the
  `.csv` member under the same zip-bomb guards). When a privilege log is present,
  each document is also given a pre-production HANDOFF sweep (tracked changes,
  comments, hidden text, authoring metadata, sensitive-data patterns) whose roll-up
  shows in the JSON, the DOCX section, and the UI card — full parity with the CLI
  `--production-qa` mode. This completes the browser integration of the
  production-QA pack.

### Fixed
- **A liability cap written "$5.5mm" is no longer read as five dollars.** The
  cross-document cap parser's magnitude-suffix list had drifted from the one the
  amount extractor uses, and was missing the "mm" / "mn" / "kk" shorthands. That
  is not a gap but a MIS-read: the optional suffix cannot consume "mm" (the `m`
  alternative is followed by another word character, so the trailing word
  boundary fails), and the number then backtracks to "5" so the decimal point can
  supply the boundary. A bundle whose master agreement says "$5,500,000" and
  whose order form says "$5.5mm" was compared as 5,500,000 against 5 and reported
  as a 1,100,000× discrepancy between two documents that agree exactly. The list
  now mirrors the extractor's, full words before single letters and "mm"/"mn"
  ahead of a bare "m" so they are not shadowed.
- **Two rules no longer accuse a clause that says the opposite of what they
  flag.** The class-action-waiver rule and the model-training-rights rule each
  sliced out "the current sentence" with a bare `lastIndexOf(".")` before testing
  it for a sentence-leading "Nothing" / "Neither" / "At no time" / "Under no
  circumstances". A bare period stops at the "." in "Section 5.2" and in "Acme
  Inc.", so the protective opening was cut out of view: "Nothing in this
  Agreement, including Section 5.2, waives your right to a class action" was
  reported as a class-action waiver, and "At no time, subject to Section 4.1,
  will we use your data to train our models" as a training grant — the very
  false accusation each rule's own comment says the guard exists to prevent.
  Both now use the shared, abbreviation-aware sentence bound. A repo-wide sweep
  found these two; they were the fifth and sixth copies of that boundary rule.
- **The DTSA notice completeness check now reads the notice, not the whole
  document.** It counted its three statutory components — immunity, disclosure to
  a government official or attorney, and a sealed-filing carve-out — anywhere in
  the agreement, and each component pattern is deliberately loose. That was wrong
  in both directions. A notice missing its sealed-filing prong scored as complete
  because an unrelated exhibit was "filed under seal", so the rule went silent on
  an incomplete statutory notice — which under 18 U.S.C. § 1833(b) costs the
  employer its exemplary-damages and fees remedy. And on an NDA with no notice at
  all the count fell short and the rule reported "DTSA notice is incomplete",
  describing a notice that does not exist; absence is the presence rule's finding
  and its wording says so properly. The components are now counted inside the
  clause itself, and where a document mentions the topic more than once — an NDA
  names trade secrets in its perpetuity carve-out as well as in the notice — the
  best candidate is judged rather than the first, so a compliant agreement is not
  accused because its carve-out quite properly carries none of the pillars. The
  count spans the anchored paragraph and its immediate neighbours within the same
  section, because a drafter may legitimately split one notice across two
  paragraphs — citation and immunity in the first, the sealed-filing carve-out in
  the second — and judging the anchor paragraph alone accused that perfectly
  ordinary drafting. The window stops at three paragraphs and at the section
  boundary rather than widening to the whole section, since a document with few
  headings is one enormous section and that would reopen the document-wide
  counting this fix exists to stop. The anchor also recognizes a notice that
  paraphrases the statute without citing it, naming the Act, or using the word
  "immunity", which is ordinary drafting the first attempt missed entirely — with
  a trade-secret context requirement so that an ordinary "shall not be held
  liable" limitation clause is not mistaken for a notice.
- **Two rule helpers no longer lose a negation at an abbreviation.** The shared
  helpers that ~30 always-on rules call to decide whether a clause is disclaimed
  (`isPresenceDisclaimed`) or whether a trigger is negated
  (`firstUnnegatedParagraphMatch`) each carried their own reverse boundary scan
  — a literal `lastIndexOf(". ")` and a `split(/[.;]\s|\n/)` — while
  `enclosingSentence`, in the same file, already walked the shared,
  abbreviation-aware `SENTENCE_END`. Both private scans stopped at the period in
  "Sec. 5", so a cross-reference sitting between the negation and the trigger cut
  the negation out of the window: "does not include, per Sec. 5 hereof, an
  indemnification clause" read as a clause that was present, and "shall not, per
  Sec. 5 hereof, automatically renew" read as a live auto-renewal. Both helpers
  exist precisely to *find* that negation, and firing on drafting that plainly
  disclaims the clause is the confident false accusation this file's own comments
  call the worst honesty failure for an always-on rule. All three now share one
  scan, which is the point — this was the third copy of a boundary rule that had
  drifted before, and a single definition cannot drift from itself. Zero golden
  churn.

  The shared scan runs BACKWARD from the match and stops at the first boundary
  of any kind, so its cost follows the distance back to that boundary rather
  than the length of the document. That matters because these helpers are called
  once per match inside a loop over every match in a paragraph: the obvious
  implementations — running the boundary rule forward from index 0, or calling
  `lastIndexOf` for a separator the text does not contain — are each O(n) per
  call and made the whole scan super-linear. A 190,000-character paragraph took
  849ms and now takes 3ms. The rule helpers had no performance gate at all (the
  extractor fuzz suite caps its inputs at a few hundred characters and does not
  reach this layer), so one was added.
- **Three more DKB fetchers now survive one source's outage.** The eCFR fetcher
  was given two guards after a build shipped stale data silently — a per-title
  `try`/`catch` so one bad title cannot discard the titles that already parsed,
  and a parser that throws when a response yields no sections rather than
  accepting it as a legitimate zero. Its siblings never got them. The US Code,
  Common Paper and ULC fetchers all looped over their items with an unguarded
  `await`, so a single title, template repo or act failing threw out of the
  fetcher and `runBuild`'s per-source catch dropped every record collected so
  far — one outage costing the whole source. The US Code and Common Paper
  parsers also read an error page served with HTTP 200 as "zero records". That
  combination is invisible to every gate: because these sources merge additively
  onto the curated baseline, nothing shrinks, so the shrinkage gate sees nothing
  — the existing entries are simply never refreshed again. All three now isolate
  per item, log the failure, and throw only when *every* item fails, which is the
  source being down rather than one item's outage.
- **The accuracy scoreboard no longer publishes a headline it told you it was
  excluding.** A rule with no κ-confident grading document is unmeasured — its
  only evidence is one unverified annotator — and the scoreboard's own note says
  such rules are "excluded from the headline". They were not: `totals` and the
  macro averages were accumulated before the low-confidence flag was even
  computed, so a single unverified annotator's one false positive could publish a
  headline precision of 0%. Unmeasured rules are still reported per-rule with
  their counts and the flag, so nothing is hidden — they just no longer move a
  number the evidence cannot support. The headline is counted from κ-confident
  documents only, rather than merely dropping the rules that have none:
  confidence is a property of the grading *document*, so a rule with one
  verified and one single-annotator document was treated as measured and had
  both documents' counts published, which narrowed the leak without closing it.
- **The v4 sub-domain classifier matches a feature as a word, not as a
  substring.** Feature phrases were tested with a plain `includes`, so every
  short entry fired inside ordinary English: "iso" (incentive stock option) on
  "adv**iso**ry", "cam" (common area maintenance) on "be**cam**e" and
  "**cam**paign", "cla" on "**cla**use" — a word in every contract — "safe" on
  "**safe**ty", and "rent" on "cur**rent**", "diffe**rent**" and "appa**rent**",
  which handed the real-estate sub-domain a spurious distinguishing hit on
  nearly every document. That is the same substring-versus-word-boundary defect
  as "lease" inside "release", and it both puts false evidence in the
  user-visible reasoning trail and can tip a borderline document into the wrong
  sub-domain. Matching is now bounded by lookarounds rather than `\b`, because
  many phrases begin or end with a non-word character ("501(c)(3)", "35 u.s.c.",
  "cc&rs") where `\b` asserts the opposite of what is wanted — and a trailing
  plural "s" still counts, because documents write "the Owners", "all rents" and
  "the ISOs" and the old substring test caught those for free. Rejecting them
  would have traded a false positive for a false negative on the routing layer:
  an adversarial pass found a lease written entirely in the plural falling off
  the real-estate sub-domain altogether. Zero golden churn.
- **Loading a second custom playbook before the first finished validating no
  longer leaves the first one active.** The picker's handler is async — it reads
  the file, then validates, which dynamic-imports the pipeline chunk — so two
  picks in flight raced and whichever resolved LAST won. Picking a slow playbook
  and then a fast one activated the slow one, and the next analysis silently ran
  the file the user thought they had replaced. Each pick now carries a
  generation and drops its result if a newer pick has started.
- **A test that measures asymptotics no longer fails on a busy machine.** The
  extractor fuzz gate exists to catch a super-linear blowup, but asserted a
  2000ms wall-clock budget against a slowest case that already takes ~1.5s idle
  — so it went red over scheduler contention rather than over a complexity
  regression. The budget is now 8000ms, which still fails a quadratic pattern
  decisively (50,000 characters squared is billions of operations) while
  surviving a parallel run.
- **A multi-word run-in heading is now read as a clause boundary.** The playbook
  clause scanner required a period immediately after the anchor stem, so it only
  recognized a single-word run-in heading. "Confidentiality Obligations." and
  "Limitation of Liability." — at least as common in commercial drafting as the
  bare form — were not boundaries, so the following clause's mutual language bled
  into this one and a genuinely one-way indemnity scored as mutual. A heading may
  now carry up to three further words. The bound is the safety margin: widening
  the heading token *narrows* the mutuality window, and clipping in the wrong
  place accuses compliant drafting of being one-way. An adversarial probe proved
  that necessary twice over — the first version of this fix read
  "Indemnification is reciprocal." as a heading and cut the clause off before its
  own "each party" tail, and the second, which rejected a sentence by looking for
  a finite verb in a stop-list, leaked on "Confidentiality obligations survive
  termination." because English verbs are unbounded and a denylist cannot be the
  primary signal. Capitalization is what actually separates a run-in heading from
  a sentence opening with the same word, so the scanner now reads the original-
  case text (it had only ever kept a lower-cased copy) and requires each further
  word to be capitalized, admitting the lowercase connectives a real heading
  carries ("Limitation **of** Liability."). The verb stop-list is kept as a
  second guard behind it. Both directions are pinned by tests.
- **`compare --dkb` now uses the directory it was given.** The flag was parsed
  and then dropped from the returned arguments, so a run that pinned an explicit
  DKB for reproducibility silently resolved the default one instead, with no
  error to say so. `compare`'s three free-form flags (`--playbook`,
  `--playbook-file`, `--dkb`) also read the next token blindly, so `compare a b
  --playbook --posture` took `--posture` as the playbook id and left posture off —
  the same class `analyze` grew its `requireValue` guard for.
- **A rule that crashes is no longer recorded as a rule that found nothing.** The
  rule contract is pure, so a `check()` that throws is swallowed and the run
  continues — but the execution-log entry it produced was byte-identical to the
  one a rule that ran and stayed silent writes. A rule failing on a real bug
  reported "screened, and clean" forever, with nothing anywhere in the run to
  contradict it. Both engine logs now carry an `errored` flag, omitted rather than
  `false` on the common path so no existing run's hash moves, and inside the hash
  for the same reason `ran` is: a run in which a rule crashed is a different
  analysis from one in which it passed.
- **An SSN written without separators is now detected and masked.** The
  pre-disclosure sweep matched only the dashed form, and while its bare-9-digit
  routing pattern does scan the same span, that pattern drops everything failing
  the ABA checksum — so an SSN copied out of a spreadsheet cell produced no
  finding at all and was handed to the opposing party unmasked. The scan's own
  dedup logic already treated the two spellings as one SSN, so the bare form was
  always meant to be reachable. It is reported at low confidence, because nine
  bare digits are genuinely ambiguous and the honesty contract phrases every hit
  as "spans match SSN format" rather than as a count of SSNs, and it is still
  gated on structural validity. A document carrying both spellings reports one
  SSN, at the higher confidence — and a bare run that satisfies the ABA checksum
  is left to the routing-number scan rather than being reported a second time as
  an SSN, since wire and ACH details are ordinary contract content.
- **A section heading is now cleaned the same way run text is.** The heading was
  the one text path that skipped `normalizeRunText`: it got the whitespace
  collapse and nothing else, so the soft hyphens and zero-width joiners Word and
  PDF inject mid-word survived in a heading while the identical string in a
  paragraph run was cleaned, and XML-illegal C0 control bytes rode a heading into
  the DOCX report. Both matter — the v4 classifier matches document families by
  reading headings literally, so an invisible U+00AD inside "Con[shy]fidentiality"
  silently lost the family match. Routing the heading through the same helper is a
  strict superset of the old behavior (that helper already ends in the same
  collapse), so a heading carrying no format or control character is byte-identical
  and no offset moves. Zero golden churn across the corpus.
- **A deadline is no longer computed from a date that does not exist.** `parseIso`
  range-checked day-of-month against a flat 31, so `2025-02-29` (not a leap year)
  and `2026-04-31` passed the "not a valid ISO date" guard, and the calendar
  arithmetic then rolled them silently forward into a real date. `computeDeadline`
  answered `resolved: true` with a deadline computed from a day the caller never
  named — the worst failure mode this module has, because the answer looks
  authoritative. The day is now checked against that month of that year using the
  leap-correct `daysInMonth` the file already defined. The same one-line gap sat in
  the holiday-calendar schema's own validator, where it let a seeded calendar
  declare a holiday on a date the Gregorian calendar has no room for.
- **The DKB build no longer loses three sources to one source's outage.** Making
  the eCFR parser throw correctly surfaced a bad response, but it threw straight
  out of the fetcher's title loop, so the per-source catch discarded every record
  already collected — one title's outage cost all four. Each title now fails on its
  own and the rest still contribute; only a run where *every* title fails throws,
  because that is the source being down rather than a per-title outage. Relatedly,
  an eCFR response carrying no sections is now treated as a failure rather than as
  a legitimate zero.
- **A DKB acknowledgment now expires with the thing it acknowledged.** Both gates
  keyed their acknowledgments on identifiers that said nothing about the content a
  human had actually reviewed, which made every acknowledgment a standing
  exemption. The staleness gate matched on `(node_id, citation)`, so dispositioning
  one cosmetic renumbering as "no substantive change" meant that citation never
  raised the gate again — the next real amendment would publish silently, which is
  precisely the event the gate exists for. The shrinkage gate matched on
  `(section, new_count)` with no record of what the count fell *from*, so an old
  disposition would bless an unrelated later regression that happened to land on
  the same number — a partial repeat of the incident the gate was built for. Each
  acknowledgment now names the version or the transition it reviewed
  (`fetched_hash`, `prior_count`), and an entry missing the field is dropped rather
  than treated as a wildcard, so a hand-written acknowledgment that omits it fails
  closed.
- **A clause opening is judged by its heading shape, not by one character.** The
  playbook clause scanner accepted any stem preceded by `.`, `;`, `:` or a newline,
  which was wrong in both directions. A semicolon joining two halves of one
  sentence — or separating items in a list — was read as a clause boundary, cutting
  a clause off before its own mutuality tail and reporting compliant drafting as
  one-way. And a numbered run-in heading ("4) Indemnification." … "5)
  Confidentiality.") has `)` before the stem, so the boundary was rejected, the two
  clauses bled together, and a genuinely one-way indemnity read as mutual. That is
  ordinary commercial drafting, not an edge case. The mutuality window is now
  clipped at clause *openings* rather than at topic mentions, so a neighbouring
  clause's mutual language no longer counts as this clause's.
- **A value-taking CLI flag no longer swallows the flag after it.** `analyze
  doc.txt --playbook --delivery` exited 0 with a clean report and no delivery scan:
  `--playbook` took the string `--delivery` as its playbook id and stepped over it,
  and because a forced playbook id that matches nothing falls back to auto-matching,
  the run silently used `generic-fallback` with no error and no warning. A gate the
  caller believes is enabled being quietly switched off is the worst thing this
  parser can do. The allowlist-validated flags already rejected a flag-shaped value
  as a side effect of validating it; the nine free-form ones now share a
  `requireValue` guard.
- **Rules that never ran are no longer counted as evidence the document is
  clean.** The comparison report's "no regression" number selected rules on
  `fired === false` alone — but the engine logs `fired: false` for a rule it
  *skipped*, using the identical entry shape it writes for a rule that ran and
  stayed silent. Rules never evaluated at all were being counted as evidence the
  document had been screened and come back clean, which is exactly the reassurance
  an attorney reads that number for and exactly what a skipped rule cannot support.
  The v4 execution log now carries the `ran` field the consistency log has had since
  it shipped, with the same semantics, and every consumer reads it.
- **Production QA reads a Bates range filename as a range.** A produced file named
  for a range was parsed as a single, corrupted number, and a range whose end is
  written as bare digits (inheriting the prefix from its start) failed the CI gate
  on a log that was in fact correct. A privilege-log row logging a single Bates id
  is also no longer dropped.
- **The shared sentence boundary no longer cuts at an abbreviation.** The rule
  that decides where a sentence ends was hand-copied seven times across the
  extractors and treated any period as a terminator, so "5:00 p.m." and "No. 5"
  split a sentence in two — and, worse, a suppression that widened the window let
  one finding report an unrelated figure from a merged neighbour. There is now a
  single `SENTENCE_END` in `extract/walk.ts`, keyed on the character that follows
  the period, and the clause boundary and the obligations splitter share the same
  abbreviation list rather than each carrying part of it.
- **Five extractor defects that produced phantom or missing entities.** A
  comma-suffixed party name registered twice; a two-column signature block
  registered "Jane Roe By: John Doe" as one party while a real signer was dropped by
  a field cap; a proviso was invented where none existed; and a venue clause went
  unread. Each fix is pinned by a test that fails against the old behavior.
- **A date sort in TEMP-002 is now a total comparator.** Two dates comparing equal
  were left in input order, so the same document could produce two different
  outputs — a determinism leak in the one product guarantee that must not have one.
- **The cross-document cap check reads the figure from whichever anchor carries
  it,** rather than taking the first anchor and, when that one held no figure,
  falling back to the very value it had just rejected.
- **The mutation harness now runs every suite that covers the code it mutates.**
  Its config listed only `x.test.ts` for a mutated `x.ts`, so sibling suites never
  ran and their kills went uncounted — which is why two features with weeks-old test
  suites had been recorded as entirely untested. Fixing the include list alone
  lifted the measured score with zero new tests. The scope guard now derives the
  list from each test file's imports rather than restating it, and the two suites
  that must be excluded are declared with reasons instead of silently missing.
- **A policy that expressly disclaims an AML/BSA clause is no longer scored as
  compliant.** A clause-presence rule reads the document for the words the
  required clause would use, so a policy that states "the Company performs no
  OFAC sanctions screening" satisfied every one of POL-013's presence patterns
  and the rule stayed silent — while a policy that merely never mentioned OFAC
  was flagged. The express disclaimer is the worse document, and under OFAC's
  strict-liability regime it is the one that must not be missed. Presence rules
  now accept a `denied_if` guard (built by the shared `expressDenial()` frames)
  that outranks the presence check and reports the denying sentence itself
  rather than "(clause absent from the document)". Wired into the six AML/BSA
  rules — POL-012 (five-pillar AML program), POL-013 (OFAC screening),
  POL-014 (SAR), POL-015 (CIP / beneficial ownership), POL-016 (CTR), and
  POL-017 (AML recordkeeping), each bumped to v1.1.0. The frames refuse to
  cross a conditional connective or a scope verb, so the compliant drafting
  that pairs a negation with the topic — "no customer shall be onboarded
  **without** OFAC screening", "this policy does not **apply to** OFAC
  screening by third parties" — is not read as a denial. Golden churn is
  `result_hash` only across all 99 v4 fixtures: zero finding-level changes.
- **An ordinary commercial MSA is no longer auto-detected as an unrelated v3
  document family.** A single weight-1 signal was enough to name a specific
  family and suggest its playbook, so a routine "maintain insurance with a
  carrier providing coverage" covenant detected a Certificate of Insurance, and
  a routine "does not infringe any trade secrets" IP representation detected a
  deep NDA. Separately, "Service Provider" — the ordinary vendor-role label in
  any MSA — scored weight 2 with no privacy content required, which tied with
  the "Master Services Agreement" title signal and won on declaration order:
  a plain MSA was routed to the CCPA service-provider playbook at 0.5
  confidence, above the module's own "faint" threshold, which would have
  switched on the entire US-state-privacy chip row. Naming a family now takes
  either a strong signal or two weak ones, and the vendor-role definition
  counts only as corroboration for a real privacy signal. A genuine CCPA
  addendum still detects at full confidence.
- **The pre-disclosure report no longer mis-decodes XML entities in recovered
  comment, tracked-change, and metadata text.** The decoder ran a chain of
  replacements with `&amp;` first, which decodes twice: file bytes `&amp;lt;` —
  the correct encoding of the four characters a reviewer typed as `&lt;` —
  became `&lt;` after the first step and then a live `<` after the second, so
  the report showed text the document did not contain. It now decodes in a
  single pass, consuming each entity exactly once.
- **Dropping a second document while an analysis is running no longer shows a
  report for the wrong file.** Nothing checked whether an analysis was already
  in flight, so a second drop started a concurrent pipeline; both finished and
  each replaced the dropzone with its own "complete" render, meaning whichever
  finished last won — not necessarily the file dropped last, since parse time
  varies by size and page count. A user could be reading a finished report for
  a different document than the one they just dropped, with no error shown.
  Analyses are now serialized: while one is running the zone keeps showing
  "analyzing" with the file it is working on, and further drops are ignored.
- **Four v3 rules no longer report the compliant clause as the violation it
  forbids.** The same defect class a prior sweep found across the v4 packs,
  audited in v3 for the first time: an `exclude_if` guard written as a literal
  "not" adjacent to the verb, so the drafting the rule's own recommendation
  asks for — phrased with "never", or with a fronted "under no circumstances" —
  slips past and trips the bad pattern. MSA-017 read "service credits shall
  NEVER be Customer's sole and exclusive remedy" as making them the sole
  remedy. MSA-024 read "venue shall never be in Delaware" — an explicit
  exclusion, i.e. alignment — as a governing-law/venue mismatch, and also
  missed the ordinary "shall not BE in" because it required "not" to sit
  directly before "in". DPA-036 read "the SOC 2 report shall never be provided
  in lieu of any audit right" as eliminating the audit. TRANSFER-003 read "the
  SCCs may never be amended" — a textbook Clause 2 non-derogation clause — as
  the modification Clause 2 forbids. Each fix is paired with a check that the
  genuinely bad clause still fires. Golden churn is `result_hash` only.
- **Quoted excerpts in the bundle DOCX and the comparison DOCX no longer
  corrupt non-BMP characters.** The surrogate-pair-safe `truncate` was fixed
  once in the shared DOCX helpers, but `bundle.ts` and `compare-docx.ts` each
  carried their own pre-fix copy, so every excerpt they quote — the audit-trail
  clause text, and each base/revised finding pair in a comparison — still cut
  between the two halves of an emoji or a CJK Extension B character and emitted
  U+FFFD where the character should be. Both now import the shared helper, and
  a new test scans the renderer sources so a future copy without the guard
  fails by name.
- **The definitions CSV export no longer lets a defined term open as a live
  spreadsheet formula.** Every other CSV writer routes through a shared field
  escaper that neutralizes formula injection (CWE-1236); `definitions.ts` had
  its own copy that quoted commas and quotes but omitted that guard. Defined
  terms are verbatim document text, so a term beginning `=`, `+`, `-`, or `@`
  executed on open in Excel or Sheets. It now uses the shared escaper.
- **A zip whose headers under-declare an entry's size is now rejected instead
  of silently handing back a fragment of the document.** `unzipSync` sizes each
  output buffer from the entry's declared `originalSize` and inflate stops when
  that buffer is full, so an archive claiming 10 bytes for an entry that really
  holds 10 MB extracted "successfully" as a 10-byte stub — the archive lied and
  nothing reported it. The post-inflate guard meant to catch this tested
  `byteLength > declared`, which by that same property can never be true: it
  was unreachable, and no test covered it. A streaming pass (fflate's `Unzip`,
  which takes no size hint) now measures the real inflated length, rejects any
  entry that out-runs its declaration, and aborts mid-inflate rather than
  expanding the whole stream first.
- **The express-denial sweep now covers every rule pack in the product.** The
  last three v3 families are done: MSA-001 (a supplier that does not indemnify
  against third-party IP infringement), MSA-016 (no service level applies),
  MSA-018 (a party barred from terminating for material breach), MSA-021 (no
  data return or portability on termination — the classic lock-in defect),
  ADDENDA-015 (AI subprocessors not disclosed), ADDENDA-016 (fine-tuning data
  not deleted on termination, so customer data persists in the model),
  NDA-D-001 (an NDA stating it provides no DTSA whistleblower immunity, which
  18 U.S.C. § 1833(b) confers by statute), and NDA-D-013 (confidential
  information need not be returned or destroyed). Rules whose required clause
  is itself a disclaimer, waiver, exclusion, or carve-out are left unguarded by
  design. Golden churn is `result_hash` only: zero finding-level changes.
- **A CCPA service-provider addendum or an SCC transfer that expressly
  disclaims its obligations is no longer scored as compliant.** Ten more rules
  guarded: USDPA-005 (same level of privacy protection), USDPA-007 (monitoring
  and oversight), USDPA-008 (consumer-request assistance), USDPA-009 (notice of
  inability to comply), USDPA-010 (subcontractor flow-down), and TRANSFER-004
  through TRANSFER-008 (SCC Clauses 8, 9, 11, 14, 15). USDPA-002/003/004 are
  deliberately unguarded with a test pinning them — their required clauses ARE
  prohibitions ("shall not sell", "shall not use for cross-context
  advertising"), so a denial frame would flag the compliant drafting. The SCCs
  needed a narrow local pattern: "does not apply to" is treated as a scope
  carve-out everywhere else, but Clause 2 makes the SCCs invariable, so
  disapplying a clause outright voids the transfer basis — while a genuine
  subset carve-out ("Clause 9 does not apply to sub-processors engaged before
  the effective date") still passes. Golden churn is `result_hash` only.
- **A GDPR DPA that expressly disclaims an Article 28(3) obligation is no longer
  scored as compliant.** Eight processor obligations now carry a `denied_if`
  guard: DPA-008 (confidentiality undertaking), DPA-009 (Art. 32 security
  measures), DPA-011 (data-subject-rights assistance), DPA-012 (Art. 32-36
  assistance), DPA-013 (deletion or return at end of services), DPA-014 (audits
  and inspections), DPA-015 (subprocessor prior authorisation), and DPA-017
  (subprocessor flow-down). DPA-007 is deliberately left unguarded with a test
  pinning it: "shall process personal data ONLY on documented instructions" is
  itself a restriction, and a denial frame would flag the required drafting.
  Golden churn is `result_hash` only: zero finding-level changes.
- **A HIPAA BAA that expressly disclaims an obligation is no longer scored as
  compliant.** The same defect the v4 packs had, found in the v3 layer's
  highest-stakes family and confirmed by probe: a BAA stating "Business
  Associate shall NOT report to the Covered Entity any use or disclosure of PHI
  not provided for by this Agreement" satisfied BAA-004's presence pattern and
  the rule stayed silent, while a BAA that never mentioned reporting was flagged
  critical. Seven rules now carry a `denied_if` guard — BAA-003 (safeguards),
  BAA-004 (incident reporting), BAA-005 (subcontractor flow-down), BAA-006
  (individual access), BAA-007 (amendment), BAA-008 (accounting of disclosures),
  and BAA-009 (HHS access to books and records) — and the finding reports the
  denying sentence rather than "(clause absent from the document)". BAA-002 is
  deliberately left unguarded and has a test pinning that: its compliant
  drafting IS a negation ("shall not use or disclose PHI other than as
  permitted"), so a denial frame would flag the required language as its own
  violation. `expressDenial` moved to the shared rule helpers so the v3 packs
  can use it without pulling v4 code into their bundle chunk. Golden churn is
  `result_hash` only across all 340 affected fixtures: zero finding-level
  changes.
- **The shipped `dist/index.html` no longer carries a duplicate `crossorigin`
  attribute.** Vite already emits a bare `crossorigin` on the module script and
  its modulepreload links; the SRI plugin appended `integrity="sha384-…"
  crossorigin="anonymous"` unconditionally, so both tags shipped with the
  attribute twice — invalid HTML, and if the two values ever disagreed only the
  first would take effect. The plugin now strips an existing `crossorigin`
  before adding its own, exactly as it already did for `integrity`. Every
  existing SRI assertion passed throughout, because `[^>]*crossorigin=
  "anonymous"` matches a tag carrying two of them; the new guard parses out
  attribute names and asserts none repeats.
- **Seven more presence rules now catch the clause their document expressly
  disclaims.** Same defect class as the AML rules above, extended across five
  packs after a two-agent audit of all sixteen: HC-015 (a HIPAA authorization
  that states it "cannot be revoked" or "is irrevocable"), EMP-016 (an ADEA
  waiver that bars revocation, which voids the waiver under OWBPA), EMP-021 and
  SET-008 (an agreement barring the employee or claimant from communicating with
  the SEC / EEOC / NLRB / DOL, unlawful on its face under SEC Rule 21F-17),
  PRV-004 (a cookie notice stating consent "may not be withdrawn", contrary to
  GDPR Art. 7(3)), and PRV-029 / PRV-032 (a vendor questionnaire stating data is
  not encrypted or that no incident-response plan exists). Each is paired with
  compliant decoys that must stay silent — "strictly necessary cookies do not
  require consent", "nothing in this Agreement prevents Employee from
  communicating with the SEC", "withdrawing consent does not affect the
  lawfulness of prior processing". Rules whose own presence patterns are
  themselves phrased as a negation were deliberately left alone. Golden churn is
  `result_hash` only: zero finding-level changes.
- **Five more presence rules across banking, governance, and real estate now
  catch the clause the document expressly denies.** BNK-015 (an agreement
  stating no security interest is granted, so attachment fails under UCC
  § 9-203 and there is no enforceable lien), BNK-013 (a consumer loan stating
  Regulation Z disclosures are not provided), GOV-069 (an LLC agreement
  designating no Partnership Representative, leaving the IRS to appoint one the
  partners cannot control), and RE-048 / RE-056 (an SNDA where Tenant will not
  attorn, or an assignment where Assignee assumes no lease obligations). Each is
  paired with compliant decoys that must stay silent, including the "does not
  apply to" scope carve-outs these documents use constantly. Rules whose
  required clause is itself a waiver or a prohibition (INS-012 waiver of
  subrogation, GOV-072 inurement, RE-046 subordination) were deliberately left
  alone: there the negative IS the compliant drafting. Golden churn is
  `result_hash` only.
- **Nine more presence rules across the remaining seven packs now catch the
  clause the document expressly denies**, completing the sweep of all sixteen
  v4 packs: MNA-031 (a merger agreement declaring appraisal rights unavailable,
  contrary to DGCL § 262), MNA-016 (selling stockholders subject to no
  non-compete, so the buyer paid for unprotected goodwill), EQT-049 / EQT-052
  (investors given no demand registration or pro rata participation right),
  EST-032 (a power of attorney that terminates on incapacity and states it is
  not durable — the opposite of the instrument's purpose), EST-039 (a premarital
  agreement reciting that no financial disclosure was exchanged, the leading
  ground for invalidation), IPL-014 (a licensor exercising no quality control,
  which documents a naked license and risks abandonment of the marks), CON-006
  (a contractor who will not indemnify the owner), and REG-030 (an offering
  memorandum disclosing no conflicts of interest). Golden churn is `result_hash`
  only across all 99 v4 fixtures: zero finding-level changes.
- **The party-role picker no longer scrolls the page sideways on a narrow
  phone.** A dropdown never wraps its option text and a `fieldset` defaults to
  `min-inline-size: min-content`, so a party role long enough to exceed the
  viewport — the names come from a user-supplied playbook — widened the fieldset
  and pushed the whole page into horizontal scroll (114 px of overflow at
  320 px, in both themes). Both the fieldset and the control now carry
  `min-width: 0`. This was invisible because the panel's a11y/responsive spec
  asserted against a hand-written copy of the component's markup that predated
  the role picker entirely: the one control in the panel had never been
  axe-scanned or overflow-checked. The spec now covers that sub-state, and a new
  drift guard reads `src/ui/playbook-panel.ts` and fails if the component emits
  any `playbook-*` markup no fixture covers, so the fixtures cannot silently
  fall behind again. `tests/e2e/landing-responsive-a11y.spec.ts` also dropped a
  `<script>`-stripping step that had quietly become a no-op once the inline
  theme-init script was removed from `site/index.html`.
- **A build missing the pdf.js worker now fails instead of shipping broken PDF
  analysis.** The worker was located at a hardcoded
  `<repo>/node_modules/pdfjs-dist/legacy/build/…` path and the copy into `dist/`
  was guarded by `existsSync`. Wherever npm had actually put the package —
  a hoisted workspace, a git worktree whose dependencies live in the parent
  checkout — the guard quietly found nothing and the build emitted a `dist/`
  with no `pdf-worker/` at all. Since `src/ingest/pdf.ts` pins
  `GlobalWorkerOptions.workerSrc` to `/pdf-worker/pdf.worker.min.mjs`, every PDF
  dropped into that build failed on a 404, with nothing in the build log to say
  so. Found by running the Playwright suite, where both PDF specs in
  `privacy-interception.spec.ts` failed while the DOCX spec passed. The path is
  now resolved through Node (so it is found wherever it lives) and a missing
  worker aborts the build with an explicit message, the same way
  `assertShippableDkb` refuses to ship an empty DKB. Two tests pin the
  resolution so a `pdfjs-dist` upgrade that moves the worker fails at test time
  rather than at runtime. All 45 e2e specs pass.
- **Three v3 report renderers no longer corrupt non-BMP characters, and "1 days"
  reads "1 day".** `transfers.ts`, `subprocessor.ts`, and `consistency.ts` each
  carried a private copy of `truncate` that was a *pre-fix* duplicate of the one
  in `docx.ts`: it cuts UTF-16 surrogate pairs in half, and the lone high
  surrogate becomes a U+FFFD replacement character when the DOCX is packed to
  UTF-8 — so an excerpt corrupts exactly at an emoji or a CJK Extension B
  character. Separately, `subprocessor.ts` and `insurance.ts` interpolated
  `"${n} days"` with no pluralization. `truncate` and `plural` now live once in
  `v3/_dx.ts` and every caller — including `docx.ts` — imports them from there,
  so the guard cannot drift out of sync again. This layer is still dormant (the
  `v3` argument to `buildDocxReport` is always undefined), so the fix is latent
  and carries zero golden churn.
- **A custom playbook's `result_hash` now covers the evidence, not just which
  rules fired.** It was computed over `{rule_id, severity, section_id,
  citation_provenance}` only, so the same rule firing on completely different
  violating text at a different offset in the same section produced a
  byte-identical hash — a consumer using it to answer "did the findings change"
  saw no change when the evidence had changed entirely, which is the exact
  contract the module's own "changes the result_hash when findings change" test
  asserts. The clause text and document position are now part of the hashed
  payload. Scope: this is the standalone `CustomPlaybookRun.result_hash`; the
  engine-level `run.result_hash` from `runWithCustomPlaybook` already hashed the
  full findings and was never affected. No golden carries this value and no test
  pinned a literal, so there is zero churn.
- **The handoff report no longer credits one author with another's words.** The
  forward text scans in `parseComments` / `parseRevisions` read a flat character
  window from each element's opening tag without regard for where that element
  ended. An element carrying no text of its own — an empty comment, a `w:del`
  holding only a drawing — walked past its own close and picked up the **next**
  element's text. In a document where Alice leaves an empty comment and Bob
  writes "Redact the penalty," the report attributed Bob's sentence to Alice as
  well, which is exactly backwards for a screen whose whole job is to say who
  wrote what before a document goes out. The scan is now clamped to the
  element's own closing tag (matched whole, so `</w:del>` does not also hit
  `</w:delText>`), and a text-free element honestly reports no excerpt.
- **The sensitive-data scan no longer merges distinct values that share a mask.**
  Dedup keyed on the *masked* string, but masking reveals only a suffix — so
  `alice@example.com` and `adam@example.com` both mask to `a***@example.com`,
  and `123-45-6789` and `234-56-6789` both mask to `***-**-6789`. The second
  value silently vanished from both the count and the evidence, under-reporting
  how much sensitive data the document carried; every revealing type (SSN, EIN,
  card, routing, phone, email) had the same collision. Dedup now keys on the raw
  value with separators stripped and case folded, so the same value written two
  ways still counts once while genuinely different values each count. Raw values
  are used only as set keys and never leave the function — the output still
  carries masks alone.
- **CI is green again.** Every one of the last 100 runs — as far back as the API
  lists (2026-08-08) — failed at `npm run format:check` on 18 committed files
  that had drifted out of Prettier's formatting. Because the job runs under
  `bash -e`, the steps after it (`npm run coverage`, `npm run build`) never
  executed on any of those runs, hiding a second failure: the custom-playbook
  corpus harness in
  [`tests/integration/custom-playbook-harness.test.ts`](tests/integration/custom-playbook-harness.test.ts)
  analyzes every `.docx` fixture on the default 5 s budget, which fits a plain
  `npm run test` but times out under coverage's v8 instrumentation. Both are
  fixed; the reformat is whitespace-only.
- **`analyze --fail-on` no longer accepts a value it cannot enforce.** The flag
  is the CI gate, but an unrecognized severity was cast straight to `Severity`,
  leaving `SEVERITY_RANK[failOn]` undefined and making the gate comparison
  always false. `vaulytica analyze contract.docx --fail-on critcal` (a typo)
  therefore exited **0** on a document whose findings would otherwise have
  exited 2 — a CI job that believed it was gating on critical findings passed
  everything, silently, with nothing printed. A bad or missing value is now a
  usage error naming the accepted values, matching how `compare` has always
  handled the identical flag. Four regression tests in
  [`tools/cli/run.test.ts`](tools/cli/run.test.ts) cover an unknown value, a
  near-miss typo, the flag with no value, and a case variant.
- **The dev server no longer serves files outside its mounted directories.**
  `serveExtras` mounts `playbooks/`, the latest DKB build, and the pdf.js worker
  at virtual URL prefixes and reads them off disk itself — so Vite's own
  `server.fs.allow` never saw those requests, and `resolve()` followed `../`
  segments straight out of the mount. Against a live `npm run dev`,
  `GET /playbooks/../../../../../../../../../../../etc/hosts` returned the real
  file; `npm run dev --host` was an arbitrary-file-read hole on the local
  network. The path resolution moved into an exported `resolveMountedFile` that
  rejects anything not contained by its mount root (before any `existsSync`
  probe, so responses can't be used as an existence oracle either), with 10
  tests in
  [`tests/integration/dev-mount-traversal.test.ts`](tests/integration/dev-mount-traversal.test.ts)
  — including the sibling-directory prefix trap (`served-evil` vs `served`).
  Dev-only; no production surface was affected.
- **`npm run dev` serves a working app again.** `vite.config.ts` sets
  `root: "site"`, and `site/index.html` loaded the UI with
  `<script type="module" src="../src/ui/main.ts">`. A production build resolves
  that out-of-root path fine, but the dev server does not rewrite it: the browser
  requested `/src/ui/main.ts`, the SPA fallback answered with `index.html` as
  `text/html`, and the module was refused on MIME type — so `npm run dev` rendered
  the full marketing page with no application behind it (no drop handling, no
  theme toggle, no DKB footer), and nothing in the build or the suite noticed.
  The tag now points at `site/main.ts`, a one-line in-root shim that imports the
  real entry, which resolves under the dev root and leaves the production output
  unchanged (still a single `main-*.js` entry chunk of the same size). Verified in
  a real browser: the whole `src/ui/*` module graph now loads over the dev server
  and the page boots. New guard in [`site/entry.test.ts`](site/entry.test.ts)
  (4 tests) pins the entry tag to a root-absolute path that exists inside the Vite
  root and still reaches `src/ui/main.ts`.
- **The clause classifier is now immune to a stateful-regex hazard in its pattern
  overlay.** The overlay tests each category pattern with `regexp.test(text)` — a
  boolean "does this clause match" — but a pattern compiled with the `g` (or `y`)
  flag is stateful: its `lastIndex` advances between calls, so a global pattern
  would match the first paragraph, silently skip an identical second paragraph, and
  match the third, misclassifying alternating clauses. The pattern compiler now
  strips `g`/`y` from the externally-supplied flag set (the classifier reads its
  patterns from the DKB), so the overlay is a pure membership test regardless of
  what flags the data carries. The shipped DKB patterns use only `i`/`is`, so
  classification output is unchanged on the golden corpus (zero churn).
- **A mutual obligation with a two-party compound subject is now attributed to
  "the parties," not to whichever party is named last.** "The Provider and the
  Customer shall each bear their own costs" states a duty both parties share, but
  the obligor resolver keyed on the tail of the subject and returned "Customer" —
  so OBLI-002 could read the shared obligation as one-sided (a false asymmetry
  finding). When the "and"-joined segments of the subject each resolve to a known
  party or role, the obligation now resolves to "the parties," the same value the
  resolver already gives "each party" / "either party." A subject where only one
  side is a party ("The Provider and its subcontractors shall …") is unchanged, so
  a genuinely one-party duty is not collapsed to mutual. No corpus fixture carries
  a two-party compound obligor, so the golden corpus is byte-identical (zero churn).
- **The courts-first venue reader now recognizes a bare jurisdiction and the "of
  the State of" preposition.** "The state and federal courts located in Delaware
  shall have exclusive jurisdiction" and "The courts of the State of California
  shall have exclusive jurisdiction" went unread: the pattern could only end the
  captured locality at punctuation, so with the forum verb sitting directly after
  the locality (no "City, State" comma) the capture ran past it, swallowed "shall
  have …", and the clause was dropped — and the "of the State/Commonwealth of"
  phrasing was not among the recognized prepositions at all. A missed venue makes
  CHOICE-003 assert "no forum clause" on a document that has one. The locality now
  also ends before a "shall have" / "have" forum verb, and "of the
  State/Commonwealth of &lt;Name&gt;" joins "located in" / "sitting in" — gated to the
  State-of scaffold so "courts of competent jurisdiction" and "courts of Appeals"
  are not swept in. The existing "City, State" comma form is unchanged (the comma
  still terminates the capture first); no corpus fixture uses either new form, so
  the extracted stream is byte-identical on the golden corpus (zero churn).
- **The definition extractor now reads a quoted defined term with an internal
  abbreviation period.** A period-bearing abbreviation is a common defined term in
  tax and securities agreements — `"U.S. Person" means …`, `"U.K. Subsidiary"
  means …`, `"No. 5 Warehouse" means …` — but the primary inline `"Term" means …`
  matcher (and the aliased `"X" or "Y" means …` form) used a term character class
  that omitted the period, so the term stopped at the first `.`, the closing quote
  never lined up, and the whole definition was dropped. STRUCT-006 then reported the
  term as used-but-undefined even though the document plainly defines it. The two
  matchers now carry the same quoted-term class (`.` `/` `'`) their nine sibling
  patterns already use; the term is quote-bounded, so a period can only sit between
  the quotes. The bare (unquoted) glossary matcher — `U.S. Person means …` under an
  Interpretation heading — takes the same period, safely, because it only runs inside
  a Definitions/Interpretation section. No corpus fixture defines a period-bearing
  term this way, so the extracted stream is byte-identical on the golden corpus (zero
  churn).
- **The party extractor no longer truncates a multi-party "among" preamble at the
  first abbreviation period.** A three-or-more-party preamble written the way real
  merger, credit, and joint-venture agreements write it — "by and among Alpha Inc.,
  Beta Corp., and Gamma Ltd." — captured its member list with a non-greedy match
  that stopped at the FIRST period, so the period inside "Inc." ended the list and
  every party but the first ("Alpha Inc") was dropped. The list body now absorbs an
  in-abbreviation period (before a comma, another letter, a role parenthetical, or an
  "and" connector) while a real sentence-ending period still terminates it, so the
  full roster is read — with member roles ('Acme Inc. ("Buyer"), …') and in ALL-CAPS
  preambles. A member that is nothing but an entity-type suffix ("L.P." / "LLC" split
  off a comma-separated "Alpha Holdings, L.P.") is dropped rather than surfaced as a
  party. This feeds STRUCT-001 (party identification) and every party-tallying rule
  (RISK-002); no corpus fixture uses an "among" preamble, so the extracted stream is
  byte-identical on the golden corpus (zero churn).
- **CITE-001 no longer calls New York's modern reporter series "malformed."** The Indigo
  Book reporter table listed only the bare `N.Y.`, so any citation to the second/third
  series (`5 N.Y.2d 100`, `1 N.Y.3d 5`) or the New York Supplement (`850 N.Y.S.2d 12`,
  `40 N.Y.S. 9`) — the reporter nearly every New York appellate cite actually uses — has a
  period and matches the case-citation shape, but failed the known-reporter check and drew
  a false malformed-citation accusation in filing briefs. The five modern New York forms
  (`N.Y.2d`, `N.Y.3d`, `N.Y.S.`, `N.Y.S.2d`, `N.Y.S.3d`) are now in the table, exactly as
  the earlier `F.4th` gap was closed.
- **The date extractor now recognizes seven more named date anchors.**
  `Separation`, `Settlement`, `Distribution`, `Conversion`, `Exercise`, `Issuance`,
  and `Record` join the curated anchor-alias vocabulary, so the reference points that
  severance ("within 21 days of the Separation Date"), securities ("two days after the
  Settlement Date"), convertible-instrument ("five years from the Issuance Date"), and
  distribution ("holders as of the Record Date") clauses date relative deadlines from
  are surfaced as named-anchor date references instead of going unread. STRUCT-002 keys
  only on "Effective Date", so this does not affect the effective-date check; no fixture
  cites any of the new terms, so the extracted stream is byte-identical (zero golden churn).
- **The date extractor now recognizes "the Anniversary Date" as a named anchor.**
  `Anniversary` joins the curated anchor-alias vocabulary (Effective, Closing,
  Commencement, …), so a bare reference like "notice is due before the Anniversary
  Date" — the reference point renewal and fee-escalation clauses date from — is
  surfaced as a named-anchor date reference instead of going unread. STRUCT-002 keys
  only on "Effective Date", so this does not affect the effective-date check.
- **CITE-001 no longer calls the Bankruptcy Reporter "malformed."** `B.R.` — West's
  Bankruptcy Reporter, cited in nearly every bankruptcy brief — was missing from the
  reporter table, so `123 B.R. 45` matched the case-citation shape but drew a false
  malformed-citation accusation. Added to the table; the bare-acronym prose form
  (`the B.R. department`) is still not read as a citation.
- **The negotiation-ladder deal-value reader now recognizes the "equal to" /
  "in the amount of" equality phrasings.** A labeled total written as "aggregate
  purchase price **equal to** $5,000,000" or "total contract value **in the amount
  of** $2,500,000" fell through the connector check, so the size-band ladder
  dropped silently to its base default instead of the stated total. These are
  pure equality connectors (they assert the amount IS the labeled total), added
  alongside the existing "is" / "of" / "equals"; a subtraction or exclusion clause
  ("less the holdback") still yields no deal value, honesty-first. The "sum"-worded
  parallels — "in the sum of $X" and "in a sum equal to $X" — now resolve too.
- **The headless CLI can now actually analyze DOCX files — `vaulytica analyze contract.docx`
  was broken end-to-end in Node.** Two Node-only failures, both masked because the test suite
  runs under happy-dom (browser-build mammoth + a built-in `DOMParser`) while no test ever
  exercised the real CLI path in plain Node: (1) mammoth resolves to its Node build, whose
  `openZip` accepts only `path`/`buffer`/`file` and rejected the `{ arrayBuffer }` we passed
  with "Could not find file in options"; the DOCX ingest now also supplies a Node `Buffer`
  when the runtime has one (the browser build still reads `arrayBuffer`). (2) `parseDocxHtml`
  needs a `DOMParser`, which Node lacks; the CLI now lazily registers happy-dom's
  window-bound `DOMParser` the first time a binary document is ingested — the same DOM engine
  the suite validates DOCX parsing against, so the headless run stays byte-identical to the
  browser. `happy-dom` moved from dev to runtime dependencies for this. A new
  `tools/cli/api-docx-node.test.ts` (`@vitest-environment node`) pins the whole path so it
  cannot silently regress.
- **`vaulytica verify` now works for DOCX/PDF reports, not just text.** The verifier read the
  original document as UTF-8 text and re-hashed it, so a binary input always reported a
  spurious "the input document differs" and never reproduced. A new
  `verifyReproducibilityFromFile` re-ingests the original by extension through `analyzeFile`
  (binary bytes for DOCX/PDF, UTF-8 for paste), matching how the report was produced; the
  text-based `verifyReproducibility` is retained for in-memory callers.
- **Corrected the stale per-category rule-count comments in the launch registry.**
  The section comments in `src/engine/rules/index.ts` (e.g. `// Personnel — 4`,
  `// Risk allocation — 14`) had never been updated as rules were added, while the
  arrays themselves shipped the current counts (Personnel 9, Risk 17, …). They summed
  to 87 against the 115 rules actually exported. The comments now read the true
  per-category counts (Structural 19, Financial 9, Temporal 12, Obligations 9,
  Risk 17, Choice & venue 12, Termination 9, IP & data 10, Personnel 9, Dark 9 = 115),
  matching the breakdown the README publishes. No runtime behavior changed.
- **Added a regression guard so the per-category breakdown cannot silently drift again.**
  `src/engine/rules/all-rules.test.ts` now pins each category's rule count (by id prefix)
  to the documented numbers and asserts they sum to `LAUNCH_RULES.length` — the same
  integrity-guard discipline as the docs-link, scoreboard, and case-sensitivity tests.
  This is exactly the check whose absence let the comments drift unnoticed.
- **Corrected the stale launch rule count on the public landing page.** `site/index.html`
  still advertised "112 rules at launch" — the pre-v9 count — while the always-on launch
  set has been 115 since v9 added its three execution-readiness reconciliations
  (`LAUNCH_RULES.length === 115`, test-pinned). The "What I check" copy now reads 115, so
  the per-tier breakdown sums to the 1,065-rule catalog the scoreboard reports
  (115 launch + 220 v3 + 730 v4). The DKB-/version-independent "1,000+" claims were already
  correct and are unchanged.
- **Refreshed two stale present-tense counts in `tests/integration/rule-completeness.test.ts`
  doc comments** — "1,062 rules" → 1,065 (current catalog) and "the 112 rules that run on
  every document" → 115 (current launch set). The dated 2026-06-05 baseline narrative is
  left as the point-in-time record it documents. Comments only; no assertion or floor changed.
- **Corrected a stale test count in the README "Build & verify" block.** The `npm run test`
  comment still read "3,051 tests" while the suite — and the header badge — report 3,616.
  The badge was already current; only the inline command comment had drifted.
- **Regenerated the accuracy scoreboard, which had drifted to a stale catalog count.**
  `tools/accuracy/scoreboard.json` and `SCOREBOARD.md` (the spec-v5 §10 published trust
  artifact) still reported `1062 rules`; the live engine ships `1065`. `npm run accuracy`
  re-stamped the count and `scoreboard_hash`. No metrics changed — the corpus is still the
  honest empty seed, so precision/recall stay unpublished by design.
- **Added a regression guard so the scoreboard cannot silently desync again.**
  `tools/accuracy/scoreboard-current.test.ts` pins the committed scoreboard's
  `catalog.rules` / `catalog.playbooks` to the live engine count (the same integrity-guard
  discipline as the docs-link and case-sensitivity tests), with a one-line fix in the failure
  message: re-run `npm run accuracy`. It deliberately pins only the catalog counts, not the
  hash or the precision/recall metrics, which legitimately move with the corpus.
- **An absence finding no longer reads as a quotation in the Word report.** Rules
  that fire on what a contract *lacks* record a zero-length excerpt whose text is
  a marker the rule wrote — `(no IP-ownership clause)` — not words from the
  document. The report printed that under an excerpt label at `characters 0–0`,
  which read as a quotation of words the contract never contained. Such findings
  now state plainly that they are about an absence, and their index row reads
  `absent — nothing to quote` instead of a meaningless span.
- **The landing page's document-type claims can no longer go stale.** The FAQ
  advertised "twelve playbooks" against 145 shipped. The page now lists every
  shipped playbook by name and states the count from one place, both pinned to
  `playbooks/` by `tests/integration/site-document-types.test.ts`; the hero's
  rule total is pinned to the live rule arrays, and the static drop-zone caption
  is pinned to the copy the app repaints it with on boot.

### Changed
- **The front page is down to the tool and the list.** The headline states what
  this is in the words people search for — *free legal contract reviewer,
  deterministic, no AI* — above the drop zone and a four-item facts line. Below
  it, one section: the full index of all 145 document types, grouped by practice
  area. Everything else an attorney may want to audit — what it checks, how it
  works, why there is no AI, what it will not do, privacy and how to verify it,
  court and ethics compliance, sources, and the FAQ — is folded into labelled
  disclosures: present in the markup for search engines, one click away for
  readers, and out of the way of the drop zone.
- **The Word report leads with proof.** Every finding now names the rule and
  version that fired inline (`CRITICAL · RISK-004 v1.2.0`), then shows its
  evidence before its argument: the contract text behind the finding, set as an
  indented quotation under the exact character range it matched at
  (`§ 7.2, characters 12,433–12,590`), with offsets grouped so they can be read.
  A finding produced by a custom playbook says so on its own line, so "our
  standard flagged this" is never mistaken for "Vaulytica's catalog flagged this".
- **A Findings Index opens the report.** One row per finding, in report order —
  severity, rule and version, title, and location — so a reviewer can triage the
  whole run before reading a word of prose. A pure projection of the findings the
  engine already produced: it computes nothing and cannot disagree with the
  sections below it. Absent when nothing fired.
- **Empty severities cost a line, not a page.** "No critical findings" used to
  take a heading and a full sheet of paper each, and three of them could stand
  between the cover and the first real finding. They now collapse into one
  closing line that points at the Audit Trail.

### Security
- **Cleared three high-severity advisories via `npm audit fix` (semver-compatible, no
  `package.json` change).** `pdfjs-dist` 6.0.227 → 6.2.108 closes GHSA-hq66-cqwq-w95j
  (arbitrary JavaScript execution when opening a malicious PDF) — the most relevant here,
  since document ingest parses user-supplied PDFs; `js-yaml` 4.3.0 → 4.3.1 closes
  GHSA-5p4m-2wfm-xmqj (quadratic CPU on `!!omap` resolution); `nanoid` 3.3.16 → 3.3.18 and
  5.1.11 → 5.1.16 close GHSA-28wg-ghj8-5hjv / GHSA-2v37-7h3g-55p8 (non-secure generators
  can loop indefinitely on a zero/negative size). Only `package-lock.json` changed; the full
  suite and production build pass unchanged, and `npm audit` reports 0 vulnerabilities.
- **Bumped the transitive `ws` dependency 8.20.1 → 8.21.0 to clear GHSA-96hv-2xvq-fx4p** (a
  WebSocket memory-exhaustion DoS, high severity). `ws` is pulled in only by `happy-dom`, the
  vitest test environment — it is a dev/test-only dependency and never reaches the shipped
  browser bundle, so production was never exposed. `npm audit` is now clean (0 vulnerabilities).
  The same `npm install` re-synced the `package-lock.json` root version field, which had drifted
  to `9.4.0`, back to the `package.json` version (`9.41.0`).

## [9.41.0] — 2026-06-24 — Document-free exposure matrix / the per-front × per-round floor-state grid every other axis collapses (spec-v44)

### Added
- **A `coherence-matrix` headless subcommand — the raw *per-front × per-round* floor-state grid every
  other posture axis collapses, the first *non-reduction* in the family.** Every `coherence-*` reading
  from v16 to v43 takes the same N-round archive and *reduces* it to a scalar: v22 (`coherence-breadth`)
  collapses each round (column) to a below-floor count; v24 (`coherence-volatility`) collapses each
  front (row) to a crossing count; v28/v40 to a latency or a mean; v35/v42 to an edge set and its
  transitive closure. None of them emits the grid *itself* — the full two-dimensional object whose cell
  `(front, round)` is that front's binding-floor standing in that round (`below` the acceptable floor,
  `above` it, or `unstated`). v44 is that grid: a posture **heatmap** a dashboard can render and a
  spreadsheet can pivot, the raw substrate behind every scalar the family computes. This is a missing
  **shape**, not a missing reduction — every prior axis is O(fronts) or O(rounds) scalars; the matrix is
  the O(fronts × rounds) object they all collapse. Per front: the per-round `cells[]` (the raw row),
  `below_rounds`, `stated_rounds`. Per round: `below_fronts`, `stated_fronts`, and `blackout` (≥ 1 front
  stated and *every* stated front below floor). Plus the whole-grid `cell_counts`, the `blackout_rounds`
  list, and `has_blackout` (the gate verdict). The markdown render is a terminal heatmap (`▓` below
  floor, `░` at-or-above, `·` unstated, `*` marking each blackout column). It reads the same
  `weakest_tier` binding floor v22/v24 already read — no new posture math. (`src/report/coherence-matrix.ts`,
  `tools/cli/coherence-matrix.ts`.)
- **A `--fail-on-blackout-round` CI gate (exit 2), on a whole-grid pathology no reduction poses.** It
  fires when any round is a **blackout** — at least one front stated and *every* stated front below the
  acceptable floor at once, the deal's worst cross-section, the moment no front held the line. "Every
  stated front" is a structural all-quantifier, not a threshold knob, so the gate is tuning-free.
  Distinct from v22's `widened` gate (a *trend* between two endpoint counts): a deal can black out in
  round 1 and recover (not widened), or widen from one to three of five fronts without ever reaching a
  full column (no blackout) — the two verdicts are independent.

### Notes
- **Honest by construction (spec-v10 §3).** An unstated front-round is `unstated`, never `below`; a
  round in which no front is even stated is never a blackout (a blackout needs at least one stated
  front, all of them below). The denominator each round is `stated_fronts`, never the front count.
- **Deterministic & namespaced.** The report carries a `matrix_hash` (SHA-256 over the canonical grid —
  each front's `dimension` and `cells` alone; the per-round summaries, cell tally, and blackout list,
  all fully determined by the cells, are omitted), apart from every prior hash. Same N artifacts in the
  same order → identical bytes.
- **Purely additive.** A new subcommand and one pure module that reads the same binding floor v22/v24
  already read, through the shared `verifyCoherenceSequence` loader (unchanged). No existing source
  file's behavior changes; every existing command's output and golden is byte-for-byte unchanged; the
  report stays *derived* (no new on-disk format). The posture archive is now read on **twenty-six**
  orthogonal axes (thirty-three CLI commands). Full design in [`docs/spec-v44.md`](docs/spec-v44.md).

## [9.40.0] — 2026-06-24 — Document-free recovery chain / the transitive closure of v37's pairwise recovery-order relation, the recovery mirror of v42 (spec-v43)

### Added
- **A `coherence-recovery-chain` headless subcommand — the *transitive closure* of v37's pairwise
  recovery-order relation, the *recovery mirror* of v42.** v37 (`coherence-recovery-order`) reads each
  *pair* of fronts in isolation — when both *recover* (climb back at-or-above the acceptable floor),
  does one consistently recover *first* (and so the other *last*, the laggard)? It never composes the
  pairs, so two facts a deal lead wants stay hidden: the **chain** (Cap recovers before Term, Term
  before Indemnity, so Indemnity is restored *after* Cap *through* Term — the deal's *tailwater*, the
  front exposed below the floor longest of all — even with no direct Cap→Indemnity edge), and the
  **cycle** (Cap recovers before Term, Term before Indemnity, Indemnity before Cap — three clean
  pairwise orders that cannot be globally ranked, a Condorcet cycle no pairwise read can detect). v43
  reuses `computeCoherenceRecoveryOrder` **unchanged** (the join pattern v38/v40/v41/v42 use), builds
  the directed graph whose edges are exactly v37's strict-majority `leading` pairs (`first_recoverer →
  last_recoverer`), and computes its transitive closure. Per front: the sorted
  `recovers_before_directly` (direct out-neighbours), the transitive `reach` and `recovered_before_by`,
  whether it sits on a cycle (`in_cycle`), and a `class` (`source` / `relay` / `sink` / `cyclic` /
  `isolated`); plus the deal's `tailwater` (the greatest-`recovered_before_by` sink — the front
  restored last of all), `max_lag`, `edges` (= v37's `leading` tally, by construction), `acyclic`, and
  `cyclic`. Where v42 names the *headwater* (the front to watch first), v43 names the *tailwater* (the
  front exposed longest) — the two transitive reads the two directions of a floor crossing admit.
  Introduces no new crossing/ordering math — it is a reachability fixpoint over the same recovery-order
  edges v37 already derives. (`src/report/coherence-recovery-chain.ts`,
  `tools/cli/coherence-recovery-chain.ts`.)
- **A `--fail-on-recovery-cycle` gate** — exits 2 when the recovery-order relation contains a directed
  cycle: three or more fronts each recovering above the floor first over the next in a loop, so no
  single restoration order ranks every front. A directed cycle either exists or it does not — a pure
  boolean over the integer-derived edges, so the gate inherits no knob. It is the *transitive* verdict
  v37 structurally cannot pose: every pair on the loop is individually `leading` to v37, so the
  intransitivity is undetectable per-pair. *Distinct from* v37's `--fail-on-lagging-recovery` (the
  *presence* of a stable laggard; v43 flags the *incoherence* of the composed restoration order
  instead).
- **`vaulytica.posture-recovery-chain.v1` report schema** and an integer-exact `recovery_chain_hash`
  (over the canonical per-front set — the front, its sorted `recovers_before_directly`, and its
  `class`; the derived transitive `reach` / `recovered_before_by` integers and the deal-level scalars
  omitted, since the edge set fully determines them), namespaced apart from every prior hash so
  computing the chain moves no golden. Twenty-five posture axes, 31 document-free coherence
  subcommands. (`docs/spec-v43.md`.)

## [9.39.0] — 2026-06-24 — Document-free exposure lead chain / the transitive closure of v35's pairwise lead-lag relation (spec-v42)

### Added
- **A `coherence-chain` headless subcommand — the *transitive closure* of v35's pairwise lead-lag
  relation.** v35 (`coherence-precedence`) reads each *pair* of fronts in isolation — does one cross
  the acceptable floor *before* the other for a strict majority of their comparisons (`leads`)? It
  never composes the pairs, so two facts a deal lead wants stay hidden: the **chain** (Cap leads Term,
  Term leads Indemnity, so Cap is a transitive early-warning indicator for Indemnity *through* Term —
  the deal's *headwater* — even with no direct Cap→Indemnity edge), and the **cycle** (Cap leads Term,
  Term leads Indemnity, Indemnity leads Cap — three clean pairwise leads that cannot be globally ranked,
  a Condorcet cycle no pairwise read can detect). v42 reuses `computeCoherencePrecedence` **unchanged**
  (the join pattern v38/v40/v41 use), builds the directed graph whose edges are exactly v35's
  strict-majority `leading` pairs (`leader → follower`), and computes its transitive closure. Per
  front: the sorted `leads_directly` (direct out-neighbours), the transitive `reach` and `led_by`,
  whether it sits on a cycle (`in_cycle`), and a `class` (`source` / `relay` / `sink` / `cyclic` /
  `isolated`); plus the deal's `headwater` (the greatest-reach source — a front with nothing upstream),
  `max_reach`, `edges` (= v35's `leading` tally, by construction), `acyclic`, and `cyclic`. Introduces
  no new crossing/ordering math — it is a reachability fixpoint over the same lead-lag edges v35 already
  derives. (`src/report/coherence-chain.ts`, `tools/cli/coherence-chain.ts`.)
- **A `--fail-on-lead-cycle` gate** — exits 2 when the lead-lag relation contains a directed cycle:
  three or more fronts each crossing the floor first over the next in a loop, so no single watch-order
  ranks every front. A directed cycle either exists or it does not — a pure boolean over the
  integer-derived edges, so the gate inherits no knob. It is the *transitive* verdict v35 structurally
  cannot pose: every pair on the loop is individually `leading` to v35, so the intransitivity is
  undetectable per-pair. *Distinct from* v35's `--fail-on-leading-front` (the *presence* of a stable
  pair; v42 flags the *incoherence* of the composed global ordering instead — a deal whose every pair
  is `leading` can be a clean acyclic pipeline or an intransitive loop).
- **`vaulytica.posture-chain.v1` report schema** and an integer-exact `chain_hash` (over the canonical
  per-front set — the front, its sorted `leads_directly`, and its `class`; the derived transitive
  `reach` / `led_by` integers and the deal-level scalars omitted, since the edge set fully determines
  them), namespaced apart from every prior hash so computing the chain moves no golden. Twenty-three
  posture axes, 30 document-free coherence subcommands. (`docs/spec-v42.md`.)

## [9.38.0] — 2026-06-24 — Document-free recovery durability / per-front mean relapsed-interval length, the above-floor mirror of v40's below-floor mean (spec-v41)

### Added
- **A `coherence-durability` headless subcommand — the *typical length* of a fix, where v30 reads its
  *extreme*.** v30 (`coherence-relapse`) pairs each *recovery* above the acceptable floor with the
  *fall* that undoes it, then reduces the clean-interval lengths two ways — the deal's **quickest**
  single relapse (`min_interval`) and whether any recovery was undone the very next round
  (`immediate`). Both are extremes; neither reads the **mean**. A front that holds five rounds twice
  and once bounces back the next round owns the deal's quickest single relapse, yet its fixes almost
  always last; a front that holds one round *every* time has the same quickest relapse, yet it is the
  one whose every fix is fragile. v41 reuses `computeCoherenceRelapse` **unchanged** (the join pattern
  v38 used for v36+v37, v40 for v28) and averages each front's relapsed interval lengths — the
  *above-floor* mirror of v40's *below-floor* mean. Per front: the relapsed `clean_intervals`,
  `closed_intervals`, `open_intervals`, `total_rounds`, the `mean_durability`
  (`total_rounds / closed_intervals`), the `min_interval` (carried for contrast), and a `class`
  (`fragile` / `durable` / `held` / `steady` / `unstated`); plus the deal's `most_fragile_dimension`,
  `min_mean`, `total_relapsed_intervals` (= v30's `relapse_count`), `total_held_intervals` (= v30's
  `held_count`), and `fragile`. Introduces no new pairing/crossing math — it averages the same
  intervals v30 already pairs. (`src/report/coherence-durability.ts`, `tools/cli/coherence-durability.ts`.)
- **A `--fail-on-fragile-recovery` gate** — exits 2 when at least one front's relapsed recoveries
  average fewer than two clean rounds above the acceptable floor (`total_rounds < 2 × closed_intervals`):
  a *fragile* front whose fix, when it recovers, typically does not survive even one clean round before
  relapsing. Two rounds is the first integer above the metric's structural minimum (a recovery and the
  immediately following fall is one clean round), so the bar is tuning-free. *Strictly stronger
  evidence than* v30's `--fail-on-immediate-relapse`: a fragile mean forces at least one clean interval
  of one round, so every `fragile` front also trips v30's `immediate` gate — but the converse fails
  (a front with intervals `[1, 5]`, mean 3, trips v30's gate on its single fast relapse yet is
  `durable` here). *Distinct from* v40's `--fail-on-lingering-exposure` (the below-floor mean; v41 is
  its above-floor mirror). A *held* recovery (one never undone) is excluded from the mean — an
  unbounded clean interval, the durable best case — but counted (`open_intervals`).
- **`vaulytica.posture-durability.v1` report schema** and an integer-exact `durability_hash` (over the
  canonical per-front set — the front, its `floors`, sorted `clean_intervals`, `open_intervals`, and
  `class`; the derived `mean_durability` / `min_interval` / `min_mean` / `fragile` omitted), namespaced
  apart from every prior hash so computing the durability moves no golden. Twenty-two posture axes, 29
  document-free coherence subcommands. (`docs/spec-v41.md`.)

## [9.37.0] — 2026-06-24 — Document-free exposure duration / per-front mean recovered-exposure length, the central tendency of v28's recovery episodes (spec-v40)

### Added
- **A `coherence-duration` headless subcommand — the *typical length* of an exposure, where v28 reads
  its *extreme*.** v28 (`coherence-latency`) pairs each *fall* below the acceptable floor with the
  *recovery* that closes it, then reduces the episode lengths two ways — the deal's **slowest** single
  recovery (`max_latency`) and whether any fall went **unrecovered** (`open_count`). Both are extremes;
  neither reads the **mean**. A front that recovers in one round three times and once takes five owns
  the deal's slowest single recovery, yet it almost always recovers at once; a front that takes four
  rounds *every* time has a shorter worst spell, yet it is the one that chronically lingers. v40
  reuses `computeCoherenceLatency` **unchanged** (the join pattern v38 used for v36+v37) and averages
  each front's recovered episode lengths. Per front: the recovered `latencies`, `closed_episodes`,
  `open_episodes`, `total_rounds`, the `mean_duration` (`total_rounds / closed_episodes`), the
  `max_latency` (carried for contrast), and a `class` (`lingering` / `brief` / `open` / `steady` /
  `unstated`); plus the deal's `longest_mean_dimension`, `max_mean`, `total_closed_episodes`
  (= v28's `recovered_count`), `total_open_episodes` (= v28's `open_count`), and `lingering`.
  Introduces no new pairing/crossing math — it averages the same episodes v28 already pairs.
  (`src/report/coherence-duration.ts`, `tools/cli/coherence-duration.ts`.)
- **A `--fail-on-lingering-exposure` gate** — exits 2 when at least one front's recovered exposures
  average at least two rounds below the acceptable floor (`total_rounds ≥ 2 × closed_episodes`): a
  *lingering* front that, when it falls, typically does not recover the very next round. Two rounds is
  the first integer above the metric's structural minimum (a fall and the immediately following
  recovery is one round), so the bar is tuning-free. *Distinct from* v28's
  `--fail-on-unrecovered-exposure` (the open fall, blind to the closed episodes' length — a front that
  always recovers but slowly trips this gate and clears v28's; a front that recovers promptly then
  falls and never returns trips v28's and clears this one) and from a `max_latency` extreme (the mean
  can rank-swap against the worst case — episodes `[1, 6]` own the slowest single recovery yet a mean
  of 3.5, while `[4, 4]` has a smaller worst spell yet a larger mean). An *open* (unrecovered) episode
  is excluded from the mean — an unbounded duration v28's gate owns — but counted (`open_episodes`).
- **`vaulytica.posture-duration.v1` report schema** and an integer-exact `duration_hash` (over the
  canonical per-front set — the front, its `floors`, sorted `latencies`, `open_episodes`, and `class`;
  the derived `mean_duration` / `max_latency` / `max_mean` / `lingering` omitted), namespaced apart
  from every prior hash so computing the duration moves no golden. Twenty-one posture axes, 28
  document-free coherence subcommands. (`docs/spec-v40.md`.)

## [9.36.0] — 2026-06-24 — Document-free exposure cadence / per-front floor-crossing churn rate, the churn mirror of v31's dwell (spec-v39)

### Added
- **A `coherence-cadence` headless subcommand — the *churn* counterpart to v31's *dwell*.** v31
  (`coherence-tenure`) reads how *long* a front sits below the acceptable floor (its occupancy
  *share*); v24 (`coherence-volatility`) counts how *many times* a front's standing crosses the floor.
  Neither reads the **rate**: across the transitions a front actually had, how *often* did it flip
  across the floor? Two fronts with identical below-floor share — both below half their stated rounds —
  can be opposites: one dips once and holds, the other alternates every round; v31 calls them the
  same, and v24, gating on the raw count, calls a front that crossed twice in twenty transitions just
  as `volatile` as one that crossed twice in two. v39 normalizes the same crossings v24 counts by the
  transitions between the rounds that *stated* the front. Per front: the floor `crossings` (both
  directions), its `transitions` (= `stated_rounds − 1`), the `cadence` (`crossings / transitions`),
  and a `class` (`oscillating` / `settled` / `static` / `unstated`); plus the deal's
  `busiest_dimension`, `max_cadence`, `total_crossings` (= v24's `crossings` summed), and
  `oscillating`. Introduces no new crossing/ordering math — it scans the same `floors[]` v24 reads.
  (`src/report/coherence-cadence.ts`, `tools/cli/coherence-cadence.ts`.)
- **A `--fail-on-oscillating-front` gate** — exits 2 when at least one front crossed the acceptable
  floor for a strict **majority** of its transitions (`crossings × 2 > transitions`): an *oscillating*
  front that flips sides more often than it holds one, never able to settle. *Distinct from* v24's
  `--fail-on-volatile-exposure` (the raw crossing *count*, blind to opportunity — a front crossing
  twice in twenty transitions is `volatile` to v24 but `settled` here; one crossing once in its single
  transition is `monotone` to v24 but `oscillating` here) and v31's `--fail-on-majority-below` (the
  *dwell* — a front below floor rounds 1–3 of 6 that holds is a `majority` tenure but a `settled`
  cadence; a front flipping every round is a `minority` tenure but `oscillating`). A strict majority of
  the transitions is the one churn boundary needing no knob.
- **An integer-exact `cadence_hash`** (`schema: vaulytica.posture-cadence.v1`) over the canonical
  per-front set (the front, its `floors`, `stated_rounds`, `transitions`, `crossings`, and class; the
  derived float `cadence`, `busiest_dimension`, `max_cadence`, and `oscillating` omitted), namespaced
  apart from every prior hash. The busiest-cadence pick uses integer cross-multiplication
  (`crossings × transitions`, earliest label on a tie), never a float compare.

### Lineage
- **The per-front cadence v38 steered to.** v38 Open Question #1 named the next axis explicitly: with
  the pairwise-precedence family and its first synthesis complete, the natural next read is "a fresh
  *per-front cadence* read (below/above oscillation rate), not another pairwise direction or
  conjunction." v39 is that read.
- **Distinct from v24 and v31.** v24 gates on the raw crossing count (blind to opportunity); v31 on
  the below-floor dwell (blind to order); v39 on the flip *rate* (crossings normalized by transitions).
  The test suite includes a `volatile`-but-`settled` fixture (the v24 divergence) and a same-dwell /
  opposite-churn fixture (the v31 divergence).

### Unchanged (additive)
- Purely additive — a new subcommand and one pure module reusing `verifyCoherenceSequence` unchanged.
  **No existing source file's behavior changes**; every other command's output and golden is
  byte-for-byte unchanged. The report stays *derived* (no new on-disk format). Suite **3,504 passing +
  2 skips** (was 3,482 + 2; +22 new tests), 237 test files (was 235).

## [9.35.0] — 2026-06-16 — Document-free persistent weak front / the per-front join of v36 + v37 (spec-v38)

### Added
- **A `coherence-weak-front` headless subcommand — the posture family's first *per-front* synthesis:
  the join of v36's concession order and v37's recovery order.** v36 (`coherence-concession`) names,
  per pair, the front that *concedes* (falls below the acceptable floor) **first**; v37
  (`coherence-recovery-order`) names the front that *recovers* (climbs back at-or-above the floor)
  **last** — the laggard left exposed longest. Each is a directional half-truth, and each spec named
  the same prize the other could not name alone: a front that **concedes first _and_ recovers last**
  is the deal's **persistent weak point** — exposed coming and going — while a front that concedes
  first but recovers *first* is merely *volatile*. v38 reduces the `leading` edges of both halves to a
  per-front verdict. Per front (with a weak signal on either axis): the partners it
  `concedes_first_against` (v36 `leading` pairs where it is the `first_conceder`), the partners it
  `recovers_last_against` (v37 `leading` pairs where it is the `last_recoverer`), the
  `confirmed_against` (the same-partner intersection — the sharpest evidence), and a `class`
  (`persistent-weak` / `conceding` / `lagging`); plus the deal's `most_exposed_front`, the
  `weak_fronts` list, and `has_persistent_weak_front`. Introduces no new fall/recovery/ordering math —
  it reads only the `leading` pairs v36/v37 already classify. (`src/report/coherence-weak-front.ts`,
  `tools/cli/coherence-weak-front.ts`.)
- **A `--fail-on-persistent-weak-front` gate** — exits 2 when at least one front is **both** a
  strict-majority first-conceder (v36) against some partner **and** a strict-majority last-recoverer
  (v37) against some partner. *Strictly stronger* than v36's `--fail-on-leading-concession` or v37's
  `--fail-on-lagging-recovery`, which each fire on a directional ordering existing at all; this
  requires a single front to be the weak side of **both**. A deal can trip v36 and v37 (different
  fronts lead each) yet clear v38 (no one front is weak on both). The conjunction of two already
  tuning-free strict-majority verdicts; no knob.
- **An integer-exact `weak_front_hash`** (`schema: vaulytica.posture-weak-front.v1`) over the
  canonical per-front set (the front, its sorted `concedes_first_against`, its sorted
  `recovers_last_against`, the class; the derived `confirmed_against`, `most_exposed_front`, and
  `has_persistent_weak_front` omitted), namespaced apart from every prior hash. The most-exposed pick
  uses integer leading-edge counts (earliest label on a tie), never a float compare.

### Lineage
- **The join v36 and v37 each deferred.** v36 Part XVI and v37 Part XVI both deferred the join as "a
  downstream read over two independent reports, not a new command" — right while the recovery half was
  unbuilt. With v37 shipped, v38 elevates it, exactly as v37 Open Question #1 steers (the next axis
  should be *per-front*, not another pairwise direction).
- **Distinct from v36 and v37.** v36/v37 are pairwise and directional; v38 is per-front and
  bidirectional. A `first_conceder` in v36 is only `conceding` in v38 unless it is *also* a
  `last_recoverer` in v37, and vice versa. The test suite includes a fixture that trips both halves on
  *different* fronts yet has no persistent weak front (the join clears).

### Unchanged (additive)
- Purely additive — a new subcommand and one pure module reusing `verifyCoherenceSequence`,
  `computeCoherenceConcession`, and `computeCoherenceRecoveryOrder` unchanged. **No existing source
  file's behavior changes**; every other command's output and golden is byte-for-byte unchanged. The
  report stays *derived* (no new on-disk format). Suite **3,482 passing + 2 skips** (was 3,463 + 2;
  +19 new tests), 235 test files (was 233).

## [9.34.0] — 2026-06-16 — Document-free exposure recovery order / pairwise recovery-precedence (spec-v37)

### Added
- **A `coherence-recovery-order` headless subcommand — the recovery mirror of v36's
  direction-resolved precedence: per unordered *pair* of fronts, when the two both *recover* (climb
  back at-or-above the acceptable floor), does one consistently recover *first* (and so the other
  *last*)?** v36 (`coherence-concession`) ordered *falls* only — which front *concedes* first. The
  floor is crossed two ways, and the recovery half was unread. v37 restricts the ordering to
  *recoveries* only, isolating which front the counterparty restores first within a pair — and the
  warning side of the same relation, the **laggard** it leaves exposed below the floor longest. Per
  pair, how many round-transition comparisons saw front A recover *before* B (`a_recovers_first`),
  how many saw B first (`b_recovers_first`), how many were same-step ties (`co_recoveries`), out of
  all `comparisons` (`a_recovers_first + b_recovers_first + co_recoveries`); the pair's
  `first_recoverer` and its `last_recoverer` (the laggard), the `affinity` (the first-recoverer's
  share of all comparisons), the deal's clearest recovery order (`max_affinity` / `most_ordered_pair`
  / `first_recovering_front` / `last_recovering_front`), and a `class` (`leading`/`interleaved`).
  A *leading* pair has a front consistently restored last — the front the counterparty leaves
  exposed longest; an *interleaved* pair recovers in mixed order with no laggard. Reuses v33's exact
  recovery events (silence-skipping, §3); adds no posture math beyond a per-pair *ordered* comparison
  of the recovery-step lists. (`src/report/coherence-recovery-order.ts`,
  `tools/cli/coherence-recovery-order.ts`.)
- **A `--fail-on-lagging-recovery` gate** — exits 2 when at least one pair has a front that recovered
  above the floor first for a strict **majority** of the comparisons (`max(a_recovers_first,
  b_recovers_first) × 2 > comparisons`, ties and reverse-order working against it) — and so a partner
  restored *last* for that same majority. Recovering first is good news; the gate is on the laggard.
  The recovery mirror of v36's `--fail-on-leading-concession`. No tuning knob; a consumer wanting a
  different bar reads `affinity` / `max_affinity` from the JSON.
- **An integer-exact `recovery_order_hash`** (`schema: vaulytica.posture-recovery-order.v1`) over the
  canonical per-pair set (the integer `a_recovers_first`/`b_recovers_first`/`co_recoveries`, the
  `first_recoverer`, the class; the derived `last_recoverer`, the float `affinity`, and derived
  integer `comparisons` omitted), namespaced apart from every prior hash. The clearest-order pick
  uses integer cross-multiplication, never a float compare.

### Lineage
- **Exact tie to v33 and v29.** By construction each pair's `co_recoveries` (the same-step recovery
  ties) equals v33's `co_recoveries` for that pair, and summed over all pairs `total_co_recoveries`
  equals `Σ_t C(recovering_t, 2)` (v29's per-step recovery count choose-two'd) — the same total v33
  reports. Verified against `computeCoherenceRecoveryAffinity` and `computeCoherenceConcurrency` in
  the test suite.
- **Distinct from v36.** A pair `leading` on v36 (orders falls — who concedes first) can be
  `interleaved` on v37 (orders recoveries — who is restored last) and vice versa; the test suite
  includes a fixture that leads on falls but interleaves on recoveries. Joined with v36, v37 names
  the deal's persistent weak front — the one that *concedes first and recovers last*.

### Unchanged (additive)
- Purely additive — a new subcommand and one pure module reusing `verifyCoherenceSequence`
  unchanged. **No existing source file's behavior changes**; every other command's output and
  golden is byte-for-byte unchanged. The report stays *derived* (no new on-disk format). Suite
  **3,463 passing + 2 skips** (was 3,441 + 2; +22 new tests), 233 test files (was 231).

## [9.33.0] — 2026-06-16 — Document-free exposure concession order / pairwise fall-precedence (spec-v36)

### Added
- **A `coherence-concession` headless subcommand — the posture family's first *direction-resolved*
  precedence: per unordered *pair* of fronts, when the two both *fall* below the acceptable floor,
  does one consistently concede *first*?** v35 (`coherence-precedence`) ordered v24's *crossings*
  — a fall **or** a recovery — so it is *direction-blind*: a pair can lead there because one front
  reliably *recovers* first, not because it *concedes* first. v36 restricts the ordering to *falls*
  only, isolating the question a deal lead actually asks ("which front does the counterparty give
  ground on **first**?"). Per pair, how many round-transition comparisons saw front A fall *before*
  B (`a_concedes_first`), how many saw B first (`b_concedes_first`), how many were same-step ties
  (`co_falls`), out of all `comparisons` (`a_concedes_first + b_concedes_first + co_falls`); the
  pair's `first_conceder`, the `affinity` (the first-conceder's share of all comparisons), the
  deal's most-conceding pairing (`max_affinity` / `most_conceding_pair` / `first_conceding_front`),
  and a `class` (`leading`/`interleaved`). A *leading* pair has a front that reliably gives ground
  first — an **early-warning indicator** that the follower is about to concede too; an *interleaved*
  pair falls in mixed order with no first-conceder. Reuses v32's exact fall events (silence-skipping,
  §3); adds no posture math beyond a per-pair *ordered* comparison of the fall-step lists.
  (`src/report/coherence-concession.ts`, `tools/cli/coherence-concession.ts`.)
- **A `--fail-on-leading-concession` gate** — exits 2 when at least one pair has a front that fell
  below the floor first for a strict **majority** of the comparisons (`max(a_concedes_first,
  b_concedes_first) × 2 > comparisons`, ties and reverse-order working against it). The
  *direction-resolved* counterpart to v35's direction-blind `--fail-on-leading-front` — a stable
  concession order that catches the warning a recovery-driven v35 lead would mask. No tuning knob; a
  consumer wanting a different bar reads `affinity` / `max_affinity` from the JSON.
- **An integer-exact `concession_hash`** (`schema: vaulytica.posture-concession.v1`) over the
  canonical per-pair set (the integer `a_concedes_first`/`b_concedes_first`/`co_falls`, the
  `first_conceder`, the class; the derived float `affinity` and derived integer `comparisons`
  omitted), namespaced apart from every prior hash. The most-conceding pick uses integer
  cross-multiplication, never a float compare.

### Lineage
- **Exact tie to v32 and v29.** By construction each pair's `co_falls` (the same-step fall ties)
  equals v32's `co_falls` for that pair, and summed over all pairs `total_co_falls` equals
  `Σ_t C(falling_t, 2)` (v29's per-step fall count choose-two'd) — the same total v32 reports.
  Verified against `computeCoherenceAffinity` and `computeCoherenceConcurrency` in the test suite.
- **Distinct from v35.** A pair `leading` on v35 (direction-blind, orders any crossing) can be
  `interleaved` on v36 (it led only because one front *recovers* first); the test suite includes a
  fixture that leads on all crossings but interleaves on falls.

### Unchanged (additive)
- Purely additive — a new subcommand and one pure module reusing `verifyCoherenceSequence`
  unchanged. **No existing source file's behavior changes**; every other command's output and
  golden is byte-for-byte unchanged. The report stays *derived* (no new on-disk format). Suite
  **3,441 passing + 2 skips** (was 3,419 + 2; +22 new tests), 231 test files (was 229).

## [9.32.0] — 2026-06-16 — Document-free exposure precedence / pairwise lead-lag coupling (spec-v35)

### Added
- **A `coherence-precedence` headless subcommand — the posture family's first *directional*
  pairwise read: per unordered *pair* of fronts, when the two both cross the acceptable floor (in
  any direction), does one consistently cross *first*?** v32/v33/v34 read three *same-step*
  pairwise relations (which two fronts cross *together* in one transition — aligned co-fall,
  aligned co-recovery, opposed counter-move) and are blind to order *across* transitions. v35
  supplies the ordering: per pair, how many round-transition comparisons saw front A cross *before*
  B (`a_leads`), how many saw B first (`b_leads`), how many were same-step ties (`co_crossings`),
  out of all `comparisons` (`a_leads + b_leads + co_crossings`); the pair's `leader`, the
  `affinity` (the leader's share of all comparisons), the deal's most-leading pairing
  (`max_affinity` / `most_leading_pair` / `leading_front`), and a `class` (`leading`/`interleaved`).
  A *leading* pair has a front that reliably moves first — an **early-warning indicator** for the
  follower; an *interleaved* pair crosses in mixed order with no first-mover. Reuses v24's exact
  crossing events (silence-skipping, §3); adds no posture math beyond a per-pair *ordered*
  comparison of the crossing-step lists. (`src/report/coherence-precedence.ts`,
  `tools/cli/coherence-precedence.ts`.)
- **A `--fail-on-leading-front` gate** — exits 2 when at least one pair has a front that crossed
  first for a strict **majority** of the comparisons (`max(a_leads, b_leads) × 2 > comparisons`,
  ties and reverse-order working against it). The *directional* counterpart to v32's
  `--fail-on-coupled-fronts`, v33's `--fail-on-coupled-recoveries`, and v34's
  `--fail-on-opposed-fronts` — a stable lead-lag a same-step read cannot pose. No tuning knob; a
  consumer wanting a different bar reads `affinity` / `max_affinity` from the JSON.
- **An integer-exact `precedence_hash`** (`schema: vaulytica.posture-precedence.v1`) over the
  canonical per-pair set (the integer `a_leads`/`b_leads`/`co_crossings`, the `leader`, the class;
  the derived float `affinity` and derived integer `comparisons` omitted), namespaced apart from
  every prior hash. The most-leading pick uses integer cross-multiplication, never a float compare.

### Lineage
- **Exact tie to v34 and v25.** By construction each pair's `co_crossings` (the same-step ties)
  equals v34's `joint_moves` for that pair, and summed over all pairs `total_co_crossings` equals
  `Σ_t C(crossing_t, 2)` (v25's per-step crossing count choose-two'd) — the same total v34 splits
  into aligned + opposed moves. Verified against `computeCoherenceOpposition` and
  `computeCoherenceSynchrony` in the test suite.

### Unchanged (additive)
- Purely additive — a new subcommand and one pure module reusing `verifyCoherenceSequence`
  unchanged. **No existing source file's behavior changes**; every other command's output and
  golden is byte-for-byte unchanged. The report stays *derived* (no new on-disk format). Suite
  **3,419 passing + 2 skips** (was 3,397 + 2; +22 new tests), 229 test files (was 227).

## [9.31.0] — 2026-06-16 — Document-free exposure counter-move affinity / pairwise opposition coupling (spec-v34)

### Added
- **A `coherence-opposition` headless subcommand — per unordered *pair* of fronts, how often the
  two crossed the acceptable floor the same step in *opposite* directions (one fell as the other
  recovered), the deal's most-opposed such pairing, and whether any pair counter-moved more often
  than it aligned; the off-diagonal completion of v32's co-fall and v33's co-recovery affinities
  (spec-v34).** v32 (`coherence-affinity`) and v33 (`coherence-recovery-affinity`) took the
  posture family's first two pairwise reads — the two *aligned* directions: which two fronts
  *fall* together (the concession block) and which two *recover* together (the restoration
  block). Those are two of the four cells of the 2×2 of {front A falls / recovers} × {front B
  falls / recovers}. The off-diagonal is unread: across the deal, **which two fronts does the
  counterparty move in *opposite* directions at once?** A step where Cap *falls* exactly as Term
  *recovers* is a *counter-move* — a trade-off, the counterparty giving ground on one front
  precisely as it takes ground on another. The two fronts are *substitutes*, bargaining chips
  swapped against each other. v34 reads, per pair, how reliably the two move against each other —
  the substitution v32/v33 (aligned-only) and v29 (per-step counts) structurally cannot pose.
  - **The affinity (pure).** `src/report/coherence-opposition.ts` —
    `computeCoherenceOpposition(rounds)` derives each front's fall-step set and recovery-step set
    (the v29 *fall* and *recovery* events, silence-skipping per §3), then for each unordered pair
    intersects A's falls with B's recoveries and A's recoveries with B's falls for `opposed_moves`
    (transitions the two moved opposite ways), computes the aligned split `co_falls` / `co_recoveries`,
    the `joint_moves` (transitions both crossed, `co_falls + co_recoveries + opposed_moves`), the
    `affinity` (`opposed_moves / joint_moves`), and a `class`: `opposed` (a strict majority of the
    joint moves, `opposed_moves × 2 > joint_moves`) or `incidental` (≥1 counter-move but not a
    majority, including an exact split). A pair that never counter-moved has no opposition edge and
    is omitted. The deal-level report adds `most_opposed_pair` / `max_affinity` (the most-opposed
    coupling, picked by **integer cross-multiplication** — never a float compare, so the ranking is
    platform-exact), `total_opposed_moves` (= `Σ_t falling_t × recovering_t` over v29's per-step
    counts) and `total_aligned_moves` (= v32's `total_co_falls` + v33's `total_co_recoveries`),
    `class_counts`, the `opposed` verdict, and a namespaced `opposition_hash` over the integer move
    counts + class (the derived float `affinity` and derived integer `joint_moves` omitted, so the
    fingerprint is integer-exact over the inputs). `exposureOpposed` is the gate predicate;
    `buildCoherenceOppositionJson` (`schema: vaulytica.posture-opposition.v1`) and
    `renderCoherenceOppositionSummary` are the renderers.
  - **The command (headless).** `tools/cli/coherence-opposition.ts` —
    `computeCoherenceOppositionArtifacts(texts, format?)` verifies all N artifacts and runs the
    spec-v15/v16 cross-ladder guard via the shared `verifyCoherenceSequence` loader (unchanged from
    v18–v33); `runCoherenceOpposition(argv)` does the file IO and exit codes. `--fail-on-opposed-fronts`
    exits 2 when any pair counter-moved for a strict majority of the steps both crossed — distinct
    from v32's `--fail-on-coupled-fronts` and v33's `--fail-on-coupled-recoveries`. Dispatcher +
    `USAGE` wired in `tools/cli/run.ts`.
  - **Join invariants.** `total_opposed_moves` equals `Σ_t falling_t × recovering_t` (v29's per-step
    fall count times its recovery count, summed); `total_aligned_moves` equals v32's `total_co_falls`
    plus v33's `total_co_recoveries`; their sum equals `Σ_t C(crossing_t, 2)` (v25's per-step crossing
    count choose-two'd). The three pairwise reads (v32 co-fall, v33 co-recovery, v34 opposed) partition
    every pair's joint moves exactly.
- **Purely additive — zero existing-source change.** Like v19–v33, v34 needs nothing newly exported;
  `coherence-sequence.ts` and every trajectory/exposure/…/recovery-affinity function are byte-for-byte
  unchanged, and every existing command's output and golden is unchanged. 23 new tests (14 pure-module,
  9 CLI).

## [9.30.0] — 2026-06-16 — Document-free exposure co-recovery affinity / pairwise recovery coupling (spec-v33)

### Added
- **A `coherence-recovery-affinity` headless subcommand — per unordered *pair* of fronts, how
  reliably the two climbed back at-or-above the acceptable floor *together* across the deal,
  the deal's tightest such pairing, and whether any pair coupled more often than it recovered
  apart; the recovery-direction mirror of v32's co-fall affinity (spec-v33).** v32
  (`coherence-affinity`) took the posture family's first pairwise read — which two fronts
  *fall* below floor together (the concession linkage). But the floor is crossed two ways, and
  v32 reads only one. v29 resolved each step into *falls* and *recoveries*; v32 paired the fall
  direction. The mirror is unread: across the deal, **which two fronts does the counterparty
  keep *restoring* as a block?** A recovery on front A that only ever lands alongside a recovery
  on front B is a *linked recovery* — A is hostage to B, repaired as a bundle, never alone. Two
  deals with byte-identical v32 co-fall affinity can have opposite recovery coupling. v33 is to
  v32 as v30 (relapse) is to v28 (latency), and v27 (onset) is to v26 (settling): the exact
  mirror on the opposite floor-crossing direction.
  - **The affinity (pure).** `src/report/coherence-recovery-affinity.ts` —
    `computeCoherenceRecoveryAffinity(rounds)` derives each front's recovery-step set (the v29
    *recovery* event: below → at-or-above, silence-skipping per §3), then for each unordered
    pair intersects the two sets for `co_recoveries` (transitions both recovered), computes
    `union_recoveries` (transitions *either* recovered, `a_recoveries + b_recoveries −
    co_recoveries`), the `affinity` (`co_recoveries / union_recoveries`, the Jaccard overlap),
    and a `class`: `coupled` (a strict majority of the union, `co_recoveries × 2 >
    union_recoveries`) or `incidental` (≥1 co-recovery but not a majority, including an exact
    split). A pair that never both-recovered has no affinity edge and is omitted. The deal-level
    report adds `tightest_pair` / `max_affinity` (the tightest coupling, picked by **integer
    cross-multiplication** — never a float compare, so the ranking is platform-exact),
    `total_co_recoveries` (= `Σ_t C(recovering_t, 2)` over v29's per-step recovery counts) and
    `total_recoveries` (= v29's), `class_counts`, the `coupled` verdict, and a namespaced
    `recovery_affinity_hash` over the integer recovery counts + class (the derived float
    `affinity` and derived integer `union_recoveries` omitted, so the fingerprint is
    integer-exact over the inputs). `exposureRecoveryCoupled` is the gate predicate;
    `buildCoherenceRecoveryAffinityJson` (`schema: vaulytica.posture-recovery-affinity.v1`) and
    `renderCoherenceRecoveryAffinitySummary` are the renderers.
  - **The command (headless).** `tools/cli/coherence-recovery-affinity.ts` —
    `computeCoherenceRecoveryAffinityArtifacts(texts, format?)` verifies all N artifacts and
    runs the cross-ladder guard via the shared `verifyCoherenceSequence` loader (unchanged from
    v18–v32), then computes and renders the affinity. `runCoherenceRecoveryAffinity(argv)` does
    the file IO and exit codes; `--fail-on-coupled-recoveries` exits 2 when any pair recovered
    together for a strict majority of the steps either recovered. The `run.ts` dispatcher gains
    a `coherence-recovery-affinity` case and a `USAGE` entry.
  - **Distinct from v32 and v29.** A pair `coupled` on falls (v32) can be `incidental` on
    recoveries (v33) and vice versa — the two directions are independent relations over the same
    `floors[]` matrix (a covered regression test builds a pair that falls together yet recovers
    on opposite steps: v32 reports a co-fall edge, v33 reports none). Every co-recovery step is
    a v29 `recovering ≥ 2` step, but three different pairs each recovering together once give
    v29 three such steps yet leave every pair `incidental` to v33.
  - **Purely additive.** A new subcommand + one pure module; `verifyCoherenceSequence` and every
    existing source file are reused **without modification**. Every existing command's output
    and golden is byte-for-byte unchanged. Tests: source (15) + CLI (9) — identity
    disk-vs-in-memory, the linked vs the independent recovery, a co-recovery requires both
    fronts to recover the same step, the exact-split incidental boundary, the `Σ C(recovering,
    2)` and `total_recoveries` join invariants, the tightest-pair pick + tie-break,
    no-pairing/§3-silence/both-recovered-once edges, the v32-divergence, determinism,
    ≥2-artifact, cross-ladder refusal, unpinned-v1 note, tamper rejection, gate parity, render +
    JSON.

### Changed
- **README** — new "Exposure co-recovery affinity" section with a worked example; the
  posture-axis callout now reads **fifteen orthogonal axes** (adds RECOVERY-AFFINITY); the
  version table, the dispatcher command lists, the command count (twenty-two), and the CLI
  cheat-sheet all list `coherence-recovery-affinity`.

## [9.29.0] — 2026-06-16 — Document-free exposure co-fall affinity / pairwise concession coupling (spec-v32)

### Added
- **A `coherence-affinity` headless subcommand — per unordered *pair* of fronts, how
  reliably the two fell below the acceptable floor *together* across the deal, the deal's
  tightest such pairing, and whether any pair coupled more often than it fell apart; the
  first *pairwise* read the posture family has taken (spec-v32).** Every reduction through
  v31 is a scalar — per front, per round, or per episode. v25/v29 come closest to a
  relational read (they count, per step, *how many* fronts crossed or fell together) but
  collapse the relation to a count the instant they record it: v29 knows round 3 saw two
  fronts fall, even lists *which* two, but never asks across the sequence whether it is the
  same two again and again. Two deals with byte-identical v29 concurrency profiles (same
  per-step fall counts) can be opposites — one a single stable pair falling together every
  time (a linked concession), the other a different co-falling pair every round (no
  coupling). v32 supplies the missing pairwise axis.
  - **The affinity (pure).** `src/report/coherence-affinity.ts` —
    `computeCoherenceAffinity(rounds)` derives each front's fall-step set (the v29 *fall*
    event: at-or-above → below, silence-skipping per §3), then for each unordered pair
    intersects the two sets for `co_falls` (transitions both fell), computes `union_falls`
    (transitions *either* fell, `a_falls + b_falls − co_falls`), the `affinity`
    (`co_falls / union_falls`, the Jaccard overlap), and a `class`: `coupled` (a strict
    majority of the union, `co_falls × 2 > union_falls`) or `incidental` (≥1 co-fall but not
    a majority, including an exact split). A pair that never both-fell has no affinity edge
    and is omitted. The deal-level report adds `tightest_pair` / `max_affinity` (the tightest
    coupling, picked by **integer cross-multiplication** — never a float compare, so the
    ranking is platform-exact), `total_co_falls` (= `Σ_t C(falling_t, 2)` over v29's per-step
    fall counts) and `total_falls` (= v29's), `class_counts`, the `coupled` verdict, and a
    namespaced `affinity_hash` over the integer fall counts + class (the derived float
    `affinity` and derived integer `union_falls` omitted, so the fingerprint is integer-exact
    over the inputs). `exposureCoupled` is the gate predicate; `buildCoherenceAffinityJson`
    (`schema: vaulytica.posture-affinity.v1`) and `renderCoherenceAffinitySummary` are the
    renderers.
  - **The command (headless).** `tools/cli/coherence-affinity.ts` —
    `computeCoherenceAffinityArtifacts(texts, format?)` verifies all N artifacts and runs the
    cross-ladder guard via the shared `verifyCoherenceSequence` loader (unchanged from
    v18–v31), then computes and renders the affinity. `runCoherenceAffinity(argv)` does the
    file IO and exit codes; `--fail-on-coupled-fronts` exits 2 when any pair fell together for
    a strict majority of the steps either fell. The `run.ts` dispatcher gains a
    `coherence-affinity` case and a `USAGE` entry.
  - **Distinct from v29's `--fail-on-concerted-fall`.** Every co-fall step *is* a v29
    concerted-fall step (two fronts down at once), so `coupled ⟹ concerted` for that step —
    but the reverse fails where it matters: three *different* pairs each falling together once
    trip v29 (three concerted-fall steps) yet leave every pair `incidental` to v32 (each
    co-fell once, apart more). v29 asks "did any step lurch?"; v32 asks "is there a *stable*
    concession pairing?".
  - **Purely additive.** A new subcommand + one pure module; `verifyCoherenceSequence` and
    every existing source file are reused **without modification**. Every existing command's
    output and golden is byte-for-byte unchanged. Tests: source (14) + CLI (9) — identity
    disk-vs-in-memory, the coupling vs the coincidence (v29 trips, v32 clears), a co-fall
    requires both fronts to fall the same step, the exact-split incidental boundary, the
    `Σ C(falling, 2)` and `total_falls` join invariants, the tightest-pair pick + tie-break,
    no-pairing/§3-silence/both-fell-once edges, determinism, ≥2-artifact, cross-ladder
    refusal, unpinned-v1 note, tamper rejection, gate parity, render + JSON.

### Changed
- **README** — new "Exposure co-fall affinity" section with a worked example; the posture-axis
  callout now reads **fourteen orthogonal axes** (adds AFFINITY); the version table, the
  dispatcher command lists, the command count (twenty-one), and the CLI cheat-sheet all list
  `coherence-affinity`.

## [9.28.0] — 2026-06-16 — Document-free exposure tenure / below-floor occupancy share (spec-v31)

### Added
- **A `coherence-tenure` headless subcommand — per front, what *share* of the rounds that
  stated it sat below the acceptable floor, the deal's heaviest such share, and whether any
  front was below floor for a strict *majority* of its stated rounds; the occupancy axis the
  posture family never read (spec-v31).** v21 (`coherence-persistence`) reads a raw
  `rounds_below` count against the *total* round span and gates on the *endpoint* (a front
  below floor *now*). v31 supplies the missing occupancy axis: read the same `floors[]`
  matrix per front, but normalize the below-floor count by the front's *stated* rounds (the
  §3-honest denominator) and headline the *burden*. A brief dip that recovered and a chronic
  burden that recovered are identical to v21 (both `resolved`) — opposites here.
  - **The tenure (pure).** `src/report/coherence-tenure.ts` —
    `computeCoherenceTenure(rounds)` counts, per front, the rounds that *stated* it
    (`stated_rounds`, the denominator) and the rounds it sat below floor (`below_rounds`, the
    numerator; an unstated round counts toward neither, §3), and computes the `share`
    (`below_rounds / stated_rounds`). Each front is classed `majority` (below floor for a
    strict majority of its stated rounds, `below_rounds × 2 > stated_rounds`), `minority`
    (below floor but not a majority, including an exact split), `none` (never below floor), or
    `unstated` (§3). The deal-level report adds `max_share` / `heaviest_dimension` (the
    heaviest occupancy, picked by **integer cross-multiplication** — never a float compare,
    so the ranking is platform-exact; earliest dimension on a tie), `total_below_rounds`
    (equal by construction to v21's `rounds_below` summed) and `total_stated_rounds`.
    `exposureMajorityBelow` = `tenure.majority` — the gate predicate, **distinct from v21's
    `exposureOpen`**: a front below floor only at the close is `open` to v21 (gate trips) but
    a minority here (gate clears); a front below floor for rounds 1–4 of 5 that recovers at
    round 5 is `resolved` to v21 (gate clears) but a majority here (gate trips). **Honest by
    construction (§3):** silence dilutes neither the numerator nor the denominator, so a
    front below floor both times it was on the table reads 100%, not 40% diluted by rounds it
    was never part of. `buildCoherenceTenureJson` (`schema: vaulytica.posture-tenure.v1`) +
    `renderCoherenceTenureSummary` (heaviest-occupancy verdict, class tally, then one line per
    below-floor front, `majority` first). A namespaced `tenure_hash` (SHA-256 over the
    canonical per-front occupancy set — the integer `stated_rounds`/`below_rounds` and class;
    the derived float `share` is omitted, so the fingerprint is integer-exact), apart from
    every `coherence_hash` … `relapse_hash`.
  - **The command (headless).** `tools/cli/coherence-tenure.ts` —
    `computeCoherenceTenureArtifacts(texts, format?)` verifies all N artifacts and runs the
    spec-v15/v16 cross-ladder guard via the shared `verifyCoherenceSequence` loader
    (unchanged from v18–v30), then renders markdown (default) or `--format json`.
    `runCoherenceTenure(argv)` reads the files and exits 2 under `--fail-on-majority-below`
    when any front was below floor for a strict majority of its stated rounds. Wired into the
    `run.ts` dispatcher + `USAGE`. Requires ≥ 2 artifacts in round order.
  - **Tests.** 24 new (15 pure + 9 CLI): the brief dip vs the chronic burden (both `resolved`
    to v21, opposite tenure), the fresh late dip (`open` to v21 but minority here), the exact
    split (minority, not majority), stated-vs-total normalization (§3), the join invariant
    (`total_below_rounds` = v21's `rounds_below` sum), the heaviest-share pick by exact
    integer ratio + tie-break, no-front-ever-below, unstated-never-counted, stated-once-and-
    below → 100%/majority, determinism, ≥2-artifact requirement, cross-ladder refusal,
    unpinned-v1 note, tamper rejection (round-prefixed), gate parity, render + JSON.
  - **Purely additive.** No existing source file's behavior changes; every existing command's
    output and golden is byte-for-byte unchanged. TWELVE → THIRTEEN posture axes.

## [9.27.0] — 2026-06-16 — Document-free exposure relapse interval / rounds above floor per recovery-to-relapse span (spec-v30)

### Added
- **A `coherence-relapse` headless subcommand — per front, how many rounds its binding
  floor held *above* the acceptable floor between a *recovery* and the *next fall* that
  undoes it, the deal's quickest relapse, and whether any recovery was reversed the very
  next round; the exact mirror of v28's recovery latency (spec-v30).** v28
  (`coherence-latency`) pairs each *fall* forward with the *recovery* that closes it and
  reads the rounds *below* floor (the slowest recovery, gated on a fall that never came
  back). v30 supplies the missing mirror axis: pair each recovery forward with the next
  fall that undoes it and read the rounds *above* floor. Two fronts v24 reports identically
  (same crossing count) and that v28 cannot tell apart (a relapse is not a latency) — a fix
  that held for rounds vs. one reversed the next exchange — are opposites here.
  (Fulfills v28 Part XVI's deferred "clean interval" stat.)
  - **The relapse (pure).** `src/report/coherence-relapse.ts` —
    `computeCoherenceRelapse(rounds)` scans each front's binding floors, attributes each
    stated crossing to the round that reveals it (the same §3 attribution v24/v28 use),
    and pairs each `recovery` (below → at-or-above) forward with the next `fall`
    (at-or-above → below) into `intervals[]`, each carrying its `clean_rounds`
    (`fall_round − recovery_round`, the rounds above floor; `null` when the recovery held).
    Each front is classed `relapsed` (a recovery undone in-sequence — the fix did not hold),
    `held` (recovered and every recovery held), `steady` (never recovered in-sequence), or
    `unstated` (§3). The deal-level report adds `min_interval` / `quickest_dimension` (the
    quickest relapse, earliest on a tie), `relapse_count` / `held_count`, and
    `total_crossings` (equal by construction to v24's per-front sum and v25/…/v29's totals).
    `exposureImmediateRelapse` = `relapse.immediate` (any `clean_rounds === 1`) — the gate
    predicate, **distinct from v28's `exposureUnrecovered`**: v28 fires on a fall that never
    recovered (an unbounded gap *below*); v30 fires on a recovery undone the very next round
    (a minimal gap *above*). **The mirror asymmetry:** a *leading recovery* (a front below
    from round 1 that recovers) is `steady` to v28 but pairs forward here (`held`/`relapsed`).
    **Honest by construction (§3):** silence is neither a recovery nor a fall; a relapse
    revealed after a silent round spans the silent rounds (never *immediate*).
    `buildCoherenceRelapseJson` (`schema: vaulytica.posture-relapse.v1`) +
    `renderCoherenceRelapseSummary`. A namespaced `relapse_hash` (SHA-256 over the canonical
    per-front interval set) keeps every existing golden unmoved. **Zero changes to any
    existing source file** — v30 imports only the already-public `PostureCoherence`/
    `NegotiationTier` types and the shared hashing helpers.
  - **The command (headless).** `tools/cli/coherence-relapse.ts` —
    `computeCoherenceRelapseArtifacts(texts, format?)` is the pure core (the shared
    `verifyCoherenceSequence` loader — parse + hash-verify + cross-ladder guard, unchanged —
    then `computeCoherenceRelapse`, rendered markdown or JSON). `runCoherenceRelapse(argv)`
    is the handler (file IO + exit codes); requires ≥ 2 positionals; under
    `--fail-on-immediate-relapse` exits 2 only when a recovery was undone at the very next
    round. Wired into the `run.ts` dispatcher (`case "coherence-relapse"`) + `USAGE` + header
    doc + unknown-command list. A separate command, not a `coherence-latency` flag — each
    command keeps one gate and one hash.
- **Verified live end-to-end:** a deal where Cap recovers round 3 and falls again round 4
  prints `⚠ Cap: relapsed — recovered round 3 → fell again round 4 (1 round above)` and
  exits **2** under `--fail-on-immediate-relapse`; a recovery that holds ≥2 rounds before
  relapsing clears the gate — the fix-did-not-hold axis the crossing count (v24) and the
  below-latency (v28) cannot isolate.
- **Tests:** +27 (`src/report/coherence-relapse.test.ts` ×18, `tools/cli/coherence-relapse.test.ts` ×9):
  immediate relapse, durable vs immediate fix (same v24 crossing count, different interval),
  a held recovery, the v28 mirror (a fall that never recovered is `open` to v28 but `steady`
  here; a leading recovery is `steady` to v28 but `held`/`relapsed` here), the reduction
  invariant (`total_crossings` = v24's/v25's/v28's/v29's totals), the quickest-relapse pick
  across fronts, silence-does-not-shorten and silence-attribution (§3), above-floor whipsaw
  never pairs (distinct from v17), no-front-ever-recovered, unstated-never-counted (§3), two
  intervals on one front, determinism, ≥2-artifact requirement, cross-ladder refusal naming
  both rounds, unpinned-v1 note, round-prefixed tamper, gate-predicate parity, render + JSON.
  Suite **3,303 passing + 2 skips** (was 3,276), 219 test files (was 217). Every existing
  command's output and golden is byte-for-byte unchanged. New [`docs/spec-v30.md`](docs/spec-v30.md).
  The posture matrix now has **twelve axes** — MOVEMENT (v16–v19), LEVEL (v20), TIME/duration
  (v21), BREADTH (v22), RECURRENCE (v23), VOLATILITY (v24), SYNCHRONY (v25), SETTLING (v26),
  ONSET (v27), LATENCY (v28), CONCURRENCY (v29), and RELAPSE (v30, the mirror of v28).

## [9.26.0] — 2026-06-16 — Document-free exposure concurrency / fronts falling vs recovering per step (spec-v29)

### Added
- **A `coherence-concurrency` headless subcommand — per step, how many fronts *fell*
  below the floor vs. how many *recovered*, the deal's peak fall step, and whether any
  step was a concerted fall; the direction-resolved split of v25's per-step crossing
  count (spec-v29).** v25 (`coherence-synchrony`) counts the fronts crossing the floor in
  each step — but **direction-blind**: a step where two fronts *fell* together and a step
  where one fell while another recovered both register as the same "synchronized" (two
  crossings). v29 supplies the missing axis: split each step's crossings by direction.
  (Fulfills v25 Part XVI's deferred direction-homogeneous synchrony.)
  - **The concurrency (pure).** `src/report/coherence-concurrency.ts` —
    `computeCoherenceConcurrency(rounds)` scans each front's binding floors, attributes
    each stated crossing to the round that reveals it (the same §3 attribution v24/v25 use),
    and buckets it into that step's `falling` (a fall, at-or-above → below) or `recovering`
    (a recovery, below → at-or-above) list. Each step is classed by direction —
    `concerted-fall` (≥2 fell, the gate-worthy class), `concerted-recovery` (≥2 recovered,
    <2 fell), `mixed` (both directions, neither reaching two), `isolated` (one crossing),
    `quiet` (none). The deal-level report adds `peak_fall_transition` / `peak_fall_count`
    (the step the most fronts fell at once, earliest on a tie), the
    `concerted_fall_count` / `concerted_recovery_count` / `mixed_count`, and
    `total_crossings` (equal by construction to v24's per-front sum and v25/v26/v27/v28's
    totals), with `total_falls + total_recoveries = total_crossings`. `exposureConcerted` =
    `concerted_fall_count > 0` — the gate predicate, **distinct from v25's
    `exposureSynchronized`**: v25 fires on any step where ≥2 fronts crossed regardless of
    direction (a one-down-one-up churn trips it); v29 fires only on ≥2 fronts moving the
    same way, down. **Honest by construction (§3):** silence is neither a fall nor a
    recovery; a crossing across a silent gap lands on the round that reveals it, never the
    silent step. `buildCoherenceConcurrencyJson` (`schema: vaulytica.posture-concurrency.v1`)
    + `renderCoherenceConcurrencySummary`. A namespaced `concurrency_hash` (SHA-256 over the
    canonical per-transition set) keeps every existing golden unmoved. **Zero changes to any
    existing source file** — v29 imports only the already-public `PostureCoherence`/
    `NegotiationTier` types and the shared hashing helpers.
  - **The command (headless).** `tools/cli/coherence-concurrency.ts` —
    `computeCoherenceConcurrencyArtifacts(texts, format?)` is the pure core (the shared
    `verifyCoherenceSequence` loader — parse + hash-verify + cross-ladder guard, unchanged —
    then `computeCoherenceConcurrency`, rendered markdown or JSON).
    `runCoherenceConcurrency(argv)` is the handler (file IO + exit codes); requires ≥ 2
    positionals; under `--fail-on-concerted-fall` exits 2 only when a step saw ≥2 fronts fall
    together. Wired into the `run.ts` dispatcher (`case "coherence-concurrency"`) + `USAGE` +
    header doc + unknown-command list. A separate command, not a `coherence-synchrony` flag —
    each command keeps one gate and one hash.
- **Verified live end-to-end:** a concerted-fall deal (Cap and Term both fall in round
  1→2) prints `⚠ round 1→2: 2 fell (Cap, Term), 0 recovered (—) [concerted-fall]` and exits
  **2** under `--fail-on-concerted-fall`; a staggered deal (Cap then Term fall one at a
  time) classes both steps `isolated` and exits **0** — the coordinated-collapse axis v25's
  direction-blind count cannot isolate.
- **Tests:** +24 (`src/report/coherence-concurrency.test.ts` ×15, `tools/cli/coherence-concurrency.test.ts` ×9):
  concerted fall vs churn (same v25 crossing count, different concurrency class), concerted
  recovery, concerted-fall dominates a step with a simultaneous recovery, isolated single
  crossing, the reduction invariant (`total_crossings` = v24's/v25's/v28's totals;
  `total_falls + total_recoveries = total_crossings`), silence-attribution and
  silence-is-quiet (§3), above-floor whipsaw never crosses (distinct from v17),
  no-front-ever-fell, earliest-peak-fall tiebreak, determinism, ≥2-artifact requirement,
  cross-ladder refusal naming both rounds, unpinned-v1 note, round-prefixed tamper,
  gate-predicate parity, render + JSON. Suite **3,276 passing + 2 skips** (was 3,252), 217
  test files (was 215). Every existing command's output and golden is byte-for-byte
  unchanged. New [`docs/spec-v29.md`](docs/spec-v29.md). The posture matrix now has **eleven
  axes** — MOVEMENT (v16–v19), LEVEL (v20), TIME/duration (v21), BREADTH (v22), RECURRENCE
  (v23), VOLATILITY (v24), SYNCHRONY (v25), SETTLING (v26), ONSET (v27), LATENCY (v28), and
  CONCURRENCY (v29, the direction split of v25).

## [9.25.0] — 2026-06-15 — Document-free exposure recovery latency / rounds below floor per episode (spec-v28)

### Added
- **A `coherence-latency` headless subcommand — per front, how many rounds its
  standing sat *below* the floor between a fall and the recovery that closes it, the
  deal's slowest recovery, and whether any fall went unrecovered; the recovery-latency
  reduction of the same crossings v24/v25/v26/v27 count (spec-v28).** v24
  (`coherence-volatility`) counts a front's crossings (`crossings`); v25
  (`coherence-synchrony`) re-buckets them per step; v26 (`coherence-settling`) /
  v27 (`coherence-onset`) read the **index** of the *last* / *first* crossing. All four
  reduce the crossings to a count or a single index — and a count and an index both
  throw away the **gap between a fall and the recovery that closes it**. Two fronts with
  the identical crossing count (both fell once and recovered once) can be opposites here:
  a fall caught at the next exchange (one round below) vs. one that festered for rounds.
  v28 supplies the missing axis: pair each fall with the recovery that closes it and read
  the duration between them. (Fulfills v26/v27 Part XVI's deferred re-exposure-latency
  stat.)
  - **The latency (pure).** `src/report/coherence-latency.ts` —
    `computeCoherenceLatency(rounds)` scans each front's binding floors, attributes each
    stated crossing to the round that reveals it (the same §3 attribution v24/v25/v26/v27
    use), and pairs each *fall* (at-or-above → below) with the next *recovery* (below →
    at-or-above) into `episodes[]`. Each closed episode carries its `latency`
    (`recovery_round − fall_round` — the rounds below floor); an unclosed fall is an *open*
    episode (`recovery_round` `null`, an unbounded latency). The deal-level report adds
    `max_latency` / `slowest_dimension` (the longest closed episode and the front that owns
    it), `recovered_count` / `open_count`, a per-front `LatencyClass`
    (`open` / `recovered` / `steady` / `unstated`), and `total_crossings` — equal by
    construction to v24's per-front sum and v25/v26/v27's per-step sum.
    `exposureUnrecovered(latency)` = `open_count > 0` — the gate predicate, **distinct
    from v21's `exposureOpen`**: v21 fires on a front whose *current standing* is below
    floor (including one stated below from round 1 that never *fell* in-sequence); v28
    fires only on an in-sequence *fall that never closed*. **Honest by construction (§3):**
    silence inside a gap does not reset the standing or invent a recovery; a front stated
    below from round 1 has no in-sequence fall to pair (its descent predates the archive),
    so it contributes no episode and is `steady`. `buildCoherenceLatencyJson`
    (`schema: vaulytica.posture-latency.v1`) + `renderCoherenceLatencySummary`. A
    namespaced `latency_hash` (SHA-256 over the canonical per-front episode set) keeps every
    existing golden unmoved. **Zero changes to any existing source file** — v28 imports only
    the already-public `PostureCoherence`/`NegotiationTier` types and the shared hashing
    helpers.
  - **The command (headless).** `tools/cli/coherence-latency.ts` —
    `computeCoherenceLatencyArtifacts(texts, format?)` is the pure core (the shared
    `verifyCoherenceSequence` loader — parse + hash-verify + cross-ladder guard, unchanged
    — then `computeCoherenceLatency`, rendered markdown or JSON). `runCoherenceLatency(argv)`
    is the handler (file IO + exit codes); requires ≥ 2 positionals; under
    `--fail-on-unrecovered-exposure` exits 2 only when a front fell and never recovered.
    Wired into the `run.ts` dispatcher (`case "coherence-latency"`) + `USAGE` + header doc +
    unknown-command list. A separate command, not a `coherence-onset` flag — each command
    keeps one gate and one hash.
- **Verified live end-to-end:** a slow-but-recovered deal
  (`acceptable → below → below → below → acceptable`) prints
  `slowest recovery: Cap — sat below floor for 3 rounds` and exits **0**; an unrecovered
  fall (`acceptable → below → below`) prints `⚠ Cap: open — fell round 2, never recovered`
  and exits **2** — the recovery-latency axis no count or index can show.
- **Tests:** +26 (`src/report/coherence-latency.test.ts` ×17, `tools/cli/coherence-latency.test.ts` ×9):
  prompt vs slow recovery (same v24 crossing count, different latency), the unrecovered
  episode (gate trips) vs the recovered one (gate clears), the v21 distinction (a front
  below from round 1 is `open` to v21 but contributes no episode here), the reduction
  invariant (`total_crossings` = v24's/v25's/v26's/v27's totals), the slowest-recovery pick
  across fronts (earliest on a tie), silence-inside-a-gap and silence-attribution (§3),
  two-episode fronts (a recovered then an unrecovered fall), above-floor whipsaw never pairs
  (distinct from v17), no-front-ever-fell, unstated never counted, determinism, ≥2-artifact
  requirement, cross-ladder refusal naming both rounds, unpinned-v1 note, round-prefixed
  tamper, gate-predicate parity, render + JSON. Suite **3,252 passing + 2 skips** (was 3,226),
  215 test files (was 213). Every existing command's output and golden is byte-for-byte
  unchanged. New [`docs/spec-v28.md`](docs/spec-v28.md). The posture matrix now has **ten
  axes** — MOVEMENT (v16–v19), LEVEL (v20), TIME/duration (v21), BREADTH (v22), RECURRENCE
  (v23), VOLATILITY (v24, per-front crossings), SYNCHRONY (v25, per-step crossings), SETTLING
  (v26, last-crossing index), ONSET (v27, first-crossing index), and LATENCY (v28,
  fall-to-recovery gap).

## [9.24.0] — 2026-06-15 — Document-free exposure onset / first floor crossing (spec-v27)

### Added
- **A `coherence-onset` headless subcommand — the round the package *first* crossed
  the floor, and whether it degraded from the very opening; the time-of-first-movement
  mirror of v26's last-crossing index (spec-v27).** v24 (`coherence-volatility`) reads
  the N-round archive *down the front axis* (`crossings`); v25 (`coherence-synchrony`)
  re-buckets those crossings *per step* (`crossing_fronts`); v26 (`coherence-settling`)
  reads the **index of the last one** (`settling_round`, `unsettled`). v26 reads the
  *latest* crossing — and the latest throws away *when the first crossing happened*. So a
  deal lead can learn "the package's last floor crossing was the final round" (v26) but
  not "and its *first* crossing was round 1→2 — it degraded from the opening." A deal
  whose crossings were a front falling in round 1→2 and again in the final round (*early
  onset*) is **identical to v26** (same `settling_round`, same `unsettled`) as a deal
  whose crossings were a front falling in round 4→5 and again in the final round (a *clean
  lead-in* of three rounds). The first and last crossing indices are independent whenever
  a deal crosses the floor more than once. v27 supplies the missing axis: read the same
  floor crossings v24/v25/v26 count for the **index** of the first one. (Fulfills v26
  Part XVI's deferred first-crossing stat.)
  - **The onset (pure).** `src/report/coherence-onset.ts` —
    `computeCoherenceOnset(rounds)` attributes each front's stated floor crossing to the
    transition that reveals it (the same attribution v24/v25/v26 use) and marks each
    transition `active` (a front crossed) or `still` (none did). The series reports
    `onset_round` (the `to_round` of the *earliest* active step — the round the package
    first crossed the floor, `null` when none ever did), `lead_in` (the run of leading
    `still` steps before it — the whole sequence when none crossed), `active_count` (steps
    where any front crossed), `early_onset` (the *first* transition was active), and
    `total_crossings` — equal by construction to v24's per-front sum and v25/v26's per-step
    sum (v27 reads the same crossings for *where the first one falls*).
    `exposureEarlyOnset(onset)` = `onset.early_onset` — the *time-of-first-movement* gate
    predicate, distinct from `exposureVolatile` (a single front crossing ≥ 2 times),
    `exposureSynchronized` (≥ 2 fronts crossing in one step), and `exposureUnsettled` (the
    last crossing on the final step). **Honest by construction (§3):** silence does not
    count as a crossing; a crossing across a silent gap is attributed to the transition
    into the round that *reveals* the new standing, and an opening round left entirely
    unstated reveals no crossing — so the lead-in stays honest (silence at the open is not
    an onset). **Distinct from v26:** they are mirror reductions of the same crossings and
    coincide only when a deal crosses the floor exactly once; the moment it crosses twice,
    the first and last indices are independent — v27 separates two deals v26 reports
    identically. Carries a namespaced `onset_hash` (SHA-256, apart from every other hash).
    `buildCoherenceOnsetJson` (`schema: vaulytica.posture-onset.v1`) +
    `renderCoherenceOnsetSummary` (the onset verdict + active-step count, then one line per
    step). **Zero changes to any existing source file** — v27 imports only the
    already-public `PostureCoherence`/`NegotiationTier` types and the shared hashing helpers.
  - **The command (headless).** `tools/cli/coherence-onset.ts` —
    `computeCoherenceOnsetArtifacts(texts, format?)` is the pure core
    (`verifyCoherenceSequence` — the shared parse + hash-verify + cross-ladder guard,
    unchanged — then `computeCoherenceOnset` rendered markdown/JSON);
    `runCoherenceOnset(argv)` is the handler (file IO + exit codes), requiring ≥ 2
    positionals and exiting 2 under `--fail-on-early-onset-exposure` only when the first
    transition crossed the floor. A separate command, not a `coherence-settling` flag —
    one gate, one hash. Wired into the `run.ts` dispatcher (`case "coherence-onset"`) +
    USAGE + header doc + unknown-command list.
  - **Verified live end-to-end.** Drove the real CLI over ladder-pinned artifacts: a clean
    lead-in (`acceptable → acceptable → below`) prints `onset: at round 3 — … after 1
    steady step of clean lead-in` and exits **0**; an early cross (`below → acceptable`)
    prints `onset: EARLY — the floor was first crossed in round 1→2, the opening
    transition` and exits **2** — proving the first-move axis v26's last-move index cannot
    show.
  - **Additive.** A brand-new subcommand + one pure module — every existing command's
    output and every golden byte-for-byte unchanged; no existing source file's behavior
    changes; no new on-disk format (the onset stays *derived*). +22 tests
    (`src/report/coherence-onset.test.ts` ×14, `tools/cli/coherence-onset.test.ts` ×8);
    suite **3,226 passing + 2 skips** (was 3,204), 213 test files (was 211).
  - **Docs.** New [`docs/spec-v27.md`](docs/spec-v27.md); BUILD_PROGRESS v27 §; README
    "Saved coherence baselines" § extended with the onset workflow + the nine-axis summary
    callout + v27 spec-table row + CLI cheat-sheet + commands-table entry + specs list
    brought current v1–v27.

## [9.23.0] — 2026-06-15 — Document-free exposure settling / latest floor crossing (spec-v26)

### Added
- **A `coherence-settling` headless subcommand — the round the package *last* crossed
  the floor, and whether it was still moving at the close; the time-of-last-movement
  reduction the per-front (v24) and per-step (v25) crossing counts both leave out
  (spec-v26).** v24 (`coherence-volatility`) reads the N-round archive *down the front
  axis*: per front, how many times its standing crossed the floor across the whole deal
  (`crossings`). v25 (`coherence-synchrony`) re-buckets those same crossings *per step*:
  per round-transition, how many fronts crossed at once (`crossing_fronts`). Both reduce
  the crossings to a **count** — and a count throws away *when the last crossing
  happened*. So a deal lead can learn "the Cap front crossed the floor twice" (v24) and
  "two fronts crossed together in round 1→2" (v25) but not "the package's *last* floor
  crossing was the final round — it never settled." A deal whose only crossing was a
  front falling in round 1→2 then five steady rounds (*settled early*) is identical to
  v24 (one monotone front) and v25 (one isolated step) as a deal whose only crossing was
  a front falling in the **final** round (*unsettled*). v26 supplies the missing axis:
  read the same floor crossings v24/v25 count for the **index** of the last one.
  - **The settling (pure).** `src/report/coherence-settling.ts` —
    `computeCoherenceSettling(rounds)` attributes each front's stated floor crossing to
    the transition that reveals it (the same attribution v24/v25 use) and marks each
    transition `active` (a front crossed) or `still` (none did). The series reports
    `settling_round` (the `to_round` of the *latest* active step — the round the package
    last crossed the floor, `null` when none ever did), `quiet_tail` (the run of trailing
    `still` steps after it — the whole sequence when none crossed), `active_count` (steps
    where any front crossed), `unsettled` (the *final* transition was active), and
    `total_crossings` — equal by construction to v24's per-front sum and v25's per-step
    sum (v26 reads the same crossings for *where the last one falls*).
    `exposureUnsettled(settling)` = `settling.unsettled` — the *time-of-last-movement*
    gate predicate, distinct from `exposureVolatile` (a single front crossing ≥ 2 times)
    and `exposureSynchronized` (≥ 2 fronts crossing in one step). **Honest by
    construction (§3):** silence does not count as a crossing; a crossing across a silent
    gap is attributed to the transition into the round that *reveals* the new standing,
    and a final round left entirely unstated reveals no crossing — so the close is
    `settled` (silence at the close is stability, not movement). **Distinct from v17's
    whipsaw:** an above-floor jitter (`acceptable → ideal → acceptable`) crosses the floor
    zero times, so it has no settling round and is `settled`. **Distinct from v21's
    duration:** a front stuck below floor for all N rounds has a large `rounds_below` but
    *zero* crossings — it never moved — so it is `settled` to v26. Carries a namespaced
    `settling_hash` (SHA-256, apart from every other hash). `buildCoherenceSettlingJson`
    (`schema: vaulytica.posture-settling.v1`) + `renderCoherenceSettlingSummary` (the
    settling verdict + active-step count, then one line per step). **Zero changes to any
    existing source file** — v26 imports only the already-public `PostureCoherence`/
    `NegotiationTier` types and the shared hashing helpers.
  - **The command (headless).** `tools/cli/coherence-settling.ts` —
    `computeCoherenceSettlingArtifacts(texts, format?)` is the pure core
    (`verifyCoherenceSequence` — the shared parse + hash-verify + cross-ladder guard,
    unchanged — then `computeCoherenceSettling` rendered markdown/JSON);
    `runCoherenceSettling(argv)` is the handler (file IO + exit codes), requiring ≥ 2
    positionals and exiting 2 under `--fail-on-unsettled-exposure` only when the final
    transition crossed the floor. A separate command, not a `coherence-synchrony` flag —
    one gate, one hash. Wired into the `run.ts` dispatcher (`case "coherence-settling"`) +
    USAGE + header doc + unknown-command list.
  - **Verified live end-to-end.** Drove the real CLI over three ladder-pinned artifacts:
    a late cross (`acceptable → acceptable → below`) prints `settling: UNSETTLED — the
    floor was last crossed in round 2→3, the final transition` and exits **2**; an early
    cross (`acceptable → below → below`) prints `settled at round 2 — … then 1 steady step
    to the close` and exits **0** — proving the time axis the per-front/per-step counts
    cannot show.
  - **Additive.** A brand-new subcommand + one pure module — every existing command's
    output and every golden byte-for-byte unchanged; no existing source file's behavior
    changes; no new on-disk format (the settling stays *derived*). +22 tests
    (`src/report/coherence-settling.test.ts` ×14, `tools/cli/coherence-settling.test.ts`
    ×8); suite **3,204 passing + 2 skips** (was 3,182), 211 test files (was 209).
  - **Docs.** New [`docs/spec-v26.md`](docs/spec-v26.md); BUILD_PROGRESS v26 §; README
    "Saved coherence baselines" § extended with the settling workflow + the eight-axis
    summary callout + v26 spec-table row + CLI cheat-sheet + commands-table entry + specs
    list brought current v1–v26.

## [9.22.0] — 2026-06-15 — Document-free exposure synchrony / per-round floor crossings (spec-v25)

### Added
- **A `coherence-synchrony` headless subcommand — the per-round-transition count of
  how many fronts crossed the floor *together*, the per-step transpose of v24's
  per-front crossing count (spec-v25).** v24 (`coherence-volatility`) reads the
  N-round archive *down the front axis*: per front, how many times its standing
  crossed the floor *across the whole deal* (`crossings`). v22 (`coherence-breadth`)
  reads it *down the round axis*, but only on the *level*: per round, how many fronts
  sat *below* the floor (a static standing). Neither reads the archive down the round
  axis on the *movement*: per round-**transition**, how many fronts *crossed* the
  floor in the **same step**. So a deal lead can learn "the Cap front crossed the
  floor twice over the deal" (v24) and "four fronts were below floor in round 3" (v22)
  but not "round 1→2 is where the package **lurched** — two fronts crossed the floor
  at once." A deal with no single *volatile* front (each front crossed at most once)
  can still have a round where several fronts crossed *together* — a coordinated shift
  v24's per-front sum structurally cannot pose, because it slices the crossings by
  front, not by step. v25 supplies the missing axis: re-bucket the **same** floor
  crossings v24 counts — by *step* instead of by *front*.
  - **The synchrony (pure).** `src/report/coherence-synchrony.ts` —
    `computeCoherenceSynchrony(rounds)` attributes each front's stated floor crossing
    to the transition that reveals it and buckets the crossings *per step*: each
    transition reports `crossing_fronts` (the count), `crossed_dimensions` (which
    fronts, `localeCompare`-pinned), and a `synchrony` class — `synchronized` (≥ 2
    fronts crossed at once), `isolated` (exactly 1), `quiet` (0). The series carries
    `peak_transition`/`peak_count` (the single step the most fronts crossed together,
    earliest on a tie), `synchronized_count` (the gate-worthy count of synchronized
    steps), and `total_crossings` — equal by construction to the sum of every front's
    v24 `crossings` (v25 is the literal transpose: the same crossings sliced by step).
    `exposureSynchronized(synchrony)` = `synchronized_count > 0` — the *co-movement*
    gate predicate, distinct from `exposureVolatile` (a single front crossing ≥ 2 times
    across the deal) and `exposureWidened` (the below-floor count grew first→latest).
    **Honest by construction (§3):** silence does not count as a crossing and a crossing
    across a silent gap is attributed to the transition into the round that *reveals*
    the new standing — never to the silent step (`below → unstated → acceptable` is one
    crossing on the step ending at the third round; `below → unstated → below` is zero).
    **Distinct from v17's whipsaw:** an above-floor jitter (`acceptable → ideal →
    acceptable`) is all-`quiet` (zero floor crossings) to v25. Carries a namespaced
    `synchrony_hash` (SHA-256, apart from every other hash). `buildCoherenceSynchronyJson`
    (`schema: vaulytica.posture-synchrony.v1`) + `renderCoherenceSynchronySummary` (peak
    step + synchronized-step count, then one line per step). **Zero changes to any
    existing source file** — v25 imports only the already-public `PostureCoherence`/
    `NegotiationTier` types and the shared hashing helpers.
  - **The command (headless).** `tools/cli/coherence-synchrony.ts` —
    `computeCoherenceSynchronyArtifacts(texts, format?)` is the pure core
    (`verifyCoherenceSequence` — the shared parse + hash-verify + cross-ladder guard,
    unchanged — then `computeCoherenceSynchrony` rendered markdown/JSON);
    `runCoherenceSynchrony(argv)` is the handler (file IO + exit codes), requiring ≥ 2
    positionals and exiting 2 under `--fail-on-synchronized-exposure` only when a single
    step crossed the floor with two or more fronts at once. A separate command, not a
    `coherence-volatility` flag — one gate, one hash. Wired into the `run.ts` dispatcher
    (`case "coherence-synchrony"`) + USAGE + header doc + unknown-command list.
  - **Verified live end-to-end.** Drove the real CLI over three ladder-pinned artifacts
    (Cap+Term both fall in round 1→2, Cap recovers in round 2→3): `coherence-synchrony
    --fail-on-synchronized-exposure` prints `peak step: round 1→2 (2 fronts crossed the
    floor at once)`, `⚠ round 1→2: 2 fronts crossed (Cap, Term)`, and exits **2** (the
    lurch), with `total_crossings: 3` matching `coherence-volatility` on the same files
    (Cap 2 + Term 1 = 3) — proving the per-step transpose the per-front count cannot show.
  - **Additive.** A brand-new subcommand + one pure module — every existing command's
    output and every golden byte-for-byte unchanged; no existing source file's behavior
    changes; no new on-disk format (the synchrony stays *derived*). +20 tests
    (`src/report/coherence-synchrony.test.ts` ×12, `tools/cli/coherence-synchrony.test.ts`
    ×8); suite **3,182 passing + 2 skips** (was 3,162), 209 test files (was 207).
  - **Docs.** New [`docs/spec-v25.md`](docs/spec-v25.md); BUILD_PROGRESS v25 §; README
    badge + "Saved coherence baselines" § extended with the synchrony workflow + the
    seven-axis summary callout + v25 spec-table row + CLI cheat-sheet + commands-table
    entry + specs list brought current v1–v25.

## [9.21.0] — 2026-06-15 — Document-free exposure volatility / per-front floor crossings (spec-v24)

### Added
- **A `coherence-volatility` headless subcommand — the per-front count of times a
  front's standing *crossed* the floor, the crossing-count axis v23's episode count
  throws away (spec-v24).** v23 (`coherence-recurrence`) reads the N-round archive on
  the *episode-count* axis: per front, how many *separate* times it fell below the
  acceptable floor (`below_runs`). But an episode count counts only the **entries**
  into below-floor — it is blind to the **recoveries** between them. A front whose
  binding floor reads `below → below → below` (it never moved) and a front that reads
  `acceptable → below → acceptable` (it fell once and **cleanly recovered**) both
  report `below_runs = 1` and `recurrence = single`: the same episode count, the same
  gate — yet the second *crossed the floor twice* (down, then up) and the first never
  crossed it at all. v21 calls the first `open` and the second `resolved` (the current
  *standing*, not the *movement*); v20 calls both `exposed`; v17 nets the second
  `unchanged`. v24 supplies the missing axis: read the same N artifacts per front and
  count the **floor crossings** — every *stated* transition across the floor boundary,
  in either direction (falls **and** recoveries).
  - **The volatility (pure).** `src/report/coherence-volatility.ts` —
    `computeCoherenceVolatility(rounds)` scans each front's `floors[]` and counts every
    stated transition across the floor (`crossings`): zero is `stable` (it stayed on
    one side the whole deal), one is `monotone` (it crossed once, never back), two or
    more is `volatile` (its standing reversed across the floor at least once). Per front
    it reports the floor path, `rounds_below` (for context), `crossings`, and a
    `volatility` class — `volatile` / `monotone` / `stable` / `unstated` (§3) — plus the
    deal's `most_volatile_dimension` / `max_crossings` (the front with the most
    crossings, earliest on a tie) and `volatile_count`. `exposureVolatile` (=
    `volatile_count > 0`) is the gate predicate; JSON (`schema:
    vaulytica.posture-volatility.v1`) + markdown renderers ship beside it. A namespaced
    `volatility_hash` (SHA-256 over the canonical per-front set) keeps it apart from
    every other hash, so computing it moves no golden.
  - **§3 honesty — silence does not count as a crossing.** A round no document states
    is **skipped**: it neither counts as a crossing nor resets the standing. So
    `below → unstated → below` is **zero** crossings (silence keeps the last known
    standing), and `below → unstated → acceptable` is **one** crossing (a real
    recovery, just unstated in the gap round). A front never stated is `unstated`,
    never `volatile`/`monotone`/`stable`.
  - **Distinct from v17's whipsaw.** v17 fires on any improving *and* any regressing
    rung-step *anywhere on the ladder* (including `acceptable → ideal → acceptable`, an
    above-floor jitter that never risks the floor); v24's crossing count is specific to
    the **floor boundary**, so that same above-floor whipsaw is `stable` (zero
    crossings) to v24. v24 isolates instability that matters for exposure from rung
    jitter that never crosses the floor.
  - **The command (headless).** `tools/cli/coherence-volatility.ts` —
    `computeCoherenceVolatilityArtifacts` (pure: hash-verify + cross-ladder guard via
    the **unchanged** `verifyCoherenceSequence` loader the seven trend/exposure/
    persistence/breadth/recurrence commands share, then compute + render) and
    `runCoherenceVolatility` (file IO + exit codes). `--fail-on-volatile-exposure`
    exits **2** when any front's standing crossed the floor two or more times (it
    reversed at least once) — the *instability* counterpart to v23's churn gate and
    v21's current-standing gate, catching the front that bounced even when it ended on
    the right side of the floor, and ignoring the front that sat stably on the wrong
    side. The dispatcher (`tools/cli/run.ts`) gains the `coherence-volatility` case and
    a `USAGE` entry.
  - **Purely additive.** A new subcommand and one pure module that reads the binding
    floor (`weakest_tier`, v12) already in every artifact for the `below-acceptable`
    rung (v10); **no existing source file's behavior changes** and every existing
    command's output and golden is byte-for-byte unchanged. Tests: volatility identity
    disk-vs-in-memory, bounced (2 crossings) vs stuck (0 crossings) — the pair v23
    reports identically as `single`, single-fall (1 crossing, monotone),
    silence-does-not-cross (§3), recovery-across-silence (1 crossing),
    recover-then-relapse (2 crossings), above-floor whipsaw is stable (distinct from
    v17), most-volatile front (earliest on tie), unstated never counted, no-front-ever-
    crossed (max_crossings 0), determinism, ≥2-artifact requirement, cross-ladder
    refusal (naming both rounds), unpinned-v1 note, tamper rejection (round-prefixed),
    gate parity, render + JSON (20 new tests).

### Posture command family (after v24)
The N-round posture archive is now read on **six** orthogonal axes: MOVEMENT (v17
trajectory / v18 shift / v19 arc — which way a front moved), LEVEL (v20 exposure — how
low a front ever got), TIME (v21 persistence — how long a front was down, and is it
still), BREADTH (v22 — the per-round transpose: how many fronts were down each round),
RECURRENCE (v23 — how many *separate times* a front fell), and VOLATILITY (v24 — how
many times a front's standing *crossed* the floor, recoveries included). Each is a
separate command with exactly one gate and one namespaced hash; none changes any
other's behavior.

## [9.20.0] — 2026-06-15 — Document-free exposure recurrence / per-front below-floor episodes (spec-v23)

### Added
- **A `coherence-recurrence` headless subcommand — the per-front count of
  *separate* below-floor episodes, the episode-count axis v21's duration sum
  throws away (spec-v23).** v21 (`coherence-persistence`) reads the N-round archive
  on the *duration* axis: per front, how many rounds it sat below the acceptable
  floor (`rounds_below`) and whether it is *still* down. But `rounds_below` is a
  **sum** — it adds every below-floor round and forgets their *shape*. A front whose
  binding floor reads `below → below → below` (one steady descent) and a front that
  reads `below → acceptable → below` (it fell, **recovered**, and fell **again**)
  both report `rounds_below = 2` and `persistence = open`: the same duration, the
  same standing, the same gate — yet the second is a concession won back and lost,
  churn the first does not have. v17 (`unchanged` net), v20 (same worst point), and
  v22 (blind to *which* front) cannot tell them apart either. v23 supplies the
  missing axis: read the same N artifacts per front and count the maximal contiguous
  below-floor **episodes**.
  - **The recurrence (pure).** `src/report/coherence-recurrence.ts` —
    `computeCoherenceRecurrence(rounds)` scans each front's `floors[]` for maximal
    contiguous below-floor episodes (`below_runs`): one descent is one episode, a
    recover-then-relapse is two, an oscillating front is three or more. Per front it
    reports the floor path, `rounds_below` (the v21 sum, for context), `below_runs`,
    the 1-based round range of each `episodes[]` entry, and a `recurrence` class —
    `recurring` (≥ 2 episodes) / `single` (1) / `none` (stated, never below) /
    `unstated` (§3) — plus the deal's `most_recurrent_dimension` / `max_runs` (the
    front with the most episodes, earliest on a tie) and `recurring_count`.
    `exposureRecurred` (= `recurring_count > 0`) is the gate predicate; JSON
    (`schema: vaulytica.posture-recurrence.v1`) + markdown renderers ship beside it.
    A namespaced `recurrence_hash` (SHA-256 over the canonical per-front set) keeps
    it apart from every other hash, so computing it moves no golden.
  - **§3 honesty — silence does not split an episode.** A round no document states
    does **not** end a below-floor episode: per the v21 contract that current
    standing reads the latest *stated* round, silence after an exposure keeps the
    last known standing — it is neither a recovery nor a fresh fall. So
    `below → unstated → below` is **one** episode (not a false recurrence); only a
    *stated* at-or-above-floor round (a real recovery) splits one. A front never
    stated is `unstated`, never `recurring`/`single`/`none`.
  - **The command (headless).** `tools/cli/coherence-recurrence.ts` —
    `computeCoherenceRecurrenceArtifacts` (pure: hash-verify + cross-ladder guard
    via the **unchanged** `verifyCoherenceSequence` loader the six trend/exposure/
    persistence/breadth commands share, then compute + render) and
    `runCoherenceRecurrence` (file IO + exit codes). `--fail-on-recurring-exposure`
    exits **2** when any front fell below floor in two or more separate episodes (it
    recovered and relapsed) — the *churn* counterpart to v21's current-standing gate
    and v20's ever gate, catching the unstable front the other side keeps re-opening
    even after its latest stated floor has recovered. The dispatcher (`tools/cli/run.ts`)
    gains the `coherence-recurrence` case and a `USAGE` entry.
  - **Purely additive.** A new subcommand and one pure module that reads the binding
    floor (`weakest_tier`, v12) already in every artifact for the `below-acceptable`
    rung (v10); **no existing source file's behavior changes** and every existing
    command's output and golden is byte-for-byte unchanged. Tests: recurrence
    identity disk-vs-in-memory, recover-then-relapse vs steady descent (the pair v21
    reports identically), silence-does-not-split (§3), stated-recovery-does-split,
    recurred-then-resolved still trips, single-still-open does not, most-recurrent
    front (earliest on tie), unstated never counted, determinism, ≥2-artifact
    requirement, cross-ladder refusal (naming both rounds), unpinned-v1 note, tamper
    rejection (round-prefixed), gate parity, render + JSON (19 new tests).

### Posture command family (after v23)
The N-round posture archive is now read on **five** orthogonal axes: MOVEMENT
(v17 trajectory / v18 shift / v19 arc — which way a front moved), LEVEL (v20
exposure — how low a front ever got), TIME (v21 persistence — how long a front was
down, and is it still), BREADTH (v22 — the per-round transpose: how many fronts were
down each round), and RECURRENCE (v23 — how many *separate times* a front fell). Each
is a separate command with exactly one gate and one namespaced hash; none changes any
other's behavior.

## [9.19.0] — 2026-06-15 — Document-free exposure breadth / per-round deal standing (spec-v22)

### Added
- **A `coherence-breadth` headless subcommand — the whole-deal *per-round*
  standing across all fronts, the transpose axis every command v16–v21 skipped
  (spec-v22).** Every posture command from v16 to v21 reads the N-round archive
  *down the front axis*: pick a front, summarize its history across rounds (v17
  which way it moved, v20 how low it got, v21 how long it was down). None reads it
  *down the round axis*: pick a round, summarize the whole deal across fronts. So
  from the archive a deal lead can answer "is the Cap front still below floor?"
  (v21) but not "how many fronts were below floor in round 3, and was that the
  worst the package ever looked?" — to learn it from v20/v21 a consumer must read
  every per-front row and re-tabulate the `floors[]` columns by hand. v22 supplies
  the transpose: read the same N artifacts not per-front-across-rounds but
  per-round-across-fronts.
  - **The breadth (pure).** `src/report/coherence-breadth.ts` —
    `computeCoherenceBreadth(rounds)` counts, *per round*, the fronts whose binding
    floor (`weakest_tier`, v12) is the `below-acceptable` rung (v10), reporting per
    round `exposed_fronts`, `stated_fronts` (the denominator), and
    `exposed_dimensions` (the below-floor fronts, pinned by `localeCompare`), plus
    the deal's `worst_round`/`worst_count` (the round with the most fronts below
    floor at once, earliest on a tie), `first_count`/`latest_count`, and `widened`
    (`latest_count > first_count`). Carries a namespaced `breadth_hash` (SHA-256
    over the canonical per-round set — apart from every `coherence_hash`,
    `movement_hash`, `trajectory_hash`, `shift_trajectory_hash`, `arc_hash`,
    `exposure_hash`, and `persistence_hash`). `exposureWidened(breadth)` =
    `breadth.widened` — the deal-level breadth-trend gate predicate; unlike
    `exposureBreached` (any single front *ever* below floor) and `exposureOpen`
    (any single front *still* below floor), this fires on the *aggregate trend*:
    the package ended with more fronts below floor than it started. §3-honest: a
    front no document states in a round is not counted as below floor that round
    (silence is not exposure); `stated_fronts` gives the denominator.
    `buildCoherenceBreadthJson` (`schema: vaulytica.posture-breadth.v1`) +
    `renderCoherenceBreadthSummary` (widen/narrow/hold trend + worst round + one
    line per round).
  - **The command (headless).** `tools/cli/coherence-breadth.ts` —
    `computeCoherenceBreadthArtifacts(texts, format?)` is the pure core
    (`verifyCoherenceSequence` shared parse + hash-verify + cross-ladder guard,
    unchanged from v18–v21, then `computeCoherenceBreadth` rendered markdown or
    JSON), and `runCoherenceBreadth(argv)` is the handler (file IO + exit codes);
    requires ≥2 positionals; under `--fail-on-widening-exposure` exits 2 only when
    the latest round has strictly more fronts below floor than the first. A
    separate command, not a flag on a per-front command — each keeps one gate, one
    hash. Wired into the `run.ts` dispatcher (`case "coherence-breadth"`) + USAGE +
    header + unknown-command list.
  - **Verified live end-to-end.** Three ladder-pinned artifacts where the deal
    widens (round 1: Cap below floor → round 3: Cap + Risk + Indemnity below
    floor): `coherence-breadth --fail-on-widening-exposure` prints the per-round
    series `1 → 2 → 3 fronts below floor`, names `worst round: round 3`, and exits
    **2** (the package broadened), while `coherence-persistence` on the same files
    lists three open fronts but cannot show the per-round breadth trend without
    manual transposition — proving the new axis the per-front commands miss.
  - **Additive.** A brand-new subcommand + one pure module — every existing
    command's output (`analyze`/`diff`/`compare`/`compare-coherence`/
    `coherence-trend`/`coherence-shift-trend`/`coherence-arc`/`coherence-exposure`/
    `coherence-persistence`/`verify`) and every golden byte-for-byte unchanged; no
    existing source file's behavior changes; no new on-disk format (the breadth
    stays derived). +18 tests; suite 3,105 → 3,123 passing (+2 skips), 201 → 203
    test files. New [`docs/spec-v22.md`](docs/spec-v22.md). The posture matrix now
    has four axes: movement (v16–v19), level (v20), time (v21), and breadth (v22).

## [9.18.0] — 2026-06-15 — Document-free exposure persistence / current standing (spec-v21)

### Added
- **A `coherence-persistence` headless subcommand — the whole-deal below-floor
  *duration* and *current standing*, the orthogonal *time* axis v20's level view
  never read (spec-v21).** v20's `coherence-exposure` reads the posture archive
  for the *worst* binding floor each front ever reached (its low-water mark). But
  a low-water mark is a single extreme with no memory of time: a front that dipped
  to `below-acceptable` in round 2 and **recovered** to `acceptable` by round 4
  carries the same `worst_floor`/`exposed` as a front **still** below floor in the
  latest round — and v20's `--fail-on-exposure` fires on both, *forever* (the
  worst point never changes once it has happened), so a team that resolved a dip
  cannot make the gate go green. v21 reads the same N artifacts on the *duration*
  axis: not "how low did it get" but "how long was it down, and is it still down?"
  - **The persistence (pure).** `src/report/coherence-persistence.ts` —
    `computeCoherencePersistence(rounds)` matches fronts by dimension (pinned by
    the same `localeCompare` the trajectory/exposure functions use), scans each
    front's binding floors (`weakest_tier`, v12) for the `below-acceptable` rung
    (v10), and reports per front the `floors[]` sequence, `rounds_below` (count of
    rounds below floor), `first_below_round`/`last_below_round` (the span),
    `last_stated_round`, `currently_below` (latest *stated* floor is below floor),
    and a `persistence` class — `open` (still below floor), `resolved`
    (recovered), `none` (never below floor), `unstated` (never stated). Carries a
    `class_counts` tally, an `open_count`, and a namespaced `persistence_hash`
    (apart from every `coherence_hash`/`movement_hash`/`trajectory_hash`/
    `shift_trajectory_hash`/`arc_hash`/`exposure_hash`). `exposureOpen` =
    `open_count > 0` — the *current-standing* gate predicate that **clears when a
    front recovers**, unlike v20's ever-below gate. Honest by construction: a
    front no document ever states is `unstated`, never flagged; current standing
    reads the latest *stated* round, so silence after an exposure keeps the last
    *known* standing — neither an invented recovery nor a fresh exposure (§3).
    `buildCoherencePersistenceJson` (`schema: vaulytica.posture-persistence.v1`) +
    `renderCoherencePersistenceSummary` (class tally + open-front count, then one
    line per open front and one per resolved front). **Zero new posture math
    beyond a count and a last-stated lookup, and zero changes to any existing
    source file** — v21 imports only the unchanged `verifyCoherenceSequence`
    loader and a plain `below-acceptable` literal.
  - **The command.** `tools/cli/coherence-persistence.ts` —
    `computeCoherencePersistenceArtifacts(texts, format?)` is the pure core
    (shared parse + hash-verify + cross-ladder guard via
    `verifyCoherenceSequence`, then `computeCoherencePersistence` rendered
    markdown/JSON), returning `{ok, output, open, ladderNote}`.
    `runCoherencePersistence(argv)` is the handler; requires ≥2 positionals; under
    `--fail-on-open-exposure` exits 2 only when a front is *still* below floor at
    its latest stated round. A *separate* command, not a `coherence-exposure`
    flag — each command keeps one gate, one hash. Wired into the run.ts dispatcher
    (`case "coherence-persistence"`) + USAGE + header doc + unknown-command list.
  - **Additive:** a brand-new subcommand + one pure module — every existing
    command's output (analyze/diff/compare/compare-coherence/coherence-trend/
    coherence-shift-trend/coherence-arc/coherence-exposure/verify) and every
    golden byte-for-byte unchanged; no existing source file's behavior changes;
    the persistence stays *derived* (no new on-disk format). +20 tests. New
    [`docs/spec-v21.md`](docs/spec-v21.md); BUILD_PROGRESS v21 §; README extended
    with the persistence workflow + v21 spec-table row + CLI cheat-sheet +
    commands-table entry + specs list brought current v1–v21. Version 9.17.0 →
    9.18.0.

## [9.17.0] — 2026-06-15 — Document-free posture exposure / low-water mark (spec-v20)

### Added
- **A `coherence-exposure` headless subcommand — the whole-deal binding-floor
  *low-water mark*, the orthogonal *level* axis the movement family never read
  (spec-v20).** Every posture command from v10 to v19 reports *movement* — how a
  rung, a binding floor, or a coherence kind *changed* between rounds. That axis
  has a structural blind spot: a front sitting at `below-acceptable` in **every**
  round never *moves*, so v17's `coherence-trend` calls it `flat`, the summary
  omits it, and `--fail-on-coherence-regression` never fires (a floor only
  "regresses" when it changes to a *worse* rung — one born at the bottom never
  did). Yet it is the most exposed front in the deal. v20 reads the same N
  artifacts on the *level* axis: not "which way did the floor move" but "how low
  did it ever get."
  - **The low-water mark (pure).** `src/report/coherence-exposure.ts` —
    `compareCoherenceExposure(rounds)` matches fronts by dimension (pinned by the
    same `localeCompare` the trajectory functions use), takes a per-front
    **minimum** over the shared `TIER_RANK` (v11/v13) over the binding floor
    (`weakest_tier`) v12 already derives, and reports per front the `floors[]`
    sequence, the `worst_floor` (lowest-ranked stated rung, or `null` when never
    stated), the `worst_round` (1-based index it first fell there), `rounds_stated`,
    and an `exposed` flag (`worst_floor === "below-acceptable"`). Carries a
    `worst_counts` tally, an `exposed_count`, and a namespaced `exposure_hash`
    (apart from every `coherence_hash`/`movement_hash`/`trajectory_hash`/
    `shift_trajectory_hash`/`arc_hash`). `exposureBreached` = `exposed_count > 0`
    — the *level* gate predicate no movement command exposes. Honest by
    construction: a front no document ever states is `unstated`, counted but never
    flagged (silence is not below-floor, §3). `buildCoherenceExposureJson`
    (`schema: vaulytica.posture-exposure.v1`) + `renderCoherenceExposureSummary`
    (worst-level tally + exposed-front count, then one line per exposed front with
    its floor path and first-below-floor round). **Zero new posture math beyond a
    minimum over ranks, and zero changes to any existing source file** — v20
    imports only already-public functions (`TIER_RANK`, `weakest_tier`) and the
    unchanged `verifyCoherenceSequence` loader.
  - **The command.** `tools/cli/coherence-exposure.ts` —
    `compareCoherenceExposureArtifacts(texts, format?)` is the pure core (shared
    parse + hash-verify + cross-ladder guard via `verifyCoherenceSequence`, then
    `compareCoherenceExposure` rendered markdown/JSON), returning `{ok, output,
    breached, ladderNote}`. `runCoherenceExposure(argv)` is the handler; requires
    ≥2 positionals; under `--fail-on-exposure` exits 2 when any front sat below the
    acceptable floor at any round. A *separate* command, not a `coherence-trend`
    flag — each command keeps one gate, one hash. Wired into the run.ts dispatcher
    (`case "coherence-exposure"`) + USAGE + header doc + unknown-command list.
  - **Additive:** a brand-new subcommand + one pure module — every existing
    command's output (analyze/diff/compare/compare-coherence/coherence-trend/
    coherence-shift-trend/coherence-arc/verify) and every golden byte-for-byte
    unchanged; no existing source file's behavior changes; the exposure stays
    *derived* (no new on-disk format). +17 tests. New [`docs/spec-v20.md`](docs/spec-v20.md);
    BUILD_PROGRESS v20 §; README "Saved coherence baselines" § extended with the
    exposure workflow + v20 spec-table row + CLI cheat-sheet + commands-table
    entry + specs list brought current v1–v20. Version 9.16.0 → 9.17.0.

## [9.16.0] — 2026-06-15 — Document-free combined posture arc (spec-v19)

### Added
- **A `coherence-arc` headless subcommand — the v13 per-front combined view
  (binding floor *and* fracture/reconcile, in one report), generalized to N
  rounds and read from the archive alone (spec-v19, building v18 Part XVII open
  question #2).** v17's `coherence-trend` reads N archived coherence artifacts on
  the binding-*floor* axis; v18's `coherence-shift-trend` reads the same N on the
  *agreement* axis. But v13 — the two-round movement both descend from — never
  split those axes: it reports both `floor_movement` and `coherence_shift` per
  front, because a deal lead reconciling a package reads them together (*did this
  front erode, and did it also fracture? did the floor hold while the package
  quietly split? did anything go wrong on either axis?*). v19 restores that
  combined view for the N-round, document-free case, with one deal-level gate.
  - **The join (pure).** `src/report/coherence-arc.ts` —
    `compareCoherenceArc(rounds)` runs the two existing pure trajectory functions
    (`compareCoherenceTrajectory` from v17, `compareCoherenceShiftTrajectory` from
    v18) on the same rounds and joins their per-front results **positionally** on
    `dimension` (both pin fronts by the same `localeCompare`, so the arrays align
    index-for-index; a defensive dimension-equality check makes a broken join
    loud). Each `CoherenceArcFront` carries the floor fields (`floors`, `steps`,
    `net_floor_movement`, `trajectory`), the shift fields (`shifts`, `net_shift`,
    `shift_trajectory`), and the shared `coherences[]` sequence once. The arc
    carries all four count objects, the two component fingerprints **verbatim**
    (`trajectory_hash`, `shift_trajectory_hash` — byte-identical to what the two
    single-axis commands emit on the same inputs), and a namespaced `arc_hash` =
    SHA-256 over `{ trajectory_hash, shift_trajectory_hash }`.
    `arcRegressedOrFractured(arc)` is the combined gate predicate =
    `trajectoryRegressed(floor) || shiftTrajectoryFractured(shift)` — the
    deal-level "did anything go wrong on either axis" verdict neither single-axis
    command exposes. **Zero new posture math:** v19 composes two existing pure
    functions and needs nothing newly exported.
  - **The command.** `tools/cli/coherence-arc.ts` —
    `compareCoherenceArcArtifacts(texts, format?)` is the pure CLI core: it
    verifies all N artifacts and runs the v15/v16 cross-ladder guard across the
    whole sequence via the **shared `verifyCoherenceSequence` loader (unchanged
    from v18)**, then computes and renders the arc (markdown summary or
    `--format json`, `schema: vaulytica.posture-arc.v1`). `runCoherenceArc(argv)`
    is the handler: it reads the N files, prints the arc, and — under
    `--fail-on-regression-or-fracture` — exits 2 on a regression-or-fracture. A
    malformed/tampered round is a hard exit-1 error, prefixed `round N:`; a
    cross-ladder pair is refused, naming the two rounds; an unpinned (`v1`)
    artifact proceeds with a note. Dispatcher + `USAGE` wired.
  - **Not a flag on `coherence-trend`.** v18 Part XVI deferred a
    `coherence-trend --with-shift` flag precisely to keep that command
    single-purpose (one gate, one hash). v19 honors that: it is a separate
    command whose single purpose is the combined view, with its own single gate
    and its own single hash. The two single-axis commands are byte-for-byte
    unchanged in output and goldens.
  - **Tests (+17).** Arc identity disk-vs-in-memory; front-for-front join against
    the two single-axis trajectories; component-hash equality (the arc's
    `trajectory_hash`/`shift_trajectory_hash` equal the two commands' output
    byte-for-byte, cross-checked end-to-end); combined-gate parity
    (`= trajectoryRegressed || shiftTrajectoryFractured`); floor-only trip
    (regress while the package stays aligned); shift-only trip (fracture while the
    floor holds flat); both-quiet no-trip; determinism; ≥2-artifact requirement;
    cross-ladder refusal across the sequence (naming both rounds); unpinned-`v1`
    note; tamper rejection (round-prefixed); flat-and-stable front omitted from
    the summary. Every existing command's suite passes unchanged.

### Changed
- Nothing in existing behavior. v19 is purely additive — a new subcommand and one
  pure module that composes two existing pure functions; **no existing source
  file's behavior changes.** Every existing surface (`analyze`, `diff`, `compare`,
  `compare-coherence`, `coherence-trend`, `coherence-shift-trend`, `verify`) is
  byte-for-byte unchanged in output and goldens.

## [9.15.0] — 2026-06-15 — Document-free coherence-shift trajectory (spec-v18)

### Added
- **A `coherence-shift-trend` headless subcommand — the fracture/reconcile
  companion to v17's floor trajectory — that walks the same N ≥ 2 saved coherence
  artifacts and reports each front's *agreement* path across the whole
  negotiation (spec-v18, building v17 Part XVII open question #2).** v17's
  `coherence-trend` answers "did each front's binding *floor* climb, slide, or
  whipsaw?" — but the floor was never the only signal. Since v13, every
  cross-document movement has carried a second axis: did the package **fracture**
  (documents that agreed now disagree) or **reconcile** (a divergent front closed
  up)? A bundle can hold its floor steady while quietly fracturing, and that
  fracture is what a deal lead reconciling a multi-document package needs to see.
  v16/v17 archived each round's coherence kind but classified the trajectory on
  the floor only; v18 classifies the trajectory on that second axis.
  - **The classifier (pure).** `src/report/coherence-shift-trajectory.ts` —
    `compareCoherenceShiftTrajectory(rounds)` matches fronts by dimension across
    the union of all N coherences (pinned by `localeCompare`), builds each front's
    coherence kind at every round, classifies each consecutive step with the
    shared v13 `classifyShift` (now **exported** from `coherence-movement.ts` — no
    behavior change), computes the **net** shift (round 1 → round N), and reduces
    the steps to a `CoherenceShiftTrajectoryKind`: `steady-fracture` (≥1 fractured,
    0 reconciled steps) · `steady-reconcile` (≥1 reconciled, 0 fractured) ·
    `oscillating` (both directions — split apart and re-merge) · `stable` (no
    directional shift — a realign-only or appear-only front is `stable`, never a
    false oscillation, per §3 honesty). Carries a `shift_trajectory_hash`
    namespaced apart from every `coherence_hash`/`movement_hash`/`trajectory_hash`.
    `shiftTrajectoryFractured` is the gate predicate — true when any front is
    `steady-fracture` or `oscillating` (the package fractured at *some* step), the
    fracture/reconcile companion to v17's `trajectoryRegressed`.
  - **The command.** `tools/cli/coherence-shift-trend.ts` —
    `compareCoherenceShiftTrendArtifacts(texts, format?)` is the pure CLI core: it
    verifies all N artifacts and runs the v15/v16 cross-ladder guard across the
    whole sequence via the shared loader, then computes and renders the shift
    trajectory (markdown summary or `--format json`,
    `schema: vaulytica.posture-shift-trajectory.v1`). `runCoherenceShiftTrend`
    does the file IO and exit codes; `--fail-on-fracture` exits 2 when the package
    fractured at any round. A tampered round (errors prefixed `round N:`) or a
    cross-ladder pair (naming both rounds) is a hard exit-1 error.
  - **A shared sequence loader.** `tools/cli/coherence-sequence.ts` —
    `verifyCoherenceSequence(texts)` factors the parse + hash-verify +
    cross-ladder guard out of `coherence-trend.ts` so both trend commands share
    one verified-input path; `coherence-trend`'s output, errors, and exit codes
    are unchanged (its full test suite passes as-is).
  - **End-to-end demonstration.** A package that goes `aligned → divergent →
    aligned` across three rounds reads `net unchanged` (a first-vs-last diff hides
    the mid-deal fracture), but `coherence-shift-trend` classifies it
    `oscillating` and `--fail-on-fracture` exits 2 — the fracture/reconcile analog
    of v17's whipsaw gate.

### Unchanged (the five promises, re-verified)
- Deterministic (`shift_trajectory_hash` reproducible from the N artifacts on any
  machine), no AI, no server (N local files in, one summary out), citable (the
  artifacts carry v12's per-front coherence kinds — v18 adds no new claim), never
  drafts. Purely additive: a new subcommand and one pure module, plus a
  behavior-preserving loader extraction. Every existing command's output and
  golden is byte-for-byte unchanged; `coherence-movement.ts` changes only by
  exporting an existing function. Tests: **3,051** (was 3,035 — +16 across the new
  module and CLI suites).

## [9.14.0] — 2026-06-15 — Document-free coherence trajectory (spec-v17)

### Added
- **A `coherence-trend` headless subcommand that walks N ≥ 2 saved coherence
  artifacts and reports each front's binding-floor trajectory across the whole
  negotiation (spec-v17, building v16's explicitly-deferred sequence walker into
  the command that adds the signal pairwise diffs cannot).** v16's
  `compare-coherence` answers "round 3 → round 4." It cannot answer the question
  a deal lead asks across a long negotiation: *did the cap's binding floor climb
  steadily, erode steadily, or whipsaw — dip below floor mid-deal and recover?*
  A first-vs-last diff reports a recovered dip as `unchanged` and hides it; N−1
  independent pairwise diffs never say "this front moved in both directions
  across the deal." v17 walks the sequence as one object and classifies each
  front's path — the same relationship v11's trajectory has to v10's snapshot.
  - **The classifier (pure).** `src/report/coherence-trajectory.ts` —
    `compareCoherenceTrajectory(rounds)` matches fronts by dimension across the
    union of all N coherences (pinned by `localeCompare`), builds each front's
    floor and coherence kind at every round, classifies each consecutive step
    with the shared v11/v13 `classifyFloorMovement` (now **exported** from
    `coherence-movement.ts` — no behavior change), computes the **net** movement
    (round 1 → round N), and reduces the steps to a `FloorTrajectoryKind`:
    `steady-improvement` (≥1 improved, 0 regressed steps) · `steady-regression`
    (≥1 regressed, 0 improved) · `whipsaw` (both directions) · `flat` (no ranked
    movement — an appear-only or drop-only front is `flat`, never a false
    whipsaw, per §3 honesty). Carries a `trajectory_hash` namespaced apart from
    every `coherence_hash`/`movement_hash`. `trajectoryRegressed` is the gate
    predicate — true when any front is `steady-regression` or `whipsaw` (the
    floor regressed at *some* step), the faithful multi-round generalization of
    v13's `coherenceRegressed`.
  - **The command.** `tools/cli/coherence-trend.ts` —
    `compareCoherenceTrendArtifacts(texts, format?)` is the pure CLI core: it
    verifies all N artifacts (a tampered/corrupt round is a hard error, prefixed
    `round N:`), runs the v15/v16 cross-ladder guard across the **whole sequence**
    (any two ladder-pinned rounds with differing pins → refused, naming both
    rounds; any unpinned round → proceeds with a note), computes the trajectory,
    and renders the markdown summary (default) or its structured JSON
    (`schema: vaulytica.posture-trajectory.v1`). `runCoherenceTrend` is the
    handler: file IO + exit codes. Requires ≥ 2 artifacts (a single coherence has
    no trajectory). `--fail-on-coherence-regression` exits 2 on a floor that
    regressed at **any** step — strictly stronger than a first-vs-last diff, so a
    transient below-floor dip trips the gate even when the front recovered. The
    disk-sequence trajectory is byte-identical to the in-memory one (proven by
    test).
  - **Additive.** A brand-new subcommand + one pure module — every existing
    command (`analyze`, `diff`, `compare`, `compare-coherence`, `verify`) and
    every golden is byte-for-byte unchanged; `coherence-movement.ts` changes only
    by *exporting* an existing private function. No new posture math and no new
    on-disk format: the trajectory stays derived, recomputed on demand from the N
    auditable, ladder-pinned, hash-verified coherence inputs. 15 new tests
    (whipsaw detection, steady-improvement/regression, flat-on-appear-only,
    determinism, ≥2-artifact requirement, cross-ladder refusal naming both rounds,
    unpinned-v1 note, round-prefixed tamper rejection, gate-predicate parity).
    Suite 3,020 → 3,035.

## [9.13.0] — 2026-06-15 — Document-free coherence movement (spec-v16)

### Added
- **A `compare-coherence` headless subcommand that diffs two saved coherence
  artifacts with no documents on either side (spec-v16, building v14 Open
  Question #2 / the v15 "recompute from two coherence artifacts" deferral into
  the command that does it).** v14 let round one emit its coherence so round two
  could gate without round one's documents on disk — but round two still
  re-analyzed *its own* documents. v16 removes the documents from **both** sides:
  archive each round's kilobyte coherence artifact (from `analyze --posture
  --emit-coherence`), then `vaulytica compare-coherence round1.coherence.json
  round2.coherence.json` shows or gates the round-over-round binding-floor
  movement from the archive alone — no clause text, no re-ingestion, no engine
  run. The use case is a dashboard or audit log that stores each negotiation
  round's coherence and shows the delta without re-analysis.
  - **The command.** `compareCoherenceArtifacts(baseText, revisedText, format?)`
    is the pure, IO-free core: it verifies both artifacts via
    `parsePostureCoherenceJson` (a tampered/corrupt side is a hard error, prefixed
    `base:`/`revised:`), runs the spec-v15 cross-ladder guard **between the two
    artifacts** (both ladder-pinned + equal → verified; both pinned + different →
    refused; either unpinned → proceeds with a note), then diffs them with the
    same pure `compareCoherence` the `--baseline-coherence` path uses and renders
    the v13 movement summary (`--format markdown`, default) or its structured
    JSON (`--format json`). `runCompareCoherence` is the handler: file IO + exit
    codes. `--fail-on-coherence-regression` exits 2 when any front's binding
    floor regressed to a strictly worse stated rung — the same gate contract
    `analyze --fail-on-coherence-regression` ships, now over two artifacts. The
    disk-artifact movement is byte-identical to the in-memory diff (proven by
    test).
  - **Additive.** A brand-new subcommand — every existing command (`analyze`,
    `diff`, `compare`, `verify`) and every golden is byte-for-byte unchanged. No
    new posture math and no new on-disk format: the movement stays derived,
    recomputed on demand from the two auditable, ladder-pinned, hash-verified
    coherence inputs.

### Changed
- `renderCoherenceMovementSummary` moved from `tools/cli/run.ts` to
  `src/report/coherence-movement.ts` (beside its `buildCoherenceMovementJson`
  sibling) so both the `analyze --baseline*` path and `compare-coherence` render
  the movement from one definition with no cross-import between sibling CLI
  modules; `run.ts` re-exports it, so existing importers are unaffected.

## [9.12.0] — 2026-06-15 — Ladder-pinned coherence baselines (spec-v15)

### Added
- **A cross-ladder guard for saved coherence baselines (spec-v15, resolving
  spec-v14 Open Question #1 and the Part XVI "Cross-ladder verification"
  deferral).** v14 made the saved coherence artifact hash-verified for
  *integrity* (a tampered baseline is a hard error). But integrity is not
  identity: nothing stopped a team from gating round two against a baseline
  emitted under a **different playbook ladder**, producing a regression gate
  driven by a movement computed over two unrelated ladders. v15 closes that
  hole — the artifact now fingerprints the ladder its rungs sit on, and the
  consume path refuses a ladder mismatch.
  - **Thrust A — the ladder fingerprint (engine).** `ladderHash(playbook)` in
    `custom-interpreter.ts` is a stable SHA-256 over exactly what determines a
    tier: each negotiation position's `dimension` and its `ideal`/`acceptable`
    predicates (sorted by dimension, machine-independent), plus the named
    `thresholds` those predicates may reference. Per-tier `guidance` is
    **excluded** — advisory negotiation text never changes a document's tier, so
    re-wording it must not invalidate an archived baseline. A playbook with no
    `negotiation_positions` has no ladder and hashes to `null`.
  - **Thrust B — the pinned artifact + guard (headless).** A new
    `vaulytica.posture-coherence.v2` artifact (`COHERENCE_ARTIFACT_SCHEMA_V2`)
    carries a `ladder_hash` alongside the v14 fields. `buildPostureCoherenceJson`
    gained an optional ladder-hash argument: pass it and the artifact is a pinned
    `v2`; omit it and the bytes are byte-identical to v14's `v1`. The
    `ladder_hash` is **independent of `coherence_hash`** (which still covers
    `dimensions` only), so the v1 and v2 artifacts of one coherence share the
    same integrity hash. `parsePostureCoherenceJson` accepts both schemas,
    requires `ladder_hash` on `v2`, rejects a stray `ladder_hash` on `v1`, and
    returns `ladderHash: string | null`. The CLI `--emit-coherence` now pins the
    ladder automatically (the ladder is always present — it requires
    `--posture`/`--playbook-file`); `--baseline-coherence` computes this round's
    `ladderHash` and **refuses with exit 1** on a mismatch
    (`ladder mismatch — the artifact was computed against a different playbook
    ladder …`). A `v1` (unpinned) artifact still loads, with a clear note that
    cross-ladder verification is unavailable (v14's caller-owns-it contract).
  - **Additive.** No ladder hash ⇒ a `v1` artifact byte-identical to v14; the
    parser still accepts `v1`; every existing golden, round-trip, and the
    `compareCoherence`/`coherenceRegressed` math are unchanged. With neither emit
    nor consume flag the CLI is unchanged from v14.

### Changed
- The `analyze` command's `USAGE`/help text now lists `--emit-coherence`,
  `--baseline-coherence`, and the `--baseline`/`--baseline-coherence` mutual
  exclusion (they were wired in v14 but missing from the help block).

## [9.11.0] — 2026-06-14 — Saved coherence baselines (spec-v14)

### Added
- **A portable, hash-verified cross-document posture coherence artifact
  (spec-v14, resolving spec-v13 Open Question #2).** A deal lead can now gate
  round two of a negotiation against round one **without round one's documents
  on disk**. Round one emits its coherence once; round two diffs against the
  saved artifact. The diff is the same pure `compareCoherence` v13 ships — only
  the *source* of the baseline coherence changes.
  - **Thrust A — the artifact (engine).** `buildPostureCoherenceJson(coherence)`
    serializes a `PostureCoherence` to stable, pretty-printed JSON tagged
    `vaulytica.posture-coherence.v1` (the `coherence_hash`, the per-kind
    `counts`, and the full per-front, per-document rung set, in the pinned
    document order). `parsePostureCoherenceJson(text)` is the verifying inverse:
    it structurally validates the file, **re-derives the `coherence_hash` from
    the artifact's own dimensions**, and rejects any mismatch — a corrupted,
    truncated, or hand-edited baseline is a hard, legible error
    (`coherence_hash mismatch …`), never a silent gate input. `counts` is
    recomputed from the verified dimensions on load (the hash covers dimensions
    only). The fingerprint is factored into a single `coherenceHash` helper used
    both to stamp (in `bundlePostureCoherence`) and to verify (in the parser).
  - **Thrust B — emit & consume (headless).** `analyze --posture
    --emit-coherence <path>` writes the round's coherence artifact (a clear
    stderr note, not a silent no-op, when the round yields no cross-document
    coherence). `analyze --posture --baseline-coherence <coherence.json>` diffs
    against a saved, verified coherence instead of re-analyzing a baseline
    bundle (mutually exclusive with `--baseline`). `--fail-on-coherence-regression`
    now accepts **either** baseline source; the exit-2 regressed-binding-floor
    gate is unchanged.
  - **Additive.** Both flags are off by default — with neither set the CLI is
    byte-identical to v13, so every per-document `result_hash`, `coherence_hash`,
    `movement_hash`, and golden is byte-unchanged. A browser/DOCX surface is a
    principled deferral (the artifact is a CI/headless concern; the browser
    already does an in-session two-round comparison via v13 Thrust B).
  - **+8 tests** (suite 2,992 → 3,000 passing + 2 skips): seven coherence-artifact
    unit tests (round-trip identity, hash integrity, tamper rejection,
    wrong-schema rejection, malformed-JSON/non-object rejection, invalid
    tier/kind rejection, count recomputation) and one CLI integration test
    proving a disk-round-tripped coherence yields the same `movement_hash` as the
    in-memory `--baseline` diff. New [`docs/spec-v14.md`](docs/spec-v14.md).

## [9.10.1] — 2026-06-13 — Mobile overflow hardening (download status + uncovered-state line)

### Fixed
- **Long, space-free filenames no longer push the result card past the viewport
  on a narrow phone.** The post-download status line (`.download-status`) is
  filled by `saveBlob` with `Saved <filename>`, where the filename derives from
  the user's upload — names like
  `Master_Services_Agreement_..._FINAL_v12_executed.pdf` have no break
  opportunities. The element lacked `overflow-wrap`, so on a 320px screen the
  status text widened the card and reintroduced horizontal scroll (a regression
  the static-render `responsiveness-states` e2e never caught, since it renders
  states before any download has populated the line). Added
  `overflow-wrap: anywhere` to `.download-status`, and a dedicated e2e that
  injects the worst-case `Saved <long-filename>` text and re-asserts
  vertical-scroll-only at 320 / 390 / 768 / 1280px.
- **Jurisdiction "no overlay on file" line now wraps.** `.overlay-uncovered`
  (the honest coverage-gap sentence listing uncovered states) gained the same
  `overflow-wrap: anywhere` guard for safety against long state lists.

## [9.10.0] — 2026-06-13 — Cross-document posture movement in the browser + DOCX (spec-v13 Thrusts B & C)

### Added
- **Browser two-round bundle comparison (spec-v13 Thrust B, Step 190).** The
  bundle-complete view grows a "Compare a revised round…" affordance — offered
  only when the round produced a posture coherence (a positions-bearing custom
  playbook was active), exactly as v11's compare row is offered only on a single
  document. Picking the revised round's files re-analyzes them against the
  **same** active playbook, computes its v12 coherence, diffs it against the
  baseline round's via `compareCoherence`, and transitions to a new
  `bundle-comparison-complete` state. The state renders a mobile-safe per-front
  card: the left border reuses the v11 `pm-*` direction palette for the
  binding-floor movement (`Floor improved` / `Floor regressed` / …), and a
  `cm-shift-*` text color names the coherence shift (`Fractured` / `Reconciled` /
  `Realigned`). A floor transition line (`acceptable → below floor`) and the
  coherence-kind transition ride alongside. Advisory throughout — it reports
  where the binding floor that governs exposure moved on the team's own ladder,
  never a legal conclusion or which document legally governs.
- **Two-round deliverable DOCX + JSON (spec-v13 Thrust C, Step 191).** The
  comparison state offers a "Download two-round report (Word)" — the revised
  round's consolidated bundle DOCX with a trailing "Posture Movement (Across the
  Package)" section ([`src/report/bundle.ts`](src/report/bundle.ts)
  `renderPostureMovementSection`): one row per front (Front · Floor movement ·
  Binding floor base→revised · Coherence shift), color-coded by the binding-floor
  movement and carrying the `movement_hash` for verification. A structured
  movement JSON (`buildCoherenceMovementJson`) rides alongside as a second
  download. Both the DOCX section and the JSON are **additive** — threaded only
  when the two-round flow supplies a movement, so every existing per-document
  `result_hash`, `coherence_hash`, and bundle golden is byte-unchanged.

### Quality
- The new `bundle-comparison-complete` view-state is registered in the
  full-`DropzoneState` responsiveness + axe e2e (`responsiveness-states.spec.ts`):
  vertical-scroll-only at 320 / 390 / 768 / 1280 px and zero WCAG 2 AA violations
  in both the dark and light themes. The `cm-shift-*` foreground colors are
  theme-aware (the reconciled green darkens on the light surface) so they clear
  the 4.5:1 contrast floor on each theme.

### Notes
- spec-v13 is now complete end-to-end (Thrust A 9.9.0; Thrusts B & C 9.10.0).
  The fourth corner of the posture matrix — across documents, across versions —
  now has a headless surface, a CI gate, a browser card, and a Word deliverable,
  matching how v10–v12 each landed.

## [9.9.0] — 2026-06-13 — Cross-document posture movement (spec-v13 Thrust A)

### Added
- **Cross-document posture-movement engine (spec-v13 Thrust A, Step 187).** A new
  pure module [`src/report/coherence-movement.ts`](src/report/coherence-movement.ts)
  exports `compareCoherence(base, revised)`: given two v12 `PostureCoherence`
  objects — a deal package at a **base** round and at a **revised** round, both
  classified against the **same** team positions — it reports, per negotiation
  front (matched by **dimension**, not by document, so a `msa-v1.docx` →
  `msa-v2.docx` rename or an added document never confuses it), how the bundle's
  **binding floor** moved (`improved` / `regressed` / `unchanged` /
  `newly-stated` / `now-unstated`, reusing v11's exported `TIER_RANK`) and how
  the **coherence kind** shifted (`fractured` / `reconciled` / `realigned` /
  `unchanged`). Floor- and shift-count tallies and a `movement_hash` namespaced
  apart from every `result_hash`, `posture_hash`, and `coherence_hash`. A
  `coherenceRegressed(movement)` predicate mirrors v11's `postureRegressed` and
  v12's `hasDivergence`. This is the fourth corner of the posture matrix —
  v10 (single doc, single version), v11 (single doc, across versions), v12
  (across docs, single version), v13 (across docs, across versions).
- **Headless cross-round movement (spec-v13 Thrust A, Step 188).** The CLI
  [`analyze`](tools/cli/run.ts) command accepts `--baseline <path|glob|dir>`
  (requires `--posture`): it analyzes the baseline bundle against the **same**
  custom playbook, computes its v12 coherence, diffs it against the primary
  bundle's coherence via `compareCoherence`, and prints a "Cross-document posture
  movement (vs. baseline)" summary — the floor- and shift-count lines, one line
  per front whose floor moved or whose package fractured/reconciled (an unmoved
  front is omitted), and the `movement_hash`. A baseline that yields no coherence
  (fewer than two documents with a posture) is a hard error, not a silent no-op.
- **Coherence-regression CI gate (spec-v13 Thrust A, Step 189).** The CLI
  `analyze` command accepts `--fail-on-coherence-regression` (requires
  `--baseline`): it exits non-zero (code 2) when any front's binding floor moved
  to a strictly worse **stated** rung between the two rounds. The gate is the
  well-ordered floor worsening only; a front that dropped off the ladder
  (`now-unstated`) is reported but never trips it (spec-v13 §3 corollary 2 — a
  dropped front is not conflated with a rung regression; a team that wants to
  gate on it composes from `floor_counts`). Reported alongside `--fail-on` and
  `--fail-on-divergence`; any tripping sets exit 2.

### Notes
- Additive and back-compatible: an `analyze` run with no `--baseline` yields no
  movement, so every per-document `result_hash`, every `posture_hash`, every
  `coherence_hash`, and every bundle golden is byte-identical to 9.8.0.
- The movement is **advisory** (spec-v13 §3): it reports where the bundle's
  binding floor moved on the team's own ladder and whether the package fractured
  or reconciled — never that a term became legally adequate or enforceable, and
  never which document legally governs on a conflict (the v12 §3 corollary-3
  bright line, carried forward).
- Thrust B (a browser-UI two-round bundle card) and Thrust C (a DOCX section) are
  proposed (Steps 190–191); both wait on a two-bundle comparison surface that
  does not yet exist in the browser UI.

## [9.8.0] — 2026-06-13 — Posture coherence in the browser bundle + bundle DOCX (spec-v12 Thrusts B & C)

### Added
- **Per-document posture through the browser bundle pipeline (spec-v12 Thrust B,
  Step 184).** [`prepareBundle`](src/ui/pipeline.ts) now evaluates a v10
  negotiation posture for each document in a bundle when the active custom
  playbook defines `negotiation_positions` — every document classified against
  the **same** positions, independent of the matched built-in playbook that
  drives its per-document engine run (which is untouched). The postures ride on
  `BundlePerDocument.negotiation_posture` (their own `posture_hash`, outside
  every `result_hash`). [`runBundleReport`](src/ui/pipeline.ts) collects them and
  computes a [`bundlePostureCoherence`](src/report/posture-coherence.ts) when
  every document carries one (a bundle is always ≥2 documents).
  [main.ts](src/ui/main.ts) threads the active custom playbook into
  `runBundlePipeline` so the bundle path sees the positions.
- **Bundle-complete "Posture coherence" card (spec-v12 Thrust B, Step 185).** The
  bundle-complete UI state renders a mobile-safe coherence card: the per-kind
  counts (aligned / divergent / stated-by-one / unstated), one card per
  negotiation front showing the rung spread across the documents and the
  **binding floor** (the weakest stated rung + the document carrying it),
  color-coded by a `pc-*` left border (green aligned, red divergent, blue
  stated-by-one, grey unstated) reusing the v10 `np-*` overflow-wrap styles.
  Hidden when no coherence was computed. Verified vertical-scroll-only across
  320–1280px with zero axe WCAG 2 AA violations in both themes.
- **Consolidated bundle DOCX "Posture Coherence" section (spec-v12 Thrust C,
  Step 186).** [`buildBundleDocxReport`](src/report/bundle.ts) renders a trailing,
  optional "Posture Coherence" section: the per-kind counts + a color-coded table
  (Front · Coherence · per-document rung · binding floor). Omitted entirely when
  no `posture_coherence` is supplied, so every existing bundle golden is
  byte-unchanged. Advisory — it names the weakest document but never adjudicates
  which document legally governs on a conflict (spec-v12 §3 corollary 3).

### Notes
- Additive and back-compatible: a bundle run with no active posture playbook
  yields no coherence, so the bundle JSON, the consolidated DOCX, and every
  per-document `result_hash` and bundle golden are byte-identical to 9.7.0.
- In the bundle path the custom playbook contributes **only** its posture
  positions; the per-document engine run is still driven by each document's
  matched built-in playbook, and secondary-family activation continues to run
  for every bundled document (the single-doc "custom mode redefines rule
  semantics" skip does not apply here, since the custom playbook does not drive
  the bundle's engine run).

## [9.7.0] — 2026-06-13 — Cross-document posture coherence (spec-v12 Thrust A)

### Added
- **Cross-document posture coherence engine (spec-v12 Thrust A, Step 181).** A
  new pure module [`src/report/posture-coherence.ts`](src/report/posture-coherence.ts)
  exports `bundlePostureCoherence(documents)`: given one v10 `NegotiationPosture`
  per document — all classified against the **same** team positions — it reports,
  per negotiation front, whether the documents **agree** on the rung (`aligned`),
  **disagree** (`divergent`), are stated by only one (`single`), or stated by
  none (`unstated`). For every stated front it surfaces the **binding floor** —
  the weakest stated rung and the document(s) carrying it — since in a deal
  package the weakest document usually governs exposure. It reuses v11's now-
  exported `TIER_RANK` (so the rung order has one source of truth) and carries
  its own `coherence_hash`, namespaced apart from every document's `result_hash`
  and the bundle fingerprint. `unevaluable` stays unranked: an unstated front is
  never folded into a divergence and never lowers the floor (the spec-v10 §3
  honesty contract). A `hasDivergence(coherence)` predicate mirrors v11's
  `postureRegressed`.
- **Headless coherence over a bundle (spec-v12 Thrust A, Step 182).** The CLI
  `analyze` command, run with `--posture` over a bundle (a directory or glob
  resolving to ≥2 documents), now collects each document's posture and prints a
  "Cross-document posture coherence" summary after the per-document lines: the
  per-kind counts, one ⚠ line per divergent front (the rung spread + the binding
  floor + the document carrying it), and the `coherence_hash`. A single-document
  run emits no coherence (nothing to compare). The per-document JSON/SARIF/HTML
  is unchanged — the coherence is an additive bundle-level summary.
- **Divergence CI gate (spec-v12 Thrust A, Step 183).** The `analyze` command
  gains `--fail-on-divergence` (requires `--posture`): it exits non-zero (code 2)
  when any front is **divergent** — two or more documents stating the same front
  on different rungs. Per the §3 honesty contract the gate is the well-ordered
  spread only: a front only one document states (`single`) or no document states
  (`unstated`) is reported but never trips it. Reported alongside `--fail-on`;
  either tripping sets exit 2.

### Tests
- +15 tests: the coherence engine (every kind, the binding floor, `unevaluable`
  never ranked as the floor, determinism, document-order sensitivity, the
  single-document case, and the `hasDivergence` predicate — 13 tests) and the CLI
  `renderCoherenceSummary` (the counts line, ⚠ only for divergent fronts, the
  `coherence_hash` — 2 tests).

### Docs
- New [`docs/spec-v12.md`](docs/spec-v12.md) — Cross-Document Posture Coherence,
  the v4 cross-document axis of the v10 posture (sibling to v11's version axis).
  Thrust A shipped; the browser-UI bundle card and consolidated-DOCX section are
  proposed as Thrusts B/C (the bundle pipeline does not yet compute per-document
  postures).

## [9.6.0] — 2026-06-13 — Posture-movement CI regression gate (spec-v11 Thrust C)

### Added
- **Posture-movement regression gate (spec-v11 Thrust C, Step 180).** The
  headless `compare` command gains `--fail-on-regression` (requires `--posture`):
  it exits non-zero (code 2) when the posture movement holds any **regressed**
  dimension — a front that moved to a strictly worse rung on the team's own
  ladder. This turns the advisory movement into a hard CI gate, exactly as
  `--fail-on <sev>` does for the introduced-finding bucket; either tripping sets
  exit 2. Per the §3 honesty contract, the gate is the well-ordered rung
  worsening only: `now-unstated` (a term that dropped off the ladder) is reported
  but never trips it — a dropped front is not conflated with a rung regression. A
  team that wants to gate on a dropped term composes it from the JSON
  `posture_movement.counts`. A small exported `postureRegressed(pm)` predicate
  mirrors `introducedBreaches` for testability.

### Tests
- +6 tests: `--fail-on-regression` arg parsing (parses with `--posture`; rejected
  without it; defaults off) and the `postureRegressed` predicate (trips on a
  strict rung worsening; does not trip on improvement / unchanged / newly-stated;
  does not trip on now-unstated).

## [9.5.0] — 2026-06-13 — Posture movement in the Word comparison report (spec-v11 Thrust B)

### Added
- **Posture movement in the Word comparison report (spec-v11 Thrust B, Step
  179).** [`buildComparisonDocx`](src/report/compare-docx.ts) now renders a
  "Posture Movement" section into the DOCX comparison deliverable — the document
  a negotiator hands to a partner. It carries an advisory headline (the movement
  counts), the `movement_hash` for auditability, and a per-dimension table
  (Dimension · Movement · Base · Revised) with the movement cell color-coded
  (green improved / red regressed / amber dropped), reusing the single-document
  posture table's visual contract. The `PostureMovement` is threaded as a
  trailing optional argument (the v9/v10 surface-threading pattern), so the
  section is omitted when no movement is supplied and the page flow plus every
  existing comparison golden are unchanged. (The comparison deliverable is DOCX +
  JSON; there is no standalone-HTML *comparison* report, so Thrust B is DOCX-only
  by construction.)

### Tests
- +2 tests: the section renders every transition (improved / regressed /
  newly-stated / now-unstated), the `movement_hash`, and the short rung labels;
  it is omitted when no movement is supplied.

## [9.4.0] — 2026-06-13 — Negotiation posture movement (spec-v11 Thrust A)

### Added
- **Negotiation posture movement (spec-v11 Thrust A, Steps 176–178).** Extends
  the v10 Negotiation Posture along the v6 version-comparison axis: it reports
  how a team's posture *moved* between two drafts. When a counterparty sends a
  revised draft, the comparison now answers the round-over-round question —
  *which way did each front move?* — without a model and without a server. Fully
  additive: a comparison with no positions yields no movement, and the movement
  carries its own `movement_hash` namespaced apart from the comparison
  `result_hash`, so no existing golden or hash moves.
  - **Movement engine** (Step 176) — `comparePosture(base, revised)`
    ([`src/report/posture-movement.ts`](src/report/posture-movement.ts)): a pure,
    deterministic per-dimension transition classifier — **improved · regressed ·
    unchanged · newly-stated · now-unstated** (plus defensive *appeared /
    disappeared* for mismatched position sets). A single `TIER_RANK` table
    (ideal > acceptable > below-acceptable) decides improved vs. regressed;
    `unevaluable` is deliberately **unranked**, so "not stated" is never compared
    as better or worse than a stated rung — a counter that *adds* a below-floor
    term reads as `newly-stated`, never a false `regressed`.
  - **JSON + tab** (Step 177) — an additive `posture_movement` block in the
    comparison JSON (`buildComparisonJson`, trailing optional argument), and a
    mobile-safe "Posture movement" card in the comparison-complete tab (reuses
    the v10 `np-*` overflow-wrap styles + `pm-*` direction colors). The UI threads
    the base posture and the active custom playbook through `runComparison`, so
    the revised draft is classified against the *same* ladder as the base.
  - **Headless movement** (Step 178) — the CLI `compare` command accepts
    `--playbook-file <path>` + `--posture` (mirroring `analyze`): it classifies
    both drafts against the playbook's `negotiation_positions` and emits a
    `posture_movement` JSON block (or a Markdown table) — a CI redline gate can
    now show how each negotiation front moved between two versions.
- **Docs.** New [`docs/spec-v11.md`](docs/spec-v11.md); README gains a "Posture
  movement" section (with a movement-kind cheat sheet and a Mermaid diagram), a
  v11 row in the version table, and a CLI cheat-sheet entry; the threat model
  notes the new advisory surface.

### Tests
- +17 tests (2,922 → 2,939): the full movement-transition matrix, determinism of
  `movement_hash` (order-independent), the additive comparison-JSON block, CLI
  arg parsing (`--posture` requires `--playbook-file`) and Markdown rendering;
  the comparison-complete responsiveness e2e fixture gains an overflow-prone
  posture-movement card (vertical-scroll-only 320–1280px, WCAG 2 AA, both themes).

## [9.3.0] — 2026-06-13 — Negotiation posture: dimension breadth (spec-v10 Thrust C)

### Added
- **Negotiation posture — dimension breadth (spec-v10 Thrust C, Steps 173–175).**
  Widens the set of negotiable dimensions a `negotiation_position` (or any
  `custom_rule`) can assert on, each **measure-first**: wired only behind an
  extractor fixture proving the extraction is reliable on representative clause
  prose, never guessed. Fully additive — a playbook that does not use the new
  dimensions validates and runs exactly as before; no golden or `result_hash`
  moves.
  - **Temporal metrics** (Step 173) — two new `numeric_threshold` metrics:
    `cure_period_days` (the cure window for a breach) and
    `auto_renewal_notice_days` (the non-renewal notice window), both routed
    through the same `extractMetricValues` path the v6 metrics use.
  - **Financial metrics** (Step 174) — `indemnity_cap_amount` (indemnification
    cap as an absolute amount) and `uptime_sla_percent` (a service-level
    uptime/availability commitment, in percent).
  - **Mutuality predicate** (Step 175) — a new `clause_mutual` predicate kind:
    *is the indemnification / termination / confidentiality clause **mutual** or
    one-way?* It reuses the v6 `findClause` locator (`clause` anchors the
    default location; an explicit `pattern`/`section_heading` overrides it) and
    adds a bounded, deterministic reciprocity-marker scan — no model, no fuzzy
    logic. A located clause carrying "each party" / "both parties" / "mutual" /
    "respective" / … is mutual; one with none is reported one-way; a clause that
    is absent is honestly **unevaluable**, never a false "one-way" (§3 corollary
    2).
  - The published JSON Schema artifact ([`docs/v6/playbook.schema.json`](docs/v6/playbook.schema.json))
    mirrors the four new metrics and the seventh predicate kind, guarded by the
    schema-artifact test. The `acme-saas-buyer` example playbook gains three
    Thrust-C positions (cure period, uptime SLA, indemnification mutuality).
  - +18 tests (measure-first extractor fixtures for all four metrics across
    representative prose; `clause_mutual` compliant/one-way/unevaluable +
    pattern-override; Thrust-C posture ladders; the mutual-clause schema-enum
    guard). Suite 2,904 → 2,922. Version 9.2.0 → 9.3.0.

## [9.2.0] — 2026-06-13 — Negotiation posture: report & export (spec-v10 Thrust B)

### Added
- **Negotiation posture — report & export (spec-v10 Thrust B, Steps 170–172).**
  Deepens the v10 posture from a report *section* into the negotiator's actual
  worksheet, all render-side (**zero `result_hash` churn**):
  - **Standalone negotiation sheet** ([`src/report/negotiation-sheet.ts`](src/report/negotiation-sheet.ts),
    Step 170) — a self-contained, print-clean HTML sheet that regroups the
    positions by **action** rather than dimension: *escalate* (below floor) ·
    *push here* (at the floor) · *verify* (not stated) · *hold* (already ideal),
    in that priority order, so the most urgent fronts are at the top. Author
    strings are HTML-escaped; mobile-safe (an e2e asserts vertical-scroll-only
    at 320–1280px and zero WCAG 2 AA violations).
  - **Markdown + CSV posture export** ([`src/report/exports.ts`](src/report/exports.ts),
    Step 171) — `buildNegotiationPostureMarkdown` (a dimension · tier · finding ·
    guidance · section table) and `buildNegotiationPostureCsv` (RFC 4180 + the
    same formula-injection guard as the fix list, since a position's
    `dimension`/`guidance` is untrusted author text). Both download from the
    complete-state export row.
  - **Headless posture in the CLI** (Step 172) — `vaulytica analyze … --playbook-file <path>`
    loads and validates a custom playbook (a malformed file is a hard error with
    the validator's messages, never a silent no-op), and `--posture` evaluates
    its `negotiation_positions` against the document, printing a summary line
    (`Negotiation posture: N ideal, M acceptable, K below floor, J not stated`)
    and emitting the `negotiation_posture` JSON block — the same deterministic
    classification, in CI or a folder sweep. (Merging the playbook's custom
    *rules* into the headless run is a separate follow-up; `--posture` computes
    the posture only.)
  - +7 tests (Markdown/CSV structure + formula-injection guard; the sheet's
    action grouping + escaping + determinism; CLI posture via `analyzeFile`; the
    sheet responsiveness/a11y e2e). Suite 2,897 → 2,904. Version 9.1.0 → 9.2.0.

## [9.1.0] — 2026-06-13 — Negotiation Posture (spec-v10 Thrust A) + PDF annotations

### Added
- **Negotiation posture — the tiered-position ladder (spec-v10 Thrust A, Steps
  166–169).** Deepens the v6 bring-your-own-playbook axis from binary
  enforcement to a negotiation ladder. A custom playbook can now carry
  `negotiation_positions`: one entry per negotiable dimension, each an `ideal`
  and an `acceptable` predicate drawn from the **same** bounded v6 DSL the
  custom rules use, plus optional per-tier `guidance`. The engine reports which
  rung the draft meets — **ideal · acceptable · below-floor · not-stated** —
  classified **deterministically by the existing `evaluatePredicate`**, so
  there is no new fuzzy logic.
  - Schema: `negotiation_positions` on `CustomPlaybook` (Zod + the published
    [`docs/v6/playbook.schema.json`](docs/v6/playbook.schema.json) artifact),
    backward-compatible (optional field, `schema_version` unchanged). Validation
    rejects a tier clause predicate with neither `pattern` nor `section_heading`
    and a duplicate `dimension`; a posture-only `replace`-mode playbook is now
    valid.
  - Evaluator: `evaluateNegotiationPosture` ([`src/playbooks/custom-interpreter.ts`](src/playbooks/custom-interpreter.ts))
    — monotone (`ideal` strict, `acceptable` the floor); **below-floor only when
    both tiers are evaluable and both fail** (an unstated metric is honestly
    `unevaluable`, never a false walk-away — the v5/v6 honesty contract). Carries
    its own `posture_hash`, namespaced apart from the engine `result_hash`.
  - Surfaces: a `negotiation_posture` JSON block, a "Negotiation Posture"
    section in the DOCX and standalone HTML reports, and a mobile-safe
    "Negotiation posture" card in the complete-state tab — each shown only when
    the active custom playbook defined positions, so a position-free run renders
    identically to before. **Render-side, zero `result_hash` churn.**
  - Advisory, never a legal conclusion: a tier reports where the draft sits on
    the team's **own** ladder, never that a term is enforceable, adequate, or
    market.
  - +14 tests (tier classification across numeric / governing-law / clause
    ladders; schema validation; DOCX/HTML rendering + escaping; the e2e
    responsiveness stress fixture). The `saas-buyer` example playbook gains
    three worked positions. `docs/spec-v10.md` written. Suite 2,883 → 2,897.

- **PDF reviewer-annotation recovery in the pre-disclosure scan (spec-v9 §7).**
  Closes the last v9 Thrust-A deferral: the delivery scan's PDF path read only
  the Info-dictionary metadata and reported markup/comment recovery as a
  documented no-op. It now recovers **reviewer annotations** — sticky notes
  (`/Text`), free-text notes (`/FreeText`), and text markup (`/Highlight`,
  `/Underline`, `/StrikeOut`, `/Squiggly`) — from the **uncompressed** byte
  regions, surfacing each as a `CommentFact` (author from `/T`, a bounded
  excerpt from `/Contents`, literal or hex; a bare mark with no note reports its
  type, e.g. `[highlight]`), so `HANDOFF-002` now fires on a PDF carrying live
  reviewer markup, not just a DOCX. The parser reads the raw bytes (not pdf.js)
  to stay pure, bounded, and **ReDoS-free** (every regex linear; a search window
  clamped to the annotation's own object so a neighbouring object's fields are
  never pulled in); annotations or metadata inside a compressed object stream or
  an encrypted region are still not recovered, and the report's note now states
  that reach honestly rather than implying a clean bill. +4 tests (positive
  recovery, object-boundary isolation, pathological-blob totality/ReDoS guard,
  honest-note wording). Render-side / container-scoped — **zero `result_hash`
  churn**.

- **v9 output-surface completion — the Last Look surfaces now render in every
  report format.** Closes the two engineering-scoped deferrals documented at the
  9.0.0 release (spec-v9 Steps 153/159/163). The delivery (`HANDOFF-*`), closing
  checklist, and critical-dates surfaces previously rendered only in JSON / CLI /
  tab / Markdown / CSV / `.ics`; they now also render in the **DOCX** report, the
  standalone **HTML** report, and **SARIF** — all via a single optional
  `V9Surfaces` bundle ([`src/report/v9-surfaces.ts`](src/report/v9-surfaces.ts)),
  render-side, **zero `result_hash` churn** (each section is omitted when empty,
  so a document with no handoff facts / readiness gaps / derivable dates produces
  a byte-identical v8-era report):
  - **DOCX** — new "Clean to Send", "Ready to Sign — Closing Checklist", and
    "Critical Dates" sections (each a heading + table, omitted when empty).
  - **HTML** — the same three sections as bordered, mobile-safe card lists
    (every cell wraps; the standalone report still scrolls vertically only at
    320–1280px and clears WCAG 2 AA, verified by the deepened
    `html-report-responsive` e2e with overflow-prone v9 content).
  - **SARIF** — `HANDOFF-001…005` and `DATE-001…005` are now first-class SARIF
    `result`s with their own rule descriptors: handoff findings cite the
    container (no text region; `kind: "container"` logical location), derived
    deadlines surface at `note` level anchored to their section, and each carries
    its surface hash (`delivery_hash` / `critical_dates_hash`) as a
    `partialFingerprint` for cross-run dedupe. The output stays conformant
    (`sarifConformanceViolations` green). The closing checklist is a projection
    of findings already emitted, so it is intentionally **not** re-emitted as
    SARIF results.
  - Wired through `runReport` (one `V9Surfaces` bundle threaded into DOCX/HTML/
    SARIF) and the CLI `renderFormat` (`--delivery` / `--checklist` /
    `--critical-dates` now flow into `sarif`/`html` output, not just `json`).
  - +6 unit tests (html/sarif/docx structure + "byte-identical when absent")
    and the deepened HTML-report e2e. Suite 2,874 → 2,880.

## [9.0.0] — 2026-06-12 — The Last Look (spec-v9 complete)

### Added
- **Ready to Sign — execution-readiness reconciliation (spec-v9 Thrust B, Steps 155–159).**
  Deepens the `STRUCT-*` family from *detection* to *reconciliation* — three new
  always-on rules (launch set **112 → 115**), all internal-consistency only
  (they report the gap, never "validly executed"):
  - **`STRUCT-017` — signature-block completeness** (warning). Reconciles the
    declared contracting parties against the signature block and reports a
    declared party with no attributable line. Precision-first: fires only on a
    clearly multi-party-labeled block (`≥2` parties named) missing a further
    **corporate-suffix-named** party, dropping the defined-term / functional-role
    phantoms (`"Confidential Information"`, `"Receiving Party"`) the preamble
    extractor occasionally fabricates — **0 false positives across the
    341-fixture corpus**, while its unit tests prove it fires on the genuine
    "four-party agreement, three signature lines" case.
  - **`STRUCT-018` — attachment completeness** (warning). Reconciles every
    Exhibit / Schedule / Annex / Appendix / Attachment reference against the set
    present as a heading or title line, and reports referenced-but-absent (and
    present-but-unreferenced) attachments — the consolidated reconciliation view,
    distinct from `STRUCT-016`'s incorporation-risk lens.
  - **`STRUCT-019` — recited formalities** (warning). Where the document's own
    text recites notarization or witnessing, checks that the corresponding
    notary jurat / witness block is present. High precision; never asserts the
    formality is legally required.
  - **Closing Checklist** ([`src/report/closing-checklist.ts`](src/report/closing-checklist.ts)).
    Consolidates the readiness findings (`STRUCT-003`/`011`/`013`/`017`/`018`/`019`)
    and the send-readiness handoff items (`HANDOFF-001`/`002`) into one ordered,
    grouped artifact — Markdown and CSV exports, a JSON `closing_checklist` block,
    a CLI `--checklist` flag, and a tab "Ready to sign?" view. A render-side
    projection of findings the engine already produced; **zero `result_hash`
    churn** beyond the three new rules' mechanical execution-log re-baseline.
- **Tracked to Its Dates — the computed critical-dates register (spec-v9 Thrust C,
  Steps 160–164).** Turns the relative temporal terms the extractor already pulls
  into absolute, calendarable deadlines. New module
  [`src/report/critical-dates.ts`](src/report/critical-dates.ts):
  - **`deriveDate(reference, anchor)`** — pure calendar arithmetic, `anchor ± N
    {days|weeks|months|years}`, month-end-clamped (`Jan 31 + 1 month = Feb 28`)
    and leap-year-correct, proven by property tests (validity, monotonicity,
    month round-trip). Reads **no clock**. An undated anchor or a business-day
    count yields an **unresolved** "verify manually" item — never a guess. New
    additive `offset_unit` / `offset_count` / `offset_count_max` on
    `DateReference` carry the calendar unit the day-collapsed `offset_days` loses
    (extractor data, outside `result_hash` — zero golden churn).
  - **`DATE-001…005`** — auto-renewal notice, cure window, opt-out window,
    survival end, notice-period — classified from the clause context, with the
    responsible party drawn from the obligations extractor.
  - A canonically-sorted **register** with its own `critical_dates_hash`, a JSON
    `critical_dates` block, a deepened `.ics` (`buildCriticalDatesIcs`, with a
    render-only DISPLAY alarm on notice/opt-out/cure rows), a Markdown register
    (`buildCriticalDatesMarkdown`), a CLI `--critical-dates` flag, and a tab
    "Your calendar, computed" view.
  - **No-wall-clock metamorphic gate**
    ([`tests/integration/critical-dates-no-wallclock.test.ts`](tests/integration/critical-dates-no-wallclock.test.ts)):
    the same document under two different "today" values yields a byte-identical
    register, `critical_dates_hash`, `.ics`, and Markdown — only the *absolute*
    computed date is ever hashed; every relative-to-today view ("due in N days",
    "overdue", soonest-first) is render-only.
- **v9 close (Step 165).** [`docs/v9/README.md`](docs/v9/README.md) overview;
  threat-model Thrust B/C note; `RULE_TAXONOMY_VERSION` 7.0.0 → 9.0.0; spec-v9
  status table reconciled (all 18 steps shipped); README posture/test-count
  (2,829 → 2,874) and Thrust surface refresh. Version 8.1.0 → **9.0.0**.

### Notes
- The three new always-on `STRUCT-*` rules re-baseline the engine
  `result_hash` and `execution_log` mechanically across the golden corpus (355
  golden files regenerated). The new findings were audited to fire only on
  genuine readiness gaps; the regen is otherwise zero-judgment.

## [8.1.0] — 2026-06-09 — Clean to Send (spec-v9 Thrust A)

### Added
- **Clean to Send — the pre-disclosure scan (spec-v9 Thrust A, Steps 148–154).**
  A deterministic, in-tab read over a document's **original container bytes**
  (the DOCX/PDF you dropped, before mammoth/pdf.js flatten them) that recovers
  the facts the normalizing ingest discards and surfaces them as a new
  `HANDOFF-*` finding family and a `DeliveryReport`. The one document a lawyer
  must never upload to a cloud scrubber — a privileged, comment-laden redline —
  is exactly the one this catches, because nothing leaves the machine. New
  module [`src/delivery/`](src/delivery/):
  - **`HANDOFF-001` / `002` — residual tracked changes & comments** (critical).
    Parses `w:ins`/`w:del`/`w:move*` and `word/comments.xml`; reports the count,
    the author (itself a metadata leak), and a location-only excerpt.
  - **`HANDOFF-003` — hidden / non-printing content** (warning). `w:vanish` runs
    and deleted-but-retained `w:delText`; reports the recovered span so the user
    can decide. Never judges intent; never claims to catch *all* concealment.
  - **`HANDOFF-004` — authoring metadata** (info → warning → critical). Reads
    `docProps/core.xml`/`app.xml` and the PDF Info dictionary verbatim; flags a
    `Company`/`Manager`/`Template`-path naming an entity **absent from the
    document's own party set** as a likely cross-matter leak.
  - **`HANDOFF-005` — sensitive-data patterns** (warning → critical). SSN
    (structurally validated), EIN, payment-card (**Luhn**-validated), bank-routing
    (**ABA**-checksum), context-gated DOB, and lower-confidence email/phone.
    Every matched value is **masked** before it is stored — a hard invariant: the
    report warning about exposed PII never reproduces it.
  - **Additive by construction.** The `HANDOFF-*` findings carry their own
    `delivery_hash` over the container facts, **namespaced apart from** the engine
    `result_hash` (the v8 Step-146 "field outside the run" precedent), so a
    text-only or metadata-clean document yields an empty report and **no existing
    golden re-baselines**.
  - **Total & private.** `readContainer` never throws and never hangs on a
    malformed, truncated, oversized, or non-zip input — it resolves to typed
    facts or an honest "could not inspect" note (never a clean bill of health),
    under the v8 byte-cap / decompression-ratio / match-cap guards. All regexes
    are linear (the repo's ReDoS-free guarantee holds).
  - **Surfaces.** A `delivery` block in the JSON report, a CLI `--delivery` flag
    (with a one-line presence-only summary), and a prominent "Clean to send?"
    section in the tab's complete state. +29 tests (adversarial-container
    fixtures, totality contract, the masking invariant, PDF Info parsing).

### Fixed
- **ReDoS sweep of the whole extractor surface — no input can make extraction
  hang (spec-v8 Thrust A).** A systematic fuzz of every regex in `src/`
  (killable workers, 50k-char runs of each character class) found a cluster of
  super-linear backtracking beyond the two extractors fixed previously. None are
  caught by the input-size guards (a ~100-char paragraph triggers them) and all
  are reachable with characters that survive normalization. Each fix is verified
  byte-identical on real input (the full golden suite is unchanged) and linear
  on hostile input:
  - **Root cause — `normalize` now folds *all* Unicode whitespace** (`\s`, not
    just `[ \t\r\n]`). The extractors match with `\s` (which spans NBSP `U+00A0`,
    ideographic space, etc.), but those characters used to pass through intact, so
    a crafted run of thousands of NBSPs reached the extractors and drove several
    `\s*`-bearing patterns into O(n²). Folding them at the source fixes every
    whitespace-run vector at once (and makes a finding independent of whether a
    drafter typed a space or a non-breaking space). Zero fixtures contain such
    characters, so the corpus is byte-unchanged.
  - **`splitSentences` (obligations)** used `/[^.!?]+[.!?]+/g`, which is O(n²) on
    any paragraph with no `.!?` terminator (a long clause, or a hostile run) —
    the greedy run rescans from every start position. Replaced with an O(n)
    manual scan that emits byte-identical spans.
  - **Anchored edge-trims** (`/^[…]+|[…]+$/`) in the party and obligation
    extractors backtrack O(n²) on a long run of the trimmed characters (commas,
    dots) that does not reach the boundary. Replaced with linear `trimEdges` /
    `trimEnd` helpers (two-pointer scans).
  - **Bounded the remaining unbounded quantifiers** that a required-token suffix
    forces to backtrack across a run: `PARTY_DECL`'s name token (`{0,80}`), the
    amount `AMT` digit groups (`{1,40}`, comfortably above `MAX_AMOUNT_DIGITS`),
    the date count word (`\w{1,40}`), and the `\s*` gaps in `NUMERIC` /
    `RANGE_NUMERIC` / `WORD_FORM` (`\s{0,8}`). Every bound is far beyond any real
    value, so extraction is unchanged.
  The **fuzz-boundary gate** now drives the full `extractAll` surface over 50k
  runs of every character class (a ReDoS is a hang, not a throw, so the prior
  "never throws" property at 400 chars could not see it). +49 tests.
- **Catastrophic regex backtracking (ReDoS) in the amount and date extractors —
  the engine could be made to hang.** Three extractor patterns had a
  super-linear backtracking shape on adversarial input, defeating the spec-v8
  Thrust A "a tool that cannot be made to hang" guarantee (the input-size guards
  don't help — a ~100-character paragraph triggers it):
  - `amounts.ts` `WORD_FORM` used `(?:…|[-\s]+)+`, which degenerates to
    `([-\s]+)+` over a run of hyphens/spaces — **exponential** (verified:
    28 hyphens ≈ 0.8 s, each +4 ≈ 16×). A fill-in line like
    `ten ------------------` (common in templates, and hyphens survive
    normalization) would hang. Fixed to a single-char separator `[-\s]`
    (identical language and greedy match → zero golden churn; now linear —
    5,000 chars in 0.05 ms).
  - `dates.ts` `RELATIVE` / `RANGE_RELATIVE` used four adjacent unbounded `\s*`
    in the optional numeral chain — **polynomial** over a whitespace run. `\s`
    matches Unicode whitespace (NBSP `U+00A0`, etc.) that `normalize` does **not**
    collapse (it folds only `[ \t\r\n]`), so a crafted run of NBSPs was
    reachable (200 k chars ≈ 23 s before). Bounded each to `\s{0,8}` (the
    spec-v8 §5 "bound, never timeout" idiom; eight is far beyond any real
    inter-token gap, which is ≤ 2 post-normalization → byte-identical on every
    realistic input, verified across the golden suite → zero churn; now linear —
    200 k chars in 0.9 ms).
  +2 regression tests assert each extractor stays fast (< 1 s) on the
  adversarial run (under the old patterns these would not complete).
- **Headless CLI ingested a directory in host-locale order (non-deterministic
  reproduction).** `vaulytica analyze <dir>`'s `walkDir` sorted directory
  entries with a bare `localeCompare`, which depends on the host locale/ICU —
  so the same folder could be analyzed (and its per-file report lines printed,
  its output files written, its `--fail-on` evaluated) in a *different order* on
  a machine with a different `LANG`. The sibling glob branch already used
  code-unit `.sort()`, so `analyze dir/` and `analyze 'dir/*.ext'` could even
  disagree on order. Switched the walk to a code-unit comparator (locale- and
  ICU-independent, identical to the glob branch). The build-time playbook
  bundler (`tools/build-extended-playbooks.ts`) carried the same bare
  `localeCompare` over playbook ids; pinned it the same way (regenerating
  `playbooks/extended.json` is byte-identical — the IDs already sorted the same).
  The static **locale-pin guard** now also scans `tools/cli/` — the published
  CLI is a distribution surface that runs the same engine and so carries the
  same reproducibility contract as the shipped `src/` bundle; previously the
  guard only covered `src/`, which is how this slipped through. +2 tests
  (`resolveInputs` directory ordering proves uppercase sorts before lowercase,
  which `localeCompare` would not do).
- **Local Playwright e2e couldn't reach its own preview server (IPv4/IPv6
  mismatch).** `vite preview` defaults to binding `localhost`, which on a
  dual-stack machine resolves to IPv6 `::1`, but the Playwright `webServer`
  polls `127.0.0.1` (IPv4) — so the server-ready wait timed out at 60 s and
  `npx playwright test` never ran locally (it only ran in deploy CI, which hits
  the deployed site via `VAULYTICA_E2E_BASE_URL`). Forced the preview to
  `--host 127.0.0.1` so it binds the address Playwright polls. With this, the
  full e2e suite runs locally; the **responsiveness + accessibility gates were
  then verified empirically** for the first time in this environment — all 34
  responsiveness/a11y tests pass (live app + every `DropzoneState` at
  320/390/768/1280 px with zero horizontal overflow, axe WCAG 2 AA in both
  themes). CI-only `VAULYTICA_E2E_BASE_URL` path is unaffected.
- **GitHub Action install would have broken `tsx` on the runner
  (`--ignore-scripts`).** Self-reviewing the freshly-shipped Action: the install
  step used `npm ci --ignore-scripts`, which skips **esbuild**'s `postinstall`
  (`node install.js`) — and `tsx` (the CLI's runtime loader) depends on esbuild,
  which fails at runtime when its binary is left unconfigured. Switched to
  `npm ci --omit=dev`, which runs esbuild's postinstall while still skipping the
  dev-only `sharp` native build and Playwright. Verified in an isolated install
  that `--omit=dev` yields a working `tsx`. A test now pins `--omit=dev` and
  forbids `--ignore-scripts`, so the regression can't recur.
- **Trimmed `*.test.ts` from the publishable npm tarball.** Added `!**/*.test.ts`
  to the `files` allow-list — the package no longer ships test files (601 → 472
  files), while keeping `_test-fixtures.ts` (the CLI's `loadStarterDkbSync` lives
  there, not a `.test.ts`). The earlier "noted pre-publish refinement" is done.

### Added
- **Distribution surface: a `vaulytica` binary + a GitHub Action (spec-v8 §22).**
  The deferred "publish the CLI" item — the engineering half, not the
  credentialed `npm publish` itself. New `bin/vaulytica.mjs`, a thin `node
  --import tsx` launcher so the TypeScript CLI is invokable as a plain binary
  (no fragile pre-bundle of the WASM/worker ingest deps), with exit codes
  propagated for CI gating. `package.json` is now publish-ready: a `vaulytica`
  `bin`, a `files` allow-list shipping the engine + CLI + starter DKB +
  playbooks, npm metadata (keywords/repository/homepage), and `tsx` moved to
  `dependencies` (so `npx vaulytica` works) — still `private: true` so an
  accidental publish is refused. New composite **GitHub Action** (`action.yml`)
  runs the engine in any repo's CI: `analyze` (→ SARIF for code-scanning upload)
  or `compare` (a redline gate), with `fail-on` propagating the non-zero exit.
  The DKB ships with the tool, so a CI analysis opens **no socket** — nothing
  leaves the runner. New [`docs/ci-integration.md`](docs/ci-integration.md) with
  the workflow recipes, the `npx` usage, and the maintainer publish steps. +7
  tests (bin launcher smoke + exit-code propagation, `action.yml` validity,
  package-metadata consistency).
- **`vaulytica compare <base> <revised>` — headless version comparison (extends
  v8 Thrust C "reach").** Comparison was the one major feature with no headless
  entry point; the CLI did `analyze | diff | verify` but not `compare`. New
  `tools/cli/compare.ts` (wired into the `run.ts` dispatcher) analyzes both
  documents over the parity-proven Node engine, runs `compareRuns` +
  `buildClauseDiff`, and emits either a Markdown summary (a finding-delta table
  plus the inline word-level redline — `~~removed~~` / `**added**` — of every
  rewritten clause) or `--format json` (the machine-readable comparison with
  `clause_diff`). `--fail-on critical|warning|info` exits non-zero (code 2) when
  the revision *introduced* a finding at or above the threshold — so a pull
  request can be gated on "did this revision create new exposure?" with the
  redline attached as the artifact. `--confirm-pairing` permits a cross-family
  compare (mirrors the UI refusal). DKB ships with the tool → no socket.
  Build/CI-only (the corpus guard still holds: `tools/` may import `src/`, never
  the reverse). +10 tests (arg parsing, the introduced-bucket gate, the Markdown
  redline, and a real-engine end-to-end over two temp files).
- **Inline word-level redline within rewritten clauses (completes the Part XVIII
  redline).** The clause redline reported *which* clauses were rewritten but
  showed the whole old vs whole new paragraph — noisy for a one-word edit. Each
  `changed` pair now carries a `word_diff`: a second deterministic token-LCS
  (`diffWords` in `src/report/clause-diff.ts`) that marks the exact words struck
  and added (segments reassemble exactly to the base and revised texts; bounded
  by `MAX_WORD_DIFF_TOKENS`, `null` past it so the renderer falls back to the
  two full texts). The comparison Word report renders it as a true inline
  redline — strikethrough for removed words, underline for added — and the
  comparison JSON carries the `word_diff` segments for machine consumption. Still
  outside the comparison `result_hash` (zero golden churn). +7 tests.
- **Clause-level redline for version comparison (spec-v8 Part XVIII).** The
  comparison feature diffed two `EngineRun`s and told you which *findings*
  resolved / introduced / persisted, but never showed the *clause text* that
  moved. New `src/report/clause-diff.ts` (`buildClauseDiff`) computes a
  deterministic, paragraph-level text diff of the two documents — which clauses
  were **rewritten, added, or removed** — via an LCS alignment over the
  documents' own normalized text, pairing a replaced block into a single
  `changed` entry. It is **bounded** (spec-v8 §5): past a cell ceiling
  (`MAX_CLAUSE_DIFF_CELLS`) it degrades to a set-based membership diff and sets
  `truncated`, never an unbounded allocation. Surfaced in the comparison Word
  report (a "Document Redline" section with base-vs-revised tables, capped rows
  + an honest "and N more" footer), the comparison JSON (an additive
  `clause_diff` field), and a one-line UI summary in the comparison-complete
  state. It is a *verbatim* diff — no generated language, never a suggested edit
  — and lives **outside** the comparison `result_hash`, so it churned no
  comparison golden (the model-clause/overlay precedent). +18 tests across the
  algorithm (insertion/deletion/rewrite/move/whitespace/empty/bound/determinism),
  the JSON and DOCX wiring, and the UI summary. This was the last substantial
  deferral in spec-v8 Part XVIII.

### Fixed
- **Set-based redline fallback miscounted a repeated clause (multiset bug).**
  Found self-reviewing the freshly-shipped redline. The oversized-document
  fallback `setDiff` (`src/report/clause-diff.ts`) used a `count > 0` membership
  test: when a boilerplate clause appeared `b` times in base and `r` times in
  revised with `r < b`, all `r` revised copies were marked unchanged but the
  surplus `b − r` base copies were never reported as removed — silently wrong
  counts, only on the truncated path (documents past the alignment ceiling).
  Reworked to proper multiset semantics — `min(b, r)` matched, the surplus on
  each side surfaced as added/removed. +1 test over a 5×-vs-3× repeated clause.
- **DKB cache fallback could serve a corrupt record as "latest."**
  `readLatestCache` (`src/dkb/loader.ts`) — the offline fallback that picks the
  newest cached DKB out of IndexedDB when the exact requested version is missing
  — sorted records with string `localeCompare` and served the maximum. A string
  sort is not the DKB's version order: a garbage/corrupt version key like
  `zzz-corrupt` sorts *after* a valid `v2026-06-07-local` (`'z' > 'v'`) and would
  be chosen, feeding the engine a corrupt knowledge base. Switched to the
  project's own `compareDkbVersions`, which parses the `vYYYY-MM-DD-<hash>` /
  `v0.0.x-` forms and treats an unparseable version as **oldest** — so a valid
  record always outranks a corrupt one. Well-formed current versions are
  date-ordered identically, so behavior is unchanged for the normal path; this
  hardens the corrupt-cache edge (v8 §5 posture). Runtime/IndexedDB-only → zero
  golden churn; +1 test pinning the corruption-safety ordering.

### Security
- **Neutralized CSV formula injection (CWE-1236) in the fix-list and obligations
  exports.** Both CSVs carry verbatim clause text (the obligations ledger emits
  the obligation action / trigger / source clause) and custom-playbook rule
  titles — all untrusted. `csvField` did RFC 4180 quoting but did not guard the
  formula-injection class: a cell whose first character is `=`/`+`/`-`/`@` (or a
  leading tab/CR) is interpreted as a **formula** when the file is opened in
  Excel or Google Sheets, so a clause crafted as `=HYPERLINK("http://evil",…)`
  could execute on the reviewer's machine. `csvField` now prefixes such a cell
  with a single quote (the OWASP mitigation) so a spreadsheet renders it as
  inert text. Zero golden churn (no fixture cell began with a formula trigger);
  +2 tests over the `=`/`+`/`-`/`@` triggers.

### Fixed
- **`$`-replacement patterns in a custom-playbook citation URL corrupted the
  standalone HTML report's bibliography link.** The bibliography links a URL by
  `String.replace`-ing it inside the already-escaped entry text
  (`src/report/html.ts`). With a **string** replacement, a special-replacement
  pattern (`$&`, `$'`, or the dollar-backtick prefix) in the replacement string
  is expanded — so a
  user-supplied custom-playbook citation URL like
  `https://policy.example.com/s?a=$&b=1` had the matched URL spliced into its own
  `href` (e.g. `…s?a=https://policy.example.com/…`), producing a broken,
  unfollowable citation link — in the v8 §10 "custom playbook is hostile input"
  surface. (Not XSS — the spliced substring is already HTML-escaped, and the
  `safeHref` http(s)-only guard still holds; it is link **corruption**.) Switched
  to a **function** replacer, which inserts the markup verbatim. Render-side →
  zero `result_hash` churn. Added a regression test asserting a `$`-laden
  bibliography URL renders into an intact `href`, verified to fail against the
  string replacer.
- **Pinned every `toLocaleString` to `"en-US"` and added a static locale-pin
  guard (determinism hardening, round 2).** A follow-up sweep found the
  number-formatting twin of the `localeCompare` bug: eight `Number.toLocaleString()`
  calls with **no locale argument**, so a number like `1234567` renders
  `"1,234,567"` on an en-US host but `"1.234.567"` on a German one. Four of them
  (`engine/consistency/rules/v4/cross-doc-rules.ts`) format the **finding title
  and description** of the aggregate-liability and indemnity-cap cross-doc rules
  — text that is serialized into the `EngineRun` and hashed, so a bundle analyzed
  on a non-en host produced a **different `result_hash`**. Pinned all eight
  (cross-doc rules + the three oversize-input error messages in
  `ingest/limits.ts` / `ingest/multi.ts` / `playbooks/custom-playbook.ts`) to
  `"en-US"`, matching the existing `report/v3/insurance.ts` precedent; en-US
  output is byte-identical, so **zero golden churn**. Also pinned three more
  `localeCompare` sites in `extract/definitions.ts` (defined-term / circular-term
  ordering) that the prior manual grep missed. New **static locale-pin guard**
  in `tests/integration/determinism-guard.test.ts` scans all shipped `src/` and
  fails if any `localeCompare`/`toLocaleString` omits an explicit `"en"`/`"en-US"`
  locale — the repeated-run determinism test can't catch this class (the host
  locale is constant within a process), which is how two such bugs reached `main`.
- **Pinned every `localeCompare` sort to the `"en"` locale (determinism
  hardening).** Twelve stable-ordering sorts across `src/` (playbook match
  tie-break in `matcher.ts`, secondary-family ordering in
  `playbook-candidates.ts`, currency-mode pick in the v4 consistency
  `_helpers.ts`, deadline/`.ics` ordering in `exports.ts`, portfolio row order
  in `portfolio.ts`, custom-playbook error/unevaluable ordering, DKB version
  pick in `loader.ts`) called `String.prototype.localeCompare` with **no locale
  argument** — so collation fell back to the host's runtime locale (ICU/`LANG`).
  For the determinism thesis that is a latent footgun: a tie-break or a
  finding-feeding sort that orders differently under a French vs. English locale
  can move `result_hash` across machines. Several of these feed the engine run
  (`matcher` decides which playbook wins a score tie; `_helpers` picks the
  dominant currency that a finding quotes). Pinning to `"en"` makes the
  collation host-independent; ASCII ids/codes sort identically, so **zero golden
  churn** (full suite byte-unchanged, 2,702 → 2,703 only from the new ICS test).
- **`icsFold` folded `.ics` content lines by character count, not octets (RFC
  5545 §3.1).** The deadline-calendar line folder sliced at 73/72 *characters*
  while its own contract said "≤75 octets" — correct for ASCII but able to emit
  a line **over** the 75-octet limit on multi-byte clause text (accented terms,
  a `€` symbol, an emoji in a filename), which strict calendar parsers reject.
  Rewrote it to fold on **UTF-8 octet boundaries** without splitting a code
  point (`octetLength` / `splitByOctets` helpers). Pure-ASCII lines fold
  identically (zero golden churn); multi-byte text now stays within the limit.
  Added a test that a 270-octet euro-sign summary folds to ≤75-octet lines and
  unfolds back to intact UTF-8. Found in the same low-coverage audit pass.
- **Hardened the second reusable regex-exec-loop helper against the zero-width
  hang (audit follow-up).** Swept every manual `while ((m = re.exec(text)))`
  loop in `src/` for the same infinite-loop class fixed in `allMatches`. The
  ~20 one-off extractor/rule loops all use fixed, literal-anchored regexes
  (require `$`, a keyword, `\d+`, etc.) that provably can't match empty — left
  as-is. The one other *reusable* helper, `extractMetricValues`'s `all()` in
  `custom-interpreter.ts` (a growing set of metric patterns flows through it),
  got the same `lastIndex` step-past guard for consistency / future-proofing,
  even though today's patterns all require `\d+`. Zero behaviour change (56
  playbook tests unchanged).
- **`allMatches` could hang the tab on a zero-width regex (latent unbounded-work
  vector).** The shared rule helper `allMatches` (`src/engine/rules/_helpers.ts`)
  ran `while ((m = re.exec(text)))` with a global regex; a zero-width match
  (e.g. a rule regex like `/x?/` or `/\b/`) does not advance `lastIndex`, so the
  loop spins **forever** — a synchronous hang of the browser tab, exactly the
  unbounded work spec-v8 §5 forbids. No shipped rule triggers it today (the two
  callers, STRUCT-016 / RISK-002, require literal text), but it's a hang waiting
  for any future rule that passes an empty-matchable pattern. Added the standard
  `lastIndex` step-past guard; added `_helpers.test.ts` pinning termination on
  `/\b/`, `/x?/`, `/a*/`. Zero churn for the current callers (1,104
  rule/golden tests unchanged). Found by auditing low-branch-coverage modules.
- **Extractors could throw an uncaught `RangeError` on a deeply-nested tree
  (spec-v8 §5/§7 residual).** The extractor walkers (`src/extract/walk.ts`,
  `forEachParagraph` / `forEachSection`) recursed on `section.children` with no
  bound — `extractAll` (a public function) blew the call stack at a few thousand
  levels of nesting. spec-v8 §7 had listed `walk.ts` among the walkers to guard,
  but Step 128 only made `normalize` / `countWords` iterative; the extractor
  walkers stayed recursive. Production never hit this (ingest flattens to
  `MAX_SECTION_DEPTH` before extraction), but the §5 contract forbids a public
  function throwing an uncaught exception. Rewrote both walkers as **iterative
  pre-order DFS** (explicit stack) — byte-identical traversal order (zero golden
  churn; 1,110 extract/golden tests unchanged), now total to any depth (verified
  to 100k). Added a fuzz-boundary test pinning extractor stack-safety on a
  50,000-deep tree. Found by auditing the lowest-branch-coverage shipped modules.

### Documentation
- **Refreshed the README product screenshot (it was stale by two export
  formats).** `docs/images/report-mobile.png` predated the v8 UI wiring, so it
  showed only 4 export buttons; the app now offers 6 (it was missing **HTML
  report** and **SARIF**), and the link/overlay colours had since changed.
  Regenerated it from the *current* `renderState` + page CSS via a new, isolated
  generator (`tools/screenshots/capture.spec.ts`, `npm run screenshots`) so the
  product shot stays faithful as the UI evolves — and updated the alt text to
  list all seven export formats. The generator lives outside `tests/e2e`, so it
  is never run by the e2e suite or vitest; it is invoked on demand.

### Accessibility
- **Bring-your-own-playbook panel sub-states are now responsiveness/a11y-gated
  (fixed two real bugs).** The panel's JS-rendered error / loaded / warning
  sub-states aren't part of the `DropzoneState` union, so they were never
  tested. New `tests/e2e/playbook-panel-a11y.spec.ts` renders them with the real
  page CSS and found: (1) the **invalid-playbook error message** — the text that
  tells you *why* your playbook was rejected — used `var(--critical, #b00020)`,
  but `--critical` was **undefined** so it fell back to a dark-red `#b00020` at
  ~2.7:1 on the dark theme's near-black surface (barely legible) → defined
  `--critical` per theme (dark: a bright `#ff6b6b` ≥ 6:1; light: `#b00020`); (2)
  validation errors echo user-supplied ids (rule ids, metric names) that can be
  long unbreakable tokens and **overflowed a 320 px phone** → `overflow-wrap:
  anywhere` on `.playbook-status` (inherited by the lists/summary). Both pass
  responsiveness + axe in both themes now.
- **Rich complete-state content is now responsiveness/a11y-gated.** The
  exhaustive `responsiveness-states.spec.ts` complete-state fixture was minimal
  — it never rendered the jurisdiction-overlay block, compliance-frame chips,
  custom-playbook provenance, or the detected-family chip, so those elements
  (long statute citations, link colours) were untested. Enriched the fixture to
  stress all of them (and taught the harness to expose `globalThis.document` for
  the renderers that build nodes via the global, as the browser/vitest do). It
  caught a real light-theme contrast bug the minimal fixture missed: the
  jurisdiction-overlay citation link (`.overlay-cite`) used the raw brand mint
  `var(--accent)` (~2.7:1 on the cream surface) → switched to the `--link` token
  (AA on both themes). Complete state now passes responsiveness + axe in both
  themes with its full content rendered.
- **Marketing landing page is now WCAG 2 AA in both themes (gated).** The live
  axe sweep `disableRules(["color-contrast", "region"])` and only runs the dark
  theme, so the full landing page's contrast was never gated. A new
  `tests/e2e/landing-responsive-a11y.spec.ts` renders the real `site/index.html`
  via `page.setContent` (no server), pins each theme via `data-theme`, runs axe
  with **color-contrast enabled**, and checks no horizontal overflow at
  320–1280 px. It found two real, never-tested defects: (1) the
  bring-your-own-playbook panel had `aria-label` on a role-less `div`
  (`aria-prohibited-attr`) → added `role="group"`; (2) **every link in the light
  theme** rendered the brand mint (`#00a883`) at ~2.7:1 on the cream surfaces
  (links are `var(--accent)` text) — introduced a `--link` token (dark: the
  bright mint on near-black; light: a darker on-brand teal `#00735a` ≥ 5:1) so
  link text clears AA while buttons keep `--accent`.
- **Standalone HTML report is now responsive and WCAG 2 AA clean.** The
  shareable single-file report (spec-v8 §21) overflowed a 320 px phone by
  ~924 px — a long underscore-joined filename in the `<h1>` (and finding
  titles) was an unbreakable token with no wrap. Set `overflow-wrap: anywhere`
  on the report `body` (it inherits, so every heading / rule-id / SHA-256 proof
  value / citation URL wraps). An axe sweep also found the freshness label
  (`.fresh` `#777` = 4.47:1) just under AA; darkened to `#6b6b6b` (~5:1). New
  `tests/e2e/html-report-responsive.spec.ts` pins both (responsiveness +
  zero axe violations) via `page.setContent` (no server).
- **Fixed WCAG 2 AA contrast + a missing progressbar name across the app's
  non-default states/theme.** The live axe gate only scans the empty + complete
  states in the default (dark) theme; rendering the **full** `DropzoneState`
  union in **both** themes surfaced real, never-tested issues: the light-theme
  `--muted` (`#6b7280`, ~4.3:1 on the cream surface) failed AA for every muted
  label (sub-text, card meta, toggles) → darkened to `#5b626f`; the
  low-confidence card's confidence number was dimmed by `opacity: 0.75` to
  ~3.9:1 → removed the dim; the low-confidence family label used `opacity: 0.65`
  → switched to the (AA-tuned) muted colour, preserving the "faint" intent
  accessibly; the comparison DKB-mismatch warning (`#a86700` normal text) failed
  on dark → theme-aware amber; and the `analyzing` progressbar had no accessible
  name → added `aria-label`. `responsiveness-states.spec.ts` now also runs axe
  per state × theme, so these can't regress.

### Fixed
- **Mobile horizontal-overflow on long contract filenames (3 view-states).** A
  long, underscore-joined filename (e.g. `Master_Services_Agreement_..._v12_
  executed.pdf`) is a single unbreakable token; `.dropzone-title` (complete /
  analyzing states), `.dropzone-sub` (comparison "base → revised" line), and
  `.bundle-rejected-filename` (skipped-file list) had no `overflow-wrap`, so on
  a 320 px phone the filename pushed the card 100–400 px past the viewport —
  horizontal scroll. Added `overflow-wrap: anywhere` to all three. The existing
  responsiveness e2e never caught this because it drops a *short*-named fixture.

### Added
- **Exhaustive responsiveness gate over every view-state.** New
  `tests/e2e/responsiveness-states.spec.ts` renders the **full** `DropzoneState`
  union (empty · analyzing · complete · comparison · bundle · error) via the
  real `renderState` + the real page CSS through Playwright `page.setContent`
  (no server needed — so it runs anywhere), at 320 / 390 / 768 / 1280 px, with
  overflow-*stressing* fixtures (very long filenames, many per-doc cards, long
  skip reasons / error messages). This is what surfaced the overflow bugs above;
  it complements the live-app `responsiveness.spec.ts` (which pins empty +
  complete against the deployed site).

### Security
- **Neutralized a `javascript:`/`data:` URL XSS vector in the shareable HTML
  report.** `z.string().url()` accepts `javascript:alert(1)` and `data:` URLs
  (the URL constructor parses them), so a custom-playbook citation `url` could
  ride into the standalone HTML report — which spec-v8 designs to be *emailed*
  — as an active `<a href>`, executing in a recipient's browser on open.
  Two-layered fix: (1) the custom-playbook **schema now rejects any citation
  URL that is not http(s)** at load, with a clear message — protecting every
  output format at the input boundary; (2) the HTML renderer **only emits an
  http(s) `href`** and falls back to inert escaped text for any other scheme
  (defense-in-depth for the artifact that executes on open), keeping the URL
  visible/verifiable but non-executable. DKB citations were never affected
  (build-time and vetted). Threat-model updated.
- **Extended the URL-safety guard to the DOCX (the other shareable rich
  format), via one shared `isHttpUrl` predicate.** The DOCX citation-index
  built an `ExternalHyperlink` for any `source_url`; a non-http(s) scheme is now
  rendered as inert text (no hyperlink relationship is created) just like the
  HTML report. Factored the HTML `safeHref` and the custom-playbook schema
  refine onto the same `src/dkb/url-safety.ts` predicate, so the input-boundary
  schema guard and both output-boundary render guards share one canonical
  policy. `http` is allowed alongside `https` (the DKB carries a legitimate
  `http://` UK OGL license URL); only the scheme is constrained.

### Fixed
- **CLI bare-glob resolution.** `vaulytica analyze '*.docx'` (a quoted glob with
  no directory, so the shell doesn't expand it) silently matched nothing: the
  old `slice(0, lastIndexOf("/"))` produced a bogus directory (`*.doc`) for a
  slashless pattern, so `readdir` failed. Extracted `splitGlob` + `globToRegExp`
  as pure, unit-tested helpers — a slashless glob now resolves against `.`.
- **CLI `verify --playbook` argument ordering.** `verify --playbook <id> <report>
  <original>` mis-assigned the report path (the flag value leaked into the
  positional list under a filter-by-prefix parse). Replaced with a sequential
  parser that consumes the flag's value, so `--playbook` works before or after
  the positionals (and an unknown flag now errors instead of being treated as a
  path). Also guarded `run.ts`'s top-level dispatcher so importing it (for the
  new unit tests) does not execute the CLI.

### Added
- **SARIF 2.1.0 structural-conformance gate (closes the spec-v8 §20 test
  promise).** Step 141 shipped the SARIF export but its test only checked the
  `$schema` *string*; §20 promised validation against the schema. Added an
  exposed, dependency-free `sarifConformanceViolations(log)` that pins the
  ingestion-critical SARIF 2.1.0 invariants GitHub Code Scanning actually
  enforces — the `level` enum, an in-range `ruleIndex` consistent with its
  `ruleId`, string-valued `partialFingerprints`, non-empty `message.text` and
  `artifactLocation.uri`, absolute `helpUri` — with **negative tests** proving
  the checker has teeth (a dangling index, a bad level, a non-string
  fingerprint, a malformed URI are each caught). Real output conforms across
  fixtures (cited, URL-less custom, empty, multi-finding-per-rule). Full
  validation against the OASIS-*published* JSON Schema stays deferred for the
  offline/posture reason citation reachability is (§19) — the authoritative
  schema can't be fetched in-tab, and vendoring a copy and calling it "the
  published schema" would be dishonest; spec §20 + docs reconciled to describe
  the conformance check accurately.
- **Unified `vaulytica` CLI dispatcher — `analyze | diff | verify` (surfaces
  the playbook diff).** The CLI (`npm run cli -- <command>`) now dispatches
  three subcommands over the same parity-proven engine instead of only
  `analyze`. New `diff <a.json> <b.json> [--format markdown|json]
  [--exit-code]` surfaces `diffPlaybooks` (spec-v8 Step 144) — until now a
  shipped builder with **no entry point** — as a reviewable terminal/CI
  command (`--exit-code` is a `git diff`-style CI primitive that exits 1 when
  two custom playbooks differ). `verify <report.json> <original>` folds the
  reproducibility verifier (Step 145) into the same dispatcher. `analyze`
  is unchanged. New `tools/cli/diff.ts` (pure, unit-tested `formatPlaybookDiff`
  + the `runDiff` handler); `run.ts` refactored from a single-command script
  into a dispatcher with a `--help` usage banner. Added an `npm run cli`
  script (the `analyze` script is kept as a back-compat alias). Build/CI-only;
  `src/` never imports it.
- **v8 reach formats reachable from the tab (UI wiring).** The SARIF 2.1.0
  export and the standalone single-file HTML report (spec-v8 Steps 141–142)
  are now offered as one-click downloads in the complete-state export row
  ("HTML report", "SARIF") beside the existing fix-list / CSV / obligations /
  `.ics` links, and the bundle-complete state gains a "Download everything
  (.zip)" link — the spec-v8 §25 "everything" archive (consolidated DOCX +
  bundle JSON + per-document fix-list / CSV / `.ics` / JSON in one ZIP). Until
  now these v8 builders shipped but were unreachable from the browser, so the
  README's "one-click exports … SARIF … single-file HTML" claim was ahead of
  the UI; this closes that gap. `runReport`/`runBundleReport` build the blobs
  from the same run (no re-analysis); the export row's `flex-wrap` layout keeps
  the two new buttons from introducing any horizontal scroll on mobile. The
  parity test now also asserts the browser pipeline emits a non-empty,
  script-free HTML report and a `application/sarif+json` blob.

## [8.0.0] - 2026-06-08 — Hardening & Reach (spec-v8 complete)

### Added
- **Citation formatter breadth (spec-v8 Thrust B, Step 136).** `citationFamily()`
  classifies a citation `source` into `us-statutory` / `eu` / `standard` /
  `secondary` / `other`, each tied to a real DKB citation. Only US-statutory
  forms take a Bluebook parenthetical year (EU regs / ISO-NIST standards /
  secondary sources embed their own identifying year); pinpoint subsections
  (`45 C.F.R. § 164.410(a)(1)`) are preserved verbatim, never truncated to the
  base section. Pinned-string fixtures per family. Render-side → zero churn.
- **Citation freshness signal (Step 137).** `freshnessSignal()` surfaces the
  retrieval date (and publication date when genuinely known); the bibliography
  renders `(published YYYY-MM-DD)` only when `source_published_at` is present —
  **never fabricated**, absent when unknown (the honesty gate). Date-only, never
  a computed elapsed "age" (a clock read would break determinism). Additive →
  zero golden churn.
- **Never-truncate / always-wrap citations (Step 138).** `breakLongTokens()`
  splits long citation URLs into wrap-friendly DOCX runs (bibliography +
  citation-index hyperlink) and the HTML report uses `overflow-wrap: anywhere`;
  a DOCX structure test asserts the full citation source + URL render with no
  ellipsis. The split segments rejoin to the original exactly.
- **Citation integrity tool (Step 139).** Build-only `tools/citation-check`:
  per-commit URL well-formedness (pure; `npm run citation:check`) + scheduled
  reachability (`--reachability`, network, mocked in test). `accuracy-corpus-
  guard` extended to assert `src/` never imports it.
- **Cross-format citation-completeness gate (Step 140).**
  `tests/integration/citation-completeness.test.ts` asserts every cited
  finding's resolvable URL survives into **every** finding-bearing format —
  DOCX, JSON, Markdown, CSV, SARIF, HTML — and the URL-less custom case renders
  cleanly. The executable form of the §14 inline-everywhere contract.
- **SARIF 2.1.0 export (spec-v8 Thrust C, Step 141).** `buildSarif` /
  `buildSarifJson` / `sarifBlob` — rule→`reportingDescriptor` (citation →
  `helpUri`), finding→`result` (severity→level, section→`logicalLocation`,
  offset→`region`), finding-id + `result_hash` → `partialFingerprints` for
  cross-run dedupe; deterministic canonical JSON. Render-side → zero churn.
- **Standalone single-file HTML report (Step 142).** `buildHtmlReport` —
  self-contained, all CSS inlined, **no `<script>`**, no external resource;
  cover proof fields, severity-grouped findings, inline citations with wrapped
  URLs + freshness, bibliography, clause-evidence, verbatim posture block;
  mobile-responsive and print-clean. Deterministic; escapes HTML metacharacters.
- **Node API + headless CLI (Step 143).** `tools/cli/api.ts` (`analyzeText` /
  `analyzeFile`) + `vaulytica analyze <path|glob|dir> --playbook --format
  json,sarif,html,md,csv --out --fail-on` over the parity-proven pipeline
  (`runIngested` factored out of `runDocument` so binary ingest reuses the exact
  downstream the parity test pins). DKB ships with the tool — no socket. CLI
  parity test asserts `analyzeText` ≡ `runDocument` byte-for-byte.
- **Playbook diff (Step 144).** `diffPlaybooks(a, b)` + `diffPlaybooksMarkdown`
  — structural diff of two custom playbooks (metadata, built-in rule selection,
  severity/skip overrides, thresholds, required clauses, custom-rule add /
  remove / edit). Pure, deterministic.
- **Reproducibility verifier (Step 145).** `verifyReproducibility(saved,
  original)` re-derives the `result_hash` via the parity-proven pipeline and
  reports what diverged — input / engine / DKB / unexplained; `explainReproResult`
  narrates. `tsx tools/cli/verify.ts <report.json> <original.txt>`.
- **Export enhancements (Step 146).** Bundle "everything" archive
  (`include_per_document_exports`: per-document fix-list + CSV, and ICS / JSON
  when `extracted` / `ingest` are threaded). `buildClauseEvidence` coverage
  surface — which findings pin a verbatim quoted clause span vs. a bare match —
  as a `clause_evidence` JSON field (outside the run → zero churn) + an HTML
  section.

### Changed
- Version bumped to **8.0.0** (Step 147). `RULE_TAXONOMY_VERSION` stays `7.0.0`
  — v8 adds no rules, so the rule vocabulary is unchanged. Spec statuses,
  threat-model ("v8 — hardening & reach surface"), `docs/v8/README.md`, and the
  README posture / test-count (2,621 → 2,674) / Thrust-C surfaces reconciled.

### Added (earlier in this cycle)
- **Inline-everywhere citations (spec-v8 Thrust B, Step 135).**
  The Markdown fix-list now renders authorities as clickable `[source](url)`
  links and the CSV gains a dedicated `authority_url` column — the action-item
  artifacts a user pastes into a ticket/spreadsheet stay verifiable instead of
  stripped to a bare name. Render-side fix in `formatCitation` /
  `formatBibliographyEntry`: a cited custom-playbook rule with no URL now renders
  cleanly as `Policy 4.2` (was `"Policy 4.2 — "` with a dangling em-dash) and
  `[N] Policy 4.2 (cited — Team policy)` (was `[retrieved ; license: …]` with a
  blank date). A citation-completeness meta-test asserts every cited finding's
  URL survives into the Markdown + CSV exports (extends to SARIF/HTML in Thrust
  C). All render-side → zero `result_hash` churn; only the export-test goldens
  re-baselined (mechanical, reviewed).
- **Input-boundary hardening (spec-v8 Thrust A, Steps 127–134).** Every public
  ingest/extract/playbook entry point now fails safely on hostile input —
  rejects deterministically or degrades to a bounded result, never crashes,
  hangs, or exhausts memory. New `src/ingest/limits.ts`: `MAX_DOCUMENT_BYTES`
  (50 MB) + `MAX_PASTE_CHARS` (20M) → typed `InputTooLargeError` before parsing;
  `MAX_SECTION_DEPTH` (64) makes `normalize` flatten deep trees iteratively
  (a 20,000-deep hostile tree no longer overflows the stack) and `countWords`
  iterative; `MAX_OCR_PAGES` (500) bounds the OCR loop with an honest skipped-
  pages warning. `extractZipEntries` guards via fflate's pre-inflation filter —
  `MAX_COMPRESSION_RATIO` (200×) + cumulative-uncompressed budget → typed
  `ArchiveTooLargeError` before a zip bomb expands; nested `.zip` rejected.
  `amounts.ts` drops 50+-digit / NaN / Infinity amounts (`MAX_AMOUNT_DIGITS`).
  Custom-playbook caps (`MAX_PLAYBOOK_JSON_BYTES` pre-parse, `MAX_CUSTOM_RULES`,
  per-string caps). `BUNDLE_CROSS_DOC_TOP_N` (100) caps the cross-doc appendix
  with an honest footer (full set stays in JSON). A `fast-check` fuzz boundary
  gate (`tests/integration/fuzz-boundary.test.ts`) proves the whole public
  surface returns-or-typed-throws and terminates on arbitrary input — the
  boundary analog of v7's metamorphic suite. All guards are pure functions of
  the input (determinism holds — bounds, never timeouts) and zero-churn against
  the goldens. See [`docs/spec-v8.md`](docs/spec-v8.md) + [`docs/v8/robustness-and-fuzzing.md`](docs/v8/robustness-and-fuzzing.md).
- **Mutation testing (spec-v7 Steps 123–124).** Added Stryker
  (`@stryker-mutator/core` + `vitest-runner`, dev-only) scoped to the date and
  amount extractors, a `npm run mutation` script, and a scheduled/on-demand
  `.github/workflows/mutation.yml` (weekly + `workflow_dispatch`, **never** the
  per-push gate). Committed baseline **55.65%** mutation score, raised from the
  first measured 51.26% by a survivor-fix pass (pinned unit→day conversion +
  `before`-direction signing in dates; scale-suffix multiplication + range
  currency inheritance in amounts). Regression-only `thresholds.break = 48`.
  See [`docs/v7/mutation-baseline.md`](docs/v7/mutation-baseline.md). Generated
  reports (`reports/`, `.stryker-tmp/`) are gitignored.
- **Property-based + metamorphic follow-ups (spec-v7 Steps 118/119).** A
  crossref resolve/flag property (a reference to an existing section always
  resolves; a held-out non-existent one always flags) and two metamorphic
  relations (reordering independent clauses keeps the fired-rule set but changes
  the result_hash; when order IS the defect, STRUCT-002 flips as the only date
  crosses the top-quartile boundary). Test-only; no `src/`/`result_hash` impact.

## [7.0.0] — 2026-06-05

**v7 "Depth & Proof"** — make the engine more correct on real documents (Thrust A) and prove the logic sound under inputs no author wrote down (Thrust B), without touching the deterministic / no-AI / no-server / citable / lints-not-drafts posture. See [`docs/v7/README.md`](docs/v7/README.md) and [`docs/v7/testing-architecture.md`](docs/v7/testing-architecture.md).

### Added (Thrust A — depth, Steps 103–108, 110, 113–114)
- **Extraction recall (Steps 103–108).** Dates: fiscal periods (`fiscal-period` type), broadened citable anchor-alias set + "Date Hereof", disjunctive/range deadlines (`offset_days_max`), documented `TWO_DIGIT_YEAR_PIVOT`. Amounts: range amounts (`range_max`), per-unit qualifiers (`per_unit`), deferred `$`-currency override. Parties: alias/role chains (`aliases`), `dba` operating names, two-column signature-field capture. Obligations: prohibitive/permissive boundary modals, nested-trigger decomposition (`nested_triggers`), scope exclusion (`obligor_exclusion`). Definitions: definition-by-`reference`, `scope`-gated defs, circularity detection (`circular_terms`). Crossrefs/jurisdictions: trailing sub-reference (`sub_ref`), governing-law `fallback_jurisdiction` precedence. All new fields optional and outside `result_hash`.
- **Three cross-document families (Step 110).** `CROSS-TERM-001` (termination-alignment), `CROSS-CARVEOUT-001` (liability-cap carveout mismatch), `CROSS-CURRENCY-001` (payment-currency mismatch); V4_CROSS_RULES 10 → 13, each with a bundle fixture.
- **Ingest robustness (Step 113).** Per-page text-density OCR trigger (`assessTextLayer`) so a searchable header over a scanned body OCRs the body; per-word confidence `[uncertain]` markers (`markLowConfidence`) + ingest warning.
- **Report/export fidelity (Step 114).** JSON `provenance` (DKB/engine/rule-taxonomy versions); portfolio `executive_summary` (rolled-up severity counts + per-document digest); `.ics` verify-manually events for unresolved deadlines. All outside the run.

### Added (Thrust B — proof, Steps 120, 125)
- **Node↔browser pipeline parity (Step 120).** `tools/accuracy/parity.test.ts` drives a shared fixture through both `runReport` (browser) and `runDocument` (Node accuracy harness) and asserts a byte-identical `EngineRun` — making v5's "the harness reuses the real pipeline" claim executable.
- **Responsiveness-as-a-test (Step 125).** `tests/e2e/responsiveness.spec.ts` asserts `scrollWidth ≤ clientWidth` per view-state at 320/390/768/1280 px — the manual responsiveness audit becomes a CI gate.

### Changed
- **`result_hash` re-baseline (Step 106, reviewed).** The new prohibitive/permissive modals surface previously-missed negative covenants; six goldens gained/raised an OBLI-005 "negative covenants" finding (line-reviewed — OBLI-005 only). Eleven bundle goldens got a mechanical `consistency.execution_log_count` bump 17 → 20 with no new findings on any pre-existing bundle.
- **Version 6.0.0 → 7.0.0** (Step 126). `ENGINE_VERSION` stays 0.1.0 (it feeds `result_hash`); the new `RULE_TAXONOMY_VERSION` is "7.0.0", stamped only into report provenance.

### Deferred (with reasons)
- **Step 109** (classifier live-routing) — held behind the v5 corpus; a routing change must be measured against real annotated documents.
- **Step 111** (50-state overlay + non-solicitation) — per-state enforceability is attorney-gated legal data under the v5 honesty contract.
- **Step 112** (rule-catalog depth) — a new always-on rule re-baselines every single-document golden's `execution_log` and needs a citable DKB source.
- **Steps 123–124** (Stryker mutation testing) — slow; belongs on a scheduled/on-demand job off the per-push path.

### Earlier v7 increments (Steps 115–122)
- **Schema fuzz + round-trip for the DKB (spec-v7 Step 121).** Added
  `src/dkb/schema-fuzz.test.ts` (+29 tests): every DKB artifact round-trips
  through `parse → serialize → parse`, the wrong top-level type is rejected, and
  a battery of single-field mutations (bad enum, missing-required, out-of-range,
  malformed URL/hash/ISO-datetime) is each rejected — testing that the schemas do
  their real job of *refusing* corruption, not just accepting valid input.
- **Per-rule completeness gate, measure-first (spec-v7 Step 117).** Added
  `tests/integration/rule-completeness.test.ts` (+2 tests): aggregates execution
  logs across the golden corpus to assert every always-on launch rule runs
  (112/112), and enforces a regression-only floor on how many launch rules are
  seen both to fire and to stay silent (measured 63/111/62 of 112; floors
  60/108/59). 49 launch rules have no positive case in the corpus yet — a now-
  visible gap and the ratchet's next target. Test-only; no `src/`/`result_hash`
  impact.
- **Metamorphic invariant testing (spec-v7 Step 119).** Added a suite
  (`tests/integration/metamorphic.test.ts`, +3 tests) asserting that a document
  and a copy with non-semantic whitespace noise produce the same `result_hash`
  and finding set, and that inserting a whitespace-only paragraph changes nothing.
  Tests what the engine *means*, not just that it is deterministic.

### Fixed
- **Determinism leak: heading whitespace bled into the result_hash.** The
  metamorphic suite caught it immediately — `normalize` collapsed whitespace in
  run text but stored section headings verbatim and advanced the offset cursor by
  the raw heading length, so two documents identical except for extra spaces/tabs
  in a heading produced different `result_hash`es. Fixed in `src/ingest/normalize.ts`
  by collapsing heading whitespace the same way run text is collapsed. **Zero golden
  churn** (real headings are clean single-spaced, so the collapse is a no-op for
  them; all 26 golden hashes unchanged) — the fix strictly adds whitespace-invariance.

### Added
- **Property-based testing (spec-v7 Step 118).** Added `fast-check` + a property
  suite (`tests/integration/property-based.test.ts`, +5 properties) over generated
  `DocumentTree`s — a new test *kind* that proves invariants over inputs no author
  enumerated: the normalizer is idempotent and assigns exact, non-overlapping
  offsets and drops empties; any US-dollar amount and any valid ISO date round-trips
  through its extractor. A fixed seed keeps the generated inputs identical on every
  machine/run (a non-deterministic gate is forbidden here). Raised coverage slightly
  (the properties exercise edge paths the example tests missed). Test/dev-dep only.

### Fixed
- **ESLint no longer lints generated coverage output.** Running `npm run coverage`
  before `npm run lint` left `coverage/` on disk and `eslint .` scanned it; added
  `coverage/` to the `eslint.config.js` global ignores (alongside `dist/`).
- **Property tests get a generous timeout.** Generating hundreds of recursive trees
  exceeds vitest's 5s default under V8 coverage instrumentation; the property file
  sets `testTimeout: 30_000` (same lesson as the pdfjs cold-load test) so the gate
  goes red on a real counterexample, never on a slow runner.

### Added
- **Report-structure validation (spec-v7 Step 122).** The DOCX report — the
  artifact a user cites — was tested only for ZIP validity + MIME type. Added 5
  tests (`src/report/docx.test.ts`) that unzip the generated `word/document.xml`
  and assert the report *says the right things*: the cover/audit-trail carry the
  title + engine/DKB versions + file fingerprint + result hash; findings render
  grouped Critical → Warning → Info (ordering anchored on the unique per-finding
  severity badges); cited findings render a `Sources: [n]` line + a Bibliography
  section; and the verbatim determinism/privacy/non-advice posture block is
  present. Also pins the JSON report's `{ run, ingest }` envelope shape and
  well-formed findings. Test-only; pins existing mature behavior (no `src/`,
  `result_hash`, golden, or responsiveness impact). Tests 2,502 → 2,507.
- **Code-coverage measurement + regression gate (spec-v7 Steps 115–116).** The
  suite had 161 files / 2,502 tests but **no coverage tooling or gate**. Added
  `@vitest/coverage-v8` + an `npm run coverage` script + a coverage block in
  `vitest.config.ts` scoped to the shipped `src/` bundle (build/CI-only harnesses
  and test scaffolding excluded). First measured baseline: statements 85.5% ·
  branches 72.4% · functions 87.1% · lines 87.5%. Regression-only floors (a couple
  points under each measured value — lines 85 · functions 85 · statements 83 ·
  branches 70) are wired into `.github/workflows/ci.yml` (coverage runs in place of
  the plain test step, which the cross-OS matrix keeps for determinism). The floors
  fail the build on a *drop*, never block on an aspiration — the same measure-first
  discipline the v5 accuracy scoreboard uses; a ratchet raises them as coverage
  climbs (branches is the next target). README "Build & verify" gains a coverage
  cheat-sheet. Config/CI/dev-dep only; no `src/`, `result_hash`, golden, or
  responsiveness impact.
- **spec-v7 — "Depth & Proof" (`docs/spec-v7.md`).** A full specification
  continuing the global step numbering from v6's Step 102 → Steps 103–126 (24
  steps), grounded in a codebase + test-surface audit. Two thrusts: **(A) Depth**
  — close v6 Step 98 extraction recall extractor-by-extractor, wire the measured
  `dkb/v4/sub-domain-features.json` classifier table into live routing (the
  dead-artifact gap, gated behind v5 + a reviewed golden re-baseline), more
  `CROSS-*` families, employment overlays → 50 states + a non-solicitation family,
  and deepen the thin rule categories. **(B) Proof** — the test *kinds* the suite
  lacks today (verified: 161 files / 2,502 tests, determinism pinned, but no
  coverage gate, no per-rule positive+negative completeness guarantee, and no
  property/metamorphic/mutation/parity/schema-fuzz/report-structure tests): vitest
  V8 coverage + regression-only gate, a per-rule completeness meta-test, fast-check
  property tests, a metamorphic invariant suite, Node↔browser pipeline parity,
  schema fuzz + round-trip, DOCX/JSON report-structure validation, Stryker mutation
  testing, and e2e/a11y expansion incl. responsiveness-as-a-test. Posture-clean and
  measure-before-gate throughout; makes the **testing ≠ accuracy** distinction
  explicit (Thrust B proves internal logic; v5 proves the legal premise). README
  version table + specs index updated. Doc-only; the spec is a plan, unimplemented.
- **Bundle per-doc multi-family activation** (spec-v6 multi-family, the noted
  follow-up). A composite document — an MSA embedding a DPA exhibit, say — is
  now scanned with **every** family it clearly contains when it arrives inside a
  multi-document bundle, not just its primary matched playbook. Previously this
  "don't-miss-anything" behavior ran only for a document dropped **by itself**;
  the same file produced a thinner report inside a deal folder. Now identical
  either way. Each document's per-doc DOCX/JSON download inside the bundle, the
  consolidated bundle report (an "Also checked (other detected families)" block
  in the DOCX; `secondary_families` on each `documents[]` entry in the JSON),
  and each multi-doc card in the bundle-complete view all surface the secondary
  families. Purely additive: the primary per-doc `run`/`result_hash`, the bundle
  fingerprint, and every golden are byte-unchanged; single-family bundles
  serialize identically to before. Secondary families run **only** their gated
  rules (no duplication of the launch rules that already ran). +6 tests.

### Fixed
- **spec-v4.md status was stale — said "not yet implemented" for shipped code.**
  v4 has been complete and shipped (version 4.0.0) for some time — 730 rules, 16
  sub-domains, bundle ingest, the classifier — yet its spec header still read
  "specification, not yet implemented," which would tell a reader the whole
  surface is vaporware. Updated to an accurate ✅-complete status mirroring
  spec-v5/v6, including the Part VII open-question state. Also added a matching
  status line to spec-v3.md (shipped 3.0.0), which had none. Doc-only.

### Changed
- **README — performance / first-paint load-path section.** Added a
  "Performance — the first-paint path is tiny on purpose" section quantifying
  what the README previously only asserted (a whole engine that "runs entirely
  in your browser"). Documents the eager first-paint set (≈29 KB gz: the
  self-contained `index.html`+inline-CSS plus the `main`+runtime entry — **zero**
  vendor chunks, verified against the built `dist/index.html` preload set) versus
  the lazy chunks loaded per interaction (pipeline/engine + format-specific parser
  on file drop; report + `vendor-docx` on export; tesseract only on a scanned
  PDF), the `modulePreload`-filtering design decision that keeps pdfjs off the
  critical render path, and the Lighthouse CI budget (FCP ≤ 1.8 s, TTI ≤ 2.0 s,
  perf ≥ 0.85, a11y ≥ 0.95) that fails the build on regression. All numbers taken
  from the live `vite build` output and `lighthouserc.json`. Doc-only; no `src/`,
  `result_hash`, or responsiveness impact.
- **README — cross-document consistency cheat sheet.** The headline "1,062
  rules" and the rule cheat-sheet count only *single-document* rules; the engine
  also runs **17 cross-document consistency rules** (`CROSS-*` + `CC-*`) on
  folder/`.zip` bundles — conflicting governing law, indemnity-cap stacking,
  defined-term drift across the set, BAA↔MSA scope, etc. That capability was
  mentioned only in passing under v6; added a cheat-sheet table documenting all
  of it. Verified against the live `ALL_CONSISTENCY_RULES` (exactly 17). Headline
  stats re-confirmed accurate (1,062 = 112+220+730; 35 overlays). Doc-only.

### Added
- **Documentation link-integrity guard** (`tests/integration/docs-links.test.ts`).
  Walks every authored `.md` file and fails if any relative link doesn't
  resolve to an existing file — turning the prior one-off 29-link fix into a
  permanent CI gate so stale references can't creep back. Strips fenced/inline
  code first so *illustrative* link syntax in examples isn't flagged;
  leading-slash links resolve from the repo root (as GitHub renders them); and
  it compares the on-disk canonical case (`realpathSync.native`) so wrong-case
  links — which "resolve" on case-insensitive macOS but 404 on GitHub/Linux —
  are caught on any OS. On its first run it caught exactly such a bug: the
  README's "Architecture" link pointed at lowercase `docs/architecture.md`
  while the file was misnamed `docs/ARCHITECTURE.md`. Verified to fire (both a
  missing-file and a wrong-case link injected into a doc fail the test).

### Fixed
- **README "Architecture" doc link 404'd on GitHub.** `docs/ARCHITECTURE.md`
  was renamed to lowercase `docs/architecture.md` to match the README link,
  CONTRIBUTING's prose, and the lowercase convention of every other doc (the
  mismatch was invisible on case-insensitive macOS).
- **OCR orchestration tests** (`src/ingest/ocr.test.ts`, +6). `ocr.ts` was the
  last ingest entrypoint with no coverage. The real engine (tesseract.js WASM +
  a downloaded language model) and canvas rasterization can't run headless, so
  they're mocked — this does **not** verify OCR accuracy (that needs a real
  device), but it pins the logic we own: the per-page loop, the `\n\n`
  page-separator contract downstream paragraph detection depends on, the
  progress callback cadence, and that the worker is always `terminate()`d —
  even when recognition throws — so the engine never leaks. Every ingest
  entrypoint now has a unit test.
- **PDF text-extraction regression tests** (`src/ingest/pdf.test.ts`). The
  `ingestPdfBuffer` → pdfjs path — the primary ingest route — had **zero**
  automated coverage: the suite stayed green regardless of whether pdfjs parsed
  anything, which made a pdfjs major bump unverifiable. New tests build a
  structurally-valid PDF in-process (correct `xref` offsets, real text layer)
  and assert the real pdfjs engine extracts it, hashes deterministically, and
  returns no warnings. This is what made the pdfjs 4→6 bump below a *verified*
  change rather than a hopeful one.

### Fixed
- **Latent buffer-detach fragility in PDF ingest.** `ingestPdfBuffer` hashed the
  source bytes *after* `getDocument`, but pdfjs takes ownership of the
  ArrayBuffer and may detach it (it does under pdfjs's Node fake-worker; the
  browser's copying worker happened to leave it intact). The hash now runs
  *before* the buffer is handed to pdfjs — same bytes, identical hash, no
  `result_hash`/golden change — making the path robust in any environment and
  testable headless.

### Changed
- **Doc-integrity sweep — fixed 29 broken internal markdown links.** A scan of
  all 64 tracked markdown files found stale relative links, almost all from the
  spec files having moved into `docs/` (root/nested references kept the old
  paths and wrong `../` depths). Also corrected one stale filename
  (`ccpa-civ-code.ts` → the consolidated `state-privacy.ts`) and a fragile
  leading-slash link. Re-scan confirms 0 broken links. Markdown-only.
- **`no-console` lint guard on the shipped `src/` bundle.** CONTRIBUTING
  promised "console is restricted," but the ESLint config never enforced it.
  `src/` already carries **zero** `console.*`, so the rule is added with no
  churn — a regression guard that keeps stray debug logs (noise, and a
  potential info-leak of document content to DevTools in a "nothing leaves the
  tab" tool) out of the deployed code. Scoped to non-test `src/`; `tools/`,
  `dkb/`, and tests log freely. CONTRIBUTING's code-style note corrected to
  state the actual enforcement precisely (warnings vs errors; ESLint vs `tsc`).
- **README — "What you can drop in" ingest cheat sheet.** A new section + table
  documents how each input is handled (digital PDF → pdf.js text extraction;
  scanned PDF → lazy OCR fallback; DOCX → mammoth; pasted text; folder/`.zip` →
  bundle mode with cross-document consistency), the deterministic source hash,
  and the in-tab privacy posture — closing the "can I use this on *my*
  documents?" gap the prior one-box flowchart left. Verified against the live
  ingest code (`allowOcr: true` is wired in `pipeline.ts`; `.zip` unpacks via
  fflate). Doc-only.
- **Major dependency modernization: pdfjs-dist 4 → 6** (`^4.2.67 → ^6.0.227`,
  GA, skipping 5). Verified against the new text-extraction tests: pdfjs 6
  still ships the `legacy/build/pdf.mjs` entry we import, and extraction is
  byte-correct. **Honest cost:** the non-eager `vendor-pdfjs` chunk grew
  112.77 → 146.03 KB gzipped (+33 KB) — total gzipped JS is now ~713 KB against
  the 1065 KB ceiling (bundle-size test green), and pdfjs loads only when a PDF
  is dropped (excluded from modulepreload), so first-paint is unaffected
  (Lighthouse green). **OCR-path caveat:** the scanned-PDF fallback
  (`ocr.ts`, which renders pages to a canvas for tesseract.js) is not
  headless-testable and is **left unchanged** — pdfjs 6 reworked `render`
  (`canvas` is now primary, `canvasContext` backwards-compatible with `canvas`
  defaulting from the context), and our `canvasContext`-only call remains
  supported; real-device validation of the OCR fallback stays pending (a
  pre-existing gap, not a regression). 0 vulnerabilities. (Last deferred major:
  tesseract.js 5→7 — the OCR engine, same untestable-headless path.)
- **Major dependency modernization: ESLint 9 → 10** (`eslint ^9.39 → ^10.4`,
  `@eslint/js ^9 → ^10`, `globals ^16 → ^17`). The flat config carries over
  unchanged. ESLint 10 promotes two rules into `js.configs.recommended` that
  surfaced 5 genuine findings, all **fixed** (not disabled): `no-useless-
  assignment` flagged dead default-initializers that both the `try` and `catch`
  always overwrite (in the two engine runners + the accuracy pipeline loader) —
  removed, since the variable is definitely-assigned after the try/catch and the
  initializer was never read (behavior-preserving, no `result_hash` change);
  `preserve-caught-error` flagged two golden test-helper re-throws that dropped
  the original error — now attach `{ cause: e }`, improving the error chain when
  a playbook fails schema validation. ESLint 10 requires Node `^20.19 ||
  ^22.13 || >=24`, satisfied by CI's `node-version: 22` (installs the latest
  22.x) and `.nvmrc`. typescript-eslint@8.60 (peer `eslint ^10`) emits no
  unsupported-version warning. Gate green (lint 0 problems + typecheck + 2486
  tests + build), clean `npm ci`, 0 vulnerabilities. (Remaining deferred
  majors: pdfjs-dist 4→6, tesseract.js 5→7.)
- **Major dependency modernization: TypeScript 5.9 → 6.0** (`^5.4.5 → ^6.0.3`,
  GA). Zero code changes — `tsc --noEmit` passes clean. The codebase was
  already TS-6-ready: the tsconfig carries none of the long-deprecated options
  TS 6.0 turns into errors (`importsNotUsedAsValues`, `preserveValueImports`,
  `keyofStringsOnly`, ES3 targets, …), `target`/`module` are modern
  (ES2022/ESNext), and the existing `strict` + `noUncheckedIndexedAccess`
  settings already satisfy 6.0's stricter checks. Only `npm run typecheck`
  (tsc) and the linter (typescript-eslint, whose `<6.1.0` peer range covers
  6.0 — no unsupported-version warning) consume the `typescript` package; vite
  and tsx transpile via esbuild, so there is no transpile or runtime change.
  Gate green (lint + typecheck + 2486 tests + build), clean `npm ci`, 0
  vulnerabilities. (Remaining deferred majors: eslint 9→10 + globals 16→17,
  pdfjs-dist 4→6, tesseract.js 5→7.)
- **Major dependency modernization: zod 3 → 4** (`^3.23.4 → ^4.4.3`). The
  validation library underpinning every DKB / playbook / accuracy / custom-rule
  schema is now on the current major (zod 3 will eventually lose maintenance).
  The bare `"zod"` import resolves to zod 4's recommended **classic** API, which
  retains `.url()` / `.strict()` / `.finite()` / `.nonnegative()` (none flagged
  `@deprecated`) and the two-arg `z.record(key, value)` form the codebase
  already used — so the **only** code change was the one API zod 4 removed:
  `z.ZodIssueCode.custom` → the string literal `"custom"` (4 `superRefine`
  sites, the form the zod 4 migration guide recommends; fully covered by the
  custom-playbook validation tests). All 2486 tests, typecheck, and build pass.
  **Honest cost:** zod 4 classic is *larger* than zod 3, not smaller — the
  `vendor-zod` chunk grew 12.98 → 19.39 KB gzipped (+6.4 KB). The smaller-core
  benefit only comes from `zod/mini`'s functional API, which would mean
  rewriting every schema (out of scope). The increase is well within the bundle
  budget (total ~705 KB gzipped vs the 1065 KB ceiling) and `vendor-zod` is a
  non-eager chunk, so first-paint (the eager `main` entry) is unaffected.
  0 vulnerabilities. (Other deferred majors unchanged: eslint 9→10, typescript
  5.9→6.0, pdfjs-dist 4→6, tesseract.js 5→7.)
- **Dependency hygiene pass.** `@types/node` `^20 → ^22` to match the Node 22
  runtime baseline (the *supported floor*, not the newer `^25`, so the types
  never permit an API the CI runtime lacks). Refreshed every in-range
  patch/minor to current: `docx` 9.6.1→9.7.1, `vite` 8.0.13→8.0.16, `vitest`
  4.1.6→4.1.8, `tsx` 4.21.0→4.22.4, `happy-dom` 20.9.0→20.10.1, `js-yaml`
  4.1.1→4.2.0. `npm audit` reports **0 vulnerabilities**; the full gate
  (lint + typecheck + 2486 tests + build) and a clean `npm ci` stay green —
  notably the `docx` minor did not perturb any report test (the DOCX tests
  assert structure/content, not bytes). **Deferred majors** (each a real
  breaking-change migration, left for a deliberate individual pass): `eslint`
  9→10 / `globals` 16→17 (the ecosystem still settling on v9), `typescript`
  5.9→6.0, `zod` 3→4, `pdfjs-dist` 4→6, `tesseract.js` 5→7.
- **Linting: migrated ESLint 8 (EOL) → ESLint 9 flat config.** ESLint 8 reached
  end-of-life in October 2024 and its legacy `.eslintrc` system pulled the
  deprecated `inflight`, `rimraf@3`, and `@humanwhocodes/config-array` /
  `object-schema` transitive packages (the `npm install` deprecation warnings).
  `.eslintrc.cjs` → `eslint.config.js` (flat config); `eslint@^8 → ^9.39`;
  the separate `@typescript-eslint/{parser,eslint-plugin}@^7` → the unified
  `typescript-eslint@^8.60` meta-package; `eslint-config-prettier@^9 → ^10`
  (using its `/flat` export); added `@eslint/js@^9` and `globals@^16`. The
  config is **behavior-preserving** — same ignores, same browser+node globals
  (the old `env` block), same two rule overrides (`no-unused-vars` warn with
  `^_` ignore, `no-explicit-any` warn). typescript-eslint v8's recommended set
  surfaced **0 new errors**. ESLint 9's default `reportUnusedDisableDirectives`
  flagged 5 dead `// eslint-disable-next-line no-console` comments (the
  `no-console` rule was never enabled) in tools/tests that legitimately log;
  removed. A fresh `npm install` now emits **zero** deprecation warnings, and
  `npm ci` resolves cleanly. (ESLint 10 exists but typescript-eslint's mature
  support targets v9; revisit once the v10 ecosystem settles.)
- **CI: migrated every GitHub-published action off the deprecated Node 20
  runtime.** GitHub is forcing Node 20 actions to Node 24 by 2026-06-16; all
  five workflows now pin the current Node-24 majors —
  `actions/checkout@v4 → v6`, `actions/setup-node@v4 → v6`,
  `actions/cache@v4 → v5` (dkb-rebuild), `actions/upload-artifact@v4 → v7`
  (deploy + lighthouse failure paths). No API changes affect our usage:
  `setup-node`'s new auto-caching is inert because we set `cache: "npm"`
  explicitly and ship no `packageManager` field; `cache`/`upload-artifact`
  inputs are unchanged; GitHub-hosted runners exceed the new minimum runner
  version. Third-party actions (`cloudflare/wrangler-action`,
  `peter-evans/create-pull-request`) are unchanged — they run only in
  secret-gated/scheduled jobs, not the public gate.
- **Project Node baseline raised 20 → 22 LTS** (`.nvmrc`, `package.json`
  `engines` `>=20 → >=22`, every workflow `node-version`/matrix entry). Node 20
  reached end-of-life on 2026-04-30; the suite already passes on Node 25
  locally and on 20 in CI, so Node 22 is safely bracketed. `result_hash` is
  Node-version-independent (SHA-256 over canonical JSON), so determinism is
  unaffected.

### Added
- **v5 Step 75 — legal-basis ledger scaffolding + `tier` on `Rule`/`Finding`**
  (spec-v5 Part III). New `RuleTier` (`established` / `prevailing-practice` /
  `opinion`) is added as an **optional** field on `Rule` and `Finding`;
  `makeFinding` copies it through only when set, so an unsigned rule omits the
  field and `result_hash` is byte-unchanged (same additive discipline as the
  existing `source?` marker — verified zero golden churn). The ledger schema +
  loader live in `tools/accuracy/legal-basis.ts` (build-and-CI-only; `src/`
  never imports it), with an honestly-empty machine mirror at
  `docs/legal-basis/ledger.json` and a documented protocol in
  `docs/legal-basis/README.md`. `tierForRule` bakes in spec-v5 §14: an
  `unsound` verdict surfaces no tier (the rule is retired, not shown) and a
  `disputed` verdict caps the tier at `opinion`. A machine-mirror test
  (`tests/integration/legal-basis-ledger.test.ts`) enforces schema validity,
  no duplicate `rule_id`, rule + DKB referential integrity, and — load-bearing
  — that **every inline `Rule.tier` is backed by a signed ledger entry**, so a
  surfaced tier badge can never be author-asserted. No attorney has signed yet
  (Steps 76/77 are human-gated); the ledger reports an honest 0-of-N coverage.

### Changed
- README.md gains real product imagery (`docs/images/hero.png`,
  `docs/images/report-mobile.png`) — actual headless renders of the
  shipped UI (dark-theme landing hero; the `complete`-state result
  card at a 390 px phone width) — and a one-word accuracy fix in the
  project layout ("four document states" → "six-state result machine",
  matching the `empty`/`analyzing`/`complete`/`comparison-complete`/
  `bundle-complete`/`error` machine). Images live under `docs/`, so
  they touch neither the deployed bundle nor the Lighthouse budget.
  Headline counts re-verified against live code (1,062 rules; 35 state
  overlays; 2,468 tests; v6.0.0). Doc-only; no test impact. Full-surface
  responsiveness (no horizontal scroll, 320–1280 px, all six view
  states) was re-verified empirically — see `BUILD_PROGRESS.md`.

## [6.0.0] — 2026-06-01

The 4.0.0 → 6.0.0 release. The package version jumps straight from 4.0.0 to
6.0.0: v5 (Ground Truth) is specified and its measurement infrastructure is
built, but its published accuracy numbers are human-gated, so it never took a
standalone package bump; v6 (Workflow) is the release that closes out the
sequence. The `ENGINE_VERSION` that feeds `result_hash` is deliberately
**unchanged at `0.1.0`** — every v6 surface is additive and lives outside the
`EngineRun`, so no existing report hash moved. The full per-step rationale
accumulated under `[Unreleased]` during the build is preserved as the detail
sections beneath this summary.

### v6 — Workflow (Steps 87–102)

Six feature parts, each passing the five-part posture filter (deterministic ·
no AI · no server · citable · lints-not-drafts):

- **Part I — Version comparison (Steps 89–90).** Drop a base and a revised
  document; get a deterministic finding-delta (resolved / introduced /
  unchanged / carried-clean) with a comparison hash
  `SHA-256(base_hash + revised_hash + canonical(delta))`, a compare UI, and a
  DOCX/JSON comparison report.
- **Part II — Bring-your-own playbook (Steps 91–94).** A team encodes its own
  positions as a user-authored `.json` playbook, validated **client-side** against
  a public versioned schema (`docs/v6/playbook.schema.json`; authoritative Zod
  in `src/playbooks/custom-playbook.ts`) — declarative data, never executable
  code. A bounded six-predicate DSL interpreter (`src/playbooks/custom-interpreter.ts`)
  evaluates it with no `eval` and no network; predicates it cannot evaluate are
  reported, never guessed. Load-a-playbook UI (augment vs replace; findings
  carry `source: custom-playbook` provenance and cite the team's own authority);
  authoring guide + two worked examples. A privacy guard test asserts zero
  egress across the full load→validate→enforce path.
- **Part III — Findings to action (Steps 87–88).** Export the fix-list (Markdown
  + CSV), the obligations ledger (CSV), and deadlines as an `.ics` calendar with
  notice windows computed deterministically (`term end − notice period`);
  ambiguous dates are listed "verify manually," never guessed.
- **Part IV — Model-clause references (Steps 95–96).** For a finding whose rule
  has an associated public model clause, the rule card points to an attributed
  reference into Common Paper / Bonterms / the EU SCCs (source URL + license) —
  a reference, never a generated redline. `src/dkb/model-clauses.ts`; surfaced
  outside the `EngineRun`, coverage published honestly.
- **Part V — Portfolio risk matrix (Step 97).** A deal-folder bundle gains a
  documents × key-checks grid (liability cap · auto-renewal · governing law ·
  data-processing terms · breach-notice) plus rollups; a rule that did not run
  renders an honest grey `N/A`, never a wrong "Risk." `portfolio_fingerprint`
  extends the bundle fingerprint; a 50-row scale guard reports the true total.
- **Part VI — Depth (Steps 99–101).** The sub-domain classifier's feature table
  was re-engineered, lifting top-1 accuracy **70.7% → 100%** (75/75) on the
  labeled golden corpus and resolving the four named confusions — still a
  hand-authored, inspectable table, no model. The cross-document consistency
  engine grew **7 → 10** CROSS-\* families (defined-term *usage* drift,
  indemnity-cap stacking, confidentiality survival-period conflict).
  Jurisdiction overlays: **35** per-(family × state) state-law deltas across the
  three families where state law dominates — employment non-compete (15 states),
  residential-lease deposit (10), lending usury (10) — surfaced as a citable
  reference layer outside the `EngineRun`, with honest `uncovered_states`.
- **Full-catalog wiring + multi-family activation.** The live pipeline now
  serves the v3+v4 playbook catalog (`playbooks/extended.json`) and runs all
  **1,062** rules (LAUNCH 112 + V3 220 + V4 730), family-gated via
  `selectMatchCandidates` so a plain NDA is unaffected, and a composite document
  runs every family it clearly contains. (Before this, only the 112 launch rules
  fired in production — the other 950 gated to playbook ids that were never
  served.)
- **Step 98 (extraction recall)** is deliberately deferred behind v5 measurement
  (spec-v6 Part IX #7).

### v5 — Ground Truth: measurement infrastructure (Steps 67, 69, 71, 83)

The accuracy & validation harness that measures the engine against real
contracts it did not write, built and unit-tested under `tools/accuracy/`
(`npm run accuracy`): corpus scaffolding + provenance + deterministic PII
redaction (67); the gold-annotation schema + Cohen's κ inter-annotator
agreement + annotation protocol (69); the full-catalog Node pipeline (the same
`ingest → extract → classify → engine` path the browser uses) + closed-world
TP/FP/FN/TN + precision/recall/F1 (macro + micro) + a reproducible SHA-256
scoreboard (71); and the privacy/determinism guards asserting no `src/` file
imports `tools/accuracy` or `corpus/`, so corpus bytes never reach the deployed
bundle (83). The committed scoreboard honestly reports `status: empty` — no
precision/recall number is published until real license-clean documents and
credentialed-attorney annotation land (human-gated Steps 68/70/73–77/85).

### Changed
- `package.json` version bumped from `4.0.0` to `6.0.0`; `ENGINE_VERSION`
  unchanged at `0.1.0` (feeds `result_hash`, so bumping it would churn every
  golden).

### Detail — entries accumulated under `[Unreleased]` during the v4-follow-up → v6 build

The entries below were logged incrementally during the post-4.0.0 build
sequence and are preserved here so the per-step rationale is part of the
6.0.0 release record.

### Changed
- README.md + marketing site (`site/index.html`) updated to reflect
  the current rule counts: v1 launch is 112 rules (was "~80"),
  v3 adds 220, v4 adds 730, total is 1,000+ (was "~145"). Four
  stale references corrected: `README.md` headline, the schema.org
  `SoftwareApplication.featureList` entry, the `SoftwareApplication.description`
  text, the on-page "What I check" paragraph, and the architecture-
  diagram inline SVG label.
  - No static-HTML tests pin the counts, so this is doc-only with
    no test impact.

### Added
- Single-doc JSON report surfaces `playbook_deprecated` +
  `playbook_superseded_by` alongside `run` / `ingest` (closes the
  single-doc ↔ bundle JSON parity gap on deprecation; the bundle
  JSON has carried the per-entry fields since 943d114). Fields are
  emitted only when the matched playbook carries `deprecated: true`
  in its JSON, so JSON output for non-deprecated playbooks is
  byte-identical to prior output.
  - [`src/report/json.ts`](src/report/json.ts) `buildJsonReport`
    gains an optional third `playbook?: Playbook` parameter. The
    fields live alongside `run` / `ingest` (not inside `run`)
    because adding to the run would change `result_hash`.
  - [`src/ui/pipeline.ts`](src/ui/pipeline.ts): both single-doc
    pipeline call-sites thread the matched playbook into
    `buildJsonReport`.
  - [`src/report/docx.test.ts`](src/report/docx.test.ts): +3 tests
    (deprecated path, explicitly non-deprecated, playbook arg
    omitted).

- DOCX audit-trail Playbook line surfaces deprecation. Mirrors the
  annotation already on the cover (commit edc1ff9) so the in-report
  audit trail is self-consistent — a reviewer scrolling to the
  Audit Trail section sees the same legacy hint as the cover.
  - [`src/report/docx.ts`](src/report/docx.ts) `renderAuditTrail`
    appends `— legacy; superseded by <id>` (or `— legacy`) to the
    Playbook line when `playbook.deprecated === true`.
  - [`src/report/docx.test.ts`](src/report/docx.test.ts): the
    existing deprecated-cover test now also asserts the substring
    appears at least twice in `word/document.xml` (once in the
    cover, once in the audit trail).

- UI complete-state and bundle-complete cards surface playbook
  deprecation (closes the user-visible feedback loop for the v2 NDA
  deprecation — single-doc DOCX cover landed in edc1ff9, bundle
  DOCX + JSON landed in 943d114; this commit lands the on-page
  affordance).
  - [`src/ui/states.ts`](src/ui/states.ts): complete-state gains
    optional `playbook_deprecation?: { superseded_by?: string }`.
    When present, the reasoning line is appended with
    "Legacy playbook — superseded by <id>." (or "Legacy playbook."
    when `superseded_by` is absent). Multi-doc card `documents[]`
    gains optional `playbook_deprecated?: boolean`; when true the
    card's playbook label is suffixed " (legacy)".
  - [`src/ui/main.ts`](src/ui/main.ts): both single-doc and bundle
    paths thread `result.playbook.deprecated` +
    `result.playbook.superseded_by` end-to-end. The narrow
    inline-type for the single-doc helper widened to include the
    two optional Playbook fields.
  - [`src/ui/states.test.ts`](src/ui/states.test.ts): +4 tests
    (single-doc with successor, single-doc no successor,
    single-doc back-compat omits the suffix, multi-doc card
    annotation across mixed states).

- Bundle DOCX + JSON surface per-document playbook deprecation
  (spec-v3 §27 follow-up; companion to the single-doc DOCX cover
  addition in commit edc1ff9). When a deprecated playbook matched
  for any document in a bundle, the per-document subsection's
  "Playbook:" line in the bundle DOCX is annotated with
  "— legacy" or "— legacy; superseded by <id>", and the bundle
  JSON's `documents[]` entry carries optional `playbook_deprecated`
  + `playbook_superseded_by` fields. Non-deprecated bundles
  serialize byte-identically to prior output.
  - [`src/report/bundle.ts`](src/report/bundle.ts):
    `BundleDocument` gains optional `playbook_deprecated?: boolean`
    + `playbook_superseded_by?: string`; `BundleJsonDocument`
    mirrors them. The DOCX renderer reads them on the per-doc
    Playbook line; the JSON emitter sets them per-entry when
    `playbook_deprecated === true`.
  - [`src/ui/pipeline.ts`](src/ui/pipeline.ts): the bundle pipeline
    threads `d.playbook.deprecated` + `d.playbook.superseded_by`
    into each `BundleDocument` so production bundles carry the
    signal end-to-end.
  - [`src/report/bundle.test.ts`](src/report/bundle.test.ts): +2
    tests covering DOCX annotation (mix of deprecated +
    superseded_by, deprecated alone, non-deprecated) and JSON
    emission shape.

- DOCX cover surfaces playbook deprecation. When a deprecated
  playbook matches (e.g. v2 `mutual-nda`), the Playbook line on the
  cover now reads
  `Mutual Non-Disclosure Agreement (mutual-nda v1.0.0) — match
  confidence 0.92 — legacy; superseded by mutual-nda-deep`. A
  reader of the report alone — without the playbook JSON open — can
  see they were analyzed against a legacy playbook and which one
  supersedes it.
  - [`src/report/docx.ts`](src/report/docx.ts) `renderCover` reads
    the optional `deprecated` + `superseded_by` Playbook fields.
    Non-deprecated playbooks render byte-identically to before.
  - [`src/report/docx.test.ts`](src/report/docx.test.ts) +2 tests:
    deprecated-path asserts the suffix appears in `word/document.xml`,
    non-deprecated path asserts neither "legacy" nor "superseded by"
    appears.

### Changed
- v4 bundle MSA + SOW fixtures pinned via `.playbook` sidecars so they
  route to `msa-general` / `sow` instead of NDA / SaaS playbooks.
  Adopts the v3 golden-harness pattern (pin per-doc playbook on
  bundle fixtures so the bundle test focuses on the consistency
  engine's cross-doc semantics, not on playbook routing).
  - 8 `tests/golden/v4/bundles/*/msa.txt.playbook` (all → `msa-general`).
  - 4 `tests/golden/v4/bundles/*/sow.txt.playbook` (all → `sow`).
  - All 8 bundle goldens at `tests/golden/v4/bundle-expected/`
    regenerated; only `per_document.result_hash` and
    consistency `result_hash` changed.

### Deprecated
- v2 `mutual-nda` and `unilateral-nda` playbooks are now marked
  `deprecated: true` in their JSON, with `superseded_by` pointing to
  the v3 `mutual-nda-deep` / `unilateral-nda-deep` successors.
  - [`src/playbooks/types.ts`](src/playbooks/types.ts) `Playbook` type
    and Zod schema gain optional `deprecated` + `superseded_by`
    fields.
  - [`playbooks/mutual-nda.json`](playbooks/mutual-nda.json) and
    [`playbooks/unilateral-nda.json`](playbooks/unilateral-nda.json)
    carry the new fields. The ids are intentionally unchanged so the
    13+ stable callsites in src/ and tests/ continue to work and the
    v2 launch-surface engine-run hashes stay byte-identical.
  - [`src/playbooks/matcher.ts`](src/playbooks/matcher.ts) gains a
    tiebreak: when two playbooks score the same `raw_score`, a
    non-deprecated playbook beats a deprecated one before the
    lexicographic id tiebreak fires.
  - Surfaces a real improvement on the v4 bundle MSA fixtures
    (clean-msa-baa / missing-companion-dpa / precedence-clash): the
    MSAs were previously tying at 0.8 between `mutual-nda` and
    `saas-vendor` and lex-order would pick `mutual-nda` for an MSA;
    the deprecation demotion now picks `saas-vendor` for the tie.
    Three bundle goldens regenerated.
  - Closes the remaining Step 27 follow-up flagged at
    `BUILD_PROGRESS.md` (the "deprecate v2 mutual-nda /
    unilateral-nda" item; the auto-detect re-pointing half was
    already done via `FAMILY_TO_PLAYBOOK["nda-deep"]` +
    `resolveNdaDeepVariant`).

### Added
- v3 `detectV3Family` defined-term signals across the remaining
  contract-style detectors (the form-style detectors — SCC, UK IDTA,
  ACORD-25 — keep their `void extracted;` shims by design because the
  underlying documents are pre-printed regulator / industry forms with
  no meaningful definitions section).
  - [`src/ui/v3/auto-detect.ts`](src/ui/v3/auto-detect.ts) `detectNdaDeep`
    emits `Confidential Information defined` (weight 2) and `Discloser /
    Recipient defined` (weight 1) from `extracted.definitions.entries`.
  - `detectMsaDeep` emits `Services defined` + `Order Form / SOW
    defined` (weight 1 each).
  - `detectVendorSecurity` emits `Customer / Personal Data defined` +
    `Security Measures defined` (weight 1 each).
  - `detectAiAddendum` emits `Model / Foundation Model defined` +
    `Training Data / Output defined` (weight 1 each).
  - All signals are additive — no existing weights change, no fixtures
    regenerated, no goldens shifted. The `source: "definition"`
    classification matches what `detectBaa` / `detectDpaEu` /
    `detectDpaUsState` already use.
  - [`src/ui/v3/v3-ui.test.ts`](src/ui/v3/v3-ui.test.ts): 4 new tests,
    one per detector, each with body text intentionally sparse enough
    that the definition signal carries non-redundant weight.

### Changed
- v3 `detectV3Family` now routes the `nda-deep` family to either
  `mutual-nda-deep` or `unilateral-nda-deep` based on symmetry
  signals, instead of unconditionally suggesting the mutual variant.
  Both playbooks now ship at v1.0.0 with distinct compliance-matrix
  columns (mutual symmetry vs. discloser / receiver role framing);
  the prior hard-coded mapping meant a document self-titled "One-way
  NDA" would still suggest the mutual playbook and render the wrong
  matrix column on accept.
  - [`src/ui/v3/auto-detect.ts`](src/ui/v3/auto-detect.ts): new
    `resolveNdaDeepVariant(text)` helper scores mutual-vs-unilateral
    title and role-framing cues and picks the matching playbook.
    Ties default to mutual (the safer fallback — mutual rules include
    a symmetry check the unilateral playbook does not, so misrouting
    a unilateral document under mutual produces a correctable
    false-positive surface; the inverse silently misses a rule).
    Resolver signals are appended to the detection audit trail.
  - Family id (`nda-deep`), `V3_FAMILY_LABELS["nda-deep"]`, fixtures,
    goldens, and consistency-engine `kindOf` resolver all unchanged
    — only `suggested_playbook` gains a second possible value.
  - [`src/ui/v3/v3-ui.test.ts`](src/ui/v3/v3-ui.test.ts): 3 new tests
    pinning mutual-route, unilateral-route, and tie-fallback cases.

### Fixed
- Replaced two `github.com/clay-good/vaulytica/blob/main/spec-v4.md`
  citation URLs with canonical anchors on `https://vaulytica.com`.
  Both citations belong to self-referential disclaimer rules
  (EST-060, REG-040) that previously cited the project's own spec
  via a mutable branch in GitHub's code-hosting UI — not something a
  partner can sign off on. The inline citation text in each rule's
  `source` field already names the exact spec section (§6.N for
  EST-060, §6.P for REG-040), so the auditable reference is now
  self-contained in the citation row.
  - [`src/engine/rules/v4/trust-estate/rules.ts`](src/engine/rules/v4/trust-estate/rules.ts)
  - [`src/engine/rules/v4/regulatory-prose/rules.ts`](src/engine/rules/v4/regulatory-prose/rules.ts)
  - 10 v4 golden fixtures regenerated; `result_hash` drift contained
    to exactly the two affected rules.

### Added
- DOCX report: real parties / dates / amounts / definitions /
  jurisdictions tables in the Extracted Data Appendix, and the
  obligor / modal / action / trigger ledger in the Obligations
  Ledger (closes the long-standing Step 9 follow-up noted in
  `BUILD_PROGRESS.md`).
  - [`src/report/docx.ts`](src/report/docx.ts) `buildDocxReport` now
    accepts an optional sixth parameter `extracted?: ExtractedData`.
    When threaded, `renderExtractedAppendix` renders parties (name /
    role / entity type / formation jurisdiction), dates (raw / type /
    ISO / anchor + offset), amounts (raw / currency / amount / word
    form), defined terms (term / definition / use count + an unused-
    terms line), and jurisdictions (clause kind / raw text /
    normalized id). `renderObligationsLedger` renders the full
    obligor / modal / action / trigger-qualifier table instead of the
    finding-derived two-column summary. Without `extracted`, the
    legacy counts-only appendix and finding-derived ledger render
    unchanged.
  - [`src/ui/pipeline.ts`](src/ui/pipeline.ts) threads
    `prepared.extracted` (single-doc) and `extracted` (bundle path)
    through to `buildDocxReport`.
  - [`src/report/docx.test.ts`](src/report/docx.test.ts) adds 2 tests:
    one verifying the enriched DOCX is larger than the baseline when
    extracted data is provided, one pinning the legacy counts-only
    fallback path.

### Added
- Compliance-frame UI toggle re-run (closes the remaining
  v3-o follow-up; spec-v3 §61).
  - [`src/ui/pipeline.ts`](src/ui/pipeline.ts) is now factored into
    two phases. `prepareDocument` does the slow ingest + DKB load +
    extract + playbook match and returns a `PreparedDocument`.
    `runReport` does the engine run + report build against a
    prepared payload (frame-aware via `options.active_frames`).
    `runPipeline` chains them and returns `result.prepared`
    alongside the report so the UI can retain it.
  - [`src/ui/main.ts`](src/ui/main.ts) `runFile` builds a re-run
    closure that calls `runReport` directly when chips toggle —
    no PDF re-parse, no DKB re-fetch. Rapid toggles are coalesced
    via a pending-frame slot so an in-flight re-run never queues
    a backlog.
  - [`src/ui/states.ts`](src/ui/states.ts) `complete` state accepts
    `on_frames_change?: (active_frames) => void`. The chip-toggle
    handler invokes it with the *current union* of active frames
    after each flip, sourced from a closure-shared `Set`.
  - [`src/ui/states.test.ts`](src/ui/states.test.ts) gains one test
    that drives a 3-step toggle sequence (HIPAA off, GDPR on, HIPAA
    back on) and asserts the callback receives the expected unions.

### Added
- Engine-side compliance-frame rule filtering (spec-v3 §61, the named
  follow-up to LAUNCH row v3-o).
  - [`src/ui/frame-filter.ts`](src/ui/frame-filter.ts) (new) ships the
    pure functions `framesForRule(ruleId)` and `filterRulesByFrames(rules,
    activeFrames)`. The frame ↔ rule-id-prefix map covers every rule
    family currently in v3: BAA-* → HIPAA, DPA-* → GDPR, USDPA-* → all 8
    US state privacy statutes (CCPA + VCDPA + CPA + CTDPA + UCPA + TDPSA
    + OCPA + DPDPA), TRANSFER-* → GDPR + UK-GDPR, ADDENDA-010..016
    (AI Addendum) → NIST-AI-RMF + EU-AI-Act, ADDENDA-019
    (FTC Click-to-Cancel) → FTC-ROSCA, ADDENDA-020 (privacy policy) →
    GDPR + CCPA. The vendor-security and EULA ADDENDA ranges + every
    V1 launch / V3 deep / V4 prefix are intentionally unframed —
    they're playbook-bound, not regulator-bound, so toggling HIPAA off
    must not silence the missing-party-name check. Longer prefixes
    win in the lookup (USDPA- vs DPA-).
  - [`src/ui/frame-filter.test.ts`](src/ui/frame-filter.test.ts) (new)
    24 unit tests covering every mapping, the union semantics for
    multi-frame activation, the unframed-prefix invariant, and a
    purity check (the input array is not mutated).
  - [`src/ui/pipeline.ts`](src/ui/pipeline.ts) `runPipeline` and
    `runBundlePipeline` now accept an `options.active_frames` parameter
    typed as `ReadonlyArray<ComplianceFrame>`. When omitted, the full
    LAUNCH + V3 rule set runs (preserves existing behavior for every
    caller in the tree today). When supplied, the rule set is filtered
    through `filterRulesByFrames` before the engine runs.
  - Wiring the chip-toggle UI in the complete state to call the
    pipeline with the new frames + caching the per-doc ingest is the
    remaining piece for the v3-o follow-up.
- Test coverage for the v4 bundle-pipeline expansion helper.
  [`src/ui/pipeline.test.ts`](src/ui/pipeline.test.ts) (new) pins
  `expandBundleInputs` across 6 paths: multi-file passthrough,
  unsupported-extension filtering, zip-bundle unpack, zip
  determinism (sorted entry order), single-non-zip edge case, and
  empty-zip handling. The bundle pipeline was shipped without unit
  coverage in commit 6f20dc5; this closes the gap.
- Shared v3 family-label module. [`src/ui/v3-labels.ts`](src/ui/v3-labels.ts)
  (new) carries `V3_FAMILY_LABELS` + `familyDisplayLabel`, consumed by
  both `main.ts` (eager bundle, no heavy deps) and `pipeline.ts`
  (dynamic chunk). Removes the duplicated table that previously lived
  in `main.ts` alongside the pipeline's own copy. Unit tests in
  [`src/ui/v3-labels.test.ts`](src/ui/v3-labels.test.ts) pin the table
  coverage against the auto-detect family ids and the
  `familyDisplayLabel` fallback contract.

### Changed
- Bundle DOCX cover now surfaces the v3 detected family for each
  per-document subsection rather than the bare playbook id.
  [`src/ui/pipeline.ts`](src/ui/pipeline.ts) `runBundlePipeline` sets
  `BundleDocument.detected_family` via `familyDisplayLabel(family,
  playbook.name)`, so a BAA shows "Business Associate Agreement (BAA)"
  in the consolidated report while a Mutual NDA (family "unknown" at
  the v3 detector level) still shows "Mutual NDA".

### Added
- v3 family detection in the bundle path (extends LAUNCH row v3-o to
  multi-doc). [`src/ui/pipeline.ts`](src/ui/pipeline.ts) `runBundlePipeline`
  now calls `detectV3Family` per document and exposes `v3_detection`
  on each `BundlePerDocument`. [`src/ui/states.ts`](src/ui/states.ts)
  `bundle-complete` state adds an optional
  `[data-role="bundle-detected-families"]` line that lists the human-
  readable detected families when at least one document is non-
  "unknown". Unit coverage added in [`src/ui/states.test.ts`](src/ui/states.test.ts):
  2 new tests (rendered, hidden-when-empty).
- Static a11y hardening (LAUNCH rows h / v4-f).
  [`tests/integration/static-html.test.ts`](tests/integration/static-html.test.ts)
  gains 5 new assertions: monotonic heading hierarchy (no h1 → h3
  jumps), exactly one `<h1>`, every native `<button>` has an
  accessible name (text content or aria-label), every form control
  has a label association (aria-label / aria-labelledby /
  `<label for>`), every `<a>` has a non-empty accessible name.

### Fixed
- Heading hierarchy: the source catalog cards under "Where the rules
  come from." were `<h4>` directly under the section's `<h2>`,
  skipping `<h3>`. Promoted to `<h3>` (12 cards) and the matching
  CSS selectors `.source-card h4` / `.source-card h4 span` retargeted
  to `h3`. Caught by the new monotonic-heading test.

### Added
- v3 UI hookup — Step 33 DOM wiring (LAUNCH row v3-o; spec-v3 §§60–61).
  [`src/ui/pipeline.ts`](src/ui/pipeline.ts) now calls the pure
  `detectV3Family` + `defaultFramesForPlaybook` modules and surfaces
  `v3_detection` + `v3_frames` on `PipelineResult`. [`src/ui/states.ts`](src/ui/states.ts)
  renders a "Detected: <family>" pill (`[data-role="v3-family"]`,
  carries a `data-confidence` integer percent), a compliance-frame
  chip row (`[data-role="compliance-frame-chips"]`, one `role="switch"`
  button per `ALL_FRAMES` entry, `aria-checked` mirrors the playbook
  defaults, Space + Enter flip the chip — matches the existing
  `tests/e2e/v3/a11y-keyboard.spec.ts` probe), and a one-line hint at
  `[data-role="compliance-frame-hint"]` for playbooks with no default
  frames. [`src/ui/main.ts`](src/ui/main.ts) carries the family-id →
  human-label table. Unit coverage in [`src/ui/states.test.ts`](src/ui/states.test.ts):
  5 new tests (family-chip render, hidden-when-unknown, chip-row
  aria-checked, Space + Enter toggle, hint visibility). Engine-side
  filtering on toggle is a follow-up; chip toggles are presentational
  at this hookup.
- v4 folder ingest UI hookup (LAUNCH row v4-o; spec-v4 §8 step 1).
  [`src/ui/dropzone.ts`](src/ui/dropzone.ts) now ships a second hidden
  `<input type="file" webkitdirectory multiple>` alongside the existing
  multi-file picker, plus a "choose a folder…" affordance in the empty-
  state template (`[data-role="folder-pick"]`). Folder drag-drop is
  handled in the `drop` listener via `DataTransferItem.webkitGetAsEntry()`
  and a new exported `collectFilesFromEntries` recursive walker. Both
  paths filter to `.pdf` / `.docx` before dispatching through the same
  `onFiles` channel, so `runBundlePipeline` is unchanged. Unit coverage
  added in [`src/ui/dropzone.test.ts`](src/ui/dropzone.test.ts): probe
  selector match, click-routing for the folder affordance, change-event
  filtering of non-PDF/DOCX entries, and a nested-tree walker test.
- v4 multi-doc UI hookup (LAUNCH row v4-d → 🟡 partial; spec-v4 §8 / §11).
  [`src/ui/dropzone.ts`](src/ui/dropzone.ts) now exposes
  `input[type="file"][multiple]` and accepts `.pdf,.docx,.zip`; multi-file
  drops + single-`.zip` drops route through a new `onFiles` callback so the
  pipeline owns the bundle branch (single-file behavior is unchanged).
  [`src/ui/pipeline.ts`](src/ui/pipeline.ts) ships `runBundlePipeline`
  which expands inputs (multi-file or single zip via `extractZipEntries`),
  plans the bundle via `planBundle`, runs the per-doc engine and cross-doc
  consistency against `ALL_CONSISTENCY_RULES`, and emits the consolidated
  bundle DOCX + bundle JSON via `buildBundleDocxReport` /
  `buildBundleJsonBlob`. [`src/ui/states.ts`](src/ui/states.ts) adds a
  `bundle-complete` state with `[data-role="bundle-download"]` and
  `[data-role="bundle-json-download"]` buttons plus a cross-document
  finding summary. Unit coverage: [`src/ui/dropzone.test.ts`](src/ui/dropzone.test.ts)
  (multi-file routing, zip routing, accept-list, fallback to single-file
  when `onFiles` is omitted) and [`src/ui/states.test.ts`](src/ui/states.test.ts)
  (bundle-complete render + zero-finding copy). The forward-compatible
  skip in [`tests/e2e/v4/no-network.spec.ts`](tests/e2e/v4/no-network.spec.ts)
  lifts automatically once the page is served from `dist/`. Folder-picker
  (`webkitdirectory`) affordance is the remaining piece for row v4-o.

### Fixed
- `PlaybookSchema` (`src/playbooks/types.ts`) now accepts the v3 playbook
  shape — `expected_clauses` / `expected_defined_terms` as `string[]`
  and `sources` as structured citation objects — coercing each to the
  canonical engine shape. Previously 15 of the 19 v3 playbooks failed
  Zod validation and were silently swallowed by the v3 golden harness,
  causing v3 fixtures to run under v2 fallback playbooks and their
  v3-scoped rules to never fire. All 19 v3 + 15 v4 goldens regenerated.

### Added
- Seed v3 fail-fixture corpus under [`tests/golden/v3/fixtures/`](tests/golden/v3/fixtures/):
  `baa-missing-subcontractor-flow-down-fail.txt`,
  `mutual-nda-deep-missing-dtsa-fail.txt`,
  `dpa-controller-processor-missing-documented-instructions-fail.txt`,
  `ai-addendum-training-without-optin-fail.txt`. Each exercises a
  load-bearing critical rule (BAA-018, NDA-D-001/002, DPA-007,
  ADDENDA-011 respectively). Pinned by new
  [`tests/golden/v3/fixture-sanity.test.ts`](tests/golden/v3/fixture-sanity.test.ts).
- Expand the v3 fail-fixture corpus from 4 to 7 (LAUNCH row v3-b):
  `vendor-security-addendum-missing-incident-window-fail.txt` (ADDENDA-004),
  `scc-module-2-modified-clauses-fail.txt` (TRANSFER-003 critical),
  `dpa-ccpa-service-provider-no-business-purpose-fail.txt` (USDPA-020
  critical). Sanity test now pins 7 fail-fixtures.
- Expand the v3 fail-fixture corpus from 7 to 10 (LAUNCH row v3-b):
  `unilateral-nda-deep-missing-term-fail.txt` (NDA-D-003),
  `msa-vendor-deep-no-liability-cap-fail.txt` (MSA-006),
  `uk-idta-addendum-modified-mandatory-clauses-fail.txt` (TRANSFER-015
  critical). Sanity test now pins 10 fail-fixtures.
- Expand the v3 fail-fixture corpus from 10 to 13 (LAUNCH row v3-b):
  `eula-no-license-grant-or-prohibitions-fail.txt` (ADDENDA-017),
  `scc-module-3-missing-clause-15-fail.txt` (TRANSFER-008 critical),
  `dpa-processor-subprocessor-missing-deletion-or-return-fail.txt`
  (DPA-013 critical). Sanity test now pins 13 fail-fixtures.
- Expand the v3 fail-fixture corpus from 13 to 16 (LAUNCH row v3-b):
  `baa-subcontractor-missing-return-or-destruction-fail.txt`
  (BAA-010 critical),
  `msa-customer-deep-missing-ip-indemnity-fail.txt` (MSA-001),
  `dpa-multi-state-us-missing-deletion-or-return-fail.txt`
  (USDPA-015 critical). Sanity test now pins 16 fail-fixtures.
- Expand the v3 fail-fixture corpus from 66 to 69 (LAUNCH row v3-b)
  with three new fail-fixtures spanning three distinct v3 rule families
  (TRANSFER, NDA-deep, MSA-deep) — each exercises a load-bearing rule
  not previously covered end-to-end:
  `scc-module-2-missing-clause-14-fail.txt` (TRANSFER-007 — "Clause
  14 — Local Laws and Practices Assessment" replaced by a generic
  "Destination-Country Conditions Statement" paragraph; every
  `clause 14`, `local laws and practices`, `transfer impact
  assessment`, and `TIA` anchor stripped, breaking the Schrems II
  TIA hook),
  `mutual-nda-deep-non-solicit-no-carve-out-fail.txt` (NDA-D-020
  warning — non-solicit clause added without the
  general-solicitation / public-job-postings safe-harbor language;
  the rule's negative lookahead for `general\s+solicitation` /
  `not\s+specifically\s+directed` / `general\s+advertis` fires
  within the 300-char window), and
  `msa-vendor-deep-indemnity-carved-out-of-cap-fail.txt` (MSA-005
  info — Section 8(b) "Carveouts" tightened so that "cap shall not
  apply to indemnification" sits inside the rule's 80-char
  proximity window, surfacing the commercially-contested
  cap-carve-out choice for explicit review). Sanity test now pins
  69 fail-fixtures.
- Expand the v3 fail-fixture corpus from 63 to 66 (LAUNCH row v3-b)
  with three new fail-fixtures spanning three distinct v3 rule families
  (DPA-GDPR, BAA, ADDENDA) — each exercises a load-bearing rule not
  previously covered end-to-end:
  `dpa-controller-processor-missing-art32-36-assistance-fail.txt`
  (DPA-012 — Section 9 "Assistance with Articles 32 to 36
  Obligations" replaced by a generic "Cooperation on Operational
  Matters" paragraph; every `Articles 32 to 36` and `assist ...
  (breach|security|DPIA)` anchor is stripped per GDPR Art. 28(3)(f)),
  `baa-missing-administrative-safeguards-fail.txt` (BAA-014 warning —
  Safeguards narrowed from "administrative, physical, and technical
  safeguards … 45 CFR §§ 164.308, 164.310, and 164.312" to
  "physical and technical safeguards … 45 CFR §§ 164.310 and 164.312";
  every `administrative safeguards` and `164.308` anchor stripped
  while "Security Rule" is retained so BAA-013 still passes), and
  `vendor-security-addendum-missing-named-encryption-fail.txt`
  (ADDENDA-008 warning — Section 2 rewritten to remove every named
  encryption standard, replacing AES-256 / TLS 1.2 / TLS 1.3 /
  FIPS 140-3 references with generic "industry-standard symmetric
  ciphers" and "a current version of the Transport Layer Security
  protocol"). Sanity test now pins 66 fail-fixtures.
- Expand the v3 fail-fixture corpus from 60 to 63 (LAUNCH row v3-b)
  with three new fail-fixtures spanning three distinct v3 rule families
  (BAA, NDA-deep, MSA-deep) — each exercises a load-bearing rule not
  previously covered end-to-end:
  `baa-missing-access-to-phi-fail.txt` (BAA-006 — the "Access,
  Amendment, Accounting" header is rewritten as "Amendment, Accounting";
  every `access to PHI`, `right of access`, and `164.524` anchor is
  stripped and the surviving prose uses "inspect or obtain a copy" so
  none of BAA-006's three present_patterns match — leaving the
  covered entity without a contractual hook to satisfy individuals'
  right of access under § 164.524 per 45 CFR
  § 164.504(e)(2)(ii)(E)),
  `mutual-nda-deep-unusual-governing-law-fail.txt` (NDA-D-018 info —
  governing law re-pointed from Delaware to Wyoming and venue to
  Cheyenne; NDA-D-017 still passes but Wyoming sits outside the
  viable-jurisdiction whitelist so NDA-D-018's `laws\s+of\s+...`
  present_pattern fails and the rule fires as a soft warning that an
  atypical jurisdiction may produce unpredictable NDA enforcement),
  and
  `msa-vendor-deep-one-sided-consequential-waiver-fail.txt` (MSA-008
  info — Section 8(c)'s "IN NO EVENT SHALL EITHER PARTY BE LIABLE
  TO THE OTHER PARTY" rewritten as "VENDOR SHALL NOT BE LIABLE TO
  CUSTOMER", every "neither party"/"each party"/"mutual" scoping
  stripped; MSA-008's present_pattern requires a mutual scoping
  anchor within 160 chars of a consequential-damages token, so the
  one-sided phrasing fails to match and the rule fires). Sanity
  test now pins 63 fail-fixtures.
- Expand the v3 fail-fixture corpus from 57 to 60 (LAUNCH row v3-b)
  with three new fail-fixtures spanning three distinct v3 rule families
  (BAA, NDA-deep, TRANSFER) — each exercises a load-bearing rule not
  previously covered end-to-end:
  `baa-missing-phi-amendment-fail.txt` (BAA-007 — the "Access,
  Amendment, Accounting" section is rewritten as "Access, Accounting";
  every "amendment", "amend.*PHI", and "164.526" anchor is stripped
  and the surviving sentence references only § 164.524 and § 164.528,
  with the commercial substitute deliberately avoiding both "amend"
  and "amendment" so neither alternation in BAA-007's present_patterns
  matches — leaving an amendment request bottlenecked at the BA with
  no contractual hook to satisfy § 164.526),
  `mutual-nda-deep-missing-governing-law-fail.txt` (NDA-D-017 —
  Section 8 is rewritten as "Dispute Resolution; Venue"; every
  "governing law", "governed by the laws", and "laws of the State of /
  country of" anchor is stripped and the surviving clause designates
  only a forum, explicitly disclaiming any substantive-law selection
  and deferring conflict-of-laws to the forum court — exposing the
  parties' substantive expectations to whichever forum-state
  conflict-of-laws regime picks up the case),
  `scc-module-2-missing-clause-11-fail.txt` (TRANSFER-006 warning —
  the "Clause 11 — Redress" heading is replaced by a generic
  "Customer Service Contact Point" paragraph; every "Clause 11"
  anchor and every "redress" token is stripped — the contact-point
  obligation survives in prose but the SCC clause-numbering and the
  statutory term are lost, breaking automated compliance lookups
  and internal SCC cross-references back to Clause 11).
  Sanity test now pins 60 fail-fixtures.
- Expand the v3 fail-fixture corpus from 54 to 57 (LAUNCH row v3-b)
  with three new fail-fixtures spanning three distinct v3 rule families
  (TRANSFER, MSA, DPA-GDPR) — each exercises a load-bearing rule not
  previously covered end-to-end:
  `scc-module-2-missing-clause-9-fail.txt` (TRANSFER-005 — SCC Module 2
  with the "Clause 9 — Use of Sub-Processors" heading replaced by a
  generic "Downstream Vendor Management" paragraph; every "clause 9"
  anchor is absent, breaking the prior-authorisation regime and the
  Art. 28(4) sub-processor flow-down hook),
  `msa-vendor-deep-missing-gross-negligence-indemnity-fail.txt` (MSA-004
  warning — indemnification covers only IP-infringement and Customer-
  violation claims; the gross-negligence, wilful-misconduct, and
  data-protection indemnity prong is entirely absent, leaving the
  counterparty unprotected for the highest-impact conduct categories),
  `dpa-controller-processor-missing-data-subjects-fail.txt` (DPA-005 —
  Section 2 enumerates types of personal data only; every "categories
  of data subjects" anchor is stripped and Annex I is retitled without
  a subjects enumeration, failing the GDPR Art. 28(3) introductory
  paragraph requirement).
  Sanity test now pins 57 fail-fixtures.
- Expand the v3 fail-fixture corpus from 51 to 54 (LAUNCH row v3-b)
  with three new fail-fixtures spanning three distinct v3 rule families
  (TRANSFER, DPA-GDPR, BAA) — each exercises a load-bearing rule not
  previously covered end-to-end:
  `scc-module-2-missing-clause-8-fail.txt` (TRANSFER-004 — SCC Module 2
  with the "Clause 8 — Data Protection Safeguards" heading stripped;
  all obligations survive in prose but no "clause 8" anchor remains,
  breaking automated compliance lookup and internal SCC cross-references),
  `dpa-controller-processor-missing-dsr-assistance-fail.txt` (DPA-011 —
  Section 8 rewritten to strip every "assist the controller", "data
  subject rights", and "Chapter III" anchor; processor has no explicit
  GDPR Art. 28(3)(e) obligation to assist with access, erasure,
  portability, and objection requests),
  `baa-missing-security-rule-compliance-fail.txt` (BAA-013 critical —
  Safeguards section rewritten to drop all "Security Rule", "164.30X",
  and "administrative … physical … technical" anchors; a generic
  "appropriate safeguards" clause does not satisfy 45 C.F.R.
  § 164.314(a)(2)(i)'s explicit Security Rule mandate).
  Sanity test now pins 54 fail-fixtures.
- Expand the v3 fail-fixture corpus from 48 to 51 (LAUNCH row v3-b)
  with three new NDA-deep fail-fixtures — each exercises a load-bearing
  NDA-D rule not previously covered end-to-end:
  `mutual-nda-deep-missing-return-attestation-fail.txt` (NDA-D-014 —
  return-or-destroy clause present but written certification requirement
  stripped; discloser has no contractual proof of destruction after
  relationship ends),
  `mutual-nda-deep-missing-injunctive-relief-fail.txt` (NDA-D-015 —
  injunctive-relief / irreparable-harm clause replaced by generic
  "Remedies" section; discloser must prove inadequate-remedy-at-law from
  scratch in any emergency motion),
  `mutual-nda-deep-missing-no-license-clause-fail.txt` (NDA-D-021 —
  no-license clause omitted entirely; aggressive receiver could argue
  an implied license arose from disclosure).
  Sanity test now pins 51 fail-fixtures.
- Expand the v3 fail-fixture corpus from 45 to 48 (LAUNCH row v3-b)
  with three new fail-fixtures across three distinct v3 rule families —
  each exercises a load-bearing rule not previously covered:
  `baa-missing-unreasonable-delay-language-fail.txt` (BAA-022 —
  Reporting section rewritten to keep only the 60-calendar-day outer
  bound from discovery, stripping every "without unreasonable delay"
  anchor; HIPAA's 45 C.F.R. § 164.410(b) requires *both* the inner
  "without unreasonable delay" standard *and* the 60-day cap),
  `dpa-multi-state-us-missing-subcontractor-written-contract-fail.txt`
  (USDPA-018 critical — Section 7 (Sub-Processor Management) rewritten
  to require only prior notification and vetting; "written contract" /
  "same obligations" anchors stripped, leaving the controller without
  the equivalent-obligations guarantee Va. Code § 59.1-579 requires),
  `msa-vendor-deep-missing-indemnity-procedure-fail.txt` (MSA-002 —
  Section 7(c) Indemnification Procedure stripped; no "promptly notify",
  "control of the defense", or "settlement … consent" anchor remains,
  leaving the indemnitor without ability to control its own defense and
  exposing it to moral-hazard and collusive-settlement risk).
  Sanity test now pins 48 fail-fixtures.
- Expand the v3 fail-fixture corpus from 42 to 45 (LAUNCH row v3-b)
  with three new fail-fixtures across three distinct v3 rule families —
  each exercises a load-bearing rule not previously covered:
  `mutual-nda-deep-missing-independent-development-exclusion-fail.txt`
  (NDA-D-009 — "independently developed" prong removed from Section 2
  Carveouts; the final sentence affirmatively ropes in information
  generated by the Receiving Party's own personnel, so ordinary parallel
  R&D by exposed staff could be captured as a breach),
  `baa-missing-breach-discovery-trigger-fail.txt` (BAA-021 — breach-
  notification clock runs from "confirmation and written assessment"
  rather than from "discovery of the breach", stripping every "discovery
  of the breach" anchor; shifting the trigger post-discovery can cause
  the covered entity to blow the 45 C.F.R. § 164.410 60-day statutory
  cap before the BA's clock even starts),
  `dpa-multi-state-us-missing-compliance-demonstration-fail.txt`
  (USDPA-019 critical — Section 3 (Virginia VCDPA Processor Obligations)
  drops the "make available all information necessary to demonstrate
  compliance" sentence and Section 12 renames to "Attestation" with
  "adherence" language, removing every "demonstrate compliance" anchor
  required by Va. Code § 59.1-579 and equivalent state statutes).
  Sanity test now pins 45 fail-fixtures.
- Expand the v3 fail-fixture corpus from 39 to 42 (LAUNCH row v3-b)
  with three new fail-fixtures across three distinct v3 rule families —
  each exercises a load-bearing rule not previously covered:
  `mutual-nda-deep-missing-third-party-exclusion-fail.txt` (NDA-D-008 —
  "third party lawfully obtained" carve-out removed from Carveouts; last
  sentence reincorporates information from any "external party not under a
  separate NDA", closing the standard third-party-channel safe harbour),
  `msa-vendor-deep-missing-force-majeure-fail.txt` (MSA-022 — force-majeure
  clause rewritten as vendor-only "Excused Performance" with no bilateral
  "neither party" / "either party" framing; commercially abnormal one-sided
  scope leaves Customer without relief for its own force-majeure events),
  `baa-missing-cure-infeasible-termination-fail.txt` (BAA-012 — Term and
  Termination section rewrites to cure-period + insolvency termination only,
  stripping every "cure is not feasible" / "infeasible to cure" anchor; HHS
  guidance expects BAAs to permit exit when a HIPAA breach cannot be cured).
  Sanity test now pins 42 fail-fixtures.
- Expand the v3 fail-fixture corpus from 36 to 39 (LAUNCH row v3-b)
  with three new fail-fixtures across three distinct v3 rule families —
  each exercises a load-bearing rule not previously covered:
  `mutual-nda-deep-missing-prior-knowledge-exclusion-fail.txt`
  (NDA-D-007 — "already known / prior to disclos" exclusion removed from
  Section 2 Carveouts, replaced with an affirmative sentence that sweeps
  in information regardless of when the Receiving Party came to know it),
  `msa-vendor-deep-missing-sla-fail.txt` (MSA-016 — no SLA, uptime, or
  availability commitment reference anywhere in an otherwise complete
  vendor-form MSA; customer has no contractual remedy for downtime),
  `dpa-controller-processor-missing-art32-security-measures-fail.txt`
  (DPA-009 critical — Section 6 rewritten to a vague general-security-
  commitment paragraph, stripping every reference to "Article 32",
  "technical and organisational measures", "encryption",
  "pseudonymisation", CIA-R, restore-availability, and regular-testing).
  Sanity test now pins 39 fail-fixtures.
- Expand the v3 fail-fixture corpus from 33 to 36 (LAUNCH row v3-b)
  with three new fail-fixtures across three distinct v3 rule families —
  each exercises a load-bearing rule not previously covered:
  `dpa-controller-processor-missing-compliance-demonstration-fail.txt`
  (DPA-014 critical — Section 11 replaced with internal-records-only
  clause, stripping every "demonstrate compliance" / audit-cooperation
  anchor required by GDPR Art. 28(3)(h)),
  `dpa-multi-state-us-missing-audit-cooperation-fail.txt` (USDPA-017
  critical — audit-cooperation clause replaced with annual security-
  program clause, stripping every "allow and cooperate with reasonable
  assessments" / assessor anchor),
  `msa-vendor-deep-missing-compliance-noninfringement-warranty-fail.txt`
  (MSA-014 — no comply-with-laws or non-infringement warranty clause
  present; Section 6 covers only workmanlike performance and malware-
  free deliverables). Sanity test now pins 36 fail-fixtures.
- Expand the v3 fail-fixture corpus from 30 to 33 (LAUNCH row v3-b)
  with three new fail-fixtures across three distinct v3 rule families —
  each exercises a load-bearing rule not previously covered:
  `baa-missing-accounting-of-disclosures-fail.txt` (BAA-008 critical —
  "accounting of disclosures" / 164.528 anchor stripped from the
  Individual Rights section),
  `msa-vendor-deep-missing-service-warranties-fail.txt` (MSA-013 —
  Section 6 rewritten to a flat AS-IS disclaimer stripping workmanlike /
  conformance-to-documentation / no-malicious-code warranty families),
  `mutual-nda-deep-missing-public-domain-exclusion-fail.txt` (NDA-D-006 —
  "publicly available" / "public domain" carve-out removed from the
  Carveouts section). Sanity test now pins 33 fail-fixtures.
- Expand the v3 fail-fixture corpus from 27 to 30 (LAUNCH row v3-b)
  with a fourth failure-mode fixture per already-covered playbook —
  exercising a distinct load-bearing rule that prior fixtures did not:
  `baa-missing-breach-notification-fail.txt` (BAA-019 critical —
  Reporting section rewritten to drop the "breach of unsecured PHI" /
  164.410 anchor, leaving the notification obligation legally
  ambiguous),
  `mutual-nda-deep-missing-ci-definition-fail.txt` (NDA-D-005 —
  "Confidential Information means …" definition block removed so
  confidentiality scope is undefined),
  `msa-customer-deep-missing-data-return-fail.txt` (MSA-021 —
  data-portability / return-on-termination section stripped, leaving
  customer locked out of its own data). Sanity test now pins 30
  fail-fixtures.
- Expand the v3 fail-fixture corpus from 24 to 27 (LAUNCH row v3-b)
  with a third failure-mode fixture per already-covered playbook —
  exercising a distinct load-bearing rule that prior fixtures did not:
  `baa-missing-termination-for-breach-fail.txt` (BAA-011 critical —
  termination-for-material-breach right stripped, leaving only
  convenience and insolvency termination),
  `msa-vendor-deep-missing-cap-carveouts-fail.txt` (MSA-007 —
  Section 8(b) cap carve-outs block removed so aggregate cap absorbs
  fraud / wilful-misconduct / IP-indemnity / confidentiality claims),
  `mutual-nda-deep-missing-perpetual-trade-secret-fail.txt` (NDA-D-004
  — perpetual trade-secret carve-out stripped, leaving a flat
  three-year term). Sanity test now pins 27 fail-fixtures.
- Expand the v3 fail-fixture corpus from 21 to 24 (LAUNCH row v3-b)
  with a second failure-mode fixture per already-covered playbook —
  exercising a distinct load-bearing rule that prior fixtures did not:
  `msa-customer-deep-missing-termination-clause-fail.txt` (MSA-018 —
  termination-for-material-breach / cure-period clause removed),
  `mutual-nda-deep-missing-return-or-destruction-fail.txt` (NDA-D-013
  — return-or-destruction section stripped entirely),
  `dpa-multi-state-us-missing-confidentiality-duty-fail.txt`
  (USDPA-016 — "bound by confidentiality" anchor replaced with generic
  access-control language). Sanity test now pins 24 fail-fixtures.
- Expand the v3 fail-fixture corpus from 18 to 21 (LAUNCH row v3-b)
  with a second failure-mode fixture per already-covered playbook —
  exercising a distinct load-bearing rule that prior fixtures did not:
  `baa-missing-hhs-books-records-fail.txt` (BAA-009 critical — 45
  C.F.R. § 164.504(e)(2)(ii)(H) HHS Secretary books-and-records
  availability),
  `dpa-controller-processor-missing-personnel-confidentiality-fail.txt`
  (DPA-008 critical — GDPR Art. 28(3)(b) personnel confidentiality
  commitment),
  `msa-vendor-deep-missing-background-foreground-ip-fail.txt`
  (MSA-011 — commercial drafting baseline background/foreground IP
  allocation). Sanity test now pins 21 fail-fixtures.
- Expand the v3 fail-fixture corpus from 16 to 18 (LAUNCH row v3-b):
  `saas-tos-no-click-to-cancel-fail.txt` (ADDENDA-019 — phone-only
  cancellation strips every FTC Click-to-Cancel / ROSCA anchor),
  `privacy-policy-lint-missing-disclosures-fail.txt` (ADDENDA-020 —
  vague boilerplate strips every CCPA § 1798.130 / GDPR Art. 13–14 /
  data-subject-rights anchor). Sanity test now pins 18 fail-fixtures.
  The remaining v3 playbook without a fail-fixture (`coi`) carries no
  v3 presence rules; coverage will land alongside the ACORD-25
  spatial extractor.

---

## [v4.0.0] — 2026-05-17

v4 expands the catalog from contracts (v1) and regulated agreements (v3) to all logically-operative legal documents — 16 sub-domains, 700+ new rules, multi-document ingest (folder / zip / multi-file drop), and a cross-document consistency engine. UI surface unchanged per spec-v4 §18. Determinism contract preserved.

### Added

- **v4 Step 61 — Test corpus expansion** (spec-v4.md Part VI).
  New v4 golden-test harness at `tests/golden/v4/` mirroring
  `tests/golden/v3/`: `_pipeline.ts` loads LAUNCH + v3 + every v4
  playbook and runs `LAUNCH_RULES + V3_RULES + V4_RULES`;
  `golden.test.ts` is the single-doc harness; `bundle.test.ts` is
  the multi-doc harness driving `runEngineMulti` +
  `CONSISTENCY_RULES` (spec-v4.md §§10–11). 15 single-doc fixtures
  (one per v4 sub-domain B–P) with `.playbook` sidecars; 5
  multi-doc bundles (party-name-conflict, governing-law-mismatch,
  effective-date-paradox, cap-mismatch, clean-msa-baa) exercising
  the CROSS-* rule families. Three sanity guards per fixture
  (golden match, two-run determinism, v4-playbook + ≥1 finding).
  Regeneration via `VAULYTICA_REGEN_GOLDEN=1`. 62 new tests;
  1124/1124 + 2 skips.
- **v4 Step 60 — DKB build pipeline (v4 fetchers)** (spec-v4.md §13).
  Eight v4 source families wired under `dkb/build/v4/fetchers/`
  emitting v3 DKB nodes (spec §12: v3 schema reused, no v4-specific
  node type): `nvca` (NVCA model legal documents — SPA, IRA, Voting,
  ROFR/Co-Sale, COI, Term Sheet); `dgcl` (DGCL §§ 102, 109, 141, 211,
  251, 262); `mbca` (ABA MBCA §§ 2.02 / 7.01–7.02 / 8.01 / 10.03);
  `ucc-article-2/3/9` (Cornell LII — § 2-201, § 2-314, § 2-316,
  § 3-104, § 3-305, § 9-203, § 9-108, § 9-502); `aia` (A101 / A102 /
  A201 / A401 / G701 / G702-G703 catalog); `frcp` + `fre` (Rules
  37(e), 41, 408, 502); `state-landlord-tenant` (CA / NY / TX / FL /
  IL); `state-trust-will` (CA / NY / TX / FL / IL). 19 fetcher ids
  registered in `V4_FETCHERS`. Snapshot fixtures vendored at
  `dkb/fixtures/v4/snapshots/{sha256(source_url)}.txt`. Step-20
  staleness gate covers v4 nodes unchanged because they pass through
  the v3 `V3DkbNodeListSchema`. 31 new tests; 1062/1062 + 2 skips.
- **v4 Step 44 — consolidated bundle report renderer** (spec-v4.md §11).
  New `src/report/bundle.ts` ships `buildBundleDocxReport`,
  `buildBundleJson` / `buildBundleJsonBlob`, `buildBundleZip`, and
  `bundleFingerprint`. The DOCX includes cover (bundle fingerprint,
  document count, engine + DKB versions, ISO date), executive summary
  (per-document + cross-document severity counts), per-document
  subsections capped at `BUNDLE_TOP_N = 10` findings each, the full
  cross-document consistency appendix, a deduped citation
  bibliography, the full audit trail (per-doc + cross-doc execution
  logs with elapsed times), and the standard determinism / privacy /
  non-advice disclaimer block. The bundle zip pins per-entry mtime to
  2000-01-01 UTC so the zip envelope is byte-identical across runs.
  Bundle JSON shape: `{ runs, cross_doc_findings, bundle_fingerprint,
  dkb_version, engine_version }`. The `fflate` dep introduced in Step
  41 for zip ingest is reused for the §11 zip output path — one
  library, two paths. 13 new unit tests; 864/864 passing.

## [v3.0.0] — 2026-05-16

The **compliance & regulated-agreement expansion** release. v3 extends
v2 with 220 new rules across HIPAA, GDPR / UK GDPR, eight US state
privacy laws, EU SCCs, the UK IDTA + Addendum, Swiss Addendum,
international privacy regimes, trade-secret law, commercial-law
overlays, insurance norms, and the AI / vendor-security / EULA / ToS /
privacy-policy / COI surfaces. Same posture as v2: browser-only, no AI,
no telemetry, no server.

### Headline additions

- **220 new rules** across seven rulesets — BAA (45), DPA-GDPR (55),
  DPA-US-state (25), MSA-deep (30), NDA-deep (25), Transfer (20),
  Addenda (20). `V3_RULES` ships alongside `LAUNCH_RULES`; the runner
  filters by playbook so v2's `result_hash` is preserved.
- **Nine v3 extractors** under `src/extract/v3/` covering role
  classification, PII / PHI category detection, cross-border transfer
  mechanisms, security-measures inventory, breach-notification timing,
  audit-rights extraction, subprocessor inventory, insurance schedules,
  and DTSA whistleblower-notice detection.
- **Cross-document consistency engine** at `src/engine/consistency/`
  with seven cross-document rules (BAA permitted-uses no broader than
  MSA, DPA purpose matches MSA services, DPA data categories not
  broader than MSA, BAA term aligns with MSA, governing-law alignment,
  notice-clause alignment, order-of-precedence consistency). The
  engine accepts up to four documents in one bundle, mirrors the v2
  determinism contract (SHA-256 over canonicalized run JSON with
  volatile fields blanked), and emits findings that cite every
  contributing document with the conflicting text from each.
- **DOCX report extensions** under `src/report/v3/`: compliance-matrix
  section with Pass / Partial / Fail / N/A cell shading and screen-
  reader-friendly table semantics; cross-border transfer summary page;
  subprocessor inventory page; insurance summary page; two-document
  consistency appendix; citation-depth verification appendix with
  Word `ExternalHyperlink` click-through; per-page footer carrying
  engine version + DKB version + result hash + "Citations as of [date]".
  All conditional on the corresponding input being present; the v2
  API is unchanged.
- **DKB v3 expansion** with six new node types (`regulator_model_form`,
  `statutory_clause_requirement`, `transfer_mechanism`,
  `subprocessor_requirement`, `insurance_norm`, `consistency_check`),
  source-pinning protocol with content-hash-at-pin, weekly staleness
  detector with explicit ack-or-fail gate, and 24 new fetchers covering
  the full v3 source catalog (eCFR Title 45; HHS sample BAA; OCR
  resolutions; CCPA + 7 US state-privacy statutes; GDPR; EU SCCs
  2021/914 with all four modules; UK GDPR; UK IDTA; UK Addendum; Swiss
  revFADP + Addendum; EDPB guidelines; PIPEDA; LGPD; APPI; PIPL).
- **v3 UI primitives** at `src/ui/v3/` — pure detection scorer over 12
  document families, compliance-frame chip-row defaults per playbook
  (DPA → GDPR + CCPA on; BAA → HIPAA on; MSA → all off with a hint),
  immutable multi-document state reducer with `MAX_DOCUMENTS = 4`, and
  centralized empty-state and error-state copy.
- **v3 documentation** — seven new docs under `docs/v3/`: overview,
  adding-a-baa-rule, adding-a-dpa-rule, adding-a-playbook, regulators
  (full source catalog), two-document-mode, compliance-matrix.
- **v3 threat-model expansion** — new section in `docs/threat-model.md`
  covering DKB integrity, the staleness gate, the citation surface,
  the "consensus practice" AI-addendum disclaimer, and the explicit
  non-promise of universal regulator coverage.
- **v3 launch checklist** in `LAUNCH.md` with 15 v3-specific items
  tracked end-to-end.
- **v3 golden-output harness** at `tests/golden/v3/` running
  `LAUNCH_RULES ∪ V3_RULES`, with sidecar-driven playbook forcing,
  byte-identical-in-process determinism check, and one starter BAA
  fixture committed and baselined.
- **v3 bundle-size guard** at `tests/integration/bundle-size.test.ts`
  enforcing eager-entry ≤ 50 KB gzipped and total payload ≤ v2 + 600 KB.
- **v3 Playwright specs** at `tests/e2e/v3/` — no-network privacy
  guard and keyboard-accessibility coverage (with forward-compatible
  probes for the v3 chip row + multi-doc cards).

### Changed

- `package.json` version bumped from `1.0.0` to `3.0.0`. (v2 is
  represented by spec-v2.md and the v2 launch entry but never received
  its own package version bump — going straight to 3.0.0 keeps the
  spec-and-package versions aligned.)
- `README.md` "What I check" gains a v3 line pointing to
  `docs/v3/overview.md`.
- DOCX report builder `buildDocxReport` takes an optional fifth
  `v3?: V3ReportInputs` argument; v2 callers are unchanged.

### Citations

Every v3 rule cites a specific regulator subdivision or a DKB-pinned
practitioner source. Every citation in every report renders as a
Word `ExternalHyperlink` in the citation-index appendix. The DKB
staleness gate is wired and exits non-zero on unacknowledged drift.

### Detail (per spec-v3 build step)

The entries below were accumulated under `[Unreleased]` during the
v3 build sequence (spec-v3 Part IX, Steps 18–39). They are preserved
here so the per-step rationale is part of the v3.0.0 release record.

- **v3 documentation (spec-v3 Step 35):** seven new markdown documents under `docs/v3/` cover the full v3 surface — `overview.md` (audience, scope, what's new vs. v2), `adding-a-baa-rule.md` (HIPAA-anchored rule walkthrough with the BAA-NNN presence/language factories), `adding-a-dpa-rule.md` (GDPR Art. 28 + US-state-privacy walkthrough with the generic `_regulated-rule.ts` factory), `adding-a-playbook.md` (v3 playbook schema additions — `regulator_frame`, `applicable_jurisdictions`, `companion_playbooks`, `compliance_matrix_columns` — with per-family column conventions), `regulators.md` (the full source catalog with canonical URLs grouped by US-HIPAA-privacy / EU / UK / Switzerland / international / trade-secret / commercial-law / insurance / AI-consensus-practice), `two-document-mode.md` (when to use, the seven shipped consistency rules, how findings are shaped, the determinism contract, how to add a CC-NNN rule), and `compliance-matrix.md` (anatomy of the matrix, what Partial means, how to cite the matrix in an audit, what the matrix does not say). `README.md` gains the v3 line; `docs/threat-model.md` gains a v3-specific section covering DKB integrity, the staleness gate, the citation surface, the "consensus practice" AI-addendum disclaimer, and the explicit non-promise that v3 covers every regulator. All gates green: typecheck clean, lint clean, **788/788 tests + 2 skips**, build green.
- **Threat-model v3 expansion (spec-v3 Step 38):** new "v3 additions" section in `docs/threat-model.md` covering five new attack surfaces and trust assumptions that v3 introduces — DKB integrity, the staleness gate, the citation surface, the "consensus practice" AI-addendum disclaimer, and the explicit non-promise that v3 covers every regulator in every jurisdiction. The section closes with a "what v3 still does not protect against" enumeration consistent with the v2 threat model.
- **v3 extractors (spec-v3 Step 30, 9 modules):** all nine placeholder stubs under `src/extract/v3/` are now real, deterministic, pure functions. `role-classifier.ts` walks each paragraph in document order and pulls roles by priority (`definition` > `recital` > `clause-usage`), keyed to a 12-role controlled vocabulary (covered-entity / business-associate / subcontractor / controller / processor / sub-processor / joint-controller / third-party / service-provider-ccpa / contractor-ccpa / service-recipient / service-supplier). `pii-category.ts` catalogs HIPAA's 18 identifiers + GDPR Art. 9 special categories + Art. 10 criminal convictions + CCPA sensitive personal information, plus a separate "special categories" flag that fires on the umbrella phrase. `transfer-mechanism.ts` classifies SCC modules 1–4 + UK IDTA + UK Addendum + Swiss Addendum + Adequacy + BCR + Art. 49 + DPF, suppresses unspecified-SCC when a more-specific module hit the same paragraph, and infers location by precedence `annex > attachment > hyperlink > by-reference > recital-only > inline`. `security-measures.ts` normalizes a 17-slug controlled vocabulary (encryption-at-rest / encryption-in-transit / MFA / SSO / vuln-scanning / pen-testing / training / BCP-DR / IR / RBAC / logging-audit / network-seg / hardware-tokens / SDLC / SOC2-T2 / ISO-27001 / HITRUST) with cadence + scope inference. `breach-timing.ts` matches breach↔notification in either order, normalizes hour/day windows, and preserves vague phrases ("without unreasonable delay", "promptly", "as soon as practicable") when no numeric value is present. `audit-rights.ts` extracts frequency, notice, scope, permitted methods (onsite / remote / questionnaire / SOC 2 substitution / third-party auditor), cost allocation, confidentiality, and third-party-auditor permission. `subprocessor.ts` returns the most-informative subprocessor paragraph as a single normalized record covering Art. 28(2) consent form, list location (annex / URL / on-request / absent), notice days, objection right + consequence, and Art. 28(4) flow-down. `insurance.ts` extracts per-line amounts (CGL / professional / cyber / umbrella / WC / employers / auto / EPLI / fiduciary / other) with per-occurrence vs. aggregate split, ISO endorsement form numbers (CG 20 10 / CG 20 37 / CG 20 26 etc.), AM-Best rating, and notice of cancellation. `dtsa-notice.ts` detects the 18 U.S.C. § 1833(b) notice and substantive completeness across all three pillars — § 1833(b)(1) government/attorney disclosure, § 1833(b)(2) under-seal court filing, and contractor/consultant coverage. `types.ts` declares the full `V3ExtractedData` aggregate; `index.ts` re-exports every extractor + `extractAllV3(tree, {parties?})` convenience that runs all nine in dependency order. Tests at `tests/v3/extract/v3-extractors.test.ts` (23/23 passing) cover one positive + one empty/edge case per extractor + an aggregate determinism check. **723/723 tests passing + 2 intentional skips.** The v3 rule engine continues to run pattern-based against the raw document for now — Step 31 (consistency-check engine) and Step 32 (report renderer) will thread these structured outputs through, so this step is purely additive. ACORD-25 binary spatial-layout parsing for COIs remains deferred to a follow-up that depends on v2's PDF text-with-position output, consistent with the Step 29 note.
- **Addenda ruleset + six new playbooks (spec-v3 Step 29, 20 rules):** new `src/engine/rules/v3/addenda/` ruleset implementing §34 across six playbook surfaces — vendor-security-addendum (ADDENDA-001..009), ai-addendum (ADDENDA-010..016), eula (ADDENDA-017..018), saas-tos (ADDENDA-019), privacy-policy-lint (ADDENDA-020). Coverage on the **security** surface: enumerated controls + named encryption (FIPS 140-3 / AES-256 / TLS 1.2+) + security-review cadence + right-to-audit / SOC 2 substitution + incident-response window + vulnerability-disclosure + SDLC + data-classification + pen-test cadence. **AI** surface: definitions (Generative AI / Foundation Model / Output / Training Data), prohibited training-on-customer-data without opt-in (**critical**), transparency (features + default state + hosting), IP ownership of outputs, hallucination disclaimer + human-review obligation, AI subprocessor disclosure, fine-tuning-data deletion on termination. AI citations explicitly carry the "consensus practice, not statute" framing per spec §34 — NIST AI RMF / EU AI Act / FTC enforcement actions. **EULA** surface: license grant + prohibited uses; EU Digital Content Directive 2019/770 minimums. **ToS** surface: FTC Click-to-Cancel + ROSCA alignment. **Privacy-policy-lint**: CCPA § 1798.130 + GDPR Art. 13/14 + COPPA § 312.4 disclosures. New DKB node `dkb/fixtures/v3/nodes/am-best-ratings.json` carries acceptable / marginal / unacceptable AM Best rating buckets ("AM Best public ratings as of 2026-05-13 (DKB build date)") plus 8 curated common carriers. The six playbooks (`vendor-security-addendum`, `ai-addendum`, `eula`, `saas-tos`, `privacy-policy-lint`, `coi`) upgraded from placeholder to v1.0.0 with title keywords, distinguishing phrases, expected defined terms, multi-source citations, and per-surface compliance-matrix columns. `V3_RULES` now ships 220 rules total (ADDENDA 20 + BAA 45 + DPA-GDPR 55 + DPA-US-state 25 + MSA-deep 30 + NDA-deep 25 + Transfer 20). Tests at `src/engine/rules/v3/addenda/addenda-ruleset.test.ts` (12/12 passing): registry contract, inert-when-no-playbook, surface scoping (security rules don't fire on AI playbook), compliant security + compliant AI fixtures → 0 criticals, six failure-mode tests covering each surface, determinism. ACORD-25 binary spatial-layout extractor, real privacy-policy fixture corpus, and the privacy-policy / DPA consistency check are deferred to a follow-up commit (same pattern as Steps 27 + 28).
- **MSA-deep ruleset (spec-v3 Step 28, 30 rules):** new `src/engine/rules/v3/msa-deep/` ruleset implementing the §33 MSA-deep rules (MSA-001 through MSA-030). Coverage: indemnification scope + procedure + cap-carve-out flag (001–005); aggregate cap + carve-outs + mutual consequential waiver + California Civil Code § 1668 overlay + N.Y. Gen. Oblig. Law § 5-322.1 anti-indemnity (006–010); IP allocation (background / foreground) + feedback license scope (011–012); service warranties (workmanlike + conformance + no-malicious-code + compliance + non-infringement) + UCC § 2-316 implied-warranty disclaimer overreach (013–015); SLA reference + sole-and-exclusive-remedy flag (016–017); termination for material breach / insolvency / wind-down (018–020); data return / portability (021); balanced force majeure (022); assignment change-of-control silence (023); governing-law vs venue mismatch (024); amendment + no-waiver + survival + entire-agreement boilerplate (025–026); custom **order-of-precedence consistency** rule that fires when MSA precedence places it over the SOW yet operative terms (indemnity, liability cap, IP, warranty) actually live in the subordinate document (027); AI usage clause presence (NIST AI RMF, 028); Tex. Bus. & Com. Code § 151.102 anti-indemnity overlay (029); UCC § 2-719(2) limited-remedy fail-of-essential-purpose escape (030). All rules carry `category: "msa-deep"` and `applies_to_playbooks: ["msa-vendor-deep", "msa-customer-deep"]`, leaving v2's `msa-general` / `saas-vendor` / `saas-customer` LAUNCH determinism untouched. New DKB node `dkb/fixtures/v3/nodes/state-commercial-overlays.json` carries 5 `statutory_clause_requirement` entries (Cal. Civ. Code § 1668, N.Y. Gen. Oblig. § 5-322.1, Tex. Bus. & Com. Code § 151.102, U.C.C. § 2-316, U.C.C. § 2-719). `msa-vendor-deep.json` and `msa-customer-deep.json` playbooks upgraded from placeholder to v1.0.0 with title keywords, distinguishing phrases, expected defined terms, three commercial source citations each, and 16-/17-column compliance matrices. `V3_RULES` now ships 200 rules total (BAA 45 + DPA-GDPR 55 + DPA-US-state 25 + MSA-deep 30 + NDA-deep 25 + Transfer 20). Tests at `src/engine/rules/v3/msa-deep/msa-deep-ruleset.test.ts` (10/10 passing): registry contract, inert-when-no-MSA-playbook, compliant-MSA fixture under both vendor + customer playbooks → 0 criticals, five failure-mode tests (MSA-006/009/005/017/027), determinism. Playbook v2 deprecation (`msa-general` / `saas-vendor` / `saas-customer` → `*-legacy`) and Common Paper + SEC-EDGAR-sourced real-MSA fixture corpus deferred to a follow-up commit (same pattern as Step 27).
- **NDA-deep ruleset (spec-v3 Step 27, 25 rules):** new `src/engine/rules/v3/nda-deep/` ruleset implementing the 25 NDA-deep rules of spec-v3 §32 (NDA-D-001 through NDA-D-025). Coverage: DTSA whistleblower-immunity notice presence + three-pillar completeness (18 U.S.C. § 1833(b)); confidentiality term + trade-secret perpetual carve-out; all four standard Confidential-Information exclusions (publicly available, previously known, third-party lawful, independently developed); residuals-clause flag at info severity; permitted-use scope detector + 'to evaluate the Purpose' framing; return-or-destruction with attestation; injunctive relief + irreparable harm + waiver of bond; governing-law presence and viable-jurisdiction soft warning; no-precedent / MFN, non-solicit-without-general-solicitation-carve-out, no-license, authority representation, successors-and-assigns with consent; mutual-NDA symmetry detector (scoped to `mutual-nda-deep` only); unilateral-NDA role-framing check (scoped to `unilateral-nda-deep` only). Rules are `category: "nda"` and scoped via `applies_to_playbooks: ["mutual-nda-deep", "unilateral-nda-deep"]`, leaving v2's `mutual-nda` / `unilateral-nda` LAUNCH determinism untouched. `V3_RULES` now ships 170 rules total. Tests at `src/engine/rules/v3/nda-deep/nda-deep-ruleset.test.ts` (8/8 passing) — registry contract, playbook scoping, compliant-mutual-NDA fixture → 0 criticals, determinism, four failure-mode cases. Playbook v1.0.0 metadata refresh and Common Paper / CUAD fixture corpus deferred to a follow-up commit.

### Changed

- **Browser tab title simplified to "Vaulytica":** removed the keyword-rich subtitle from `<title>` in `site/index.html`. OG / Twitter / JSON-LD titles (which carry the full SEO copy) are unchanged.
- **Research-driven fixture + rule expansion (rule count 101 → 106; fixture corpus 13 → 25):** a 3-agent parallel research swarm surfaced common real-world drafting pitfalls absent from the existing catalog (residuals clauses, AI/ML training rights over Customer Data, training-repayment / "TRAP" clauses, unilateral SaaS suspension, out-of-state choice-of-law on California workers, MFN pricing, CAM gross-up asymmetry, security-deposit overcollection, hostage-data termination, AMN-style non-solicits, DTSA whistleblower notice gaps). Twelve new bad-* fixtures were synthesized to exercise each pattern, each generated deterministically by `tests/fixtures/build-fixtures.ts`. Five high-value rules were added to catch the most common patterns:
  - **OBLI-009 — Residuals clause swallows confidentiality (warning, obligations; 102nd rule).** Detects `Residuals` / `unaided memory` / `general knowledge, skills and experience` carve-outs that effectively license trade secrets via human memory. Cites Dentons / Venable / Galkin practitioner guidance. 4 dedicated tests.
  - **CHOICE-011 — Out-of-state choice-of-law on California worker (warning, choice-and-venue; 103rd rule).** Fires when a California-resident / California-working signal is present AND the governing-law selection is non-California. Cites Cal. Lab. Code § 925 and Cal. Bus. & Prof. Code § 16600.5. 3 dedicated tests.
  - **PERS-008 — Training-repayment / stay-or-pay clause (critical, personnel; 104th rule).** Detects training-cost / signing-bonus / relocation claw-back clauses. Cites NLRB GC Memorandum 25-01 (Oct. 7, 2024) and N.Y. Trapped at Work Act (Dec. 2025). 5 dedicated tests.
  - **DARK-008 — Unilateral suspension without notice or cure (warning, dark-patterns; 105th rule).** Detects `Vendor may suspend the Service immediately / without notice / in its sole discretion` framings. Cites Morgan Lewis Sourcing@MorganLewis + ContractNerds. 3 dedicated tests.
  - **IPDATA-009 — AI / model-training rights over Customer Data (critical, ip-and-data; 106th rule).** Detects licenses to use Customer Data to train / develop / improve ML / AI models. Cites GDPR Art. 17, *Andersen v. Stability AI*, *Getty Images v. Stability AI*. 3 dedicated tests.

  Sanity-guard entries were added in `tests/integration/fixture-sanity.test.ts` for all 12 new fixtures, and the golden corpus was regenerated against the new 106-rule registry. **Fixture corpus is now 25 fixtures (target was ≥2–3 per major category); every launch playbook now has 2–3 distinct exemplars in the bad-* corpus.**

### Changed

- **Bundle splitting for initial-load performance (LAUNCH.md row l):** the full analysis pipeline (pdfjs, mammoth, docx, decimal, zod, tesseract) is split out of `src/ui/main.ts` into `src/ui/pipeline.ts` and dynamic-imported on first file drop / drag-over / `requestIdleCallback`. Initial-load JS shrinks from **560 KB → 9.51 KB** (gzipped 165 KB → 3.75 KB) — a ~45× reduction in what blocks first paint.
- **Manual chunk groups in `vite.config.ts`:** every heavy dependency is now an isolated vendor chunk (`vendor-pdfjs`, `vendor-mammoth`, `vendor-docx`, `vendor-tesseract`, `vendor-decimal`, `vendor-zod`) so a bump to one dep doesn't invalidate the cache for the others. With the year-long immutable cache on `/assets/*`, returning users only pay for the chunk that actually changed. Vaulytica's own pipeline code is its own ~115 KB (36 KB gz) chunk.
- **Parallel playbook fetch:** `ensurePlaybooks` in `src/ui/pipeline.ts` now fetches all 12 launch playbook JSONs via `Promise.all` instead of a sequential `for`-loop. Order in the result still mirrors `LAUNCH_PLAYBOOK_IDS` (Promise.all preserves index). The service worker pre-caches `/playbooks/*` so cold load gets HTTP/2 multiplexing; warm load is cache-hit-then-respond regardless.
- **FIN-001 + FIN-002 no longer skipped by NDA playbooks:** both rules have narrow pattern matchers (`<spelled-out amount> (<numeral>)` and `the <Name> of $X`) so they only fire when monetary content actually appears in the document. Skipping them on NDAs was over-cautious — when an NDA *does* carry a liquidated-damages clause, the mismatch is a real drafting error worth catching. The bad-nda fixture's intentional `fifty thousand dollars ($75,000)` mismatch now fires. **bad-nda intentional-violation detection now sits at 5/5 (was 4/5).** Other FIN-* rules (003 through 008 — fees, payment terms, late fees, etc.) remain skipped on NDA playbooks because they truly don't apply.

### Added

- **PERS-007 — IC misclassification signals (warning, personnel; 101st rule)**: when the document labels a worker as `independent contractor` AND ≥2 employee-indicator signals appear (fixed daily hours / company-supplied equipment / daily reporting / exclusivity / salary-like flat monthly retainer / required on-site presence), the rule fires. Cites IRS 20-factor test, DOL economic-realities test, California AB-5 ABC test, Massachusetts M.G.L. c.149 §148B. 6 dedicated tests including a clean IC engagement (silent), 2-signal, 3-signal, label-without-signals, signals-without-label, and salary-shaped-IC paths.
- **Lighthouse CI workflow + budgets (LAUNCH.md row l)**: new `.github/workflows/lighthouse.yml` + `lighthouserc.json` run Lighthouse against the built `dist/` on every push and PR using the mobile-4G throttled preset. CI fails if FCP > 1500 ms, LCP > 2000 ms, TTI > 2000 ms, TBT > 200 ms, CLS > 0.1, or category scores drop below performance 0.85 / accessibility 0.95 / best-practices 0.9 / SEO 0.9. 3 runs per build to dampen noise. Catches performance regressions before they reach `vaulytica.com`.
- **Playbook fixture coverage enforcement (`tests/integration/playbook-coverage.test.ts`)**: 13 assertions — for every id in `LAUNCH_PLAYBOOK_IDS`, the test runs every committed fixture and asserts that at least one fixture's matched playbook is that id, OR that the id is explicitly listed in `EXEMPT_PLAYBOOK_IDS` with a stated reason. Today's exempt list: `generic-fallback` (implicit fallback) and `saas-vendor` (overlaps saas-customer for generic SaaS docs; exercised via bad-saas-vendor.docx but matched as saas-customer). A new playbook added without a fixture now fails CI.
- **`bad-sow.docx` fixture (corpus 12 → 13)**: targets the `sow` playbook (child of `msa-general`). Matched `sow` at 0.9 confidence. Intentional violations: undefined deliverables (`as further detailed by Customer from time to time at Customer's sole discretion`), 2%/month late fee, `[TBD]` placeholder, `best efforts` undefined. Sanity guard locks in STRUCT-013, FIN-009, OBLI-008. **Playbook fixture coverage: 10 → 11 of 12 launch playbooks** — only the implicit `generic-fallback` is now uncovered, and that's by design.
- **bad-saas-vendor.docx + bad-consulting.docx fixtures (corpus 10 → 12)**: two more synthetic fixtures. `bad-saas-vendor.docx` carries aggressive vendor-side language (99.99% uptime via `best efforts`, IP indemnity, cap with indemnity carve-out) and surfaces FIN-009 + IPDATA-007 + RISK-015 + OBLI-008 + STRUCT-013. The matcher picks `saas-customer` over `saas-vendor` because the playbooks share most features for a generic SaaS doc; sanity guard is playbook-agnostic. `bad-consulting.docx` (matched `consulting-agreement` @ 0.9 confidence) exercises the new PERS-007 rule alongside PERS-005, PERS-006, OBLI-008, STRUCT-013. **Playbook fixture coverage: 8 → 10 of 12 launch playbooks** (mutual-nda, unilateral-nda, employment-at-will-us, independent-contractor, saas-customer, msa-general, lease-commercial-multitenant, lease-residential-us, consulting-agreement — plus implicit coverage of the remaining 2 via shared features).
- **Cross-OS test-matrix workflow (LAUNCH.md row c)**: new `.github/workflows/test-matrix.yml` runs the full lint + typecheck + test suite on `ubuntu-latest` + `macos-latest` + `windows-latest` against Node 20 on every push to main and every PR. Verifies the engine's cross-machine `result_hash` determinism guarantee (spec §17): the determinism-guard + golden-output suites pin the hash; the matrix verifies the same hash across three OSes. Sets `VAULYTICA_SKIP_BUILD_TESTS=1` so the heavy SRI build test runs only in the deploy workflow.
- **Static HTML validation tests (LAUNCH.md rows h + j)**: new `tests/integration/static-html.test.ts` adds 20 assertions across two surfaces. **Row j (OG / Twitter Card meta tags):** every required OG property (`og:title`, `og:description`, `og:image`, `og:url`, `og:type`, `og:site_name`) plus every Twitter Card property (`twitter:card`, `twitter:title`, `twitter:description`, `twitter:image`) is present; `og:url` matches `https://vaulytica.com`; `og:title` ≤ 70 chars; `og:description` ≤ 200 chars; `og:type` is `website`; `twitter:card` is `summary_large_image`; viewport + theme-color metas present. **Row h (static accessibility):** `<html lang>` declared, charset meta present, `<main>` / `<nav>` / `<footer>` landmarks present, `alt` on every `<img>`, `aria-label` + `tabindex="0"` on every non-native `role="button"`, no `<a href="#">` placeholder anchors, multi-nav `aria-label` discipline. Neither replaces the live axe audit / live link-preview test but both catch the static-shape regressions before they ship.
- **schema.org JSON-LD validation tests (LAUNCH.md row k)**: new `tests/integration/schema-org.test.ts` parses every `application/ld+json` block out of `site/index.html` and asserts (1) exactly 4 blocks ship (Organization + SoftwareApplication + TechArticle + FAQPage), (2) every block uses the schema.org @context, (3) each block carries its required Rich Results fields, (4) no terse FAQ answers, (5) no whitespace-padded Question names. **8 assertions; a regression in any block now fails CI before it ships.** **Site fix shipped alongside**: TechArticle was missing `author` and is now properly attributed to the Vaulytica organization — strengthens the Rich Results card on the deployed site.
- **bad-unilateral-nda.docx + bad-residential-lease.docx + bad-msa.docx fixtures (corpus 7 → 10, spec §27 row-(m) target hit)**: three more synthetic fixtures rounding out playbook coverage. `bad-unilateral-nda.docx` (unilateral-nda @ 1.0 confidence) — uncapped damages + survival-silent + placeholder. `bad-residential-lease.docx` (lease-residential-us @ 1.0 confidence) — 7-day non-renewal + 60%/year late fee + asymmetric pre-suit notice + browsewrap modification + tenant non-disparagement + placeholder. `bad-msa.docx` (msa-general @ 1.0 confidence) — MAC clause + undefined `reasonable efforts` + uncapped indemnity + bare insurance + DE-law/TX-venue mismatch + asymmetric termination + placeholder. **Sanity-guard entries added; all 16 newly-required rules fire. Spec §27 row-(m) corpus target reached: 10/10 fixtures.** Direct playbook fixture coverage now stands at 8 of 12 launch playbooks (mutual-nda, unilateral-nda, employment-at-will-us, independent-contractor, saas-customer, msa-general, lease-commercial-multitenant, lease-residential-us). The remaining 4 (saas-vendor, sow, consulting-agreement, generic-fallback) are either children of covered playbooks (sow ⊂ msa) or implicit (generic-fallback).
- **Pipeline body-text fix**: both `src/ui/pipeline.ts` and `tests/integration/_pipeline-helpers.ts` previously walked only `sections[0]` for the body text passed to `matchPlaybook`. This caused unilateral NDAs to match mutual-nda because the unilateral-specific phrasing (`the Disclosing Party`, `the Receiving Party`, `shall not disclose`) lives deeper in the document. Both helpers now recursively walk every section + child paragraph. Verified by `bad-unilateral-nda.docx` now matching `unilateral-nda` at 1.0 confidence instead of mutual-nda at 0.8.
- **FIN-009 regex broadened**: the keyword-to-rate gap can now contain a colon (`Late fee: 5% per month` previously slipped through). The `\s+` between the keyword and the rate was tightened to `[:\s]` so colon-separated formats match. Caught by the `bad-residential-lease.docx` sanity guard.
- **bad-lease.docx + bad-contractor.docx fixtures + sanity guards**: 6th and 7th synthetic fixtures. `bad-lease.docx` exercises the `lease-commercial-multitenant` playbook (matched at 0.7 confidence) with 7 intentional violations covering the unique commercial-real-estate surface (Premises placeholder, 10-day non-renewal window, 36%/year late fee, bare insurance clause, uncapped indemnification, asymmetric pre-suit notice, one-sided jury waiver) — all 7 fire. `bad-contractor.docx` exercises the `independent-contractor` playbook (matched at 0.8 confidence) with a misclassification-dark-pattern setup (fixed hours, company tools, exclusivity, non-compete in California, non-disparagement, asymmetric termination, class-action waiver) — 5 rules fire to surface the pattern. **Pushes the spec §27 row-(m) corpus from 5 → 7 fixtures (target: 10).** The 12 launch playbooks now have direct fixture coverage for 5 of 12: mutual-nda, saas-customer, employment-at-will-us, lease-commercial-multitenant, independent-contractor.
- **bad-employment.docx fixture + sanity guard**: 5th synthetic fixture covering the `employment-at-will-us` playbook (no fixture exercised this surface before). Seven intentional violations target the post-1.0 personnel + dark-pattern rules: California non-compete (PERS-005), non-disparagement without NLRA/SEC carve-outs (PERS-006), asymmetric termination-for-convenience (TERM-009), one-sided jury-trial waiver (CHOICE-010), undefined `best efforts` (OBLI-008), class-action waiver (DARK-005), survival clause silent on confidentiality + IP (TEMP-012). All 7 fire under the matched `employment-at-will-us` playbook. Sanity guard in `fixture-sanity.test.ts` locks them in. Golden generated.
- **Subresource Integrity (SRI) on the main module-script tag (threat-model hardening item):** new `subresourceIntegrity` Vite plugin runs after `deployAssets`'s `closeBundle` and rewrites every same-origin `<script src=…>` and `<link rel="modulepreload|preload|stylesheet" href=…>` in `dist/index.html` to carry an `integrity="sha384-…"` + `crossorigin="anonymous"` pair generated from the on-disk asset bytes. If a CDN cache, misconfigured edge, or supply-chain attacker swaps a JS chunk, the browser refuses to execute it — the page goes blank rather than silently running tampered code. Dynamic-import chunks load *after* the entry's SRI check passes, so this hardens the actual entrypoint. `tests/integration/sri.test.ts` runs `npm run build` and verifies the emitted hash matches `sha384(read on-disk asset)` byte-for-byte. `docs/threat-model.md` updated.
- **🎯 100-rule milestone: OBLI-008 + CHOICE-010 (99th + 100th rules):**
  - **OBLI-008 — Efforts standard undefined (info, obligations)**: surfaces `best efforts` / `commercially reasonable efforts` / `reasonable efforts` / `good faith efforts` / `diligent efforts` when no in-document `"<phrase>" means …` definition exists. Different efforts-standard phrases carry materially different obligation strengths under *Bloor v. Falstaff* (2d Cir. 1979) and its progeny. Silent when the phrase is defined. 5 dedicated tests.
  - **CHOICE-010 — Asymmetric jury-trial waiver (warning, choice-and-venue)**: fires when a jury-trial waiver binds one named party (Customer / Licensee / Recipient / Employee / Tenant / Contractor / Consumer / User / Buyer / Purchaser / Borrower) without imposing a mirror waiver on the drafter. Cites *Leasing Service Corp. v. Crane* (4th Cir. 1986) on the `knowing and voluntary` standard. Silent on bilateral `each party hereby waives` framings. 5 dedicated tests.
- **PERS-006 — Non-disparagement clause present (warning, personnel; 96th rule):** surfaces `non-disparagement`, `shall not disparage`, `will not make disparaging remarks` language for explicit review against NLRB *McLaren Macomb* (Feb 2023) and SEC Rule 21F-17 whistleblower-carve-out requirements. 4 dedicated tests.
- **DARK-007 — Browsewrap / passive-acceptance language (warning, dark-patterns; 97th rule):** detects `by using the Service you agree`, `continued use constitutes acceptance`, `you are deemed to have agreed` and similar passive-acceptance constructs that lack an affirmative consent step. Cites *Specht*, *Nguyen*, *Berkson*. 5 dedicated tests.
- **TEMP-012 — Survival clause silent on sticky obligations (warning, temporal; 98th rule):** when survival language exists AND confidentiality / IP-ownership / indemnification language exists, the rule names every sticky obligation the survival clause failed to enumerate. Silent when survival expressly names every present sticky obligation. 5 dedicated tests.
- **FIN-009 — Late fee above 18%/year (warning, financial; 93rd rule):** parses interest / late-fee / finance-charge rates and normalizes to annual (`2% per month` → 24%, `0.05% per day` → 18.25%). Fires when annualized rate > 18%. Cites N.Y. Gen. Oblig. Law § 5-501. 6 dedicated tests covering month/year/day periods, the 1.5%/month boundary, and the silent-no-rate path.
- **IPDATA-008 — Cross-border data transfer without safeguard (warning, ip-and-data; 94th rule):** fires when the contract authorizes data transfer outside the EU/EEA/UK/US/etc. but no clause references Standard Contractual Clauses, BCRs, an adequacy decision, the Data Privacy Framework, or GDPR Article 46 / Chapter V. 6 dedicated tests across each safeguard form + the no-transfer-language silent path.
- **RISK-016 — Insurance requirement without coverage minimum (warning, risk-allocation; 95th rule):** fires when the contract requires the counterparty to `maintain insurance` / `carry insurance` / `procure coverage` without specifying a per-occurrence or aggregate minimum or a `not less than $X` clause. 6 dedicated tests including `$X per occurrence`, `at least $X`, and `not less than $X` framings.
- **STRUCT-015 — Numbered section gaps (info, structural; 90th rule):** walks the section outline and reports any gap in dotted-decimal numbering (Section 1, 2, 4 → missing 3). Conservative: requires ≥3 numbered siblings before firing so unrelated stragglers don't trigger noise. 5 dedicated tests.
- **PERS-005 — Non-compete clause present (warning, personnel; 91st rule):** surfaces `non-compete`, `covenant not to compete`, `shall not directly or indirectly compete`, and similar phrasings. Cites Cal. Bus. & Prof. Code § 16600 because enforceability splits sharply by jurisdiction (California voids; Washington narrow; Texas requires § 15.50 fit; FTC 2024 nationwide ban vacated). Doesn't fire on bare non-solicitation. 4 dedicated tests.
- **TERM-009 — Asymmetric termination-for-convenience (warning, termination; 92nd rule):** fires when one party (Vendor / Provider / Company / Licensor / Employer / Landlord / Disclosing Party) can terminate at any time / in its sole discretion AND the counterparty (Customer / Licensee / Employee / Tenant / Contractor) is bound by a cure-period or material-breach gate. Skips bilateral `either party may terminate` framings. 4 dedicated tests.
- **OBLI-007 — Material Adverse Change clause present (warning, obligations; 87th rule):** surfaces `material adverse change` / `material adverse effect` / `MAC event` / `MAE clause` language for explicit review. Doesn't fire on bare `material breach`. 5 dedicated tests.
- **IPDATA-007 — Data retention period unspecified (warning, ip-and-data; 88th rule):** fires when the contract handles data (`Customer Data`, `personal data`, `PII`, `DPA`, `data processing`) but no clause specifies retention duration, deletion, return-or-destroy, or purge obligations. Aligns with GDPR Art. 5(1)(e) / CCPA retention-definition expectations. 5 dedicated tests.
- **CHOICE-009 — Governing law differs from venue jurisdiction (info, choice-and-venue; 89th rule):** surfaces contracts where the choice-of-law jurisdiction is different from the venue / forum jurisdiction (e.g., "Delaware law, California venue"). Uses the jurisdictions extractor's normalized `jurisdiction_id` when available, falls back to a text-comparison otherwise. 4 dedicated tests.
- **TEMP-011 — Auto-renewal notice window under 30 days (warning, temporal; 84th rule):** parses the number of days specified in a non-renewal notice clause and fires when it's < 30. Matches `30 days prior written notice`, `thirty (30) days`, `30-day notice`, `at least 30 days prior`. Cites the FTC Negative Option Rule (`stat-16-cfr-425`). The example rule from `docs/adding-a-rule.md` is now a real implementation. 5 dedicated tests.
- **RISK-015 — Indemnification without aggregate cap (warning, risk-allocation; 85th rule):** fires when indemnification language (`shall indemnify`, `hold harmless`, `defend and indemnify`) is present and either (a) no liability cap exists anywhere in the document, or (b) a cap exists but explicitly carves out indemnification (`limited to twelve months… except for indemnification obligations`). 5 dedicated tests covering both fail modes + the silent-on-clean-cap path.
- **DARK-006 — Asymmetric pre-suit notice / cure window (warning, dark-patterns; 86th rule):** detects clauses requiring one party (Customer / Employee / Licensee / Tenant / Contractor / Consumer / User / Buyer) to give pre-suit notice or a cure period before initiating a claim, without imposing the same gate on the drafter. Skips bilateral framings like `each party shall…`. 4 dedicated tests.
- **DARK-005 — Class-action waiver (critical, dark-patterns; 83rd rule):** detects clauses that prohibit class-action participation, force individual arbitration, or waive collective- / representative-action rights. Regex covers `waives [right to] class action`, `gives up the right to [join a] collective action`, `no class action`, `on an individual basis only`. Cites the FTC deception statement; relevant in consumer- and employee-facing contracts since AT&T Mobility v. Concepcion (2011) and Epic Systems v. Lewis (2018). 6 dedicated tests.
- **STRUCT-014 — Inconsistent defined-term casing (info, structural; 82nd rule):** when a multi-word Title-Case term is defined (`"Confidential Information" means …`) but referenced in lowercase elsewhere (`recipient may not share confidential information`), the lowercase form is flagged. Skips single-word defined terms (too noisy) and sentence-start lowercase (often unavoidable). 5 dedicated tests.
- **STRUCT-013 — Unfilled template placeholders (critical, structural; 81st rule):** catches `[insert …]`, `[Title-Case Name]`, `[TBD]` / `[REDACTED]` / `[PLACEHOLDER]` / `[PENDING]`, `{{mustache}}`, `<<angle>>`, `XXX`-runs of 3+ uppercase Xs, and underscore-line placeholders of 10+ chars. Doesn't fire on bracketed footnotes like `[1]` or `[a]`. Runs in every playbook (no override). Combined with the FIN-001 skip-lift below, `bad-nda.docx` now catches **5/5** intentional violations (was 2/5 at v1.0.0).
- **Per-fixture sanity guards (`tests/integration/fixture-sanity.test.ts`):** pin down the rule IDs that **must** fire for each bad-* fixture so a rule regression that silently drops a finding is caught even when the `result_hash` legitimately drifts. Today's lockdown: `bad-nda.docx` → TEMP-001 + STRUCT-007 + STRUCT-013 + FIN-001 + RISK-009 (5/5 intentional violations); `bad-saas.docx` → TEMP-004 + OBLI-002 + RISK-011. Clean fixtures are intentional `it.skip` placeholders.
- **End-to-end report-builder test (`tests/integration/end-to-end-report.test.ts`):** for every committed fixture, runs the live engine, hands the `EngineRun` to `buildDocxReport` + `buildJsonReport`, and asserts the DOCX is a valid OOXML zip + the JSON re-serializes with the same `result_hash`. Catches regressions where the report builder chokes on real engine output (the existing unit tests use mocked runs).
- **Cross-run determinism guard (`tests/integration/determinism-guard.test.ts`):** every fixture runs 5 times in the same process; asserts one unique `result_hash` per fixture. Pins down determinism alongside the existing all-rules + golden-output suites; the cross-machine half lands once the launch CI matrix fans out across ubuntu/macos/windows.

### Fixed

- **RISK-009 ("Uncapped liability") regex broadened** to match the canonical `(liable|responsible) for all damages…without limitation` phrasing alongside the original `unlimited liability` / `no cap on liability` / `without (any) cap/limitation on (its) liability` forms. The bad-nda fixture's intentional violation now fires.
- **Extractor + rule precision (v1.1 backlog from LAUNCH.md):** eight detection gaps closed and the corresponding tests re-enabled (no more `it.skip` + `// TODO(v1.1)` markers): `extractDates` named-anchor detection ("the Effective Date") now case-insensitive with titlecase normalization; `extractDates` ISO branch emits `iso: undefined` for calendar-impossible dates instead of skipping them, so TEMP-001 ("Impossible date") fires; `extractJurisdictions` governing-law regex case-insensitive; `extractObligations` `TRIGGER_RE` accepts word-number durations like `within thirty (30) days`; `extractParties` `PARTY_DECL` regex dropped the `/i` flag that was slurping lowercase connectives (`is`/`made`/`between`/`and`) into the captured name and dropping `jurisdiction_of_formation`; TEMP-004 auto-renewal regex matches `renews automatically` / `auto-renew` / `shall renew automatically`; RISK-007 consequential-damages-waiver regex matches the canonical `Neither party shall be liable for consequential, special, incidental, or punitive damages` phrasing. Golden outputs regenerated.
- Test suite: **453/453 passing + 2 deliberately skipped** (the 2 clean fixtures in `fixture-sanity.test.ts` are intentional placeholders; the previous skip-count of 7 from v1.0.0 was real regressions).

## [1.0.0] — 2026-05-12

Initial public release. Vaulytica is now feature-complete for the seventeen-step build plan in [`spec.md`](docs/spec.md) §26.

### Added

- **Repo scaffolding (Step 0):** TypeScript + Vite + Vitest, ESLint, Prettier, EditorConfig, .nvmrc pinned to Node 20. Directory structure per spec §6.
- **Marketing site (Step 1):** Single-file `site/index.html` — nav, hero, drop zone, "what I check" grid, inline SVG architecture diagram, "what I do not do," "why no AI," "your privacy," 12-card source grid, 10-question FAQ, footer. Four schema.org JSON-LD blocks (Organization, SoftwareApplication, TechArticle, FAQPage). OG + Twitter meta. Theme toggle. FAQ accordions.
- **Ingest layer (Step 2):** `pdfjs-dist`-backed PDF ingest with heading-from-font-size heuristics; `mammoth`-backed DOCX ingest with `parseDocxHtml` exposed for tests; paste ingest with ATX + Setext heading detection; `normalize.ts` for stable IDs + contiguous offsets; SHA-256 hashing.
- **OCR fallback (Step 3):** `tesseract.js`-backed OCR triggered only when the PDF text layer is empty and the caller opts in. OffscreenCanvas + per-call worker lifecycle.
- **Extractors (Step 4):** Nine pure extractors — `parties`, `dates`, `amounts` (decimal.js-backed normalizer), `definitions`, `sections`, `crossrefs`, `obligations` (LEXDEMOD-style), `jurisdictions`, `classifier`. `extractAll` composes them in dependency order.
- **DKB scaffolding (Step 5):** Typed shapes + Zod schemas + version helpers + `loadDkb` with IndexedDB cache and offline fallback. Hand-authored starter DKB at `dkb/dist/v0.0.1-starter/` (30 clauses, 12 jurisdictions, 10 definition templates, 8 dark patterns, 30 statutory citations, 14 classifier patterns).
- **Rule engine + 12 launch rules (Step 6):** Engine core (`finding.ts`, `ordering.ts`, `runner.ts`) with SHA-256 `result_hash` over canonicalized run. STRUCT-001..008, FIN-001, FIN-002, TEMP-001, RISK-009.
- **Remaining 68 rules (Step 7):** Full 80-rule catalog per spec §18 across structural / financial / temporal / obligations / risk-allocation / choice-and-venue / termination / IP-and-data / personnel / dark-patterns categories. Shared `rules/_helpers.ts`.
- **Playbook system + 12 playbooks (Step 8):** Zod-validated `Playbook` type, deterministic `matchPlaybook` (additive per-match scoring: +0.3 title / +0.4 required-clause / +0.2 distinguishing / −0.1 negative; threshold 0.5; lexicographic tiebreak), `parsePlaybook` + `fetchPlaybooks` loaders, 12 JSON playbooks under `playbooks/` (mutual-nda, unilateral-nda, employment-at-will-us, independent-contractor, saas-customer, saas-vendor, msa-general, sow, lease-commercial-multitenant, lease-residential-us, consulting-agreement, generic-fallback).
- **DOCX + JSON report builder (Step 9):** `docx@^9.6`-backed `buildDocxReport(run, ingest, dkb, playbook)` producing the cover / executive summary / findings / obligations / extracted appendix / audit trail / verbatim disclaimer per spec §22; US Letter, Arial 11pt, mint accent. `buildJsonReport`, `formatCitation` (Bluebook flavor for U.S.C. / C.F.R. / public-law / state-code citations), `buildBibliography` with document-order numbering.
- **DKB build pipeline part 1 (Step 10):** `dkb/build/sources.yaml` with all 8 sources from §12, `RateLimitedHttp` client with per-source RPS + UA + retry, `FilesystemCache` + `MemoryCache`, 8 fetchers (edgar, uscode, ecfr, govinfo, commonpaper, cuad, ledgar, ulc) each splitting a pure `parse*` function from the network orchestrator. CLI: `npm run dkb:fetch -- <id>`.
- **DKB build pipeline part 2 (Step 11):** `stopwords.txt`, `classifier_taxonomy.json` (55+ canonical clauses reconciling CUAD + LEDGAR), deterministic TF-IDF trainer with byte-stable JSON output, 27 hand-authored regex pattern overlays, `build.ts` orchestrator, `regression.ts` golden-output harness, `.github/workflows/dkb-rebuild.yml` weekly cron with PR-on-diff.
- **UI hookup (Step 12):** `src/ui/` modules (`theme.ts`, `dropzone.ts`, `progress.ts`, `ticker.ts`, `states.ts`, `main.ts`). Drop zone transforms in place through empty → analyzing → complete states. Full pipeline: file → ingest → extract → loadDkb (cached) → matchPlaybook → runEngine with live `onRule` progress → buildDocxReport → Blob URL download.
- **PWA + offline (Step 13):** Service worker with per-concern caches (`-html`, `-assets`, `-dkb`, `-playbooks`), network-first / cache-first-revalidate / stale-while-revalidate strategies. Manifest with full icon set (PNG 192/512 + maskable-512 generated from `favicon.svg` via `sharp`). `npm run icons` regenerates. "Works offline" footer badge once the SW is in control.
- **Cloudflare Pages deployment (Step 14):** Vite plugin emits `dist/_headers` (strict CSP with `connect-src 'self'`, Permissions-Policy denying hardware APIs, HSTS, COOP/CORP, per-route cache rules) + `dist/_redirects`. Build hook copies `playbooks/`, latest `dkb/dist/<v>/`, icons, manifest, and `sw.js` into `dist/`. Playwright smoke test asserts ZIP magic bytes + zero cross-origin requests during analysis. Deploy workflow at `.github/workflows/deploy.yml`.
- **Documentation (Step 15):** `docs/architecture.md`, `docs/adding-a-rule.md`, `docs/adding-a-playbook.md`, `docs/data-sources.md`, `docs/threat-model.md`, `docs/determinism.md`. CONTRIBUTING rewritten with full PR flow, accept/reject rules, and verification gate. README docs section.
- **Test corpus + golden outputs (Step 16):** `tests/fixtures/build-fixtures.ts` deterministically generates `mutual-nda.docx` (clean baseline), `bad-nda.docx` (5 intentional violations), `bad-saas.docx` (auto-renewal-buried + unilateral mod right + asymmetric indemnity), `pasted-mutual-nda.txt`. `tests/integration/golden-output.test.ts` asserts `result_hash` + canonical-JSON equality against committed goldens; `npm run fixtures:regen-golden` updates the baseline on deliberate rule changes.
- **Launch checklist (Step 17):** [`LAUNCH.md`](LAUNCH.md) tracks every spec §27 item with status / date / verifier. Cross-machine determinism row is the load-bearing claim; mechanical items pass, deployment-bound items remain ⏳ pending until the v1.0.0 deploy.

### Changed

- **Engine runner determinism fix:** `computeResultHash` now blanks `execution_log[*].elapsed_ms` along with `result_hash` and `executed_at`. Pre-existing bug where repeated runs produced different hashes is fixed. The determinism contract (spec §17) is now genuinely cross-machine, not just same-machine-fast-enough.
- **Runner API:** Optional `onRule({ rule, index, total, fired })` progress callback on `runEngine` — used by the UI ticker, optional for tests, deterministic-safe.

### Production dependencies

`decimal.js`, `docx`, `mammoth`, `pdfjs-dist`, `tesseract.js`, `zod`.

### Dev dependencies

`@playwright/test`, `@types/js-yaml`, `@types/node`, `@typescript-eslint/eslint-plugin`, `@typescript-eslint/parser`, `@xmldom/xmldom`, `eslint`, `eslint-config-prettier`, `happy-dom`, `js-yaml`, `prettier`, `sharp`, `tsx`, `typescript`, `vite`, `vitest`.

[1.0.0]: https://github.com/clay-good/vaulytica/releases/tag/v1.0.0
