/**
 * v5 sub-domain A″ — US digital and consumer commercial families
 * (spec-v45.md §6.A2).
 *
 * Eight families whose governing text is consumer-protection law rather
 * than the UCC: ROSCA and the state automatic-renewal statutes, the FTC
 * Act § 5 assent and disclosure line, state lottery statutes, and the
 * contract-formation cases that decide whether a browsewrap binds anyone
 * at all. Rule ids continue the COMM namespace at 201.
 */

import type { Rule } from "../../finding.js";
import { pack } from "./_pack.js";
import { agency, expressDenial, practice, stateLaw, ucc, usc } from "./_helpers.js";

const C = "commercial";

// ── Website terms of use ────────────────────────────────────────────
const WEBSITE_TOU = pack("website-terms-of-use", C, [
  {
    id: "COMM-201",
    name: "Assent mechanism identified",
    cite: practice(
      "online-assent",
      "clickwrap versus browsewrap assent in US contract-formation cases",
    ),
    pat: [
      /(by\s+(clicking|checking|creating\s+an\s+account|registering)|you\s+agree\s+to\s+these\s+terms)/i,
      /(by\s+(using|accessing|continuing\s+to\s+use)\s+(this\s+)?(site|service)|constitutes?\s+(your\s+)?acceptance)/i,
    ],
    why: "US courts enforce clickwrap almost uniformly and browsewrap almost never. Terms that state no assent mechanism at all are the weakest position of the three: there is no record that any user ever agreed.",
    fix: "State the assent mechanism, and back it with an interface that requires an affirmative act (checkbox or button) adjacent to a conspicuous link to these terms.",
    sev: "critical",
  },
  {
    id: "COMM-202",
    name: "Unilateral modification and notice to users",
    cite: practice(
      "unilateral-modification",
      "illusory-promise problem in unilateral online modification clauses",
    ),
    pat: [
      /(we\s+may\s+(modify|change|update)\s+these\s+terms|reserve\s+the\s+right\s+to\s+(modify|change))/i,
      /(notice|notify|posting\s+the\s+(revised|updated)|effective\s+date)/i,
    ],
    why: "A right to change terms at any time without notice has been held illusory, taking the arbitration clause down with it in several circuits. Notice plus a prospective effective date is what saves the clause.",
    fix: "State that changes take effect only prospectively after notice, describe the notice method, and state that continued use after the effective date is acceptance.",
  },
  {
    id: "COMM-203",
    name: "DMCA agent designation and takedown procedure",
    cite: usc("17", "512", "DMCA — limitations on liability relating to material online"),
    pat: [
      /(digital\s+millennium|dmca|17\s+u\.?s\.?c\.?\s*§?\s*512)/i,
      /(designated\s+agent|copyright\s+agent|notice\s+of\s+(claimed\s+)?infringement|counter-?notice)/i,
    ],
    why: "§ 512(c) safe harbor is available only to a service provider that has designated an agent with the Copyright Office and published the contact information. Sites hosting user content without it have no safe harbor.",
    fix: "Publish the designated agent's name and contact details, describe the § 512(c)(3) notice elements and the counter-notice procedure, and state the repeat-infringer policy.",
    when: [/(user[- ](generated|submitted)\s+content|upload|post\s+content|submissions)/i],
    sev: "critical",
  },
  {
    id: "COMM-204",
    name: "User-content license scope",
    cite: practice("ugc-license", "user-generated content licenses in online terms"),
    pat: [
      /(you\s+grant\s+(us|the\s+company)|license\s+to\s+(use|reproduce|display))/i,
      /(user\s+content|your\s+content|submissions)/i,
    ],
    why: "Without a license, a platform has no right to display, cache, or transcode what users post. Overbroad grants — perpetual, sublicensable, for any purpose — are the recurring source of user backlash and state AG attention.",
    fix: "Grant the narrowest license the service needs (host, display, reformat, and promote), state that the user retains ownership, and say what happens to the license on deletion.",
    when: [/(user[- ](generated|submitted)\s+content|upload|post\s+content|submissions)/i],
  },
  {
    id: "COMM-205",
    name: "Arbitration clause and class waiver conspicuousness",
    cite: usc("9", "2", "Federal Arbitration Act — validity of arbitration agreements"),
    pat: [/arbitrat/i, /(class\s+action\s+waiver|on\s+an\s+individual\s+basis|no\s+class)/i],
    why: "Consumer arbitration clauses survive under the FAA, but only where the term was conspicuous and assented to. Burying it in an unlinked footer is the fact pattern courts use to refuse enforcement.",
    fix: "Set the arbitration and class-waiver clause in a conspicuous, separately-headed section, in bold or capitals, and add an opt-out window with a stated method.",
    when: [/arbitrat/i],
  },
  {
    id: "COMM-206",
    name: "Disclaimer and liability cap conspicuousness",
    cite: ucc("2-316", "Exclusion or modification of warranties"),
    pat: [
      /(as\s+is|disclaim(s|er)?\s+(all|any)\s+warrant|without\s+warrant(y|ies)\s+of\s+any\s+kind)/i,
      /(limitation\s+of\s+liability|shall\s+not\s+be\s+liable|aggregate\s+liability)/i,
    ],
    why: "A warranty disclaimer must be conspicuous to be effective, and consequential-damage exclusions are unenforceable where unconscionable. Both usually appear on a consumer page in the same undifferentiated block of body text.",
    fix: "Set the disclaimer and liability limit in conspicuous type in their own headed sections, and carve out the liabilities that cannot be limited under applicable law.",
  },
]);

// ── API terms ───────────────────────────────────────────────────────
const API_TERMS = pack("api-terms", C, [
  {
    id: "COMM-207",
    name: "License scope and permitted use",
    cite: practice("api-license", "license scoping in developer API terms"),
    pat: [
      /(grants?\s+(you|developer)\s+a\s+.{0,60}license|license\s+to\s+(access|use)\s+the\s+api)/i,
      /(permitted\s+use|solely\s+(to|for)|scope\s+of\s+(the\s+)?license)/i,
    ],
    why: "An API's terms are its only enforcement mechanism; the technical interface is not a contract. Without a defined license scope, a developer's competing use is a factual argument, not a breach.",
    fix: "Grant a limited, revocable, non-exclusive, non-transferable license, name the permitted uses, and prohibit reverse engineering, scraping, and building a competing service.",
    sev: "critical",
  },
  {
    id: "COMM-208",
    name: "Rate limits, quotas, and suspension",
    cite: practice("api-limits", "rate limiting and suspension in API terms"),
    pat: [
      /(rate\s+limit|quota|throttl|calls?\s+per\s+(second|minute|day))/i,
      /(suspend|revoke\s+(your\s+)?api\s+key|disable\s+access)/i,
    ],
    why: "Rate limits published only in documentation are not contract terms. When a suspension takes an integration offline, whether the provider had the right turns on what the agreement said.",
    fix: "State that limits are set in the documentation and may change with notice, and describe the grounds, notice, and reinstatement path for suspension.",
  },
  {
    id: "COMM-209",
    name: "Deprecation and breaking-change notice period",
    cite: practice("api-deprecation", "deprecation policies in API terms"),
    pat: [
      /(deprecat|sunset|end\s+of\s+life)/i,
      /(\d+\s+(days|months)'?\s+notice|advance\s+notice|notice\s+period)/i,
    ],
    why: "A developer's whole product can rest on an endpoint. Without a committed deprecation window, the provider can break every integration overnight and be within its rights.",
    fix: "Commit to a stated notice period before breaking changes or endpoint removal, define what counts as a breaking change, and describe the migration support offered.",
  },
  {
    id: "COMM-210",
    name: "End-user data handling and privacy flow-down",
    cite: practice("api-data", "end-user data obligations in API terms"),
    pat: [
      /(end\s+user\s+data|user\s+data\s+(you|developer)\s+(receive|obtain))/i,
      /(privacy\s+policy|consent|delete\s+(the\s+)?data|retention)/i,
    ],
    why: "The provider remains accountable to its own users for what a developer does with data pulled through the API. That accountability is only manageable if the developer's duties are contractual.",
    fix: "Require the developer to publish a privacy policy, obtain the consents its use requires, honor deletion requests, limit retention, and prohibit selling or combining the data.",
  },
  {
    id: "COMM-211",
    name: "Branding and attribution requirements",
    cite: practice("api-branding", "attribution and brand-guideline requirements in API terms"),
    pat: [
      /(brand\s+(guidelines|assets)|attribution|logo)/i,
      /(powered\s+by|display\s+the\s+following|may\s+not\s+(use|imply))/i,
    ],
    why: "Attribution requirements are how a provider preserves trademark control across thousands of integrations, and how it avoids implied endorsement of a developer's product.",
    fix: "State the required attribution, incorporate brand guidelines by link, and prohibit any use implying endorsement, partnership, or affiliation.",
  },
  {
    id: "COMM-212",
    name: "Termination and wind-down of live integrations",
    cite: practice("api-termination", "wind-down obligations on API termination"),
    pat: [
      /(terminat|expire)/i,
      /(cease\s+(all\s+)?use|delete\s+(all\s+)?data|wind-?down|transition\s+period)/i,
    ],
    why: "Termination of API terms strands live end users of the developer's product. A wind-down period and a data-deletion duty are what convert an abrupt cutoff into a managed transition.",
    fix: "State the termination grounds and notice, provide a wind-down period for live integrations, and require deletion or return of provider data on termination.",
  },
]);

// ── Data license ────────────────────────────────────────────────────
const DATA_LICENSE = pack("data-license-agreement", C, [
  {
    id: "COMM-213",
    name: "Scope of permitted use and field of use",
    cite: practice("data-license-scope", "field-of-use scoping in data licenses"),
    pat: [
      /(licensed\s+data|the\s+data\s+(may|shall)\s+be\s+used)/i,
      /(permitted\s+(use|purpose)|field\s+of\s+use|internal\s+business\s+purposes)/i,
    ],
    why: "Data licenses are priced by use, so the boundary between internal analytics, customer-facing product, and resale is the whole commercial bargain.",
    fix: "Define the permitted use precisely — internal analysis, embedding in a product, or redistribution — and state which uses require a separate license.",
    sev: "critical",
  },
  {
    id: "COMM-214",
    name: "Derived data and model-training rights",
    cite: practice("derived-data", "derived data and AI training rights in data licenses"),
    pat: [
      /(derived\s+data|derivative\s+works?\s+of\s+the\s+data|insights\s+derived)/i,
      /(train(ing)?\s+(any\s+)?(machine\s+learning|model|artificial\s+intelligence)|model\s+training)/i,
    ],
    why: "Whether a licensee may train a model on licensed data, and who owns the model and its outputs, is now the most contested term in data licensing. Silence guarantees a dispute.",
    fix: "Define derived data, state whether training AI or ML models is permitted, and allocate ownership of the trained model, its weights, and its outputs.",
    sev: "critical",
  },
  {
    id: "COMM-215",
    name: "Redistribution and sublicensing",
    cite: practice("data-redistribution", "redistribution controls in data licenses"),
    pat: [
      /(redistribut|resell|sublicense)/i,
      /(may\s+not|shall\s+not|prohibited|only\s+with\s+(the\s+)?prior\s+written)/i,
    ],
    why: "A dataset's value collapses if a licensee can pass it on. Redistribution controls also carry the licensor's own upstream obligations to its sources.",
    fix: "Prohibit redistribution and sublicensing except as expressly permitted, and state the form in which any permitted downstream delivery may occur (aggregated, de-identified, or capped).",
  },
  {
    id: "COMM-216",
    name: "Source warranties and right to license",
    cite: practice("data-provenance", "provenance warranties in data licenses"),
    pat: [
      /(right(s)?\s+to\s+(grant|license)|owns\s+or\s+has\s+the\s+right)/i,
      /(lawfully\s+(collected|obtained)|consent|provenance|source\s+of\s+the\s+data)/i,
    ],
    why: "A licensee inherits the licensor's collection defects — scraped content, unconsented personal data, third-party terms breached upstream. The rights warranty is the only backstop.",
    fix: "Warrant that the licensor owns or has the right to license the data and collected it lawfully, and back it with an IP and privacy indemnity.",
  },
  {
    id: "COMM-217",
    name: "Attribution and audit obligations",
    cite: practice("data-audit", "attribution and audit rights in data licenses"),
    pat: [
      /(attribut|credit\s+the\s+source|cite\s+the\s+data)/i,
      /(audit|usage\s+report|records\s+of\s+use|inspect)/i,
    ],
    why: "Usage-based data licenses are unenforceable in practice without records and an audit right; attribution is often required by the licensor's own upstream sources.",
    fix: "State the required attribution and the licensee's obligation to keep usage records, with an audit right, notice period, and cost-shifting for material under-reporting.",
  },
  {
    id: "COMM-218",
    name: "Post-termination deletion versus perpetual rights",
    cite: practice("data-termination", "post-termination data rights"),
    pat: [
      /(upon\s+(termination|expiration)|after\s+termination)/i,
      /(delete|destroy|return\s+the\s+data|perpetual\s+(license|right)|retain)/i,
    ],
    why: "Data cannot be un-learned. Whether a licensee must delete, may keep derived outputs, or holds a perpetual right in what it already built has to be resolved before termination, not after.",
    fix: "State what must be deleted, what may be retained (backups, aggregated outputs, trained models), and certify deletion within a stated period.",
  },
]);

// ── Loyalty program ─────────────────────────────────────────────────
const LOYALTY = pack("loyalty-program-terms", C, [
  {
    id: "COMM-219",
    name: "Points expiration and forfeiture",
    cite: stateLaw(
      "loyalty-points",
      "expiration and forfeiture limits applied to loyalty points and stored value",
      "https://www.law.cornell.edu/wex/gift_card",
    ),
    pat: [/(expir|forfeit)/i, /(points|rewards|miles|program\s+currency)/i],
    all: true,
    why: "Several state gift-card and unclaimed-property statutes reach loyalty currency where it was purchased rather than earned. Undisclosed expiration is also the classic UDAP theory.",
    fix: "Disclose the expiration rule and the inactivity period that triggers it, state whether purchased points expire, and describe the notice given before forfeiture.",
  },
  {
    id: "COMM-220",
    name: "Unilateral devaluation and program termination",
    cite: practice("loyalty-devaluation", "unilateral modification of loyalty program value"),
    pat: [
      /(modify|change|discontinue|terminate)\s+(the\s+)?program/i,
      /(at\s+any\s+time|without\s+notice|in\s+our\s+(sole\s+)?discretion|with\s+notice)/i,
    ],
    why: "Devaluation is the most common consumer complaint in loyalty programs, and litigation turns on whether the terms reserved the right and gave notice. An unreserved devaluation is a breach.",
    fix: "Reserve the right to modify earning and redemption rates prospectively, commit to advance notice, and state what happens to accrued points on program termination.",
  },
  {
    id: "COMM-221",
    name: "Redemption mechanics and blackout limits",
    cite: practice("loyalty-redemption", "redemption terms in loyalty programs"),
    pat: [/redeem|redemption/i, /(blackout|availability|restrictions|capacity\s+controlled)/i],
    why: "A points balance is worthless if redemption is discretionary. The disclosed mechanics are what makes the program currency a benefit rather than a marketing statement.",
    fix: "Describe the redemption process, the value or award chart, and any blackout dates, capacity controls, or minimum balances.",
  },
  {
    id: "COMM-222",
    name: "Gift-card and stored-value law interaction",
    cite: usc(
      "15",
      "1693l-1",
      "Electronic Fund Transfer Act — general-use prepaid cards, gift certificates and store gift cards",
    ),
    pat: [
      /(no\s+cash\s+value|not\s+redeemable\s+for\s+cash|have\s+no\s+monetary\s+value)/i,
      /(gift\s+card|stored\s+value|prepaid)/i,
    ],
    why: "Points earned through purchase can be treated as stored value in some states, pulling in expiration limits and escheat duties. The 'no cash value' recital is the standard defense against that characterization.",
    fix: "State that points have no cash value, are not property, and are not transferable, and confirm the treatment of any points purchased for money.",
  },
  {
    id: "COMM-223",
    name: "Account closure and transfer on death",
    cite: practice("loyalty-account", "account closure and inheritance of loyalty balances"),
    pat: [
      /(close\s+(your\s+)?account|account\s+(closure|termination)|inactive\s+account)/i,
      /(death|estate|transfer\s+(of\s+)?points|non-?transferable)/i,
    ],
    why: "Whether a balance survives account closure or the member's death is a routine consumer question that most programs answer nowhere, and a growing subject of state legislation.",
    fix: "State the grounds for account closure, whether points survive it, and the program's position on transfer to an estate.",
  },
]);

// ── Sweepstakes ─────────────────────────────────────────────────────
const SWEEPSTAKES = pack("sweepstakes-official-rules", C, [
  {
    id: "COMM-224",
    name: "No-purchase-necessary statement and alternate method of entry",
    cite: stateLaw(
      "lottery",
      "the three-element lottery prohibition (prize, chance, consideration) every state enacts",
      "https://www.law.cornell.edu/wex/lottery",
    ),
    pat: [
      /no\s+purchase\s+necessary/i,
      /(alternate\s+method\s+of\s+entry|amoe|mail-?in\s+entry|free\s+method\s+of\s+entry)/i,
    ],
    why: "A promotion with prize, chance, and consideration is an illegal lottery in every state. Removing consideration through a genuine free alternate method of entry is what makes a sweepstakes lawful.",
    fix: 'Include "NO PURCHASE NECESSARY TO ENTER OR WIN. A PURCHASE WILL NOT INCREASE YOUR CHANCES OF WINNING." and describe a free alternate method of entry with equal dignity.',
    sev: "critical",
  },
  {
    id: "COMM-225",
    name: "Odds of winning disclosure",
    cite: usc(
      "39",
      "3001",
      "Nonmailable matter — sweepstakes and skill contests (Deceptive Mail Prevention and Enforcement Act)",
    ),
    pat: [
      /odds\s+of\s+winning/i,
      /(depend\s+on\s+the\s+number\s+of\s+(eligible\s+)?entries|1\s+in\s+|approximately)/i,
    ],
    why: "Odds disclosure is required by the DMPEA for mailed promotions and by New York and Florida registration rules, and its absence is a standard UDAP theory everywhere else.",
    fix: 'State the odds — typically "Odds of winning depend on the number of eligible entries received" — or the numeric odds for an instant-win game.',
  },
  {
    id: "COMM-226",
    name: "Eligibility, age, and geographic limits",
    cite: practice("sweeps-eligibility", "eligibility and geographic limits in US promotions"),
    pat: [
      /(eligib|open\s+(only\s+)?to|must\s+be\s+at\s+least)/i,
      /(legal\s+residents?|18\s+years|void\s+where\s+prohibited|excluding)/i,
    ],
    why: "Eligibility limits are how a sponsor stays out of registration and bonding states, out of jurisdictions that ban the promotion type, and out of COPPA territory.",
    fix: "State the eligible jurisdictions and minimum age, exclude employees and immediate family, and add the void-where-prohibited limitation.",
  },
  {
    id: "COMM-227",
    name: "Start and end dates and entry period",
    cite: practice("sweeps-period", "promotion period disclosure"),
    pat: [
      /(begins?\s+(on|at)|start\s+date|promotion\s+period|entry\s+period)/i,
      /(ends?\s+(on|at)|11:59|deadline)/i,
    ],
    why: "The promotion period fixes when entries are valid and when the sponsor's obligations end. Ambiguous timing — no time zone, no end time — is the most common drafting failure in official rules.",
    fix: "State the start and end date and time with the controlling time zone, and identify the official clock for entry receipt.",
  },
  {
    id: "COMM-228",
    name: "Prize description, ARV, and winner tax responsibility",
    cite: agency(
      "IRS",
      "Form 1099-MISC reporting of prizes and awards of $600 or more",
      "https://www.irs.gov/forms-pubs/about-form-1099-misc",
    ),
    pat: [
      /(approximate\s+retail\s+value|arv|prize\s+value)/i,
      /(tax(es)?\s+(are|is)\s+the\s+(sole\s+)?responsibility|1099|w-?9)/i,
    ],
    why: "Prizes of $600 or more are reportable on Form 1099-MISC, and the winner owes the tax. Rules that do not disclose ARV and tax responsibility routinely produce refusals at affidavit stage.",
    fix: "Describe each prize, state its approximate retail value, state that all taxes are the winner's responsibility, and require a W-9 before award where reporting applies.",
  },
  {
    id: "COMM-229",
    name: "Sponsor identity and availability of the rules",
    cite: practice("sweeps-sponsor", "sponsor identification in official rules"),
    pat: [
      /sponsor(ed)?\s+(is|by)/i,
      /(official\s+rules\s+(are\s+)?available|for\s+a\s+copy\s+of\s+(the\s+)?(official\s+)?rules)/i,
    ],
    why: "Registration states require the sponsor's legal name and address, and entrants need a way to obtain the rules after the promotion page comes down.",
    fix: "Name the sponsor and any administrator with full legal name and address, and state where the rules and winners list remain available.",
  },
  {
    id: "COMM-230",
    name: "Winner list and publicity release",
    cite: stateLaw(
      "publicity-release",
      "limits on conditioning a prize on a publicity release (New York and Florida)",
      "https://www.law.cornell.edu/wex/publicity",
    ),
    pat: [
      /(winners?\s+list|list\s+of\s+winners)/i,
      /(publicity|name,?\s+(likeness|image)|except\s+where\s+prohibited)/i,
    ],
    why: "New York prohibits conditioning a prize on a publicity release, so the standard clause must carve those states out. A winners-list offer is separately required in several states.",
    fix: 'Add a publicity release with an "except where prohibited by law" carve-out, and state how to request a winners list and for how long.',
  },
]);

// ── Auto-renewal ────────────────────────────────────────────────────
const AUTO_RENEWAL = pack("auto-renewal-terms", C, [
  {
    id: "COMM-231",
    name: "Clear and conspicuous automatic-renewal disclosure",
    cite: usc("15", "8403", "Restore Online Shoppers' Confidence Act — negative option marketing"),
    pat: [
      /(automatic(ally)?\s+renew|auto-?renew)/i,
      /(clear(ly)?\s+and\s+conspicuous|before\s+(obtaining|charging)|prior\s+to\s+(the\s+)?(charge|purchase))/i,
    ],
    all: true,
    why: "ROSCA § 8403 makes it unlawful to charge on a negative-option basis online without clearly and conspicuously disclosing all material terms before obtaining billing information. This is the FTC's most-used consumer enforcement authority.",
    fix: "Disclose the renewal term, the renewal price, the billing frequency, and the cancellation deadline in a conspicuous block adjacent to the enrollment control, before billing information is taken.",
    sev: "critical",
  },
  {
    id: "COMM-232",
    name: "Affirmative consent to the recurring charge",
    cite: usc("15", "8403", "ROSCA — informed consent requirement"),
    pat: [
      /(you\s+(authorize|consent|agree)\s+to\s+(the\s+)?(recurring|automatic)\s+charg|by\s+(checking|clicking))/i,
      /(express(ly)?\s+(consent|authorize|agree)|affirmative\s+consent)/i,
    ],
    why: "ROSCA requires the consumer's express informed consent to the negative option feature specifically — not general assent to a terms page containing it.",
    fix: "Capture a separate affirmative act consenting to the recurring charge, and retain the record of that consent.",
    sev: "critical",
  },
  {
    id: "COMM-233",
    // 1.1.0 — an express disclaimer of this column is now reported as a
    // disclaimer rather than read as compliance (`v5/_pack.ts`, `denied`).
    ver: "1.1.0",
    name: "Simple cancellation mechanism",
    cite: usc("15", "8403", "ROSCA — simple mechanisms for stopping recurring charges"),
    pat: [
      /cancel/i,
      /(online|same\s+(way|manner|medium)|one\s+click|simple\s+mechanism|self-?service)/i,
    ],
    why: "ROSCA requires a simple mechanism to stop recurring charges, and California and several other states require cancellation in the same medium as enrollment. Phone-only cancellation of an online signup is the paradigm violation.",
    fix: "Provide online, self-service cancellation available in the same medium as enrollment, and describe it in the terms with the exact steps.",
    denied: expressDenial(String.raw`(?:online\s+)?cancellation\s+(?:mechanism|method|option)?`),
    sev: "critical",
  },
  {
    id: "COMM-234",
    name: "Advance renewal and price-increase notice",
    cite: stateLaw(
      "automatic-renewal",
      "advance renewal-reminder and price-change notice requirements in state automatic renewal laws",
      "https://www.law.cornell.edu/wex/consumer_protection",
    ),
    pat: [
      /(reminder|notice\s+(before|prior\s+to)\s+(the\s+)?renewal|renewal\s+notice)/i,
      /(price\s+(increase|change)|amount\s+of\s+the\s+charge|\d+\s+days\s+before)/i,
    ],
    why: "California, New York, and others require a renewal reminder for longer terms and advance notice of any material price change. The notice windows differ by state and by term length.",
    fix: "Commit to a renewal reminder within the statutory window for terms that require it, and to advance notice of any price increase before it takes effect.",
  },
  {
    id: "COMM-235",
    name: "Post-cancellation confirmation",
    cite: stateLaw(
      "automatic-renewal-confirmation",
      "acknowledgment and confirmation requirements in state automatic renewal laws",
      "https://www.law.cornell.edu/wex/consumer_protection",
    ),
    pat: [
      /(confirmation|acknowledg)/i,
      /(after\s+(you\s+)?cancel|cancellation\s+(confirmation|email)|retainable\s+form)/i,
    ],
    why: "State ARLs require an acknowledgment of the auto-renewal terms in a retainable form after enrollment, and many require confirmation of cancellation. The confirmation is also the merchant's evidence in a chargeback.",
    fix: "Send a retainable post-enrollment acknowledgment of the renewal terms and cancellation method, and a confirmation when cancellation takes effect.",
  },
  {
    id: "COMM-236",
    name: "State automatic-renewal-law overlays",
    cite: stateLaw(
      "state-arl",
      "state automatic renewal statutes (California, New York, Oregon, Colorado, and others)",
      "https://www.law.cornell.edu/wex/consumer_protection",
    ),
    pat: [
      /(california|new\s+york|state\s+(law|residents))/i,
      /(automatic\s+renewal\s+law|additional\s+(rights|disclosures)|if\s+you\s+(are\s+a\s+)?reside)/i,
    ],
    why: "State ARLs impose different windows, notice contents, and remedies than ROSCA, and several make an unauthorized renewal an unconditional gift to the consumer.",
    fix: "Add a state-specific supplement for the ARL states where the service is sold, or apply the strictest standard nationwide.",
  },
]);

// ── OEM / white-label ───────────────────────────────────────────────
const OEM = pack("oem-agreement", C, [
  {
    id: "COMM-237",
    name: "Embedded license scope and branding rights",
    cite: practice("oem-license", "embedded license scoping in OEM agreements"),
    pat: [
      /(embed|incorporate\s+(the\s+)?(licensed\s+)?(technology|software)\s+(in|into))/i,
      /(rebrand|under\s+the\s+oem'?s?\s+(brand|name)|remove\s+(the\s+)?(supplier'?s?\s+)?marks)/i,
    ],
    all: true,
    why: "An OEM license is a license to make the supplier's product disappear into someone else's. Whether the OEM may remove marks, and whether the supplier may be identified at all, is the core of the deal.",
    fix: "Define the licensed technology, the permitted embedding, whether the OEM may rebrand, and what supplier attribution (if any) must remain.",
    sev: "critical",
  },
  {
    id: "COMM-238",
    name: "End-user license pass-through",
    cite: practice("oem-eula", "end-user license flow-down in OEM agreements"),
    pat: [
      /(end\s+user\s+license|eula|end\s+users?\s+(shall|must)\s+(be\s+)?(bound|agree))/i,
      /(flow[- ]down|pass[- ]through|no\s+less\s+protective)/i,
    ],
    why: "The supplier has no contract with the OEM's customers. Its protections — use restrictions, disclaimers, export terms — reach them only if the OEM's EULA carries them.",
    fix: "Require the OEM's end-user terms to include stated minimum protections for the supplier, and make the OEM responsible for their enforcement.",
  },
  {
    id: "COMM-239",
    name: "Support tiering",
    cite: practice("oem-support", "level 1/2/3 support allocation in OEM agreements"),
    pat: [/(level\s+[123]|l[123]\s+support|tier\s+[123])/i, /(first-?line|second-?line|escalat)/i],
    why: "The OEM owns the customer relationship and takes first-line support; the supplier takes escalations. Without a defined split and response targets, every incident starts with a jurisdictional argument.",
    fix: "Define the L1/L2/L3 split, response and resolution targets for escalated issues, and the escalation contacts and hours.",
  },
  {
    id: "COMM-240",
    name: "IP indemnity and defense control",
    cite: practice("oem-indemnity", "IP indemnity in embedded-technology agreements"),
    pat: [/indemnif/i, /(infring|intellectual\s+property\s+claim)/i],
    why: "An infringement claim lands on the OEM's customer, not the supplier. The OEM needs an indemnity that reaches downstream and a defense-control allocation that does not leave it unable to settle.",
    fix: "Provide an IP indemnity covering the OEM and its end users, with defense control, a duty to procure rights or replace, and a stated cap treatment.",
  },
  {
    id: "COMM-241",
    name: "Minimum commitments and pricing",
    cite: practice("oem-pricing", "minimum commitments in OEM agreements"),
    pat: [
      /(minimum\s+(purchase|commitment|volume)|committed\s+(volume|revenue))/i,
      /(price|royalty|per\s+(unit|seat|copy))/i,
    ],
    why: "OEM pricing is volume-tiered and the tiers only work if the commitment is real. A commitment with no shortfall consequence is a forecast.",
    fix: "State the minimum commitment by period, the pricing tiers, and the consequence of a shortfall (true-up payment or tier reset).",
  },
  {
    id: "COMM-242",
    name: "Source-code escrow or continuity",
    cite: practice("oem-continuity", "business-continuity protection in embedded-technology deals"),
    pat: [
      /(escrow|continuity)/i,
      /(source\s+code|bankruptcy|cease(s)?\s+(to\s+)?(do\s+business|support))/i,
    ],
    why: "An OEM whose shipping product embeds a supplier's code cannot survive that supplier's failure. Escrow with defined release conditions is the standard mitigation.",
    fix: "Add a source-code escrow with release conditions (insolvency, cessation of support, uncured material breach) and a post-release license to maintain the product.",
  },
]);

// ── Venue rental ────────────────────────────────────────────────────
const VENUE = pack("venue-rental-agreement", C, [
  {
    id: "COMM-243",
    name: "Cancellation and attrition fee schedule",
    cite: practice("venue-attrition", "attrition and cancellation damages in venue contracts"),
    pat: [
      /(cancel(l)?ation\s+(fee|schedule|charges)|liquidated\s+damages)/i,
      /(attrition|room\s+block|food\s+and\s+beverage\s+minimum|sliding\s+scale)/i,
    ],
    why: "Attrition and cancellation fees are liquidated damages and are unenforceable as penalties unless they approximate the venue's actual loss and account for resale of the space.",
    fix: "State the sliding cancellation schedule and attrition formula, tie them to actual anticipated loss, and require the venue to credit resold space.",
  },
  {
    id: "COMM-244",
    name: "Force majeure and impossibility standard",
    cite: practice("venue-force-majeure", "force majeure standards in event contracts"),
    pat: [
      /force\s+majeure/i,
      /(impossible|impracticab|inadvisable|commercially\s+impracticable|government\s+order)/i,
    ],
    why: "The 2020 cancellations turned on whether the clause required impossibility or merely inadvisability, and whether government orders and epidemics were enumerated. Both parties need the standard stated.",
    fix: 'Enumerate the triggering events (including epidemic and government order), state the standard ("impossible, illegal, or commercially impracticable"), and set the refund and rebooking consequence.',
  },
  {
    id: "COMM-245",
    name: "Insurance and additional-insured status",
    cite: practice("venue-insurance", "insurance requirements in venue rental agreements"),
    pat: [
      /insur(e|ance)/i,
      /(additional\s+insured|certificate\s+of\s+insurance|general\s+liability|\$\d)/i,
    ],
    why: "Venues require event liability coverage naming them as additional insured; a licensee that does not carry it is personally exposed for every guest injury.",
    fix: "State the required coverages and limits, require additional-insured status and a certificate before load-in, and add waivers of subrogation.",
  },
  {
    id: "COMM-246",
    name: "Alcohol service and dram-shop allocation",
    cite: stateLaw(
      "dram-shop",
      "dram shop and social-host liability for alcohol service",
      "https://www.law.cornell.edu/wex/dram_shop_laws",
    ),
    pat: [
      /(alcohol|liquor|bar\s+service|beverage\s+service)/i,
      /(dram\s+shop|licensed\s+server|liquor\s+liability|no\s+outside\s+alcohol)/i,
    ],
    why: "Dram-shop statutes impose liability on the server, and social-host statutes can reach the host. Which party holds the license and the liquor-liability coverage decides who is exposed.",
    fix: "State who holds the liquor license, that only licensed servers may serve, and require liquor-liability coverage from the serving party.",
    when: [/(alcohol|liquor|bar\s+service|wine|beer|open\s+bar)/i],
  },
  {
    id: "COMM-247",
    name: "Damage deposit and restoration",
    cite: practice("venue-damage", "damage deposits and restoration obligations in venue rentals"),
    pat: [
      /(deposit|security\s+deposit)/i,
      /(damage|restore|return\s+the\s+(space|premises)|clean(ing|up))/i,
    ],
    why: "Restoration disputes after an event are routine. A stated deposit, a documented pre-event condition, and a return deadline convert them into a short accounting.",
    fix: "State the deposit amount, the condition standard on return, the pre- and post-event walkthrough, and the deadline for returning the unused deposit with an itemized statement.",
  },
]);

export const V5_COMMERCIAL_DIGITAL_RULES: readonly Rule[] = [
  ...WEBSITE_TOU,
  ...API_TERMS,
  ...DATA_LICENSE,
  ...LOYALTY,
  ...SWEEPSTAKES,
  ...AUTO_RENEWAL,
  ...OEM,
  ...VENUE,
];
