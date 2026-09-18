/**
 * The search-landing pages, the 404 page, `sitemap.xml` and `llms.txt`.
 *
 * The app itself is one page (`site/index.html`), which can rank for one set
 * of queries. People do not search for "deterministic contract linter"; they
 * search for "free NDA review", "DPA checker", "HIPAA BAA checklist". Each
 * page below answers one of those intents with its own URL, title and
 * content, and sends the reader to the tool on the home page.
 *
 * The pages are static HTML with no script (JSON-LD is data, not script, so
 * the CSP in `vite.config.ts` needs no new hash). The build writes each one to
 * `dist/<slug>.html`, which Cloudflare Pages serves at `/<slug>`.
 *
 * Every claim here must be true of the shipped engine. The two headline
 * numbers are never typed into this file: the build reads them from the
 * landing page, where `headline-count-drift.test.ts` already guards them.
 */

export const ORIGIN = "https://vaulytica.com";

/**
 * The date the page content last changed. Used as `lastmod` in the sitemap
 * and `dateModified` in the JSON-LD. Bump it when the copy changes — never
 * stamp the build date: a `lastmod` that is always today is a signal search
 * engines learn to ignore, and it would make `dist/` nondeterministic.
 */
export const CONTENT_UPDATED = "2026-09-18";

export interface HeadlineCounts {
  /** e.g. "1,825" */
  readonly rules: string;
  /** e.g. "268" */
  readonly docTypes: string;
}

export interface SeoPage {
  readonly slug: string;
  /** `<title>`. Keep it under ~60 characters so it is not truncated. */
  readonly title: string;
  /** Meta description. Keep it under ~160 characters. */
  readonly description: string;
  /** Short label used in links, breadcrumbs and the footer. */
  readonly label: string;
  readonly h1: string;
  /** HTML. May use `{rules}` and `{docTypes}`. */
  readonly lead: string;
  readonly cta: string;
  readonly checksHeading: string;
  /** [what it checks, why it matters]. HTML allowed. */
  readonly checks: ReadonlyArray<readonly [string, string]>;
  /** An optional page-specific section. HTML allowed. */
  readonly extra?: { readonly heading: string; readonly html: string };
  /** [question, answer]. Plain text: also emitted as FAQPage JSON-LD. */
  readonly faq: ReadonlyArray<readonly [string, string]>;
}

export const SEO_PAGES: ReadonlyArray<SeoPage> = [
  {
    slug: "nda-review",
    title: "Free NDA Review — Check an NDA in Seconds | Vaulytica",
    description:
      "Free NDA checker. Find a missing DTSA notice, weak exclusions, residuals and one-sided terms in a mutual or one-way NDA. Private: nothing is uploaded.",
    label: "NDA review",
    h1: "Free NDA review, in seconds.",
    lead: "Drop a mutual or one-way non-disclosure agreement and get a report of what is missing, what is one-sided, and what could cost you — each finding quoted from your NDA and tied to the rule and source behind it. Free, private, no signup.",
    cta: "Check your NDA now",
    checksHeading: "What it checks in an NDA",
    checks: [
      [
        "DTSA whistleblower-immunity notice",
        "Under 18 U.S.C. § 1833(b), an employer that omits the notice from an agreement with an employee or contractor can lose exemplary damages and attorney fees in a trade-secret suit.",
      ],
      [
        "The definition of Confidential Information",
        "Too narrow and your information is unprotected; too broad and it may not be enforceable.",
      ],
      [
        "The four standard exclusions",
        "Publicly available, already known, received lawfully from a third party, and independently developed. A missing one is a common drafting gap.",
      ],
      [
        "Permitted use and residuals",
        "Whether the recipient may use what it learns for anything beyond the stated purpose, including information retained in unaided memory.",
      ],
      [
        "Return or destruction, with certification",
        "What happens to your information when the relationship ends, and whether you can get proof.",
      ],
      [
        "Injunctive relief and bond waiver",
        "Whether you can get a court order quickly if the NDA is breached.",
      ],
      [
        "Mutual symmetry",
        "In a mutual NDA, whether obligations that should bind both parties only bind one.",
      ],
      [
        "Non-solicit, no-license and governing law",
        "The clauses that quietly turn an NDA into something broader than a confidentiality promise.",
      ],
    ],
    faq: [
      [
        "Is this NDA review really free?",
        "Yes. Vaulytica is free and open source under the MIT license. There is no account, no trial and no paid tier.",
      ],
      [
        "Does my NDA get uploaded anywhere?",
        "No. The analysis runs inside your browser tab. Your document is never sent to a server.",
      ],
      [
        "Does it work on one-way (unilateral) NDAs?",
        "Yes. Mutual and unilateral NDAs each have their own playbook, so a one-way NDA is not flagged for missing reciprocal obligations.",
      ],
      [
        "Will it tell me whether to sign?",
        "No. It is a checking tool, not legal advice. It shows you what the document says and does not say, so you or your lawyer can decide faster.",
      ],
    ],
  },
  {
    slug: "msa-review",
    title: "Free MSA & SOW Review — Contract Checker | Vaulytica",
    description:
      "Free Master Services Agreement and Statement of Work review. Checks liability caps, indemnity, SLAs, termination, data return and order of precedence.",
    label: "MSA & SOW review",
    h1: "Free MSA and SOW review.",
    lead: "Drop a Master Services Agreement, a Statement of Work, or both. Vaulytica checks the terms that decide who pays when things go wrong, and cross-checks the documents against each other so the SOW does not quietly contradict the MSA.",
    cta: "Review your MSA now",
    checksHeading: "What it checks in an MSA",
    checks: [
      [
        "Limitation of liability and its carve-outs",
        "Whether the cap exists, what it is measured against, and whether indemnity, confidentiality and data breaches sit inside or outside it.",
      ],
      ["Indemnification", "Who defends whom, for what, and whether the obligation is mutual."],
      [
        "Service levels and remedies",
        "Whether uptime or delivery commitments exist and what you actually get when they are missed. Exclusive-remedy language is read against U.C.C. § 2-719.",
      ],
      [
        "Termination and data return",
        "How either side can exit, the cure period, and whether your data comes back when the contract ends.",
      ],
      [
        "Order of precedence",
        "Which document wins when the MSA, a SOW and an order form disagree.",
      ],
      [
        "Confidentiality, data protection and governing law",
        "The baseline clauses every services relationship needs.",
      ],
    ],
    extra: {
      heading: "Check the whole deal, not one file",
      html: "<p>Drop up to four documents at once — for example an MSA, a SOW and a DPA — and Vaulytica also checks them against each other: two documents that name different governing law, inconsistent dates, or a privacy notice that contradicts its own DPA. Customer-side and vendor-side playbooks read the same clause from the side you are on.</p>",
    },
    faq: [
      [
        "Can it review an MSA and SOW together?",
        "Yes. Drop both files at once and each is reviewed on its own, then the two are checked against each other for conflicts.",
      ],
      [
        "I am the vendor, not the customer. Does that matter?",
        "Yes. There are separate customer-side and vendor-side MSA playbooks, because the same clause can be a risk for one side and a protection for the other.",
      ],
      [
        "What file types does it accept?",
        "PDF and DOCX. Everything is read locally in your browser.",
      ],
    ],
  },
  {
    slug: "saas-agreement-review",
    title: "Free SaaS Agreement Review — Subscription Checker | Vaulytica",
    description:
      "Free SaaS agreement review. Checks auto-renewal notice windows, liability caps, SLAs, data processing, IP indemnity and unilateral change rights.",
    label: "SaaS agreement review",
    h1: "Free SaaS agreement review.",
    lead: "Before you sign a software subscription, find the auto-renewal trap, the vendor-favorable liability cap, and the clause that lets them change the terms later. Every finding quotes the clause and cites its source.",
    cta: "Review your SaaS agreement",
    checksHeading: "What it checks in a SaaS agreement",
    checks: [
      [
        "Auto-renewal and notice windows",
        "When the contract renews on its own and how early you must give notice to stop it. Stated deadlines export to a calendar file you can import.",
      ],
      [
        "Unilateral modification",
        "Whether the vendor can change price or terms by posting an update on its website.",
      ],
      [
        "Limitation of liability",
        "The cap, what it excludes, and whether it covers the vendor losing your data.",
      ],
      ["Warranties and disclaimers", "What the vendor actually promises the software will do."],
      [
        "Indemnification, including IP",
        "Whether the vendor stands behind you if someone claims the software infringes their rights.",
      ],
      [
        "Data processing, term and termination for cause",
        "Whether data processing terms are present, and how you can leave if the service fails.",
      ],
    ],
    faq: [
      [
        "Does it work on click-through terms of service?",
        "Yes. Consumer-facing SaaS terms of service have their own playbook, separate from negotiated enterprise subscriptions.",
      ],
      [
        "Can it tell me when I need to cancel?",
        "When the contract states its renewal and notice terms, the deadlines are exported as a calendar (.ics) file you can add to Google Calendar, Outlook or Apple Calendar.",
      ],
      [
        "Is my contract sent to an AI model?",
        "No. There is no AI and no server. The checks are deterministic rules that run in your browser.",
      ],
    ],
  },
  {
    slug: "dpa-review",
    title: "Free DPA Checker — GDPR Article 28 & CCPA | Vaulytica",
    description:
      "Free Data Processing Agreement checker. Reviews GDPR Article 28(3) terms, sub-processors, breach notice, international transfers and CCPA service-provider terms.",
    label: "DPA review (GDPR / CCPA)",
    h1: "Free DPA checker for GDPR and US privacy laws.",
    lead: "Drop a Data Processing Agreement and see which required terms are present, which are missing, and which are too weak — checked against the text of the GDPR, UK GDPR, the CCPA and other US state privacy laws, with every finding linked to the provision it relies on.",
    cta: "Check your DPA now",
    checksHeading: "What it checks in a DPA",
    checks: [
      [
        "GDPR Article 28(3) required terms",
        "Documented instructions, confidentiality of personnel, security, sub-processing, assistance with data-subject rights, deletion or return, and audit rights.",
      ],
      [
        "Sub-processor governance",
        "Prior authorization, notice of changes and flow-down of obligations under Articles 28(2), 28(4) and 28(9).",
      ],
      [
        "Security, breach notice and DPIA assistance",
        "Article 32 security measures, Article 33(2) notice to the controller, and Article 35 support.",
      ],
      [
        "International transfers",
        "Chapter V transfer mechanisms, including the EU Standard Contractual Clauses, the UK IDTA and Addendum, and Swiss FADP terms.",
      ],
      [
        "CCPA / CPRA service-provider terms",
        "The contract terms Cal. Civ. Code § 1798.140(ag) and 11 CCR § 7051 require for service-provider status.",
      ],
      [
        "Other US state privacy laws",
        "Processor-contract requirements under Virginia, Colorado, Connecticut, Utah, Texas, Oregon and other state laws.",
      ],
    ],
    faq: [
      [
        "Which DPAs does it support?",
        "Controller-to-processor and processor-to-sub-processor DPAs under the EU and UK GDPR, CCPA service-provider agreements, and multi-state US DPAs.",
      ],
      [
        "Can it check a DPA against its privacy notice or main agreement?",
        "Yes. Drop the documents together and they are cross-checked, for example a privacy notice that denies a disclosure its own DPA authorizes.",
      ],
      [
        "Is it safe to use on a confidential DPA?",
        "Yes. The analysis runs in your browser. Nothing is uploaded, logged or retained, and you can confirm that in your browser's Network tab.",
      ],
    ],
  },
  {
    slug: "baa-review",
    title: "Free HIPAA BAA Checker — Business Associate Review | Vaulytica",
    description:
      "Free HIPAA Business Associate Agreement checker. Reviews the 45 CFR 164.504(e) required terms, Security Rule flow-down, breach notice and subcontractor BAAs.",
    label: "HIPAA BAA review",
    h1: "Free HIPAA BAA checker.",
    lead: "Drop a Business Associate Agreement and see whether it contains the terms HIPAA requires, with each finding tied to the section of 45 C.F.R. Part 164 behind it. Your document never leaves your browser.",
    cta: "Check your BAA now",
    checksHeading: "What it checks in a BAA",
    checks: [
      [
        "45 C.F.R. § 164.504(e) required terms",
        "Permitted uses and disclosures, safeguards, reporting, access and amendment, accounting, HHS access to books and records, and return or destruction at termination.",
      ],
      [
        "Security Rule flow-down",
        "The § 164.314(a) obligations for electronic protected health information.",
      ],
      [
        "Breach notification",
        "Whether the business associate must report breaches of unsecured PHI, and how fast, under § 164.410.",
      ],
      [
        "Subcontractor BAAs",
        "Business-associate-to-subcontractor agreements have their own playbook, so the downstream chain is checked too.",
      ],
      [
        "Scope against the main agreement",
        "Drop the BAA with its services agreement and Vaulytica flags a BAA that is broader than the agreement it sits under.",
      ],
    ],
    faq: [
      [
        "Is a BAA checker the same as HIPAA compliance?",
        "No. It checks the contract's terms. Compliance also depends on what the parties actually do, which no document review can confirm.",
      ],
      [
        "Can I use it on documents with patient information?",
        "The document is processed only in your browser and nothing is uploaded. Follow your own organization's policies for handling PHI.",
      ],
      [
        "Does it check Notices of Privacy Practices?",
        "Yes. HIPAA Notices of Privacy Practices have their own playbook.",
      ],
    ],
  },
  {
    slug: "employment-contract-review",
    title: "Free Employment Contract Review — Offer Letter Check | Vaulytica",
    description:
      "Free employment contract review. Check offer letters, executive agreements, non-competes and contractor agreements for IP, confidentiality and restrictive covenants.",
    label: "Employment contract review",
    h1: "Free employment contract review.",
    lead: "Offer letter, executive agreement, non-compete, or independent-contractor agreement — drop it in and see what it says about your IP, your next job, and how the relationship can end. Free, private, and nothing is uploaded.",
    cta: "Review your employment contract",
    checksHeading: "What it checks in an employment contract",
    checks: [
      ["IP assignment", "What inventions and work product you are assigning to the company."],
      ["Confidentiality", "What you must keep secret, and for how long."],
      [
        "Non-compete and non-solicit",
        "Restrictive covenants, read with state-law overlays such as California Business and Professions Code § 16600.",
      ],
      ["Termination and at-will terms", "How the job can end, and for cause or with notice."],
      [
        "Arbitration and class waivers",
        "Whether disputes must go to private arbitration instead of court.",
      ],
      [
        "Contractor misclassification signals",
        "For independent-contractor agreements, the terms that look like employment rather than a services relationship.",
      ],
    ],
    faq: [
      [
        "Can I use it as an employee, not a company?",
        "Yes. It is free for anyone. It shows what the contract says so you can ask better questions before you sign.",
      ],
      [
        "Does it know my state's law?",
        "Where a state overlay exists, such as California's limits on non-competes, the report notes it next to the affected findings. It is not a substitute for advice on your specific situation.",
      ],
      [
        "Which employment documents are supported?",
        "Offer letters, at-will employment agreements, executive employment agreements, restrictive covenant agreements, employment arbitration agreements, independent-contractor agreements and employee handbooks, among others.",
      ],
    ],
  },
  {
    slug: "lease-review",
    title: "Free Lease Agreement Review — Commercial & Residential | Vaulytica",
    description:
      "Free lease review for commercial and residential leases. Check rent, term, renewal deadlines, insurance, indemnity and assignment, and export key dates to your calendar.",
    label: "Lease review",
    h1: "Free lease agreement review.",
    lead: "Commercial office lease, net lease, sublease or apartment lease — drop it in to see the rent terms, renewal deadlines, insurance and assignment rules in one report, and put every deadline on your calendar.",
    cta: "Review your lease now",
    checksHeading: "What it checks in a lease",
    checks: [
      [
        "Rent and payment terms",
        "Whether rent and payment terms are stated, including operating-expense pass-throughs in multi-tenant leases.",
      ],
      [
        "Term and renewal options",
        "When the lease ends and when you must act to renew. Deadlines export to a calendar file.",
      ],
      [
        "Insurance and indemnification",
        "What coverage you must carry and who is responsible for what.",
      ],
      [
        "Assignment and subletting",
        "Whether you can transfer the lease if your business moves or is sold.",
      ],
      [
        "Termination, notices and governing law",
        "How either side can end the lease and where notices must go.",
      ],
      [
        "Word/numeral and date mismatches",
        "A rent written as one amount in words and another in digits, or a date that cannot exist.",
      ],
    ],
    faq: [
      [
        "Does it handle both commercial and residential leases?",
        "Yes. There are playbooks for multi-tenant commercial leases, single-tenant net (NNN) leases, ground leases, subleases, lease assignments, SNDAs, equipment leases and US residential leases.",
      ],
      [
        "Does it know my state's landlord-tenant law?",
        "Residential lease law varies a lot by state, so the report treats governing law as a key item and does not claim to replace local advice.",
      ],
      [
        "Can I get the lease deadlines on my calendar?",
        "Yes. Deadlines the lease states are exported as an .ics file for Google Calendar, Outlook or Apple Calendar.",
      ],
    ],
  },
  {
    slug: "ai-contract-review-alternative",
    title: "AI Contract Review vs. Deterministic Review | Vaulytica",
    description:
      "Comparing AI contract review tools? Vaulytica is a free alternative that gives the same cited answer every time and never sends your contract to a model.",
    label: "AI contract review alternative",
    h1: "A contract reviewer that gives the same answer every time.",
    lead: "AI contract tools are fluent and fast, and useful for summaries and first drafts. But run the same contract twice and you can get two different answers, neither of which cites where it came from. Vaulytica is the opposite: {rules} fixed, cited checks that produce the same report on any machine, for free, without your contract leaving your browser.",
    cta: "Try it on your contract",
    checksHeading: "How the two approaches differ",
    checks: [
      [
        "Same input, same output",
        "Vaulytica is a rule engine, not a model. The same file, engine version and knowledge base always produce the same report, with a hash you can use to prove it.",
      ],
      [
        "Every finding is cited",
        "Each finding quotes the clause, gives its position in the document, and names the rule and the statute, regulation or drafting standard behind it.",
      ],
      [
        "Nothing leaves your device",
        "Most AI tools send your document to a hosted model. Vaulytica has no server to send it to.",
      ],
      [
        "Exhaustive by design",
        "Every applicable rule runs on every document, and the audit trail lists the rules that found nothing as well as the ones that fired.",
      ],
      [
        "Free, with no usage limits",
        "No per-document pricing, no seats, no trial. MIT-licensed and open source.",
      ],
      [
        "Where AI is better",
        "Explaining a clause in plain English, summarizing a long agreement, or drafting new language. Vaulytica does none of those, and says so.",
      ],
    ],
    extra: {
      heading: "Use both",
      html: "<p>The two approaches answer different questions. An AI assistant helps you understand a document; a deterministic checker makes sure nothing on the checklist was missed and gives you a record you can show someone else. Many reviewers run Vaulytica first, then spend their judgment — or an AI tool — on the findings it surfaces.</p>",
    },
    faq: [
      [
        "Does Vaulytica use AI at all?",
        "No generative AI, no language model and no probabilistic component. The checks are deterministic rules.",
      ],
      [
        "Is deterministic review less capable than AI review?",
        "It is narrower. It cannot interpret or draft, but it will never skip a check or invent a clause that is not there, and each result can be traced to its source.",
      ],
      [
        "Why would a lawyer prefer a deterministic tool?",
        "Because the output can be cited, reproduced and audited. Many courts now require disclosure or certification of generative-AI use in filings, and a deterministic tool can document that none was used.",
      ],
    ],
  },
  {
    slug: "contract-review-for-lawyers",
    title: "Contract Review Software for Lawyers — Free, No AI | Vaulytica",
    description:
      "Free contract review software for attorneys: cited findings, Word comments on your own draft, firm playbooks, and a verification certificate for no-AI court orders.",
    label: "For lawyers",
    h1: "Contract review software for lawyers. Free, cited, and no generative AI.",
    lead: "A first pass that never gets tired: {rules} checks across {docTypes} document types, every finding quoted and cited, your firm's own standard layered on top, and a report you can hand to a partner, a client or a court.",
    cta: "Run a first-pass review",
    checksHeading: "What it gives a legal team",
    checks: [
      [
        "Findings as Word comments on your own draft",
        "A reviewed copy of your .docx with each finding anchored as a comment on the clause — never a generated redline.",
      ],
      [
        "Your firm's playbook",
        "Load a custom playbook and its rules run alongside the catalog. Findings from your standard are labeled as yours.",
      ],
      [
        "Citations you can check",
        "Legal assertions cite the statute or regulator by URL; drafting-practice findings cite their practice source.",
      ],
      [
        "Verification certificate",
        "A one-page certificate (Word and JSON) with the engine version, the input's SHA-256 and the result hash, stating that no generative AI was used. Anyone can re-run it to reproduce the analysis.",
      ],
      [
        "Deal-level checks",
        "Cross-check up to four related documents, compare two versions, and export a closing checklist, obligations ledger and critical-dates calendar.",
      ],
      [
        "Confidentiality by architecture",
        "No server, no upload, no telemetry. Client documents stay on your machine.",
      ],
    ],
    extra: {
      heading: "Built for courts that regulate AI",
      html: "<p>Courts increasingly regulate generative-AI use in filings, and many orders require disclosure of AI use or a certification that none occurred. ABA Formal Opinion 512 places the duty to verify on the lawyer. Vaulytica's verification certificate documents what this tool did — a deterministic rule evaluation performed locally — so the certification can be shown rather than asserted. It certifies the tool's process, never your overall compliance.</p>",
    },
    faq: [
      [
        "Is using Vaulytica consistent with confidentiality duties?",
        "The document is processed only in the browser tab and never transmitted. You can verify that yourself in your browser's developer tools.",
      ],
      [
        "Can we run it inside the firm without the website?",
        "Yes. It is MIT-licensed and open source. You can self-host the static site or run the command-line tool on your own machines.",
      ],
      [
        "Has a lawyer reviewed the rules?",
        "Every rule cites a public source. Separately, a public legal-basis ledger records which rules a licensed attorney has independently signed off on, so you can see exactly how far that review has progressed.",
      ],
    ],
  },
  {
    slug: "contract-linter-ci",
    title: "Contract Linter for CI — CLI & GitHub Action (SARIF) | Vaulytica",
    description:
      "Lint contracts like code. Free, open-source CLI and GitHub Action that reviews PDF and DOCX contracts, emits SARIF, and fails the build on critical findings.",
    label: "CLI & GitHub Action",
    h1: "Lint contracts like code.",
    lead: "The same deterministic engine that runs in the browser ships as a command-line tool and a GitHub Action. Keep your templates in a repository and let a pull request fail when a change introduces a critical issue — with findings annotated in code scanning.",
    cta: "Try it in the browser first",
    checksHeading: "What you can automate",
    checks: [
      [
        "SARIF for code scanning",
        "Upload findings to GitHub code scanning so contract problems show up on the pull request, like a lint error.",
      ],
      [
        "Fail on severity",
        "<code>fail-on: critical</code> turns any critical finding into a failed check.",
      ],
      [
        "Redline gates",
        "Compare a base and revised document and fail only on findings the revision introduced.",
      ],
      [
        "Deal-folder consistency",
        "Gate on cross-document conflicts, such as two documents that name different governing law.",
      ],
      [
        "Every report format",
        "JSON, HTML, Markdown, CSV, Word, a commented copy of your .docx, calendar files and more.",
      ],
      [
        "No network during analysis",
        "The knowledge base ships with the tool, so nothing leaves the runner.",
      ],
    ],
    extra: {
      heading: "GitHub Action",
      html: `<pre><code>- uses: clay-good/vaulytica@v9
  with:
    command: analyze
    files: contracts/
    format: sarif
    out: vaulytica-out
    fail-on: critical
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: vaulytica-out }</code></pre>
<p>Full recipes, including the redline gate and the CLI, are in the <a href="https://github.com/clay-good/vaulytica/blob/main/docs/ci-integration.md">CI integration guide</a>.</p>`,
    },
    faq: [
      [
        "Does the Action send my contracts anywhere?",
        "No. The analysis opens no network connection; the knowledge base ships with the tool.",
      ],
      [
        "Is the CLI output the same as the website's?",
        "Yes. The browser and the Node pipeline run the same engine and produce the same result for the same input.",
      ],
      ["What does it cost?", "Nothing. It is MIT-licensed open source."],
    ],
  },
];

const escapeHtml = (s: string): string =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

const fill = (s: string, counts: HeadlineCounts): string =>
  s.replace(/\{rules\}/g, counts.rules).replace(/\{docTypes\}/g, counts.docTypes);

export const pageUrl = (slug: string): string => `${ORIGIN}/${slug}`;

/**
 * Read the two headline numbers from the landing page. Those numbers are
 * already pinned to the live catalog by `headline-count-drift.test.ts`, so
 * reading them here means the landing pages can never state a different one.
 */
export function readHeadlineCounts(indexHtml: string): HeadlineCounts {
  const rules = /data-rule-total>([\d,]+)</.exec(indexHtml)?.[1];
  const docTypes = /data-doc-types>(\d+)</.exec(indexHtml)?.[1];
  if (rules === undefined || docTypes === undefined) {
    throw new Error("seo-pages: index.html no longer states the rule or document-type count");
  }
  return { rules, docTypes };
}

const STYLE = `
:root{--bg:#0e1119;--surface:#161b26;--heading:#f3efe4;--body:#c9c6bc;--muted:#97948b;--line:#262c3a;--accent:#e3b341;--link:#e9c05a;--max:980px;--pad:clamp(20px,4vw,40px);--serif:"Iowan Old Style","Palatino Linotype",Palatino,Georgia,serif;--sans:ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
*{box-sizing:border-box}html,body{margin:0}body{background:var(--bg);color:var(--body);font:18px/1.65 var(--sans);-webkit-font-smoothing:antialiased}
a{color:var(--link)}a:hover{text-decoration:none}
h1,h2,h3{color:var(--heading);line-height:1.15;margin:0 0 .5em}h1,h2{font-family:var(--serif)}h1{font-size:clamp(32px,5.5vw,52px)}h2{font-size:clamp(24px,3.2vw,32px)}h3{font-size:19px}
p{margin:0 0 1em}.wrap{max-width:var(--max);margin:0 auto;padding:0 var(--pad)}
header{border-bottom:1px solid var(--line)}header .wrap{display:flex;align-items:center;justify-content:space-between;gap:16px;padding-top:14px;padding-bottom:14px}
.wordmark{display:inline-flex;align-items:center;gap:9px;font:600 24px var(--serif);color:var(--heading);text-decoration:none}.wordmark span{width:11px;height:11px;border-radius:50%;background:var(--accent);border:2px solid var(--bg);box-shadow:0 0 0 1.5px var(--accent)}
header nav a{margin-left:14px;font-size:15px;white-space:nowrap}
.crumbs{font-size:15px;color:var(--muted);margin:28px 0 0}.crumbs a{color:var(--muted)}
.hero{padding:28px 0 48px}.lead{font-size:20px;max-width:760px}
.cta{display:inline-block;background:var(--accent);color:#0e1119;font-weight:700;padding:14px 22px;border-radius:10px;text-decoration:none;margin:8px 12px 8px 0}.cta:hover{background:#f0c862}
.trust{list-style:none;padding:0;margin:20px 0 0;display:flex;flex-wrap:wrap;gap:8px 20px;color:var(--muted);font-size:15px}.trust li::before{content:"✓ ";color:var(--accent)}
section{padding:44px 0;border-top:1px solid var(--line)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:20px}.card p{margin:0;font-size:16.5px}
ol.steps{padding-left:22px}ol.steps li{margin-bottom:10px}
pre{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:16px;overflow-x:auto;font-size:14.5px;color:var(--heading)}
.sev{margin-top:10px!important;font-size:14px!important;color:var(--muted)}.faq h3{margin-top:24px}.links{columns:2 240px;padding-left:20px}
footer{border-top:1px solid var(--line);padding:32px 0 48px;font-size:15px;color:var(--muted)}footer a{color:var(--muted)}
`.trim();

function head(opts: {
  title: string;
  description: string;
  canonical: string | null;
  robots: string;
  jsonLd: ReadonlyArray<object>;
}): string {
  const canonical =
    opts.canonical === null
      ? ""
      : `<link rel="canonical" href="${opts.canonical}" />
    <meta property="og:url" content="${opts.canonical}" />`;
  const ld = opts.jsonLd
    .map((o) => `<script type="application/ld+json">${JSON.stringify(o)}</script>`)
    .join("\n    ");
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(opts.title)}</title>
    <meta name="description" content="${escapeHtml(opts.description)}" />
    <meta name="robots" content="${opts.robots}" />
    <meta name="theme-color" content="#0E1119" />
    <meta name="color-scheme" content="dark" />
    ${canonical}
    <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
    <link rel="apple-touch-icon" href="/apple-touch-icon.png" />
    <meta property="og:type" content="website" />
    <meta property="og:site_name" content="Vaulytica" />
    <meta property="og:title" content="${escapeHtml(opts.title)}" />
    <meta property="og:description" content="${escapeHtml(opts.description)}" />
    <meta property="og:image" content="${ORIGIN}/og-image.png" />
    <meta property="og:image:width" content="1200" />
    <meta property="og:image:height" content="630" />
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:title" content="${escapeHtml(opts.title)}" />
    <meta name="twitter:description" content="${escapeHtml(opts.description)}" />
    <meta name="twitter:image" content="${ORIGIN}/og-image.png" />
    <style>${STYLE}</style>
    ${ld}
  </head>`;
}

const HEADER = `<header>
      <div class="wrap">
        <a class="wordmark" href="/"><span aria-hidden="true"></span>vaulytica</a>
        <nav aria-label="Primary"><a href="/">Review a contract</a><a href="https://github.com/clay-good/vaulytica">GitHub</a></nav>
      </div>
    </header>`;

function footer(): string {
  const links = SEO_PAGES.map((p) => `<a href="/${p.slug}">${escapeHtml(p.label)}</a>`).join(" · ");
  return `<footer>
      <div class="wrap">
        <p><a href="/">Vaulytica</a> · ${links} · <a href="/reviews">All document types</a></p>
        <p>Free and open source under the MIT license · <a href="https://github.com/clay-good/vaulytica">Source on GitHub</a> · Made by <a href="https://claygood.com">Clay Good</a></p>
        <p>Vaulytica is a software tool, not a law firm. It does not give legal advice, and using it does not create an attorney-client relationship.</p>
      </div>
    </footer>`;
}

/** Render one landing page to a complete HTML document. */
export function renderSeoPage(page: SeoPage, counts: HeadlineCounts): string {
  const url = pageUrl(page.slug);
  const lead = fill(page.lead, counts);
  const checks = page.checks
    .map(([t, why]) => `<div class="card"><h3>${t}</h3><p>${why}</p></div>`)
    .join("\n          ");
  const faq = page.faq
    .map(([q, a]) => `<h3>${escapeHtml(q)}</h3>\n          <p>${escapeHtml(a)}</p>`)
    .join("\n          ");
  const related = SEO_PAGES.filter((p) => p.slug !== page.slug)
    .map((p) => `<li><a href="/${p.slug}">${escapeHtml(p.label)}</a></li>`)
    .join("");
  const extra =
    page.extra === undefined
      ? ""
      : `<section>
        <h2>${page.extra.heading}</h2>
        ${page.extra.html}
      </section>`;

  const jsonLd = [
    {
      "@context": "https://schema.org",
      "@type": "WebPage",
      "@id": `${url}#webpage`,
      url,
      name: page.title,
      description: page.description,
      inLanguage: "en-US",
      dateModified: CONTENT_UPDATED,
      isPartOf: { "@id": `${ORIGIN}/#website` },
      about: { "@id": `${ORIGIN}/#webapp` },
      breadcrumb: { "@id": `${url}#breadcrumb` },
    },
    {
      "@context": "https://schema.org",
      "@type": "BreadcrumbList",
      "@id": `${url}#breadcrumb`,
      itemListElement: [
        { "@type": "ListItem", position: 1, name: "Vaulytica", item: `${ORIGIN}/` },
        { "@type": "ListItem", position: 2, name: page.label, item: url },
      ],
    },
    {
      "@context": "https://schema.org",
      "@type": "FAQPage",
      mainEntity: page.faq.map(([q, a]) => ({
        "@type": "Question",
        name: q,
        acceptedAnswer: { "@type": "Answer", text: a },
      })),
    },
  ];

  return `${head({ title: page.title, description: page.description, canonical: url, robots: "index, follow, max-image-preview:large, max-snippet:-1", jsonLd })}
  <body>
    ${HEADER}
    <main class="wrap">
      <nav class="crumbs" aria-label="Breadcrumb"><a href="/">Vaulytica</a> › ${escapeHtml(page.label)}</nav>
      <div class="hero">
        <h1>${escapeHtml(page.h1)}</h1>
        <p class="lead">${lead}</p>
        <a class="cta" href="/">${escapeHtml(page.cta)} →</a>
        <ul class="trust" aria-label="At a glance">
          <li>Free forever (MIT)</li>
          <li>Nothing uploaded</li>
          <li>No account</li>
          <li>${counts.rules} cited checks</li>
          <li>PDF or DOCX</li>
        </ul>
      </div>
      <section>
        <h2>${escapeHtml(page.checksHeading)}</h2>
        <div class="grid">
          ${checks}
        </div>
      </section>
      ${extra}
      <section>
        <h2>What you get</h2>
        <div class="grid">
          <div class="card"><h3>A Word report</h3><p>A findings index by severity, then each finding in full: the quoted clause, its position, the rule, and its source.</p></div>
          <div class="card"><h3>Comments on your own draft</h3><p>Your .docx back with each finding attached as a Word comment on the clause it is about.</p></div>
          <div class="card"><h3>Deadlines on your calendar</h3><p>Renewal, notice and cure dates the document states, as an .ics file.</p></div>
          <div class="card"><h3>Obligations and fix lists</h3><p>Who owes what, and what to fix, as spreadsheets you can sort and share.</p></div>
        </div>
      </section>
      <section>
        <h2>How it works</h2>
        <ol class="steps">
          <li><strong>Open <a href="/">vaulytica.com</a></strong> — no account, nothing to install.</li>
          <li><strong>Drop your PDF or DOCX.</strong> It is read inside your browser tab; nothing is uploaded.</li>
          <li><strong>Get your report in seconds.</strong> The document type is detected and only the checks that belong to it run.</li>
        </ol>
        <a class="cta" href="/">${escapeHtml(page.cta)} →</a>
      </section>
      <section class="faq">
        <h2>Questions</h2>
          ${faq}
      </section>
      <section>
        <h2>Other free reviews</h2>
        <ul class="links">${related}</ul>
      </section>
    </main>
    ${footer()}
  </body>
</html>
`;
}

/** A real 404, so an unknown URL is not indexed as a copy of the home page. */
export function render404(): string {
  const links = SEO_PAGES.map(
    (p) => `<li><a href="/${p.slug}">${escapeHtml(p.label)}</a></li>`,
  ).join("");
  return `${head({ title: "Page not found | Vaulytica", description: "This page does not exist.", canonical: null, robots: "noindex", jsonLd: [] })}
  <body>
    ${HEADER}
    <main class="wrap">
      <div class="hero">
        <h1>Page not found.</h1>
        <p class="lead">The page you asked for does not exist. The contract reviewer is on the home page.</p>
        <a class="cta" href="/">Review a contract →</a>
      </div>
      <section>
        <h2>Free reviews</h2>
        <ul class="links">${links}</ul>
      </section>
    </main>
    ${footer()}
  </body>
</html>
`;
}

/** `sitemap.xml`: the home page and every landing page. No fragment URLs. */
export function buildSitemap(docTypes: ReadonlyArray<{ readonly id: string }> = []): string {
  const url = (loc: string): string =>
    `  <url>\n    <loc>${loc}</loc>\n    <lastmod>${CONTENT_UPDATED}</lastmod>\n  </url>`;
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    url(`${ORIGIN}/`),
    ...SEO_PAGES.map((p) => url(pageUrl(p.slug))),
    ...(docTypes.length > 0 ? [url(`${ORIGIN}/reviews`)] : []),
    ...docTypes.map((t) => url(docTypeUrl(t.id))),
    "</urlset>",
    "",
  ].join("\n");
}

/**
 * `llms.txt` (llmstxt.org): a plain summary for AI search engines and
 * assistants, so when someone asks one for a free contract reviewer the
 * answer can describe this tool accurately and link the right page.
 */
export function buildLlmsTxt(counts: HeadlineCounts): string {
  return [
    "# Vaulytica",
    "",
    `> Free, open-source (MIT) contract review tool that runs entirely in the browser. Drop a PDF or DOCX and get a report in which every finding quotes the clause and cites its rule and source. ${counts.rules} deterministic checks across ${counts.docTypes} document types. No AI, no account, no upload.`,
    "",
    "Vaulytica is a deterministic rule engine, not a language model: the same file always produces the same report. It checks for missing clauses, one-sided terms, dates and deadlines, financial inconsistencies and drafting defects, and exports a Word report, a commented copy of the user's .docx, calendar (.ics) deadlines, and CSV obligation and fix lists. It is not legal advice.",
    "",
    "## Reviews",
    "",
    ...SEO_PAGES.map((p) => `- [${p.label}](${pageUrl(p.slug)}): ${p.description}`),
    "",
    "## Project",
    "",
    `- [Use the tool](${ORIGIN}/): the browser app`,
    `- [Every document type](${ORIGIN}/reviews): each of the ${counts.docTypes} document types and the checks it gets`,
    "- [Source code](https://github.com/clay-good/vaulytica): MIT-licensed repository",
    "- [CI integration](https://github.com/clay-good/vaulytica/blob/main/docs/ci-integration.md): CLI and GitHub Action",
    "",
  ].join("\n");
}

// ---------------------------------------------------------------------------
// Per-document-type pages (`/review/<id>`) and their index (`/reviews`).
// Data: tools/site/doc-types.json, generated from the rule catalog.
// ---------------------------------------------------------------------------

export interface DocTypePageData {
  readonly id: string;
  readonly name: string;
  readonly group: string;
  readonly summary: string;
  readonly checks: ReadonlyArray<{
    readonly id: string;
    readonly name: string;
    readonly description: string;
    readonly severity: string;
  }>;
  readonly general_checks: number;
  readonly companions: ReadonlyArray<string>;
  readonly sources: ReadonlyArray<{ readonly title: string; readonly url: string }>;
}

export const docTypeUrl = (id: string): string => `${ORIGIN}/review/${id}`;

const SEVERITY_LABEL: Record<string, string> = {
  critical: "Critical",
  warning: "Warning",
  info: "Note",
};

/** `<title>`: the longest form that still fits a search result. */
export function docTypeTitle(name: string): string {
  for (const t of [`Free ${name} Review | Vaulytica`, `${name} Review | Vaulytica`]) {
    if (t.length <= 65) return t;
  }
  return `${name} | Vaulytica`;
}

/** Meta description: what it checks, in the reader's words, under 160 characters. */
export function docTypeDescription(t: DocTypePageData): string {
  const n = t.checks.length;
  const tail = " Free, cited, nothing uploaded.";
  const base =
    n === 0
      ? `Free ${t.name} review in your browser: ${t.general_checks} general contract checks.`
      : `Free ${t.name} review: ${n} document-specific check${n === 1 ? "" : "s"} plus ${t.general_checks} general checks.`;
  const named = t.checks.slice(0, 3).map((c) => c.name);
  for (let k = named.length; k > 0; k--) {
    const d = `${base} Includes ${named.slice(0, k).join("; ")}.${tail}`;
    if (d.length <= 160) return d;
  }
  return (base + tail).length <= 160 ? base + tail : base;
}

export function renderDocTypePage(
  t: DocTypePageData,
  all: ReadonlyArray<DocTypePageData>,
  counts: HeadlineCounts,
): string {
  const url = docTypeUrl(t.id);
  const byId = new Map(all.map((x) => [x.id, x]));
  const title = docTypeTitle(t.name);
  const description = docTypeDescription(t);
  const checks =
    t.checks.length === 0
      ? `<p>Vaulytica recognizes this document type and runs its ${t.general_checks} general checks on it — structure, parties and signatures, defined terms, cross-references, dates, amounts, and one-sided terms. It has no checks written for this document type alone yet.</p>`
      : `<div class="grid">
          ${t.checks
            .map(
              (c) =>
                `<div class="card"><h3>${escapeHtml(c.name)}</h3><p>${escapeHtml(c.description)}</p><p class="sev">${SEVERITY_LABEL[c.severity] ?? escapeHtml(c.severity)} · <code>${escapeHtml(c.id)}</code></p></div>`,
            )
            .join("\n          ")}
        </div>
        <p style="margin-top:20px">Every run also applies ${t.general_checks} general checks that belong to any agreement: structure, parties and signatures, defined terms, cross-references, dates, amounts, and one-sided terms.</p>`;
  const sources =
    t.sources.length === 0
      ? ""
      : `<section>
        <h2>Sources</h2>
        <ul>${t.sources.map((s) => `<li><a href="${escapeHtml(s.url)}" rel="noopener">${escapeHtml(s.title)}</a></li>`).join("")}</ul>
      </section>`;
  const companions = t.companions.filter((c) => byId.has(c));
  const related =
    companions.length === 0
      ? ""
      : `<section>
        <h2>Often reviewed with</h2>
        <ul class="links">${companions.map((c) => `<li><a href="/review/${c}">${escapeHtml(byId.get(c)!.name)}</a></li>`).join("")}</ul>
      </section>`;
  const siblings = all.filter((x) => x.group === t.group && x.id !== t.id);
  const jsonLd = [
    {
      "@context": "https://schema.org",
      "@type": "WebPage",
      "@id": `${url}#webpage`,
      url,
      name: title,
      description,
      inLanguage: "en-US",
      dateModified: CONTENT_UPDATED,
      isPartOf: { "@id": `${ORIGIN}/#website` },
      about: { "@id": `${ORIGIN}/#webapp` },
      breadcrumb: { "@id": `${url}#breadcrumb` },
    },
    {
      "@context": "https://schema.org",
      "@type": "BreadcrumbList",
      "@id": `${url}#breadcrumb`,
      itemListElement: [
        { "@type": "ListItem", position: 1, name: "Vaulytica", item: `${ORIGIN}/` },
        { "@type": "ListItem", position: 2, name: "Document types", item: `${ORIGIN}/reviews` },
        { "@type": "ListItem", position: 3, name: t.name, item: url },
      ],
    },
  ];
  return `${head({ title, description, canonical: url, robots: "index, follow, max-image-preview:large, max-snippet:-1", jsonLd })}
  <body>
    ${HEADER}
    <main class="wrap">
      <nav class="crumbs" aria-label="Breadcrumb"><a href="/">Vaulytica</a> › <a href="/reviews">Document types</a> › ${escapeHtml(t.name)}</nav>
      <div class="hero">
        <h1>${escapeHtml(t.name)} review</h1>
        <p class="lead">${escapeHtml(t.summary)}</p>
        <a class="cta" href="/">Review your document — free →</a>
        <ul class="trust" aria-label="At a glance">
          <li>${t.checks.length} document-specific check${t.checks.length === 1 ? "" : "s"}</li>
          <li>+ ${t.general_checks} general checks</li>
          <li>Nothing uploaded</li>
          <li>Free forever (MIT)</li>
        </ul>
      </div>
      <section>
        <h2>What it checks</h2>
        ${checks}
      </section>
      ${sources}
      ${related}
      <section>
        <h2>How it works</h2>
        <ol class="steps">
          <li><strong>Open <a href="/">vaulytica.com</a></strong> — no account, nothing to install.</li>
          <li><strong>Drop your PDF or DOCX.</strong> The document type is detected and only the checks that belong to it run, inside your browser tab.</li>
          <li><strong>Get a Word report</strong> in which every finding quotes the clause and cites the rule and source behind it — one of ${counts.rules} checks across ${counts.docTypes} document types.</li>
        </ol>
        <a class="cta" href="/">Review your document — free →</a>
      </section>
      <section>
        <h2>More ${escapeHtml(t.group.toLowerCase())} documents</h2>
        <ul class="links">${siblings.map((x) => `<li><a href="/review/${x.id}">${escapeHtml(x.name)}</a></li>`).join("")}</ul>
        <p><a href="/reviews">Every document type →</a></p>
      </section>
    </main>
    ${footer()}
  </body>
</html>
`;
}

/** `/reviews`: every document type, grouped as the landing page groups them. */
export function renderDocTypeIndex(
  all: ReadonlyArray<DocTypePageData>,
  counts: HeadlineCounts,
  groupOrder: ReadonlyArray<string>,
): string {
  const url = `${ORIGIN}/reviews`;
  const title = "Every Document Type Vaulytica Reviews | Vaulytica";
  const description = `The ${all.length} contracts and legal documents Vaulytica reviews for free, and the checks each one gets. Every finding cited; nothing uploaded.`;
  // The landing page's group order, which is the order of `all` by group.
  const groups = [...new Set(all.map((t) => t.group))].sort(
    (a, b) => groupOrder.indexOf(a) - groupOrder.indexOf(b),
  );
  const body = groups
    .map((g) => {
      const items = all.filter((t) => t.group === g);
      return `<section>
        <h2>${escapeHtml(g)} <span style="color:var(--muted);font-size:.6em">${items.length}</span></h2>
        <ul class="links">${items.map((t) => `<li><a href="/review/${t.id}">${escapeHtml(t.name)}</a></li>`).join("")}</ul>
      </section>`;
    })
    .join("\n      ");
  const jsonLd = [
    {
      "@context": "https://schema.org",
      "@type": "CollectionPage",
      "@id": `${url}#webpage`,
      url,
      name: title,
      description,
      inLanguage: "en-US",
      dateModified: CONTENT_UPDATED,
      isPartOf: { "@id": `${ORIGIN}/#website` },
    },
  ];
  return `${head({ title, description, canonical: url, robots: "index, follow, max-image-preview:large, max-snippet:-1", jsonLd })}
  <body>
    ${HEADER}
    <main class="wrap">
      <nav class="crumbs" aria-label="Breadcrumb"><a href="/">Vaulytica</a> › Document types</nav>
      <div class="hero">
        <h1>Every document type Vaulytica reviews.</h1>
        <p class="lead">${all.length} kinds of contracts and legal documents, backed by ${counts.rules} checks in all. Pick one to see exactly what is checked, or drop any document on the home page and the type is detected for you.</p>
        <a class="cta" href="/">Review a document — free →</a>
      </div>
      ${body}
    </main>
    ${footer()}
  </body>
</html>
`;
}

/**
 * Link every entry of the landing page's document-type index to its page.
 * Done at build time so `site/index.html` stays a readable list; a deprecated
 * playbook's entry links to the playbook that superseded it.
 */
export function linkDocTypeIndex(
  html: string,
  types: ReadonlyArray<{ readonly id: string; readonly name: string }>,
  superseded: Readonly<Record<string, string>>,
  allNames: ReadonlyMap<string, string>,
): string {
  const start = html.indexOf('<div class="doc-groups">');
  if (start < 0) throw new Error("seo-pages: the document-type index is missing from index.html");
  const end = html.indexOf("</details>", start);
  const byName = new Map<string, string>();
  for (const t of types) byName.set(escapeHtml(t.name), t.id);
  for (const [old, next] of Object.entries(superseded)) {
    const name = allNames.get(old);
    if (name !== undefined) byName.set(escapeHtml(name), next);
  }
  const region = html.slice(start, end).replace(/<li>([^<]+)<\/li>/g, (m, raw: string) => {
    const id = byName.get(raw.trim());
    return id === undefined ? m : `<li><a href="/review/${id}">${raw.trim()}</a></li>`;
  });
  return html.slice(0, start) + region + html.slice(end);
}
