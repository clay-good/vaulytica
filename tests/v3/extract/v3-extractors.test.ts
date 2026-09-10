import { describe, expect, it } from "vitest";
import { buildTree } from "../../../src/extract/_fixtures.js";
import {
  classifyRoles,
  extractAuditRights,
  extractBreachTimings,
  extractDataCategories,
  extractDtsaNotice,
  extractInsuranceSchedule,
  extractSecurityMeasures,
  extractSubprocessorInventory,
  extractTransferMechanisms,
  extractAllV3,
} from "../../../src/extract/v3/index.js";

describe("v3 role classifier", () => {
  it("detects roles from quoted definitions", () => {
    const tree = buildTree([
      "Definitions",
      `"Processor" means the entity that processes Personal Data on behalf of the Controller.`,
    ]);
    const roles = classifyRoles(tree);
    expect(roles.some((r) => r.role === "processor" && r.evidence === "definition")).toBe(true);
  });

  it("detects role from parenthetical alias", () => {
    const tree = buildTree([
      "Preamble",
      `Acme Corp. (the "Business Associate") shall protect PHI.`,
    ]);
    const roles = classifyRoles(tree);
    expect(roles.some((r) => r.role === "business-associate")).toBe(true);
  });

  it("detects role via CCPA clause usage", () => {
    const tree = buildTree([
      "Body",
      "As a Service Provider under the CCPA, Recipient shall not retain Personal Information.",
    ]);
    const roles = classifyRoles(tree);
    expect(roles.some((r) => r.role === "service-provider-ccpa")).toBe(true);
  });

  it("is empty when no role language appears", () => {
    const tree = buildTree(["Body", "The Effective Date is January 1, 2026."]);
    expect(classifyRoles(tree)).toEqual([]);
  });

  it("is deterministic across runs", () => {
    const tree = buildTree([
      "Body",
      `"Controller" means the entity. "Processor" means the entity that processes.`,
    ]);
    expect(JSON.stringify(classifyRoles(tree))).toEqual(JSON.stringify(classifyRoles(tree)));
  });
});

/**
 * A role belongs to a PARTY, and the party list already says which.
 *
 * 🚨 `PARENS_ROLE_RX` captures the Title-Case run immediately before the role
 * marker, and in a preamble that run is often not the party:
 *
 *   "…Larkmoor Instruments GmbH, a company organized under the laws of Germany
 *    with its registered office at Industriestrasse 14, 70565 Stuttgart
 *    ("Supplier")…"
 *
 * The Supplier was recorded as **Stuttgart** — a city — with a fabricated
 * `party_id` of `role:stuttgart`. The substring fallback could not rescue it,
 * and the binding it needed had already been extracted: Larkmoor's `Party`
 * carries `role: "Supplier"` and `aliases: ["Supplier", …]`. The classifier had
 * that list passed in and asked it only about the captured NAME, never about
 * the ROLE — the one thing it is certain of.
 */
describe("classifyRoles — the party a role belongs to", () => {
  const PREAMBLE =
    "This Agreement is entered into between Larkmoor Instruments GmbH, a company " +
    "organized under the laws of Germany with its registered office at " +
    'Industriestrasse 14, 70565 Stuttgart ("Supplier"), and Ardent Scientific ' +
    'Supply, Inc., a Delaware corporation ("Distributor").';

  const parties = [
    {
      id: "party-1",
      name: "Larkmoor Instruments GmbH",
      role: "Supplier",
      aliases: ["Supplier", "Larkmoor Instruments", "Larkmoor"],
      positions: [],
    },
  ];

  it("does not name a city as the party a role belongs to", () => {
    const roles = classifyRoles(buildTree(["Agreement", PREAMBLE]), parties);
    const supplier = roles.find((r) => r.role === "service-supplier");
    expect(supplier?.party_name).toBe("Larkmoor Instruments GmbH");
    expect(supplier?.party_name).not.toBe("Stuttgart");
  });

  it("uses the real party id, not a synthetic one, when the role resolves", () => {
    const roles = classifyRoles(buildTree(["Agreement", PREAMBLE]), parties);
    const supplier = roles.find((r) => r.role === "service-supplier");
    expect(supplier?.party_id).toBe("party-1");
    expect(supplier?.party_id).not.toMatch(/^role:/);
  });

  it("still resolves when the alias is only in the aliases list", () => {
    const viaAlias = [
      { id: "party-9", name: "Halcyon Data Ltd", aliases: ["Processor"], positions: [] },
    ];
    const roles = classifyRoles(
      buildTree(["DPA", 'Halcyon Data Ltd of 4 Rivergate, Dublin ("Processor") shall process.']),
      viaAlias,
    );
    expect(roles.find((r) => r.role === "processor")?.party_name).toBe("Halcyon Data Ltd");
  });

  it("marks an unbound role with a synthetic id rather than a real one", () => {
    // A form or an SCC module that names a role without an entity behind it is
    // still a real detection — it just cannot name a party. The synthetic
    // `role:` id is what says so, and it is what a consumer reads to tell a
    // bound role from an unbound one.
    //
    // ⚠️ 9 of the corpus's 22 assignments are still in this state, and three of
    // those name something that is plainly not an entity (an SCC "Module Two",
    // a document TITLE). Naming them by their role instead would fix that and
    // would also throw away "Rowan Regional Health System" — a real entity the
    // v2 party extractor missed and this one surfaced. Measured, and left:
    // that trade is a product call, not a derivation.
    const roles = classifyRoles(
      buildTree(["SCC", 'Module Two ("Controller") transfers to the data importer.']),
      [],
    );
    const hit = roles.find((r) => r.role === "controller");
    expect(hit).toBeDefined();
    expect(hit!.party_id).toMatch(/^role:/);
  });
});

describe("v3 data-category extractor", () => {
  /**
   * 🚨 HIPAA's first identifier is the ordinary English word.
   *
   * `hipaa-names` was a bare `/\bnames?\b/i` while every sibling in the
   * catalog requires a phrase that NAMES the category ("telephone numbers",
   * "medical record numbers", "dates of birth"). It matched "shall **name**
   * Licensor as an additional insured", the "**Name:**" line of every
   * signature block, and "trade **name**": **235 of 327 specimens** were
   * recorded as containing a HIPAA identifier, an office lease and a patent
   * licence among them. Scoped in 9.675.0 to 18, every one a privacy or health
   * document.
   */
  it("does not read an ordinary use of the word 'name' as a HIPAA identifier", () => {
    for (const sentence of [
      "Licensee shall name Licensor as an additional insured under the policy.",
      "Name: Ruth Okonjo",
      "The Products are sold under the trade name Halcyon.",
      "Each party shall name a relationship manager within ten (10) days.",
    ]) {
      const cats = extractDataCategories(buildTree(["Clause", sentence]));
      expect(
        cats.map((c) => c.slug),
        `"${sentence}" was read as containing a HIPAA identifier`,
      ).not.toContain("hipaa-names");
    }
  });

  it("reads the bare word inside a real category list", () => {
    // The false-negative direction, and the one that matters most: an Annex I
    // list writes the identifier bare, and refusing it would trade a false
    // positive for a miss on the document type this extractor exists for.
    for (const sentence of [
      "Categories of Personal Data: name, business contact details, employee identification number.",
      "Categories include names, telephone numbers and email addresses.",
      "The data elements are name, address and date of birth.",
      "Protected Health Information includes the patient's name and medical record number.",
    ]) {
      const cats = extractDataCategories(buildTree(["Annex I", sentence]));
      expect(
        cats.map((c) => c.slug),
        `"${sentence}" is a category list and should record the identifier`,
      ).toContain("hipaa-names");
    }
  });

  it("reads a qualified name anywhere, without needing a list", () => {
    for (const sentence of [
      "The Provider collects the patient name at intake.",
      "Please print your full name below.",
      "We ask for the first name of the child.",
    ]) {
      const cats = extractDataCategories(buildTree(["Clause", sentence]));
      expect(cats.map((c) => c.slug)).toContain("hipaa-names");
    }
  });

  it("records the term itself, not the lead-in that qualified it", () => {
    // `raw_text` and `position` stay on the term because the context is a
    // paragraph-level precondition rather than part of the match.
    const cats = extractDataCategories(
      buildTree(["Annex I", "Categories of Personal Data: name, business contact details."]),
    );
    const hit = cats.find((c) => c.slug === "hipaa-names");
    expect(hit?.raw_text).toBe("name");
  });

  it("detects HIPAA identifiers", () => {
    const tree = buildTree([
      "PHI",
      "Categories include names, telephone numbers, email addresses, social security numbers, and IP addresses.",
    ]);
    const cats = extractDataCategories(tree);
    const slugs = cats.map((c) => c.slug);
    expect(slugs).toContain("hipaa-names");
    expect(slugs).toContain("hipaa-phone");
    expect(slugs).toContain("hipaa-email");
    expect(slugs).toContain("hipaa-ssn");
    expect(slugs).toContain("hipaa-ip");
  });

  it("detects GDPR special categories and flag", () => {
    const tree = buildTree([
      "Annex I.B",
      "The data includes special categories of personal data: racial or ethnic origin and data concerning health.",
    ]);
    const cats = extractDataCategories(tree);
    expect(cats.some((c) => c.slug === "special-categories-flag")).toBe(true);
    expect(cats.some((c) => c.group === "gdpr-special")).toBe(true);
  });

  it("reads the 'precise location' paraphrase of CCPA precise geolocation", () => {
    const cats = extractDataCategories(
      buildTree(["Data", "Categories include precise location information about the user."]),
    );
    expect(cats.some((c) => c.slug === "ccpa-precise-geolocation")).toBe(true);
  });

  it("returns nothing on clean text", () => {
    const tree = buildTree(["Body", "The parties agree to terms."]);
    expect(extractDataCategories(tree)).toEqual([]);
  });
});

describe("v3 transfer-mechanism extractor", () => {
  it("classifies SCC Module 2 and locates the annex", () => {
    const tree = buildTree([
      "Cross-border",
      "The parties incorporate Module 2 of the Standard Contractual Clauses, attached as Annex A.",
    ]);
    const mechs = extractTransferMechanisms(tree);
    expect(mechs.some((m) => m.kind === "scc-module-2")).toBe(true);
    expect(mechs.find((m) => m.kind === "scc-module-2")?.location).toBe("annex");
  });

  it("detects UK IDTA, Addendum, and Adequacy Decision", () => {
    const tree = buildTree([
      "Body",
      "Pursuant to the International Data Transfer Agreement (IDTA) and the UK Addendum, transfers rely on an adequacy decision.",
    ]);
    const mechs = extractTransferMechanisms(tree);
    const kinds = mechs.map((m) => m.kind);
    expect(kinds).toContain("uk-idta");
    expect(kinds).toContain("uk-addendum");
    expect(kinds).toContain("adequacy-decision");
  });

  it("classifies Privacy Shield as its own defunct mechanism, not DPF", () => {
    const kinds = extractTransferMechanisms(
      buildTree(["Transfers", "Transfers rely on the EU-U.S. Privacy Shield Framework."]),
    ).map((m) => m.kind);
    expect(kinds).toContain("privacy-shield");
    expect(kinds).not.toContain("data-privacy-framework");
  });

  it("reads adequacy 'finding' and UK adequacy 'regulations' as the adequacy basis", () => {
    for (const text of [
      "Transfers are permitted under an adequacy finding by the Commission.",
      "Transfers rely on the UK adequacy regulations.",
    ]) {
      const kinds = extractTransferMechanisms(buildTree(["Transfers", text])).map((m) => m.kind);
      expect(kinds, text).toContain("adequacy-decision");
    }
  });

  it("returns empty when no transfer language is present", () => {
    const tree = buildTree(["Body", "Effective Date: 2026-01-01."]);
    expect(extractTransferMechanisms(tree)).toEqual([]);
  });
});

describe("v3 security-measures extractor", () => {
  it("detects measures and cadence", () => {
    const tree = buildTree([
      "Annex II",
      "Vendor shall maintain encryption at rest, encryption in transit, multi-factor authentication, and conduct annual penetration testing.",
    ]);
    const measures = extractSecurityMeasures(tree);
    const slugs = measures.map((m) => m.slug);
    expect(slugs).toContain("encryption-at-rest");
    expect(slugs).toContain("encryption-in-transit");
    expect(slugs).toContain("mfa");
    expect(slugs).toContain("penetration-testing");
    const pen = measures.find((m) => m.slug === "penetration-testing");
    expect(pen?.cadence).toBe("annual");
  });

  it("attributes each measure's own cadence when two appear in one sentence", () => {
    // Whole-paragraph inference tagged both measures with the first-listed
    // cadence ("annual"); proximity keeps each measure's neighbouring qualifier.
    const measures = extractSecurityMeasures(
      buildTree([
        "Security",
        "Vendor performs penetration testing annually and conducts continuous vulnerability scanning.",
      ]),
    );
    expect(measures.find((m) => m.slug === "penetration-testing")?.cadence).toBe("annual");
    expect(measures.find((m) => m.slug === "vulnerability-scanning")?.cadence).toBe("continuous");
  });

  it("detects spelled two-factor and passive/hyphenated encryption phrasings", () => {
    const expect_slug = (text: string, slug: string) => {
      const slugs = extractSecurityMeasures(buildTree(["Security", text])).map((m) => m.slug);
      expect(slugs, text).toContain(slug);
    };
    expect_slug("Vendor requires two-factor authentication for administrative access.", "mfa");
    expect_slug("Vendor enforces two-step verification for remote logins.", "mfa");
    expect_slug("All data at rest is encrypted using AES-256.", "encryption-at-rest");
    expect_slug(
      "Vendor maintains data-at-rest encryption across all databases.",
      "encryption-at-rest",
    );
    expect_slug("All data in transit is encrypted.", "encryption-in-transit");
  });

  it("returns empty on clean text", () => {
    const tree = buildTree(["Body", "The Term begins on the Effective Date."]);
    expect(extractSecurityMeasures(tree)).toEqual([]);
  });
});

describe("v3 breach-timing extractor", () => {
  it("normalizes hours and days", () => {
    const tree = buildTree([
      "Notification",
      "In the event of a personal data breach, Processor shall notify the Controller within 48 hours of discovery.",
    ]);
    const t = extractBreachTimings(tree);
    const first = t[0];
    expect(first).toBeDefined();
    expect(first!.max_delay_hours).toBe(48);
    expect(first!.addressee).toBe("controller");
    expect(first!.trigger).toBe("discovery");
  });

  it("captures vague phrases", () => {
    const tree = buildTree([
      "Notification",
      "Business Associate shall report any security incident to Covered Entity without unreasonable delay.",
    ]);
    const t = extractBreachTimings(tree);
    const first = t[0];
    expect(first).toBeDefined();
    expect(first!.max_delay_phrase).toBe("without unreasonable delay");
    expect(first!.max_delay_hours).toBeNull();
  });

  it("reads the numeral in the 'word (numeral)' drafting form", () => {
    // "within seventy-two (72) hours" is the dominant breach-clause form; the
    // parenthesized numeral is authoritative. It previously parsed to null.
    for (const [text, hours] of [
      [
        "Processor shall notify Controller of any personal data breach within seventy-two (72) hours of discovery.",
        72,
      ],
      [
        "Vendor shall notify Customer of a security incident within twenty-four (24) hours of confirmation.",
        24,
      ],
      [
        "Processor shall inform Controller of any personal data breach within two (2) business days.",
        48,
      ],
      [
        "Processor shall notify Controller of any personal data breach within sixty (60) days of discovery.",
        1440,
      ],
    ] as const) {
      const t = extractBreachTimings(buildTree(["Notification", text]));
      expect(
        t.some((x) => x.max_delay_hours === hours),
        `${text} -> ${JSON.stringify(t.map((x) => x.max_delay_hours))}`,
      ).toBe(true);
    }
  });

  it("matches a plural breach noun ('report Breaches')", () => {
    // A BAA states its duty in the plural; `\bbreach\b` never matched "Breaches"
    // so the whole clause was dropped.
    const t = extractBreachTimings(
      buildTree([
        "Breach Reporting",
        "Business Associate shall report Breaches to Covered Entity within sixty (60) days of discovery.",
      ]),
    );
    expect(t.some((x) => x.max_delay_hours === 1440 && x.addressee === "controller")).toBe(true);
  });

  it("classifies identify/verify/reasonable-belief triggers and US-statute addressees", () => {
    const trig = (text: string) =>
      extractBreachTimings(buildTree(["Notification", text]))[0]?.trigger;
    const addr = (text: string) =>
      extractBreachTimings(buildTree(["Notification", text]))[0]?.addressee;
    expect(
      trig(
        "Processor shall notify Controller within 48 hours of identifying a personal data breach.",
      ),
    ).toBe("discovery");
    expect(
      trig("Vendor shall notify Customer within 24 hours after verifying a security incident."),
    ).toBe("confirmation");
    expect(
      trig(
        "Vendor shall notify Customer upon a reasonable belief that a breach occurred, within 24 hours.",
      ),
    ).toBe("suspicion");
    expect(
      addr("Vendor shall notify affected individuals of a data breach without undue delay."),
    ).toBe("data-subject");
    expect(addr("Vendor shall notify the Attorney General of the breach within 30 days.")).toBe(
      "regulator",
    );
  });

  it("does not read 'personally identifiable information' as a discovery trigger", () => {
    const t = extractBreachTimings(
      buildTree([
        "Notification",
        "Vendor shall protect personally identifiable information and report any incident to Customer within 72 hours.",
      ]),
    );
    expect(t[0]?.trigger).toBe("unspecified");
  });
});

describe("v3 audit-rights extractor", () => {
  /**
   * 🚨 An audit RIGHT is an entitlement, not the word "audit".
   *
   * The trigger was `/\b(?:audit|inspect|inspection)[^.]{0,400}\./i`, so any
   * sentence containing the word produced a record: **107 of 327 specimens**,
   * and **80% of the records carried no detail at all** because there were no
   * audit terms to read. 107 → 56 documents in 9.677.0.
   */
  it("does not read the WORD audit as an audit right", () => {
    for (const sentence of [
      "The Audit Committee of the Board shall meet at least twice each year.",
      "The Architect performs periodic inspections, and does not control or have charge of construction means, methods or sequences.",
      "Lessee shall inspect each item of Equipment on delivery and sign an acceptance certificate.",
      "The Company retains independent auditors.",
    ]) {
      expect(
        extractAuditRights(buildTree(["Clause", sentence])),
        `"${sentence}" was read as granting an audit right`,
      ).toHaveLength(0);
    }
  });

  it("reads a right whose entitlement sits far from the verb", () => {
    // The notice period, the frequency cap and the scope all go between them,
    // which is exactly how a well-drafted audit clause reads. A tight window
    // loses the clauses this extractor exists for.
    const tree = buildTree([
      "Audit",
      "Business Associate may, on thirty (30) days' written notice and not more " +
        "than once in any twelve-month period, audit Subcontractor's handling of PHI.",
    ]);
    const a = extractAuditRights(tree);
    expect(a).toHaveLength(1);
    expect(a[0]!.notice_days).toBe(30);
  });

  it("reads the PLURAL noun, which is how the GDPR states it", () => {
    // Art. 28(3)(h): "allow for and contribute to audits, including
    // inspections". `\baudit\b` cannot match "audits" — the boundary falls
    // between "t" and "s", where there is none.
    const tree = buildTree([
      "Audit",
      "Processor shall allow for and contribute to audits, including inspections, " +
        "conducted by the Controller or another auditor mandated by the Controller.",
    ]);
    expect(extractAuditRights(tree)).toHaveLength(1);
  });

  it("reads the passive form, which names no entitled party", () => {
    const tree = buildTree([
      "Audit",
      "Processor shall be audited annually by an independent auditor.",
    ]);
    const a = extractAuditRights(tree);
    expect(a).toHaveLength(1);
    expect(a[0]!.frequency_per_year).toBe(1);
  });

  it("captures frequency, notice, methods", () => {
    const tree = buildTree([
      "Audit",
      "Customer may audit Processor once per year upon 30 days' prior written notice; onsite audits and SOC 2 substitution are permitted under confidentiality obligations.",
    ]);
    const a = extractAuditRights(tree);
    const first = a[0];
    expect(first).toBeDefined();
    expect(first!.frequency_per_year).toBe(1);
    expect(first!.notice_days).toBe(30);
    expect(first!.methods).toContain("onsite");
    expect(first!.methods).toContain("soc2-substitution");
    expect(first!.confidentiality_required).toBe(true);
  });

  it("reads the notice period in the 'word (numeral)' form", () => {
    const a = extractAuditRights(
      buildTree([
        "Audit",
        "Customer may audit Processor once per year upon thirty (30) days' prior written notice.",
      ]),
    );
    expect(a[0]?.notice_days).toBe(30);
  });

  it("reads annual and twelve-month audit-frequency forms as once per year", () => {
    for (const text of [
      "Customer may audit Processor once annually upon reasonable notice.",
      "Customer may audit Processor no more than once in any twelve (12) month period.",
      "Customer may audit Processor no more than once per twelve-month period.",
      "Customer may audit Processor once every twelve months.",
      "Processor shall be audited annually by an independent auditor.",
      // Adjective-before-noun "annual audit" sits before the audit-keyword
      // window; the whole-paragraph fallback still reads it, including an
      // intervening adjective ("annual independent audit").
      "Customer may conduct an annual audit of Processor.",
      "Processor shall permit an annual independent audit of its controls.",
    ]) {
      const a = extractAuditRights(buildTree(["Audit", text]));
      expect(a[0]?.frequency_per_year, text).toBe(1);
    }
    const twice = extractAuditRights(
      buildTree(["Audit", "Customer may audit Processor twice annually."]),
    );
    expect(twice[0]?.frequency_per_year).toBe(2);
  });
});

describe("v3 subprocessor extractor", () => {
  it("captures consent form, list location, notice, objection, flow-down", () => {
    const tree = buildTree([
      "Subprocessors",
      "Processor has general written authorization to engage sub-processors listed in Annex III, subject to 30 days' prior written notice; Controller may object on reasonable grounds, and Processor shall impose the same data protection obligations on sub-processors.",
    ]);
    const s = extractSubprocessorInventory(tree);
    expect(s).not.toBeNull();
    expect(s?.consent_form).toBe("general-written");
    expect(s?.list_location).toBe("annex");
    expect(s?.notice_days).toBe(30);
    expect(s?.objection_right).toBe(true);
    expect(s?.flow_down_required).toBe(true);
  });

  it("returns null when no subprocessor language appears", () => {
    const tree = buildTree(["Body", "Effective Date: 2026-01-01."]);
    expect(extractSubprocessorInventory(tree)).toBeNull();
  });

  it("reads the notice period in the 'word (numeral)' form", () => {
    const s = extractSubprocessorInventory(
      buildTree([
        "Subprocessors",
        "Processor may engage sub-processors listed in Annex III, subject to thirty (30) days' prior written notice; Controller may object on reasonable grounds.",
      ]),
    );
    expect(s?.notice_days).toBe(30);
  });

  it("reads a singular-verb prohibition ('No sub-processor is permitted') as not permitted", () => {
    const isForm = extractSubprocessorInventory(
      buildTree(["Subprocessors", "No sub-processor is permitted to process Personal Data."]),
    );
    expect(isForm?.permitted).toBe(false);
    const areForm = extractSubprocessorInventory(
      buildTree(["Subprocessors", "No sub-processors are permitted without approval."]),
    );
    expect(areForm?.permitted).toBe(false);
    const shallForm = extractSubprocessorInventory(
      buildTree(["Subprocessors", "No sub-processor shall be permitted absent consent."]),
    );
    expect(shallForm?.permitted).toBe(false);
    // A permissive clause still reads permitted=true.
    const yes = extractSubprocessorInventory(
      buildTree([
        "Subprocessors",
        "Processor may engage sub-processors with general written authorization.",
      ]),
    );
    expect(yes?.permitted).toBe(true);
  });
});

describe("v3 insurance extractor", () => {
  it("captures lines, amounts, endorsements, AM Best, notice", () => {
    const tree = buildTree([
      "Insurance",
      "Vendor shall maintain commercial general liability insurance of $2,000,000 per occurrence and $4,000,000 aggregate, professional liability of $5,000,000, and cyber liability of $5,000,000. Each policy shall be written with an A.M. Best rating of A-VII or better. Required endorsements: CG 20 10 and CG 20 37. Vendor shall provide 30 days' prior written notice of cancellation.",
    ]);
    const sched = extractInsuranceSchedule(tree);
    const lines = new Set(sched.amounts.map((a) => a.line));
    expect(lines.has("commercial-general-liability")).toBe(true);
    expect(lines.has("professional-liability")).toBe(true);
    expect(lines.has("cyber-liability")).toBe(true);
    const cgl = sched.amounts.find(
      (a) => a.line === "commercial-general-liability" && a.per_occurrence_usd === 2_000_000,
    );
    expect(cgl).toBeDefined();
    const forms = sched.endorsements.map((e) => e.form_number);
    expect(forms).toContain("CG 20 10");
    expect(forms).toContain("CG 20 37");
    expect(sched.required_am_best_rating).toBe("A-VII");
    expect(sched.notice_of_cancellation_days).toBe(30);
  });

  it("reads the notice period in the 'word (numeral)' drafting form", () => {
    // "thirty (30) days' notice of cancellation" previously parsed to null.
    for (const [text, days] of [
      ["Insurer shall provide thirty (30) days' prior written notice of cancellation.", 30],
      ["Insurer shall give ten (10) days notice of cancellation for non-payment.", 10],
      ["Sixty (60) days' notice of non-renewal is required.", 60],
    ] as const) {
      const sched = extractInsuranceSchedule(buildTree(["Insurance", text]));
      expect(sched.notice_of_cancellation_days, text).toBe(days);
    }
  });

  it("reads limits stated with a currency code instead of a leading '$'", () => {
    for (const text of [
      "Vendor shall carry commercial general liability insurance of 1,000,000 USD per occurrence.",
      "Vendor shall carry commercial general liability insurance of USD 1,000,000 per occurrence.",
      "Vendor shall carry commercial general liability insurance of 1,000,000 dollars per occurrence.",
    ]) {
      const sched = extractInsuranceSchedule(buildTree(["Insurance", text]));
      const cgl = sched.amounts.find(
        (a) => a.line === "commercial-general-liability" && a.per_occurrence_usd === 1_000_000,
      );
      expect(cgl, text).toBeDefined();
    }
  });

  it("captures per-claim and each-accident limit qualifiers", () => {
    const sched = extractInsuranceSchedule(
      buildTree([
        "Insurance",
        "Consultant shall maintain professional liability (errors and omissions) insurance of $5,000,000 per claim.",
        "Consultant shall maintain employers' liability insurance of $1,000,000 each accident.",
      ]),
    );
    const eo = sched.amounts.find((a) => a.line === "professional-liability");
    expect(eo?.per_occurrence_usd).toBe(5_000_000);
    expect(eo?.raw_text).toContain("per claim");
    const el = sched.amounts.find((a) => a.line === "employers-liability");
    expect(el?.per_occurrence_usd).toBe(1_000_000);
    expect(el?.raw_text).toContain("each accident");
  });

  it("captures the A.M. Best minus grade and a space-separated size category", () => {
    // A- is a materially lower grade than A; the old pattern read only '+' and a
    // single delimiter, so "A- VII" (minus, then a space before the numeral)
    // collapsed to "A".
    const minusSpace = extractInsuranceSchedule(
      buildTree(["Insurance", "Insurers shall carry an A.M. Best rating of A- VII or better."]),
    );
    expect(minusSpace.required_am_best_rating).toBe("A- VII");
    const bareMinus = extractInsuranceSchedule(
      buildTree(["Insurance", "Each insurer shall have an A.M. Best rating of A- or higher."]),
    );
    expect(bareMinus.required_am_best_rating).toBe("A-");
    // The contiguous form still round-trips unchanged.
    const contiguous = extractInsuranceSchedule(
      buildTree(["Insurance", "Policies written by an A.M. Best A-VII rated carrier."]),
    );
    expect(contiguous.required_am_best_rating).toBe("A-VII");
  });

  it("detects Directors & Officers and Crime/Fidelity lines", () => {
    const expect_line = (text: string, line: string) => {
      const lines = extractInsuranceSchedule(buildTree(["Insurance", text])).amounts.map(
        (a) => a.line,
      );
      expect(lines, text).toContain(line);
    };
    expect_line(
      "Directors and Officers liability insurance of $5,000,000 per claim.",
      "directors-officers-liability",
    );
    expect_line("D&O insurance with a limit of $5,000,000.", "directors-officers-liability");
    expect_line("Crime insurance of $1,000,000 per occurrence.", "crime-fidelity");
    expect_line("Fidelity bond in the amount of $1,000,000.", "crime-fidelity");
    expect_line("Employee dishonesty coverage of $500,000.", "crime-fidelity");
  });

  it("does not read a governance 'directors and officers' clause as a D&O line", () => {
    const sched = extractInsuranceSchedule(
      buildTree([
        "Indemnification",
        "The directors and officers of the Company shall be indemnified up to $5,000,000 for claims arising from their service.",
      ]),
    );
    expect(sched.amounts.some((a) => a.line === "directors-officers-liability")).toBe(false);
  });

  it("does not treat a bare number without a currency marker as a limit", () => {
    const sched = extractInsuranceSchedule(
      buildTree([
        "Insurance",
        "Under Section 25, the Contractor shall maintain Commercial General Liability insurance for a period of 3 years covering 2 locations.",
      ]),
    );
    expect(sched.amounts).toHaveLength(0);
  });
});

describe("v3 DTSA notice extractor", () => {
  it("detects substantively-complete notice", () => {
    const tree = buildTree([
      "DTSA",
      "Notice pursuant to the Defend Trade Secrets Act: An individual shall not be held criminally or civilly liable under any federal or state trade secret law for the disclosure of a trade secret that is made in confidence to a federal, state, or local government official or to an attorney solely for the purpose of reporting a suspected violation of law, or that is filed under seal in a lawsuit or other proceeding. This notice extends to employees, contractors, and consultants.",
    ]);
    const d = extractDtsaNotice(tree);
    expect(d.present).toBe(true);
    expect(d.covers_government_disclosure).toBe(true);
    expect(d.covers_under_seal).toBe(true);
    expect(d.covers_contractors).toBe(true);
    expect(d.substantively_complete).toBe(true);
  });

  it("detects incomplete notice", () => {
    const tree = buildTree([
      "DTSA",
      "Notice under 18 U.S.C. § 1833: employees may disclose trade secrets in some circumstances.",
    ]);
    const d = extractDtsaNotice(tree);
    expect(d.present).toBe(true);
    expect(d.substantively_complete).toBe(false);
  });

  it("reads a notice whose elements span the following paragraph", () => {
    // The immunity elements commonly sit in a separate "elements" paragraph;
    // the extractor previously looked only at the paragraph where DTSA matched.
    const tree = buildTree([
      "Immunity Notice",
      "This Agreement provides notice under the Defend Trade Secrets Act (DTSA) regarding immunity for the disclosure of a trade secret.",
      "Such immunity applies where the disclosure is made in confidence to a federal government official or to an attorney solely for the purpose of reporting a suspected violation of law, and where any disclosure made under seal in a lawsuit is protected. This notice applies to the Company's employees, contractors, and consultants.",
    ]);
    const d = extractDtsaNotice(tree);
    expect(d.present).toBe(true);
    expect(d.covers_government_disclosure).toBe(true);
    expect(d.covers_under_seal).toBe(true);
    expect(d.covers_contractors).toBe(true);
    expect(d.substantively_complete).toBe(true);
  });

  it("returns absent when no notice present", () => {
    const tree = buildTree(["Body", "Effective Date: 2026-01-01."]);
    const d = extractDtsaNotice(tree);
    expect(d.present).toBe(false);
    expect(d.substantively_complete).toBe(false);
  });
});

describe("v3 aggregate extractAllV3", () => {
  it("produces a fully-populated V3ExtractedData and is deterministic", () => {
    const tree = buildTree([
      "Body",
      `"Processor" means the entity that processes Personal Data on behalf of the Controller. Module 2 of the Standard Contractual Clauses is incorporated. Encryption at rest is required. Notify Controller within 72 hours of any personal data breach upon discovery. Customer may audit Processor once per year upon 30 days' prior written notice.`,
    ]);
    const a = extractAllV3(tree);
    expect(a.roles.length).toBeGreaterThan(0);
    expect(a.transfer_mechanisms.length).toBeGreaterThan(0);
    expect(a.security_measures.length).toBeGreaterThan(0);
    expect(a.breach_timings.length).toBeGreaterThan(0);
    expect(a.audit_rights.length).toBeGreaterThan(0);
    expect(a.dtsa_notice.present).toBe(false);
    expect(JSON.stringify(a)).toEqual(JSON.stringify(extractAllV3(tree)));
  });
});
