import { describe, expect, it } from "vitest";

import { MSA_DEEP_RULES } from "./rules.js";
import { buildContext } from "../../../_test-fixtures.js";
import { runEngine } from "../../../runner.js";
import type { Playbook, RuleContext } from "../../../finding.js";

const VENDOR: Playbook = { id: "msa-vendor-deep", version: "1.0.0" };
const CUSTOMER: Playbook = { id: "msa-customer-deep", version: "1.0.0" };
const SRC = { name: "msa.docx", sha256: "0".repeat(64), size_bytes: 1 };

const withPb = (ctx: RuleContext, p: Playbook): RuleContext => ({ ...ctx, playbook: p });

// Compliant MSA fixture covering every rule's present_patterns so a
// well-drafted MSA produces zero critical findings.
const COMPLIANT_MSA: [string, ...string[]][] = [
  [
    "Master Services Agreement",
    "This Agreement is entered into between Customer and Vendor effective January 1, 2026.",
  ],
  [
    "Indemnification",
    "Vendor shall indemnify Customer against any third-party intellectual property infringement claim arising from the Services, including IP claims. Vendor shall promptly notify Customer, control the defense with reputable counsel, and obtain Customer consent to any settlement that includes non-monetary terms. Vendor shall further indemnify Customer for breach of confidentiality obligations and for damages arising from gross negligence, wilful misconduct, or breach of data protection obligations.",
  ],
  [
    "Limitation of Liability",
    "The aggregate liability of either party under this Agreement shall not exceed twelve months of fees paid. The cap shall not apply to (a) fraud, (b) wilful misconduct, (c) IP indemnification, (d) breach of confidentiality, or (e) breach of data protection — these are carved out and supercap structure applies. Neither party shall be liable to the other for any indirect, incidental, special, consequential, or punitive damages, including lost profits.",
  ],
  [
    "Intellectual Property",
    "Each party retains its background IP and pre-existing IP. Foreground IP developed hereunder for Customer Deliverables vests in Customer; vendor tooling remains Vendor's. Customer feedback license is limited to product improvement.",
  ],
  [
    "Warranties",
    "Vendor warrants the Services will be performed in a workmanlike, professional manner, will conform to the documentation, and will be free of malicious code, virus, worm, or trojan. Vendor further warrants compliance with applicable laws and that the Services do not infringe third-party IP. VENDOR DISCLAIMS ALL OTHER IMPLIED WARRANTIES, INCLUDING THE IMPLIED WARRANTY OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.",
  ],
  [
    "Service Levels",
    "A Service Level Agreement (SLA) with 99.9% uptime is attached as Schedule A; service-level credits are available without being the sole remedy.",
  ],
  [
    "Term and Termination",
    "Either party may terminate this Agreement for material breach on 30 days' written notice if the breaching party fails to cure. Either party may terminate on bankruptcy, insolvency, appointment of receiver, or assignment for the benefit of creditors. Upon termination, Vendor will provide up to 90 days of wind-down and transition assistance.",
  ],
  [
    "Data Return",
    "Upon termination, Vendor shall return all customer data in a machine-readable format and then delete its copies within 30 days, and shall support data portability.",
  ],
  [
    "Force Majeure",
    "Neither party shall be liable for delay or failure due to force majeure beyond its reasonable control; payment obligations are not excused.",
  ],
  [
    "Assignment",
    "Neither party may assign this Agreement without consent, except a change of control or merger shall be deemed an assignment requiring consent; affiliate assignment is permitted.",
  ],
  [
    "Governing Law and Venue",
    "This Agreement is governed by the laws of the State of New York. The exclusive venue and jurisdiction is the state and federal courts in New York.",
  ],
  [
    "Boilerplate",
    "No amendment is effective unless in writing signed by both parties. No failure to enforce shall be deemed a waiver. The obligations of confidentiality, indemnity, and IP shall survive termination. This Agreement is the entire agreement and supersedes all prior negotiations.",
  ],
  [
    "Order of Precedence",
    "In the event of any conflict between this Agreement and a Statement of Work, the SOW controls only as to scope, schedule, and fees; this Agreement controls in all other respects.",
  ],
  [
    "AI Usage",
    "Vendor does not use generative AI or large language model technology in providing the Services. If Vendor adopts AI, notice will be provided.",
  ],
  [
    "Remedies",
    "If any limited remedy is found to fail of its essential purpose under U.C.C. § 2-719, the customer's other remedies under this Agreement and applicable law remain available.",
  ],
];

describe("MSA-deep ruleset — registry contract", () => {
  it("exports exactly 30 rules with stable MSA-NNN ids", () => {
    expect(MSA_DEEP_RULES.length).toBe(30);
    const ids = MSA_DEEP_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(30);
    for (const r of MSA_DEEP_RULES) {
      expect(r.id).toMatch(/^MSA-\d{3}$/);
      expect(r.category).toBe("msa-deep");
      expect(r.applies_to_playbooks).toEqual(
        expect.arrayContaining(["msa-vendor-deep", "msa-customer-deep"]),
      );
    }
  });

  it("does not run when no MSA-deep playbook is active", async () => {
    const ctx = buildContext(["Agreement", "Generic services agreement, no MSA playbook active."]);
    const run = await runEngine({
      rules: MSA_DEEP_RULES,
      ctx,
      executed_at: "2026-05-13T00:00:00Z",
      source_file: SRC,
    });
    expect(run.findings).toHaveLength(0);
  });
});

describe("MSA-deep ruleset — compliant MSA fixture", () => {
  it("zero critical findings under msa-vendor-deep", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_MSA), VENDOR);
    const run = await runEngine({
      rules: MSA_DEEP_RULES,
      ctx,
      executed_at: "2026-05-13T00:00:00Z",
      source_file: SRC,
    });
    const criticals = run.findings.filter((f) => f.severity === "critical");
    expect(criticals).toHaveLength(0);
  });

  it("zero critical findings under msa-customer-deep", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_MSA), CUSTOMER);
    const run = await runEngine({
      rules: MSA_DEEP_RULES,
      ctx,
      executed_at: "2026-05-13T00:00:00Z",
      source_file: SRC,
    });
    const criticals = run.findings.filter((f) => f.severity === "critical");
    expect(criticals).toHaveLength(0);
  });
});

describe("MSA-deep ruleset — failure modes", () => {
  it("missing aggregate cap fires MSA-006", async () => {
    const ctx = withPb(
      buildContext([
        "MSA",
        "Vendor will provide the Services. Vendor shall indemnify Customer for IP claims. Vendor warrants workmanlike services conforming to the documentation, free of malicious code; complies with laws and non-infringement. Statement of Work attached. Service Level Agreement attached. Material breach termination on 30 days notice. Return all customer data. Force majeure neither party. Neither party may assign except change of control. Governed by New York law, venue New York. Amendment in writing, no waiver. Survive termination. Entire agreement. Order of Precedence: this Agreement controls. Generative AI: none. Essential purpose preserved.",
      ]),
      VENDOR,
    );
    const run = await runEngine({
      rules: MSA_DEEP_RULES,
      ctx,
      executed_at: "2026-05-13T00:00:00Z",
      source_file: SRC,
    });
    expect(run.findings.find((f) => f.rule_id === "MSA-006")).toBeTruthy();
  });

  it("California § 1668 problem fires MSA-009", async () => {
    const ctx = withPb(
      buildContext([
        "Liability",
        "The limitation of liability includes fraud and wilful misconduct. Governed by the laws of California.",
      ]),
      VENDOR,
    );
    const run = await runEngine({
      rules: MSA_DEEP_RULES,
      ctx,
      executed_at: "2026-05-13T00:00:00Z",
      source_file: SRC,
    });
    expect(run.findings.find((f) => f.rule_id === "MSA-009")).toBeTruthy();
  });

  it("indemnity-outside-cap fires MSA-005", async () => {
    const ctx = withPb(
      buildContext([
        "Cap",
        "The aggregate liability cap shall not apply to indemnification obligations under this Agreement.",
      ]),
      CUSTOMER,
    );
    const run = await runEngine({
      rules: MSA_DEEP_RULES,
      ctx,
      executed_at: "2026-05-13T00:00:00Z",
      source_file: SRC,
    });
    expect(run.findings.find((f) => f.rule_id === "MSA-005")).toBeTruthy();
  });

  it("SLA-credit-as-sole-and-exclusive remedy fires MSA-017", async () => {
    const ctx = withPb(
      buildContext([
        "SLA",
        "The service credit is the sole and exclusive remedy for any downtime under the Service Level Agreement.",
      ]),
      CUSTOMER,
    );
    const run = await runEngine({
      rules: MSA_DEEP_RULES,
      ctx,
      executed_at: "2026-05-13T00:00:00Z",
      source_file: SRC,
    });
    expect(run.findings.find((f) => f.rule_id === "MSA-017")).toBeTruthy();
  });

  // v1.1.0 — the customer-favorable inverse (service credits are NOT the sole
  // and exclusive remedy) preserves other remedies and must not be flagged.
  it("does not fire MSA-017 when credits are NOT the sole and exclusive remedy", async () => {
    const ctx = withPb(
      buildContext([
        "SLA",
        "Service credits are not the sole and exclusive remedy for downtime; Customer may also terminate for chronic failure.",
      ]),
      CUSTOMER,
    );
    const run = await runEngine({
      rules: MSA_DEEP_RULES,
      ctx,
      executed_at: "2026-05-13T00:00:00Z",
      source_file: SRC,
    });
    expect(run.findings.find((f) => f.rule_id === "MSA-017")).toBeFalsy();
  });

  it("still fires MSA-017 when an unrelated 'not' shares the sentence", async () => {
    const ctx = withPb(
      buildContext([
        "SLA",
        "Service credits, but not cash refunds, are the sole and exclusive remedy for downtime.",
      ]),
      CUSTOMER,
    );
    const run = await runEngine({
      rules: MSA_DEEP_RULES,
      ctx,
      executed_at: "2026-05-13T00:00:00Z",
      source_file: SRC,
    });
    expect(run.findings.find((f) => f.rule_id === "MSA-017")).toBeTruthy();
  });

  it("order-of-precedence inconsistency fires MSA-027", async () => {
    const ctx = withPb(
      buildContext([
        "MSA",
        "In the event of conflict, this Agreement shall control over any Statement of Work. The indemnification and limitation of liability for the Services are set out in the SOW attached hereto.",
      ]),
      VENDOR,
    );
    const run = await runEngine({
      rules: MSA_DEEP_RULES,
      ctx,
      executed_at: "2026-05-13T00:00:00Z",
      source_file: SRC,
    });
    expect(run.findings.find((f) => f.rule_id === "MSA-027")).toBeTruthy();
  });
});

describe("MSA-deep ruleset — determinism", () => {
  it("two runs over the same input produce the same result_hash", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_MSA), VENDOR);
    const a = await runEngine({
      rules: MSA_DEEP_RULES,
      ctx,
      executed_at: "2026-05-13T00:00:00Z",
      source_file: SRC,
    });
    const b = await runEngine({
      rules: MSA_DEEP_RULES,
      ctx,
      executed_at: "2026-05-13T00:00:00Z",
      source_file: SRC,
    });
    expect(a.result_hash).toBe(b.result_hash);
  });
});

describe("MSA-010 / MSA-029 — broad-form indemnity in its real wording (v1.1.0)", () => {
  const run1 = async (body: string, pb: Playbook) => {
    const ctx: RuleContext = { ...buildContext(["Indemnity", body]), playbook: pb };
    const run = await runEngine({ rules: MSA_DEEP_RULES, ctx, source_file: SRC });
    return new Set(run.findings.map((f) => f.rule_id));
  };

  it("MSA-010 fires on a NY 'in whole or in part' indemnity naming the party", async () => {
    expect(
      (
        await run1(
          "Governed by New York law. Vendor shall indemnify Customer for all claims caused in whole or in part by the negligence of Customer.",
          VENDOR,
        )
      ).has("MSA-010"),
    ).toBe(true);
  });

  it("MSA-010 is silent on a NY limited indemnity and on a non-NY document", async () => {
    expect(
      (
        await run1(
          "Governed by New York law. Vendor shall indemnify Customer only to the extent of Vendor's own negligence.",
          VENDOR,
        )
      ).has("MSA-010"),
    ).toBe(false);
    expect(
      (
        await run1(
          "Governed by California law. Vendor shall indemnify Customer in whole or in part.",
          VENDOR,
        )
      ).has("MSA-010"),
    ).toBe(false);
  });

  it("MSA-029 fires on a Texas 'in whole or in part' indemnity", async () => {
    expect(
      (
        await run1(
          "Governed by the laws of Texas. Contractor shall indemnify Owner from liability arising in whole or in part from Owner's own negligence.",
          VENDOR,
        )
      ).has("MSA-029"),
    ).toBe(true);
  });
});

describe("MSA-009 — Cal. § 1668 fraud-exemption in its real wording (v1.1.0)", () => {
  const run1 = async (body: string) => {
    const ctx: RuleContext = { ...buildContext(["Liability", body]), playbook: VENDOR };
    const run = await runEngine({ rules: MSA_DEEP_RULES, ctx, source_file: SRC });
    return new Set(run.findings.map((f) => f.rule_id));
  };

  it("fires on 'exempts itself from liability for fraud' and 'disclaims all liability for fraud'", async () => {
    expect(
      (await run1("Vendor exempts itself from liability for its own fraud.")).has("MSA-009"),
    ).toBe(true);
    expect(
      (await run1("Provider disclaims all liability for fraud and willful misconduct.")).has(
        "MSA-009",
      ),
    ).toBe(true);
  });

  it("stays silent on a compliant carve-out that preserves fraud liability", async () => {
    expect(
      (
        await run1("The limitation of liability does not apply to fraud or willful misconduct.")
      ).has("MSA-009"),
    ).toBe(false);
    expect(
      (await run1("Nothing in this Agreement limits liability for fraud.")).has("MSA-009"),
    ).toBe(false);
  });
});

describe("MSA-005 — indemnity-cap carve-out recognizes 'does not apply' / 'shall not limit' (v1.1.0)", () => {
  const fires = async (b: string) =>
    (
      await runEngine({
        rules: MSA_DEEP_RULES,
        ctx: withPb(buildContext(["MSA", b]), VENDOR),
        source_file: SRC,
      })
    ).findings.some((f) => f.rule_id === "MSA-005");

  it.each([
    "The limitation of liability shall not apply to the indemnification obligations.",
    "The foregoing cap does not apply to a party's indemnification obligations.",
    "The liability cap shall not limit either party's indemnity obligations under Section 9.",
  ])("fires on an indemnity carve-out from the cap: %s", async (b) => {
    expect(await fires(b)).toBe(true);
  });

  it.each([
    "The liability cap applies to all claims including indemnification.",
    "The cap shall not limit the parties' payment obligations.",
  ])("stays silent when indemnity is inside the cap / no indemnity: %s", async (b) => {
    expect(await fires(b)).toBe(false);
  });
});

describe("MSA-012 — unbounded feedback license recognizes 'use Feedback for any purpose' (v1.1.0)", () => {
  const fires = async (b: string) =>
    (
      await runEngine({
        rules: MSA_DEEP_RULES,
        ctx: withPb(buildContext(["MSA", b]), VENDOR),
        source_file: SRC,
      })
    ).findings.some((f) => f.rule_id === "MSA-012");

  it.each([
    "Customer grants Vendor a perpetual, irrevocable, royalty-free license to use Feedback for any purpose.",
    "Vendor may use any Feedback for any purpose without restriction.",
    "Customer hereby assigns all right, title and interest in Feedback to Vendor.",
  ])("fires on an unbounded feedback grant: %s", async (b) => {
    expect(await fires(b)).toBe(true);
  });

  it("stays silent on a purpose-limited feedback grant", async () => {
    expect(
      await fires(
        "Vendor may use Feedback solely for the limited purpose of improving the Services, and for no other purpose.",
      ),
    ).toBe(false);
  });
});

describe("MSA-015 — UCC disclaimer overreach recognizes hyphenated 'AS-IS' & 'all implied warranties' (v1.1.0)", () => {
  const fires = async (b: string) =>
    (
      await runEngine({
        rules: MSA_DEEP_RULES,
        ctx: withPb(buildContext(["MSA", b]), VENDOR),
        source_file: SRC,
      })
    ).findings.some((f) => f.rule_id === "MSA-015");

  it.each([
    "The Services are provided AS IS, without any warranty of any kind.",
    "Vendor disclaims all warranties, express or implied.",
    "Vendor disclaims all implied warranties, express or statutory.",
    "The Product is provided AS-IS, without any warranties whatsoever.",
  ])("fires on a merchantability-silent disclaimer: %s", async (b) => {
    expect(await fires(b)).toBe(true);
  });

  it.each([
    "VENDOR DISCLAIMS ALL IMPLIED WARRANTIES, INCLUDING MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.",
    "Vendor disclaims all warranties other than the implied warranty of merchantability.",
    "Vendor warrants the Services will conform to the documentation.",
  ])("stays silent when merchantability is named or no disclaimer is present: %s", async (b) => {
    expect(await fires(b)).toBe(false);
  });
});
