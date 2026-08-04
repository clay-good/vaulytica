import { describe, expect, it } from "vitest";

import { COMMERCIAL_V4_RULES } from "./rules.js";
import { COMM_PLAYBOOK_IDS } from "./_helpers.js";
import { buildContext } from "../../../_test-fixtures.js";
import { runEngine } from "../../../runner.js";
import type { Playbook, Rule, RuleContext } from "../../../finding.js";

const MFG: Playbook = { id: "manufacturing-supply-agreement", version: "1.0.0" };
const SRC = { name: "test.docx", sha256: "0".repeat(64), size_bytes: 100 };

const withPb = (ctx: RuleContext, pb: Playbook): RuleContext => ({ ...ctx, playbook: pb });
const fired = async (pb: Playbook, body: string) => {
  const run = await runEngine({
    rules: COMMERCIAL_V4_RULES as Rule[],
    ctx: withPb(buildContext(["Supply Agreement", body]), pb),
    source_file: SRC,
  });
  return new Set(run.findings.map((f) => f.rule_id));
};

describe("v4 Commercial ruleset — registry contract", () => {
  it("exports COMM-NNN rules scoped to a commercial playbook", () => {
    expect(COMMERCIAL_V4_RULES.length).toBeGreaterThanOrEqual(7);
    const allowed = new Set<string>(COMM_PLAYBOOK_IDS);
    for (const r of COMMERCIAL_V4_RULES) {
      expect(r.id, r.id).toMatch(/^COMM-\d{3}$/);
      expect(r.version, r.id).toMatch(/^\d+\.\d+\.\d+$/);
      expect(r.category, r.id).toBe("commercial");
      for (const pb of r.applies_to_playbooks ?? []) {
        expect(allowed.has(pb), `${r.id} → ${pb}`).toBe(true);
      }
    }
    expect(new Set(COMMERCIAL_V4_RULES.map((r) => r.id)).size).toBe(COMMERCIAL_V4_RULES.length);
  });

  it("does not fire under a non-commercial playbook", async () => {
    const run = await runEngine({
      rules: COMMERCIAL_V4_RULES as Rule[],
      ctx: buildContext(["Some other doc", "This is not a supply agreement."]),
      source_file: SRC,
    });
    expect(run.findings.length).toBe(0);
    expect(run.execution_log.every((e) => !e.fired)).toBe(true);
  });
});

describe("v4 Commercial — manufacturing / supply agreement (A.10)", () => {
  const COMPLETE =
    "Quantity. Buyer shall purchase its requirements of the Goods from Seller. " +
    "Delivery. Seller shall deliver within 30 days FOB origin per the delivery schedule. " +
    "Specifications. The Goods shall conform to the Specifications and Seller warrants that the Goods will be free from defects. " +
    "Price. The unit price is set on a cost-plus basis with annual price adjustment. " +
    "Inspection. Buyer may inspect and reject nonconforming goods within 10 days. " +
    "Force Majeure. Neither party is liable for delays beyond its reasonable control. " +
    "Warranty of Title. Seller conveys good title free and clear of all liens and warrants that the Goods do not infringe any third-party patent, with an infringement indemnity. " +
    "Remedies. Repair or replacement, or a refund, is Buyer's sole and exclusive remedy, provided that if that remedy fails of its essential purpose the full UCC remedies apply. " +
    "Best Efforts. Seller shall use commercially reasonable efforts to supply Buyer's requirements.";

  it("emits no findings against a complete supply agreement", async () => {
    expect((await fired(MFG, COMPLETE)).size).toBe(0);
  });

  it("flags every required clause on a bare agreement (COMM-007 gated by exclusivity)", async () => {
    const bare = await fired(MFG, "Seller shall sell certain goods to Buyer from time to time.");
    // Non-exclusive bare doc: the six unconditional clauses fire; COMM-007 is
    // inapplicable (no requirements / output / exclusive arrangement).
    for (const id of ["COMM-001", "COMM-002", "COMM-003", "COMM-004", "COMM-005", "COMM-006"]) {
      expect(bare.has(id), id).toBe(true);
    }
    expect(bare.has("COMM-007")).toBe(false);
  });

  it("COMM-007 fires when the arrangement is exclusive but omits a best-efforts obligation", async () => {
    const excl = await fired(
      MFG,
      "Buyer shall purchase its requirements of the Goods exclusively from Seller. " +
        "Delivery within 30 days FOB origin. The Goods shall conform to the Specifications and are warranted free from defects. " +
        "Unit price per the price schedule. Buyer may inspect and reject nonconforming goods. " +
        "Neither party is liable for events beyond its reasonable control.",
    );
    expect(excl.has("COMM-007")).toBe(true);
  });

  it("COMM-024/025 fire when title/infringement warranty and remedy limits are absent", async () => {
    const bare = await fired(
      MFG,
      "Seller shall sell the Goods to Buyer at the price in Exhibit A.",
    );
    expect(bare.has("COMM-024")).toBe(true);
    expect(bare.has("COMM-025")).toBe(true);
  });
});

describe("v4 Commercial — reseller / distribution agreement (A.8)", () => {
  const DIST: Playbook = { id: "distribution-agreement", version: "1.0.0" };
  const COMPLETE =
    "Appointment. Supplier appoints Distributor as its exclusive distributor of the Products in the Territory. " +
    "Minimum Purchases. Distributor shall purchase an annual minimum of 10,000 units. " +
    "Resale Prices. Distributor is free to determine its own resale prices; any pricing control is limited to a minimum advertised price (MAP) policy. " +
    "Term and Termination. This Agreement may be terminated for cause upon 60 days prior written notice and a 30-day cure period. " +
    "Trademark License. Supplier grants Distributor a limited license to use the Trademarks subject to Supplier's quality control and right to inspect. " +
    "Competing Products. During the Term, Distributor shall not carry, sell, or promote any competing products in the Territory. " +
    "Product Liability. Supplier shall indemnify Distributor against any product-liability claim arising from a defect in the Products, and the parties shall cooperate on any recall, which Supplier shall conduct and fund. " +
    "Post-Termination. Supplier shall repurchase unsold inventory and Distributor shall cease using the marks and return all branded materials.";

  it("emits no findings against a complete distribution agreement", async () => {
    expect((await fired(DIST, COMPLETE)).size).toBe(0);
  });

  it("flags the missing unconditional clauses on a bare appointment", async () => {
    const bare = await fired(
      DIST,
      "Supplier appoints Distributor as reseller of the Products in the Territory.",
    );
    // Appointment/territory present (COMM-008 silent); pricing & trademark are
    // gated and inapplicable here; the min-purchase, term, and post-termination
    // clauses are genuinely absent.
    expect(bare.has("COMM-008")).toBe(false);
    for (const id of ["COMM-009", "COMM-011", "COMM-013"]) {
      expect(bare.has(id), id).toBe(true);
    }
    expect(bare.has("COMM-010")).toBe(false);
    expect(bare.has("COMM-012")).toBe(false);
  });

  it("COMM-010 fires when the agreement fixes a minimum resale price without a freedom / MAP statement", async () => {
    const rpm = await fired(
      DIST,
      "Distributor shall not sell below the minimum resale price of $50 set by Supplier.",
    );
    expect(rpm.has("COMM-010")).toBe(true);
  });

  it("COMM-012 fires when the agreement uses the marks but omits quality control", async () => {
    const marks = await fired(
      DIST,
      "Distributor may use the Supplier's trademarks and brand in marketing the Products in the Territory.",
    );
    expect(marks.has("COMM-012")).toBe(true);
  });

  it("COMM-026 fires only on an exclusive deal that is silent on competing products", async () => {
    const excl = await fired(
      DIST,
      "Supplier appoints Distributor as the exclusive distributor of the Products in the Territory. Minimum purchases apply.",
    );
    expect(excl.has("COMM-026")).toBe(true);
    const nonExcl = await fired(
      DIST,
      "Supplier appoints Distributor as a non-exclusive reseller of the Products in the Territory.",
    );
    expect(nonExcl.has("COMM-026")).toBe(false);
  });

  it("COMM-027 fires when product-liability / recall allocation is absent", async () => {
    const bare = await fired(
      DIST,
      "Supplier appoints Distributor as reseller of the Products in the Territory.",
    );
    expect(bare.has("COMM-027")).toBe(true);
  });
});

describe("v4 Commercial — channel partner / referral agreement (A.9)", () => {
  const REF: Playbook = { id: "channel-referral-agreement", version: "1.0.0" };
  const COMPLETE =
    "Qualified Referral means a prospect the Partner introduces who executes an order. " +
    "Referral Fee. Company shall pay a referral fee of 10% of the contract value, payable within 30 days after collection. " +
    "Independent Contractor. Partner is not an agent or employee and has no authority to bind the Company. " +
    "Confidentiality. Each party shall keep confidential the referred leads and the other party's customer lists and proprietary information, using them only for the referral relationship. " +
    "Non-Circumvention. Neither party shall circumvent the other or deal directly with a relationship introduced under this Agreement to avoid the Referral Fee for two years. " +
    "Survival of Fees. Referral fees remain payable and shall survive termination for any referral introduced before termination that converts within a six-month tail period. " +
    "Representations. Partner shall use only Company-approved materials and shall make no representations, warranties, or guarantees about the Company or its products beyond those materials. " +
    "Anti-Bribery. Partner shall comply with the FCPA and applicable anti-corruption laws and make no improper payments.";

  it("emits no findings against a complete commercial referral agreement", async () => {
    expect((await fired(REF, COMPLETE)).size).toBe(0);
  });

  it("COMM-016 fires on a settlement-service referral with no RESPA compliance clause", async () => {
    const respa = await fired(
      REF,
      "Partner refers mortgage and title insurance settlement services and receives a referral fee of $500 per closing. Independent contractor with no authority to bind. Anti-bribery: Partner complies with the FCPA.",
    );
    expect(respa.has("COMM-016")).toBe(true);
  });

  it("COMM-016 is inapplicable to an ordinary commercial referral (no settlement services)", async () => {
    const commercial = await fired(
      REF,
      "Qualified Referral means an introduced customer who executes an order. Referral fee of 10% payable within 30 days after collection. Partner is an independent contractor with no authority to bind. Partner complies with the FCPA and makes no improper payments.",
    );
    expect(commercial.has("COMM-016")).toBe(false);
  });

  it("COMM-028/029 fire when lead confidentiality and non-circumvention are absent", async () => {
    const bare = await fired(
      REF,
      "Partner earns a referral fee for each qualified referral introduced to Company.",
    );
    expect(bare.has("COMM-028")).toBe(true);
    expect(bare.has("COMM-029")).toBe(true);
  });

  it("COMM-032/033 fire when the tail and representation-restriction clauses are absent", async () => {
    const bare = await fired(
      REF,
      "Partner earns a referral fee for each qualified referral introduced to Company.",
    );
    expect(bare.has("COMM-032")).toBe(true);
    expect(bare.has("COMM-033")).toBe(true);
  });

  it("COMM-034 fires only when the Partner conducts outreach without an anti-spam clause", async () => {
    const outreach = await fired(
      REF,
      "Partner will make cold calls and send an email blast to solicit referrals for Company.",
    );
    expect(outreach.has("COMM-034")).toBe(true);
    const passive = await fired(
      REF,
      "Partner earns a referral fee for each qualified referral it introduces by word of mouth.",
    );
    expect(passive.has("COMM-034")).toBe(false);
  });
});

describe("v4 Commercial — marketing services agreement (A.11)", () => {
  const MKT: Playbook = { id: "marketing-services-agreement", version: "1.0.0" };
  const COMPLETE =
    "Scope of Work. Agency shall provide the marketing services and deliverables described in the SOW for the campaign. " +
    "Endorsements. All influencers shall clearly and conspicuously disclose the material connection (#ad) per 16 CFR Part 255. " +
    "Email. All commercial email shall comply with CAN-SPAM: accurate headers, a working unsubscribe, and a physical postal address. " +
    "Ownership. All deliverables and work product are works made for hire owned by Client, and Agency assigns all rights. " +
    "Data Privacy. The Agency processes personal data and email list data only on the Client's instructions and shall comply with applicable privacy laws (CCPA/CPRA and GDPR) as a service provider, with a deletion obligation on termination. " +
    "Approvals. The Client's prior written approval is required for all creative, media plans, and public claims before publication. " +
    "Rights Clearance. The Agency shall obtain all licenses, releases, and clearances for third-party materials (stock imagery, licensed music, fonts, and talent / model releases) and warrants that the deliverables do not infringe any third-party intellectual-property or publicity right. " +
    "Confidentiality. The Agency shall keep the Client's confidential information confidential and use it only to perform the services. " +
    "Subcontractors. The Agency remains responsible for its subcontractors and influencers and shall bind them in writing to the same material obligations, flowing down the FTC disclosure, confidentiality, and IP terms. " +
    "Claims. All advertising claims shall be truthful and substantiated before use.";

  it("emits no findings against a complete marketing services agreement", async () => {
    expect((await fired(MKT, COMPLETE)).size).toBe(0);
  });

  it("COMM-020 fires on an influencer campaign with no FTC disclosure requirement", async () => {
    const inf = await fired(
      MKT,
      "Scope of Work: Agency runs an influencer campaign with paid endorsements and testimonials. Deliverables owned by Client. Claims substantiated.",
    );
    expect(inf.has("COMM-020")).toBe(true);
  });

  it("COMM-021 fires on an email campaign with no CAN-SPAM clause", async () => {
    const em = await fired(
      MKT,
      "Scope of Work: Agency runs an email newsletter campaign. Deliverables owned by Client. Claims substantiated.",
    );
    expect(em.has("COMM-021")).toBe(true);
  });

  it("COMM-020 and COMM-021 are inapplicable to a plain media-buy campaign", async () => {
    const media = await fired(
      MKT,
      "Scope of Work: Agency runs a media-buy campaign and provides the deliverables. Deliverables are owned by Client. Claims shall be substantiated.",
    );
    expect(media.has("COMM-020")).toBe(false);
    expect(media.has("COMM-021")).toBe(false);
  });

  it("COMM-030 fires only on a data-driven campaign missing a privacy-compliance clause", async () => {
    const data = await fired(
      MKT,
      "Scope of Work: Agency manages the Client's email list and consumer personal data for retargeting. Deliverables owned by Client. Claims substantiated.",
    );
    expect(data.has("COMM-030")).toBe(true);
    const plain = await fired(
      MKT,
      "Scope of Work: Agency runs a media-buy campaign and provides deliverables. Deliverables owned by Client. Claims substantiated.",
    );
    expect(plain.has("COMM-030")).toBe(false);
  });

  it("COMM-031 fires when the client has no approval rights over creative and claims", async () => {
    const bare = await fired(
      MKT,
      "Scope of Work: Agency runs the campaign and provides deliverables. Deliverables owned by Client. Claims substantiated.",
    );
    expect(bare.has("COMM-031")).toBe(true);
  });

  it("COMM-035/036 fire when rights-clearance and confidentiality clauses are absent", async () => {
    const bare = await fired(
      MKT,
      "Scope of Work: Agency runs the campaign and provides deliverables. Deliverables owned by Client. Claims substantiated.",
    );
    expect(bare.has("COMM-035")).toBe(true);
    expect(bare.has("COMM-036")).toBe(true);
  });

  it("COMM-037 fires only when subcontractors / influencers are used without a flow-down clause", async () => {
    const sub = await fired(
      MKT,
      "Scope of Work: Agency may engage subcontractors and influencers to run the campaign. Deliverables owned by Client.",
    );
    expect(sub.has("COMM-037")).toBe(true);
    const inHouse = await fired(
      MKT,
      "Scope of Work: Agency's in-house team runs a media-buy campaign and provides deliverables. Deliverables owned by Client.",
    );
    expect(inHouse.has("COMM-037")).toBe(false);
  });
});
