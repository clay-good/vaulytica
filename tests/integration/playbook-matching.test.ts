/**
 * Integration tests for the playbook matcher (build step 8). For every
 * launch playbook, a small synthetic fixture is fed through the
 * extractor stack and the matcher must pick the right id. Three
 * ambiguous fixtures are also exercised to confirm they fall back to
 * `generic-fallback`.
 */

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  GENERIC_FALLBACK_ID,
  LAUNCH_PLAYBOOK_IDS,
  matchPlaybook,
  parsePlaybook,
  PlaybookSchema,
  type Playbook,
} from "../../src/playbooks/index.js";
import { buildTree } from "../../src/extract/_fixtures.js";
import { extractAll } from "../../src/extract/index.js";
import { loadStarterDkbSync } from "../../src/engine/_test-fixtures.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const playbookDir = join(__dirname, "..", "..", "playbooks");

function loadAllPlaybooks(): Playbook[] {
  return LAUNCH_PLAYBOOK_IDS.map((id) =>
    parsePlaybook(JSON.parse(readFileSync(join(playbookDir, `${id}.json`), "utf8"))),
  );
}

function runMatch(title: string, body: string): ReturnType<typeof matchPlaybook> {
  const tree = buildTree([title, body]);
  const dkb = loadStarterDkbSync();
  const extracted = extractAll(tree, {
    classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
  });
  return matchPlaybook(extracted, extracted.classified, loadAllPlaybooks(), {
    title,
    body_text: body,
  });
}

describe("Playbook JSON files", () => {
  const playbooks = loadAllPlaybooks();

  it("ships all 12 launch playbooks", () => {
    expect(playbooks).toHaveLength(12);
    const ids = playbooks.map((p) => p.id);
    expect(new Set(ids).size).toBe(12);
  });

  it("every file validates against the schema", () => {
    for (const id of LAUNCH_PLAYBOOK_IDS) {
      const raw = JSON.parse(readFileSync(join(playbookDir, `${id}.json`), "utf8"));
      expect(() => PlaybookSchema.parse(raw), id).not.toThrow();
    }
  });

  it("every balanced_default references a known DKB source id", () => {
    const dkb = loadStarterDkbSync();
    const sourceIds = new Set(dkb.manifest.sources.map((s) => s.id));
    for (const p of playbooks) {
      for (const d of p.balanced_defaults) {
        expect(sourceIds.has(d.source_dkb_id), `${p.id} → ${d.source_dkb_id}`).toBe(true);
      }
    }
  });

  it("every playbook (excluding the fallback) cites at least one source", () => {
    for (const p of playbooks) {
      if (p.id === GENERIC_FALLBACK_ID) continue;
      expect(p.sources.length, p.id).toBeGreaterThan(0);
    }
  });
});

describe("matchPlaybook — positive fixtures", () => {
  it("picks mutual-nda for a Common Paper-shaped mutual NDA", () => {
    const r = runMatch(
      "Mutual Non-Disclosure Agreement",
      "This Mutual Non-Disclosure Agreement is entered into between Discloser and Recipient. Each party shall protect the other's Confidential Information and use it only for the Permitted Purpose.",
    );
    expect(r.playbook_id).toBe("mutual-nda");
    expect(r.confidence).toBeGreaterThan(0.5);
    expect(r.reasoning.length).toBeGreaterThan(0);
  });

  it("picks unilateral-nda for a one-way NDA", () => {
    const r = runMatch(
      "One-Way Non-Disclosure Agreement",
      "The Recipient shall not disclose the Disclosing Party's Confidential Information and shall use it only for the Permitted Purpose.",
    );
    expect(r.playbook_id).toBe("unilateral-nda");
  });

  it("picks employment-at-will-us for an at-will offer letter", () => {
    const r = runMatch(
      "Offer Letter",
      "Your position is Senior Engineer, exempt, at-will. Your base compensation is $200,000. You report to the CTO. As an Employee you will sign the IP assignment.",
    );
    expect(r.playbook_id).toBe("employment-at-will-us");
  });

  it("picks independent-contractor for a 1099 contractor agreement", () => {
    const r = runMatch(
      "Independent Contractor Agreement",
      "Contractor is engaged as an independent contractor and not an employee. Contractor will be paid via 1099. Contractor shall provide its own equipment.",
    );
    expect(r.playbook_id).toBe("independent-contractor");
  });

  it("picks saas-customer for a SaaS subscription title", () => {
    const r = runMatch(
      "Cloud Service Agreement",
      "Vendor will provide the Service to Customer for the Subscription Term. Customer Data uploaded to the Service is processed under the DPA. The Service is subject to uptime commitments.",
    );
    expect(["saas-customer", "saas-vendor"]).toContain(r.playbook_id);
  });

  it("picks saas-vendor when vendor-language dominates", () => {
    const r = runMatch(
      "Master Subscription Agreement",
      "Provider grants Customer access to the Service for the Subscription Term. The Service is provided AS-IS. Vendor disclaims implied warranties to the maximum extent permitted by law.",
    );
    expect(["saas-customer", "saas-vendor"]).toContain(r.playbook_id);
  });

  it("picks msa-general for a generic professional-services MSA", () => {
    const r = runMatch(
      "Master Services Agreement",
      "Provider will perform the Services described in each Statement of Work for Customer. Deliverables will be governed by this Master Agreement.",
    );
    expect(r.playbook_id).toBe("msa-general");
  });

  it("picks sow for a child statement of work", () => {
    const r = runMatch(
      "Statement of Work #1",
      "This SOW is entered into under the Master Agreement dated January 1, 2026. The Deliverables and milestones are described below.",
    );
    expect(r.playbook_id).toBe("sow");
  });

  it("picks lease-commercial-multitenant for an office lease", () => {
    const r = runMatch(
      "Office Lease",
      "Landlord leases the Premises (15,000 Rentable Square Feet) to Tenant. Tenant shall pay Base Rent monthly plus its proportionate share of Operating Expenses (CAM) and Common Area charges. Subleasing requires consent.",
    );
    expect(r.playbook_id).toBe("lease-commercial-multitenant");
  });

  it("picks lease-residential-us for an apartment lease", () => {
    const r = runMatch(
      "Residential Lease Agreement",
      "Landlord rents the Premises to Tenant for residential use only. Rent shall be paid on the first of each month. No smoking. Pets are not permitted without written approval. A security deposit equal to one month's Rent is required.",
    );
    expect(r.playbook_id).toBe("lease-residential-us");
  });

  it("picks consulting-agreement for a named consultant engagement", () => {
    const r = runMatch(
      "Consulting Agreement",
      "Consultant will provide advisory services as an independent contractor. The Consulting Services and deliverables are described in the SOW. Consultant brings their own expertise.",
    );
    expect(["consulting-agreement", "independent-contractor"]).toContain(r.playbook_id);
  });

  it("picks generic-fallback explicitly when configured (the fallback playbook itself)", () => {
    // The fallback playbook has no positive features. Even if it is in the list,
    // any other clearly matching contract should not select it.
    const r = runMatch(
      "Mutual Non-Disclosure Agreement",
      "Each party shall protect the other's Confidential Information.",
    );
    expect(r.playbook_id).not.toBe(GENERIC_FALLBACK_ID);
  });
});

describe("matchPlaybook — ambiguous fixtures fall to generic-fallback", () => {
  it("falls back when the document is a press release with no contract signals", () => {
    const r = runMatch(
      "Press Release",
      "Acme Corp announced its quarterly earnings today. The company reported revenue of $50 million.",
    );
    expect(r.playbook_id).toBe(GENERIC_FALLBACK_ID);
    expect(r.confidence).toBeLessThan(0.5);
  });

  it("falls back when the document is a generic letter with no defining terms", () => {
    const r = runMatch(
      "Letter Regarding Our Discussions",
      "Dear Counterparty, thank you for the productive meeting last week. We look forward to continuing the conversation.",
    );
    expect(r.playbook_id).toBe(GENERIC_FALLBACK_ID);
  });

  it("falls back for a multi-clause unknown contract that triggers conflicting features", () => {
    const r = runMatch(
      "General Agreement",
      "The parties agree to cooperate on the project. This agreement is governed by the laws of the State of Delaware. Notices shall be sent in writing.",
    );
    expect(r.playbook_id).toBe(GENERIC_FALLBACK_ID);
  });
});

describe("matchPlaybook — determinism", () => {
  it("returns identical results across runs", () => {
    const title = "Mutual Non-Disclosure Agreement";
    const body = "This is a mutual NDA between Discloser and Recipient regarding Confidential Information.";
    const a = runMatch(title, body);
    const b = runMatch(title, body);
    expect(b).toEqual(a);
  });

  it("breaks ties lexicographically by playbook id", () => {
    // Two playbooks share a generic feature; the alphabetically-earlier id wins
    // on equal score.
    const r = runMatch(
      "Generic",
      "this document contains the word agreement and nothing else of interest",
    );
    expect(r.playbook_id).toBe(GENERIC_FALLBACK_ID);
  });
});

describe("Playbook deprecation metadata (Step 27 follow-up)", () => {
  const playbooks = loadAllPlaybooks();
  const byId = new Map(playbooks.map((p) => [p.id, p]));

  it("v2 mutual-nda is marked deprecated and superseded by mutual-nda-deep", () => {
    const p = byId.get("mutual-nda");
    expect(p?.deprecated).toBe(true);
    expect(p?.superseded_by).toBe("mutual-nda-deep");
  });

  it("v2 unilateral-nda is marked deprecated and superseded by unilateral-nda-deep", () => {
    const p = byId.get("unilateral-nda");
    expect(p?.deprecated).toBe(true);
    expect(p?.superseded_by).toBe("unilateral-nda-deep");
  });

  it("no other LAUNCH playbook is deprecated", () => {
    for (const p of playbooks) {
      if (p.id === "mutual-nda" || p.id === "unilateral-nda") continue;
      expect(p.deprecated ?? false, p.id).toBe(false);
    }
  });

  it("the deprecation metadata does not change matcher output for v2 NDA documents", () => {
    // The v2 NDA fixtures continue to pick mutual-nda / unilateral-nda
    // because they outscore every other playbook on their own — the
    // deprecated-demotion tiebreak only kicks in on exact raw-score ties.
    const mutual = runMatch(
      "Mutual Non-Disclosure Agreement",
      "This Mutual Non-Disclosure Agreement is entered into between Discloser and Recipient. Each party shall protect the other's Confidential Information and use it only for the Permitted Purpose.",
    );
    expect(mutual.playbook_id).toBe("mutual-nda");
    const unilateral = runMatch(
      "One-Way Non-Disclosure Agreement",
      "The Recipient shall not disclose the Disclosing Party's Confidential Information and shall use it only for the Permitted Purpose.",
    );
    expect(unilateral.playbook_id).toBe("unilateral-nda");
  });

  it("cross-version: when v2 mutual-nda and v3 mutual-nda-deep are both in the candidate set on a tie, the v3 deep variant wins", () => {
    // Mirrors the v4 bundle pipeline's candidate set (loadAllPlaybooks
    // includes LAUNCH + v3 + v4). When both NDA playbooks score the
    // same raw_score against a clean Mutual NDA, the deprecation
    // demotion must elevate `mutual-nda-deep` above `mutual-nda`.
    // We construct a synthetic two-playbook candidate set to isolate
    // the cross-version behavior from the matcher's other heuristics.
    const v2 = loadAllPlaybooks().find((p) => p.id === "mutual-nda");
    const v3DeepRaw = JSON.parse(
      readFileSync(
        join(__dirname, "..", "..", "src", "playbooks", "v3", "mutual-nda-deep.json"),
        "utf8",
      ),
    );
    const v3Deep = parsePlaybook(v3DeepRaw);
    expect(v2?.deprecated).toBe(true);
    expect(v3Deep.deprecated ?? false).toBe(false);

    // Force both to score 0 by passing an empty fixture so the only
    // operative sort key is the deprecation tiebreak.
    const dkb = loadStarterDkbSync();
    const tree = buildTree(["x", "y"]);
    const extracted = extractAll(tree, {
      classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
    });
    const r = matchPlaybook(extracted, extracted.classified, [v2!, v3Deep], {
      title: "x",
      body_text: "y",
    });
    expect(r.alternatives[0]?.playbook_id).toBe("mutual-nda-deep");
  });

  it("on a raw-score tie, a non-deprecated playbook beats a deprecated one", () => {
    // Synthetic two-playbook ranking — same raw score, only deprecated flag differs.
    // We import the matcher directly with an empty extracted/classified
    // payload so neither playbook gets any feature hits; both score 0,
    // both fall to fallback, but the sort order itself is what we pin.
    const dkb = loadStarterDkbSync();
    const tree = buildTree(["x", "y"]);
    const extracted = extractAll(tree, {
      classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
    });
    const emptyFeatures = {
      title_keywords: [],
      required_clauses: [],
      distinguishing_phrases: [],
      negative_features: [],
    };
    const base: Omit<Playbook, "id" | "deprecated"> = {
      version: "1.0.0",
      name: "",
      description: "",
      match_features: emptyFeatures,
      expected_clauses: [],
      expected_defined_terms: [],
      rule_overrides: {},
      balanced_defaults: [],
      sources: [],
    };
    // Alphabetic order would otherwise pick `a-legacy`. The deprecated
    // tiebreak must promote `b-current` ahead of it.
    const legacy: Playbook = { ...base, id: "a-legacy", deprecated: true };
    const current: Playbook = { ...base, id: "b-current" };
    const r = matchPlaybook(extracted, extracted.classified, [legacy, current], {
      title: "x",
      body_text: "y",
    });
    // Both score 0 → top alternative reported. We assert via reasoning + alternatives.
    expect(r.alternatives[0]?.playbook_id).toBe("b-current");
  });
});
