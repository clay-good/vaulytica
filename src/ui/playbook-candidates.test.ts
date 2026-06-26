import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  familySignalStrength,
  selectMatchCandidates,
  familyIsPresent,
  selectSecondaryFamilies,
  MAX_SECONDARY_FAMILIES,
  ADMIT_THRESHOLD,
} from "./playbook-candidates.js";
import { parsePlaybook, matchPlaybook, type Playbook } from "../playbooks/index.js";
import type { ExtractedData, ClassifiedParagraph } from "../extract/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = join(__dirname, "..", "..");

// --- fixtures ---------------------------------------------------------------

function pb(id: string, features: Partial<Playbook["match_features"]>): Playbook {
  return {
    id,
    version: "1.0.0",
    name: id,
    description: id,
    match_features: {
      title_keywords: [],
      required_clauses: [],
      distinguishing_phrases: [],
      negative_features: [],
      ...features,
    },
  } as Playbook;
}

function emptyExtracted(over: Partial<ExtractedData> = {}): ExtractedData {
  return {
    parties: [],
    dates: [],
    amounts: [],
    definitions: { entries: [], unused_terms: [], undefined_capitalized: [] },
    outline: { nodes: [], by_id: {} },
    crossrefs: [],
    obligations: [],
    jurisdictions: [],
    classified: [],
    ...over,
  };
}

function signals(title: string, body: string, classified: ClassifiedParagraph[] = []) {
  return { title, body, classified, extracted: emptyExtracted({ classified }) };
}

// --- familySignalStrength ---------------------------------------------------

describe("familySignalStrength", () => {
  const baa = pb("baa", {
    title_keywords: ["business associate agreement", "baa"],
    distinguishing_phrases: ["protected health information", "covered entity"],
  });

  it("a specific title keyword alone clears the admit threshold", () => {
    const s = familySignalStrength(
      baa,
      signals("Business Associate Agreement", "...generic body..."),
    );
    expect(s).toBeGreaterThanOrEqual(ADMIT_THRESHOLD);
  });

  it("two distinguishing phrases clear the threshold without a title hit", () => {
    const s = familySignalStrength(
      baa,
      signals("Agreement", "the protected health information held by the covered entity"),
    );
    expect(s).toBeGreaterThanOrEqual(ADMIT_THRESHOLD);
  });

  it("a single weak body phrase does not clear the threshold", () => {
    const s = familySignalStrength(baa, signals("Agreement", "covered entity only"));
    expect(s).toBeLessThan(ADMIT_THRESHOLD);
  });
});

// --- selectMatchCandidates --------------------------------------------------

describe("selectMatchCandidates", () => {
  const launch = [pb("mutual-nda", { title_keywords: ["non-disclosure agreement"] })];
  const extended = [
    pb("baa", { title_keywords: ["business associate agreement"] }),
    pb("bylaws-corporation", {
      title_keywords: ["bylaws"],
      distinguishing_phrases: ["board of directors", "quorum"],
    }),
    pb("asset-purchase-agreement", { title_keywords: ["asset purchase agreement"] }),
  ];

  it("always keeps the launch playbooks", () => {
    const got = selectMatchCandidates(launch, extended, signals("Some Doc", "nothing special"));
    expect(got.map((p) => p.id)).toContain("mutual-nda");
  });

  it("admits only the family the document signals", () => {
    const got = selectMatchCandidates(
      launch,
      extended,
      signals("Bylaws of Acme, Inc.", "the board of directors shall meet; a quorum is required"),
    );
    const ids = got.map((p) => p.id);
    expect(ids).toContain("bylaws-corporation");
    expect(ids).not.toContain("baa");
    expect(ids).not.toContain("asset-purchase-agreement");
  });

  it("admits nothing extra for a plain document (today's behavior preserved)", () => {
    const got = selectMatchCandidates(
      launch,
      extended,
      signals("Services Agreement", "generic terms"),
    );
    expect(got.map((p) => p.id)).toEqual(["mutual-nda"]);
  });
});

// --- familyIsPresent (strict activation bar) --------------------------------

describe("familyIsPresent", () => {
  const dpa = pb("dpa-controller-processor", {
    title_keywords: ["data processing agreement", "dpa"],
    distinguishing_phrases: ["controller", "processor", "article 28", "sub-processor"],
  });

  it("activates on a single specific title keyword", () => {
    expect(familyIsPresent(dpa, signals("Data Processing Agreement", "..."))).toBe(true);
  });

  it("activates on three or more distinguishing phrases (no title hit)", () => {
    expect(
      familyIsPresent(
        dpa,
        signals("Exhibit C", "the controller instructs the processor per article 28"),
      ),
    ).toBe(true);
  });

  it("does NOT activate on a mere passing mention (two phrases)", () => {
    expect(familyIsPresent(dpa, signals("Exhibit C", "the controller and processor"))).toBe(false);
  });
});

// --- selectSecondaryFamilies ------------------------------------------------

describe("selectSecondaryFamilies", () => {
  const extended = [
    pb("dpa-controller-processor", {
      title_keywords: ["data processing agreement"],
      distinguishing_phrases: ["controller", "processor", "article 28"],
    }),
    pb("ip-licensing-patent", { title_keywords: ["patent license agreement"] }),
    pb("msa-vendor-deep", { title_keywords: ["master services agreement"] }),
  ];

  it("returns families clearly present, excluding the primary match", () => {
    const got = selectSecondaryFamilies(
      extended,
      signals(
        "Master Services Agreement with Data Processing Addendum",
        "the controller instructs the processor under article 28",
      ),
      "msa-vendor-deep", // primary
    );
    const ids = got.map((p) => p.id);
    expect(ids).toContain("dpa-controller-processor");
    expect(ids).not.toContain("msa-vendor-deep"); // excluded — it's the primary
    expect(ids).not.toContain("ip-licensing-patent"); // not present in the doc
  });

  it("returns nothing for a single-family document", () => {
    const got = selectSecondaryFamilies(
      extended,
      signals("Master Services Agreement", "services and deliverables"),
      "msa-vendor-deep",
    );
    expect(got).toEqual([]);
  });

  it("caps the number of secondary families", () => {
    const many = Array.from({ length: 10 }, (_, i) =>
      pb(`fam-${i}`, { title_keywords: [`family ${i} agreement`] }),
    );
    const title = many.map((_, i) => `Family ${i} Agreement`).join(" and ");
    const got = selectSecondaryFamilies(many, signals(title, ""), "none");
    expect(got.length).toBeLessThanOrEqual(MAX_SECONDARY_FAMILIES);
  });
});

// --- integration over the real served manifest ------------------------------

describe("gating over the real launch + extended playbooks", () => {
  const launch: Playbook[] = ["mutual-nda", "msa-general", "saas-customer"].map((id) =>
    parsePlaybook(JSON.parse(readFileSync(join(REPO, "playbooks", `${id}.json`), "utf8"))),
  );
  const extended: Playbook[] = (
    JSON.parse(readFileSync(join(REPO, "playbooks", "extended.json"), "utf8")) as unknown[]
  ).map((p) => parsePlaybook(p));

  it("a Business Associate Agreement routes to the baa playbook, not a launch one", () => {
    const title = "Business Associate Agreement";
    const body =
      "This Business Associate Agreement governs Protected Health Information disclosed by the Covered Entity to the Business Associate under 45 CFR 164.504.";
    const candidates = selectMatchCandidates(launch, extended, signals(title, body));
    expect(candidates.map((p) => p.id)).toContain("baa");
    const match = matchPlaybook(emptyExtracted(), [], candidates, { title, body_text: body });
    expect(match.playbook_id).toBe("baa");
  });

  it("a plain mutual NDA does NOT route into a v4 family", () => {
    const title = "Mutual Non-Disclosure Agreement";
    const body =
      "Each party may disclose Confidential Information to the Recipient for the Permitted Purpose. The Discloser retains all rights.";
    const candidates = selectMatchCandidates(launch, extended, signals(title, body));
    const match = matchPlaybook(emptyExtracted(), [], candidates, { title, body_text: body });
    // Stays in the NDA family (launch mutual-nda or a v3 nda-deep successor),
    // never a v4 sub-domain playbook.
    expect(match.playbook_id).toMatch(/nda/);
  });
});
