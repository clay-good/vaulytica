import { describe, expect, it } from "vitest";
import type { ExtractedData } from "../../extract/types.js";

import { detectV3Family } from "./auto-detect.js";
import { defaultFramesForPlaybook, toggleFrame } from "./compliance-frame.js";
import {
  EMPTY_MULTI_DOC_STATE,
  MAX_DOCUMENTS,
  addDocument,
  markAnalyzing,
  markComplete,
  markError,
  removeDocument,
  setConsistencyEnabled,
  setConsistencyFindingsCount,
  isReadyForConsistency,
  hasUsableConsistencyBundle,
} from "./multi-doc.js";
import { v3ErrorMessage, EMPTY_STATE_COPY } from "./copy.js";

function emptyExtracted(definitions: Record<string, string> = {}): ExtractedData {
  return {
    parties: [],
    dates: [],
    amounts: [],
    definitions: {
      entries: Object.entries(definitions).map(([term, body]) => ({
        term,
        definition: body,
        defined_at: { section_id: "s1", start: 0, end: body.length },
        used_at: [],
      })),
      unused_terms: [],
      undefined_capitalized: [],
    },
    outline: { nodes: [], by_id: {} },
    crossrefs: [],
    obligations: [],
    jurisdictions: [],
    classified: [],
  };
}

/* ---------------- detectV3Family ---------------- */

describe("detectV3Family", () => {
  it("flags a BAA on definitional + statutory + phrase signals", () => {
    const ext = emptyExtracted({
      "Business Associate":
        "shall mean the party that creates or receives Protected Health Information on behalf of Covered Entity.",
    });
    const text =
      "Business Associate Agreement. This BAA is entered into per 45 CFR § 164.504(e). Protected Health Information.";
    const d = detectV3Family(ext, text);
    expect(d.family).toBe("baa");
    expect(d.suggested_playbook).toBe("baa");
    expect(d.signals.length).toBeGreaterThanOrEqual(2);
    expect(d.confidence).toBeGreaterThan(0);
  });

  it("flags a DPA-EU when Controller + Processor are defined and Article 28 cited", () => {
    const ext = emptyExtracted({
      Controller: "the party that determines the purposes and means of processing.",
      Processor: "the party that processes personal data on behalf of the Controller.",
    });
    const text =
      "Data Processing Agreement. Pursuant to Article 28 of the GDPR, the Processor shall...";
    const d = detectV3Family(ext, text);
    expect(d.family).toBe("dpa-eu");
    expect(d.suggested_playbook).toBe("dpa-controller-processor");
  });

  it("flags SCC Module 2 by Implementing Decision + Module 2 phrasing", () => {
    const ext = emptyExtracted();
    const text =
      "These Standard Contractual Clauses are based on Implementing Decision (EU) 2021/914. The parties have selected Module Two (controller-to-processor).";
    const d = detectV3Family(ext, text);
    expect(d.family).toBe("scc-module-2");
  });

  it("flags a COI from ACORD 25 / Certificate of Liability Insurance", () => {
    const ext = emptyExtracted();
    const text =
      "ACORD 25 (2016/03) — Certificate of Liability Insurance. Insurer: Globex. Coverage: General Liability $1M / $2M.";
    const d = detectV3Family(ext, text);
    expect(d.family).toBe("coi");
    expect(d.suggested_playbook).toBe("coi");
  });

  it("returns 'unknown' with no playbook for a document with no signals", () => {
    const ext = emptyExtracted();
    const d = detectV3Family(ext, "A generic services agreement between Acme and Globex.");
    expect(d.family).toBe("unknown");
    expect(d.suggested_playbook).toBeNull();
    expect(d.signals).toEqual([]);
  });

  it("routes nda-deep to mutual-nda-deep on mutual / two-way header", () => {
    const ext = emptyExtracted();
    const text =
      "Mutual Non-Disclosure Agreement. Each party agrees to protect Confidential Information of the other. Trade secrets are governed by 18 U.S.C. § 1833.";
    const d = detectV3Family(ext, text);
    expect(d.family).toBe("nda-deep");
    expect(d.suggested_playbook).toBe("mutual-nda-deep");
    // Resolver appends its own signals to the audit trail so the user
    // (and a future reviewer) can see why the variant was picked.
    expect(d.signals.some((s) => /Mutual \/ two-way \/ bilateral NDA/i.test(s.evidence))).toBe(
      true,
    );
  });

  it("routes nda-deep to unilateral-nda-deep on one-way / discloser-recipient framing", () => {
    const ext = emptyExtracted();
    const text =
      "One-way Non-Disclosure Agreement. The Disclosing Party may share Confidential Information with the Receiving Party for the purpose of evaluating a potential transaction. Trade secrets remain the property of the Discloser.";
    const d = detectV3Family(ext, text);
    expect(d.family).toBe("nda-deep");
    expect(d.suggested_playbook).toBe("unilateral-nda-deep");
    // Resolver appends its own signals to the audit trail.
    expect(d.signals.some((s) => /Unilateral \/ one-way NDA/i.test(s.evidence))).toBe(true);
  });

  it("picks up nda-deep on the defined-term signal even when the body text is sparse", () => {
    // Common case: definitions appendix is the only place "Confidential
    // Information" and "Disclosing Party" appear in formal definition
    // form. Body text mentions confidentiality and trade secrets but
    // does not repeat the canonical defined-term names. Detector should
    // still pick nda-deep on the strength of the definition entries.
    const ext = emptyExtracted({
      "Confidential Information":
        "means any non-public information disclosed by one party to the other.",
      "Disclosing Party": "means the party that discloses Confidential Information.",
      "Receiving Party": "means the party that receives Confidential Information.",
    });
    const text =
      "Non-Disclosure Agreement. The parties agree to protect each other's trade secrets.";
    const d = detectV3Family(ext, text);
    expect(d.family).toBe("nda-deep");
    expect(d.signals.some((s) => s.source === "definition")).toBe(true);
  });

  it("picks up msa-deep on a defined Services + SOW signal even when MSA-specific phrases are absent", () => {
    const ext = emptyExtracted({
      Services: "means the services to be provided by Vendor to Customer as described in each SOW.",
      "Statement of Work": "means each ordering document executed under this Agreement.",
    });
    const text = "Master Services Agreement. Limitation of liability applies.";
    const d = detectV3Family(ext, text);
    expect(d.family).toBe("msa-deep");
    expect(d.signals.some((s) => s.source === "definition")).toBe(true);
  });

  it("picks up vendor-security on Customer Data + Security Measures defined-term signals", () => {
    const ext = emptyExtracted({
      "Customer Data":
        "means data that Customer provides to Vendor in connection with the services.",
      "Security Measures":
        "means the administrative, technical, and physical safeguards Vendor maintains.",
    });
    const text = "Vendor Security Addendum. SOC 2 Type II maintained.";
    const d = detectV3Family(ext, text);
    expect(d.family).toBe("vendor-security");
    expect(d.signals.some((s) => s.source === "definition")).toBe(true);
  });

  it("picks up ai-addendum on Foundation Model + Training Data defined-term signals", () => {
    const ext = emptyExtracted({
      "Foundation Model":
        "means the large language model made available by Vendor for Customer use.",
      "Training Data":
        "means input data used by Vendor to train, fine-tune, or evaluate any Model.",
    });
    const text = "AI Addendum. NIST AI RMF.";
    const d = detectV3Family(ext, text);
    expect(d.family).toBe("ai-addendum");
    expect(d.signals.some((s) => s.source === "definition")).toBe(true);
  });

  it("falls back to mutual-nda-deep when nda-deep signals are present but mutual/unilateral cues are absent", () => {
    const ext = emptyExtracted();
    // No "mutual" / "one-way" header, no discloser/recipient framing —
    // bare "confidentiality agreement" + DTSA citation is enough to
    // trigger nda-deep but does not pick a side. Mutual is the safer
    // default (see resolveNdaDeepVariant doc).
    const text =
      "Confidentiality Agreement. The parties agree to protect trade secrets pursuant to 18 U.S.C. § 1833.";
    const d = detectV3Family(ext, text);
    expect(d.family).toBe("nda-deep");
    expect(d.suggested_playbook).toBe("mutual-nda-deep");
  });
});

/* ---------------- compliance-frame defaults ---------------- */

describe("defaultFramesForPlaybook", () => {
  it("turns HIPAA on for any BAA playbook", () => {
    expect(defaultFramesForPlaybook("baa").on).toContain("HIPAA");
    expect(defaultFramesForPlaybook("baa-subcontractor").on).toContain("HIPAA");
  });

  it("turns GDPR + CCPA on for a Controller-Processor DPA", () => {
    const f = defaultFramesForPlaybook("dpa-controller-processor");
    expect(f.on).toContain("GDPR");
    expect(f.on).toContain("CCPA");
  });

  it("turns every US-state frame on for the multi-state DPA", () => {
    const f = defaultFramesForPlaybook("dpa-multi-state-us");
    expect(f.on).toEqual(
      expect.arrayContaining(["CCPA", "VCDPA", "CPA", "CTDPA", "UCPA", "TDPSA", "OCPA", "DPDPA"]),
    );
  });

  it("renders the MSA hint when no frames default-on", () => {
    const f = defaultFramesForPlaybook("msa-vendor-deep");
    expect(f.on).toEqual([]);
    expect(f.hint).toMatch(/companion DPA or BAA/);
  });

  it("turns NIST AI RMF + EU AI Act on for the AI addendum", () => {
    const f = defaultFramesForPlaybook("ai-addendum");
    expect(f.on).toEqual(expect.arrayContaining(["NIST-AI-RMF", "EU-AI-Act"]));
  });

  it("turns GDPR + UK-GDPR on for an SCC playbook", () => {
    const f = defaultFramesForPlaybook("scc-module-2");
    expect(f.on).toEqual(expect.arrayContaining(["GDPR", "UK-GDPR"]));
  });

  it("offers every frame as available regardless of playbook", () => {
    const f = defaultFramesForPlaybook("generic-fallback");
    expect(f.available.length).toBeGreaterThan(15);
  });
});

describe("toggleFrame", () => {
  it("adds a frame that is not currently on", () => {
    expect(toggleFrame(["HIPAA"], "GDPR")).toEqual(["HIPAA", "GDPR"]);
  });
  it("removes a frame that is currently on", () => {
    expect(toggleFrame(["HIPAA", "GDPR"], "GDPR")).toEqual(["HIPAA"]);
  });
  it("never mutates the input", () => {
    const before: ("HIPAA" | "GDPR")[] = ["HIPAA"];
    void toggleFrame(before, "GDPR");
    expect(before).toEqual(["HIPAA"]);
  });
});

/* ---------------- multi-doc state model ---------------- */

describe("multi-doc state model", () => {
  it("accepts up to MAX_DOCUMENTS documents", () => {
    let s = EMPTY_MULTI_DOC_STATE;
    for (let i = 0; i < MAX_DOCUMENTS; i++) {
      const r = addDocument(s, { id: `d${i}`, filename: `doc${i}.docx`, kind: "docx" });
      expect(r.ok).toBe(true);
      if (r.ok) s = r.state;
    }
    expect(s.documents).toHaveLength(MAX_DOCUMENTS);
  });

  it("rejects the (MAX_DOCUMENTS + 1)th document", () => {
    let s = EMPTY_MULTI_DOC_STATE;
    for (let i = 0; i < MAX_DOCUMENTS; i++) {
      const r = addDocument(s, { id: `d${i}`, filename: `doc${i}.docx`, kind: "docx" });
      if (r.ok) s = r.state;
    }
    const r = addDocument(s, { id: "extra", filename: "extra.docx", kind: "docx" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/up to/);
  });

  it("rejects duplicate ids", () => {
    let s = EMPTY_MULTI_DOC_STATE;
    const r1 = addDocument(s, { id: "a", filename: "a.docx", kind: "docx" });
    if (r1.ok) s = r1.state;
    const r2 = addDocument(s, { id: "a", filename: "a.docx", kind: "docx" });
    expect(r2.ok).toBe(false);
  });

  it("transitions queued → analyzing → complete", () => {
    let s = EMPTY_MULTI_DOC_STATE;
    s = (addDocument(s, { id: "a", filename: "a.docx", kind: "docx" }) as { state: typeof s })
      .state;
    s = markAnalyzing(s, "a", 0.5, "v0.0.1-starter");
    const a1 = s.documents[0]!;
    expect(a1.status).toBe("analyzing");
    if (a1.status === "analyzing") expect(a1.progress).toBe(0.5);
    s = markComplete(s, "a", {
      playbook_id: "mutual-nda",
      playbook_name: "Mutual NDA",
      result_hash: "h".repeat(64),
      counts: { critical: 0, warning: 1, info: 2 },
    });
    const a2 = s.documents[0]!;
    expect(a2.status).toBe("complete");
  });

  it("records errors per document without affecting siblings", () => {
    let s = EMPTY_MULTI_DOC_STATE;
    s = (addDocument(s, { id: "a", filename: "a.docx", kind: "docx" }) as { state: typeof s })
      .state;
    s = (addDocument(s, { id: "b", filename: "b.docx", kind: "docx" }) as { state: typeof s })
      .state;
    s = markError(s, "a", "ingest failed");
    s = markComplete(s, "b", {
      playbook_id: "mutual-nda",
      playbook_name: "Mutual NDA",
      result_hash: "h".repeat(64),
      counts: { critical: 0, warning: 0, info: 0 },
    });
    expect(s.documents[0]!.status).toBe("error");
    expect(s.documents[1]!.status).toBe("complete");
  });

  it("removes a document by id", () => {
    let s = EMPTY_MULTI_DOC_STATE;
    s = (addDocument(s, { id: "a", filename: "a.docx", kind: "docx" }) as { state: typeof s })
      .state;
    s = (addDocument(s, { id: "b", filename: "b.docx", kind: "docx" }) as { state: typeof s })
      .state;
    s = removeDocument(s, "a");
    expect(s.documents).toHaveLength(1);
    expect(s.documents[0]!.id).toBe("b");
  });

  it("isReadyForConsistency only when ≥2 docs and all terminal", () => {
    let s = EMPTY_MULTI_DOC_STATE;
    s = (addDocument(s, { id: "a", filename: "a.docx", kind: "docx" }) as { state: typeof s })
      .state;
    expect(isReadyForConsistency(s)).toBe(false);
    s = (addDocument(s, { id: "b", filename: "b.docx", kind: "docx" }) as { state: typeof s })
      .state;
    expect(isReadyForConsistency(s)).toBe(false); // both queued
    s = markComplete(s, "a", {
      playbook_id: "x",
      playbook_name: "X",
      result_hash: "h".repeat(64),
      counts: { critical: 0, warning: 0, info: 0 },
    });
    s = markComplete(s, "b", {
      playbook_id: "y",
      playbook_name: "Y",
      result_hash: "h".repeat(64),
      counts: { critical: 0, warning: 0, info: 0 },
    });
    expect(isReadyForConsistency(s)).toBe(true);
    expect(hasUsableConsistencyBundle(s)).toBe(true);
  });

  it("hasUsableConsistencyBundle is false when only one doc succeeded", () => {
    let s = EMPTY_MULTI_DOC_STATE;
    s = (addDocument(s, { id: "a", filename: "a.docx", kind: "docx" }) as { state: typeof s })
      .state;
    s = (addDocument(s, { id: "b", filename: "b.docx", kind: "docx" }) as { state: typeof s })
      .state;
    s = markComplete(s, "a", {
      playbook_id: "x",
      playbook_name: "X",
      result_hash: "h".repeat(64),
      counts: { critical: 0, warning: 0, info: 0 },
    });
    s = markError(s, "b", "boom");
    expect(hasUsableConsistencyBundle(s)).toBe(false);
  });

  it("consistency_enabled is user-toggleable and defaults to true", () => {
    let s = EMPTY_MULTI_DOC_STATE;
    expect(s.consistency_enabled).toBe(true);
    s = setConsistencyEnabled(s, false);
    expect(s.consistency_enabled).toBe(false);
    s = setConsistencyFindingsCount(s, 3);
    expect(s.consistency_findings_count).toBe(3);
  });
});

/* ---------------- copy strings ---------------- */

describe("v3 copy strings", () => {
  it("v3ErrorMessage returns a known mapping or a generic fallback", () => {
    const known = v3ErrorMessage("baa-no-business-associate");
    expect(known.title).toMatch(/Business Associate/);
    const unknown = v3ErrorMessage("nope");
    expect(unknown.title).toMatch(/Something went wrong/);
  });
  it("EMPTY_STATE_COPY headline mentions four documents", () => {
    expect(EMPTY_STATE_COPY.headline).toMatch(/four/);
  });
});
