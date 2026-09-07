import { describe, expect, it } from "vitest";
import { missingCompanions, type CompanionCatalogEntry } from "./companions.js";

const CATALOG: CompanionCatalogEntry[] = [
  { id: "complaint", name: "Complaint", companion_playbooks: ["answer", "trial-motion"] },
  { id: "answer", name: "Answer", companion_playbooks: ["complaint"] },
  { id: "trial-motion", name: "Trial Motion" },
  {
    id: "document-requests",
    name: "Document Requests",
    companion_playbooks: ["discovery-responses", "privilege-log"],
  },
  { id: "discovery-responses", name: "Discovery Responses" },
  { id: "privilege-log", name: "Privilege Log" },
  { id: "generic-fallback", name: "Generic Fallback" },
];

const doc = (playbook_id: string) => ({ playbook_id });

describe("missingCompanions", () => {
  it("names the companion the package does not contain", () => {
    expect(missingCompanions([doc("complaint")], CATALOG)).toEqual([
      {
        missing_playbook_id: "answer",
        missing_playbook_name: "Answer",
        expected_by: ["complaint"],
      },
      {
        missing_playbook_id: "trial-motion",
        missing_playbook_name: "Trial Motion",
        expected_by: ["complaint"],
      },
    ]);
  });

  it("stays silent about a companion that IS in the package", () => {
    const gaps = missingCompanions([doc("complaint"), doc("answer")], CATALOG);
    expect(gaps.map((g) => g.missing_playbook_id)).toEqual(["trial-motion"]);
  });

  it("returns nothing when the package is complete", () => {
    expect(
      missingCompanions([doc("answer"), doc("complaint"), doc("trial-motion")], CATALOG),
    ).toEqual([]);
  });

  it("credits every family that named the same missing document", () => {
    const catalog: CompanionCatalogEntry[] = [
      ...CATALOG,
      {
        id: "interrogatories",
        name: "Interrogatories",
        companion_playbooks: ["discovery-responses"],
      },
    ];
    const gaps = missingCompanions([doc("document-requests"), doc("interrogatories")], catalog);
    const responses = gaps.find((g) => g.missing_playbook_id === "discovery-responses");
    expect(responses?.expected_by).toEqual(["document-requests", "interrogatories"]);
  });

  it("never invents a name for a companion the catalog cannot resolve", () => {
    const dangling: CompanionCatalogEntry[] = [
      { id: "questionnaire", name: "Questionnaire", companion_playbooks: ["no-such-playbook"] },
    ];
    expect(missingCompanions([doc("questionnaire")], dangling)).toEqual([]);
  });

  it("never asks for the generic fallback, which is not a document", () => {
    const catalog: CompanionCatalogEntry[] = [
      { id: "complaint", name: "Complaint", companion_playbooks: ["generic-fallback"] },
      { id: "generic-fallback", name: "Generic Fallback" },
    ];
    expect(missingCompanions([doc("complaint")], catalog)).toEqual([]);
  });

  it("ignores a document whose playbook is not in the catalog at all", () => {
    expect(missingCompanions([doc("custom-thing")], CATALOG)).toEqual([]);
  });

  it("is unaffected by two copies of the same family", () => {
    const once = missingCompanions([doc("complaint")], CATALOG);
    const twice = missingCompanions([doc("complaint"), doc("complaint")], CATALOG);
    expect(twice).toEqual(once);
  });

  it("is deterministic regardless of the order documents arrive in", () => {
    const a = missingCompanions([doc("complaint"), doc("document-requests")], CATALOG);
    const b = missingCompanions([doc("document-requests"), doc("complaint")], CATALOG);
    expect(a).toEqual(b);
    expect(a.map((g) => g.missing_playbook_id)).toEqual([
      "answer",
      "discovery-responses",
      "privilege-log",
      "trial-motion",
    ]);
  });

  it("is empty for an empty package", () => {
    expect(missingCompanions([], CATALOG)).toEqual([]);
  });
});
