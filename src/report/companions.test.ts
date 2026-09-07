import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { missingCompanions, relatedDocuments, type CompanionCatalogEntry } from "./companions.js";

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

describe("relatedDocuments", () => {
  it("lists the families the matched playbook is normally paired with", () => {
    expect(relatedDocuments("complaint", CATALOG)).toEqual([
      { playbook_id: "answer", name: "Answer" },
      { playbook_id: "trial-motion", name: "Trial Motion" },
    ]);
  });

  it("asserts nothing about absence — a companion is listed either way", () => {
    // The single-document counterpart cannot know what else exists, so unlike
    // missingCompanions it never filters on what is "present".
    expect(relatedDocuments("answer", CATALOG)).toEqual([
      { playbook_id: "complaint", name: "Complaint" },
    ]);
  });

  it("is empty for a family that names no companion", () => {
    expect(relatedDocuments("trial-motion", CATALOG)).toEqual([]);
  });

  it("is empty for a playbook the catalog does not have", () => {
    expect(relatedDocuments("no-such-playbook", CATALOG)).toEqual([]);
  });

  it("never invents a name for an unresolvable companion", () => {
    const dangling: CompanionCatalogEntry[] = [
      { id: "questionnaire", name: "Questionnaire", companion_playbooks: ["no-such-playbook"] },
    ];
    expect(relatedDocuments("questionnaire", dangling)).toEqual([]);
  });

  it("never lists the generic fallback, or the document itself", () => {
    const catalog: CompanionCatalogEntry[] = [
      {
        id: "complaint",
        name: "Complaint",
        companion_playbooks: ["generic-fallback", "complaint", "answer"],
      },
      { id: "generic-fallback", name: "Generic Fallback" },
      { id: "answer", name: "Answer" },
    ];
    expect(relatedDocuments("complaint", catalog)).toEqual([
      { playbook_id: "answer", name: "Answer" },
    ]);
  });

  it("de-duplicates a companion named twice", () => {
    const catalog: CompanionCatalogEntry[] = [
      { id: "a", name: "A", companion_playbooks: ["b", "b"] },
      { id: "b", name: "B" },
    ];
    expect(relatedDocuments("a", catalog)).toEqual([{ playbook_id: "b", name: "B" }]);
  });

  it("every shipped family's related list resolves and is stable", () => {
    // A guard on the real data rather than a fixture: the same catalog the
    // report renders against, so a name that stops resolving fails here.
    const shipped: CompanionCatalogEntry[] = JSON.parse(
      readFileSync(join(process.cwd(), "playbooks", "extended.json"), "utf8"),
    );
    const declaring = shipped.filter((p) => (p.companion_playbooks ?? []).length > 0);
    expect(declaring.length, "anti-vacuity: the catalog declares companions").toBeGreaterThan(150);
    for (const p of declaring) {
      const related = relatedDocuments(p.id, shipped);
      for (const r of related) {
        expect(r.name.length).toBeGreaterThan(0);
        expect(r.name).not.toBe(r.playbook_id);
      }
      expect(relatedDocuments(p.id, shipped)).toEqual(related);
    }
  });
});
