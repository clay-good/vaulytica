import { describe, expect, it } from "vitest";
import type { IngestResult } from "../ingest/types.js";
import { LAUNCH_RULES } from "../engine/rules/index.js";
import { FILING_RULES, CITE_RULES } from "../engine/rules/filing/index.js";
import { getCourtProfile } from "./court-profile.js";
import { activateFiling } from "./activate.js";

const ingest: IngestResult = {
  tree: { type: "document", sections: [] },
  source: "pdf",
  word_count: 5000,
  page_count: 12,
  sha256: "a".repeat(64),
  warnings: [],
};
const FRAP = getCourtProfile("frap-default")!;

describe("activateFiling", () => {
  it("adds the CITE pack (but not FILE) for a filing playbook with no court profile", () => {
    const w = activateFiling(undefined, "appellate-brief", ingest, LAUNCH_RULES);
    // Citation lint runs on any brief; the format pack stays dormant without --court.
    expect(w.rules.length).toBe(LAUNCH_RULES.length + CITE_RULES.length);
    expect(w.options).toBeUndefined();
    expect(w.filing_profile).toBeUndefined();
  });

  it("is a no-op for a non-filing playbook even with a profile selected", () => {
    const w = activateFiling(
      { profile: FRAP, brief_kind: "principal" },
      "mutual-nda",
      ingest,
      LAUNCH_RULES,
    );
    expect(w.rules).toBe(LAUNCH_RULES);
    expect(w.filing_profile).toBeUndefined();
  });

  it("appends both the CITE and FILE packs and stamps the profile for a filing playbook", () => {
    const w = activateFiling(
      { profile: FRAP, brief_kind: "principal" },
      "appellate-brief",
      ingest,
      LAUNCH_RULES,
    );
    expect(w.rules.length).toBe(LAUNCH_RULES.length + CITE_RULES.length + FILING_RULES.length);
    expect(w.options?.filing).toMatchObject({ word_count: 5000, page_count: 12, source: "pdf" });
    expect(w.filing_profile).toMatchObject({ id: "frap-default", brief_kind: "principal" });
    expect(w.filing_profile?.authority.length).toBeGreaterThan(0);
  });
});
