import { describe, expect, it } from "vitest";
import {
  buildFixListMarkdown,
  buildFixListCsv,
  buildObligationsCsv,
  buildDeadlinesIcs,
  collectDeadlines,
} from "./exports.js";
import type { EngineRun, Finding, Severity } from "../engine/finding.js";
import type {
  DateReference,
  ExtractedData,
  Obligation,
} from "../extract/types.js";

// --- fixtures ---------------------------------------------------------------

function finding(rule_id: string, severity: Severity, position: number): Finding {
  return {
    id: `${rule_id}-${position}`,
    rule_id,
    rule_version: "1.0.0",
    severity,
    title: `Issue with ${rule_id}`,
    description: "desc",
    excerpt: { text: "excerpt", section_id: `s${position}`, start_offset: position, end_offset: position + 5 },
    explanation: "Why this matters.",
    recommendation: "Fix the clause.",
    source_citations: [
      {
        id: "src-1",
        source: "45 C.F.R. § 164.410",
        source_url: "https://example.com",
        retrieved_at: "2026-05-01T00:00:00Z",
        license: "Public domain",
        license_url: "https://www.usa.gov/government-works",
      },
    ],
    document_position: position,
  };
}

function makeRun(findings: Finding[]): EngineRun {
  return {
    version: "0.1.0",
    dkb_version: "v0.0.1-starter",
    playbook_id: "mutual-nda",
    source_file: { name: "test.pdf", sha256: "a".repeat(64), size_bytes: 1024 },
    executed_at: "2026-05-12T12:00:00Z",
    findings,
    execution_log: [],
    result_hash: "b".repeat(64),
  };
}

function emptyExtracted(): ExtractedData {
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
  };
}

function date(
  type: DateReference["type"],
  raw_text: string,
  extra: Partial<DateReference>,
): DateReference {
  return {
    id: `d-${raw_text}`,
    type,
    raw_text,
    position: { section_id: "s1", start: 0, end: raw_text.length },
    ...extra,
  };
}

function obligation(extra: Partial<Obligation>): Obligation {
  return {
    id: "o-1",
    obligor: "Vendor",
    action: "deliver the Services",
    modal: "shall",
    raw_text: "Vendor shall deliver the Services within 30 days.",
    position: { section_id: "s3", start: 0, end: 10 },
    ...extra,
  };
}

// --- fix list ---------------------------------------------------------------

describe("buildFixListMarkdown", () => {
  it("groups findings by severity and renders checkboxes", () => {
    const run = makeRun([
      finding("MSA-006", "critical", 10),
      finding("NDA-003", "warning", 20),
    ]);
    const md = buildFixListMarkdown(run);
    expect(md).toContain("# Vaulytica fix list");
    expect(md).toContain("## Critical (1)");
    expect(md).toContain("## Warning (1)");
    expect(md).toContain("## Info (0)");
    expect(md).toContain("- [ ] **MSA-006** — Issue with MSA-006");
    expect(md).toContain("- Recommendation: Fix the clause.");
    expect(md).toContain("- Authority: 45 C.F.R. § 164.410");
    expect(md).toContain("_None._"); // info bucket
  });

  it("is deterministic — identical across two runs", () => {
    const run = makeRun([finding("A-1", "critical", 1), finding("B-2", "info", 2)]);
    expect(buildFixListMarkdown(run)).toBe(buildFixListMarkdown(run));
  });

  it("appends a manual-verify section for unresolved dates when extracted is supplied", () => {
    const ex = emptyExtracted();
    ex.dates = [date("absolute", "13/13/2025", {})]; // invalid → no iso
    const md = buildFixListMarkdown(makeRun([]), ex);
    expect(md).toContain("## Dates to verify manually (1)");
    expect(md).toContain("not machine-readable");
    expect(md).toContain("13/13/2025");
  });

  it("omits the manual-verify section when there are no unresolved dates", () => {
    const ex = emptyExtracted();
    ex.dates = [date("absolute", "2025-06-01", { iso: "2025-06-01" })];
    const md = buildFixListMarkdown(makeRun([]), ex);
    expect(md).not.toContain("Dates to verify manually");
  });
});

describe("buildFixListCsv", () => {
  it("emits a header and one row per finding in run order", () => {
    const run = makeRun([finding("MSA-006", "critical", 10), finding("NDA-003", "warning", 20)]);
    const csv = buildFixListCsv(run);
    const rows = csv.trimEnd().split("\r\n");
    expect(rows[0]).toBe("severity,rule_id,section,title,explanation,recommendation,authority");
    expect(rows).toHaveLength(3);
    expect(rows[1]).toContain("critical,MSA-006,s10,");
  });

  it("RFC-4180-escapes fields containing commas", () => {
    const f = finding("X-1", "critical", 1);
    f.title = "Cap is missing, unbounded exposure";
    const csv = buildFixListCsv(makeRun([f]));
    expect(csv).toContain('"Cap is missing, unbounded exposure"');
  });

  it("RFC-4180-escapes embedded quotes by doubling", () => {
    const f = finding("X-1", "critical", 1);
    f.explanation = 'The term "Services" is undefined';
    const csv = buildFixListCsv(makeRun([f]));
    expect(csv).toContain('"The term ""Services"" is undefined"');
  });

  it("is deterministic", () => {
    const run = makeRun([finding("A-1", "critical", 1)]);
    expect(buildFixListCsv(run)).toBe(buildFixListCsv(run));
  });
});

// --- obligations ------------------------------------------------------------

describe("buildObligationsCsv", () => {
  it("emits a header and one row per obligation", () => {
    const ex = emptyExtracted();
    ex.obligations = [
      obligation({}),
      obligation({ id: "o-2", obligor: "Customer", action: "pay fees", modal: "must" }),
    ];
    const csv = buildObligationsCsv(ex);
    const rows = csv.trimEnd().split("\r\n");
    expect(rows[0]).toBe("obligor,modal,action,trigger,qualifier,section,source_text");
    expect(rows).toHaveLength(3);
    expect(rows[1]).toContain("Vendor,shall,deliver the Services");
    expect(rows[2]).toContain("Customer,must,pay fees");
  });

  it("handles an empty ledger (header only)", () => {
    expect(buildObligationsCsv(emptyExtracted())).toBe(
      "obligor,modal,action,trigger,qualifier,section,source_text\r\n",
    );
  });
});

// --- deadlines (.ics) -------------------------------------------------------

describe("collectDeadlines", () => {
  it("turns valid absolute dates into events", () => {
    const ex = emptyExtracted();
    ex.dates = [date("absolute", "2025-06-01", { iso: "2025-06-01" })];
    const { events, unresolved } = collectDeadlines(ex);
    expect(events).toHaveLength(1);
    expect(events[0]!.iso).toBe("2025-06-01");
    expect(events[0]!.computed).toBe(false);
    expect(unresolved).toHaveLength(0);
  });

  it("marks absolute dates without a resolvable iso as unresolved", () => {
    const ex = emptyExtracted();
    ex.dates = [date("absolute", "Marchtember 5", {})];
    const { events, unresolved } = collectDeadlines(ex);
    expect(events).toHaveLength(0);
    expect(unresolved).toHaveLength(1);
    expect(unresolved[0]!.reason).toContain("not machine-readable");
  });

  it("computes a relative date when its anchor's definition pins a concrete date", () => {
    const ex = emptyExtracted();
    ex.definitions.entries = [
      {
        term: "Effective Date",
        definition: "the Effective Date means January 1, 2025",
        defined_at: { section_id: "s1", start: 0, end: 5 },
        used_at: [],
      },
    ];
    ex.dates = [
      date("relative", "thirty (30) days after the Effective Date", {
        anchor: "Effective Date",
        offset_days: 30,
      }),
    ];
    const { events, unresolved } = collectDeadlines(ex);
    expect(unresolved).toHaveLength(0);
    expect(events).toHaveLength(1);
    expect(events[0]!.iso).toBe("2025-01-31");
    expect(events[0]!.computed).toBe(true);
    expect(events[0]!.notice).toBe(false);
  });

  it("flags a negative-offset relative date as a notice deadline", () => {
    const ex = emptyExtracted();
    ex.definitions.entries = [
      {
        term: "Termination Date",
        definition: "Termination Date: 2025-12-31",
        defined_at: { section_id: "s1", start: 0, end: 5 },
        used_at: [],
      },
    ];
    ex.dates = [
      date("relative", "60 days before the Termination Date", {
        anchor: "Termination Date",
        offset_days: -60,
      }),
    ];
    const { events } = collectDeadlines(ex);
    expect(events).toHaveLength(1);
    expect(events[0]!.iso).toBe("2025-11-01");
    expect(events[0]!.notice).toBe(true);
  });

  it("does not fabricate a date when the anchor has no defined date", () => {
    const ex = emptyExtracted();
    ex.dates = [
      date("relative", "30 days after the Effective Date", {
        anchor: "Effective Date",
        offset_days: 30,
      }),
    ];
    const { events, unresolved } = collectDeadlines(ex);
    expect(events).toHaveLength(0);
    expect(unresolved).toHaveLength(1);
    expect(unresolved[0]!.reason).toContain("no defined calendar date");
  });

  it("treats named-anchor references as unresolved, not events", () => {
    const ex = emptyExtracted();
    ex.dates = [date("named-anchor", "Effective Date", { anchor: "Effective Date" })];
    const { events, unresolved } = collectDeadlines(ex);
    expect(events).toHaveLength(0);
    expect(unresolved).toHaveLength(1);
  });

  it("sorts events by date deterministically", () => {
    const ex = emptyExtracted();
    ex.dates = [
      date("absolute", "2025-12-01", { iso: "2025-12-01" }),
      date("absolute", "2025-01-01", { iso: "2025-01-01" }),
    ];
    const { events } = collectDeadlines(ex);
    expect(events.map((e) => e.iso)).toEqual(["2025-01-01", "2025-12-01"]);
  });
});

describe("buildDeadlinesIcs", () => {
  function icsWithOneEvent(): string {
    const ex = emptyExtracted();
    ex.dates = [date("absolute", "2025-06-01", { iso: "2025-06-01" })];
    return buildDeadlinesIcs(ex);
  }

  it("produces a well-formed VCALENDAR with all-day VEVENTs and CRLF lines", () => {
    const ics = icsWithOneEvent();
    expect(ics).toContain("BEGIN:VCALENDAR\r\n");
    expect(ics).toContain("PRODID:-//Vaulytica//Deadlines Export//EN");
    expect(ics).toContain("BEGIN:VEVENT");
    expect(ics).toContain("DTSTART;VALUE=DATE:20250601");
    expect(ics).toContain("DTEND;VALUE=DATE:20250602");
    expect(ics).toContain("END:VCALENDAR\r\n");
  });

  it("uses a fixed DTSTAMP so output carries no wall-clock", () => {
    expect(icsWithOneEvent()).toContain("DTSTAMP:20200101T000000Z");
  });

  it("is byte-identical across two runs (deterministic)", () => {
    expect(icsWithOneEvent()).toBe(icsWithOneEvent());
  });

  it("emits a VALARM for notice deadlines", () => {
    const ex = emptyExtracted();
    ex.definitions.entries = [
      {
        term: "Termination Date",
        definition: "Termination Date: 2025-12-31",
        defined_at: { section_id: "s1", start: 0, end: 5 },
        used_at: [],
      },
    ];
    ex.dates = [
      date("relative", "60 days before the Termination Date", {
        anchor: "Termination Date",
        offset_days: -60,
      }),
    ];
    const ics = buildDeadlinesIcs(ex);
    expect(ics).toContain("BEGIN:VALARM");
    expect(ics).toContain("TRIGGER:PT0S");
    expect(ics).toContain("SUMMARY:Notice deadline:");
  });

  it("escapes ICS special characters in summaries", () => {
    const ex = emptyExtracted();
    ex.dates = [date("absolute", "2025-06-01; see note, urgent", { iso: "2025-06-01" })];
    const ics = buildDeadlinesIcs(ex);
    expect(ics).toContain("\\;");
    expect(ics).toContain("\\,");
  });

  it("produces an empty calendar (no VEVENTs) when there are no resolvable dates", () => {
    const ics = buildDeadlinesIcs(emptyExtracted());
    expect(ics).toContain("BEGIN:VCALENDAR");
    expect(ics).not.toContain("BEGIN:VEVENT");
  });
});
