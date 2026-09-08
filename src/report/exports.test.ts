import { describe, expect, it } from "vitest";
import {
  buildFixListMarkdown,
  buildFixListCsv,
  buildObligationsCsv,
  buildDeadlinesIcs,
  collectDeadlines,
} from "./exports.js";
import type { EngineRun, Finding, Severity } from "../engine/finding.js";
import type { DateReference, ExtractedData, Obligation } from "../extract/types.js";

// --- fixtures ---------------------------------------------------------------

function finding(rule_id: string, severity: Severity, position: number): Finding {
  return {
    id: `${rule_id}-${position}`,
    rule_id,
    rule_version: "1.0.0",
    severity,
    title: `Issue with ${rule_id}`,
    description: "desc",
    excerpt: {
      text: "excerpt",
      section_id: `s${position}`,
      start_offset: position,
      end_offset: position + 5,
    },
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
    const run = makeRun([finding("MSA-006", "critical", 10), finding("NDA-003", "warning", 20)]);
    const md = buildFixListMarkdown(run);
    expect(md).toContain("# Vaulytica fix list");
    expect(md).toContain("## Critical (1)");
    expect(md).toContain("## Warning (1)");
    expect(md).toContain("## Info (0)");
    expect(md).toContain("- [ ] **MSA-006** — Issue with MSA-006");
    expect(md).toContain("- Recommendation: Fix the clause.");
    expect(md).toContain("- Authority: [45 C.F.R. § 164.410](https://example.com)");
    expect(md).toContain("_None._"); // info bucket
  });

  it("is deterministic — identical across two runs", () => {
    const run = makeRun([finding("A-1", "critical", 1), finding("B-2", "info", 2)]);
    expect(buildFixListMarkdown(run)).toBe(buildFixListMarkdown(run));
  });

  it("records asserted opt-in packs, naming the estate posture for a seeded state", () => {
    const bare = makeRun([]);
    expect(buildFixListMarkdown(bare)).not.toContain("Estate checks");

    const run = makeRun([]);
    run.asserted_regimes = ["ccpa"];
    run.estate_checks_asserted = true;
    run.asserted_state = "us-pa";
    const md = buildFixListMarkdown(run);
    expect(md).toContain("**Privacy regimes:** ccpa — asserted by the user");
    expect(md).toContain("**Estate checks:** asserted by the user (--state us-pa)");
    // The estate line speaks the verified posture, not just the code.
    expect(md).toContain("Pennsylvania: No attesting witnesses required (ordinary signed will)");
    expect(md).toContain("20 Pa. C.S. § 2502");
  });

  it("renders the per-regime coverage table when the PNOT pack ran", () => {
    const run = makeRun([finding("PNOT-CCPA-002", "warning", 1)]);
    run.playbook_id = "privacy-notice-us";
    run.asserted_regimes = ["ccpa"];
    const md = buildFixListMarkdown(run);
    expect(md).toContain("Regime coverage — CCPA/CPRA privacy policy");
    // PNOT-CCPA-002 fired → its item is not found; another is found.
    expect(md).toMatch(/- \[ \] .*(sources)/i);
    expect(md).toMatch(/- \[x\] /);
    // Absent when no regime asserted.
    expect(buildFixListMarkdown(makeRun([]))).not.toContain("Regime coverage");
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
    expect(rows[0]).toBe(
      "severity,rule_id,section,title,explanation,recommendation,authority,authority_url,clause",
    );
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

  it("neutralizes CSV formula injection (CWE-1236) in untrusted cells", () => {
    const f = finding("X-1", "critical", 1);
    // A malicious clause weaponized as a spreadsheet formula.
    f.title = '=HYPERLINK("http://evil.example","click")';
    const csv = buildFixListCsv(makeRun([f]));
    // The cell is prefixed with ' so it renders as text, never executes.
    expect(csv).toContain(`'=HYPERLINK`);
    expect(csv).not.toContain(`,=HYPERLINK`);
  });

  it("neutralizes the +,-,@ formula triggers too", () => {
    for (const lead of ["+", "-", "@"]) {
      const f = finding("X-1", "critical", 1);
      f.title = `${lead}cmd`;
      const csv = buildFixListCsv(makeRun([f]));
      expect(csv).toContain(`'${lead}cmd`);
    }
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

  it("folds long multi-byte summaries to ≤75 octets without splitting a code point", () => {
    const ex = emptyExtracted();
    // 90 chars, every one a 3-octet euro sign → 270 octets, forces several folds.
    const longSummary = "€".repeat(90);
    ex.dates = [date("absolute", `${longSummary} 2025-06-01`, { iso: "2025-06-01" })];
    const ics = buildDeadlinesIcs(ex);
    const encoder = new TextEncoder();
    for (const line of ics.split("\r\n")) {
      // RFC 5545 §3.1: a folded content line is ≤75 octets.
      expect(encoder.encode(line).length).toBeLessThanOrEqual(75);
    }
    // Unfolding (strip CRLF + leading space) must reproduce intact UTF-8 — no half a euro sign.
    const summaryLine = ics.slice(ics.indexOf("SUMMARY:"));
    const unfolded = summaryLine.split("\r\n ").join("").split("\r\n")[0]!;
    expect(unfolded).toContain(longSummary);
    expect(unfolded).not.toContain("�");
  });

  it("produces an empty calendar (no VEVENTs) when there are no resolvable dates", () => {
    const ics = buildDeadlinesIcs(emptyExtracted());
    expect(ics).toContain("BEGIN:VCALENDAR");
    expect(ics).not.toContain("BEGIN:VEVENT");
  });

  it("emits unresolved dates as all-day 'verify manually' events rather than dropping them", () => {
    const ex = emptyExtracted();
    ex.dates = [date("absolute", "13/13/2025", {})]; // impossible date → unresolved
    const ics = buildDeadlinesIcs(ex);
    expect(ics).toContain("SUMMARY:Verify manually: 13/13/2025");
    expect(ics).toContain("DTSTART;VALUE=DATE:20200101"); // fixed sentinel date
    expect(ics).toContain("not machine-readable");
  });
});

describe("citation completeness across action exports (spec-v8 §14, Step 140)", () => {
  // The §14 contract: if an output names a finding, that output carries the
  // finding's resolvable citation. Parameterized over the action-item formats
  // that exist today (Markdown, CSV); extends to SARIF/HTML in Thrust C.
  it("every cited finding's URL survives into the Markdown and CSV exports", () => {
    const run = makeRun([finding("MSA-006", "critical", 10)]);
    const url = "https://example.com";
    const md = buildFixListMarkdown(run);
    // Markdown: a clickable link, not a stripped bare name.
    expect(md).toContain(`](${url})`);
    // CSV: a dedicated authority_url column carrying the resolvable URL.
    const csv = buildFixListCsv(run);
    expect(csv.split("\r\n")[0]).toContain("authority_url");
    expect(csv).toContain(url);
  });
});

/**
 * The fix list is what a reviewer pastes into a ticket, so it carries what the
 * ingest could and could not READ.
 *
 * It already led with the classification notice. It took no `ingest` argument
 * at all, so it was the last surface in the tree that could not carry the
 * other honesty caveat — "this document was read as a redline with all changes
 * accepted", "this PDF fell back to OCR". Either one changes what every line
 * below it means.
 */
describe("buildFixListMarkdown — the ingest's own caveats", () => {
  const run = makeRun([finding("MSA-006", "critical", 10)]);

  it("leads with what the ingest could not read", () => {
    const md = buildFixListMarkdown(run, undefined, undefined, {
      warnings: ["Tracked changes were read as all-changes-accepted."],
    });
    expect(md).toContain(
      "> **About this input.** Tracked changes were read as all-changes-accepted.",
    );
    // Above the findings it qualifies.
    expect(md.indexOf("About this input")).toBeLessThan(md.indexOf("## Critical"));
  });

  it("renders one line per warning", () => {
    const md = buildFixListMarkdown(run, undefined, undefined, {
      warnings: ["First caveat.", "Second caveat."],
    });
    expect(md).toContain("First caveat.");
    expect(md).toContain("Second caveat.");
  });

  it("is byte-identical when the ingest had nothing to say", () => {
    // Gated on presence, like every other render-side addition in the tree.
    const bare = buildFixListMarkdown(run);
    expect(buildFixListMarkdown(run, undefined, undefined, { warnings: [] })).toBe(bare);
    expect(bare).not.toContain("About this input");
  });
});

/**
 * A fix list is WORKED FROM, not read.
 *
 * It gave a rule id, a title, a section and the reasoning — and no clause. The
 * one question the artifact exists to answer, "what do I edit?", sent the
 * reviewer back to the document to find the sentence themselves.
 *
 * The two honest shapes stay apart here exactly as they do in the reports: a
 * finding about an ABSENCE has nothing to quote and says so, rather than
 * printing the rule's own marker string as if it were the contract's words.
 */
describe("the fix list names the clause to edit", () => {
  const withSpan = (): Finding => {
    const f = finding("CAP-1", "critical", 4);
    f.excerpt = {
      text: "  Liability   is\nunlimited.  ",
      section_id: "s4",
      start_offset: 5,
      end_offset: 40,
    };
    return f;
  };
  const absence = (): Finding => {
    const f = finding("MISS-1", "warning", 7);
    f.excerpt = { text: "RULE-MARKER-STRING", section_id: "s7", start_offset: 0, end_offset: 0 };
    return f;
  };

  it("quotes it in the Markdown, whitespace-collapsed for a one-line item", () => {
    const md = buildFixListMarkdown(makeRun([withSpan()]));
    expect(md).toContain('- Clause: "Liability is unlimited."');
  });

  it("says there is nothing to edit when the finding is about an absence", () => {
    const md = buildFixListMarkdown(makeRun([absence()]));
    expect(md).toContain("About an absence — there is no clause to edit.");
    expect(md).not.toContain("RULE-MARKER-STRING");
  });

  it("appends a clause column to the CSV rather than inserting one", () => {
    // Appended so a consumer reading by column index keeps working.
    const csv = buildFixListCsv(makeRun([withSpan(), absence()]));
    const rows = csv.trimEnd().split("\r\n");
    expect(rows[0]!.split(",").pop()).toBe("clause");
    expect(rows[1]).toContain("Liability is unlimited.");
    // Empty for the absence row, and never the marker string.
    expect(rows[2]!.endsWith(",")).toBe(true);
    expect(csv).not.toContain("RULE-MARKER-STRING");
  });
});

/**
 * What the calendar says about a deadline it could NOT pin.
 *
 * Every unresolved date becomes an all-day "Verify manually" event on a
 * sentinel date rather than being silently dropped — and the *reason* is the
 * whole content of that event. Mutation testing found every one of those
 * sentences, and the sort that orders them, with no test executing it: the
 * range-deadline case, the two relative-anchor cases, the fiscal-period case,
 * and the named-anchor case.
 *
 * A user subscribes to this file. A deadline the tool could not compute must
 * arrive saying which deadline and why, or it is a mystery entry they delete.
 */
describe("the deadlines calendar explains what it could not resolve", () => {
  const ex = (dates: unknown[]): ExtractedData =>
    ({
      parties: [],
      dates,
      amounts: [],
      jurisdictions: [],
      definitions: { entries: [] },
      crossrefs: [],
      sections: [],
      classified: [],
      obligations: [],
    }) as unknown as ExtractedData;

  /**
   * RFC 5545 folds long lines at 75 octets with a CRLF + single space, so a
   * reason sentence is routinely split mid-word in the raw file. Unfold before
   * matching — the first draft of these tests asserted against the raw text and
   * "failed" on a renderer that was working correctly.
   */
  const unfold = (ics: string): string => ics.replace(/\r\n /g, "");

  const date = (over: Record<string, unknown>): unknown => ({
    id: "d",
    type: "relative",
    raw_text: "the period",
    position: { section_id: "s1", start: 0, end: 5 },
    ...over,
  });

  it("names a range deadline as one, instead of guessing a bound", () => {
    const ics = unfold(
      buildDeadlinesIcs(
        ex([
          date({ raw_text: "30 to 60 days after signing", offset_days: 30, offset_days_max: 60 }),
        ]),
      ),
    );
    expect(ics).toContain("Verify manually: 30 to 60 days after signing");
    expect(ics).toContain("range deadline — verify the controlling bound manually");
  });

  it("names the anchor it could not resolve, and says so when there is none", () => {
    const named = unfold(
      buildDeadlinesIcs(
        ex([
          date({
            raw_text: "30 days after the Closing Date",
            anchor: "Closing Date",
            offset_days: 30,
          }),
        ]),
      ),
    );
    expect(named).toContain('relative to "Closing Date"');
    expect(named).toContain("which has no defined calendar date");
    const anon = unfold(
      buildDeadlinesIcs(ex([date({ raw_text: "30 days later", offset_days: 30 })])),
    );
    expect(anon).toContain("relative date with no resolvable anchor");
  });

  it("says a fiscal period is not a calendar date", () => {
    const ics = unfold(
      buildDeadlinesIcs(
        ex([date({ type: "fiscal-period", raw_text: "the second fiscal quarter" })]),
      ),
    );
    expect(ics).toContain("fiscal period — no fixed calendar date");
  });

  it("orders unresolved entries deterministically, by text then section", () => {
    // The file is regenerated on every analysis; an unstable order makes two
    // identical documents produce different bytes, which is the property the
    // whole export layer is built on.
    const rows = ex([
      date({ raw_text: "zulu period", type: "fiscal-period" }),
      date({ raw_text: "alpha period", type: "fiscal-period" }),
      date({
        raw_text: "alpha period",
        type: "fiscal-period",
        position: { section_id: "s0", start: 0, end: 5 },
      }),
    ]);
    const ics = unfold(buildDeadlinesIcs(rows));
    const order = [...ics.matchAll(/SUMMARY:Verify manually: ([^\r\n]+)/g)].map((m) => m[1]!);
    expect(order).toEqual(["alpha period", "alpha period", "zulu period"]);
    // And the tie between the two "alpha period" rows breaks on section, so
    // the sections read s0, s1 across the pair before zulu's own s1.
    const sections = [...ics.matchAll(/from section (s\d)/g)].map((m) => m[1]!);
    expect(sections).toEqual(["s0", "s1", "s1"]);
    // Byte-stable across two builds of the same input.
    expect(unfold(buildDeadlinesIcs(rows))).toBe(ics);
  });
});

/**
 * The fix list's own header — what was switched on, and what qualifies the
 * whole list.
 *
 * A fix list is the artifact a reviewer pastes into a ticket, and every line of
 * this header changes what the items below it mean: which optional rule packs
 * ran, that the document was read as a redline with all changes accepted, that
 * its type was not recognized at all. The block was written for exactly that
 * reason and mutation testing found none of it executed — each line could be
 * deleted and every test still passed.
 */
describe("the fix list header states what qualifies the list", () => {
  const baseRun = (over: Record<string, unknown>): EngineRun =>
    ({ ...makeRun([finding("CAP-1", "critical", 1)]), ...over }) as EngineRun;

  it("names each opt-in pack the user asserted", () => {
    const md = buildFixListMarkdown(
      baseRun({
        filing_profile: { id: "cand-civil", brief_kind: "opposition" },
        asserted_regimes: ["gdpr", "ccpa"],
        estate_checks_asserted: true,
      }),
    );
    expect(md).toContain("**Court profile:** cand-civil (opposition brief) — asserted by the user");
    expect(md).toContain("**Privacy regimes:** gdpr, ccpa — asserted by the user");
    expect(md).toContain("**Estate checks:** asserted by the user (--estate-checks)");
  });

  it("names the estate state and its verified formality posture", () => {
    const md = buildFixListMarkdown(
      baseRun({ estate_checks_asserted: true, asserted_state: "us-ca" }),
    );
    expect(md).toContain("--state us-ca");
    // The overlay's own headline and citation, not a bare state code: the
    // formality posture is the reason the pack was switched on.
    expect(md).toMatch(/--state us-ca\) — California: .+ \(.+\)/);
  });

  it("says nothing about a pack the user did not assert", () => {
    // Anti-vacuity, and the property that matters: a report must never imply a
    // check ran that did not.
    const md = buildFixListMarkdown(baseRun({}));
    expect(md).not.toContain("Court profile");
    expect(md).not.toContain("Privacy regimes");
    expect(md).not.toContain("Estate checks");
  });

  it("carries the ingest's caveats about what it could and could not read", () => {
    const md = buildFixListMarkdown(baseRun({}), undefined, undefined, {
      warnings: ["Redline read with all changes accepted.", "PDF fell back to OCR."],
    });
    expect(md).toContain("> **About this input.** Redline read with all changes accepted.");
    expect(md).toContain("> **About this input.** PDF fell back to OCR.");
    // And nothing when the ingest had nothing to say.
    expect(buildFixListMarkdown(baseRun({}), undefined, undefined, { warnings: [] })).not.toContain(
      "About this input",
    );
  });

  it("carries the unmatched-document banner", () => {
    const md = buildFixListMarkdown(
      baseRun({
        classification_notice: {
          message: "Fell back to the generic checklist.",
          reason: "no-match",
        },
      }),
    );
    expect(md).toContain("> **Document type not recognized.** Fell back to the generic checklist.");
    expect(buildFixListMarkdown(baseRun({}))).not.toContain("Document type not recognized");
  });
});
