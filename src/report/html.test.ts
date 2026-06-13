import { describe, expect, it } from "vitest";
import { buildHtmlReport } from "./html.js";
import { loadStarterDkbSync } from "../engine/_test-fixtures.js";
import type { EngineRun, Finding } from "../engine/finding.js";
import type { IngestResult } from "../ingest/types.js";

const ingest: IngestResult = {
  tree: { type: "document", sections: [] },
  source: "pdf",
  word_count: 1000,
  sha256: "a".repeat(64),
  warnings: [],
};

function finding(id: string, sev: Finding["severity"]): Finding {
  return {
    id,
    rule_id: "STRUCT-001",
    rule_version: "1.0.0",
    severity: sev,
    title: `Finding ${id}`,
    description: "Description of the finding",
    excerpt: { text: "excerpt", section_id: "s1", start_offset: 0, end_offset: 7 },
    explanation: "Plain explanation.",
    recommendation: "Consider revising.",
    source_citations: [
      {
        id: "cfr-164-410",
        source: "45 C.F.R. § 164.410(a)(1)",
        source_url:
          "https://www.govinfo.gov/content/pkg/CFR-2024-title45-vol2/xml/CFR-2024-title45-vol2-sec164-410.xml",
        retrieved_at: "2026-05-11T00:00:00Z",
        license: "Public domain",
        license_url: "https://www.usa.gov/government-works",
      },
    ],
    document_position: 0,
  };
}

function makeRun(): EngineRun {
  return {
    version: "0.1.0",
    dkb_version: "v0.0.1-starter",
    playbook_id: "mutual-nda",
    source_file: { name: "test.pdf", sha256: "a".repeat(64), size_bytes: 1024 },
    executed_at: "2026-06-08T12:00:00Z",
    findings: [finding("c1", "critical"), finding("w1", "warning")],
    execution_log: [],
    result_hash: "b".repeat(64),
  };
}

describe("buildHtmlReport (spec-v8 §21 — standalone single-file HTML)", () => {
  it("is a self-contained HTML document with inlined CSS and no scripts", () => {
    const html = buildHtmlReport(makeRun(), ingest, loadStarterDkbSync());
    expect(html.startsWith("<!doctype html>")).toBe(true);
    expect(html).toContain("<style>");
    expect(html).not.toContain("<script");
    expect(html).not.toContain("http-equiv"); // no external refresh/refs
    // No external stylesheet/resource links.
    expect(html).not.toMatch(/<link\b/);
  });

  it("renders the cover proof fields", () => {
    const html = buildHtmlReport(makeRun(), ingest, loadStarterDkbSync());
    expect(html).toContain("mutual-nda");
    expect(html).toContain("v0.0.1-starter");
    expect(html).toContain("a".repeat(64)); // file fingerprint
    expect(html).toContain("b".repeat(64)); // result hash
  });

  it("groups findings by severity and renders inline citations in full (never truncated)", () => {
    const html = buildHtmlReport(makeRun(), ingest, loadStarterDkbSync());
    expect(html).toContain("Critical Findings (1)");
    expect(html).toContain("Warnings (1)");
    // Full citation source and full URL both present, with a working link.
    expect(html).toContain("45 C.F.R. § 164.410(a)(1)");
    expect(html).toContain(
      'href="https://www.govinfo.gov/content/pkg/CFR-2024-title45-vol2/xml/CFR-2024-title45-vol2-sec164-410.xml"',
    );
    expect(html).not.toContain("…");
  });

  it("renders the bibliography and the verbatim posture block", () => {
    const html = buildHtmlReport(makeRun(), ingest, loadStarterDkbSync());
    expect(html).toContain("Bibliography");
    expect(html).toContain("This analysis was performed entirely inside the user");
    expect(html).toContain("Vaulytica is a software tool, not a lawyer");
  });

  it("escapes HTML metacharacters in finding content", () => {
    const run = makeRun();
    run.findings = [{ ...finding("x", "info"), title: "Cap <script>alert(1)</script> & \"q\"" }];
    const html = buildHtmlReport(run, ingest, loadStarterDkbSync());
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).toContain("&lt;script&gt;");
  });

  it("never emits an active javascript:/data: citation href (XSS defense in depth)", () => {
    // A citation URL with a dangerous scheme (e.g. from a custom playbook that
    // bypassed schema validation) must render as inert text, not a live link.
    const run = makeRun();
    run.findings = [
      {
        ...finding("x", "warning"),
        source_citations: [
          {
            id: "policy-evil",
            source: "Team Policy 9",
            source_url: "javascript:alert(document.domain)",
            retrieved_at: "2026-05-11T00:00:00Z",
            license: "Team policy",
            license_url: "",
          },
        ],
      },
    ];
    const html = buildHtmlReport(run, ingest, loadStarterDkbSync());
    expect(html).not.toContain('href="javascript:');
    expect(html).not.toContain('href="data:');
    // The URL stays visible (citability) — just inert, HTML-escaped text.
    expect(html).toContain("javascript:alert(document.domain)");
  });

  it("renders a bibliography citation URL containing $-replacement patterns verbatim", () => {
    // The bibliography links the URL by `String.replace`-ing it inside the
    // already-escaped entry. With a *string* replacement, `$&`/`` $` ``/`$'` in a
    // user-supplied custom-playbook citation URL expand as special patterns and
    // corrupt the href (the matched URL gets spliced into itself). A *function*
    // replacement inserts the markup verbatim. Assert on the bibliography <ol>.
    const tricky = "https://policy.example.com/s?a=$&b=$1&c=$`d";
    const run = makeRun();
    run.findings = [
      {
        ...finding("x", "warning"),
        source_citations: [
          {
            id: "policy-dollar",
            source: "Team Policy 12",
            source_url: tricky,
            retrieved_at: "2026-05-11T00:00:00Z",
            license: "Team policy",
            license_url: "",
          },
        ],
      },
    ];
    const html = buildHtmlReport(run, ingest, loadStarterDkbSync());
    const biblio = html.slice(html.indexOf('<ol class="biblio">'), html.indexOf("</ol>"));
    const escapedUrl = tricky.replace(/&/g, "&amp;"); // tricky has no other esc-able chars
    // The bibliography href carries the full URL, HTML-escaped, uncorrupted.
    expect(biblio).toContain(`href="${escapedUrl}"`);
    // The corruption splices the URL into itself: `s?a=https://policy…` (the `$`
    // is consumed by `$&`). It must not appear.
    expect(biblio).not.toContain("s?a=https://policy");
  });

  it("is deterministic: identical inputs → identical bytes", () => {
    const dkb = loadStarterDkbSync();
    expect(buildHtmlReport(makeRun(), ingest, dkb)).toBe(buildHtmlReport(makeRun(), ingest, dkb));
  });

  it("renders the v9 Last Look sections and escapes their content", () => {
    const dkb = loadStarterDkbSync();
    const v9 = {
      delivery: {
        source: "docx" as const,
        inspectable: true,
        findings: [
          {
            rule_id: "HANDOFF-001",
            severity: "critical" as const,
            title: "Tracked changes are present",
            description: "2 tracked-change revisions remain.",
            count: 2,
            evidence: ["insertion by <b>Opposing Counsel</b>"],
          },
        ],
        summary: "Delivery: 2 tracked changes — review before sending.",
        delivery_hash: "d".repeat(64),
      },
      closingChecklist: {
        open_count: 1,
        items: [
          {
            category: "attachment" as const,
            rule_id: "STRUCT-018",
            label: "Referenced attachment not present: Exhibit C",
            section: "s3",
          },
        ],
      },
      criticalDates: {
        register: [
          {
            rule_id: "DATE-001",
            kind: "auto-renewal-notice" as const,
            resolved: true,
            computed_date: "2025-11-01",
            trigger: "60 days before the Renewal Date",
            anchor: "Renewal Date",
            responsible: "Acme Corp",
            section: "s8",
          },
        ],
        resolved_count: 1,
        unresolved_count: 0,
        critical_dates_hash: "e".repeat(64),
      },
    };
    const html = buildHtmlReport(makeRun(), ingest, dkb, undefined, v9);
    expect(html).toContain("Clean to send — pre-disclosure scan");
    expect(html).toContain("Ready to sign — closing checklist");
    expect(html).toContain("Critical dates — computed from the document");
    expect(html).toContain("2025-11-01");
    expect(html).toContain("HANDOFF-001");
    // HANDOFF evidence with markup is escaped, never live.
    expect(html).toContain("&lt;b&gt;Opposing Counsel&lt;/b&gt;");
    expect(html).not.toContain("<b>Opposing Counsel</b>");
    expect(html).not.toContain("<script");
  });

  it("omits the v9 sections entirely when no surface is supplied (v8-identical)", () => {
    const dkb = loadStarterDkbSync();
    expect(buildHtmlReport(makeRun(), ingest, dkb)).toBe(
      buildHtmlReport(makeRun(), ingest, dkb, undefined, {}),
    );
  });
});
