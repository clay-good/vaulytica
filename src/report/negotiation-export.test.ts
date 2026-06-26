import { describe, expect, it } from "vitest";
import { buildNegotiationPostureMarkdown, buildNegotiationPostureCsv } from "./exports.js";
import { buildNegotiationSheet } from "./negotiation-sheet.js";
import type { NegotiationPosture } from "../playbooks/custom-interpreter.js";

const posture: NegotiationPosture = {
  counts: { ideal: 1, acceptable: 1, below_acceptable: 1, unevaluable: 1 },
  posture_hash: "f".repeat(64),
  positions: [
    {
      dimension: "Liability cap",
      tier: "below-acceptable",
      detail: "Found liability_cap_multiple = 3; requires ≥ 6.",
      guidance: "Below our 6x floor — escalate.",
      section_id: "s4",
    },
    {
      dimension: "Notice period",
      tier: "acceptable",
      detail: "Found notice_period_days = 45; ideal requires ≤ 30.",
      guidance: "Up to 60 days is tolerable.",
      section_id: "s12",
    },
    { dimension: "Governing law", tier: "ideal", guidance: "Delaware — hold." },
    {
      dimension: "Uptime SLA",
      tier: "unevaluable",
      reason: "could not locate a value for the uptime SLA",
    },
  ],
};

describe("negotiation posture export (spec-v10 Step 171)", () => {
  it("renders a Markdown table with every dimension and tier", () => {
    const md = buildNegotiationPostureMarkdown(posture);
    expect(md).toContain("# Vaulytica negotiation posture");
    expect(md).toContain("Liability cap");
    expect(md).toContain("Below floor");
    expect(md).toContain("Not stated");
    expect(md).toContain(posture.posture_hash);
    // Advisory disclaimer present — it explicitly does NOT claim legal adequacy.
    expect(md).toMatch(/not whether a term is legally adequate/i);
  });

  it("renders CSV with a formula-injection guard on untrusted author text", () => {
    const evil: NegotiationPosture = {
      ...posture,
      positions: [{ dimension: "=cmd|' /c calc'!A1", tier: "ideal", guidance: "+hack" }],
    };
    const csv = buildNegotiationPostureCsv(evil);
    expect(csv.split("\r\n")[0]).toBe("dimension,tier,finding,guidance,section");
    // Leading formula triggers are neutralized with a single quote.
    expect(csv).toContain("'=cmd");
    expect(csv).toContain("'+hack");
  });

  it("handles an empty posture honestly", () => {
    const empty: NegotiationPosture = {
      counts: { ideal: 0, acceptable: 0, below_acceptable: 0, unevaluable: 0 },
      posture_hash: "0".repeat(64),
      positions: [],
    };
    expect(buildNegotiationPostureMarkdown(empty)).toContain("No negotiation positions");
    expect(buildNegotiationPostureCsv(empty).trim()).toBe(
      "dimension,tier,finding,guidance,section",
    );
  });
});

describe("negotiation sheet (spec-v10 Step 170)", () => {
  it("groups positions by action in priority order (escalate first, hold last)", () => {
    const html = buildNegotiationSheet(posture, "Acme MSA");
    expect(html.startsWith("<!doctype html>")).toBe(true);
    expect(html).not.toContain("<script");
    expect(html).toContain("Negotiation sheet — Acme MSA");
    // The escalate heading precedes the hold heading.
    const esc = html.indexOf("Escalate — below your floor");
    const push = html.indexOf("Push here");
    const hold = html.indexOf("Hold — already at your ideal");
    expect(esc).toBeGreaterThan(0);
    expect(esc).toBeLessThan(push);
    expect(push).toBeLessThan(hold);
  });

  it("escapes author-supplied content (never live markup in a shared sheet)", () => {
    const xss: NegotiationPosture = {
      ...posture,
      positions: [
        { dimension: "<b>Cap</b>", tier: "ideal", guidance: "<script>alert(1)</script>" },
      ],
    };
    const html = buildNegotiationSheet(xss);
    expect(html).toContain("&lt;b&gt;Cap&lt;/b&gt;");
    expect(html).not.toContain("<b>Cap</b>");
    expect(html).not.toContain("<script>alert(1)</script>");
  });

  it("is deterministic and handles an empty posture", () => {
    const empty: NegotiationPosture = {
      counts: { ideal: 0, acceptable: 0, below_acceptable: 0, unevaluable: 0 },
      posture_hash: "0".repeat(64),
      positions: [],
    };
    const a = buildNegotiationSheet(empty);
    expect(a).toBe(buildNegotiationSheet(empty));
    expect(a).toContain("No negotiation positions were defined");
  });
});
