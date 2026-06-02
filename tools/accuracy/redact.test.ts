import { describe, expect, it } from "vitest";
import { redact } from "./redact.js";

describe("corpus redaction (spec-v5 §4)", () => {
  it("masks emails, phones, and id numbers, logging each", () => {
    const { text, log } = redact(
      "Contact jane@acme.com or (415) 555-0199. EIN 12-3456789. Acct 1234567890123.",
    );
    expect(text).toContain("[EMAIL]");
    expect(text).toContain("[PHONE]");
    expect(text).toContain("[ID-NUMBER]");
    expect(text).toContain("[ACCOUNT]");
    expect(text).not.toContain("jane@acme.com");
    const kinds = log.map((e) => e.kind);
    expect(kinds).toContain("email");
    expect(kinds).toContain("phone");
    expect(kinds).toContain("account-number");
  });

  it("masks supplied party names with stable, length-ordered placeholders", () => {
    const { text, log } = redact(
      "Acme Corporation and Beta LLC agree. Acme Corporation shall pay Beta LLC.",
      ["Acme Corporation", "Beta LLC"],
    );
    expect(text).not.toContain("Acme Corporation");
    expect(text).not.toContain("Beta LLC");
    expect(text).toContain("[PARTY-1]");
    expect(text).toContain("[PARTY-2]");
    const party = log.find((e) => e.replacement === "[PARTY-1]");
    expect(party?.count).toBe(2);
  });

  it("does not touch clause structure (headings, defined terms, governing law)", () => {
    const src =
      '1. CONFIDENTIALITY. "Confidential Information" means X. This Agreement is governed by the laws of the State of Delaware.';
    const { text } = redact(src, ["X Corp"]);
    expect(text).toContain("1. CONFIDENTIALITY.");
    expect(text).toContain('"Confidential Information" means');
    expect(text).toContain("governed by the laws of the State of Delaware");
  });

  it("is deterministic — same input, byte-identical output and log", () => {
    const src = "Reach me at a@b.co or 212-555-1212. Acme Inc. signs.";
    const r1 = redact(src, ["Acme Inc."]);
    const r2 = redact(src, ["Acme Inc."]);
    expect(r1.text).toBe(r2.text);
    expect(JSON.stringify(r1.log)).toBe(JSON.stringify(r2.log));
  });

  it("returns an empty log when there is nothing to redact", () => {
    const { text, log } = redact("This Agreement has no identifying detail.");
    expect(text).toBe("This Agreement has no identifying detail.");
    expect(log).toEqual([]);
  });
});
