import { describe, it, expect } from "vitest";
import { readContainer } from "./container.js";
import { deriveHandoffFindings } from "./handoff.js";
import { scanSensitive } from "./sensitive.js";
import { maskDigits, maskEmail, luhnValid, ssnStructurallyValid } from "./mask.js";
import { scanDelivery } from "./index.js";
import {
  trackedChangesDocx,
  hiddenContentDocx,
  metadataLeakDocx,
  truncatedDocx,
  malformedCommentsDocx,
  authorlessRevisionDocx,
  notAZip,
  buildDocx,
  documentXml,
} from "./_fixtures.js";

describe("container read — tracked changes & comments (HANDOFF-001/002)", () => {
  it("recovers insertions, deletions and the comment store with authors", () => {
    const facts = readContainer(trackedChangesDocx(), "docx", "Ordinary visible text.");
    expect(facts.inspectable).toBe(true);
    const kinds = facts.revisions.map((r) => r.kind).sort();
    expect(kinds).toEqual(["deletion", "insertion"]);
    expect(facts.revisions.find((r) => r.kind === "insertion")?.author).toBe("Opposing Counsel");
    expect(facts.revisions.find((r) => r.kind === "insertion")?.excerpt).toContain("indemnify");
    expect(facts.comments).toHaveLength(1);
    expect(facts.comments[0]?.author).toBe("Reviewer Bob");
  });

  it("derives critical HANDOFF-001 and HANDOFF-002 findings", () => {
    const facts = readContainer(trackedChangesDocx(), "docx", "x");
    const findings = deriveHandoffFindings(facts);
    const h1 = findings.find((f) => f.rule_id === "HANDOFF-001");
    const h2 = findings.find((f) => f.rule_id === "HANDOFF-002");
    expect(h1?.severity).toBe("critical");
    expect(h1?.count).toBe(2);
    expect(h2?.severity).toBe("critical");
    expect(h2?.count).toBe(1);
  });
});

describe("hidden content (HANDOFF-003)", () => {
  it("recovers w:vanish runs and reports the span", () => {
    const facts = readContainer(hiddenContentDocx(), "docx", "Visible paragraph.");
    const vanish = facts.hidden.find((h) => h.kind === "vanish");
    expect(vanish?.excerpt).toContain("internal margin");
    const findings = deriveHandoffFindings(facts);
    expect(findings.find((f) => f.rule_id === "HANDOFF-003")?.severity).toBe("warning");
  });
});

describe("authoring metadata (HANDOFF-004)", () => {
  it("reads core.xml and app.xml verbatim", () => {
    const facts = readContainer(metadataLeakDocx(), "docx", "Body.");
    const fields = Object.fromEntries(facts.metadata.map((m) => [m.field, m.value]));
    expect(fields.creator).toBe("Alex Drafter");
    expect(fields.company).toBe("Globex Corporation");
    expect(fields.template).toContain("PriorClient_MSA");
  });

  it("flags a cross-matter leak when an identity field is not a named party", () => {
    const facts = readContainer(metadataLeakDocx(), "docx", "Body.");
    // Parties are Acme and Vaulytica; Globex is not among them.
    const findings = deriveHandoffFindings(facts, ["Acme LLC", "Vaulytica Inc"]);
    const h4 = findings.find((f) => f.rule_id === "HANDOFF-004");
    expect(h4?.severity).toBe("critical");
    expect(h4?.evidence.some((e) => e.includes("not a named party"))).toBe(true);
  });

  it("does not over-claim a cross-matter leak when the entity is a party", () => {
    // Company is the only entity field and it matches a party; the bare author
    // name never elevates on its own (§12).
    const core = `<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Alex Drafter</dc:creator></cp:coreProperties>`;
    const app = `<?xml version="1.0"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Company>Globex Corporation</Company></Properties>`;
    const bytes = buildDocx({
      document: documentXml(`<w:p><w:r><w:t>Body.</w:t></w:r></w:p>`),
      core,
      app,
    });
    const facts = readContainer(bytes, "docx", "Body.");
    const findings = deriveHandoffFindings(facts, ["Globex Corporation", "Acme LLC"]);
    const h4 = findings.find((f) => f.rule_id === "HANDOFF-004");
    expect(h4?.severity).not.toBe("critical");
  });
});

describe("sensitive-data scan (HANDOFF-005)", () => {
  it("matches a structurally-valid SSN and masks it", () => {
    const hits = scanSensitive("Employee SSN: 123-45-6789 on file.");
    const ssn = hits.find((h) => h.type === "ssn");
    expect(ssn?.confidence).toBe("high");
    expect(ssn?.masked).toBe("***-**-6789");
    expect(ssn?.masked).not.toContain("123");
  });

  it("rejects SSNs in never-issued ranges", () => {
    expect(scanSensitive("000-12-3456").some((h) => h.type === "ssn")).toBe(false);
    expect(scanSensitive("666-12-3456").some((h) => h.type === "ssn")).toBe(false);
  });

  it("matches only Luhn-valid card candidates", () => {
    const good = scanSensitive("Card 4242 4242 4242 4242 charged.");
    expect(good.find((h) => h.type === "card")?.masked).toMatch(/\*+ ?.*4242$/);
    const bad = scanSensitive("Invoice 1234 5678 9012 3456 issued.");
    expect(bad.some((h) => h.type === "card")).toBe(false);
  });

  it("never echoes an unmasked value (the §Part XIV invariant)", () => {
    const text = "SSN 123-45-6789, card 4242424242424242, dob 01/02/1980, jane@example.com";
    const facts = readContainer(
      buildDocx({ document: documentXml(`<w:p><w:r><w:t>${text}</w:t></w:r></w:p>`) }),
      "docx",
      text,
    );
    const findings = deriveHandoffFindings(facts);
    const joined = JSON.stringify(findings);
    expect(joined).not.toContain("123-45-6789");
    expect(joined).not.toContain("4242424242424242");
    expect(joined).not.toContain("jane@example.com");
  });
});

describe("masking helpers", () => {
  it("masks digits revealing only the tail", () => {
    expect(maskDigits("123-45-6789", 4)).toBe("***-**-6789");
    expect(maskDigits("4242424242424242", 4)).toBe("************4242");
  });
  it("masks an email to first char + domain", () => {
    expect(maskEmail("jane.doe@example.com")).toBe("j***@example.com");
  });
  it("validates Luhn", () => {
    expect(luhnValid("4242424242424242")).toBe(true);
    expect(luhnValid("1234567890123456")).toBe(false);
  });
  it("validates SSN structure", () => {
    expect(ssnStructurallyValid("123", "45", "6789")).toBe(true);
    expect(ssnStructurallyValid("900", "45", "6789")).toBe(false);
    expect(ssnStructurallyValid("123", "00", "6789")).toBe(false);
  });
});

describe("totality contract — never throws, never asserts cleanliness", () => {
  const malformed: Array<[string, ArrayBuffer]> = [
    ["truncated document.xml", truncatedDocx()],
    ["malformed comments.xml", malformedCommentsDocx()],
    ["authorless revision", authorlessRevisionDocx()],
    ["not a zip", notAZip()],
    ["empty", new ArrayBuffer(0)],
  ];
  for (const [name, bytes] of malformed) {
    it(`resolves to typed facts for: ${name}`, () => {
      expect(() => readContainer(bytes, "docx", "text")).not.toThrow();
      const facts = readContainer(bytes, "docx", "text");
      expect(Array.isArray(facts.revisions)).toBe(true);
    });
  }

  it("an authorless revision still counts as a tracked change", () => {
    const facts = readContainer(authorlessRevisionDocx(), "docx", "added");
    expect(facts.revisions).toHaveLength(1);
    expect(facts.revisions[0]?.author).toBeUndefined();
  });

  it("pasted text reports honestly that there is no container", () => {
    const facts = readContainer(new ArrayBuffer(8), "paste", "some pasted text");
    expect(facts.inspectable).toBe(false);
    expect(facts.note).toMatch(/no container/i);
  });
});

describe("PDF container read", () => {
  // A minimal PDF byte stream carrying an Info dictionary with literal and
  // hex string values — enough to exercise the metadata parser deterministically.
  function minimalPdf(): ArrayBuffer {
    const text =
      "%PDF-1.7\n" +
      "1 0 obj\n<< /Title (Acme Master Services Agreement) /Author (Jane Q. Drafter) " +
      "/Creator <4d6963726f736f667420576f7264> /Producer (pdf-lib) >>\nendobj\n" +
      "trailer\n<< /Info 1 0 R >>\n%%EOF\n";
    const bytes = new TextEncoder().encode(text);
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
  }

  it("reads the Info dictionary (literal and hex strings)", () => {
    const facts = readContainer(minimalPdf(), "pdf", "body text");
    expect(facts.inspectable).toBe(true);
    const fields = Object.fromEntries(facts.metadata.map((m) => [m.field, m.value]));
    expect(fields.title).toBe("Acme Master Services Agreement");
    expect(fields.author).toBe("Jane Q. Drafter");
    expect(fields.creator).toBe("Microsoft Word"); // decoded from hex
  });

  it("notes its reach honestly (uncompressed regions only), without asserting cleanliness", () => {
    const facts = readContainer(minimalPdf(), "pdf", "x");
    expect(facts.note).toMatch(/not recovered/i);
    expect(facts.note).toMatch(/compressed object stream|encrypted/i);
    expect(facts.revisions).toHaveLength(0);
  });

  it("scans PDF body text for sensitive data", () => {
    const facts = readContainer(minimalPdf(), "pdf", "SSN 123-45-6789 here");
    expect(facts.sensitive.some((s) => s.type === "ssn")).toBe(true);
  });

  // A PDF with reviewer annotations: a sticky note (Text), a strikeout with a
  // note (StrikeOut + /Contents), and a bare highlight (no /Contents).
  function annotatedPdf(): ArrayBuffer {
    const text =
      "%PDF-1.7\n" +
      "1 0 obj\n<< /Type /Annot /Subtype /Text /T (Opposing Counsel) " +
      "/Contents (please revise this indemnity) /Rect [10 10 20 20] >>\nendobj\n" +
      "2 0 obj\n<< /Type /Annot /Subtype /StrikeOut /T (Jane Partner) " +
      "/Contents <64656c657465> /Rect [30 30 40 40] >>\nendobj\n" +
      "3 0 obj\n<< /Type /Annot /Subtype /Highlight /Rect [50 50 60 60] >>\nendobj\n" +
      "trailer\n<< >>\n%%EOF\n";
    const bytes = new TextEncoder().encode(text);
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
  }

  it("recovers reviewer markup/comment annotations (sticky notes + text markup)", () => {
    const facts = readContainer(annotatedPdf(), "pdf", "body");
    expect(facts.comments).toHaveLength(3);
    const sticky = facts.comments.find((c) => c.author === "Opposing Counsel");
    expect(sticky?.excerpt).toBe("please revise this indemnity");
    const strike = facts.comments.find((c) => c.author === "Jane Partner");
    expect(strike?.excerpt).toBe("delete"); // hex-decoded /Contents
    // A bare highlight with no /Contents still reports the mark, by label.
    expect(facts.comments.some((c) => c.excerpt === "[highlight]")).toBe(true);
  });

  it("never pulls a neighbouring annotation's note across the object boundary", () => {
    const facts = readContainer(annotatedPdf(), "pdf", "body");
    // The bare highlight (object 3) must not inherit object 2's strikeout note.
    const highlight = facts.comments.find((c) => c.excerpt === "[highlight]");
    expect(highlight).toBeDefined();
    expect(highlight?.author).toBeUndefined();
  });

  it("stays total and fast on a pathological annotation blob (ReDoS-safe)", () => {
    // Thousands of subtypes, an unterminated /Contents literal, and a huge
    // unbroken run — the bounded linear regexes must finish quickly and never
    // throw (the repo's ReDoS-free + totality contract).
    const evil =
      "%PDF-1.7\n" +
      "/Subtype /Text /Contents (" +
      "A".repeat(50000) + // never closed
      "/Subtype /Highlight ".repeat(5000) +
      "(".repeat(20000) +
      "\n%%EOF\n";
    const bytes = new TextEncoder().encode(evil);
    const buf = bytes.buffer.slice(
      bytes.byteOffset,
      bytes.byteOffset + bytes.byteLength,
    ) as ArrayBuffer;
    const start = performance.now();
    const facts = readContainer(buf, "pdf", "x");
    expect(performance.now() - start).toBeLessThan(1000);
    expect(facts.inspectable).toBe(true);
    // Bounded output: never unbounded, never a throw.
    expect(facts.comments.length).toBeLessThanOrEqual(2000);
  });
});

describe("non-container sources", () => {
  it("reports image-only input has no container", () => {
    const facts = readContainer(new ArrayBuffer(16), "image", "");
    expect(facts.inspectable).toBe(false);
    expect(facts.note).toMatch(/image/i);
  });
  it("reports an unknown source honestly", () => {
    const facts = readContainer(new ArrayBuffer(16), "unknown", "");
    expect(facts.inspectable).toBe(false);
  });
});

describe("delivery report aggregate", () => {
  it("produces a stable delivery_hash and a presence-only summary", async () => {
    const report = await scanDelivery({
      bytes: trackedChangesDocx(),
      source: "docx",
      text: "Ordinary visible text.",
    });
    expect(report.delivery_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(report.summary).toMatch(/tracked change/);
    expect(report.summary).toMatch(/review before sending/);
    // Determinism: a second run over the same bytes yields the same hash.
    const again = await scanDelivery({
      bytes: trackedChangesDocx(),
      source: "docx",
      text: "Ordinary visible text.",
    });
    expect(again.delivery_hash).toBe(report.delivery_hash);
  });

  it("never claims a clean bill of health on an uninspectable input", async () => {
    const report = await scanDelivery({
      bytes: new ArrayBuffer(4),
      source: "paste",
      text: "hello",
    });
    expect(report.summary).not.toMatch(/\bclean\b|\bsafe\b/i);
  });

  it("a metadata-clean, text-only document yields no findings (additive — no result_hash move)", async () => {
    const bytes = buildDocx({
      document: documentXml(`<w:p><w:r><w:t>Just plain prose, nothing else.</w:t></w:r></w:p>`),
    });
    const report = await scanDelivery({
      bytes,
      source: "docx",
      text: "Just plain prose, nothing else.",
    });
    expect(report.findings).toHaveLength(0);
  });
});
