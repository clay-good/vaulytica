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

  it("detects an American Express number in its canonical spaced 4-6-5 grouping", () => {
    // 3782 822463 10005 is a Luhn-valid Amex test number; the 4-4-4 pattern
    // cannot form the 6-digit middle group, so it was previously missed.
    const hits = scanSensitive("Card on file: 3782 822463 10005 (Amex).");
    const card = hits.find((h) => h.type === "card");
    expect(card).toBeDefined();
    expect(card?.masked).toMatch(/0005$/);
    expect(card?.masked).not.toContain("822463");
    // A same-shape run that fails Luhn is still not a card.
    expect(scanSensitive("Ref 1234 567890 12345 end.").some((h) => h.type === "card")).toBe(false);
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

/**
 * Author attribution must not bleed between elements. The forward text scans
 * in `parseComments` / `parseRevisions` used to read a flat character window
 * from the open tag, ignoring where the element ended — so an element with no
 * text of its own (an empty comment, a `w:del` holding only a drawing) walked
 * past its own close and picked up the NEXT element's text. A pre-send report
 * whose entire job is "who wrote what" then credited one author with another's
 * words.
 */
describe("container: text-free elements do not borrow the next element's text", () => {
  it("an empty comment reports no excerpt instead of the following comment's", () => {
    const bytes = buildDocx({
      document: documentXml(`<w:p><w:r><w:t>Body.</w:t></w:r></w:p>`),
      comments:
        `<?xml version="1.0"?><w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
        `<w:comment w:id="0" w:author="Alice"></w:comment>` +
        `<w:comment w:id="1" w:author="Bob"><w:p><w:r><w:t>Redact the penalty.</w:t></w:r></w:p></w:comment>` +
        `</w:comments>`,
    });
    const facts = readContainer(bytes, "docx", "Body.");
    const alice = facts.comments.find((c) => c.author === "Alice");
    const bob = facts.comments.find((c) => c.author === "Bob");
    expect(alice?.excerpt).toBeUndefined();
    expect(bob?.excerpt).toContain("Redact the penalty.");
  });

  it("a text-free revision reports no excerpt instead of the following revision's", () => {
    const bytes = buildDocx({
      document: documentXml(
        `<w:p><w:del w:id="1" w:author="Alice"><w:r><w:drawing/></w:r></w:del>` +
          `<w:ins w:id="2" w:author="Bob"><w:r><w:t>Confidential clause.</w:t></w:r></w:ins></w:p>`,
      ),
    });
    const facts = readContainer(bytes, "docx", "Body.");
    const alice = facts.revisions.find((r) => r.author === "Alice");
    const bob = facts.revisions.find((r) => r.author === "Bob");
    expect(alice?.excerpt).toBeUndefined();
    expect(bob?.excerpt).toContain("Confidential clause.");
  });

  it("still reads the excerpt of an element that does carry its own text", () => {
    const facts = readContainer(trackedChangesDocx(), "docx", "Ordinary visible text.");
    const ins = facts.revisions.find((r) => r.kind === "insertion");
    const del = facts.revisions.find((r) => r.kind === "deletion");
    expect(ins?.excerpt).toContain("indemnify and hold harmless");
    expect(del?.excerpt).toContain("net 30 days");
  });
});

/**
 * Dedup must key on the raw value, not the masked one. Masking reveals only a
 * suffix, so distinct values collapse to identical masks — keying on the mask
 * silently dropped the second value from both the count and the evidence,
 * under-reporting how much sensitive data a document actually carries.
 */
describe("sensitive: distinct values sharing a mask are counted separately", () => {
  it("two SSNs with the same last four are two facts", () => {
    const facts = scanSensitive("SSN 123-45-6789 and also 234-56-6789 on file.");
    expect(facts.filter((f) => f.type === "ssn")).toHaveLength(2);
  });

  it("two emails sharing the first character and domain are two facts", () => {
    const facts = scanSensitive("Contact alice@example.com or adam@example.com for details.");
    expect(facts.filter((f) => f.type === "email")).toHaveLength(2);
  });

  it("two phone numbers with the same last four are two facts", () => {
    const facts = scanSensitive("Call 415-555-1234 or 617-555-1234 today.");
    expect(facts.filter((f) => f.type === "phone")).toHaveLength(2);
  });

  it("still collapses the same value repeated, including across formats", () => {
    const facts = scanSensitive("SSN 123-45-6789 appears again as 123-45-6789 and as 123456789.");
    expect(facts.filter((f) => f.type === "ssn")).toHaveLength(1);
  });

  it("never puts an unmasked value in the output", () => {
    const facts = scanSensitive("SSN 123-45-6789 and email alice@example.com.");
    for (const f of facts) expect(f.masked).toContain("*");
  });
});

/**
 * The dedup key normalizes away formatting noise so one value is counted once.
 * For digit types that is right — "123-45-6789" and "123456789" are one SSN.
 * For an email it is not: `+`, `_`, `%` and `-` are significant in a local
 * part, and stripping them merged two distinct addresses into one. That is the
 * same under-count that keying on the RAW value (rather than the masked value)
 * was introduced to fix, reappearing one layer down — in a scan whose whole
 * job is to say how many addresses a document exposes.
 */
describe("scanSensitive — distinct emails are not merged by the dedup key", () => {
  it.each([
    ["plus tag", "Contact user+tag@example.com or usertag@example.com for details."],
    ["underscore", "Reach first_last@example.com and firstlast@example.com now."],
    ["dot", "Write to a.b@example.com or ab@example.com today."],
  ])("%s: counts both addresses", (_label, text) => {
    expect(scanSensitive(text).filter((f) => f.type === "email")).toHaveLength(2);
  });

  it("still counts one SSN written two ways as a single value", () => {
    const facts = scanSensitive("SSN 123-45-6789 also written 123456789.");
    expect(facts.filter((f) => f.type === "ssn")).toHaveLength(1);
  });
});

describe("scanSensitive — an SSN written without separators", () => {
  // The dashed form was the only one matched. Nine bare digits have no dashes
  // for the SSN pattern, and the bare-9-digit ROUTING pattern drops everything
  // that fails the ABA checksum — so an SSN copied out of a spreadsheet cell
  // produced no finding at all and was disclosed unmasked.
  it("detects a bare-digit SSN and masks it", () => {
    const facts = scanSensitive("Employee SSN: 123456789 on file.");
    const ssn = facts.filter((f) => f.type === "ssn");
    expect(ssn).toHaveLength(1);
    expect(ssn[0]!.masked).toBe("*****6789");
    expect(ssn[0]!.confidence).toBe("low");
    // The value itself must never survive into the fact.
    expect(JSON.stringify(ssn[0])).not.toContain("123456789");
  });

  it("still reports the dashed form at high confidence", () => {
    const ssn = scanSensitive("SSN: 123-45-6789").filter((f) => f.type === "ssn");
    expect(ssn).toHaveLength(1);
    expect(ssn[0]!.confidence).toBe("high");
  });

  it("counts both spellings of one SSN once", () => {
    // Dedup normalizes digit types by stripping separators, and the dashed hit
    // is pushed first, so the surviving fact keeps the higher confidence.
    const ssn = scanSensitive("SSN 123-45-6789 (also written 123456789)").filter(
      (f) => f.type === "ssn",
    );
    expect(ssn).toHaveLength(1);
    expect(ssn[0]!.confidence).toBe("high");
  });

  it("does not report a structurally impossible bare run", () => {
    // Area 000/666/9xx, group 00 and serial 0000 are never issued.
    expect(scanSensitive("Ref 000456789").filter((f) => f.type === "ssn")).toHaveLength(0);
    expect(scanSensitive("Ref 666456789").filter((f) => f.type === "ssn")).toHaveLength(0);
    expect(scanSensitive("Ref 123004567").filter((f) => f.type === "ssn")).toHaveLength(0);
    expect(scanSensitive("Ref 123450000").filter((f) => f.type === "ssn")).toHaveLength(0);
  });
});

describe("scanSensitive — a bare 9-digit run that is not an SSN", () => {
  it("does not also report a validated routing number as an SSN", () => {
    // Wire/ACH details are ordinary contract content. Nine digits satisfying
    // the ABA checksum are a routing number, which the routing scan already
    // reports — the bare-SSN pattern pushed the identical span a second time
    // under a second type, because dedup keys include the type.
    const facts = scanSensitive("Please wire funds using routing number 011401533.");
    expect(facts.filter((f) => f.type === "routing")).toHaveLength(1);
    expect(facts.filter((f) => f.type === "ssn")).toHaveLength(0);
  });

  it("does not find an SSN inside a longer digit run", () => {
    // The pattern is \b-anchored at both ends, so a 10+ digit account number or
    // a 16-digit card cannot yield a spurious 9-digit interior match.
    for (const text of [
      "Account 1234567890 is active.",
      "Order 123456789012 placed.",
      "Card 4111111111111111 on file.",
      "Ref ABC123456789 shipped.",
    ]) {
      expect(scanSensitive(text).filter((f) => f.type === "ssn")).toHaveLength(0);
    }
  });
});
