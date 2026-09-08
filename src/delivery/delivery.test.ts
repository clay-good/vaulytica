import { describe, it, expect } from "vitest";
import { readContainer } from "./container.js";
import { deriveHandoffFindings } from "./handoff.js";
import { MAX_PER_TYPE, MAX_SCAN_CHARS, scanSensitive } from "./sensitive.js";
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
    // 🚨 THE POSITIVE ASSERTION IS LOAD-BEARING, and this test did not have it.
    // Every check below is a `not.toContain`, and a run that produced NO
    // FINDINGS satisfies all three — `joined` is "[]", which contains none of
    // them. Proven by making `scanSensitive` return an empty array: seventeen
    // tests in this file went red and THIS ONE stayed green, while the
    // invariant it exists to defend — a draft's SSN never reaching the report —
    // was no longer being tested at all.
    //
    // A test built only from negative assertions passes hardest when nothing
    // happened. Say what must have been found before saying what must not have
    // been echoed.
    expect(findings.some((f) => f.rule_id === "HANDOFF-005")).toBe(true);
    expect(joined).toContain("6789");
    expect(joined).toContain("4242");
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
  /**
   * The masking module's safety paths, which its tests did not reach.
   *
   * `maskEmail`'s "I cannot parse this as an email" branch came back
   * **NoCoverage** — and it is the safest failure the function has: reveal
   * nothing rather than guess at a local part. If it broke, the fallback for an
   * unparseable value is to return something, and the something would be the
   * value.
   *
   * `luhnValid`'s length window is the false-positive control for card numbers:
   * a 12-digit run is too short to be one and a 20-digit run too long, and the
   * scan reports a Luhn-valid run as a card candidate. Nothing tested either
   * end.
   */
  it("reveals nothing when a value cannot be parsed as an email", () => {
    expect(maskEmail("notanemail")).toBe("***");
    expect(maskEmail("@example.com")).toBe("***");
    expect(maskEmail("")).toBe("***");
    // And still masks a real one, so the branch above is the fallback and not
    // the whole function.
    expect(maskEmail("jane@example.com")).toBe("j***@example.com");
  });

  it("rejects digit runs outside the card-length window", () => {
    // 13–19 digits is the range a payment card occupies. Outside it, a
    // Luhn-valid run is an invoice or part number, not a card.
    expect(luhnValid("424242424242")).toBe(false); // 12
    expect(luhnValid("42424242424242424242")).toBe(false); // 20
    // Separators do not change the length that matters.
    expect(luhnValid("4242-4242-4242-4242")).toBe(true);
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
    // The summary must SAY something before it can be checked for what it must
    // not say: a blank summary matches no forbidden word and claims nothing.
    expect(report.summary.trim().length).toBeGreaterThan(0);
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
    // The count first, and not as decoration. Every assertion in this test is
    // inside the loop, so a scanner that found NOTHING would satisfy it — and
    // this is the check standing between a draft and a leaked SSN. "Nothing
    // was unmasked" and "nothing was found" must not look the same here.
    expect(facts.map((f) => f.type).sort()).toEqual(["email", "ssn"]);
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

/**
 * The three paths mutation testing found nobody had exercised.
 *
 * When `src/delivery/sensitive.ts` joined the mutated set, five of its mutants
 * came back **NoCoverage** — not "survived", but never executed at all. Two of
 * them were real gaps in the check whose failure direction is a leak:
 *
 *  - the whole `EIN` branch, so a document's employer identification number was
 *    detected by code no test had ever run;
 *  - `text.slice(0, MAX_SCAN_CHARS)`, the cap that decides how much of a
 *    document is looked at.
 *
 * The second was worse than untested. It was **silent**: everything past the
 * cap is invisible to the scan, and the report said nothing, so a 6 MB document
 * with an SSN in its last megabyte produced the same clean bill of health as a
 * document that had none.
 */
describe("scanSensitive — the paths nothing had executed", () => {
  it("finds an EIN, which no test had ever reached", () => {
    const facts = scanSensitive("Vendor EIN 12-3456789 on file for 1099 reporting.");
    const ein = facts.find((f) => f.type === "ein");
    expect(ein).toBeDefined();
    // Masked like every other digit type: only the tail survives.
    expect(ein!.masked).toContain("*");
    expect(ein!.masked).not.toContain("12-3456789");
  });

  it("stops at the scan cap", () => {
    // Past the cap the value is invisible — that is the behaviour, and it is
    // the reason the caveat below has to exist.
    const filler = "x".repeat(MAX_SCAN_CHARS);
    expect(scanSensitive(`${filler} SSN 123-45-6789.`).some((f) => f.type === "ssn")).toBe(false);
    // The same value inside the cap is found, so the negative above is the cap
    // and not the pattern.
    expect(scanSensitive("SSN 123-45-6789.").some((f) => f.type === "ssn")).toBe(true);
  });

  it("SAYS SO when the cap bit — a partial scan must not read as a clean one", () => {
    const oversized = `${"x".repeat(MAX_SCAN_CHARS)} SSN 123-45-6789.`;
    const facts = readContainer(new ArrayBuffer(0), "paste", oversized);
    expect(facts.note).toContain("was not scanned");
    expect(facts.note).toContain(MAX_SCAN_CHARS.toLocaleString("en-US"));
  });

  it("says nothing extra about reach when the whole document was read", () => {
    const facts = readContainer(new ArrayBuffer(0), "paste", "SSN 123-45-6789.");
    // The positive half first — this pack's own guard requires it, and it is
    // right to: a `readContainer` that returned nothing would carry no reach
    // caveat either, and the assertion below would pass for the wrong reason.
    expect(facts.sensitive.some((f) => f.type === "ssn")).toBe(true);
    expect(facts.note).not.toContain("was not scanned");
  });
});

/**
 * Every bound in this pack is now SAID.
 *
 * 9.553.0 fixed the scan's 5 MB character cap, which was silent. Two more were
 * hiding beside it, and the rule is the same for all three: **a bound that is
 * not stated is a number the reader trusts and should not.**
 *
 *  - `MAX_PER_TYPE` stops at 200 distinct values per type. The finding still
 *    fires, so the document is never called clean — but its count stops being a
 *    total and becomes a floor, and "247 SSNs" and "200 SSNs" are different
 *    facts to act on.
 *  - The PDF path reads the first `MAX_PART_BYTES` of the container. The
 *    existing note was careful about compressed streams and encrypted regions
 *    and said nothing about the part of the file it never opened.
 */
describe("the pre-disclosure scan states its bounds", () => {
  it("says when the per-type cap was reached, and names the type", () => {
    // 250 distinct, structurally valid SSNs: more than the cap.
    const ssns: string[] = [];
    for (let i = 0; i < 250; i++) {
      const serial = String(1000 + i).padStart(4, "0");
      ssns.push(`123-45-${serial}`);
    }
    const facts = readContainer(new ArrayBuffer(0), "paste", ssns.join(" and "));
    expect(facts.sensitive.filter((f) => f.type === "ssn")).toHaveLength(MAX_PER_TYPE);
    expect(facts.note).toContain("a floor, not a total");
    expect(facts.note).toContain("ssn");
  });

  it("says nothing about the cap when it was not reached", () => {
    const facts = readContainer(new ArrayBuffer(0), "paste", "SSN 123-45-6789.");
    // Positive first: the scan ran and found the value.
    expect(facts.sensitive.some((f) => f.type === "ssn")).toBe(true);
    expect(facts.note ?? "").not.toContain("a floor, not a total");
  });
});

/**
 * The fourth bound, and the last one in this pack that was silent.
 *
 * Each container fact array stops at `MAX_FACTS`, so a document with 3,000
 * tracked changes reports 2,000 — and the closing checklist then tells a
 * reviewer to clear "2,000 tracked changes", a floor presented as a total.
 *
 * The comparison DOCX had the right answer for its own cap all along:
 * `MAX_REDLINE_ROWS`'s comment says it "shows the first N and an honest 'and X
 * more' footer rather than truncating silently". This is that, for the
 * container scan.
 */
describe("the container scan states its fact cap", () => {
  it("says when a fact kind hit the cap, and names the kind", () => {
    // More tracked insertions than the cap allows.
    const runs = Array.from(
      { length: 2100 },
      (_, i) => `<w:ins w:author="A"><w:r><w:t>edit ${i}</w:t></w:r></w:ins>`,
    ).join("");
    const facts = readContainer(
      buildDocx({ document: documentXml(`<w:p>${runs}</w:p>`) }),
      "docx",
      "body text",
    );
    // Positive first: the scan really did read 2,000 of them.
    expect(facts.revisions.length).toBe(2000);
    expect(facts.note).toContain("a floor, not a total");
    expect(facts.note).toContain("tracked changes");
  });

  it("says nothing about the cap for an ordinary redline", () => {
    const facts = readContainer(
      buildDocx({
        document: documentXml(
          '<w:p><w:ins w:author="A"><w:r><w:t>one edit</w:t></w:r></w:ins></w:p>',
        ),
      }),
      "docx",
      "body text",
    );
    expect(facts.revisions.length).toBe(1);
    expect(facts.note ?? "").not.toContain("a floor, not a total");
  });
});

/**
 * Four behaviours the leak scanner has and its tests did not pin.
 *
 * Read off `sensitive.ts`'s surviving mutants after 9.556.0 took the module to
 * 75%. Each is a real difference rather than one of the regex-alternation
 * variations that are equivalent in practice:
 *
 *  - the entire **DOB** loop body could be emptied with nothing failing — the
 *    same shape as the EIN branch 9.553.0 found, one sensitive type further on;
 *  - the **ABA checksum** could be made always-true, so nothing asserted that a
 *    random nine-digit run is *rejected* as a routing number;
 *  - every **confidence** label could be rewritten, and confidence is what
 *    drives the finding's severity;
 *  - the **canonical sort** could be removed, and the whole point of it is that
 *    `delivery_hash` is stable.
 */
describe("scanSensitive — the behaviours its own mutants exposed", () => {
  it("finds a date of birth", () => {
    const dob = scanSensitive("Employee DOB: 04/17/1982 on file.").find((f) => f.type === "dob");
    expect(dob).toBeDefined();
    // Fully masked: a birth date reveals nothing useful in a location report.
    expect(dob!.masked).not.toContain("1982");
  });

  it("rejects a nine-digit run that fails the ABA checksum", () => {
    // The guard that keeps an invoice or part number from being reported as a
    // bank routing number. 021000021 is a real, checksum-valid ABA; 123456789
    // is not, and it must not be reported.
    expect(scanSensitive("Wire to routing 021000021.").some((f) => f.type === "routing")).toBe(
      true,
    );
    expect(
      scanSensitive("Reference number 123456789 for the order.").some((f) => f.type === "routing"),
    ).toBe(false);
  });

  it("attaches the confidence each type is reported at", () => {
    // Confidence drives the finding's severity, so a swapped label is a
    // silently different report. Pinned per type rather than in aggregate.
    const facts = scanSensitive(
      "SSN 123-45-6789, card 4242424242424242, routing 021000021, EIN 12-3456789, " +
        "DOB: 04/17/1982, jane@example.com, 415-555-1234.",
    );
    const at = (t: string): string | undefined => facts.find((f) => f.type === t)?.confidence;
    expect(at("ssn")).toBe("high");
    expect(at("card")).toBe("high");
    expect(at("routing")).toBe("medium");
    expect(at("ein")).toBe("medium");
    expect(at("dob")).toBe("medium");
    expect(at("email")).toBe("low");
    expect(at("phone")).toBe("low");
  });

  it("returns a canonical order, which is what makes delivery_hash stable", () => {
    const text = "jane@example.com and SSN 123-45-6789 and 415-555-1234 and card 4242424242424242.";
    const facts = scanSensitive(text);
    expect(facts.length).toBeGreaterThan(3);
    // By type, then by masked value — and NOT the order they appear in the text,
    // which is what a hash over the list would otherwise depend on.
    const keys = facts.map((f) => `${f.type}|${f.masked}`);
    expect(keys).toEqual([...keys].sort());
  });
});
