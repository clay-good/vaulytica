import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { parsePrivilegeLog, type PrivilegeLogEntry } from "./privilege-log.js";

/** Tiny local RFC-4180 encoder mirroring csvField's escaping semantics. */
function encodeField(value: string): string {
  if (/[",\r\n]/.test(value)) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

function encodeRow(fields: string[]): string {
  return fields.map(encodeField).join(",");
}

const HEADER = ["Control", "Bates Start", "Bates End", "Date", "Author", "Recipients", "Privilege", "Description"];

function encodeLog(rows: string[][]): string {
  return [HEADER, ...rows].map(encodeRow).join("\r\n");
}

describe("parsePrivilegeLog — header mapping", () => {
  it("maps synonym headers case-insensitively", () => {
    const csv = encodeLog([
      ["LOG-1", "ACME_000010", "ACME_000012", "2024-01-01", "Alice", "Bob", "Attorney-Client", "Legal advice re: merger"],
    ]);
    const log = parsePrivilegeLog(csv);
    expect(log.unmapped_columns).toEqual([]);
    expect(log.entries).toHaveLength(1);
    expect(log.entries[0]).toEqual({
      control: "LOG-1",
      bates_start: "ACME_000010",
      bates_end: "ACME_000012",
      date: "2024-01-01",
      author: "Alice",
      recipients: "Bob",
      privilege: "Attorney-Client",
      description: "Legal advice re: merger",
      row_index: 0,
    });
  });

  it("splits a combined bates range column on a hyphen", () => {
    const csv = "Control,Bates Range,Privilege,Description\r\nLOG-1,ACME_000010-ACME_000012,AC,desc";
    const log = parsePrivilegeLog(csv);
    expect(log.entries[0]?.bates_start).toBe("ACME_000010");
    expect(log.entries[0]?.bates_end).toBe("ACME_000012");
  });

  it("splits a combined bates range column on 'to'", () => {
    const csv = "Control,Bates Range,Privilege,Description\r\nLOG-1,ACME_000010 to ACME_000012,AC,desc";
    const log = parsePrivilegeLog(csv);
    expect(log.entries[0]?.bates_start).toBe("ACME_000010");
    expect(log.entries[0]?.bates_end).toBe("ACME_000012");
  });

  it("records unrecognized columns as unmapped_columns, not errors", () => {
    const csv = "Control,Custom Field,Privilege,Description\r\nLOG-1,foo,AC,desc";
    const log = parsePrivilegeLog(csv);
    expect(log.unmapped_columns).toEqual(["Custom Field"]);
    expect(log.entries).toHaveLength(1);
  });

  it("returns empty entries + warning when no header is recognizable", () => {
    const csv = "Foo,Bar,Baz\r\n1,2,3";
    const log = parsePrivilegeLog(csv);
    expect(log.entries).toEqual([]);
    expect(log.warnings.length).toBeGreaterThan(0);
  });

  it("returns empty entries + warning for empty input", () => {
    const log = parsePrivilegeLog("");
    expect(log.entries).toEqual([]);
    expect(log.warnings.length).toBeGreaterThan(0);
  });
});

describe("parsePrivilegeLog — RFC-4180 quoting", () => {
  it("handles quoted fields containing commas", () => {
    const csv = 'Control,Privilege,Description\r\nLOG-1,AC,"Memo, re: settlement"';
    const log = parsePrivilegeLog(csv);
    expect(log.entries[0]?.description).toBe("Memo, re: settlement");
  });

  it("handles quoted fields containing embedded newlines", () => {
    const csv = 'Control,Privilege,Description\r\nLOG-1,AC,"Line one\nLine two"';
    const log = parsePrivilegeLog(csv);
    expect(log.entries[0]?.description).toBe("Line one\nLine two");
  });

  it("handles escaped double quotes", () => {
    const csv = 'Control,Privilege,Description\r\nLOG-1,AC,"She said ""privileged"""';
    const log = parsePrivilegeLog(csv);
    expect(log.entries[0]?.description).toBe('She said "privileged"');
  });

  it("recovers from an unterminated quote without throwing", () => {
    const csv = 'Control,Privilege,Description\r\nLOG-1,AC,"unterminated';
    const log = parsePrivilegeLog(csv);
    expect(log.warnings.some((w) => /unterminated/i.test(w))).toBe(true);
    expect(log.entries).toHaveLength(1);
  });
});

describe("parsePrivilegeLog — properties", () => {
  it("never throws on arbitrary strings", () => {
    fc.assert(
      fc.property(fc.string(), (s) => {
        expect(() => parsePrivilegeLog(s)).not.toThrow();
      }),
    );
  });

  it("round-trips CSVs produced by a matching RFC-4180 encoder", () => {
    const cell = fc.string({ minLength: 1 }).filter((s) => s.trim().length > 0 && !/^[-–]|to$/i.test(s));
    fc.assert(
      fc.property(
        fc.array(fc.tuple(cell, cell, cell, cell), { minLength: 1, maxLength: 8 }),
        (rows) => {
          const dataRows = rows.map(([control, author, privilege, description]) => [
            control,
            "ACME_000001",
            "ACME_000002",
            "2024-01-01",
            author,
            "recipient",
            privilege,
            description,
          ]);
          const csv = encodeLog(dataRows);
          const log = parsePrivilegeLog(csv);
          expect(log.entries).toHaveLength(rows.length);
          log.entries.forEach((entry: PrivilegeLogEntry, i: number) => {
            const [control, author, privilege, description] = rows[i]!;
            expect(entry.control).toBe(control.trim());
            expect(entry.author).toBe(author.trim());
            expect(entry.privilege).toBe(privilege.trim());
            expect(entry.description).toBe(description.trim());
          });
        },
      ),
    );
  });
});
