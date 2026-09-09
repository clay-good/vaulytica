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

const HEADER = [
  "Control",
  "Bates Start",
  "Bates End",
  "Date",
  "Author",
  "Recipients",
  "Privilege",
  "Description",
];

function encodeLog(rows: string[][]): string {
  return [HEADER, ...rows].map(encodeRow).join("\r\n");
}

describe("parsePrivilegeLog — header mapping", () => {
  it("maps synonym headers case-insensitively", () => {
    const csv = encodeLog([
      [
        "LOG-1",
        "ACME_000010",
        "ACME_000012",
        "2024-01-01",
        "Alice",
        "Bob",
        "Attorney-Client",
        "Legal advice re: merger",
      ],
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
    const csv =
      "Control,Bates Range,Privilege,Description\r\nLOG-1,ACME_000010-ACME_000012,AC,desc";
    const log = parsePrivilegeLog(csv);
    expect(log.entries[0]?.bates_start).toBe("ACME_000010");
    expect(log.entries[0]?.bates_end).toBe("ACME_000012");
  });

  it("splits a combined bates range column on 'to'", () => {
    const csv =
      "Control,Bates Range,Privilege,Description\r\nLOG-1,ACME_000010 to ACME_000012,AC,desc";
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

describe("parsePrivilegeLog — audit-round pins", () => {
  it("skips Excel-style all-empty ',,,' trailing rows instead of accusing them", () => {
    const log = parsePrivilegeLog(
      "Bates Start,Privilege,Description\r\nABC_000001,AC,Email\r\n,,\r\n,,\r\n",
    );
    expect(log.entries).toHaveLength(1);
  });
});

/**
 * Which cell shapes become a RANGE, and which stay one id.
 *
 * This decides whether an entry participates in PROD-010/011/012 at all: a
 * cell that fails to split leaves `bates_start` holding the whole string,
 * `parseBates` rejects it, and the entry drops out of every range check —
 * silently. That is the failure the first-hyphen audit finding describes, and
 * mutation testing found `splitBatesRange`'s dash branches executed by no
 * test.
 *
 * 🚨 Measured across the shapes below, one was wrong: an EM-dash range
 * (`PROD_0001—PROD_0009`) did not split. Only the en dash was handled, and a
 * privilege log written in Word — or round-tripped through it — carries
 * whatever its autocorrect produced. This CSV never passes through the
 * ingest normalizer that folds dash variants elsewhere in the tree; it is
 * parsed as typed.
 */
describe("parsePrivilegeLog — what counts as a Bates range", () => {
  const range = (cell: string): [string | undefined, string | undefined] => {
    const log = parsePrivilegeLog(`Bates Range,Description\n"${cell}",memo`);
    const e = log.entries[0];
    return [e?.bates_start, e?.bates_end];
  };

  it.each([
    ["ABC-000124 - ABC-000125", "spaced ASCII hyphen, hyphen-convention ids"],
    ["ABC-000124–ABC-000125", "en dash, no spaces"],
    ["ABC-000124 – ABC-000125", "en dash, spaced"],
    ["ABC-000124—ABC-000125", "EM dash, no spaces"],
    ["ABC-000124 — ABC-000125", "em dash, spaced"],
    ["ABC-000124―ABC-000125", "horizontal bar"],
    ["ABC-000124 to ABC-000131", "the word 'to'"],
  ])("splits %j (%s)", (cell) => {
    const [start, end] = range(cell);
    expect(start, `${cell} did not split — the entry drops out of every range check`).toBe(
      "ABC-000124",
    );
    expect(end).toBeTruthy();
  });

  it("splits a bare hyphen only where both halves are Bates ids", () => {
    expect(range("ABC000124-ABC000125")).toEqual(["ABC000124", "ABC000125"]);
  });

  it("keeps a single hyphen-convention id whole", () => {
    // The case the audit finding is about: "ABC-000124" is one id, and
    // splitting it on its own internal hyphen yields start="ABC".
    expect(range("ABC-000124")).toEqual(["ABC-000124", undefined]);
  });

  it("still splits a cell that is not Bates at all, rather than swallowing it", () => {
    expect(range("Smith Memo - Draft")).toEqual(["Smith Memo", "Draft"]);
    expect(range("DOC 1 to DOC 9")).toEqual(["DOC 1", "DOC 9"]);
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
    const cell = fc
      .string({ minLength: 1 })
      .filter((s) => s.trim().length > 0 && !/^[-–]|to$/i.test(s));
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
