import { describe, expect, it } from "vitest";
import { extractBatesSet } from "./bates.js";
import { parsePrivilegeLog, type PrivilegeLog } from "./privilege-log.js";
import { reconcileProduction } from "./reconcile.js";

const EMPTY_LOG: PrivilegeLog = { entries: [], warnings: [], unmapped_columns: [] };

function filenames(prefix: string, numbers: number[], padding = 6): string[] {
  return numbers.map((n) => `${prefix}_${String(n).padStart(padding, "0")}.pdf`);
}

describe("reconcileProduction — clean production", () => {
  it("returns [] when the sequence is contiguous, unique, and single-prefix", () => {
    const bates = extractBatesSet(filenames("ACME", [1, 2, 3, 4, 5]));
    expect(reconcileProduction({ bates, log: EMPTY_LOG })).toEqual([]);
  });
});

describe("reconcileProduction — PROD-001 sequence gaps", () => {
  it("detects a missing range within a prefix", () => {
    const bates = extractBatesSet(filenames("ACME", [1, 2, 5, 6]));
    const findings = reconcileProduction({ bates, log: EMPTY_LOG });
    const gap = findings.find((f) => f.code === "PROD-001");
    expect(gap).toBeDefined();
    expect(gap?.severity).toBe("warning");
    expect(gap?.detail).toContain("ACME_000003–ACME_000004");
  });
});

describe("reconcileProduction — audit-round pins", () => {
  it("a huge span (1e11) completes instantly via range-walk, no per-integer loop", () => {
    const bates = extractBatesSet(["ABC_00000000001.pdf", "ABC_99999999999.pdf"]);
    const start = performance.now();
    const findings = reconcileProduction({ bates, log: EMPTY_LOG });
    expect(performance.now() - start).toBeLessThan(1000);
    const gap = findings.find((f) => f.code === "PROD-001");
    expect(gap?.detail).toContain("ABC_00000000002–ABC_99999999998");
  });

  it("case-mismatched log prefixes reconcile: PROD-010 fires, no false PROD-011", () => {
    const bates = extractBatesSet(filenames("ABC", [1, 2, 4]));
    const log = parsePrivilegeLog(
      "Bates Start,Bates End,Privilege,Description\nabc_000002,abc_000003,AC,Email\n",
    );
    const findings = reconcileProduction({ bates, log });
    expect(findings.some((f) => f.code === "PROD-010")).toBe(true);
    expect(findings.some((f) => f.code === "PROD-011")).toBe(false);
  });

  it("hyphen-convention Bates in a combined range column parses (PROD-010 fires)", () => {
    const bates = extractBatesSet(["ABC-000123.pdf", "ABC-000124.pdf", "ABC-000125.pdf"]);
    const log = parsePrivilegeLog(
      "Bates Range,Privilege,Description\nABC-000124 - ABC-000124,AC,Memo\n",
    );
    const findings = reconcileProduction({ bates, log });
    expect(findings.some((f) => f.code === "PROD-010")).toBe(true);
  });
});

describe("reconcileProduction — PROD-002 duplicates", () => {
  it("detects the same bates number on two filenames", () => {
    const bates = extractBatesSet(["ACME_000001.pdf", "ACME_000002.pdf", "ACME_000002.docx"]);
    const findings = reconcileProduction({ bates, log: EMPTY_LOG });
    const dup = findings.find((f) => f.code === "PROD-002");
    expect(dup).toBeDefined();
    expect(dup?.detail).toContain("ACME_000002.pdf");
    expect(dup?.detail).toContain("ACME_000002.docx");
  });
});

describe("reconcileProduction — PROD-003 prefix inconsistency", () => {
  it("flags 2+ distinct prefixes as info", () => {
    const bates = extractBatesSet([...filenames("ACME", [1, 2]), ...filenames("ZETA", [1, 2])]);
    const findings = reconcileProduction({ bates, log: EMPTY_LOG });
    const drift = findings.find((f) => f.code === "PROD-003");
    expect(drift).toBeDefined();
    expect(drift?.severity).toBe("info");
    expect(drift?.detail).toContain("ACME");
    expect(drift?.detail).toContain("ZETA");
  });
});

describe("reconcileProduction — PROD-004 padding inconsistency", () => {
  it("flags mixed padding widths within one prefix", () => {
    const bates = extractBatesSet(["ACME_000001.pdf", "ACME_02.pdf"]);
    const findings = reconcileProduction({ bates, log: EMPTY_LOG });
    const padDrift = findings.find((f) => f.code === "PROD-004");
    expect(padDrift).toBeDefined();
    expect(padDrift?.severity).toBe("warning");
  });
});

describe("reconcileProduction — log-based rules", () => {
  it("PROD-010: a withheld log range overlapping a produced bates number", () => {
    const bates = extractBatesSet(filenames("ACME", [10, 11, 12]));
    const csv =
      "Control,Bates Start,Bates End,Privilege,Description\r\nLOG-1,ACME_000011,ACME_000011,Attorney-Client,Legal memo";
    const log = parsePrivilegeLog(csv);
    const findings = reconcileProduction({ bates, log });
    const overlap = findings.find((f) => f.code === "PROD-010");
    expect(overlap).toBeDefined();
    expect(overlap?.severity).toBe("warning");
    expect(overlap?.detail).toContain("ACME_000011.pdf");
  });

  it("PROD-011: a produced gap not covered by any log entry", () => {
    const bates = extractBatesSet(filenames("ACME", [1, 2, 5, 6]));
    const findings = reconcileProduction({ bates, log: EMPTY_LOG });
    const unlogged = findings.find((f) => f.code === "PROD-011");
    expect(unlogged).toBeDefined();
    expect(unlogged?.severity).toBe("info");
  });

  it("PROD-011 does not fire when the gap is covered by a log entry", () => {
    const bates = extractBatesSet(filenames("ACME", [1, 2, 5, 6]));
    const csv =
      "Control,Bates Start,Bates End,Privilege,Description\r\nLOG-1,ACME_000003,ACME_000004,Attorney-Client,Legal memo";
    const log = parsePrivilegeLog(csv);
    const findings = reconcileProduction({ bates, log });
    expect(findings.find((f) => f.code === "PROD-011")).toBeUndefined();
  });

  it("PROD-012: two overlapping log entries", () => {
    const csv =
      "Control,Bates Start,Bates End,Privilege,Description\r\n" +
      "LOG-1,ACME_000010,ACME_000015,Attorney-Client,Memo one\r\n" +
      "LOG-2,ACME_000013,ACME_000018,Attorney-Client,Memo two";
    const log = parsePrivilegeLog(csv);
    const findings = reconcileProduction({ bates: [], log });
    const overlap = findings.find((f) => f.code === "PROD-012");
    expect(overlap).toBeDefined();
    expect(overlap?.severity).toBe("warning");
  });

  it("PROD-013: rows missing privilege or description", () => {
    const csv =
      "Control,Bates Start,Bates End,Privilege,Description\r\n" +
      "LOG-1,ACME_000010,ACME_000011,,Memo one\r\n" +
      "LOG-2,ACME_000012,ACME_000013,Attorney-Client,";
    const log = parsePrivilegeLog(csv);
    const findings = reconcileProduction({ bates: [], log });
    const missing = findings.find((f) => f.code === "PROD-013");
    expect(missing).toBeDefined();
    expect(missing?.severity).toBe("warning");
    expect(missing?.detail).toContain("row 0");
    expect(missing?.detail).toContain("row 1");
  });
});

describe("reconcileProduction — output ordering", () => {
  it("sorts findings by code then detail", () => {
    const bates = extractBatesSet([...filenames("ACME", [1, 3]), ...filenames("ZETA", [1, 2])]);
    const findings = reconcileProduction({ bates, log: EMPTY_LOG });
    const codes = findings.map((f) => f.code);
    const sorted = [...codes].sort();
    expect(codes).toEqual(sorted);
  });
});
