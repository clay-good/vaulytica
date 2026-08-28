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

describe("reconcileProduction — PROD-010 over a ranged produced member", () => {
  it("flags a withheld range landing inside a produced member's span", () => {
    // The produced member covers 100-200. The log withholds 150-160, squarely
    // inside it. Testing only the member's START number (100) against the
    // withheld range missed this entirely, so a genuine privilege waiver went
    // unreported.
    const bates = extractBatesSet(["ACME_000100-000200.pdf"]);
    const log = parsePrivilegeLog(
      "Beg Bates,End Bates,Description,Privilege\nACME_000150,ACME_000160,Memo,AC\n",
    );
    const findings = reconcileProduction({ bates, log });
    expect(findings.some((f) => f.code === "PROD-010")).toBe(true);
  });

  it("does not flag a withheld range that misses the span entirely", () => {
    const bates = extractBatesSet(["ACME_000100-000200.pdf"]);
    const log = parsePrivilegeLog(
      "Beg Bates,End Bates,Description,Privilege\nACME_000300,ACME_000310,Memo,AC\n",
    );
    const findings = reconcileProduction({ bates, log });
    expect(findings.some((f) => f.code === "PROD-010")).toBe(false);
  });
});

describe("reconcileProduction — a bare-digit range end in the log", () => {
  const produced = extractBatesSet(["ACME_000100.pdf", "ACME_000200.pdf"]);
  const csv = (end: string) =>
    `Beg Bates,End Bates,Description,Privilege\nACME_000101,${end},Memo,AC\n`;

  it("accounts for the produced-set gap the same as a fully-prefixed end", () => {
    // "ACME_000101" .. "000199" is an ordinary way to write a range. The bare
    // end used to read as a prefix mismatch, the row was dropped, and the gap
    // it covers was reported as UNLOGGED — a false PROD-011 against a correct
    // log, on one of the two codes the CI gate exits 2 on.
    const bare = reconcileProduction({ bates: produced, log: parsePrivilegeLog(csv("000199")) });
    const full = reconcileProduction({
      bates: produced,
      log: parsePrivilegeLog(csv("ACME_000199")),
    });
    expect(bare.map((f) => f.code)).toEqual(full.map((f) => f.code));
    expect(bare.some((f) => f.code === "PROD-011")).toBe(false);
  });

  it("still drops a row whose two ends carry different prefixes", () => {
    const log = parsePrivilegeLog(
      "Beg Bates,End Bates,Description,Privilege\nACME_000101,SMITH_000199,Memo,AC\n",
    );
    const findings = reconcileProduction({ bates: produced, log });
    // The range is unusable, so the produced gap is still unaccounted for.
    expect(findings.some((f) => f.code === "PROD-011")).toBe(true);
  });
});

describe("reconcileProduction — range filenames", () => {
  it("reports no gap for contiguous ranged members", () => {
    const bates = extractBatesSet(["ACME_000001-000010.pdf", "ACME_000011-000020.pdf"]);
    expect(reconcileProduction({ bates, log: EMPTY_LOG })).toEqual([]);
  });

  it("does not report a ranged document's own interior pages as a gap", () => {
    const bates = extractBatesSet(["ACME_000001-000010.pdf", "ACME_000011.pdf"]);
    expect(reconcileProduction({ bates, log: EMPTY_LOG })).toEqual([]);
  });

  it("still detects a real gap between two ranged members", () => {
    const bates = extractBatesSet(["ACME_000001-000010.pdf", "ACME_000021-000030.pdf"]);
    const gap = reconcileProduction({ bates, log: EMPTY_LOG }).find((f) => f.code === "PROD-001");
    expect(gap).toBeDefined();
    expect(gap?.detail).toContain("ACME_000011–ACME_000020");
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

  it("intra-row mixed-case range still reconciles: PROD-010 fires (privilege-waiver check)", () => {
    // A single log row whose two ends differ only in prefix casing must not be
    // dropped — that would silently disable overlap detection for the range.
    const bates = extractBatesSet(filenames("SMITH", [100, 125, 150]));
    const log = parsePrivilegeLog(
      "Bates Start,Bates End,Privilege,Description\nsmith_000100,SMITH_000150,AC,Email\n",
    );
    const findings = reconcileProduction({ bates, log });
    expect(findings.some((f) => f.code === "PROD-010")).toBe(true);
  });

  it("cross-row mixed-case overlap fires PROD-012 (duplicate privilege claim)", () => {
    const bates = extractBatesSet(filenames("ABC", [100, 105, 110, 115]));
    const log = parsePrivilegeLog(
      "Bates Start,Bates End,Privilege,Description\nabc_000100,abc_000110,AC,A\nABC_000105,ABC_000115,AC,B\n",
    );
    const findings = reconcileProduction({ bates, log });
    expect(findings.some((f) => f.code === "PROD-012")).toBe(true);
  });

  it("hyphen-convention Bates in a combined range column parses (PROD-010 fires)", () => {
    const bates = extractBatesSet(["ABC-000123.pdf", "ABC-000124.pdf", "ABC-000125.pdf"]);
    const log = parsePrivilegeLog(
      "Bates Range,Privilege,Description\nABC-000124 - ABC-000124,AC,Memo\n",
    );
    const findings = reconcileProduction({ bates, log });
    expect(findings.some((f) => f.code === "PROD-010")).toBe(true);
  });

  it("a single hyphen-convention Bates id (no range) is not split into prefix/number", () => {
    const log = parsePrivilegeLog("Bates,Privilege,Description\nABC-000124,AC,Legal memo\n");
    // Splitting on the id's own internal hyphen yielded start="ABC", which
    // parseBates rejects, dropping the row from every range check.
    expect(log.entries[0]?.bates_start).toBe("ABC-000124");
    expect(log.entries[0]?.bates_end).toBeUndefined();
  });

  it("a withheld single hyphen-convention id that was produced fires PROD-010", () => {
    const bates = extractBatesSet(["ABC-000123.pdf", "ABC-000124.pdf"]);
    const log = parsePrivilegeLog("Bates,Privilege,Description\nABC-000124,AC,Legal memo\n");
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

describe("the reported Bates number is one the production actually contains", () => {
  // The separator was a hardcoded "_". A production of VAN000001, VAN000002,
  // VAN000005 had its gap reported as "VAN_000003–VAN_000004" — a Bates
  // number that appears nowhere in it, so an attorney searching for the
  // missing documents finds nothing while the two that are actually missing
  // keep their real names.
  const cases: Array<[string, string[], string]> = [
    ["no separator", ["VAN000001.pdf", "VAN000002.pdf", "VAN000005.pdf"], "VAN000003–VAN000004"],
    [
      "underscore",
      ["ACME_000001.pdf", "ACME_000002.pdf", "ACME_000005.pdf"],
      "ACME_000003–ACME_000004",
    ],
    [
      "hyphen",
      ["ACME-000001.pdf", "ACME-000002.pdf", "ACME-000005.pdf"],
      "ACME-000003–ACME-000004",
    ],
  ];

  for (const [label, files, expected] of cases) {
    it(`names the gap the way a ${label} production names its documents`, () => {
      const findings = reconcileProduction({ bates: extractBatesSet(files), log: EMPTY_LOG });
      const gap = findings.find((f) => f.code === "PROD-001");
      expect(gap?.detail, `PROD-001 detail: ${gap?.detail}`).toContain(expected);
    });
  }
});
