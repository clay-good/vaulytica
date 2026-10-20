/**
 * A closing set: every final draft against its signed copy
 * (add-executed-copy-conformity, the closing-set half of task 5).
 *
 * Files are paired by the document's own title, as routing reads it, never by
 * filename: a signed copy arrives as `Scan_0041.pdf`. A legend line
 * ("EXECUTION VERSION") is not a title, so the first line that is not one is
 * used. Two files on one side with the same title are a tie, and a title on
 * one side only is unpaired; both are listed, and nothing is guessed.
 *
 * `conformity_hash` here is the SET's: SHA-256 over the canonical rows (each
 * row carries its own pair's `conformity_hash`), the unpaired files and the
 * ties. Namespaced apart from every `result_hash`.
 */
import { sha256Hex } from "../ingest/hash.js";
import { executionAllowance, CONFORMITY_VERSION, type Conformity } from "./conformity.js";

/** One file on one side of the set, with the title it is paired by. */
export type ClosingEntry = { file: string; title: string };

export type ClosingRow = {
  title: string;
  final: string;
  signed: string;
  /** `unreadable` when the signed copy could not be compared (an image-only scan headless). */
  verdict: Conformity["verdict"] | "unreadable";
  difference_count?: number;
  conformity_hash?: string;
  reason?: string;
};

export type ClosingSet = {
  version: string;
  rows: ClosingRow[];
  unpaired: Array<{ side: "final" | "signed"; file: string; title: string }>;
  ties: Array<{ side: "final" | "signed"; title: string; files: string[] }>;
  conformity_hash: string;
};

/** The first line of a title corpus that is not a legend or watermark, normalized for pairing. */
export function pairingTitle(corpus: string): string {
  const line =
    corpus
      .split("\n")
      .map((l) => l.trim())
      .find((l) => l && !executionAllowance(l)) ?? "";
  return line
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, " ")
    .trim()
    .slice(0, 160);
}

/** Pair two sides by title. Order-independent: every list comes back sorted. */
export function pairClosingSet(
  finals: readonly ClosingEntry[],
  signed: readonly ClosingEntry[],
): {
  pairs: Array<{ title: string; final: string; signed: string }>;
  unpaired: ClosingSet["unpaired"];
  ties: ClosingSet["ties"];
} {
  const group = (entries: readonly ClosingEntry[]): Map<string, string[]> => {
    const m = new Map<string, string[]>();
    for (const e of entries) m.set(e.title, [...(m.get(e.title) ?? []), e.file].sort());
    return m;
  };
  const f = group(finals);
  const s = group(signed);
  const pairs: Array<{ title: string; final: string; signed: string }> = [];
  const unpaired: ClosingSet["unpaired"] = [];
  const ties: ClosingSet["ties"] = [];
  const titles = [...new Set([...f.keys(), ...s.keys()])].sort();
  for (const title of titles) {
    const fs = f.get(title) ?? [];
    const ss = s.get(title) ?? [];
    if (fs.length > 1) ties.push({ side: "final", title, files: fs });
    if (ss.length > 1) ties.push({ side: "signed", title, files: ss });
    if (fs.length > 1 || ss.length > 1) continue;
    if (fs.length === 1 && ss.length === 1) pairs.push({ title, final: fs[0]!, signed: ss[0]! });
    else if (fs.length === 1) unpaired.push({ side: "final", file: fs[0]!, title });
    else if (ss.length === 1) unpaired.push({ side: "signed", file: ss[0]!, title });
  }
  return { pairs, unpaired, ties };
}

/** The set's table and its hash. Rows sorted by title, then file. */
export async function buildClosingSet(
  rows: readonly ClosingRow[],
  unpaired: ClosingSet["unpaired"],
  ties: ClosingSet["ties"],
): Promise<ClosingSet> {
  const sorted = [...rows].sort((a, b) =>
    a.title < b.title ? -1 : a.title > b.title ? 1 : a.final < b.final ? -1 : 1,
  );
  const canonical = JSON.stringify({
    namespace: "vaulytica-closing-set",
    version: CONFORMITY_VERSION,
    rows: sorted.map((r) => [
      r.title,
      r.final,
      r.signed,
      r.verdict,
      r.difference_count ?? null,
      r.conformity_hash ?? null,
    ]),
    unpaired: unpaired.map((u) => [u.side, u.file, u.title]),
    ties: ties.map((t) => [t.side, t.title, t.files]),
  });
  return {
    version: CONFORMITY_VERSION,
    rows: sorted,
    unpaired: [...unpaired],
    ties: [...ties],
    conformity_hash: await sha256Hex(canonical),
  };
}

/** True when every pair is identical outside the allowance and nothing is unpaired or tied. */
export function closingSetConforms(set: ClosingSet): boolean {
  return (
    set.unpaired.length === 0 &&
    set.ties.length === 0 &&
    set.rows.every((r) => r.verdict === "identical")
  );
}

const cell = (s: string): string => s.replace(/\|/g, "\\|").replace(/\s+/g, " ");

/** The set as Markdown: the table, then what could not be paired. */
export function closingSetMarkdown(set: ClosingSet): string {
  const verdict = (r: ClosingRow): string =>
    r.verdict === "identical"
      ? "identical outside the execution allowance"
      : r.verdict === "differences"
        ? `${r.difference_count} difference${r.difference_count === 1 ? "" : "s"}`
        : `not compared: ${r.reason ?? "unreadable"}`;
  const lines = [
    "# Closing set: signed copies against the finals",
    "",
    `${set.rows.length} pair${set.rows.length === 1 ? "" : "s"}, ` +
      `${set.rows.filter((r) => r.verdict === "identical").length} identical outside the execution allowance, ` +
      `${set.unpaired.length} unpaired, ${set.ties.length} tied.`,
    "",
  ];
  if (set.rows.length > 0) {
    lines.push("| Document | Final | Signed copy | Conformity |", "| --- | --- | --- | --- |");
    for (const r of set.rows) {
      lines.push(`| ${cell(r.title)} | ${cell(r.final)} | ${cell(r.signed)} | ${verdict(r)} |`);
    }
    lines.push("");
  }
  if (set.unpaired.length > 0) {
    lines.push("## Unpaired", "");
    for (const u of set.unpaired) {
      lines.push(
        `- ${u.side === "final" ? "Final with no signed copy" : "Signed copy with no final"}: ${u.file} ("${u.title}")`,
      );
    }
    lines.push("");
  }
  if (set.ties.length > 0) {
    lines.push("## Tied titles (not paired)", "");
    for (const t of set.ties) {
      lines.push(
        `- ${t.side === "final" ? "Finals" : "Signed copies"} titled "${t.title}": ${t.files.join(", ")}`,
      );
    }
    lines.push("");
  }
  lines.push(`conformity_hash: ${set.conformity_hash}`, "");
  return lines.join("\n");
}
