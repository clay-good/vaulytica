import { describe, it } from "vitest";

// current
function cur(paragraph: string, matchIndex: number): string {
  const start = Math.max(
    paragraph.lastIndexOf(". ", matchIndex),
    paragraph.lastIndexOf("; ", matchIndex),
    paragraph.lastIndexOf("\n", matchIndex),
  );
  const rel = paragraph.slice(matchIndex).search(/[;\n]|\.(?=\s|$)/);
  const end = rel === -1 ? paragraph.length : matchIndex + rel + 1;
  return paragraph.slice(start + 1, end);
}
// fixed: a "." is a sentence boundary only if followed by space+Capital/digit or end
function fix(paragraph: string, matchIndex: number): string {
  const back = /\.(?=\s+[A-Z0-9]|\s*$)/g;
  let dot = -1;
  let mm: RegExpExecArray | null;
  while ((mm = back.exec(paragraph)) !== null && mm.index < matchIndex) dot = mm.index;
  const start = Math.max(
    dot,
    paragraph.lastIndexOf("; ", matchIndex),
    paragraph.lastIndexOf("\n", matchIndex),
  );
  const rel = paragraph.slice(matchIndex).search(/[;\n]|\.(?=\s+[A-Z0-9]|\s*$)/);
  const end = rel === -1 ? paragraph.length : matchIndex + rel + 1;
  return paragraph.slice(start + 1, end);
}

describe("enclosingSentence probe", () => {
  const cases: [string, string][] = [
    ["XYZ Inc. shall indemnify Vendor from claims of gross negligence.", "indemnify"],
    ["XYZ Inc. shall indemnify Vendor from claims of gross negligence.", "XYZ"],
    ["The vendor at vendor.com shall provide 99.9 uptime per year.", "uptime"],
    ["Foo happened. Bar shall indemnify. Baz ended.", "indemnify"],
    ["Fees are due. The Company shall pay within 30 days.", "pay"],
    ["Payment is 5 p.m. deadline for all invoices.", "deadline"],
  ];
  it("prints", () => {
    for (const [p, needle] of cases) {
      const idx = p.indexOf(needle);
      // eslint-disable-next-line no-console
      console.log("CUR:", JSON.stringify(cur(p, idx)), "\n  FIX:", JSON.stringify(fix(p, idx)));
    }
  });
});
