/**
 * What clause text the register's deadline family is read from.
 *
 * `classifyDeadline` is documented as reading "the clause text around" each
 * date and was handed the whole SECTION. A pasted or plain-text document is a
 * single section, so every date in the document saw the same haystack and the
 * whole register came back with one kind — whichever family's word appeared
 * first, anywhere. An executive employment agreement's vacation entitlement,
 * its severance window, and its Change-of-Control window were all filed as
 * "auto-renewal-notice" because one clause elsewhere said "anniversary".
 */
import { describe, expect, it } from "vitest";
import { buildCriticalDates } from "./critical-dates.js";
import { buildTree } from "../extract/_fixtures.js";
import { extractAll } from "../extract/index.js";

async function kindOf(paras: [string, ...string[]], trigger: string) {
  const tree = buildTree(paras);
  const rows = (await buildCriticalDates(extractAll(tree), tree)).register;
  const row = rows.find((r) => r.trigger.includes(trigger));
  expect(row, `no register row whose trigger contains ${trigger}`).toBeTruthy();
  return row!.kind;
}

const DOC: [string, ...string[]] = [
  "Employment Agreement",
  "The Term renews automatically on each anniversary of the Effective Date unless either party gives notice of non-renewal.",
  "Confidential Information shall survive and remain in effect for five (5) years after the date of disclosure.",
  "The Company may terminate for Cause only if the breach is not cured within thirty (30) days after written notice.",
];

describe("the register's deadline family", () => {
  it("reads the survival clause, not a renewal clause elsewhere in the section", async () => {
    expect(await kindOf(DOC, "five (5) years")).toBe("survival-end");
  });

  it("reads the cure clause, not a renewal clause elsewhere in the section", async () => {
    expect(await kindOf(DOC, "thirty (30) days")).toBe("cure-window");
  });

  it("still classifies a renewal deadline from its own clause", async () => {
    const rows = (
      await buildCriticalDates(
        extractAll(
          buildTree([
            "Services Agreement",
            "This Agreement renews automatically unless a party gives notice at least sixty (60) days before the anniversary.",
          ]),
        ),
        buildTree([
          "Services Agreement",
          "This Agreement renews automatically unless a party gives notice at least sixty (60) days before the anniversary.",
        ]),
      )
    ).register;
    expect(rows.map((r) => r.kind)).toContain("auto-renewal-notice");
  });
});
