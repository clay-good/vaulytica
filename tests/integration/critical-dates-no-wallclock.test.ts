import { afterEach, describe, expect, it, vi } from "vitest";
import { buildTree } from "../../src/extract/_fixtures.js";
import { extractAll } from "../../src/extract/index.js";
import {
  buildCriticalDates,
  buildCriticalDatesIcs,
  buildCriticalDatesMarkdown,
} from "../../src/report/index.js";

/**
 * spec-v9 Thrust C, Step 164 — the no-wall-clock invariant gate.
 *
 * The single rule that keeps the thrust posture-clean (spec §3 corollary 4,
 * companion §6): a *derived* absolute date is `result_hash`-stable; anything
 * *relative to today* ("due in 12 days", "overdue") is render-only and never
 * enters the register, its hash, or any export's stable content.
 *
 * The metamorphic test: build the register and every export for the SAME
 * document under two wildly different "today" values, and assert the
 * register, its `critical_dates_hash`, and the .ics / Markdown bytes are
 * IDENTICAL. The derivation module reads no clock by construction, so this
 * passes today; the gate exists so a later edit that quietly leaks a
 * "days remaining" value into a hashed/exported artifact fails the build.
 */

afterEach(() => {
  vi.useRealTimers();
});

const TREE = buildTree(
  ["Definitions", '"Effective Date" means January 1, 2025.', '"Renewal Date" means December 31, 2025.'],
  ["Term", "The initial term runs for 12 months after the Effective Date."],
  ["Auto-renewal", "This Agreement renews automatically. Either party may opt out 60 days before the Renewal Date."],
  ["Cure", "Provider shall cure within 30 days after the Notice Date."],
);

async function snapshotUnderClock(iso: string): Promise<{
  hash: string;
  ics: string;
  md: string;
  json: string;
}> {
  vi.useFakeTimers();
  vi.setSystemTime(new Date(iso));
  const extracted = extractAll(TREE);
  const register = await buildCriticalDates(extracted, TREE);
  return {
    hash: register.critical_dates_hash,
    ics: buildCriticalDatesIcs(register),
    md: buildCriticalDatesMarkdown(register),
    json: JSON.stringify(register),
  };
}

describe("critical dates — no wall-clock in the hash (spec-v9 Step 164)", () => {
  it("the register, its hash, and every export are byte-identical under two different 'today' values", async () => {
    const early = await snapshotUnderClock("2020-06-15T08:00:00Z");
    const late = await snapshotUnderClock("2099-12-31T23:59:59Z");
    expect(late.hash).toBe(early.hash);
    expect(late.json).toBe(early.json);
    expect(late.ics).toBe(early.ics);
    expect(late.md).toBe(early.md);
  });

  it("no export contains a relative-to-today phrase", async () => {
    const snap = await snapshotUnderClock("2026-06-12T00:00:00Z");
    for (const text of [snap.ics, snap.md, snap.json]) {
      expect(text).not.toMatch(/days? remaining|overdue|due in \d|next deadline/i);
    }
  });
});
