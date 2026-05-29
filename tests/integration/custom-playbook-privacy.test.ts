/**
 * Custom-playbook privacy guard (spec-v6 Part VII).
 *
 * A user-supplied playbook is loaded, validated, previewed, and enforced
 * **entirely in the tab** — no bytes ever leave the browser. This test makes
 * that contract executable: it embeds a unique marker string in the playbook,
 * stubs every network egress primitive (`fetch`, `XMLHttpRequest`,
 * `navigator.sendBeacon`, `WebSocket`), runs the full validate → preview →
 * enforce path against a real fixture document, and asserts that no network
 * call occurred at all — and that the marker never appears in any captured
 * request payload.
 *
 * Mirrors the v5 §VIII / bundle-excludes-corpus privacy-guard family.
 */

import { describe, expect, it, afterEach } from "vitest";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { runFixture, listFixtures } from "./_pipeline-helpers.js";
import { extractAll } from "../../src/extract/index.js";
import { loadStarterDkbSync, GENERIC_PLAYBOOK } from "../../src/engine/_test-fixtures.js";
import { LAUNCH_RULES, V3_RULES } from "../../src/engine/index.js";
import {
  validateCustomPlaybook,
  previewCustomPlaybook,
  runWithCustomPlaybook,
} from "../../src/playbooks/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONTRACTS = join(__dirname, "..", "fixtures", "contracts");

const MARKER = "SECRET-PLAYBOOK-MARKER-d0n0t3xfil-9f3a";

type Capture = { kind: string; payload: string };

/** Install stubs over every browser network primitive; return the capture log + a restore fn. */
function installEgressTraps(): { captures: Capture[]; restore: () => void } {
  const captures: Capture[] = [];
  const g = globalThis as unknown as Record<string, unknown>;
  const saved: Record<string, unknown> = {};

  const record = (kind: string, ...args: unknown[]): void => {
    captures.push({ kind, payload: safeStringify(args) });
  };

  saved.fetch = g.fetch;
  g.fetch = (...args: unknown[]) => {
    record("fetch", ...args);
    return Promise.reject(new Error("network disabled in privacy guard"));
  };

  saved.XMLHttpRequest = g.XMLHttpRequest;
  g.XMLHttpRequest = class {
    open(...a: unknown[]): void {
      record("xhr.open", ...a);
    }
    send(...a: unknown[]): void {
      record("xhr.send", ...a);
    }
    setRequestHeader(): void {}
    addEventListener(): void {}
  };

  saved.WebSocket = g.WebSocket;
  g.WebSocket = class {
    constructor(...a: unknown[]) {
      record("websocket", ...a);
    }
    send(...a: unknown[]): void {
      record("websocket.send", ...a);
    }
    close(): void {}
  };

  const nav = (g.navigator ?? {}) as { sendBeacon?: unknown };
  saved.sendBeacon = nav.sendBeacon;
  nav.sendBeacon = (...a: unknown[]): boolean => {
    record("sendBeacon", ...a);
    return true;
  };
  if (!g.navigator) g.navigator = nav;

  return {
    captures,
    restore: () => {
      g.fetch = saved.fetch;
      g.XMLHttpRequest = saved.XMLHttpRequest;
      g.WebSocket = saved.WebSocket;
      (g.navigator as { sendBeacon?: unknown }).sendBeacon = saved.sendBeacon;
    },
  };
}

function safeStringify(v: unknown): string {
  try {
    return JSON.stringify(v, (_k, val) =>
      typeof val === "object" && val !== null ? val : String(val),
    );
  } catch {
    return String(v);
  }
}

let activeRestore: (() => void) | null = null;
afterEach(() => {
  activeRestore?.();
  activeRestore = null;
});

describe("custom-playbook privacy guard (spec-v6 Part VII)", () => {
  it("loads, validates, previews, and enforces a playbook with zero network egress", async () => {
    const trap = installEgressTraps();
    activeRestore = trap.restore;

    // A user-supplied playbook carrying a unique marker. This is the "load it
    // in the tab" step: parse the raw JSON text exactly as the UI does.
    const playbookJson = JSON.stringify({
      schema_version: "1.0",
      catalog_version: "0.1.0",
      id: "privacy-test-playbook",
      name: "Privacy Test Standard",
      description: `Confidential team standard ${MARKER}.`,
      custom_rules: [
        {
          id: "PRIV-1",
          title: "No arbitration",
          description: `We strike arbitration ${MARKER}.`,
          severity: "warning",
          assert: { kind: "clause_absent", pattern: "arbitration" },
          citation: { reference: `Policy ${MARKER}` },
        },
      ],
    });

    const validation = validateCustomPlaybook(JSON.parse(playbookJson));
    expect(validation.ok).toBe(true);
    if (!validation.ok) return;
    const playbook = validation.playbook;

    // Preview (what the panel renders before running).
    const catalogIds = [...LAUNCH_RULES, ...V3_RULES].map((r) => r.id);
    const preview = previewCustomPlaybook(playbook, { rule_ids: catalogIds });
    expect(preview.custom_rule_count).toBe(1);

    // Enforce end-to-end against a real fixture document.
    const fixtures = (await listFixtures(CONTRACTS)).filter((f) => f.endsWith(".docx"));
    expect(fixtures.length).toBeGreaterThan(0);
    const { ingest } = await runFixture(join(CONTRACTS, fixtures[0]!));
    const dkb = loadStarterDkbSync();
    const extracted = extractAll(ingest.tree, {
      classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
    });

    const result = await runWithCustomPlaybook({
      rules: [...LAUNCH_RULES, ...V3_RULES],
      matched_playbook: GENERIC_PLAYBOOK,
      custom_playbook: playbook,
      tree: ingest.tree,
      extracted,
      dkb,
      source_file: { name: fixtures[0]!, sha256: ingest.sha256, size_bytes: 1 },
      executed_at: "",
    });
    expect(result.run.result_hash).not.toBe("");

    // The load-bearing assertions: no egress, and the marker never escaped.
    expect(trap.captures, `unexpected network egress: ${safeStringify(trap.captures)}`).toHaveLength(
      0,
    );
    const allPayloads = trap.captures.map((c) => c.payload).join("\n");
    expect(allPayloads).not.toContain(MARKER);
  });
});
