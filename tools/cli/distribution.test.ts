import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import yaml from "js-yaml";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const BIN = join(REPO_ROOT, "bin", "vaulytica.mjs");

describe("vaulytica bin launcher (spec-v8 §22 distribution)", () => {
  it("runs the CLI and prints usage with --help", () => {
    // The launcher spawns `node --import tsx tools/cli/run.ts`; cold tsx start
    // is slow on CI, so give it room.
    const out = execFileSync(process.execPath, [BIN, "--help"], {
      encoding: "utf8",
      timeout: 60_000,
    });
    expect(out).toContain("vaulytica — deterministic legal-document linter");
    expect(out).toContain("analyze");
    expect(out).toContain("compare");
  });

  it("propagates a non-zero exit code from the CLI", () => {
    let code = 0;
    try {
      execFileSync(process.execPath, [BIN, "nonsense-command"], {
        stdio: "pipe",
        timeout: 60_000,
      });
    } catch (e) {
      code = (e as { status?: number }).status ?? -1;
    }
    expect(code).not.toBe(0);
  });
});

describe("package.json distribution metadata", () => {
  const pkg = JSON.parse(readFileSync(join(REPO_ROOT, "package.json"), "utf8"));

  it("exposes a `vaulytica` bin pointing at the launcher that exists", () => {
    expect(pkg.bin.vaulytica).toBe("bin/vaulytica.mjs");
    expect(existsSync(join(REPO_ROOT, pkg.bin.vaulytica))).toBe(true);
  });

  it("declares tsx as a runtime dependency (the bin runs TS through it)", () => {
    expect(pkg.dependencies.tsx).toBeDefined();
    expect(pkg.devDependencies?.tsx).toBeUndefined();
  });

  it("ships the engine, CLI, starter DKB, and playbooks in the published files", () => {
    for (const needed of ["src/", "tools/cli/", "tools/accuracy/", "dkb/dist/v0.0.1-starter/", "playbooks/", "bin/"]) {
      expect(pkg.files).toContain(needed);
    }
  });
});

describe("action.yml (GitHub composite Action)", () => {
  const actionText = readFileSync(join(REPO_ROOT, "action.yml"), "utf8");
  const action = yaml.load(actionText) as {
    name: string;
    runs: { using: string; steps: Array<{ run?: string; env?: Record<string, string> }> };
    inputs: Record<string, { default?: string }>;
  };

  it("is a valid composite action that installs deps and launches the bin", () => {
    expect(action.runs.using).toBe("composite");
    expect(action.runs.steps.length).toBeGreaterThanOrEqual(2);
    const runs = action.runs.steps.map((s) => s.run ?? "").join("\n");
    expect(runs).toContain("npm ci");
    expect(runs).toContain('node "$VAULYTICA_BIN"');
    // The bin is resolved from the action's own checkout.
    expect(actionText).toContain("${{ github.action_path }}/bin/vaulytica.mjs");
  });

  it("exposes the documented inputs with safe defaults", () => {
    for (const input of ["command", "files", "base", "revised", "format", "fail-on", "playbook", "out"]) {
      expect(action.inputs[input]).toBeDefined();
    }
    expect(action.inputs.command!.default).toBe("analyze");
    expect(action.inputs.format!.default).toBe("sarif");
  });
});
