/**
 * Does every input the Action DECLARES actually reach the CLI?
 *
 * `action.yml` is two halves that have to agree by hand: an `inputs:` block a
 * consumer reads and copies from, and a shell script that turns those inputs
 * into CLI arguments. Nothing connects them. An input declared, documented in
 * the README's table, and never appended to `args` is invisible: the workflow
 * accepts it, the run succeeds, and the setting the caller asked for was
 * silently dropped — the same failure shape as the `--fail-on critcal` typo
 * that used to disable a gate without saying so.
 *
 * Two facts are checkable without a network call, and this pins both: every
 * declared input is exported into the step's environment, and the name it is
 * exported under is read by the script that builds the argument list.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const action = readFileSync(join(process.cwd(), "action.yml"), "utf8");

/** The input names under the top-level `inputs:` block. */
function declaredInputs(): string[] {
  const block = action.slice(action.indexOf("\ninputs:"), action.indexOf("\nruns:"));
  return [...block.matchAll(/^ {2}([a-z][a-z0-9-]*):$/gm)].map((m) => m[1]!);
}

/** `NAME: ${{ inputs.x }}` pairs in the step's `env:` block. */
function exportedInputs(): Map<string, string> {
  const out = new Map<string, string>();
  for (const m of action.matchAll(/^\s{8}([A-Z_]+):\s*\$\{\{\s*inputs\.([a-z0-9-]+)\s*\}\}/gm)) {
    out.set(m[2]!, m[1]!);
  }
  return out;
}

/** Everything after `run: |` — the script that assembles the argument list. */
function runScript(): string {
  return action.slice(action.lastIndexOf("run: |"));
}

describe("action.yml input reach", () => {
  it("derives a plausible surface (guards the derivations themselves)", () => {
    // Empty derivations would make every assertion below vacuously true.
    expect(declaredInputs()).toContain("files");
    expect(declaredInputs().length).toBeGreaterThanOrEqual(8);
    expect(exportedInputs().get("files")).toBe("FILES");
    expect(runScript()).toContain('node "$VAULYTICA_BIN"');
  });

  it("exports every declared input into the step environment", () => {
    const exported = exportedInputs();
    for (const name of declaredInputs()) {
      expect(exported.has(name), `action.yml declares "${name}" but never exports it`).toBe(true);
    }
  });

  it("reads every exported input in the script that builds the arguments", () => {
    const script = runScript();
    const exported = exportedInputs();
    for (const [name, env] of exported) {
      // `command` picks the subcommand rather than adding a flag, so it is read
      // as `$CMD` throughout; the check is only that the variable is consumed.
      expect(script, `action.yml exports ${env} (from "${name}") but never reads it`).toContain(
        `$${env}`,
      );
    }
  });
});
