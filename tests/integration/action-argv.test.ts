/**
 * What the Action actually runs.
 *
 * `action-input-reach.test.ts` asserts the two halves of `action.yml` are
 * WIRED — every declared input is exported and every exported name is read.
 * This one asserts they are wired CORRECTLY: given a set of inputs, what argv
 * does the composite step hand the binary?
 *
 * The distinction matters because the wiring test passes for a script that
 * reads `$CONSISTENCY` and appends the wrong flag, appends it to `compare`
 * (which has no bundle and would reject it), or drops it when a sibling input
 * is also set. Those are the mistakes a shell script written in YAML actually
 * makes, and none of them is visible to a reader.
 *
 * The script is extracted from `action.yml` itself and run with the binary
 * replaced by `echo`, so this tests the shipped text rather than a copy of it.
 * No network, no npm install, no engine — just argv.
 */
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

const action = readFileSync(join(process.cwd(), "action.yml"), "utf8");
const dir = mkdtempSync(join(tmpdir(), "vaulytica-action-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

/** The composite step's shell body, with the binary call replaced by an echo. */
const script = (() => {
  const body = action.slice(action.lastIndexOf("run: |") + "run: |".length);
  const dedented = body
    .split("\n")
    .map((l) => (l.startsWith(" ".repeat(8)) ? l.slice(8) : l))
    .join("\n");
  return dedented.replace('node "$VAULYTICA_BIN"', "echo ARGV:");
})();

const scriptPath = join(dir, "step.sh");
writeFileSync(scriptPath, script);

/** Run the step with these inputs and return the argv line it would execute. */
function argv(inputs: Record<string, string>): string {
  const env: Record<string, string> = {
    PATH: process.env.PATH ?? "",
    VAULYTICA_BIN: "/dev/null",
    CMD: "analyze",
    FILES: "",
    BASE: "",
    REVISED: "",
    REDLINE: "",
    FORMAT: "",
    FAIL_ON: "",
    PLAYBOOK: "",
    OUT: "",
    CONSISTENCY: "",
    FAIL_ON_CONSISTENCY: "",
    DELIVERY: "",
    FAIL_ON_DELIVERY: "",
    PLAYBOOK_FILE: "",
    POSTURE: "",
    FAIL_ON_POSTURE: "",
    FAIL_ON_DIVERGENCE: "",
    ...inputs,
  };
  const out = execFileSync("bash", [scriptPath], { env, encoding: "utf8" });
  const line = out.split("\n").find((l) => l.startsWith("ARGV:"));
  if (!line) throw new Error(`no argv line in step output:\n${out}`);
  return line.slice("ARGV:".length).trim();
}

describe("the Action composes the argv it advertises", () => {
  it("derives a runnable script from action.yml (guards the derivation)", () => {
    // A mangled extraction would make every case below throw or pass trivially.
    expect(script).toContain("set -euo pipefail");
    expect(script).toContain("echo ARGV:");
    expect(argv({ FILES: "contracts/" })).toContain("analyze contracts/");
  });

  it("defaults analyze to sarif and passes the ordinary inputs through", () => {
    expect(argv({ FILES: "contracts/", OUT: "out", FAIL_ON: "critical" })).toBe(
      "analyze contracts/ --format sarif --fail-on critical --out out",
    );
  });

  it("adds --consistency when asked to report, without gating", () => {
    expect(argv({ FILES: "deal/", CONSISTENCY: "true" })).toContain("--consistency");
    expect(argv({ FILES: "deal/", CONSISTENCY: "true" })).not.toContain("--fail-on-consistency");
  });

  it("passes --fail-on-consistency alone, since the flag implies the pass", () => {
    // Both set must not produce both flags: the CLI infers the pass from the
    // gate, and a duplicate would be noise in the echoed command a user reads.
    const both = argv({ FILES: "deal/", CONSISTENCY: "true", FAIL_ON_CONSISTENCY: "critical" });
    expect(both).toContain("--fail-on-consistency critical");
    expect(both).not.toMatch(/--consistency(?!\S)/);
  });

  it("maps consistency: only to the bundle-only flag", () => {
    const line = argv({ FILES: "deal/", CONSISTENCY: "only" });
    expect(line).toContain("--consistency-only");
    expect(line).not.toMatch(/--consistency(?!-only)/);
  });

  it("treats anything but the literal 'true' as not asserted", () => {
    // A YAML input is a string. "false", "no", "" must all mean off, or a
    // workflow that writes `consistency: false` gets the opposite.
    for (const v of ["false", "no", "0", ""]) {
      expect(argv({ FILES: "deal/", CONSISTENCY: v }), `consistency: ${v}`).not.toContain(
        "--consistency",
      );
    }
  });

  it("--fail-on-delivery turns the scan on by itself", () => {
    // The gate is meaningless without the scan, so the flag implies it rather
    // than failing on a combination the caller would have to learn.
    const line = argv({ FILES: "outgoing.docx", FAIL_ON_DELIVERY: "critical" });
    expect(line).toContain("--delivery --fail-on-delivery critical");
  });

  it("--fail-on-posture rides with the playbook file it scores against", () => {
    const line = argv({
      FILES: "redline.docx",
      PLAYBOOK_FILE: "team.json",
      FAIL_ON_POSTURE: "below-acceptable",
    });
    expect(line).toContain("--playbook-file team.json");
    expect(line).toContain("--posture --fail-on-posture below-acceptable");
  });

  it("drops the posture flags when no playbook file was given to score against", () => {
    // --posture needs a ladder; asking for it without one would be a usage
    // error from the CLI, and the Action should not compose one.
    const line = argv({ FILES: "redline.docx", POSTURE: "true", FAIL_ON_POSTURE: "acceptable" });
    expect(line).not.toContain("--posture");
    expect(line).not.toContain("--fail-on-posture");
  });

  it("--fail-on-divergence turns the posture on, since it scores across it", () => {
    const line = argv({
      FILES: "deal/",
      PLAYBOOK_FILE: "team.json",
      FAIL_ON_DIVERGENCE: "true",
    });
    expect(line).toContain("--posture");
    expect(line).toContain("--fail-on-divergence");
  });

  it("never sends the bundle flags to compare, which has no bundle", () => {
    const line = argv({
      CMD: "compare",
      BASE: "a.docx",
      REVISED: "b.docx",
      CONSISTENCY: "true",
      FAIL_ON_CONSISTENCY: "critical",
      OUT: "out",
    });
    expect(line).toBe("compare a.docx b.docx");
  });

  it("sends a redline to compare as --redline, alone", () => {
    expect(argv({ CMD: "compare", REDLINE: "markup.docx", FAIL_ON: "warning" })).toBe(
      "compare --redline markup.docx --fail-on warning",
    );
    expect(() => argv({ CMD: "compare", REDLINE: "markup.docx", BASE: "a.docx" })).toThrow();
  });

  it("leaves compare's format alone so each command applies its own default", () => {
    // sarif is the analyze default and compare rejects it outright; passing it
    // through used to fail every compare run.
    expect(argv({ CMD: "compare", BASE: "a.docx", REVISED: "b.docx" })).not.toContain("--format");
  });

  it("fails loudly when a required input is missing", () => {
    expect(() => argv({ FILES: "" })).toThrow();
    expect(() => argv({ CMD: "compare", BASE: "a.docx", REVISED: "" })).toThrow();
  });
});

/**
 * Production QA — the mode whose gate exists FOR CI, and which CI could not
 * switch on.
 *
 * `--fail-on-production-gap`'s own comment in `tools/cli/run.ts` says it is
 * there for "a CI check before a production goes out". The Action **is** that
 * check, and it exposed neither the mode nor the gate: a litigation team could
 * run the Bates/privilege-log reconciliation at a terminal and nowhere else.
 * Same shape as the three gates found unreachable from the Action in 9.5xx.
 */
describe("the Action can run production QA", () => {
  it("passes --production-qa when asked to report", () => {
    expect(argv({ FILES: "./production", PRODUCTION_QA: "true" })).toContain("--production-qa");
  });

  it("passes the gate alone, since the flag implies the mode", () => {
    const args = argv({ FILES: "./production", FAIL_ON_PRODUCTION_GAP: "true" });
    expect(args).toContain("--production-qa");
    expect(args).toContain("--fail-on-production-gap");
    // The CLI rejects the gate without the mode, so they must go together.
    expect(args.indexOf("--production-qa")).toBeLessThan(args.indexOf("--fail-on-production-gap"));
  });

  it("adds neither by default, and treats anything but 'true' as not asserted", () => {
    const off = argv({ FILES: "./production" });
    expect(off).not.toContain("--production-qa");
    expect(off).not.toContain("--fail-on-production-gap");
    expect(argv({ FILES: "./production", PRODUCTION_QA: "yes" })).not.toContain("--production-qa");
  });

  it("never sends it to compare, which has no such mode", () => {
    expect(
      argv({ CMD: "compare", BASE: "a.docx", REVISED: "b.docx", PRODUCTION_QA: "true" }),
    ).not.toContain("--production-qa");
  });
});

/**
 * The assertions, the derived registers, and the regression gate.
 *
 * `action-flag-coverage.test.ts` found 21 analyze flags and 5 compare flags
 * that no input reached: every assertion the engine refuses to infer (state
 * overlays, privacy regimes, a readability statute, a court's filing format, a
 * deadline profile, the estate formalities), every register the export formats
 * need (critical dates, the closing checklist, defined terms, the verification
 * certificate), the baseline comparison that answers "did this pull request
 * give ground?", and the whole executed-copy conformity surface. All of them
 * worked at a terminal and none of them existed for a CI consumer.
 *
 * Composing the argv is half the job; the other half is that the CLI accepts
 * it. The last case in each block feeds the composed line to the real parser,
 * so a flag spelled almost right, or a combination the CLI refuses, fails here
 * rather than in a consumer's workflow.
 */
describe("the Action can assert the law that applies", () => {
  it("passes each assertion with its value", () => {
    const line = argv({
      FILES: "policies/",
      STATE: "ca",
      REGIME: "ccpa,gdpr",
      READABILITY: "fl",
    });
    expect(line).toContain("--state ca");
    expect(line).toContain("--regime ccpa,gdpr");
    expect(line).toContain("--readability fl");
  });

  it("asserts the estate formalities and the read-everything-as-text mode only on 'true'", () => {
    expect(argv({ FILES: "wills/", ESTATE_CHECKS: "true" })).toContain("--estate-checks");
    expect(argv({ FILES: "wills/", AS_TEXT: "true" })).toContain("--as-text");
    for (const v of ["false", "yes", ""]) {
      expect(argv({ FILES: "wills/", ESTATE_CHECKS: v }), `estate-checks: ${v}`).not.toContain(
        "--estate-checks",
      );
    }
  });

  it("turns the delivery scan on when only the SEC exhibit half was asked for", () => {
    // --sec-exhibit is a sub-check of the pre-disclosure scan. Passing it
    // without --delivery would be a flag with nothing to attach to.
    const line = argv({ FILES: "ex-10-1.docx", SEC_EXHIBIT: "true" });
    expect(line).toContain("--delivery");
    expect(line).toContain("--sec-exhibit");
  });

  it("pairs --reply with the court profile it shortens, and refuses it alone", () => {
    const line = argv({ FILES: "brief.docx", COURT: "ca9-appellate", REPLY: "true" });
    expect(line).toContain("--court ca9-appellate");
    expect(line).toContain("--reply");
    expect(() => argv({ FILES: "brief.docx", REPLY: "true" })).toThrow();
  });

  it("pairs --service-method with the deadline profile that counts it, and refuses it alone", () => {
    const line = argv({
      FILES: "motion.docx",
      DEADLINE_PROFILE: "frcp-6",
      SERVICE_METHOD: "mail",
    });
    expect(line).toContain("--deadline-profile frcp-6");
    expect(line).toContain("--service-method mail");
    expect(() => argv({ FILES: "motion.docx", SERVICE_METHOD: "mail" })).toThrow();
  });

  it("computes the registers the export formats print", () => {
    const line = argv({
      FILES: "deal/",
      CRITICAL_DATES: "true",
      CHECKLIST: "true",
      DEFINITIONS: "true",
    });
    expect(line).toContain("--critical-dates");
    expect(line).toContain("--checklist");
    expect(line).toContain("--definitions");
  });

  it("refuses the certificate without somewhere to write it", () => {
    // It is a .docx; the CLI itself throws "requires --out <dir>".
    expect(argv({ FILES: "deal/", CERTIFICATE: "true", OUT: "out" })).toContain("--certificate");
    expect(() => argv({ FILES: "deal/", CERTIFICATE: "true" })).toThrow();
  });

  it("sends none of them to compare, which takes none of them", () => {
    const line = argv({
      CMD: "compare",
      BASE: "a.docx",
      REVISED: "b.docx",
      STATE: "ca",
      REGIME: "gdpr",
      READABILITY: "fl",
      ESTATE_CHECKS: "true",
      CRITICAL_DATES: "true",
      CERTIFICATE: "true",
      SEC_EXHIBIT: "true",
      COURT: "frap-default",
      DEADLINE_PROFILE: "frcp-6",
      EMIT_CONSISTENCY: "c.json",
    });
    expect(line).toBe("compare a.docx b.docx");
  });

  it("composes a line the real analyze parser accepts", async () => {
    const { resolveAnalyzeArgs } = await import("../../tools/cli/run.js");
    const line = argv({
      FILES: "policies/",
      OUT: "out",
      STATE: "ca",
      REGIME: "ccpa,gdpr",
      READABILITY: "fl",
      ESTATE_CHECKS: "true",
      AS_TEXT: "true",
      SEC_EXHIBIT: "true",
      COURT: "ca9-appellate",
      REPLY: "true",
      DEADLINE_PROFILE: "frcp-6",
      SERVICE_METHOD: "mail",
      CRITICAL_DATES: "true",
      CHECKLIST: "true",
      DEFINITIONS: "true",
      CERTIFICATE: "true",
      EMIT_CONSISTENCY: "consistency.json",
    });
    const [command, ...rest] = line.split(" ");
    expect(command).toBe("analyze");
    const parsed = await resolveAnalyzeArgs(rest);
    // Spot-check that the values arrived where the flags say, not just that
    // nothing threw: a flag the parser silently ignores would also not throw.
    expect(parsed.estateState).toBe("us-ca");
    expect(parsed.readability).toBe("fl");
    expect(parsed.court).toBe("ca9-appellate");
    expect(parsed.reply).toBe(true);
    expect(parsed.deadlineProfile).toBe("frcp-6");
    expect(parsed.serviceMethod).toBe("mail");
    expect(parsed.criticalDates).toBe(true);
    expect(parsed.certificate).toBe(true);
    expect(parsed.secExhibit).toBe(true);
    expect(parsed.asText).toBe(true);
  });
});

describe("the Action can gate on the posture this round gave up", () => {
  it("scores this round against the last, turning the posture on itself", () => {
    const line = argv({
      FILES: "round-3/",
      PLAYBOOK_FILE: "team.json",
      BASELINE: "round-2/",
      FAIL_ON_COHERENCE_REGRESSION: "true",
    });
    expect(line).toContain("--posture");
    expect(line).toContain("--baseline round-2/");
    expect(line).toContain("--fail-on-coherence-regression");
    // One --posture, not two: the gate block and this one must not both add it.
    expect(line.match(/--posture(?!\S)/g)).toHaveLength(1);
  });

  it("takes a saved coherence as the baseline, and refuses both sources at once", () => {
    const line = argv({
      FILES: "round-3/",
      PLAYBOOK_FILE: "team.json",
      BASELINE_COHERENCE: "round-2.coherence.json",
      EMIT_COHERENCE: "round-3.coherence.json",
    });
    expect(line).toContain("--baseline-coherence round-2.coherence.json");
    expect(line).toContain("--emit-coherence round-3.coherence.json");
    expect(() =>
      argv({
        FILES: "round-3/",
        PLAYBOOK_FILE: "team.json",
        BASELINE: "round-2/",
        BASELINE_COHERENCE: "round-2.coherence.json",
      }),
    ).toThrow();
  });

  it("carries the role and the deal's value the ladder scales against", () => {
    const line = argv({
      FILES: "msa.docx",
      PLAYBOOK_FILE: "team.json",
      POSTURE: "true",
      ROLE: "customer",
      DEAL_VALUE: "2500000",
    });
    expect(line).toContain("--role customer");
    expect(line).toContain("--deal-value 2500000");
  });

  it("names the missing playbook file instead of letting the CLI name a flag", () => {
    // Every one of these requires --posture, which requires --playbook-file.
    // The error has to name the INPUT the caller set, not the flag it became.
    const cases: Record<string, string>[] = [
      { ROLE: "customer" },
      { DEAL_VALUE: "100" },
      { BASELINE: "round-2/" },
      { BASELINE_COHERENCE: "r2.json" },
      { EMIT_COHERENCE: "r3.json" },
      { FAIL_ON_COHERENCE_REGRESSION: "true" },
    ];
    for (const inputs of cases) {
      expect(() => argv({ FILES: "round-3/", ...inputs }), JSON.stringify(inputs)).toThrow();
    }
  });

  it("refuses the coherence gate with nothing to compare against", () => {
    expect(() =>
      argv({
        FILES: "round-3/",
        PLAYBOOK_FILE: "team.json",
        FAIL_ON_COHERENCE_REGRESSION: "true",
      }),
    ).toThrow();
  });

  it("composes a line the real analyze parser accepts", async () => {
    const { resolveAnalyzeArgs } = await import("../../tools/cli/run.js");
    const line = argv({
      FILES: "round-3/",
      PLAYBOOK_FILE: "team.json",
      POSTURE: "true",
      ROLE: "customer",
      DEAL_VALUE: "2500000",
      BASELINE: "round-2/",
      EMIT_COHERENCE: "round-3.coherence.json",
      FAIL_ON_COHERENCE_REGRESSION: "true",
    });
    const parsed = await resolveAnalyzeArgs(line.split(" ").slice(1));
    expect(parsed.posture).toBe(true);
    expect(parsed.baseline).toBe("round-2/");
    expect(parsed.role).toBe("customer");
    expect(parsed.dealValue).toBe(2_500_000);
    expect(parsed.emitCoherence).toBe("round-3.coherence.json");
    expect(parsed.failOnCoherenceRegression).toBe(true);
  });
});

describe("the Action can check a signed copy against its final", () => {
  it("reads base and revised as the final and its signed copy", () => {
    const line = argv({
      CMD: "compare",
      EXECUTED: "true",
      BASE: "final.docx",
      REVISED: "signed.pdf",
      FAIL_ON_NONCONFORMITY: "true",
    });
    // The flag precedes the positionals, which is the order the CLI prints.
    expect(line).toBe("compare --executed final.docx signed.pdf --fail-on-nonconformity");
  });

  it("reads them as two folders under executed-set, and pairs by title", () => {
    const line = argv({
      CMD: "compare",
      EXECUTED_SET: "true",
      BASE: "./finals",
      REVISED: "./signed",
      FAIL_ON_NONCONFORMITY: "true",
      FORMAT: "markdown",
    });
    expect(line).toContain("--executed-set ./finals ./signed");
    expect(line).toContain("--fail-on-nonconformity");
  });

  it("refuses the two modes together, and the gate without either", () => {
    expect(() =>
      argv({
        CMD: "compare",
        EXECUTED: "true",
        EXECUTED_SET: "true",
        BASE: "a",
        REVISED: "b",
      }),
    ).toThrow();
    expect(() =>
      argv({ CMD: "compare", BASE: "a.docx", REVISED: "b.docx", FAIL_ON_NONCONFORMITY: "true" }),
    ).toThrow();
  });

  it("refuses the inputs executed-set does not apply to, naming each", () => {
    // The CLI rejects --posture, --fail-on and --fail-on-regression beside
    // --executed-set. The Action refuses the INPUT, so the message names what
    // the caller wrote.
    const cases: Record<string, string>[] = [
      { FAIL_ON: "critical" },
      { POSTURE: "true" },
      { FAIL_ON_REGRESSION: "true" },
    ];
    for (const inputs of cases) {
      expect(
        () =>
          argv({
            CMD: "compare",
            EXECUTED_SET: "true",
            BASE: "./finals",
            REVISED: "./signed",
            ...inputs,
          }),
        JSON.stringify(inputs),
      ).toThrow();
    }
  });

  it("confirms a cross-family pairing and gates on a posture regression", () => {
    const line = argv({
      CMD: "compare",
      BASE: "a.docx",
      REVISED: "b.docx",
      CONFIRM_PAIRING: "true",
      PLAYBOOK_FILE: "team.json",
      FAIL_ON_REGRESSION: "true",
    });
    expect(line).toContain("--confirm-pairing");
    expect(line).toContain("--playbook-file team.json");
    expect(line).toContain("--posture --fail-on-regression");
    expect(() =>
      argv({ CMD: "compare", BASE: "a.docx", REVISED: "b.docx", FAIL_ON_REGRESSION: "true" }),
    ).toThrow();
  });

  it("carries the playbook file to compare, which scores against it too", () => {
    // It was declared, documented, and appended only under analyze: a compare
    // run scored against the built-in match however the input was set.
    expect(
      argv({ CMD: "compare", BASE: "a.docx", REVISED: "b.docx", PLAYBOOK_FILE: "team.json" }),
    ).toContain("--playbook-file team.json");
  });

  it("composes lines the real compare parser accepts", async () => {
    const { parseCompareArgs } = await import("../../tools/cli/compare.js");
    const pair = parseCompareArgs(
      argv({
        CMD: "compare",
        EXECUTED: "true",
        BASE: "final.docx",
        REVISED: "signed.pdf",
        FAIL_ON_NONCONFORMITY: "true",
      })
        .split(" ")
        .slice(1),
    );
    expect(pair.executed).toBe(true);
    expect(pair.failOnNonconformity).toBe(true);
    expect(pair.base).toBe("final.docx");
    expect(pair.revised).toBe("signed.pdf");

    const set = parseCompareArgs(
      argv({
        CMD: "compare",
        EXECUTED_SET: "true",
        BASE: "./finals",
        REVISED: "./signed",
        FAIL_ON_NONCONFORMITY: "true",
        FORMAT: "json",
      })
        .split(" ")
        .slice(1),
    );
    expect(set.executedSet).toBe(true);
    expect(set.format).toBe("json");

    const regression = parseCompareArgs(
      argv({
        CMD: "compare",
        BASE: "a.docx",
        REVISED: "b.docx",
        CONFIRM_PAIRING: "true",
        PLAYBOOK_FILE: "team.json",
        FAIL_ON_REGRESSION: "true",
      })
        .split(" ")
        .slice(1),
    );
    expect(regression.posture).toBe(true);
    expect(regression.failOnRegression).toBe(true);
    expect(regression.confirmPairing).toBe(true);
    expect(regression.playbookFile).toBe("team.json");
  });
});
