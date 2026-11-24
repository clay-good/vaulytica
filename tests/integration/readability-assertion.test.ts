/**
 * An asserted readability statute (add-readability-measure, task 4):
 * `--readability fl` holds a document to Fla. Stat. § 627.4145, read at its
 * official source. Without the assertion nothing changes, hash included.
 */
import { describe, expect, it } from "vitest";
import { analyzeText, loadAccuracyDeps } from "../../tools/cli/api.js";
import { verifyReproducibility, type SavedReport } from "../../tools/cli/verify.js";
import { READABILITY_STANDARDS } from "../../src/readability/standards.js";
import { resolveAnalyzeArgs } from "../../tools/cli/run.js";

const DENSE = `HOMEOWNERS INSURANCE POLICY

The insurer's obligation to indemnify the insured for consequential, incidental, or derivative losses occasioned by the occurrence of any peril enumerated in the declarations, notwithstanding any contrary provision of any endorsement, rider, or supplementary documentation incorporated by reference, shall be determined exclusively in accordance with the provisions of the applicable valuation methodology and the limitations, conditions, and exclusions specified in this policy.
`;
const PLAIN = `HOMEOWNERS INSURANCE POLICY

We pay for loss to your home. We do not pay for wear and tear. You must tell us of a loss soon. We will pay you within thirty days.
`;

describe("--readability fl", () => {
  it("reports a dense form below the statute's 45, with its counts", async () => {
    const deps = await loadAccuracyDeps({});
    const r = await analyzeText(DENSE, "policy.txt", { deps, readability: "fl" });
    expect(r.run.asserted_readability).toBe("fl");
    const f = r.run.findings.find((x) => x.rule_id === "READ-001");
    expect(f?.title).toMatch(/below the 45 Fla\. Stat\. § 627\.4145 requires/);
    expect(f?.explanation).toMatch(/does not apply the sampling/);
  });

  it("says nothing about a plain one", async () => {
    const deps = await loadAccuracyDeps({});
    const r = await analyzeText(PLAIN, "policy.txt", { deps, readability: "fl" });
    expect(r.run.findings.some((x) => x.rule_id.startsWith("READ-"))).toBe(false);
  });

  it("reports a form over 3,000 words with no table of contents, and accepts one with", async () => {
    const deps = await loadAccuracyDeps({});
    const body = Array.from(
      { length: 400 },
      (_v, i) => `We pay for loss number ${i} to your home.`,
    ).join(" ");
    const long = await analyzeText(`HOMEOWNERS POLICY\n\n${body}\n`, "policy.txt", {
      deps,
      readability: "fl",
    });
    expect(long.run.findings.map((x) => x.rule_id)).toContain("READ-002");
    const withContents = await analyzeText(
      `HOMEOWNERS POLICY\n\nTABLE OF CONTENTS\n\nCoverage ........ 2\n\n${body}\n`,
      "policy.txt",
      { deps, readability: "fl" },
    );
    expect(withContents.run.findings.map((x) => x.rule_id)).not.toContain("READ-002");
  });

  it("changes nothing without the assertion", async () => {
    const deps = await loadAccuracyDeps({});
    const r = await analyzeText(DENSE, "policy.txt", { deps });
    expect(r.run.asserted_readability).toBeUndefined();
    expect(r.run.execution_log.some((e) => e.rule_id.startsWith("READ-"))).toBe(false);
  });

  it("is re-derived by verify, so the saved report reproduces", async () => {
    const deps = await loadAccuracyDeps({});
    const r = await analyzeText(DENSE, "policy.txt", { deps, readability: "fl" });
    const saved = JSON.parse(JSON.stringify({ run: r.run })) as SavedReport;
    const result = await verifyReproducibility(saved, DENSE, { deps });
    expect(result.reproduced, JSON.stringify(result.divergences)).toBe(true);
  });

  it("refuses an unknown standard, and every standard names an official source", async () => {
    await expect(resolveAnalyzeArgs(["policy.txt", "--readability", "zz"])).rejects.toThrow(
      /unknown --readability/,
    );
    expect((await resolveAnalyzeArgs(["policy.txt", "--readability", "FL"])).readability).toBe(
      "fl",
    );
    for (const s of READABILITY_STANDARDS) {
      expect(new URL(s.source_url).hostname).toMatch(OFFICIAL_HOSTS[s.id] ?? /^$/);
      expect(s.retrieved_at).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    }
  });
});

/** Each standard's official host: the legislature's own statute site. */
const OFFICIAL_HOSTS: Record<string, RegExp> = {
  fl: /^www\.leg\.state\.fl\.us$/,
  me: /^legislature\.maine\.gov$/,
  mi: /^www\.legislature\.mi\.gov$/,
  mn: /^www\.revisor\.mn\.gov$/,
  nv: /^www\.leg\.state\.nv\.us$/,
  oh: /^codes\.ohio\.gov$/,
  or: /^www\.oregonlegislature\.gov$/,
  mt: /^leg\.mt\.gov$/,
  wv: /^code\.wvlegislature\.gov$/,
  nd: /^ndlegis\.gov$/,
  ne: /^nebraskalegislature\.gov$/,
  dc: /^code\.dccouncil\.gov$/,
  ok: /^www\.oscn\.net$/,
  // The New York State Senate's own site. Its API host
  // (legislation.nysenate.gov) answers 401 to an unauthenticated read, so the
  // public page is the official source used.
  "ny-consumer": /^www\.nysenate\.gov$/,
};

// Scores 46: below Maine's 50, above Florida's and Michigan's 45.
const MIDDLING = `HOMEOWNERS INSURANCE POLICY

We will pay for direct physical loss to the dwelling described in the declarations, subject to the conditions and exclusions of this policy. You must notify us promptly after any loss and cooperate with our investigation of the claim.
`;

describe("--readability me and mi", () => {
  it("holds a form to each statute's own minimum", async () => {
    const deps = await loadAccuracyDeps({});
    const ids = async (standard: string) =>
      (await analyzeText(MIDDLING, "policy.txt", { deps, readability: standard })).run.findings
        .filter((f) => f.rule_id.startsWith("READ-"))
        .map((f) => f.title);
    expect(await ids("me")).toEqual([
      "Reading ease 46 is below the 50 24-A M.R.S. § 2441 requires",
    ]);
    expect(await ids("fl")).toEqual([]);
    expect(await ids("mi")).toEqual([]);
    expect(await ids("nv")).toEqual([]);
    expect(await ids("oh")).toEqual([]);
    expect(await ids("or")).toEqual([]);
    expect(await ids("mt")).toEqual([]);
    expect(await ids("wv")).toEqual([]);
    expect(await ids("nd")).toEqual([]);
    expect(await ids("ne")).toEqual([]);
    expect(await ids("dc")).toEqual([]);
    expect(await ids("ok")).toEqual([]);
  });

  it("accepts an index for Maine but not for Michigan, which asks for a table of contents", async () => {
    const deps = await loadAccuracyDeps({});
    const body = Array.from(
      { length: 400 },
      (_v, i) => `We pay for loss number ${i} to your home.`,
    ).join(" ");
    const withIndex = `HOMEOWNERS POLICY\n\nINDEX\n\nCoverage, 2\n\n${body}\n`;
    const me = await analyzeText(withIndex, "policy.txt", { deps, readability: "me" });
    expect(me.run.findings.map((x) => x.rule_id)).not.toContain("READ-002");
    const mi = await analyzeText(withIndex, "policy.txt", { deps, readability: "mi" });
    const f = mi.run.findings.find((x) => x.rule_id === "READ-002");
    expect(f?.title).toBe("No table of contents");
    expect(f?.explanation).toMatch(/an index does not satisfy it/);
    const withContents = await analyzeText(
      `HOMEOWNERS POLICY\n\nTABLE OF CONTENTS\n\nCoverage ........ 2\n\n${body}\n`,
      "policy.txt",
      { deps, readability: "mi" },
    );
    expect(withContents.run.findings.map((x) => x.rule_id)).not.toContain("READ-002");
  });
});

describe("--readability mn", () => {
  it("asks for MORE than 40, and an index in every policy whatever its length", async () => {
    const deps = await loadAccuracyDeps({});
    const r = await analyzeText(DENSE, "policy.txt", { deps, readability: "mn" });
    const titles = r.run.findings.filter((f) => f.rule_id.startsWith("READ-")).map((f) => f.title);
    expect(titles).toHaveLength(2);
    expect(titles[0]).toMatch(
      /^Reading ease -?[\d.]+ is not above the 40 Minn\. Stat\. §§ 72C\.08–72C\.10 requires$/,
    );
    expect(titles[1]).toBe("No index of the major provisions");
    // Florida asks for no contents in a form this short.
    const fl = await analyzeText(DENSE, "policy.txt", { deps, readability: "fl" });
    expect(fl.run.findings.map((f) => f.rule_id)).not.toContain("READ-002");
  });

  it("takes an index heading as the index, and passes a plain policy that has one", async () => {
    const deps = await loadAccuracyDeps({});
    const indexed = PLAIN.replace("\n\n", "\n\nINDEX\n\nWhat we cover, 1\n\n");
    const r = await analyzeText(indexed, "policy.txt", { deps, readability: "mn" });
    expect(r.run.findings.filter((f) => f.rule_id.startsWith("READ-"))).toEqual([]);
  });
});

describe("the readability block", () => {
  it("never changes the run or its hash, for any specimen", async () => {
    const { readdirSync, readFileSync } = await import("node:fs");
    const { join } = await import("node:path");
    const { buildJsonReport } = await import("../../src/report/json.js");
    const deps = await loadAccuracyDeps({});
    const dir = join(process.cwd(), "tests", "fixtures", "specimens");
    const sample = readdirSync(dir)
      .filter((f) => f.endsWith(".txt"))
      .sort()
      .filter((_f, i) => i % 9 === 0);
    for (const name of sample) {
      const r = await analyzeText(readFileSync(join(dir, name), "utf8"), name, { deps });
      const before = JSON.stringify(r.run);
      const json = JSON.parse(await buildJsonReport(r.run, r.ingest).text()) as {
        run: { result_hash: string };
        readability: { score: number };
      };
      expect(typeof json.readability.score, name).toBe("number");
      expect(json.run.result_hash, name).toBe(r.run.result_hash);
      expect(JSON.stringify(r.run), name).toBe(before);
    }
  }, 300_000);
});

/**
 * New York's § 5-702 (add-readability-measure, `READ-003`) — the odd one out.
 *
 * Every other row in the standards table is an insurance readability statute
 * that sets a Flesch minimum. § 5-702 sets NO score and no table-of-contents
 * rule: it requires a consumer agreement to be "appropriately divided and
 * captioned by its various sections", and separately to be written "in a clear
 * and coherent manner using words with common and every day meanings", which
 * is a judgment no formula makes. So the three assertions worth making are
 * that READ-003 fires on an uncaptioned agreement, that READ-001 and READ-002
 * stay silent under a standard that sets neither threshold, and that the
 * finding says what it did not measure.
 *
 * The lease below is task 5's "uncaptioned lease" fixture: a complete,
 * ordinarily-drafted residential lease whose only defect is that its terms run
 * as unheaded paragraphs.
 */
const UNCAPTIONED_LEASE = `RESIDENTIAL LEASE AGREEMENT

This Lease is made on March 1, 2026 between Harbor Street Holdings LLC ("Landlord") and Dana Whitfield ("Tenant") for the apartment at 418 Harbor Street, Apartment 3R, Brooklyn, New York.

Tenant will pay rent of $2,450 each month, due on the first day of the month. Rent is paid to Landlord at the address above or any address Landlord gives Tenant in writing.

The term of this Lease is one year. It begins on April 1, 2026 and ends on March 31, 2027. Tenant may stay on after that only with Landlord's written consent.

Tenant will pay a security deposit of $2,450 before moving in. Landlord will hold the deposit in an interest-bearing account at a New York bank and will return it, with interest, within fourteen days after Tenant moves out, less any amount Tenant owes.

Tenant will use the apartment only as a home for Tenant and Tenant's family. Tenant will not sublet the apartment or let anyone else take it over without Landlord's written consent.

Landlord will keep the building and its systems in good repair. Tenant will tell Landlord promptly of anything that needs repair and will let Landlord in to make it, after reasonable notice.

Tenant will not keep a dog or cat in the apartment without Landlord's written consent. Tenant will not make any alteration to the apartment without that consent.

If Tenant does not pay rent when it is due, Landlord may end this Lease after giving Tenant the notice the law requires. Each party will pay its own legal costs in any dispute about this Lease.

This Lease is governed by the law of the State of New York.
`;

/** The same lease, with each of its terms under a heading. */
const CAPTIONED_LEASE = UNCAPTIONED_LEASE.replace(
  "Tenant will pay rent of",
  "1. Rent.\n\nTenant will pay rent of",
)
  .replace("The term of this Lease is", "2. Term.\n\nThe term of this Lease is")
  .replace(
    "Tenant will pay a security deposit",
    "3. Security Deposit.\n\nTenant will pay a security deposit",
  )
  .replace(
    "Tenant will use the apartment",
    "4. Use and Subletting.\n\nTenant will use the apartment",
  )
  .replace("Landlord will keep the building", "5. Repairs.\n\nLandlord will keep the building")
  .replace("Tenant will not keep a dog", "6. Pets and Alterations.\n\nTenant will not keep a dog")
  .replace("If Tenant does not pay rent", "7. Default.\n\nIf Tenant does not pay rent")
  .replace("This Lease is governed by", "8. Governing Law.\n\nThis Lease is governed by");

describe("--readability ny-consumer", () => {
  it("reports a consumer agreement whose sections carry no captions", async () => {
    const deps = await loadAccuracyDeps({});
    const r = await analyzeText(UNCAPTIONED_LEASE, "lease.txt", {
      deps,
      readability: "ny-consumer",
    });
    expect(r.run.asserted_readability).toBe("ny-consumer");
    const f = r.run.findings.find((x) => x.rule_id === "READ-003");
    expect(f, JSON.stringify(r.run.findings.map((x) => x.rule_id))).toBeDefined();
    expect(f!.description).toContain("appropriately divided and captioned by its various sections");
    // It must say what it did NOT measure, or a reader takes the finding for
    // the whole statute.
    expect(f!.explanation).toContain("clear and coherent manner");
    expect(f!.explanation).toContain("not judged here");
    // And that the $250,000 ceiling was not applied, because the agreement's
    // value is never read.
    expect(f!.description).toContain("$250,000");
    expect(f!.description).toContain("value was not read");
  });

  it("says nothing about the same lease once its sections are captioned", async () => {
    const deps = await loadAccuracyDeps({});
    const r = await analyzeText(CAPTIONED_LEASE, "lease.txt", {
      deps,
      readability: "ny-consumer",
    });
    expect(r.run.findings.some((x) => x.rule_id === "READ-003")).toBe(false);
  });

  it("draws no score or contents finding, because § 5-702 sets neither", async () => {
    // The lease is plain English and the dense policy is not, but neither
    // matters here: a standard with no `min_score` must not produce READ-001,
    // and one with no `contents_over` must not produce READ-002, however the
    // document reads. Asserting this on the DENSE policy is the sharp case —
    // it scores far below every insurance statute's minimum.
    const deps = await loadAccuracyDeps({});
    const r = await analyzeText(DENSE, "agreement.txt", { deps, readability: "ny-consumer" });
    expect(r.run.findings.some((x) => x.rule_id === "READ-001")).toBe(false);
    expect(r.run.findings.some((x) => x.rule_id === "READ-002")).toBe(false);
  });

  it("still reports the score on the cover, saying the statute sets none", async () => {
    // The cover line is the surface a reader sees first, and a standard with
    // no threshold must not print "minimum undefined" there — nor print the
    // score beside § 5-702 with no word, which would read as a threshold the
    // statute never set.
    const { ingestPaste } = await import("../../src/ingest/index.js");
    const { measureReadability, readabilityLine } = await import("../../src/report/readability.js");
    const tree = (await ingestPaste(UNCAPTIONED_LEASE)).tree;
    const std = READABILITY_STANDARDS.find((s) => s.id === "ny-consumer")!;
    const line = readabilityLine(measureReadability(tree), std);
    expect(line).toContain("sets no score");
    expect(line).not.toContain("undefined");
    expect(line).not.toMatch(/\bminimum \d/);
    // Florida's line is unchanged by the same call.
    const fl = READABILITY_STANDARDS.find((s) => s.id === "fl")!;
    expect(readabilityLine(measureReadability(tree), fl)).toMatch(/\(minimum 45\)/);
  });

  it("leaves an insurance statute's score behaviour alone", async () => {
    // The guard on the change itself: making `min_score` optional must not
    // have made Florida's threshold optional in practice.
    const deps = await loadAccuracyDeps({});
    const r = await analyzeText(DENSE, "policy.txt", { deps, readability: "fl" });
    expect(r.run.findings.some((x) => x.rule_id === "READ-001")).toBe(true);
    expect(r.run.findings.some((x) => x.rule_id === "READ-003")).toBe(false);
  });
});

/**
 * READ-003's false-positive sweep, which is what shaped the rule.
 *
 * `READ-003` is an ABSENCE finding, and the clean-document method says every
 * absence finding drawn on a well-drafted document is a bug. Asserting
 * `ny-consumer` over all 363 specimens is the cheap version of that: most are
 * not § 5-702 consumer agreements at all, but nearly all are captioned, so any
 * hit is a caption style the detector cannot read.
 *
 * Three rounds, each a real defect the sweep found and nothing else would have:
 *   - 32 hits. The detector read only the ingest's OUTLINE, and a plain-text
 *     document has no section headings at all, whatever its captions.
 *   - 10 hits. `1. PURPOSE AND SCOPE` — a numbered ALL-CAPS caption with no
 *     terminating punctuation, the commonest form in American legal drafting.
 *   - 9 hits. `uk-contract-of-employment`, captioned throughout, whose caption
 *     line runs into `1.1` with no blank line, leaving a trailing numeral that
 *     was read as an uncapitalized content word.
 *   - 0 hits, with the uncaptioned lease above still reported.
 */
describe("READ-003 over the corpus", () => {
  it("draws nothing on any specimen, while still firing on an undivided one", async () => {
    const { readdirSync, readFileSync } = await import("node:fs");
    const { join } = await import("node:path");
    const dir = join(process.cwd(), "tests", "fixtures", "specimens");
    const names = readdirSync(dir).filter((n) => n.endsWith(".txt") || n.endsWith(".md"));
    expect(names.length, "no specimens found — the sweep would be vacuous").toBeGreaterThan(300);
    const deps = await loadAccuracyDeps({});
    const hits: string[] = [];
    for (const name of names) {
      const r = await analyzeText(readFileSync(join(dir, name), "utf8"), name, {
        deps,
        readability: "ny-consumer",
      });
      if (r.run.findings.some((f) => f.rule_id === "READ-003")) hits.push(name);
    }
    expect(
      hits,
      `READ-003 called these uncaptioned; check each before widening the detector:\n  ${hits.join("\n  ")}`,
    ).toEqual([]);
    // 🚨 And the rule must still be able to FAIL, or zero hits means nothing.
    const lease = await analyzeText(UNCAPTIONED_LEASE, "lease.txt", {
      deps,
      readability: "ny-consumer",
    });
    expect(lease.run.findings.some((f) => f.rule_id === "READ-003")).toBe(true);
  }, 300_000);
});
