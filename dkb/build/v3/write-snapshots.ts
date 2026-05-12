#!/usr/bin/env node
/**
 * Snapshot-fixture generator. Writes hand-authored excerpts of each
 * v3 source under `dkb/fixtures/v3/snapshots/{sha256(url)}.txt`. The
 * fetchers read from this directory in offline mode (CI and tests).
 *
 * Re-run this script when a new fetcher source is added; the parsers
 * are tolerant of incremental snapshot growth.
 */

import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const SNAPSHOTS_DIR = join(process.cwd(), "dkb", "fixtures", "v3", "snapshots");

const SNAPSHOTS: Array<{ url: string; text: string }> = [
  {
    url: "https://www.ecfr.gov/api/versioner/v1/full/2026-05-12/title-45.xml?part=164",
    text: `Excerpts from 45 C.F.R. Part 164 — HIPAA Privacy and Security Rules.

§ 164.502(e)(1)(i) — A covered entity may disclose protected health information to a business associate only if the covered entity obtains satisfactory assurances that the business associate will appropriately safeguard the information.

§ 164.504(e) — Business associate contracts. The contract or other arrangement required by § 164.502(e) must:
  (2)(i) Establish the permitted and required uses and disclosures of such information by the business associate.
  (2)(ii)(C) Require the business associate to report to the covered entity any use or disclosure of the information not provided for by its contract of which it becomes aware, including breaches of unsecured protected health information.
  (2)(ii)(D) Ensure that any subcontractors that create, receive, maintain, or transmit protected health information on behalf of the business associate agree to the same restrictions and conditions that apply to the business associate.
  (2)(iii) Authorize termination of the contract by the covered entity, if the covered entity determines that the business associate has violated a material term.

§ 164.410 — Notification by a business associate. Following the discovery of a breach of unsecured protected health information, a business associate shall notify the covered entity. Such notifications must be made without unreasonable delay and in no case later than 60 calendar days after discovery of a breach.

§ 164.314(a) — Business associate contracts must require the business associate to comply, where applicable, with the Security Rule with respect to electronic protected health information.`,
  },
  {
    url: "https://www.hhs.gov/hipaa/for-professionals/covered-entities/sample-business-associate-agreement-provisions/index.html",
    text: `<html><body>
<h1>Sample Business Associate Agreement Provisions</h1>

<h2>Permitted Uses and Disclosures by Business Associate</h2>
<p>Business Associate may only use or disclose Protected Health Information consistent with this Agreement or as required by law.</p>

<h2>Reporting of Improper Use or Disclosure</h2>
<p>Business Associate shall report to Covered Entity any use or disclosure of PHI not provided for by this Agreement.</p>

<h2>Subcontractors</h2>
<p>In accordance with 45 CFR 164.502(e)(1)(ii) and 164.308(b)(2), Business Associate shall ensure that any subcontractors agree to the same restrictions and conditions.</p>

<h2>Access to PHI</h2>
<p>Business Associate shall provide access to PHI in a Designated Record Set as necessary to satisfy 45 CFR 164.524.</p>

<h2>Amendment of PHI</h2>
<p>Business Associate shall make amendment to PHI in a Designated Record Set as directed pursuant to 45 CFR 164.526.</p>

<h2>Accounting of Disclosures</h2>
<p>Business Associate shall maintain and make available the information required to provide an accounting of disclosures.</p>

<h2>Termination for Breach</h2>
<p>Upon Covered Entity's knowledge of a material breach by Business Associate, Covered Entity shall provide an opportunity to cure and may terminate.</p>
</body></html>`,
  },
  {
    url: "https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/agreements/index.html",
    text: `<html><body><h1>HIPAA Settlements and Resolution Agreements</h1>
<ul>
<li><a href="/agreement-2024-cardio">2024 Cardio Clinic Resolution Agreement</a></li>
<li><a href="/agreement-2023-uhh">2023 University Health Holdings Resolution Agreement</a></li>
<li><a href="/agreement-2022-cnv">2022 CityNet Vendor Settlement</a></li>
</ul></body></html>`,
  },
  {
    url: "https://leginfo.legislature.ca.gov/faces/codes_displayText.xhtml?division=3.&part=4.&lawCode=CIV&title=1.81.5",
    text: `§ 1798.100. (d) A business that collects a consumer's personal information and that sells that personal information to, or shares it with, a third party or that discloses it to a service provider or contractor for a business purpose, shall enter into an agreement with the third party, service provider, or contractor that obligates the third party, service provider, or contractor to comply with applicable obligations under this title and to provide the same level of privacy protection as required by this title.

§ 1798.140. (ag)(1) "Service provider" means a person that processes personal information on behalf of a business and that receives from or on behalf of the business consumer's personal information for a business purpose pursuant to a written contract, provided that the contract prohibits the service provider from:
  (A) Selling or sharing the personal information, including for cross-context behavioral advertising.
  (B) Retaining, using, or disclosing the personal information for any purpose other than the specific business purpose enumerated in the contract.
  (C) Retaining, using, or disclosing the information outside of the direct business relationship between the service provider and the business.`,
  },
  {
    url: "https://oag.ca.gov/privacy/ccpa/regs",
    text: `Cal. Code Regs. tit. 11, § 7051 — Contract Requirements for Service Providers and Contractors.

(a) A written contract with a service provider or contractor shall:
  (1) Identify the specific business purpose(s) for which the service provider or contractor is processing personal information;
  (2) Prohibit the service provider or contractor from selling or sharing personal information;
  (3) Prohibit the service provider or contractor from retaining, using, or disclosing personal information outside the direct business relationship;
  (4) Require the service provider or contractor to comply with all applicable obligations under the CCPA, including providing the same level of privacy protection;
  (5) Grant the business the right to take reasonable and appropriate steps to ensure that the service provider or contractor uses the personal information in a manner consistent with the business's obligations under the CCPA;
  (6) Require the service provider or contractor to notify the business if it makes a determination that it can no longer meet its obligations under the CCPA;
  (7) Grant the business the right, upon notice, to take reasonable and appropriate steps to stop and remediate unauthorized use of personal information;
  (8) Require the service provider or contractor to enable the business to comply with verifiable consumer requests.`,
  },
  {
    url: "https://law.lis.virginia.gov/vacodefull/title59.1/chapter53/",
    text: `§ 59.1-579. Data processing agreements.
A. A contract between a controller and a processor shall govern the processor's data processing procedures with respect to processing performed on behalf of the controller. The contract shall be binding and clearly set forth instructions for processing data, the nature and purpose of processing, the type of data subject to processing, the duration of processing, and the rights and obligations of both parties. The contract shall also include requirements that the processor shall:
  1. Ensure that each person processing personal data is subject to a duty of confidentiality with respect to the data;
  2. At the controller's direction, delete or return all personal data to the controller as requested at the end of the provision of services;
  3. Upon the reasonable request of the controller, make available to the controller all information in its possession necessary to demonstrate the processor's compliance with this chapter;
  4. Allow, and cooperate with, reasonable assessments by the controller or the controller's designated assessor; and
  5. Engage any subcontractor pursuant to a written contract that requires the subcontractor to meet the obligations of the processor with respect to the personal data.`,
  },
  {
    url: "https://leg.colorado.gov/sites/default/files/2021a_190_signed.pdf",
    text: `§ 6-1-1305. Data processing contract requirements.
(5) A contract between a controller and a processor shall be binding on both parties and shall clearly set forth:
  (a) Processing instructions to which the processor is bound, including the nature and purpose of the processing;
  (b) The type of personal data subject to the processing and the duration of the processing;
  (c) The rights and obligations of both parties;
  (d) A requirement that the processor delete or return all personal data to the controller as requested at the end of the provision of services unless retention is required by law; and
  (e) A requirement that the processor make available to the controller information necessary to demonstrate compliance with this part.`,
  },
  {
    url: "https://www.cga.ct.gov/2022/ACT/PA/PDF/2022PA-00015-R00SB-00006-PA.PDF",
    text: `Sec. 8 (codified at Conn. Gen. Stat. § 42-520). Processor obligations.
(b) A contract between a controller and a processor shall govern the processor's data processing procedures with respect to processing performed on behalf of the controller. The contract shall be binding, clearly set forth instructions for processing data, the nature and purpose of processing, the type of personal data, the duration of processing, and the obligations and rights of both parties. The contract shall also require the processor to:
  (1) Ensure that each person processing personal data is subject to a duty of confidentiality;
  (2) At the controller's direction, delete or return all personal data to the controller at the end of services;
  (3) Make available to the controller information necessary to demonstrate compliance;
  (4) Engage any subcontractor pursuant to a written contract that requires the subcontractor to meet the same obligations.`,
  },
  {
    url: "https://le.utah.gov/xcode/Title13/Chapter61/13-61.html",
    text: `§ 13-61-301. Processor obligations.
(2) A contract between a controller and a processor shall clearly set forth:
  (a) instructions for processing personal data;
  (b) the nature and purpose of the processing;
  (c) the type of data subject to processing;
  (d) the duration of processing; and
  (e) the rights and obligations of both parties.
(3) Before a processor engages a subcontractor, the processor shall enter into a written contract with the subcontractor that requires the subcontractor to meet the obligations of the processor with respect to the personal data.`,
  },
  {
    url: "https://capitol.texas.gov/tlodocs/88R/billtext/html/HB00004F.HTM",
    text: `§ 541.104. Data processing contract requirements.
(a) A contract between a controller and a processor must be binding and clearly set forth:
  (1) instructions for processing personal data;
  (2) the nature and purpose of the processing;
  (3) the type of personal data subject to processing;
  (4) the duration of processing;
  (5) the rights and obligations of both parties.
(b) The contract must require the processor to:
  (1) ensure that each person processing personal data is subject to a duty of confidentiality;
  (2) delete or return all personal data to the controller at the controller's direction at the end of services;
  (3) make available to the controller information necessary to demonstrate compliance;
  (4) allow reasonable assessments by the controller; and
  (5) engage any subcontractors pursuant to a written contract that imposes the same obligations.`,
  },
  {
    url: "https://olis.oregonlegislature.gov/liz/2023R1/Downloads/MeasureDocument/SB0619",
    text: `§ 646A.578. Contract between controller and processor.
(1) A contract between a controller and processor shall include processing instructions, the nature and purpose of processing, the type of personal data, the duration of processing, deletion or return of personal data at the end of services, and shall require the processor to engage subcontractors pursuant to a written contract imposing the same obligations as those of the processor.`,
  },
  {
    url: "https://delcode.delaware.gov/title6/c012D/",
    text: `§ 12D-107. Processor obligations.
(b) A contract between a controller and a processor shall be binding and shall set forth:
  (1) instructions for processing personal data;
  (2) the nature and purpose of processing;
  (3) the type of personal data;
  (4) the duration of processing;
  (5) audit rights of the controller;
  (6) confidentiality obligations of the processor and its personnel; and
  (7) a requirement that the processor engage any subcontractor pursuant to a written contract that imposes the same obligations on the subcontractor.`,
  },
];

const main = (): void => {
  mkdirSync(SNAPSHOTS_DIR, { recursive: true });
  for (const { url, text } of SNAPSHOTS) {
    const file = `${createHash("sha256").update(url).digest("hex")}.txt`;
    writeFileSync(join(SNAPSHOTS_DIR, file), text, "utf8");
    process.stdout.write(`wrote ${file} (${url})\n`);
  }
};

const isMain = (): boolean => {
  const argv1 = process.argv[1];
  if (!argv1) return false;
  return argv1.endsWith("write-snapshots.ts") || argv1.endsWith("write-snapshots.js");
};
if (isMain()) main();

export { SNAPSHOTS };
