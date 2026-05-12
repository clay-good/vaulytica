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
    url: "https://eur-lex.europa.eu/eli/reg/2016/679/oj",
    text: `Regulation (EU) 2016/679 — General Data Protection Regulation (GDPR).

Article 28 — Processor.
3. Processing by a processor shall be governed by a contract or other legal act under Union or Member State law, that is binding on the processor with regard to the controller and that sets out the subject-matter and duration of the processing, the nature and purpose of the processing, the type of personal data and categories of data subjects and the obligations and rights of the controller. That contract or other legal act shall stipulate, in particular, that the processor:
  (a) processes the personal data only on documented instructions from the controller;
  (b) ensures that persons authorised to process the personal data have committed themselves to confidentiality;
  (c) takes all measures required pursuant to Article 32;
  (d) respects the conditions referred to in paragraphs 2 and 4 for engaging another processor;
  (e) taking into account the nature of the processing, assists the controller by appropriate technical and organisational measures;
  (f) assists the controller in ensuring compliance with the obligations pursuant to Articles 32 to 36;
  (g) at the choice of the controller, deletes or returns all the personal data to the controller after the end of the provision of services;
  (h) makes available to the controller all information necessary to demonstrate compliance.

Article 32 — Security of processing. Taking into account the state of the art, the costs of implementation and the nature, scope, context and purposes of processing, the controller and the processor shall implement appropriate technical and organisational measures to ensure a level of security appropriate to the risk, including pseudonymisation and encryption of personal data; the ability to ensure ongoing confidentiality, integrity, availability and resilience of processing systems; the ability to restore availability and access to personal data in a timely manner; and a process for regularly testing, assessing and evaluating the effectiveness of measures.

Article 33 — Notification of a personal data breach to the supervisory authority.
1. In the case of a personal data breach, the controller shall without undue delay and, where feasible, not later than 72 hours after having become aware of it, notify the personal data breach to the competent supervisory authority.
2. The processor shall notify the controller without undue delay after becoming aware of a personal data breach.

Article 44 — General principle for transfers. Any transfer of personal data which are undergoing processing or are intended for processing after transfer to a third country or to an international organisation shall take place only if, subject to the other provisions of this Regulation, the conditions laid down in this Chapter are complied with by the controller and processor.

Article 46 — Transfers subject to appropriate safeguards. In the absence of a decision pursuant to Article 45(3), a controller or processor may transfer personal data to a third country or an international organisation only if the controller or processor has provided appropriate safeguards, and on condition that enforceable data subject rights and effective legal remedies for data subjects are available.`,
  },
  {
    url: "https://eur-lex.europa.eu/eli/dec_impl/2021/914/oj",
    text: `Commission Implementing Decision (EU) 2021/914 of 4 June 2021 on standard contractual clauses for the transfer of personal data to third countries pursuant to Regulation (EU) 2016/679 of the European Parliament and of the Council.

ANNEX. STANDARD CONTRACTUAL CLAUSES.

Module 1: Transfer Controller to Controller.
Module 2: Transfer Controller to Processor.
Module 3: Transfer Processor to Processor.
Module 4: Transfer Processor to Controller.

Clause 1 — Purpose and scope.
Clause 2 — Effect and invariability of the Clauses.
Clause 8 — Data protection safeguards.
Clause 14 — Local laws and practices affecting compliance with the Clauses (Transfer Impact Assessment).

ANNEX I — A. List of Parties. B. Description of Transfer. C. Competent Supervisory Authority.
ANNEX II — Technical and Organisational Measures including Technical and Organisational Measures to Ensure the Security of the Data.
ANNEX III — List of Sub-processors (Modules 2 and 3 only).`,
  },
  {
    url: "https://www.legislation.gov.uk/eur/2016/679/contents",
    text: `Regulation (EU) 2016/679 (UK GDPR) — retained EU law as amended by the Data Protection, Privacy and Electronic Communications (Amendments etc) (EU Exit) Regulations 2019.

Article 28 (UK GDPR) — Processor. Processing by a processor shall be governed by a contract binding the processor to the controller, setting out the subject-matter, duration, nature and purpose of processing, the type of personal data, categories of data subjects, and the obligations and rights of the controller.

Article 32 (UK GDPR) — Security of processing. Appropriate technical and organisational measures shall be implemented.`,
  },
  {
    url: "https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/international-transfers/international-data-transfer-agreement-and-guidance/",
    text: `UK International Data Transfer Agreement (IDTA) — published by the ICO.

Part 1 — Parties. Identification of the Exporter and Importer.
Part 2 — Transfer Details. Categories of data, data subjects, purposes, retention.
Part 3 — Security Measures. Technical and organisational measures applied to the transfer.
Part 4 — Mandatory Clauses. The clauses incorporated into the agreement.`,
  },
  {
    url: "https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/international-transfers/international-data-transfer-agreement-and-guidance/uk-addendum/",
    text: `International Data Transfer Addendum to the EU Commission Standard Contractual Clauses — UK Addendum (the ICO Addendum).

Table 1 — Parties to the Addendum. Exporter and Importer details.
Table 2 — Selected SCC Modules. Tick boxes for Modules 1–4 of the EU SCCs.
Table 3 — Appendix Information. Description of transfer, technical and organisational measures.
Table 4 — Ending This Addendum When the Approved Addendum Changes. Either party rights.`,
  },
  {
    url: "https://www.fedlex.admin.ch/eli/cc/2022/491/en",
    text: `Federal Act on Data Protection (FADP) — Switzerland, revised version in force 1 September 2023.

Article 9 — Disclosure to processors. Processing by a processor on behalf of a controller may take place only if a contract is concluded between the parties or if it is provided for by law. The processor shall process personal data only as instructed by the controller. The processor must guarantee the data security required by Article 8 and may engage a sub-processor only with the prior authorisation of the controller.`,
  },
  {
    url: "https://www.edoeb.admin.ch/edoeb/en/home/dokumentation/datenschutz/Datenuebermittlung_und_Cloud/standardvertragsklauseln.html",
    text: `FDPIC Addendum to the EU SCCs (Swiss Addendum).

Competent Supervisory Authority: the Federal Data Protection and Information Commissioner (FDPIC) for transfers covered by Swiss data protection law.

Governing Law: Swiss law where data subjects are resident in Switzerland; references in the SCCs to "Member State law" and "EU law" should be read as references to Swiss FADP.`,
  },
  {
    url: "https://edpb.europa.eu/our-work-tools/general-guidance/guidelines-recommendations-best-practices_en",
    text: `EDPB Guidelines, Recommendations and Best Practices.

- Guidelines 07/2020 on the concepts of controller and processor.
- Guidelines 05/2021 on the interplay between Article 3 and Chapter V.
- Guidelines 01/2022 on data subject rights — right of access.
- Guidelines 02/2023 on Technical Scope of Article 5(3) of the ePrivacy Directive.
- Guidelines 01/2024 on legitimate interest.`,
  },
  {
    url: "https://laws-lois.justice.gc.ca/eng/acts/p-8.6/page-1.html",
    text: `Personal Information Protection and Electronic Documents Act (PIPEDA), S.C. 2000, c. 5.

Schedule 1, Principle 4.1.3 (Accountability) — An organization is responsible for personal information in its possession or custody, including information that has been transferred to a third party for processing. The organization shall use contractual or other means to provide a comparable level of protection while the information is being processed by a third party.`,
  },
  {
    url: "https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm",
    text: `Lei Geral de Proteção de Dados Pessoais (LGPD) — Lei nº 13.709/2018.

Art. 39. O operador deverá realizar o tratamento segundo as instruções fornecidas pelo controlador, que verificará a observância das próprias instruções e das normas sobre a matéria.`,
  },
  {
    url: "https://www.ppc.go.jp/en/legal/",
    text: `Act on the Protection of Personal Information (APPI) — Japan, Law No. 57 of 2003 as amended.

Article 25 — Supervision of Trustees. When a business operator entrusts the whole or part of the handling of personal data, it shall exercise necessary and appropriate supervision over the trustee to ensure the secure handling of personal data.`,
  },
  {
    url: "https://www.npc.gov.cn/englishnpc/c23934/202112/1abd8829788946ecab270e469b13c39c.shtml",
    text: `Personal Information Protection Law of the People's Republic of China (PIPL).

Article 21. Where a personal information handler entrusts the handling of personal information to another party, the handler shall conclude an agreement with the entrusted party setting forth the purpose of processing, the period of processing, the method of processing, the types of personal information handled, the protective measures applied, and the rights and duties of both sides; the handler shall supervise the entrusted party's processing activities.

Article 38. Where a personal information handler needs to provide personal information outside the territory of the People's Republic of China for business or other needs, it shall meet one of the following conditions: (1) pass a security assessment organized by the State cybersecurity and informatization department; (2) undergo personal information protection certification conducted by a specialized institution; (3) conclude a standard contract formulated by the State cybersecurity and informatization department with the foreign receiving party; or (4) other conditions provided by laws, administrative regulations.`,
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
