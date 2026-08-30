/**
 * IPDATA-001 required "hereby assigns" as two adjacent words, so the standard
 * invention-assignment sentence — "Employee hereby IRREVOCABLY assigns to the
 * Company all right, title, and interest in any and all inventions" — was
 * reported as a contract that "does not allocate ownership of intellectual
 * property".
 */
import { describe, expect, it } from "vitest";
import { rule as IPDATA_001 } from "./IPDATA-001.js";
import { buildContext } from "../../_test-fixtures.js";

const doc = (...paras: string[]) => buildContext(["Intellectual Property", ...paras]);

describe("IPDATA-001 — IP ownership clause present", () => {
  it("reads an assignment carrying an adverb", () => {
    expect(
      IPDATA_001.check(
        doc(
          "Employee hereby irrevocably assigns to the Company all right, title, and interest in any and all inventions, discoveries, improvements, and works of authorship conceived during the term of employment.",
        ),
      ),
    ).toBeNull();
  });

  it("still requires the assignment to be of intellectual property", () => {
    // A bare assignment of something else — receivables, a lease — is not an
    // IP-ownership clause, adverb or no adverb.
    expect(
      IPDATA_001.check(
        doc(
          "Borrower hereby absolutely assigns to Lender all rents and receivables of the Premises.",
        ),
      ),
    ).not.toBeNull();
  });

  it("reads a trademark license's active reservation and goodwill inurement (v1.3.0)", () => {
    // A license allocates IP ownership by reserving it — in the active voice
    // and, for a trademark, through goodwill inurement.
    expect(
      IPDATA_001.check(
        doc(
          "The Licensor reserves all rights not expressly granted. The Licensee acquires no ownership interest in the Licensed Marks, and all goodwill arising from the Licensee's use of the Licensed Marks inures solely to the benefit of the Licensor.",
        ),
      ),
    ).toBeNull();
  });

  it("reads a bare 'Licensee acquires no ownership interest' reservation (v1.3.0)", () => {
    expect(
      IPDATA_001.check(doc("The Licensee acquires no ownership interest in the Licensed Marks.")),
    ).toBeNull();
  });

  it("reads an ownership STATEMENT — 'Licensor owns the Licensed Patents' (v1.3.1)", () => {
    expect(
      IPDATA_001.check(doc("The Licensor represents that it owns the Licensed Patents.")),
    ).toBeNull();
    expect(IPDATA_001.check(doc("Each party owns the improvements it makes."))).toBeNull();
  });

  it("does not read a bare non-IP 'owns' as an IP-ownership clause (v1.3.1)", () => {
    expect(
      IPDATA_001.check(doc("The Investor owns 10% of the outstanding shares of the Company.")),
    ).not.toBeNull();
  });

  it("reads retention / title-vesting / owner / property-of ownership forms (v1.4.0)", () => {
    expect(
      IPDATA_001.check(
        doc("Licensor retains all right, title, and interest in and to the Licensed Materials."),
      ),
    ).toBeNull();
    expect(IPDATA_001.check(doc("Title to all Inventions shall vest in the Employer."))).toBeNull();
    expect(
      IPDATA_001.check(
        doc("The Company shall be the sole and exclusive owner of all Work Product."),
      ),
    ).toBeNull();
    expect(
      IPDATA_001.check(doc("All work product is the exclusive property of the Client.")),
    ).toBeNull();
    expect(IPDATA_001.check(doc("Customer shall own all Customer Data."))).toBeNull();
  });

  it("does not read a possessive 'its own … data' as an ownership clause", () => {
    expect(
      IPDATA_001.check(
        doc("Processor shall maintain its own internal documentation of personal data flows."),
      ),
    ).not.toBeNull();
  });

  it("reads the IP-object-first 'shall belong to' / 'owned by' forms (v1.5.0)", () => {
    expect(
      IPDATA_001.check(doc("All Work Product and deliverables shall belong to the Customer.")),
    ).toBeNull();
    expect(
      IPDATA_001.check(
        doc("All right, title, and interest in the Deliverables shall be owned by Customer."),
      ),
    ).toBeNull();
    expect(
      IPDATA_001.check(doc("The patents and trade secrets belong to the Company.")),
    ).toBeNull();
  });

  it("does not read generic 'owned by' / 'belong to' with no IP object as an ownership clause", () => {
    // "the company is owned by its shareholders", "the parties belong to the
    // association" allocate no IP, so the rule still warns.
    expect(
      IPDATA_001.check(doc("The company is owned by its shareholders and managed by a board.")),
    ).not.toBeNull();
    expect(
      IPDATA_001.check(doc("The parties belong to the same trade association and meet quarterly.")),
    ).not.toBeNull();
  });
});

describe("IPDATA-001 — a conveyance never uses one verb (v1.8.0)", () => {
  /**
   * "Each Assignor hereby irrevocably SELLS, ASSIGNS, TRANSFERS, AND CONVEYS
   * to Assignee all of that Assignor's entire right, title, and interest in
   * and to the Patents" is the operative sentence of a patent assignment. The
   * assignment branch allowed a single adverb between "hereby" and "assigns",
   * so a document whose entire purpose is to allocate IP ownership was told it
   * allocates none.
   */
  it("is silent on an assignment written as a verb series", () => {
    for (const clause of [
      "Each Assignor hereby irrevocably sells, assigns, transfers, and conveys to Assignee all of that Assignor's entire right, title, and interest in and to the Patents.",
      "Seller does hereby sell, assign and transfer unto Buyer all of Seller's right, title and interest in the Trademarks.",
      "Consultant hereby grants, conveys, and assigns to Company all inventions conceived in the course of the Services.",
    ]) {
      expect(IPDATA_001.check(buildContext(["Assignment", clause])), clause).toBeNull();
    }
  });

  it("still fires on a document that allocates nothing", () => {
    expect(
      IPDATA_001.check(
        buildContext([
          "Services",
          "Consultant shall perform the Services described on Exhibit A and invoice monthly.",
        ]),
      ),
    ).not.toBeNull();
  });
});

describe("IPDATA-001 — ownership allocated by retaining rights in named content", () => {
  // Consumer terms allocate ownership of user content by retention: "You
  // retain all rights in the images and other material you upload." The
  // retention branch read only "retains ownership" and "retains all right,
  // title", so a terms page with a dedicated Your Content section was told it
  // allocates no intellectual property at all.
  it("reads 'You retain all rights in the images and other material you upload'", () => {
    const ctx = buildContext([
      "6. Your Content",
      'You retain all rights in the images and other material you upload ("Your Content"). You grant us a limited licence to store and display Your Content solely to provide the Service.',
    ]);
    expect(IPDATA_001.check(ctx)).toBeNull();
  });

  it("still fires on terms that allocate nothing", () => {
    const ctx = buildContext([
      "6. Your Content",
      "You may upload images and other material to the Service, subject to the acceptable use rules below.",
    ]);
    expect(IPDATA_001.check(ctx)).not.toBeNull();
  });
});

describe("IPDATA-001 — the bare vesting sentence", () => {
  // "ALL RIGHT, TITLE, AND INTEREST IN AND TO THE WORK PRODUCT vests in
  // Customer upon creation" is the standard allocation, and the title-vesting
  // branch wanted "title TO" / "title IN" — here the phrase reads "title, and
  // interest in", so the rule reported that the contract allocates no IP.
  it.each([
    "All right, title, and interest in and to the Work Product vests in Customer upon creation.",
    "All right, title and interest in and to any and all Inventions shall vest in the Company.",
    "All right, title, and interest in and to the Deliverables passes to Customer on payment.",
  ])("is silent on %s", (clause) => {
    expect(IPDATA_001.check(buildContext(["Ownership", clause]))).toBeNull();
  });

  it("does not read an assignment of a CONTRACT as an IP allocation", () => {
    // The new branch is anchored on an IP object, so the identical phrase over
    // a non-IP subject does not satisfy it. (Phrased WITHOUT "under the
    // Assigned Contract": that wording matches `ISSUED_UNDER_PARENT`, which
    // stands the whole rule down as a document subordinate to a named parent —
    // defensible for an assignment, but it would not be testing this branch.)
    expect(
      IPDATA_001.check(
        buildContext([
          "Assignment",
          "Assignor assigns to Assignee all of Assignor's right, title and interest in and to the Assigned Contract.",
        ]),
      ),
    ).not.toBeNull();
  });
});

describe("IPDATA-001 — retention with the rights modified before the object (v1.11.0)", () => {
  /**
   * The AIA B101 allocation. The retention branch wanted "retains all rights
   * IN <object>" adjacent; the standard sentence puts the adjectives and an
   * appositive in between, and the agreement was told it allocated no IP.
   */
  it("is silent on the standard owner-architect reservation", () => {
    expect(
      IPDATA_001.check(
        doc(
          "Architect and its consultants retain all common law, statutory, and other reserved rights, including copyright, in the Instruments of Service.",
        ),
      ),
    ).toBeNull();
  });

  it("is silent when the retained object is a patent", () => {
    expect(
      IPDATA_001.check(
        doc(
          "Licensor retains all right, title, and interest of every kind, including copyright, in and to the Licensed Patents.",
        ),
      ),
    ).toBeNull();
  });

  /** A retention with no IP object is not an IP-ownership clause. */
  it("still fires when only remedies are retained", () => {
    expect(
      IPDATA_001.check(
        doc(
          "The Lender retains all rights and remedies available at law or in equity, and no delay in exercising any of them is a waiver.",
        ),
      ),
    ).not.toBeNull();
  });
});
