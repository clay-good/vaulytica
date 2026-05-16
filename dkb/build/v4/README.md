# dkb/build/v4 — v4 DKB build pipeline

Per [`spec-v4.md`](../../../spec-v4.md) §13, Step 60. v4 fetchers land
here as Step 60 executes. Same framework as the v3 fetchers under
[`../v3/`](../v3/) — every fetcher is a pure function from a
`V3FetchContext` (snapshot reader + optional HTTP client) to a list
of DKB nodes, each carrying `content_hash_at_pin =
sha256(normalizeForHash(snapshotText))` for the staleness gate at
`../v3/staleness.ts`.

Eight new fetchers planned for Step 60 (per spec §13):

- DGCL fetcher (Delaware General Corporation Law titles relevant to
  bylaws, charters, mergers, stockholders' agreements).
- NVCA model docs index fetcher (founding-stage equity / IRA / voting
  agreement / ROFR baselines).
- IRC fetcher for the equity / cap-table sub-domain (§ 83, § 409A,
  § 422, § 280G).
- URLTA fetcher for real-estate residential lease alignment.
- AIA published-form index fetcher (A101 / A201 / G701 reference set,
  citation only — the forms themselves are copyrighted).
- UTC + UPAA + UPMAA fetcher for the trust / estate / family
  sub-domain.
- FCPA + BSA + Dodd-Frank + LDA fetcher for compliance policies.
- Reg D / Reg A / Form ADV General Instructions fetcher for
  regulatory prose.

Snapshot fixtures live under [`../../fixtures/v4/`](../../fixtures/v4/);
the existing `staleness.ts` covers v4 nodes automatically because every
node passes through the same `V4DkbNodeSchema` once Step 60 lands.
