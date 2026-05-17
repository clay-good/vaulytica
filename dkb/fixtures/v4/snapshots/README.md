# v4 snapshot corpus

Per [`../../../build/v4/README.md`](../../../build/v4/README.md) (Step 60).

Each file is named `{sha256(source_url)}.txt` and is the offline
snapshot replayed by the v4 fetcher in CI. The Step-20 staleness gate
re-hashes each snapshot at build time and compares against
`content_hash_at_pin` on every v4 node — drift becomes a build break
unless acknowledged in [`/dkb-staleness-ack.yml`](/dkb-staleness-ack.yml).

The snapshots are intentionally lean (the authoritative text lives on
the regulator's site); each file contains enough representative
language to satisfy every per-fetcher `detect` regex so every
hand-keyed requirement is emitted by the parser.
