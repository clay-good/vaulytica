# v4 playbooks

Per [`spec-v4.md`](../../../spec-v4.md) Part VI Steps 45–59. Each
sub-domain (B–P) contributes new playbook JSON files to this directory
as the corresponding step lands. The schema is the v3-extended
`Playbook` schema (`src/playbooks/types.ts`) — no v4-only schema
additions.

The current directory is intentionally empty; placeholders are not
committed because the v3 `parsePlaybook` validation rejects
zero-content schemas at load time. Each new playbook lands at v1.0.0
with title keywords, distinguishing phrases, expected defined terms,
applicable jurisdictions, regulator frame, and compliance-matrix
columns.
