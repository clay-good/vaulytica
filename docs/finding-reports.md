# Problem reports: the endpoint, and how to launch it

> **Status: written and tested, not deployed.** The Worker in
> [`workers/reports/`](../workers/reports/) is complete and its tests run in
> the gate. Launching it needs the owner's Cloudflare account, and changes
> what the site may say about itself. Until then `/report` shows what a report
> would contain and sends nothing, and every "no server" sentence on the site
> is true. Design: [`spec-v53.md`](spec-v53.md) §4–§7.

## What it is

One Worker, `vaulytica-reports`, routed only at `vaulytica.com/api/reports*`.
It accepts one request — `POST /api/reports` — and stores a short row in a D1
database. Cloudflare Pages keeps serving every static file; using the site to
review a document never invokes it.

| It accepts                                                                        | It refuses                                                         |
| --------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| A JSON body of at most 4 KB                                                       | Anything larger                                                    |
| Nine keys: `kind`, `rule`, `rv`, `engine`, `dkb`, `type`, `near`, `note`, `token` | Any other key — there is none for an excerpt, a filename or a hash |
| A `rule` or `type` that is an id in the shipped catalog                           | A custom playbook's ids                                            |
| A note of at most 280 characters, control characters stripped                     | A longer note                                                      |
| A Turnstile token verified server-side for the action `report`                    | An unverified request                                              |

What it stores is the table in
[`migrations/0001_reports.sql`](../workers/reports/migrations/0001_reports.sql),
in full. It does not store the reporter's IP address, user agent or Turnstile
token. The per-reporter daily limit uses a keyed hash of the day and the IP,
which cannot be reversed without the secret and changes at midnight UTC.

Limits are constants in [`store.ts`](../workers/reports/src/store.ts): 5
accepted reports per reporter per day, 200 per day in total, and caps on
verified attempts. Every report is deleted after 30 days, by a daily cron and
before each write.

## Launch checklist

Nothing below has been done. Each step needs the owner's Cloudflare account.

1. **Create the database.** `wrangler d1 create vaulytica-reports`, and put
   the id it prints in `workers/reports/wrangler.jsonc`.
2. **Apply the migration.**
   `wrangler d1 migrations apply vaulytica-reports --remote`, from
   `workers/reports/`.
3. **Create a Turnstile widget** for `vaulytica.com`. Its action name is
   `report` (`TURNSTILE_ACTION` in `handler.ts`).
4. **Set the two secrets**, with `wrangler secret put`:
   `TURNSTILE_SECRET` (the widget's secret key) and `REPORTER_HMAC_SECRET` (32
   or more random bytes). Neither is ever committed.
5. **Add a WAF rate-limit rule** on the path `/api/reports`, in front of the
   Worker.
6. **Confirm how Pages combines header rules.** Turnstile's script and frame
   must be allowed on `/report` only, by a path-specific Content-Security-Policy
   that replaces the inherited one there. The app page's policy does not
   change. Check this on a preview before anything depends on it.
7. **Deploy the Worker**: `wrangler deploy`, from `workers/reports/`. Confirm
   there is no `workers.dev` URL and that invocation logs are off.
8. **In the same release, rewrite the site's claims** (spec-v53 §6). The site
   says "There is no server" and shows a "0 servers" tile. After launch there
   is one, which receives a short form when a person chooses to send it. Each
   such sentence becomes the claim that stays true: your document is never
   sent anywhere; the only thing the site can receive is a problem report you
   choose to send, and it contains no part of your document. The tile becomes
   "0 uploads". The test `report-worker.test.ts` holds a line that fails on
   the day `/report` starts sending, as the reminder.
9. **Make `/report` send**, and extend the privacy end-to-end test to assert
   zero requests to `/api/` across every analysis journey.
10. **Add the endpoint to the threat model**: what it accepts, what it stores,
    how to turn it off.

## Reading reports

There is no public read endpoint. A maintainer reads the database through
authenticated `wrangler`, oldest first:

```bash
wrangler d1 execute vaulytica-reports --remote --command "SELECT created_at, kind, rule_id, rule_version, document_type, near_family, note FROM finding_reports WHERE status = 'open' ORDER BY created_at LIMIT 50"
```

Record an outcome on the row — `resolved` or `wont_fix`, with a note — and
follow the usual method for a confirmed defect: a specimen, the fix, a guard,
and a changelog entry.

## Turning it off

Remove the route, or delete either secret: with any part of its configuration
missing the Worker answers `503` and the page says reporting is unavailable.
The app is unaffected either way, because it never calls the endpoint.

## Keeping the id list current

The Worker carries the list of rule and document-type ids it will accept.
`npm run reports:ids` regenerates it, and the gate fails when it drifts from
the catalog. Redeploy the Worker after a release that adds ids, or reports
about the new ones will be refused.
