-- vaulytica-reports (spec-v53 §5). What is stored, in full.
--
-- There is no column for an excerpt, a filename, a document hash or a
-- result_hash, and no column for who sent the report: the reporter's IP, user
-- agent and Turnstile token are never written.

CREATE TABLE finding_reports (
  id TEXT PRIMARY KEY NOT NULL,
  created_at TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('wrong-finding','missed','wrong-type','site')),
  rule_id TEXT, rule_version TEXT,
  engine_version TEXT NOT NULL, dkb_version TEXT,
  document_type TEXT, near_family TEXT,
  note TEXT CHECK (note IS NULL OR length(note) <= 280),
  dedupe_key TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','resolved','wont_fix')),
  resolved_at TEXT,
  resolution_note TEXT CHECK (resolution_note IS NULL OR length(resolution_note) <= 1000)
);

CREATE INDEX finding_reports_created_at ON finding_reports (created_at);

-- Daily ceilings. `reporter` is a keyed hash of the day and the IP, under a
-- secret; it cannot be turned back into an address and means nothing the
-- next day.
CREATE TABLE report_reporter_days (
  day TEXT NOT NULL,
  reporter TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  accepted INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, reporter)
);

CREATE TABLE report_days (
  day TEXT PRIMARY KEY NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  accepted INTEGER NOT NULL DEFAULT 0
);
