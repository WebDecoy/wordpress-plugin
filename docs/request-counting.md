# Detection rows and request counts

Detection rows are saved findings. They are not a count of all requests, nor a
count of requests blocked. A request can create multiple findings. A request
from an already-blocked IP can return 403 before scoring, without a new finding.

The WordPress dashboard now shows detection rows, blocked requests and withheld
enforcement for today in UTC. Statistics compares the same measures over today,
7 and 30 UTC calendar days, with throttles and challenges shown separately.
Active blocked IPs remains the size of the current block list, not a request
counter. Dashboard finding/IP totals are read fresh to avoid mixing stale
summaries with current request counts; no cache-invalidation writes are added
to front-end requests.

## Definitions

| Metric | Meaning |
| --- | --- |
| Detection rows | Findings saved in the existing detection table; unchanged |
| Blocked requests | WebDecoy explicitly denies the HTTP request and its final response is 403; includes repeat IP blocks |
| Throttled requests | WebDecoy explicitly throttles the request and its final response is 429 |
| Challenges served | WebDecoy serves its 403 challenge; not counted as a hard block |
| Enforcement withheld | A request where protection would act but is withheld, including monitor mode; never an actual block |

One request is counted once under its strongest marked outcome. Multiple
withheld decisions in the same request do not inflate the count. Recording
happens at PHP shutdown after checking the final response, and does not change
which enforcement path runs. Nonce/permission failures, validation notices
returned with 200, decoy 200/404 responses and reserved setup-test traffic are
not counted as request denials. Wordfence, CDN and cache responses that end
before WebDecoy runs are outside its counters.

A protected form action refused through `WP_Error` or a WooCommerce notice
is not necessarily a denied HTTP request. Existing checkout/form findings
remain available separately; these counters do not relabel all protection
actions as blocked requests.

## Storage, upgrade and coverage

Schema 2.11.1 adds `webdecoy_request_counts`. Its only columns are UTC hour,
outcome and count, with a primary key on hour/outcome. Each counted request
uses an atomic `INSERT ... ON DUPLICATE KEY UPDATE hits = hits + 1`, preventing
concurrent lost updates without writing another detection row. Counter-write errors are suppressed and
do not alter the protection response; a failed write is not invented or backfilled. There are at
most four outcome buckets per hour. No new visitor IP, URL, User-Agent or
fingerprint is stored.

The existing activation/admin-upgrade path installs the table. Schema version
advances only when that table exists; failed creation retries on the next
admin request. A stored tracking-start timestamp is shown in the UI. Earlier
blocked-request totals cannot be reconstructed and are never backfilled.
Calendar-day comparisons use the same UTC boundaries for findings/outcomes,
but the request history starts at deployment and cannot cover earlier days.
Counter retention is 30 calendar days, pruned by the existing cleanup hook.
Uninstall removes the new table and start metadata, including fallback and
per-site cleanup paths. No cloud reporting/API contract is changed.

## Validation

- 235 dependency-free tests passed, including outcome precedence, final-status
  validation, setup-test exclusion, aggregation and UTC/leap-day boundaries.
- 14 focused checks passed across 60 actual HTTP requests, each reconciled with
  an independent server receipt in full WordPress/MariaDB.
- One monitor-mode login produced 3 withheld actions and exactly 1 request count.
- 40 concurrent repeat-block requests produced exactly 40 counter increments,
  zero new detection rows, and one hourly aggregate row in the observed run.
- Challenges and 429s increment their own counters; setup 403s, nonce failures
  and CLI maintenance do not increment the blocked-request metric.
- Actual admin dashboard/Statistics HTML values matched stored measurements.
- A simulated CREATE-permission failure preserved blocking, left tracking
  unavailable, and retried successfully after permissions were restored,
  without backfilling past requests. Repeated upgrade preserved start metadata.
- A database trigger rejecting counter-only writes preserved the 403 response
  without leaking database errors; removing the trigger resumed counting.
- Retention preserved the boundary bucket and removed older buckets; actual
  WordPress uninstall removed the table and start metadata.
- The full 122-request installed-plugin matrix passed again, including
  Wordfence manual enforcement and native prepend modes. Wordfence's own
  denials did not increment WebDecoy blocked-request counts.

The installed-plugin fixture now delegates directories to PHP's real admin
index and checks the `wp-admin` body class. Earlier admin-bar-only assertions
could mistake a logged-in front page for the admin dashboard; the corrected
matrix and focused UI checks above supersede that narrower evidence.

These are synthetic fixtures, not customer traffic or protection-accuracy data.
Browser JavaScript, downloaded vendor signatures, real CDN/cache/proxy topology
and full multisite behavior remain outside this validation.

See [the isolated test fixture](../tests/wp-compat/plugin-stack/README.md).
