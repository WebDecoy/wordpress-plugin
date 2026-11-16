# WordPress VIP readiness assessment

Assessed November15,2026 against WordPress plugin2.13.0, commit `e8f8041072cb9975436012d59a2f0a1454b3cd06`.

**Decision: ready for a technical partnership conversation and an offline connector demonstration; not ready to claim VIP compatibility or ship a production VIP integration.** No VIP environment, authenticated API call, customer pilot, load benchmark or VIP certification was available in this assessment.

## Evidence and gaps

| Area | Evidence | Readiness / next validation |
|---|---|---|
| Integration prototype | Offline Node planner and28tests in this directory. Input fields follow the documented VIP mutation. | Locally tested only. Need real complete restriction export and nonproduction API round-trip, propagation, response codes and rollback test. |
| Edge cache visibility | `includes/class-webdecoy-crawler-visits.php` explicitly excludes full-page cache hits; request logic executes in PHP. | Fundamental coverage gap for publishers. Pair plugin observations with a separately validated edge/log source. Do not claim PHP counts are complete site traffic. |
| VIP rules scope | Official API can control UA restrictions at VIP edge. Global matching covers cached content, assets and authenticated requests. | Declared-name blocking only; it does not establish bot identity. Publisher must choose policy and validate service/browser exclusions. |
| Static code standards | VIPCS3.1.0 / PHP8.5.10 / WordPress-VIP-Go: **45errors,191warnings**, zero auto-fixable. Full sanitized baseline in `phpcs-baseline.json`. | Findings require triage and remediation or evidence-backed justification. This is not a vulnerability count. |
| Git deployment | Plugin has source repository, versioned builds, no runtime Composer dependencies. Self-updater is gated by `WEBDECOY_SELF_HOSTED`. | VIP deploys plugins through site git repositories. Use a reviewed artifact without updater; do not enable self-hosted updates or instruct dashboard installation. |
| Data storage and scale | Custom detection, request, crawler and referral tables in activator; hourly/day aggregate counters; prepared queries. | Need realistic high-volume write/query measurements, retention/cleanup timing, multisite and object-cache evaluation on VIP. |
| Request-dependent responses | Detector/blocker uses UA, cookies, clientIP; challenge/block response and cookie paths exist. | Need cache correctness tests for anonymous/logged-in requests; ensure personalized challenges/decoys cannot leak through shared cache. No cache bypass should be enabled merely to make counting complete. |
| Proxy/client IP | `sdk/src/SignalCollector.php` trusts forwarding headers only from configured trusted hops; blocker tracks unresolved proxy state. | Validate VIP's actual server/header contract. Do not automatically trust arbitrary X-Forwarded-For or derive production allowlists from this report. |
| Outbound requests | Optional cloud/reporting/feeds use WP HTTP API, timeouts, transient caches, some queued reporting. | Review request-path latency, cron reliability, outage behavior, rate limits and privacy before enabling cloud features. |
| Data handling | Local aggregates coexist with detections and optional cloud reports. | Document each enabled module's IP/request/landing-path flow, retention and deletion; confirm DPA/support requirements with VIP. Full privacy audit not performed. |

## Static-scan triage, in priority order

1. **Cache correctness and coverage:**12UA,5REMOTE_ADDR and3COOKIE restricted-variable findings plus cookie-setting and header-validation findings. Several are expected for bot software, but need a VIP-specific architecture and runtime evidence. Deleting checks solely to silence the scanner would undermine detection.
2. **Request latency:**7high-timeout findings, including cron feed8seconds and cloud/referral operations5–10seconds.2findings come from the self-hosted updater, inactive by default and removable from a VIP artifact. Distinguish cron/admin operations from public request paths before changing deadlines.
3. **Database work:**88direct-query and69uncached-query findings across reads/writes/maintenance. Aggregate counter writes cannot simply be cached away. Measure contention, cache suitable reads, and document lifecycle operations separately.3table-interpolation errors in request counters need manual review; table names come from plugin helpers, so these scanner errors alone do not establish injection.
4. **Smaller review items:**6error-log findings,4WordPress-global assignment findings in admin partials,2rewrite flush findings in activation/deactivation. Verify actual scope; admin includes may run within method scope, and activation hooks differ from per-request theme execution. Do not blanket-suppress standards.

No existing runtime code was changed by this readiness PR. The scan includes the self-hosted updater and PHP only, not a complete security audit or JavaScript scan. Tool versions and exact scanned directories are embedded in the baseline. Re-run after changing the release artifact or dependency versions.

## Nonproduction pilot acceptance criteria

- VIP engineer/operator confirms installation and API requirements; correct environment and permission scopes established.
- Preserve existing restrictions through create/update/no-op and a rollback reconciled with intervening changes.
- Verify normal browsers, VIP monitoring, certificates, webhooks, media imports, REST and admin access after rule propagation.
- Test cached/uncached and anonymous/logged-in requests, checkout if applicable, worker/proxy failures, timeout behavior and retention/cron jobs.
- Measure latency/error rate and database cost at an agreed realistic load with/without enabled features; include measurements rather than promises in partnership material.
- Validate coverage from each data source: PHP observations, browser observations, edge logs and blocked requests remain distinct. No edge-log ingestion currently supplied by this prototype.
- Obtain VIP technical feedback before using partnership/certification badges or claiming Integration Center availability.

## Sources

See official references in [integration README](README.md). VIP does not maintain a pre-approved third-party plugin list; partner approval, site-specific deployment review and our own tests are separate evidence.
