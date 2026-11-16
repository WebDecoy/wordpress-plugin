# VIP standards remediation

November 15, 2026. Follow-up to the original plugin 2.13.0 assessment. This changes runtime code; it does **not** establish VIP approval, production compatibility, or complete edge-traffic coverage.

## Runtime fixes

- The shared HTTP adapter uses VIP's GET circuit breaker, with a `WP_Error` fallback preserving caller refusal/backoff behavior. It preserves authorization headers and response status/body. VIP GET/POST waits are bounded to 0.1–3 seconds; ordinary WordPress retains existing caller budgets. POSTs are never replayed or response-cached here. Existing caller-specific caches remain separate.
- The Statistics screen and detector/blocker/checkout summary methods cache presentation aggregates for 60 seconds in a site-scoped object-cache group. Protection, checkout velocity, audit lists, counters, and setup receipts stay live. The Statistics screen explains the delay. This is not a measured load benchmark.
- The block page validates IPs, receives the trusted-proxy-aware visitor address used for enforcement, and sends no-cache headers. Proxy guards validate direct-peer addresses. No forwarding-header trust was added.
- Successful challenge clearance and its AJAX verification response explicitly send no-cache headers. The HttpOnly clearance cookie specifies SameSite=Lax alongside existing expiry/path/HTTPS behavior.
- Debug logs require both `WP_DEBUG` and `WP_DEBUG_LOG` and accept only fixed operational event codes. Raw exceptions, credentials, and request payloads are not logged by this helper.
- WordPress adapters use `wp_json_encode`/`wp_parse_url`. The framework-independent SDK retains its native operations with specific explanations rather than gaining a WordPress dependency.
- Admin pagination variables no longer reuse WordPress global names. Uninstall declares `$wpdb` once and prepares escaped literal transient prefixes instead of broad wildcard matches.
- Activation/deactivation request soft rewrite flushes without `.htaccess` writes.
- Robots category changes queue a targeted VIP `/robots.txt` purge, preferring the current API with a guarded legacy fallback. Purges are asynchronous. Registry/constant changes during deployment still require operator invalidation. Physical robots.txt files remain outside the virtual filter.

## What zero findings means

The original baseline was **45 errors and 191 warnings**. The final scan reports **0 errors and 0 warnings, including reviewed exceptions**. This is **not 236 bugs fixed**.

Most findings concern generic direct-query/cache checks on plugin-owned tables. Event writes, queue acknowledgements, schema lifecycle, retention, and live security decisions cannot be replaced with cached results. Suitable presentation aggregates now have an actual cache. Fresh audit/export/status reads remain deliberate. [Reviewed exceptions](reviewed-exceptions.json) records file/function/sniff/rationale. Additional inline explanations cover bounded transport, non-VIP fallback, debug logging, rewrite lifecycle, clearance cookie, and robots purge.

All new exceptions are line-specific and name individual rules. No new file-wide suppressions, excluded runtime directories, lowered severity thresholds, or successful-exit overrides were added. Existing project exceptions are outside this focused review.

UA/cookie/IP signals remain **PHP request observations**. Cache hits that bypass PHP cannot be detected or blocked by this plugin. Removing these signals would weaken detection. Passing static analysis does not validate cache isolation at VIP's edge.

## Reproduce

Scanner dependencies are isolated from the PHP 7.4 plugin runtime. The lock pins VIPCS 3.1.0 and transitive tools.

```sh
composer --working-dir=docs/integrations/wordpress-vip install

docs/integrations/wordpress-vip/vendor/bin/phpcs \
  --standard=WordPress-VIP-Go --extensions=php \
  webdecoy.php uninstall.php admin includes public sdk/src templates

php tests/run.php
node --test docs/integrations/wordpress-vip/plan.test.mjs
./build.sh 2.13.0 --org
```

The new CI job fails on findings (no `|| true`); branch-protection settings determine whether the job is mandatory for merge. The original report remains in `phpcs-baseline.json`; `phpcs-remediated.json` contains the final sanitized report.

Local verification: **269 PHP tests passed**, **28 connector tests passed**, **119 PHP source/test files passed syntax checks**. Added tests cover transport response/auth/error preservation, VIP timeout bounds, site-isolated analytics cache reuse/expiry, opt-in diagnostics, invalid direct-peer input, and modern/legacy targeted robots purges. The WordPress.org ZIP builds and passes the same VIP scan. This is a test build of 2.13.0, not a published release.

## Remaining pilot requirements

A real VIP environment must validate anonymous/authenticated and cached/uncached requests, challenges/decoys/cookies, proxy configuration, realistic database contention/retention/cron/latency, service outages and timeouts, and robots purge propagation. Include the case where a one-time connection exchange completes server-side after a client timeout. Validate deploy-time robots invalidation separately.

The offline edge-policy planner also still needs authenticated nonproduction API/rollback testing. No VIP API call, production deployment, certification, or load benchmark was performed here. Scoped database exceptions are not VIP performance approval.

## Primary references

- [VIP remote data guidance](https://docs.wpvip.com/databases/optimize-queries/retrieving-remote-data/)
- [VIP helper implementation and signature](https://github.com/Automattic/vip-go-mu-plugins-built/blob/master/vip-helpers/vip-utils.php)
- [VIP targeted purge API](https://docs.wpvip.com/caching/page-cache/purging/programmatically/)
- [VIP robots.txt behavior](https://docs.wpvip.com/security-controls/robots-txt/)
- [VIP cache-control headers](https://docs.wpvip.com/caching/page-cache/customize-behavior/cache-control-headers/)
