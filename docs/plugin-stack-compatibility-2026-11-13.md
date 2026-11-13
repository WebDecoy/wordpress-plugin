# Installed WordPress plugin coexistence check — 2026-11-13

**122 synthetic HTTP cases passed across 10 scenarios**, matched one-to-one
with independent server-side access receipts. No conflict was observed in the
tested navigation, login, redirect, AI-counter or WebDecoy blocking flows.
No production detection-hook change is supported by this check.

This follows the [14-case hook-order check](hook-order-compatibility.md).
These tests use actual installed plugins, full WordPress bootstrap and a real
MariaDB database. They do not use the earlier in-memory service adapters.
The [measurement summary](plugin-stack-compatibility-2026-11-13.json) records
package hashes, runtime identities and per-scenario results. All traffic is
controlled fixture traffic, never customer traffic or detection-accuracy data.

## Versions and scenarios

WordPress7.1.4, PHP8.3.33, MariaDB11.8.9, public WebDecoy2.11.4,
Redirection5.10.1, WPS Hide Login1.9.20 and Wordfence9.1.1. Official WordPress.org
packages were staged before execution; no plugin code was patched.

| Scenario | HTTP cases | Result |
| --- | ---: | --- |
| WebDecoy alone | 10 | Passed |
| WebDecoy + Redirection | 11 | Passed |
| WebDecoy + WPS Hide Login | 11 | Passed |
| WebDecoy + Wordfence, default learning mode | 10 | Passed |
| All four plugins | 12 | Passed |
| All four, alternate load order | 12 | Passed |
| All four, Wordfence enabled with local manual rule | 14 | Passed |
| Same, alternate load order | 14 | Passed |
| All four, native Wordfence `auto_prepend_file` | 14 | Passed |
| Same, alternate load order | 14 | Passed |

The first six scenarios total 66; enforcement-enabled scenarios add 28 and native
prepend scenarios add 28. A later re-run checks the saved reproduction runner;
it does not add new coverage categories to the primary 122-case measurement.

## What was exercised

- A browser-style HTTP client retrieves the target page successfully. This is
  an HTML request check, not a browser JavaScript test.
- Ordinary `python-requests` traffic creates real local detection rows from
  WebDecoy scoring, independently of the reserved test-trigger control.
- A separate reserved Test UA returns its labeled403 JSON receipt.
- One synthetic GPTBot-UA request per scenario increments the real hourly AI
  counter by exactly one. Its identity stays **claimed**, never verified.
- Correct credentials submitted to the real login form produce a login redirect
  and an authenticated200 admin page, including WPS Hide Login's custom URL.
- An unauthenticated client-detection AJAX call without a nonce is rejected403
  through the dedicated handler and creates no general front-end detection.
- A local tripwire in monitor mode records its violation and proceeds to404;
  block mode returns403 and records the fresh violation.
- Redirection's actual installer/model API creates a301 rule; the redirected
  bot request still has a WebDecoy detection row.
- WPS Hide Login hides the original login URL with404 while WebDecoy still
  records the scored bot request.
- Wordfence's local manual UA rule returns503 and prevents target content from
  being served. In native prepend mode the receipt proves WordPress has not
  loaded and there is no WebDecoy detection row.
- Every extended-mode request independently proves that native
  `WFWAF_AUTO_PREPEND` ran; merely configuring an option is insufficient.

## Observation boundaries confirmed

A Wordfence block before WebDecoy runs appears in the server access log and has
no WebDecoy detection row. That is expected earlier termination, not evidence
that a protected action ran. The native prepend block happens before WordPress
itself loads.

A second important distinction is inside WebDecoy: **an already-blocked IP can
receive403 without being scored again or creating a new detection row**. The
initial enforcement-enabled pass exposed state carried from a preceding case.
The fixture now resets only its dummy IP blocks between scenarios and separately
asserts the repeated-block behavior. Detection-row totals are not a total of all
blocked HTTP requests. Admin/AJAX exclusions and earlier edge/cache responses
also prevent one-to-one equivalence with the host's access log.

WPS Hide Login rewrites the original hidden login URI during bootstrap. A
subsequent detector can therefore see the rewritten path. Successful login,
original-login hiding, bot scoring and AI counting still passed in this setup.

These results support keeping the detector at its present lifecycle hook.
Moving it earlier would introduce a separate dependency/bootstrap risk and
would not make a WordPress plugin observe requests stopped before WordPress.

## Isolation, evidence and limitations

The two disposable containers share only a private loopback namespace. There
are no published host ports, external network routes, production credentials,
cloud keys or mail delivery. Code and toolchains are read-only. Database,
Wordfence state, logs and uploads use bounded tmpfs. Each container has one CPU,
384MB RAM limits and PID/file-size limits; PHP requests and HTTP clients have
execution deadlines. Only a dummy local administrator is created.

The enforcement cases use a test-only trusted-loopback proxy header carrying
`192.0.2.42`, avoiding Wordfence's loopback allowlist. This is not a real
reverse-proxy deployment certification. The extended listener uses native PHP
index fallback, with no router that might skip prepend execution.

Wordfence is unlicensed and offline. Its downloaded rules file is empty. A
local manual block is exercised in enabled and native prepend modes; vendor
signature efficacy, feed updates, scanning and cloud services are not tested.
There were startup missing-rule warnings. An initial fixture-only `WP_CLI`
bootstrap mistake was corrected before measured runs. The verified HTTP cases
show no PHP critical-error page; the full setup log is not claimed to be empty.

Other untested surfaces include the client-side scanner (disabled to isolate
server-side behavior), browser JavaScript, Apache/FPM and `.htaccess`, multisite,
actual CDN/full-page-cache behavior, real crawler identity verification, cloud
reporting, and settings combinations outside this matrix.

[Reproduction fixture and isolated setup](../tests/wp-compat/plugin-stack/README.md).
The fixture contains first-party test code only; WordPress and companion
packages are supplied separately. No production plugin source was changed.
