# Detection and redirect ordering

Focused check on 2026-11-13: WebDecoy 2.11.4 at `92a92da`, PHP 8.5.10,
WordPress 7.1.4 hook dispatcher. Fourteen request cases passed.

A follow-up [installed-plugin HTTP matrix](plugin-stack-compatibility-2026-11-13.md)
now adds 122 measured cases using real WordPress and MariaDB. This page describes
the earlier, narrower hook fixture.

The general front-end check is registered on `init` at priority 1. A callback
that exits before it runs prevents detection of that request. Later redirects
do not erase an already recorded detection.

| Request path / competing callback | Local detection | Result |
| --- | --- | --- |
| Ordinary bot request, monitor mode | Yes | Request continues |
| Reserved `WebDecoy-Test/` control | Yes | Labeled test, HTTP 403 |
| Must-use plugin exits before ordinary plugins | No | Redirect ends request |
| `plugins_loaded` exits | No | Redirect ends request |
| `init` priority 0 exits | No | Redirect ends request |
| `init` priority 1 registered before WebDecoy exits | No | Registration order wins the tie |
| `init` priority 1 registered after WebDecoy exits | Yes | Detection precedes redirect |
| `init` priority 2 or 10 exits | Yes | Detection precedes redirect |
| `wp_loaded` or `template_redirect` exits | Yes | Detection precedes redirect |
| Login request with `login_init` redirect | Yes | Detection precedes redirect |
| Admin / admin-AJAX request | No general front-end record | Intentional early-check exclusions |

Admin/AJAX exclusions do not mean their separate protection hooks are absent.
The fixture also verifies registration of the login authentication filter and
the unauthenticated client-detection AJAX handler. It does not exercise their
nonce, authentication, or enforcement behavior.

## Current companion sources reviewed

These were source reviews during the initial pass. The linked installed-plugin
follow-up records the runtime cases now exercised and the remaining limits:

- Redirection 5.10.1: `includes/module/class-plugin.php` registers canonical
  redirects and initialization at default `init` priority 10, with page
  redirects on `template_redirect`. These are after WebDecoy's general check.
- WPS Hide Login 1.9.20: `classes/plugin.php` registers `init_block_access` at
  default `init` priority 10 and its main login handling on `wp_loaded`.
  Its earlier `plugins_loaded` handler rewrites login request paths and
  `$pagenow`; consequently WebDecoy may inspect the rewritten path rather than
  the original login URL. The follow-up exercises the main login and redirect
  flows, but not every setting.
- Wordfence 9.1.1 has earlier bootstrap protection and later hooks. Its optimized
  firewall runs before WordPress. Requests it ends before WebDecoy runs are
  outside this plugin's observation window; the initial hook fixture did not
  exercise that runtime. The follow-up now
  tests a manual Wordfence block in basic and native prepend modes; licensed
  vendor signatures remain outside its scope.

Official packages reviewed:
[Redirection](https://downloads.wordpress.org/plugin/redirection.5.10.1.zip),
[WPS Hide Login](https://downloads.wordpress.org/plugin/wps-hide-login.1.9.20.zip),
[Wordfence](https://downloads.wordpress.org/plugin/wordfence.9.1.1.zip).
See also [WordPress action ordering](https://developer.wordpress.org/plugins/hooks/actions/)
and [Wordfence firewall optimization](https://www.wordfence.com/help/firewall/optimizing-the-firewall/).

## Scope and implications

This is a hook-order regression fixture, not a complete WordPress HTTP test.
It loads real WordPress hook functions and unmodified WebDecoy constructor,
scoring, reserved-test, and logging methods. Options, caching and SQL storage
are in-memory adapters. Unrelated trap rules are disabled; monitor mode is on,
and no cloud key is supplied. The ordinary cases use `python-requests`, not
reserved test-trigger traffic. No actual SQL writes, cloud reporting, reverse
proxy, cache, theme, or full companion-plugin installation is validated here.

An early redirect ends the request; this check does **not** demonstrate access
to a protected action or a security bypass. A CDN/cache response or firewall
block before WordPress is likewise not something this WordPress plugin can
observe. Analytics describe requests that reach its execution point, not all
requests received by the host. Do not disable another firewall to make counts
match.

Do not move the detector to an earlier lifecycle hook solely to change these
counts. Its dependencies load on `plugins_loaded`, and an early move needs
separate boot-order, options, enforcement and companion-plugin integration
validation. The Playground issue is fixed in the demo's isolated request.

## Repeat the check

Use an existing WordPress source checkout; no installation or downloads occur:

```sh
python3 tests/wp-compat/hook-order.py /path/to/wordpress/wp-includes php
```

Each case is a fresh PHP process because real redirects and the reserved-test
handler exit. A failure, unexpected row/redirect, PHP fatal, or timeout fails
the runner. Supply the same WordPress version's core hook files together.
The initial run used a network-denied, read-only macOS sandbox, an empty
environment, 128 MB PHP memory, 15 CPU seconds, 20 seconds wall time per case,
64 file descriptors and 16 processes; target code could not write files or
spawn subprocesses. Only dummy IP `192.0.2.42` and `fixture.invalid` were used.
