#!/usr/bin/env python3
"""Run isolated hook-order requests. No downloads or live site access.

Usage: python3 tests/wp-compat/hook-order.py /path/to/wordpress/wp-includes [php]
Supply matching plugin.php, class-wp-hook.php and companion core hook classes.
"""
import json
from pathlib import Path
import subprocess
import sys

CASES = {
    "baseline": (1, False),
    "reserved-test": (1, False),
    "mu-plugin-exit": (0, True),
    "plugins-loaded-exit": (0, True),
    "init-0-exit": (0, True),
    "init-1-before-exit": (0, True),
    "init-1-after-exit": (1, True),
    "init-2-exit": (1, True),
    "init-10-exit": (1, True),
    "wp-loaded-exit": (1, True),
    "template-redirect-exit": (1, True),
    "login": (1, True),
    "admin": (0, False),
    "ajax": (0, False),
}


def main():
    if len(sys.argv) not in (2, 3):
        print(__doc__, file=sys.stderr)
        return 2
    includes = Path(sys.argv[1]).resolve()
    php = sys.argv[2] if len(sys.argv) == 3 else "php"
    fixture = Path(__file__).with_name("hook-order-request.php")
    failures = 0
    for case, (count, redirect) in CASES.items():
        try:
            result = subprocess.run(
                [php, "-n", "-d", "memory_limit=128M", "-d", "max_execution_time=10",
                 str(fixture), case, str(includes)],
                capture_output=True, text=True, timeout=20, check=False,
            )
            data = json.loads(result.stdout)
            assert result.returncode == 0, result.stderr or data.get("fatal", "PHP failed")
            assert "fatal" not in data, data.get("fatal")
            assert len(data["rows"]) == count, data
            assert bool(data["redirect"]) == redirect, data
            if redirect:
                assert data["status"] == 302, data
            if count:
                row = data["rows"][0]
                assert row["table"] == "wp_webdecoy_detections", row
                assert row["row"]["source"] == "wordpress_plugin", row
                assert row["row"]["ip_address"] == "192.0.2.42", row
                flags = json.loads(row["row"]["flags"])
                if case == "reserved-test":
                    assert flags["metadata"]["test"] is True, flags
                    assert "test_trigger" in flags["flags"], flags
                    assert data["status"] == 403 and data["body_is_reserved_test"], data
                else:
                    assert "cli_tool" in flags["flags"], flags
                    assert "test_trigger" not in flags["flags"], flags
                    assert row["row"]["score"] >= 40, row
            if case in ("login", "admin", "ajax"):
                assert data["login_filter_registered"] is True, data
                assert data["ajax_handler_registered"] is True, data
            print(f"PASS {case}: rows={count}, redirect={redirect}")
        except (AssertionError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
            failures += 1
            print(f"FAIL {case}: {error}", file=sys.stderr)
    print(f"{len(CASES) - failures}/{len(CASES)} hook-order cases passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
