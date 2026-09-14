#!/usr/bin/env python3
"""Log in to the throwaway site and re-POST the WebDecoy settings form
unchanged, which runs sanitize_options() the way the admin UI does.
Usage: roundtrip.py http://localhost:8071"""
import html, html.parser, http.cookiejar, re, sys, urllib.parse, urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8071"
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
opener.addheaders = [("User-Agent", "Mozilla/5.0 (Macintosh) Chrome/128 Safari/537.36")]
opener.open(BASE + "/wp-login.php").read()
opener.open(BASE + "/wp-login.php", urllib.parse.urlencode({
    "log": "admin", "pwd": "admin", "wp-submit": "Log In", "testcookie": "1"}).encode()).read()


class Form(html.parser.HTMLParser):
    """Collect the name/value pairs a browser would submit for the options.php form."""

    def __init__(self):
        super().__init__()
        self.inform = False
        self.fields = []
        self.sel = None
        self.sel_done = False
        self.ta = None
        self.ta_buf = ""

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form" and a.get("action", "").endswith("options.php"):
            self.inform = True
        if not self.inform:
            return
        if tag == "input" and a.get("name"):
            t = a.get("type", "text")
            if t in ("checkbox", "radio"):
                if "checked" in a:
                    self.fields.append((a["name"], a.get("value", "on")))
            elif t not in ("submit", "button", "file"):
                self.fields.append((a["name"], a.get("value", "")))
        elif tag == "select":
            self.sel, self.sel_done = a.get("name"), False
        elif tag == "option" and self.sel and "selected" in a and not self.sel_done:
            self.fields.append((self.sel, a.get("value", "")))
            self.sel_done = True
        elif tag == "textarea":
            self.ta, self.ta_buf = a.get("name"), ""

    def handle_data(self, data):
        if self.ta:
            self.ta_buf += data

    def handle_endtag(self, tag):
        if tag == "select":
            self.sel = None
        elif tag == "textarea" and self.ta:
            self.fields.append((self.ta, html.unescape(self.ta_buf)))
            self.ta = None
        elif tag == "form":
            self.inform = False


page = opener.open(BASE + "/wp-admin/admin.php?page=webdecoy").read().decode()
form = Form()
form.feed(page)
names = [n for n, _ in form.fields]
ok = "option_page" in names and "_wpnonce" in names
print(f"settings form: {len(form.fields)} fields, nonce present: {ok}")
if not ok:
    sys.exit(1)
try:
    r = opener.open(urllib.request.Request(BASE + "/wp-admin/options.php", urllib.parse.urlencode(form.fields).encode()))
    print("options.php ->", r.status, "saved:", "settings-updated=true" in r.geturl())
except urllib.error.HTTPError as e:
    print("options.php -> HTTP", e.code, e.read().decode()[:300])
    sys.exit(1)
after = opener.open(BASE + "/wp-admin/admin.php?page=webdecoy&settings-updated=true").read().decode()
markers = len(re.findall(r"<b>(Warning|Fatal error|Deprecated|Notice)</b>", after))
print("php error markers after save:", markers)
sys.exit(1 if markers else 0)
