=== WebDecoy Bot Detection ===
Contributors: webdecoy
Donate link: https://webdecoy.com
Tags: security, bot detection, spam protection, woocommerce, firewall
Requires at least: 5.6
Tested up to: 6.8
Stable tag: 2.0.0
Requires PHP: 7.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Zero-configuration bot protection for WordPress. Works immediately on activation — no account, no API key, no external dependencies. Multi-layer detection with invisible proof-of-work challenges.

== Description ==

WebDecoy is a **free, fully-functional** bot detection and protection plugin that works 100% locally. Unlike CAPTCHA solutions that frustrate visitors, WebDecoy uses invisible multi-layer detection — legitimate users never see challenges or interruptions.

**Works immediately on activation.** No account needed. No API key required. No external connections on the front end. (The admin Statistics page loads Chart.js from the jsDelivr CDN.)

= Why WebDecoy? =

* **Zero friction** — Humans never see CAPTCHAs or challenges
* **Zero configuration** — Install, activate, done
* **Zero dependencies** — Everything runs locally on your server
* **Multi-layer detection** — Server-side + client-side + proof-of-work challenges
* **Free forever** — Full protection at no cost. Premium cloud features are optional.

= Free Features (No API Key Needed) =

**Server-Side Detection**
* User-Agent analysis and HTTP header inspection
* Good bot verification (reverse DNS for Googlebot, Bingbot, etc.)
* MITRE ATT&CK path analysis (admin probing, config file access)
* Rate limiting with automatic blocking
* IP blocking (individual + CIDR, IPv4/IPv6, expiration)

**Client-Side Detection**
* WebDriver detection (Selenium, Puppeteer, Playwright)
* Headless browser detection (Chrome headless, PhantomJS)
* Automation framework detection
* Behavioral analysis (mouse movement, click patterns, scroll behavior)
* Canvas/WebGL fingerprinting
* AI crawler detection (GPTBot, ClaudeBot, PerplexityBot)

**Invisible Proof-of-Work Challenges**
* SHA-256 challenges solved in background (no user interaction)
* Challenge mode for suspicious requests (checkbox widget, auto-solves)
* Difficulty scales based on threat signals
* No external CAPTCHA service needed

**Form Protection**
* Comment spam protection
* Login brute force protection
* Registration spam prevention
* Invisible honeypot fields with obfuscated names

**WooCommerce Protection**
* Checkout carding attack prevention
* Velocity limiting (configurable attempts per time window)
* Card testing pattern detection
* WooCommerce Blocks compatible

**Local Dashboard & Analytics**
* Detection log with threat scores and MITRE tactic mapping
* Statistics page with 30-day trend charts
* Blocked IPs management
* Dashboard widget with threat overview
* CSV export
* Automatic data cleanup (30 days)

**Smart Bot Recognition**
* 60+ known good bots automatically allowed
* Search engines, social media, monitoring services, SEO tools
* Optional AI crawler blocking
* Custom allowlist support

= Premium Features (Optional WebDecoy Cloud) =

Connect an API key to unlock cloud-powered intelligence:

* **IP Reputation** — AbuseIPDB integration, threat scoring
* **VPN/Proxy Detection** — Identify visitors hiding behind VPNs, proxies, and Tor
* **GeoIP Enrichment** — Geographic data from MaxMind
* **Cloud Sync** — Forward detections to centralized dashboard
* **Cross-Site Intelligence** — Aggregate threat data from all WebDecoy customers
* **Advanced Analytics** — Cloud dashboard at app.webdecoy.com with indefinite history
* **Webhooks & Alerts** — Automated response chains, email notifications

[Explore Plans](https://webdecoy.com/pricing) | [Start Free Trial](https://app.webdecoy.com/register)

= Threat Scoring =

WebDecoy uses an intelligent scoring system (0-100):

* 0-19: MINIMAL — Allow (likely human)
* 20-39: LOW — Log only
* 40-59: MEDIUM — Optional challenge
* 60-74: HIGH — Challenge or block
* 75-100: CRITICAL — Automatic block

The threshold is fully configurable to match your site's needs.

== Installation ==

1. Upload the `webdecoy` folder to the `/wp-content/plugins/` directory, or install directly from the WordPress plugin repository
2. Activate the plugin through the 'Plugins' menu in WordPress
3. **That's it!** Protection is active immediately with sensible defaults

= Optional: Connect to WebDecoy Cloud =

1. Go to **WebDecoy > Settings > WebDecoy Cloud** tab
2. Enter your API key from your [WebDecoy dashboard](https://app.webdecoy.com)
3. Click "Test Connection" to verify
4. Cloud features (threat intel, VPN detection, etc.) activate automatically

== Frequently Asked Questions ==

= Do I need an API key? =

**No.** WebDecoy works 100% locally without any API key or account. All detection, blocking, rate limiting, form protection, and WooCommerce protection works out of the box. The API key is only needed for optional cloud features like IP reputation and VPN detection.

= What does WebDecoy Cloud add? =

WebDecoy Cloud adds threat intelligence feeds (AbuseIPDB, VPNAPI, MaxMind), centralized monitoring across multiple sites, indefinite detection history, and automated response features like webhooks and email alerts. [Compare plans](https://webdecoy.com/pricing).

= Does WebDecoy slow down my site? =

No. WebDecoy adds less than 5ms of latency to requests. Server-side detection runs in milliseconds. The client-side scanner loads asynchronously with the `defer` attribute and doesn't block page rendering.

= Will it block legitimate visitors? =

WebDecoy is designed to minimize false positives. You can adjust the sensitivity and blocking threshold. Start with "Log only" mode to monitor before enabling blocking. Good bots (Googlebot, Bingbot, etc.) are automatically recognized.

= Does it work with caching plugins? =

Yes. WebDecoy works alongside popular caching plugins. The client-side scanner runs after page load, and server-side checks happen before caching.

= What about search engine bots? =

WebDecoy automatically recognizes and allows 60+ legitimate bots including Googlebot, Bingbot, and other search engine crawlers. Good bot verification uses reverse DNS lookup. Your SEO won't be affected.

= Can I block AI training crawlers? =

Yes. WebDecoy can identify and optionally block AI crawlers like GPTBot, ClaudeBot, PerplexityBot, and others. Enable this in Settings > Good Bots.

= Does it work with WooCommerce? =

Yes. WebDecoy includes specialized carding protection for WooCommerce including checkout velocity limiting, card testing detection, and automatic fraud blocking. Compatible with both classic checkout and WooCommerce Blocks.

= Is my data secure? =

Without an API key, the plugin makes **zero external connections on the front end** — visitors' browsers never contact third-party servers. The admin Statistics page loads Chart.js from the jsDelivr CDN (see External Services below). All detection data stays on your server. Detection logs are automatically cleaned up after 30 days. When using WebDecoy Cloud, all communication is encrypted over HTTPS.

= How does the proof-of-work challenge work? =

When a suspicious visitor is detected and your block action is set to "Challenge", they see a checkbox widget. Clicking it starts a SHA-256 puzzle that solves in the background (typically under 1 second for humans). Bots and automation tools take much longer or fail entirely. No external CAPTCHA service is involved.

== External Services ==

This plugin can optionally connect to the following external services when you provide an API key:

= WebDecoy Cloud (api.webdecoy.com / ingest.webdecoy.com) =
Used for: Threat intelligence feeds, IP reputation data, cross-site intelligence, cloud analytics, detection forwarding
When connected: Detection data (IP addresses, user agents, threat scores) is sent to WebDecoy Cloud for analysis
Privacy Policy: [https://webdecoy.com/privacy](https://webdecoy.com/privacy)
Terms of Service: [https://webdecoy.com/terms](https://webdecoy.com/terms)

**Without an API key, the plugin operates 100% locally with zero external connections on the front end.** The admin Statistics page loads Chart.js from jsDelivr CDN (see below).

= Chart.js (cdn.jsdelivr.net) =
Used for: Rendering detection trend charts on the Statistics admin page
When loaded: Only on the WebDecoy Statistics admin page, loaded from jsDelivr CDN
Privacy Policy: [https://www.jsdelivr.com/terms/privacy-policy-jsdelivr-net](https://www.jsdelivr.com/terms/privacy-policy-jsdelivr-net)

== Screenshots ==

1. Protection settings — configure detection and blocking
2. Statistics page — 30-day detection trends and threat distribution
3. Detections log — view threats with scores and MITRE tactics
4. Blocked IPs — manage blocked addresses with expiration
5. Dashboard widget — threat overview at a glance
6. WebDecoy Cloud — optional premium features
7. WooCommerce checkout protection settings
8. Challenge page — invisible proof-of-work for suspicious visitors

== Changelog ==

= 2.0.0 =
* **Major: All detection and protection now works locally — no API key required**
* Added: Invisible proof-of-work (PoW) challenge system
* Added: Behavioral scoring for form submissions
* Added: Statistics page with Chart.js detection trend charts
* Added: Enhanced detections page with date filters, CSV export, bulk actions
* Added: WebDecoy Cloud settings tab (optional premium features)
* Added: Cloud upsell sections throughout dashboard
* Improved: Settings page restructured — Protection tab is now default
* Improved: Dashboard widget with cloud intelligence upsell
* Changed: CDN update checker gated behind WEBDECOY_SELF_HOSTED constant
* Changed: Version bump to 2.0.0 signaling architecture change
* Fixed: PHP 7.4 str_ends_with polyfill (already present)

= 1.3.8 =
* Fixed: Removed no_plugins trigger (deprecated in modern browsers, caused false positives)

= 1.3.7 =
* Version bump

= 1.3.6 =
* Protection hooks only activate when API key is validated as active
* E2E test compatibility

= 1.3.5 =
* Security improvements and code hardening
* Updated WooCommerce compatibility to 9.4
* Performance optimizations for detection checks

= 1.3.0 =
* Major performance improvements
* Added bulk IP blocking/unblocking
* Enhanced good bot detection (60+ bots)
* Improved WooCommerce checkout protection

= 1.0.0 =
* Initial release

== Upgrade Notice ==

= 2.0.0 =
Major update! All protection now works without an API key. Existing API keys continue working — premium features auto-enable. Settings are preserved.

= 1.3.5 =
Security improvements and WooCommerce 9.4 compatibility. Recommended upgrade.

== Privacy Policy ==

WebDecoy collects the following data locally for bot detection purposes:

* IP addresses
* User agent strings
* HTTP headers
* Browser fingerprint signals
* Request patterns

This data is stored in your WordPress database and automatically cleaned up after 30 days. No data is sent externally unless you configure a WebDecoy Cloud API key.

For more information, see our [Privacy Policy](https://webdecoy.com/privacy).
