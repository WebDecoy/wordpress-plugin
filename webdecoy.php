<?php
/**
 * Plugin Name: WebDecoy Bot Detection
 * Plugin URI: https://webdecoy.com/wordpress
 * Description: Protect your WordPress site from bots, spam, and carding attacks with WebDecoy's advanced threat detection.
 * Version: 2.7.1
 * Requires at least: 6.1
 * Requires PHP: 7.4
 * Author: WebDecoy
 * Author URI: https://webdecoy.com
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: webdecoy
 * Domain Path: /languages
 * WC requires at least: 5.0
 * WC tested up to: 9.4
 *
 * @package WebDecoy
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// PHP 7.4 polyfills for functions available in PHP 8.0+
if (!function_exists('str_ends_with')) {
    function str_ends_with(string $haystack, string $needle): bool
    {
        if ($needle === '') {
            return true;
        }
        return substr($haystack, -strlen($needle)) === $needle;
    }
}
if (!function_exists('str_starts_with')) {
    function str_starts_with(string $haystack, string $needle): bool
    {
        return strncmp($haystack, $needle, strlen($needle)) === 0;
    }
}

// Plugin constants
define('WEBDECOY_VERSION', '2.7.1');
define('WEBDECOY_PLUGIN_FILE', __FILE__);
define('WEBDECOY_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('WEBDECOY_PLUGIN_URL', plugin_dir_url(__FILE__));
define('WEBDECOY_PLUGIN_BASENAME', plugin_basename(__FILE__));

// Code-level configuration (wp-config.php constants). Loaded before anything
// reads options, because WEBDECOY_DEFAULT_MODE participates in load_options().
require_once WEBDECOY_PLUGIN_DIR . 'includes/class-webdecoy-runtime-config.php';

// Load the SDK (bundled)
$sdk_paths = [
    WEBDECOY_PLUGIN_DIR . 'sdk/',
];

$sdk_loaded = false;
foreach ($sdk_paths as $sdk_path) {
    // Try Composer autoloader first
    if (file_exists($sdk_path . 'vendor/autoload.php')) {
        require_once $sdk_path . 'vendor/autoload.php';
        $sdk_loaded = true;
        break;
    }
    // Fall back to manual includes
    if (file_exists($sdk_path . 'src/Client.php')) {
        require_once $sdk_path . 'src/Exception/WebDecoyException.php';
        require_once $sdk_path . 'src/Detection.php';
        require_once $sdk_path . 'src/DetectionResult.php';
        require_once $sdk_path . 'src/GoodBotList.php';
        require_once $sdk_path . 'src/SignalCollector.php';
        require_once $sdk_path . 'src/BotDetector.php';
        require_once $sdk_path . 'src/Client.php';
        // Rules engine (tripwires, filters, rate-limit rules) — pure logic.
        require_once $sdk_path . 'src/Rules/RuleInterface.php';
        require_once $sdk_path . 'src/Rules/RuleContext.php';
        require_once $sdk_path . 'src/Rules/RuleResult.php';
        require_once $sdk_path . 'src/Rules/RuleEngineResult.php';
        require_once $sdk_path . 'src/Rules/ViolationEvent.php';
        require_once $sdk_path . 'src/Rules/RuleEngine.php';
        require_once $sdk_path . 'src/Rules/TripwireRule.php';
        // Filter expression language (tokenizer → parser → evaluator).
        require_once $sdk_path . 'src/Rules/Filter/FilterSyntaxException.php';
        require_once $sdk_path . 'src/Rules/Filter/Tokenizer.php';
        require_once $sdk_path . 'src/Rules/Filter/Parser.php';
        require_once $sdk_path . 'src/Rules/Filter/Evaluator.php';
        require_once $sdk_path . 'src/Rules/FilterRule.php';
        $sdk_loaded = true;
        break;
    }
}

if (!$sdk_loaded) {
    add_action('admin_notices', function () {
        echo '<div class="notice notice-error"><p>';
        echo '<strong>' . esc_html__('WebDecoy:', 'webdecoy') . '</strong> ' . esc_html__('SDK not found. Please reinstall the plugin.', 'webdecoy');
        echo '</p></div>';
    });
    return;
}

/**
 * Main WebDecoy Plugin Class
 */
final class WebDecoy_Plugin
{
    /**
     * Plugin instance
     *
     * @var WebDecoy_Plugin|null
     */
    private static ?WebDecoy_Plugin $instance = null;

    /**
     * Plugin options
     *
     * @var array
     */
    private array $options = [];

    /**
     * Set by build_rule_engine() when a configured filter rule references an
     * ip.* field, signalling build_rule_context() to fetch IP enrichment.
     *
     * @var bool
     */
    private bool $rules_need_enrichment = false;

    /**
     * WebDecoy API Client
     *
     * @var \WebDecoy\Client|null
     */
    private ?\WebDecoy\Client $client = null;

    /**
     * Bot Detector
     *
     * @var \WebDecoy\BotDetector|null
     */
    private ?\WebDecoy\BotDetector $detector = null;

    /**
     * Cloud connect controller (one-click connect + entitlements sync).
     *
     * @var WebDecoy_Cloud_Connect|null
     */
    private ?WebDecoy_Cloud_Connect $cloud_connect = null;

    /**
     * Actor feed controller (hourly network-block sync — Pro+ only).
     *
     * @var WebDecoy_Actor_Feed|null
     */
    private ?WebDecoy_Actor_Feed $actor_feed = null;

    /**
     * Post-CRITICAL moment controller (one-shot upgrade notice).
     *
     * @var WebDecoy_Critical_Moment|null
     */
    private ?WebDecoy_Critical_Moment $critical_moment = null;

    /**
     * Get plugin instance
     *
     * @return WebDecoy_Plugin
     */
    public static function instance(): WebDecoy_Plugin
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Constructor
     */
    private function __construct()
    {
        $this->load_options();
        $this->init_hooks();
    }

    /**
     * Load plugin options
     */
    private function load_options(): void
    {
        $defaults = [
            // API Configuration - only API key required now
            'api_key' => '',

            // Publishable site key (org id) for the browser clearance client.
            // Distinct from the secret api_key: minting needs no secret, so this
            // is safe to expose in page markup. Enables silent wd_clearance
            // cookie minting so tripwire/decoy hits bind to a device fingerprint.
            'site_key' => '',
            // Optional scope passed to the clearance client (advanced).
            'clearance_scope' => '',

            // Cloud connection metadata, populated by the one-click connect flow
            // (WebDecoy_Cloud_Connect). Managed outside the settings form; the
            // sanitizer carries these forward so a normal save never wipes them.
            'organization_id' => '',
            'organization_name' => '',
            'plan' => '',

            // Proxy / client IP resolution. By default the plugin uses the direct
            // connection IP (REMOTE_ADDR) and IGNORES forwarding headers, which are
            // spoofable. Sites behind a reverse proxy/CDN must opt in so that
            // X-Forwarded-For / CF-Connecting-IP are honored ONLY from trusted hops.
            'behind_cloudflare' => false,
            'trusted_proxies' => '', // newline/comma separated IPs or CIDRs

            // Detection Settings
            'enabled' => true,
            'sensitivity' => 'medium',
            'min_score_to_block' => 75,
            'min_threat_level' => 'HIGH',

            // Good Bot Handling
            'allow_search_engines' => true,
            'allow_social_bots' => true,
            'block_ai_crawlers' => false,
            'custom_allowlist' => [],

            // Blocking Settings
            // Monitor mode is the safe default: everything is detected, logged and
            // reported, and nothing is ever blocked, throttled or 403'd. Turn it off
            // deliberately, once the Detections page shows what enforcement would do.
            'monitor_mode' => true,
            'ip_allowlist' => [], // IPs/CIDRs that bypass all detection
            'block_action' => 'block',
            // 93% of hostile addresses are gone inside an hour, so a longer default
            // buys almost nothing against the adversary and carries a full extra day
            // of exposure to blocking whoever inherits the address next.
            'block_duration' => 1,
            'show_block_page' => true,
            'block_page_message' => 'Access to this site has been restricted.',

            // Rate Limiting
            'rate_limit_enabled' => true,
            'rate_limit_requests' => 60,
            'rate_limit_window' => 60,
            // Algorithm: fixed window (DB) or sliding window (object cache when a
            // persistent one is present, else fixed). Key: per IP, IP+route, or
            // logged-in user. Dry-run records without throttling.
            'rate_limit_algorithm' => 'fixed',
            'rate_limit_key' => 'ip',
            'rate_limit_dry_run' => false,

            // Tripwires (F4 deception layer). Deterministic, zero-false-positive:
            // a request for a scanner-bait honeypot path is automated by
            // construction. On by default — the built-in bait paths carry no
            // false-positive risk for real visitors, so protection is active
            // out of the box.
            'tripwire_enabled' => true,
            'tripwire_include_defaults' => true,
            'tripwire_paths' => [],      // extra exact paths
            'tripwire_prefixes' => [],   // startsWith matches
            'tripwire_patterns' => [],   // regex bodies (no delimiters)
            'tripwire_action' => 'block', // block | throttle
            'tripwire_dry_run' => false,  // record violations without blocking
            // How a tripwire hit responds: block (403), notfound (404), decoy
            // (200 fake content w/ canary credentials), or tarpit (slow drip).
            'tripwire_response' => 'block',

            // Honeytoken: auto-inject a hidden decoy link on front-end pages and
            // arm its secret path as a tripwire. Only link-following scrapers
            // ever hit it — deterministic, zero false positives. On by default.
            'honeytoken_enabled' => true,
            'honeytoken_rotate' => false, // rotate the token daily (with grace)

            // WordPress-native traps.
            'traps_fake_plugins' => true,  // arm fake vulnerable-plugin paths (absent plugins only)
            'traps_xmlrpc' => false,       // trap xmlrpc.php (off: legit clients use it)
            'traps_author_enum' => true,   // trap ?author=N + REST user enumeration

            // Filter rules: expression-based rules evaluated by the rule engine.
            // Each entry: ['expression'=>string, 'action'=>'block'|'throttle',
            // 'dry_run'=>bool, 'name'=>string]. Empty by default.
            'filter_rules' => [],

            // Form Protection
            'protect_comments' => true,
            'protect_login' => true,
            'protect_registration' => true,
            'inject_honeypot' => true,

            // WooCommerce
            'protect_checkout' => true,
            'checkout_velocity_limit' => 5,
            'checkout_velocity_window' => 3600,
            // Plant a hidden honeytoken coupon; applying it is a deterministic
            // bot signal (no human ever sees the code).
            'woo_honeytoken_coupons' => true,

            // Client-side Scanner
            'scanner_enabled' => true,
            'scanner_min_score' => 20,
            'scanner_on_all_pages' => true,
            'scanner_exclude_logged_in' => false,

            // Proof-of-Work
            'pow_enabled' => true,
            'pow_difficulty' => 4,
            'challenge_duration' => 15,
            // "Protected by WebDecoy" credit on the challenge page. Off by
            // default: WordPress.org guideline 10 requires user-facing
            // attribution to be an explicit admin opt-in.
            'challenge_show_credit' => false,
        ];

        $saved = get_option('webdecoy_options', []);
        $this->options = array_merge($defaults, $saved);

        // WEBDECOY_DEFAULT_MODE forces the mode from wp-config.php, overriding
        // whatever is stored: agencies pin 'monitor' (or 'block') in a config
        // that clients cannot edit, and a database reset cannot undo.
        $forced = WebDecoy_Runtime_Config::forced_monitor_mode();
        if ($forced !== null) {
            $this->options['monitor_mode'] = $forced;
        }

        // Decrypt API key if it's encrypted
        if (!empty($this->options['api_key']) && $this->is_encrypted($this->options['api_key'])) {
            $this->options['api_key'] = $this->decrypt_value($this->options['api_key']);
        }
    }

    /**
     * Cloudflare published IP ranges (https://www.cloudflare.com/ips/).
     * Used to verify that a request claiming a CF-Connecting-IP actually arrived
     * via Cloudflare, rather than trusting the header from any direct connection.
     */
    private const CLOUDFLARE_RANGES = [
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
        '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
        '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
        '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
        '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
    ];

    /**
     * Build the list of trusted proxy IPs/CIDRs from plugin settings. Returns an
     * empty array (= direct mode, ignore forwarding headers) unless the site is
     * explicitly configured to be behind Cloudflare and/or trusted proxies.
     *
     * @return string[]
     */
    public function get_trusted_proxies(): array
    {
        $proxies = [];

        if (!empty($this->options['behind_cloudflare'])) {
            $proxies = array_merge($proxies, self::CLOUDFLARE_RANGES);
        }

        $configured = $this->options['trusted_proxies'] ?? '';
        if (is_array($configured)) {
            $proxies = array_merge($proxies, $configured);
        } elseif (is_string($configured) && $configured !== '') {
            // Allow newline- or comma-separated entries.
            $parts = preg_split('/[\s,]+/', $configured) ?: [];
            $proxies = array_merge($proxies, $parts);
        }

        return array_values(array_filter(array_map('trim', $proxies)));
    }

    /**
     * True when the request arrived through a proxy the plugin has not been told
     * about. In that state SignalCollector::getIP() correctly refuses the spoofable
     * forwarding headers and returns REMOTE_ADDR — which is the proxy, not the
     * visitor — so every visitor resolves to the same address and any IP-keyed
     * action hits all of them at once.
     *
     * This is a detection of OUR misconfiguration. It must never cause the plugin to
     * start trusting the headers: that would let any client choose their own identity
     * and frame a third party into the block table.
     */
    public function proxy_misconfigured(): bool
    {
        // NEVER infer this from the CURRENT request's headers. Forwarding headers are
        // client-controlled, so `forwarding_headers_present() && no trusted proxy`
        // would let any visitor send `X-Forwarded-For:` and switch the whole
        // enforcement stack off for their own request — a complete bypass, and worse
        // than the bug this state exists to contain.
        //
        // The flag is written only from an authenticated administrator's request
        // (maybe_flag_proxy(), on admin_init), which is a trustworthy sample of how
        // traffic actually reaches this site and cannot be forged by a visitor.
        return $this->get_trusted_proxies() === []
            && (bool) get_option('webdecoy_proxy_detected', false);
    }

    /**
     * Record whether this site sits behind an unconfigured reverse proxy, sampled
     * from an administrator's own request. Front-end code reads the stored flag; it
     * must never read the headers directly. See proxy_misconfigured().
     */
    public function maybe_flag_proxy(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        $seen = WebDecoy_Blocker::forwarding_header_seen();
        $flagged = (bool) get_option('webdecoy_proxy_detected', false);

        if ($seen !== '' && !$flagged) {
            update_option('webdecoy_proxy_detected', $seen, false);
        } elseif ($seen === '' && $flagged) {
            // The proxy is gone, or the admin is reaching the origin directly.
            delete_option('webdecoy_proxy_detected');
        }
    }

    /**
     * Why enforcement is currently suppressed, or '' when it is live.
     *
     * Detection, logging and cloud reporting continue in every suppressed state —
     * only the act of blocking, throttling or serving a 403 is withheld.
     */
    public function suppression_reason(): string
    {
        if (defined('WEBDECOY_DISABLE') && WEBDECOY_DISABLE) {
            return 'disabled';
        }
        if (!empty($this->options['monitor_mode'])) {
            return 'monitor';
        }
        if ($this->proxy_misconfigured()) {
            return 'proxy';
        }
        return '';
    }

    /** Convenience wrapper: is any enforcement action allowed on this request? */
    public function enforcement_suppressed(): bool
    {
        return $this->suppression_reason() !== '';
    }

    /**
     * One-time migrations, keyed on the stored schema version.
     */
    public function maybe_upgrade(): void
    {
        $stored = get_option('webdecoy_schema_version', '0');
        if (version_compare($stored, '2.3.2', '>=')) {
            return;
        }

        // 2.3.2: the cross-site actor feed no longer writes to the block table.
        // Remove every row it wrote, so upgrading actually stops the enforcement
        // rather than leaving up to 2,000 stale addresses blocked until they age
        // out. Refs WebDecoy/app#476.
        if (class_exists('WebDecoy_Actor_Feed')) {
            $purged = WebDecoy_Actor_Feed::purge_feed_blocks();
            if ($purged > 0) {
                set_transient('webdecoy_upgrade_notice_232', $purged, DAY_IN_SECONDS);
            }
        }

        // 2.3.2: bring sites still sitting on the old 24-hour default down to the
        // new 1-hour default. A site that deliberately chose some other number keeps
        // it; only the untouched default moves. 24 is indistinguishable from a
        // deliberate 24, and on a safety release the shorter block is the safer of
        // the two mistakes.
        $saved = get_option('webdecoy_options', []);
        if (!is_array($saved)) {
            $saved = [];
        }
        $dirty = false;

        // 2.3.2: PERSIST the new monitor_mode default. load_options() merges it in at
        // runtime, but the settings form reads the stored array directly — without this
        // the checkbox renders unchecked while the plugin is in monitor mode, and
        // because an unchecked box submits nothing and sanitize_options() rebuilds the
        // array from scratch, the next save of ANY setting writes false and silently
        // turns full enforcement on.
        if (!array_key_exists('monitor_mode', $saved)) {
            $saved['monitor_mode'] = true;
            $dirty = true;
        }

        if (isset($saved['block_duration']) && (int) $saved['block_duration'] === 24) {
            $saved['block_duration'] = 1;
            $dirty = true;
        }

        if ($dirty) {
            $this->update_options_raw($saved);
            $this->load_options();
        }

        update_option('webdecoy_schema_version', '2.3.2', true);
    }

    /**
     * Tell the administrator, on every admin screen, when the plugin is watching
     * rather than acting — and why. A security plugin that has silently stopped
     * enforcing is worse than one that never did.
     */
    public function render_state_notices(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        $settings_url = admin_url('admin.php?page=webdecoy-settings');

        if (defined('WEBDECOY_DISABLE') && WEBDECOY_DISABLE) {
            printf(
                '<div class="notice notice-warning"><p><strong>%s</strong> %s</p></div>',
                esc_html__('WebDecoy is disabled.', 'webdecoy'),
                esc_html__('WEBDECOY_DISABLE is defined in wp-config.php, so nothing is detected or blocked on the front end. Remove it to resume.', 'webdecoy')
            );
            return;
        }

        // The dangerous state: a proxy in front, and we were never told about it,
        // so every visitor resolves to the same address.
        if ($this->proxy_misconfigured()) {
            // The stored flag holds the header name that was seen on an admin request.
            $seen = (string) get_option('webdecoy_proxy_detected', '');
            if ($seen === '' || $seen === '1') {
                $seen = __('a forwarding header', 'webdecoy');
            }
            $header_html = '<code>' . esc_html($seen) . '</code>';
            printf(
                '<div class="notice notice-error"><p><strong>%s</strong> %s</p><p>%s</p><p><a class="button button-primary" href="%s">%s</a></p></div>',
                esc_html__('WebDecoy is not blocking: this site is behind a proxy it has not been told about.', 'webdecoy'),
                wp_kses(
                    sprintf(
                        /* translators: %s: comma-separated list of HTTP header names */
                        esc_html__('Your requests arrive with %s, but no trusted proxy is configured. Until that is fixed every visitor looks like the same address, so blocking anyone would block everyone.', 'webdecoy'),
                        $header_html
                    ),
                    ['code' => []]
                ),
                esc_html__('Detection, logging and reporting continue as normal. Only blocking, rate limiting and the 403 page are withheld.', 'webdecoy'),
                esc_url($settings_url),
                esc_html__('Configure trusted proxies', 'webdecoy')
            );
            return;
        }

        if (!empty($this->options['monitor_mode'])) {
            $stats = get_option('webdecoy_suppressed_actions', []);
            $total = 0;
            if (is_array($stats)) {
                foreach ($stats as $day) {
                    $total += (int) ($day['count'] ?? 0);
                }
            }
            printf(
                '<div class="notice notice-info"><p><strong>%s</strong> %s</p><p><a class="button" href="%s">%s</a></p></div>',
                esc_html__('WebDecoy is in monitor mode.', 'webdecoy'),
                $total > 0
                    ? sprintf(
                        /* translators: %d: number of actions that were withheld */
                        esc_html__('Everything is detected and logged; nothing is blocked. Enforcing would have acted on %d requests in the last 30 days.', 'webdecoy'),
                        (int) $total
                    )
                    : esc_html__('Everything is detected and logged; nothing is blocked. No request has met the bar for enforcement yet.', 'webdecoy'),
                esc_url($settings_url),
                esc_html__('Review and turn on blocking', 'webdecoy')
            );
        }
    }

    /**
     * Sanitize the trusted-proxies setting: accept newline/comma separated IPs or
     * CIDR ranges, discard anything that isn't a valid IP or CIDR, and store back
     * as a newline-separated string. This prevents garbage entries from widening
     * the trusted set.
     */
    private function sanitize_trusted_proxies($input): string
    {
        if (is_array($input)) {
            $entries = $input;
        } else {
            $entries = preg_split('/[\s,]+/', (string) $input) ?: [];
        }

        $valid = [];
        foreach ($entries as $entry) {
            $entry = trim((string) $entry);
            if ($entry === '') {
                continue;
            }
            if (strpos($entry, '/') !== false) {
                [$addr, $bits] = array_pad(explode('/', $entry, 2), 2, '');
                if (filter_var($addr, FILTER_VALIDATE_IP) && ctype_digit($bits) && (int) $bits >= 0 && (int) $bits <= 128) {
                    $valid[] = $entry;
                }
            } elseif (filter_var($entry, FILTER_VALIDATE_IP)) {
                $valid[] = $entry;
            }
        }

        return implode("\n", array_unique($valid));
    }

    /**
     * Sanitize a newline/comma separated list of URL paths into a clean array.
     * Each entry is normalized to begin with a leading slash.
     *
     * @param mixed $input
     * @return string[]
     */
    private function sanitize_path_list($input): array
    {
        if (is_array($input)) {
            $entries = $input;
        } else {
            $entries = preg_split('/[\r\n,]+/', (string) $input) ?: [];
        }

        $valid = [];
        foreach ($entries as $entry) {
            $entry = trim((string) $entry);
            if ($entry === '') {
                continue;
            }
            // Strip whitespace and control chars; keep it a bare path.
            $entry = sanitize_text_field($entry);
            if ($entry === '') {
                continue;
            }
            if ($entry[0] !== '/') {
                $entry = '/' . $entry;
            }
            $valid[] = $entry;
        }

        return array_values(array_unique($valid));
    }

    /**
     * Sanitize a newline separated list of regex bodies (no delimiters).
     * Discards any pattern that isn't a valid PCRE so a bad rule can never
     * throw at evaluation time.
     *
     * @param mixed $input
     * @return string[]
     */
    private function sanitize_pattern_list($input): array
    {
        if (is_array($input)) {
            $entries = $input;
        } else {
            $entries = preg_split('/[\r\n]+/', (string) $input) ?: [];
        }

        $valid = [];
        foreach ($entries as $entry) {
            $entry = trim((string) $entry);
            if ($entry === '') {
                continue;
            }
            $delimited = '#' . str_replace('#', '\\#', $entry) . '#';
            // phpcs:ignore
            if (@preg_match($delimited, '') !== false) {
                $valid[] = $entry;
            }
        }

        return array_values(array_unique($valid));
    }

    /**
     * Sanitize the filter-rules repeater. Each rule's expression is validated by
     * attempting to parse it; a malformed expression is kept (so the admin can
     * fix it) but flagged with an `error` and surfaced as a settings notice, and
     * skipped at engine-build time so it can never fatal a request.
     *
     * @param mixed $input
     * @return array<int,array<string,mixed>>
     */
    private function sanitize_filter_rules($input): array
    {
        if (!is_array($input)) {
            return [];
        }

        $rules = [];
        foreach ($input as $row) {
            if (!is_array($row)) {
                continue;
            }
            $expression = trim((string) ($row['expression'] ?? ''));
            if ($expression === '') {
                continue;
            }

            $rule = [
                'name' => sanitize_text_field($row['name'] ?? ''),
                'expression' => $expression,
                'action' => in_array($row['action'] ?? 'block', ['block', 'throttle'], true) ? $row['action'] : 'block',
                'dry_run' => !empty($row['dry_run']),
            ];

            // Validate by parsing. Keep the text either way; flag on failure.
            try {
                new \WebDecoy\Rules\FilterRule(['expression' => $expression]);
            } catch (\Throwable $e) {
                $rule['error'] = $e->getMessage();
                add_settings_error(
                    'webdecoy_options',
                    'filter_rule_invalid',
                    sprintf(
                        /* translators: 1: filter expression, 2: parser error */
                        __('Filter rule "%1$s" is invalid and was disabled: %2$s', 'webdecoy'),
                        $expression,
                        $e->getMessage()
                    ),
                    'error'
                );
            }

            $rules[] = $rule;
        }

        return $rules;
    }

    /**
     * Get the scanner ID (auto-generated from site URL)
     *
     * @return string
     */
    private function get_scanner_id(): string
    {
        return 'wp-' . substr(md5(get_site_url()), 0, 12);
    }

    /**
     * Get encryption key (unique per site)
     *
     * @return string
     */
    private function get_encryption_key(): string
    {
        // Use AUTH_KEY if available, otherwise generate and store one
        if (defined('AUTH_KEY') && AUTH_KEY !== '') {
            return hash('sha256', AUTH_KEY . 'webdecoy_api_key');
        }

        // Fallback: get or create a stored key
        $key = get_option('webdecoy_encryption_key');
        if (!$key) {
            $key = wp_generate_password(64, true, true);
            update_option('webdecoy_encryption_key', $key, false);
        }
        return hash('sha256', $key);
    }

    /**
     * Encrypt a value
     *
     * @param string $value
     * @return string Encrypted value with prefix
     */
    private function encrypt_value(string $value): string
    {
        if (empty($value)) {
            return '';
        }

        $key = $this->get_encryption_key();

        // Use OpenSSL if available
        if (function_exists('openssl_encrypt')) {
            $iv = openssl_random_pseudo_bytes(16);
            $encrypted = openssl_encrypt($value, 'AES-256-CBC', $key, 0, $iv);
            if ($encrypted !== false) {
                return 'enc:' . base64_encode($iv . $encrypted);
            }
        }

        // Fallback: simple obfuscation (not secure, but better than plaintext)
        return 'obs:' . base64_encode($value ^ str_repeat($key, ceil(strlen($value) / strlen($key))));
    }

    /**
     * Decrypt a value
     *
     * @param string $value Encrypted value with prefix
     * @return string Decrypted value
     */
    private function decrypt_value(string $value): string
    {
        if (empty($value)) {
            return '';
        }

        $key = $this->get_encryption_key();

        // Check for encryption prefix
        if (strpos($value, 'enc:') === 0) {
            // OpenSSL encryption
            $data = base64_decode(substr($value, 4));
            if ($data === false || strlen($data) < 16) {
                return ''; // Invalid data
            }
            $iv = substr($data, 0, 16);
            $encrypted = substr($data, 16);
            $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, $iv);
            return $decrypted !== false ? $decrypted : '';
        }

        if (strpos($value, 'obs:') === 0) {
            // Simple obfuscation fallback
            $data = base64_decode(substr($value, 4));
            return $data ^ str_repeat($key, ceil(strlen($data) / strlen($key)));
        }

        // Not encrypted (legacy value)
        return $value;
    }

    /**
     * Check if a value is encrypted
     *
     * @param string $value
     * @return bool
     */
    private function is_encrypted(string $value): bool
    {
        return strpos($value, 'enc:') === 0 || strpos($value, 'obs:') === 0;
    }

    /**
     * Initialize hooks
     */
    private function init_hooks(): void
    {
        // Activation/Deactivation
        register_activation_hook(WEBDECOY_PLUGIN_FILE, [$this, 'activate']);
        register_deactivation_hook(WEBDECOY_PLUGIN_FILE, [$this, 'deactivate']);

        // Self-hosted update mechanism: CDN distribution only, gated behind the
        // WEBDECOY_SELF_HOSTED constant AND the presence of the updater file.
        // The WordPress.org build (build.sh --org) omits class-webdecoy-updater.php,
        // so this stays inert there — .org installs update exclusively via .org.
        if (defined('WEBDECOY_SELF_HOSTED') && WEBDECOY_SELF_HOSTED) {
            $updater_file = WEBDECOY_PLUGIN_DIR . 'includes/class-webdecoy-updater.php';
            if (file_exists($updater_file)) {
                require_once $updater_file;
                new WebDecoy_Updater();
            }
        }

        // Early request check (as early as possible)
        add_action('init', [$this, 'early_check'], 1);

        // Load includes
        add_action('plugins_loaded', [$this, 'load_includes']);

        // Admin hooks
        if (is_admin()) {
            // WEBDECOY_HIDE_ADMIN_UI removes the visible surfaces (menu, widget,
            // notices) for white-label agency installs. Upgrade routines, settings
            // registration and proxy sampling still run: hidden is not disabled.
            if (!WebDecoy_Runtime_Config::hide_admin_ui()) {
                add_action('admin_menu', [$this, 'admin_menu']);
                add_action('admin_notices', [$this, 'render_state_notices']);
                add_action('wp_dashboard_setup', [$this, 'dashboard_widget']);
            }
            add_action('admin_init', [$this, 'register_settings']);
            add_action('admin_init', [$this, 'maybe_upgrade']);
            // Sample "are we behind a proxy" from a trusted (admin) request, so the
            // front end never has to consult a client-controlled header.
            add_action('admin_init', [$this, 'maybe_flag_proxy']);
            add_action('admin_enqueue_scripts', [$this, 'admin_scripts']);
        }

        // Form protection hooks - always active when enabled
        if ($this->options['protect_comments']) {
            add_action('pre_comment_on_post', [$this, 'check_comment']);
            add_filter('preprocess_comment', [$this, 'filter_comment']);
        }

        if ($this->options['protect_login']) {
            add_filter('authenticate', [$this, 'check_login'], 30, 3);
        }

        // Canary-credential login detection: a login attempt using a fake
        // credential we only ever handed out via a decoy response is
        // unambiguous exfiltration evidence. Active whenever tripwires are on
        // (the canaries' source), independent of login protection.
        if (!empty($this->options['tripwire_enabled']) || !empty($this->options['honeytoken_enabled'])) {
            add_filter('authenticate', [$this, 'check_canary_login'], 5, 3);
        }

        if ($this->options['protect_registration']) {
            add_action('register_post', [$this, 'check_registration'], 10, 3);
        }

        // Honeypot injection
        if ($this->options['inject_honeypot']) {
            add_action('comment_form', [$this, 'inject_comment_honeypot']);
            add_action('login_form', [$this, 'inject_login_honeypot']);
            add_action('register_form', [$this, 'inject_register_honeypot']);
        }

        // WooCommerce hooks
        if ($this->options['protect_checkout'] && class_exists('WooCommerce')) {
            add_action('woocommerce_checkout_process', [$this, 'check_checkout']);
            add_action('woocommerce_payment_complete', [$this, 'track_payment']);
            add_action('woocommerce_checkout_order_processed', [$this, 'track_checkout_attempt']);
        }

        // AJAX handlers (admin)
        add_action('wp_ajax_webdecoy_test_connection', [$this, 'ajax_test_connection']);
        add_action('wp_ajax_webdecoy_get_stats', [$this, 'ajax_get_stats']);
        add_action('wp_ajax_webdecoy_block_ip', [$this, 'ajax_block_ip']);
        add_action('wp_ajax_webdecoy_unblock_ip', [$this, 'ajax_unblock_ip']);
        add_action('wp_ajax_webdecoy_bulk_block', [$this, 'ajax_bulk_block']);

        // AJAX handlers for client-side scanner (both logged-in and guests)
        add_action('wp_ajax_webdecoy_client_detection', [$this, 'ajax_client_detection']);
        add_action('wp_ajax_nopriv_webdecoy_client_detection', [$this, 'ajax_client_detection']);

        // PoW challenge AJAX handlers
        add_action('wp_ajax_webdecoy_pow_challenge', [$this, 'ajax_pow_challenge']);
        add_action('wp_ajax_nopriv_webdecoy_pow_challenge', [$this, 'ajax_pow_challenge']);
        add_action('wp_ajax_webdecoy_pow_verify', [$this, 'ajax_pow_verify']);
        add_action('wp_ajax_nopriv_webdecoy_pow_verify', [$this, 'ajax_pow_verify']);

        // Frontend scanner script (only if API is active)
        if ($this->options['scanner_enabled'] && !is_admin()) {
            add_action('wp_enqueue_scripts', [$this, 'frontend_scripts']);
        }

        // Browser clearance client: mints the wd_clearance cookie for real
        // visitors so tripwire/decoy hits bind to a device fingerprint. Needs
        // only the publishable site key (no secret / premium gate).
        if (!empty($this->options['site_key']) && !is_admin()) {
            add_action('wp_enqueue_scripts', [$this, 'enqueue_clearance_client']);
        }

        // Honeytoken: inject the hidden decoy link on front-end pages. The path
        // itself is armed as a tripwire in build_rule_engine().
        if (!empty($this->options['honeytoken_enabled']) && !is_admin()) {
            add_action('wp_footer', [$this, 'inject_honeytoken_link'], 99);
        }

        // WordPress-native query/REST traps (author enumeration). Registered
        // after includes are loaded so the traps class is available.
        if (!empty($this->options['traps_author_enum'])) {
            add_action('plugins_loaded', [$this, 'register_wp_traps'], 20);
        }

        // JS execution verification: inject challenge token meta tag and report page serve
        // Only active when scanner is enabled and API key is configured (premium)
        if ($this->options['scanner_enabled'] && !is_admin() && $this->is_premium()) {
            add_action('wp_head', [$this, 'inject_js_verification_token'], 1);
        }

        // Clear API cache when settings are saved
        add_action('update_option_webdecoy_options', [$this, 'clear_api_status_cache']);

        // Safety-net cron drain of the violation-report spool.
        add_action('webdecoy_flush_violations', [$this, 'cron_flush_violations']);

        // Load text domain

        // Declare HPOS compatibility for WooCommerce
        add_action('before_woocommerce_init', [$this, 'declare_hpos_compatibility']);

        // Add defer attribute to frontend scanner script for better performance
        add_filter('script_loader_tag', [$this, 'add_defer_to_scanner'], 10, 3);
    }

    /**
     * Declare High-Performance Order Storage (HPOS) compatibility for WooCommerce
     */
    public function declare_hpos_compatibility(): void
    {
        if (class_exists(\Automattic\WooCommerce\Utilities\FeaturesUtil::class)) {
            \Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility('custom_order_tables', WEBDECOY_PLUGIN_FILE, true);
        }
    }

    /**
     * Add defer attribute to scanner script for non-blocking page load
     *
     * @param string $tag Script HTML tag
     * @param string $handle Script handle
     * @param string $src Script source URL
     * @return string Modified script tag
     */
    public function add_defer_to_scanner(string $tag, string $handle, string $src): string
    {
        if ($handle === 'webdecoy-scanner') {
            return str_replace(' src', ' defer src', $tag);
        }

        // The clearance client auto-starts from data-* attributes on its own
        // script tag; inject them here (WP core has no API to set arbitrary
        // script-tag attributes on older versions). Also load it async.
        if ($handle === 'webdecoy-clearance') {
            $attrs = ' async data-site-key="' . esc_attr((string) $this->options['site_key']) . '"';
            $scope = (string) ($this->options['clearance_scope'] ?? '');
            if ($scope !== '') {
                $attrs .= ' data-scope="' . esc_attr($scope) . '"';
            }
            return str_replace(' src', $attrs . ' src', $tag);
        }

        return $tag;
    }

    /**
     * Load plugin includes
     */
    public function load_includes(): void
    {
        require_once WEBDECOY_PLUGIN_DIR . 'includes/class-webdecoy-activator.php';
        require_once WEBDECOY_PLUGIN_DIR . 'includes/class-webdecoy-blocker.php';
        require_once WEBDECOY_PLUGIN_DIR . 'includes/class-webdecoy-detector.php';
        require_once WEBDECOY_PLUGIN_DIR . 'includes/class-webdecoy-rate-limiter.php';

        require_once WEBDECOY_PLUGIN_DIR . 'includes/class-webdecoy-pow.php';
        require_once WEBDECOY_PLUGIN_DIR . 'includes/class-webdecoy-behavioral-scorer.php';
        require_once WEBDECOY_PLUGIN_DIR . 'includes/class-webdecoy-violation-reporter.php';
        require_once WEBDECOY_PLUGIN_DIR . 'includes/class-webdecoy-honeytoken.php';
        require_once WEBDECOY_PLUGIN_DIR . 'includes/class-webdecoy-ip-enrichment.php';
        require_once WEBDECOY_PLUGIN_DIR . 'includes/class-webdecoy-decoy-response.php';
        require_once WEBDECOY_PLUGIN_DIR . 'includes/class-webdecoy-rate-limit-rule.php';
        require_once WEBDECOY_PLUGIN_DIR . 'includes/class-webdecoy-wp-traps.php';
        require_once WEBDECOY_PLUGIN_DIR . 'includes/class-webdecoy-cloud-connect.php';
        require_once WEBDECOY_PLUGIN_DIR . 'includes/class-webdecoy-actor-intel.php';

        // WP-CLI surface for agency deploy scripts: wp webdecoy status|config|
        // allowlist|logs. Only loaded when WP-CLI is actually running.
        if (defined('WP_CLI') && WP_CLI) {
            require_once WEBDECOY_PLUGIN_DIR . 'includes/class-webdecoy-cli.php';
            \WP_CLI::add_command('webdecoy', 'WebDecoy_CLI_Command');
        }
        require_once WEBDECOY_PLUGIN_DIR . 'includes/class-webdecoy-actor-feed.php';
        require_once WEBDECOY_PLUGIN_DIR . 'includes/class-webdecoy-critical-moment.php';

        // One-click Cloud connect + entitlements sync. Makes no external request
        // until the admin explicitly clicks "Connect".
        $this->cloud_connect = new WebDecoy_Cloud_Connect();
        $this->cloud_connect->register();

        // Actor feed: hourly network-block sync. Self-guards to make no external
        // request unless connected AND entitled to the actor feed (Pro+).
        $this->actor_feed = new WebDecoy_Actor_Feed();
        $this->actor_feed->register();

        // Post-CRITICAL moment: one-shot, throttled upgrade notice. Queued from
        // the CRITICAL detection insert sites; renders in wp-admin only.
        $this->critical_moment = new WebDecoy_Critical_Moment();
        $this->critical_moment->register();

        if (class_exists('WooCommerce')) {
            require_once WEBDECOY_PLUGIN_DIR . 'includes/class-webdecoy-woocommerce.php';
        }
    }

    /**
     * Plugin activation
     */
    public function activate(): void
    {
        require_once WEBDECOY_PLUGIN_DIR . 'includes/class-webdecoy-activator.php';
        WebDecoy_Activator::activate();
    }

    /**
     * Plugin deactivation
     */
    public function deactivate(): void
    {
        require_once WEBDECOY_PLUGIN_DIR . 'includes/class-webdecoy-activator.php';
        WebDecoy_Activator::deactivate();
    }

    /**
     * Early request check
     */
    public function early_check(): void
    {
        // Emergency off switch. `define('WEBDECOY_DISABLE', true);` in wp-config.php
        // stops the plugin doing anything on the front end, so an owner who has locked
        // themselves out can recover over FTP without touching the database.
        if (defined('WEBDECOY_DISABLE') && WEBDECOY_DISABLE) {
            return;
        }

        // Skip if disabled
        if (!$this->options['enabled']) {
            return;
        }

        // Skip admin and AJAX requests
        if (is_admin() || wp_doing_ajax()) {
            return;
        }

        // Check if IP is blocked
        $blocker = new WebDecoy_Blocker();
        $ip = $this->get_client_ip();

        // Reserved test trigger (WebDecoy/app#677):
        //   curl -A "WebDecoy-Test/1.0" https://your-site.example/
        // always records a detection, so a fresh install can prove itself end
        // to end. Deliberately checked before the allowlist (a developer
        // testing from an allowlisted IP still gets their receipt), before the
        // block check, and before rules (a test must never trip enforcement).
        // The cloud labels these rows as tests and keeps them out of stats.
        if ($this->is_test_trigger_request()) {
            $this->handle_test_trigger($ip);
            return;
        }

        // Allowlisted IPs bypass all detection entirely.
        if ($blocker->is_allowlisted($ip)) {
            return;
        }

        // Detection continues in every suppressed state; only the 403 is withheld.
        if ($blocker->is_blocked($ip) && !$this->enforcement_suppressed()) {
            $this->block_request(__('Your IP has been blocked.', 'webdecoy'));
            return;
        }

        // Deterministic rule engine (tripwires / filters). Runs before heuristic
        // scoring: a rule DENY/THROTTLE short-circuits and scoring never runs,
        // matching @webdecoy/node's protect() flow. Rules also record violations
        // (reported to the cloud) even when they don't decide the outcome.
        $engine = $this->build_rule_engine();
        if ($engine !== null) {
            $context = $this->build_rule_context($ip);
            $engineResult = $engine->evaluate($context);

            if ($engineResult->violations) {
                // Log locally so hits show in the Detections admin page even for
                // local-only installs and dry-run rules (which record but don't
                // block).
                $this->log_rule_violations($engineResult->violations);

                // Report to the cloud (premium only). Tripwire hits carry
                // wd_clearance so the backend can durably deny the actor's
                // device fingerprint.
                $reporter = WebDecoy_Violation_Reporter::instance($this->is_premium() ? (string) $this->options['api_key'] : '');
                if ($reporter !== null) {
                    $reporter->report($engineResult->violations);
                }
            }

            if (!$engineResult->isAllowed()) {
                $this->handle_rule_decision($engineResult, $ip);
                return;
            }
        }

        // Rate limiting now runs as a rule inside the engine above (THROTTLE →
        // 429 + Retry-After + X-RateLimit-* headers), so it evaluates in order
        // with tripwires and filters rather than as a separate pre-check.

        // Run bot detection through the WebDecoy_Detector wrapper — the single
        // detector path (SDK BotDetector + WP-specific signals), the same one
        // WooCommerce uses. It collects request signals, adds the request path
        // for MITRE ATT&CK path analysis, and merges WP context.
        $result = (new WebDecoy_Detector($this->options))->analyze();

        // Skip if good bot
        if ($result->isGoodBot()) {
            return;
        }

        // Log any detection with score >= 40 (captures MITRE tactic detections)
        // This is lower than the blocking threshold (default 75)
        $log_threshold = 40;
        if ($result->getScore() >= $log_threshold) {
            // Always log detection locally
            $this->log_detection($result, $ip);

            // Submit to API (fail open)
            try {
                $this->submit_detection($result, $ip);
            } catch (\Exception $e) {
                error_log('WebDecoy API error: ' . $e->getMessage());
            }
        }

        // Check if should block (higher threshold)
        if ($result->shouldBlock($this->options['min_score_to_block'])) {
            $this->handle_blocking($result, $ip);
        }
    }

    /**
     * Build the rule engine from current settings, or null when no rules are
     * configured (so the common case adds zero overhead).
     *
     * @return \WebDecoy\Rules\RuleEngine|null
     */
    private function build_rule_engine(): ?\WebDecoy\Rules\RuleEngine
    {
        $rules = [];

        $action = ($this->options['tripwire_action'] ?? 'block') === 'throttle'
            ? \WebDecoy\Rules\RuleResult::THROTTLE
            : \WebDecoy\Rules\RuleResult::DENY;
        $dryRun = !empty($this->options['tripwire_dry_run']);

        if (!empty($this->options['tripwire_enabled'])) {
            $rules[] = new \WebDecoy\Rules\TripwireRule([
                'paths' => is_array($this->options['tripwire_paths'] ?? null) ? $this->options['tripwire_paths'] : [],
                'prefixes' => is_array($this->options['tripwire_prefixes'] ?? null) ? $this->options['tripwire_prefixes'] : [],
                'patterns' => is_array($this->options['tripwire_patterns'] ?? null) ? $this->options['tripwire_patterns'] : [],
                'includeDefaults' => !empty($this->options['tripwire_include_defaults']),
                'action' => $action,
                'dryRun' => $dryRun,
            ]);
        }

        // Arm the honeytoken path(s) as a tripwire. Independent of the general
        // tripwire toggle: if honeytokens are on, their secret path is always
        // enforced (the hidden link is only useful if a hit actually trips).
        if (!empty($this->options['honeytoken_enabled'])) {
            $honeytoken = new WebDecoy_Honeytoken(!empty($this->options['honeytoken_rotate']));
            $rules[] = new \WebDecoy\Rules\TripwireRule([
                'paths' => $honeytoken->active_paths(),
                'includeDefaults' => false,
                'action' => $action,
                'dryRun' => $dryRun,
            ]);
        }

        // WordPress-native path traps: fake vulnerable-plugin routes (only for
        // absent plugins) and, optionally, xmlrpc.php. Armed as a tripwire so
        // they get the full DENY + violation + clearance + optional-decoy path.
        $trap_prefixes = [];
        $trap_paths = [];
        if (!empty($this->options['traps_fake_plugins'])) {
            $trap_prefixes = array_merge($trap_prefixes, WebDecoy_WP_Traps::plugin_path_prefixes());
        }
        if (!empty($this->options['traps_xmlrpc'])) {
            $trap_paths[] = '/xmlrpc.php';
        }
        if ($trap_prefixes !== [] || $trap_paths !== []) {
            $rules[] = new \WebDecoy\Rules\TripwireRule([
                'paths' => $trap_paths,
                'prefixes' => $trap_prefixes,
                'includeDefaults' => false,
                'action' => $action,
                'dryRun' => $dryRun,
            ]);
        }

        // Filter (expression) rules. A malformed stored expression is skipped
        // defensively so it can never fatal a request (it was already flagged in
        // the admin on save). Track whether any rule needs IP enrichment.
        $filterRules = $this->options['filter_rules'] ?? [];
        if (is_array($filterRules)) {
            foreach ($filterRules as $fr) {
                if (!is_array($fr) || empty($fr['expression']) || !empty($fr['error'])) {
                    continue;
                }
                try {
                    $rule = new \WebDecoy\Rules\FilterRule([
                        'expression' => (string) $fr['expression'],
                        'name' => (string) ($fr['name'] ?? ''),
                        'action' => ($fr['action'] ?? 'block') === 'throttle'
                            ? \WebDecoy\Rules\RuleResult::THROTTLE
                            : \WebDecoy\Rules\RuleResult::DENY,
                        'dryRun' => !empty($fr['dry_run']),
                    ]);
                } catch (\Throwable $e) {
                    continue; // malformed despite the save-time check — skip
                }
                if ($rule->needsEnrichment()) {
                    $this->rules_need_enrichment = true;
                }
                $rules[] = $rule;
            }
        }

        // Rate limiting runs last: a deterministic tripwire/filter DENY should
        // win over a THROTTLE for the same request.
        if (!empty($this->options['rate_limit_enabled'])) {
            $rules[] = new WebDecoy_Rate_Limit_Rule([
                'limit' => (int) ($this->options['rate_limit_requests'] ?? 60),
                'window' => (int) ($this->options['rate_limit_window'] ?? 60),
                'algorithm' => $this->options['rate_limit_algorithm'] ?? 'fixed',
                'keyBy' => $this->options['rate_limit_key'] ?? 'ip',
                'dryRun' => !empty($this->options['rate_limit_dry_run']),
            ]);
        }

        if ($rules === []) {
            return null;
        }

        return new \WebDecoy\Rules\RuleEngine($rules);
    }

    /**
     * Register the WordPress-native query/REST traps (author enumeration),
     * wired to record synthetic tripwire violations.
     */
    public function register_wp_traps(): void
    {
        $traps = new WebDecoy_WP_Traps([$this, 'record_synthetic_tripwire']);
        $traps->register(!empty($this->options['traps_author_enum']));
    }

    /**
     * Record + report a synthetic tripwire hit for traps that don't flow through
     * the rule engine (author enumeration, REST user probing). Logged locally
     * and, when premium, reported with the wd_clearance token so the actor's
     * device fingerprint can be durably denied — same as an engine tripwire.
     *
     * @param string $rule
     * @param string $path
     */
    public function record_synthetic_tripwire(string $rule, string $path): void
    {
        $ip = $this->get_client_ip();
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
        $clearance = null;
        if ($rule === 'tripwire' && isset($_COOKIE['wd_clearance'])) {
            $clearance = sanitize_text_field(wp_unslash($_COOKIE['wd_clearance']));
        }

        $event = new \WebDecoy\Rules\ViolationEvent(
            $rule,
            \WebDecoy\Rules\RuleResult::DENY,
            $ip,
            $path,
            isset($_SERVER['REQUEST_METHOD']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD'])) : 'GET',
            $ua !== '' ? $ua : null,
            'WordPress trap hit: ' . $path,
            $clearance,
            ['path' => $path, 'confidence' => 100, 'trap' => true],
            false,
            gmdate('Y-m-d\TH:i:s') . '.000Z'
        );

        $this->log_rule_violations([$event]);

        $reporter = WebDecoy_Violation_Reporter::instance($this->is_premium() ? (string) $this->options['api_key'] : '');
        if ($reporter !== null) {
            $reporter->report([$event]);
        }
    }

    /**
     * Queue the post-CRITICAL upgrade moment when a detection is recorded at
     * CRITICAL severity (the decoy/canary exfiltration path). No-op for any
     * lower severity and self-throttled to at most one notice every 7 days.
     * Never makes an external request at this point — the intel lookup that
     * personalises the copy is deferred to the admin render.
     *
     * @param string $ip
     * @param string $threat_level
     */
    private function flag_critical_moment(string $ip, string $threat_level): void
    {
        if ($this->critical_moment === null) {
            return;
        }
        if ($threat_level !== \WebDecoy\DetectionResult::THREAT_CRITICAL) {
            return;
        }
        $this->critical_moment->maybe_queue($ip);
    }

    /**
     * Cron: drain any spooled violation reports that the per-request shutdown
     * flush couldn't deliver (e.g. a brief ingest outage). A non-empty API key
     * is all that's required to attempt delivery.
     */
    public function cron_flush_violations(): void
    {
        $apiKey = (string) ($this->options['api_key'] ?? '');
        if ($apiKey === '') {
            return;
        }
        WebDecoy_Violation_Reporter::drain_queue($apiKey);
    }

    /**
     * Inject the hidden honeytoken decoy link into the page footer. Only
     * link-following scrapers ever request the path it points at.
     */
    public function inject_honeytoken_link(): void
    {
        if (empty($this->options['honeytoken_enabled'])) {
            return;
        }

        $honeytoken = new WebDecoy_Honeytoken(!empty($this->options['honeytoken_rotate']));
        if (!$honeytoken->should_inject()) {
            return;
        }

        // The link markup is a fixed, safe template (the path is esc_attr'd
        // inside render_link()); emit it verbatim.
        echo $honeytoken->render_link(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
    }

    /**
     * Build the rule context for the current request (trusted-proxy-resolved IP,
     * path, method, UA, and headers — the Cookie header carries wd_clearance).
     *
     * @param string $ip
     * @return \WebDecoy\Rules\RuleContext
     */
    private function build_rule_context(string $ip): \WebDecoy\Rules\RuleContext
    {
        $method = isset($_SERVER['REQUEST_METHOD'])
            ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD']))
            : 'GET';
        $userAgent = isset($_SERVER['HTTP_USER_AGENT'])
            ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT']))
            : '';

        // Headers rules may read: Cookie (wd_clearance — the token's base64url/JWT
        // characters pass through sanitize_text_field intact for forwarding) and
        // any header referenced via req.header("name"). We forward the full request
        // header set for the latter, plus the sanitized cookie header.
        $headers = $this->collect_request_headers();
        if (isset($_SERVER['HTTP_COOKIE'])) {
            $headers['cookie'] = sanitize_text_field(wp_unslash($_SERVER['HTTP_COOKIE']));
        }

        // Fetch IP enrichment only when a filter rule needs it (premium only).
        $enrichment = null;
        if ($this->rules_need_enrichment && $this->is_premium()) {
            $enricher = new WebDecoy_IP_Enrichment((string) $this->options['api_key']);
            $enrichment = $enricher->enrich($ip);
        }

        return new \WebDecoy\Rules\RuleContext(
            $ip,
            $this->get_request_path(),
            $method,
            $userAgent,
            $headers,
            null,
            $enrichment
        );
    }

    /**
     * Collect request headers as a lowercased-key map for filter rules'
     * req.header("name") lookups. Derived from $_SERVER HTTP_* entries.
     *
     * @return array<string,string>
     */
    private function collect_request_headers(): array
    {
        $headers = [];
        foreach ($_SERVER as $key => $value) {
            if (strpos((string) $key, 'HTTP_') !== 0) {
                continue;
            }
            // HTTP_X_REQUESTED_WITH -> x-requested-with
            $name = strtolower(str_replace('_', '-', substr((string) $key, 5)));
            $headers[$name] = sanitize_text_field((string) wp_unslash($value));
        }
        return $headers;
    }

    /**
     * Act on a non-ALLOW rule-engine decision: DENY blocks, THROTTLE serves 429.
     *
     * @param \WebDecoy\Rules\RuleEngineResult $result
     * @param string $ip
     */
    /**
     * The configured block duration in hours, or null for permanent.
     */
    private function block_duration(): ?int
    {
        $hours = (int) ($this->options['block_duration'] ?? 1);
        return $hours > 0 ? $hours : null;
    }

    /**
     * The single gate every automatic block passes through.
     *
     * Returns false — and blocks nothing — whenever enforcement is suppressed, so the
     * caller can skip serving a 403 too. Manual blocks from the admin UI deliberately
     * do NOT come through here: a human typing an address has already decided.
     *
     * @return bool True when the block was actually written.
     */
    private function enforce_block(string $ip, string $reason, ?int $duration = null): bool
    {
        $suppression = $this->suppression_reason();
        if ($suppression !== '') {
            do_action('webdecoy_enforcement_suppressed', $ip, $suppression, null);
            $this->record_suppressed_action($suppression, $reason);
            return false;
        }

        $blocker = new WebDecoy_Blocker();
        return $blocker->block($ip, $reason, $duration ?? $this->block_duration());
    }

    /**
     * Count what enforcement would have done, so monitor mode produces a number
     * rather than silence. Kept as a bounded option — no new table, no per-request
     * write beyond a single non-autoloaded counter.
     */
    private function record_suppressed_action(string $suppression, string $reason): void
    {
        $stats = get_option('webdecoy_suppressed_actions', []);
        if (!is_array($stats)) {
            $stats = [];
        }
        $day = gmdate('Y-m-d');
        if (!isset($stats[$day])) {
            $stats[$day] = ['count' => 0, 'by' => []];
        }
        $stats[$day]['count']++;
        $key = substr($reason, 0, 80);
        $stats[$day]['by'][$key] = ($stats[$day]['by'][$key] ?? 0) + 1;
        if (count($stats[$day]['by']) > 25) {
            arsort($stats[$day]['by']);
            $stats[$day]['by'] = array_slice($stats[$day]['by'], 0, 25, true);
        }
        // Keep 30 days.
        if (count($stats) > 30) {
            ksort($stats);
            $stats = array_slice($stats, -30, null, true);
        }
        update_option('webdecoy_suppressed_actions', $stats, false);
        unset($suppression);
    }

    private function handle_rule_decision(\WebDecoy\Rules\RuleEngineResult $result, string $ip): void
    {
        // Monitor mode, the kill switch, or an unconfigured proxy: the violation has
        // already been logged and reported by the caller. Take no action on the
        // request itself. This is the single gate for every enforcement path below —
        // 429, deceptive response, local IP block and 403 alike.
        $suppression = $this->suppression_reason();
        if ($suppression !== '') {
            /**
             * Fires when enforcement was withheld for a request that would otherwise
             * have been acted on. The counterfactual, for the Detections page.
             *
             * @param string $ip
             * @param string $suppression One of 'disabled', 'monitor', 'proxy'.
             * @param \WebDecoy\Rules\RuleEngineResult $result
             */
            do_action('webdecoy_enforcement_suppressed', $ip, $suppression, $result);
            // THROTTLE is counted too: rate limiting is the action most likely to meet
            // real traffic, so omitting it made the number the owner decides on
            // meaningless — "no request has met the bar" while everything was being
            // throttled. Keyed on the RULE NAME, not the reason, because a throttle
            // reason embeds the request counter and would mint a fresh breakdown key
            // per request. A throttled request already writes webdecoy_rate_limits and
            // inserts a detections row, so this adds no new order of cost.
            $this->record_suppressed_action(
                $suppression,
                $result->action === \WebDecoy\Rules\RuleResult::THROTTLE
                    ? ('Throttled: ' . ($result->rule ?? 'rate-limit'))
                    : ($result->reason ?? ('Rule enforced: ' . ($result->rule ?? 'rule')))
            );
            return;
        }

        if ($result->action === \WebDecoy\Rules\RuleResult::THROTTLE) {
            $meta = is_array($result->metadata) ? $result->metadata : [];
            $retryAfter = isset($meta['retryAfter']) ? max(1, intval($meta['retryAfter'])) : 60;
            nocache_headers();
            status_header(429);
            header('Retry-After: ' . $retryAfter);
            if (isset($meta['max'])) {
                header('X-RateLimit-Limit: ' . (int) $meta['max']);
                header('X-RateLimit-Remaining: ' . (int) ($meta['remaining'] ?? 0));
                if (isset($meta['resetAt'])) {
                    header('X-RateLimit-Reset: ' . (int) $meta['resetAt']);
                }
            }
            wp_die(
                esc_html__('Too many requests. Please try again later.', 'webdecoy'),
                esc_html__('Too Many Requests', 'webdecoy'),
                ['response' => 429]
            );
            return;
        }

        // Tripwire DENY with a deceptive response configured: serve fake content
        // / 404 / tarpit instead of a plain 403. We deliberately do NOT locally
        // block the IP in these modes — letting the scanner keep digging decoys
        // gathers more evidence (each hit another reported violation), while
        // edge enforcement still happens via the reported clearance token.
        if ($result->rule === 'tripwire') {
            $mode = $this->options['tripwire_response'] ?? 'block';

            // log — record and do nothing. The caller has already written the
            // violation and reported it, so there is nothing left to do here.
            //
            // Note this is NOT the same as the `tripwire_dry_run` setting, which is
            // handled inside the rule and collapses the result to ALLOW at
            // sdk/src/Rules/TripwireRule.php:139 — before RuleEngine gets a chance to
            // record it. Dry run is therefore silent; this is observable.
            if ($mode === 'log') {
                return;
            }

            // challenge — serve the proof-of-work interstitial rather than a 403 and
            // a block. The middle option for an operator who wants the tripwire armed
            // but is not ready to hard-block on it.
            //
            // Understand what this does to a non-browser client: the challenge needs
            // JavaScript AND a human click (public/js/webdecoy-challenge.js binds
            // startChallenge to a click on #challengeBox), so nothing automated can
            // ever complete it. On a tripwire that is the intent — the path requested
            // exists nowhere on the site and is reachable only from a hidden element
            // or a robots.txt disallow, so a well-behaved crawler never asks for it.
            // It is still a denial for any non-JS caller, which is why `block`
            // remains the default rather than this.
            if ($mode === 'challenge') {
                if ($this->is_challenge_verified($ip)) {
                    return;
                }
                $this->serve_challenge_page($ip);
                return;
            }

            if ($mode !== 'block') {
                $path = (is_array($result->metadata) && isset($result->metadata['path'])) ? (string) $result->metadata['path'] : '';
                $decoy = new WebDecoy_Decoy_Response();
                if ($mode === 'decoy') {
                    $served = $decoy->served_canaries($path);
                    if ($served !== []) {
                        $this->log_decoy_served($path, $ip, $served);
                    }
                }
                if ($decoy->serve($path, $mode)) {
                    return; // deceptive response served + exited
                }
                // No believable template for this path — fall through to 403.
            }
        }

        // DENY: record the block, then serve the block page / wp_die.
        $blocker = new WebDecoy_Blocker();
        $duration = $this->options['block_duration'] > 0 ? $this->options['block_duration'] : null;
        $reason = $result->reason ?? ('Rule enforced: ' . ($result->rule ?? 'rule'));
        $blocker->block($ip, $reason, $duration);
        $this->block_request($this->options['block_page_message']);
    }

    /**
     * Record that a decoy (with canary credentials) was served, so the audit
     * trail shows what was handed out. The full canary values are recomputable,
     * so we store only the identifying markers here.
     *
     * @param array<string,string> $canaries
     */
    private function log_decoy_served(string $path, string $ip, array $canaries): void
    {
        global $wpdb;

        $flags_data = [
            'flags' => ['decoy_served'],
            'metadata' => [
                'rule' => 'tripwire',
                'decoy_path' => $path,
                'canary_db_user' => $canaries['db_user'] ?? '',
                'canary_admin_user' => $canaries['admin_user'] ?? '',
            ],
        ];

        $wpdb->insert($wpdb->prefix . 'webdecoy_detections', [
            'ip_address' => $ip,
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '',
            'score' => 100,
            'threat_level' => \WebDecoy\DetectionResult::THREAT_HIGH,
            'source' => 'wordpress_plugin',
            'flags' => wp_json_encode($flags_data),
            'created_at' => gmdate('Y-m-d H:i:s'),
        ]);
    }

    /**
     * Record rule-engine violations in the local detections table so they show
     * in the Detections admin page — including dry-run hits and installs with no
     * API key. One row per recorded violation.
     *
     * @param \WebDecoy\Rules\ViolationEvent[] $violations
     */
    private function log_rule_violations(array $violations): void
    {
        global $wpdb;

        // No emails on trap hits, deliberately (2.7.0 shipped one; 2.7.1
        // removed it by owner direction). The honeytoken is linked from every
        // public page, so crawlers find it constantly — an email per trip is
        // a metronome, not an alert. Detections are a dashboard surface.
        foreach ($violations as $violation) {
            $confidence = 100;
            if (is_array($violation->metadata) && isset($violation->metadata['confidence'])) {
                $confidence = intval($violation->metadata['confidence']);
            }

            $flags_data = [
                'flags' => [$violation->rule . '_rule'],
                'metadata' => array_merge(
                    is_array($violation->metadata) ? $violation->metadata : [],
                    [
                        'rule' => $violation->rule,
                        'rule_enforced' => !$violation->dryRun,
                        'dry_run' => $violation->dryRun,
                        'reason' => $violation->reason,
                    ]
                ),
            ];

            $wpdb->insert($wpdb->prefix . 'webdecoy_detections', [
                'ip_address' => $violation->ip,
                'user_agent' => $violation->userAgent ?? '',
                'score' => $confidence,
                'threat_level' => \WebDecoy\DetectionResult::THREAT_HIGH,
                'source' => 'wordpress_plugin',
                'flags' => wp_json_encode($flags_data),
                'created_at' => gmdate('Y-m-d H:i:s'),
            ]);
        }
    }

    /**
     * Get the current request path for detection
     *
     * @return string
     */
    private function get_request_path(): string
    {
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized with sanitize_text_field below
        $request_uri = isset($_SERVER['REQUEST_URI']) ? wp_unslash($_SERVER['REQUEST_URI']) : '/';
        return sanitize_text_field($request_uri);
    }

    /**
     * Handle blocking based on the configured action (block, challenge, or log)
     *
     * @param \WebDecoy\DetectionResult $result
     * @param string $ip
     */
    private function handle_blocking(\WebDecoy\DetectionResult $result, string $ip): void
    {
        $action = $this->options['block_action'] ?? 'block';

        if ($action === 'log') {
            return;
        }

        if ($action === 'challenge') {
            // Check if already verified via cookie
            if ($this->is_challenge_verified($ip)) {
                return;
            }

            // The challenge page is a 403 with an interstitial. It is enforcement, so
            // it passes the same gate as a block. Checked AFTER the verified-cookie
            // test so a visitor who already solved it is not counted as withheld.
            $suppression = $this->suppression_reason();
            if ($suppression !== '') {
                do_action('webdecoy_enforcement_suppressed', $ip, $suppression, null);
                $this->record_suppressed_action(
                    $suppression,
                    'Challenge (score: ' . $result->getScore() . ')'
                );
                return;
            }

            // Serve challenge page
            $this->serve_challenge_page($ip);
            return;
        }

        // Default action: block
        if ($this->enforce_block($ip, 'Bot detection score: ' . $result->getScore())) {
            $this->block_request($this->options['block_page_message']);
        }
    }

    /**
     * Check if an IP has been verified via challenge
     *
     * @param string $ip
     * @return bool
     */
    private function is_challenge_verified(string $ip): bool
    {
        $cookie = isset($_COOKIE['webdecoy_verified']) ? sanitize_text_field(wp_unslash($_COOKIE['webdecoy_verified'])) : '';
        if (empty($cookie)) {
            return false;
        }

        $stored = get_transient('webdecoy_verified_' . md5($ip));
        return $stored !== false && hash_equals($stored, $cookie);
    }

    /**
     * Serve the challenge page
     *
     * @param string $ip
     */
    private function serve_challenge_page(string $ip): void
    {
        nocache_headers();
        status_header(403);

        $pow = new WebDecoy_PoW();
        $message = __('Please verify that you are human to continue.', 'webdecoy');
        $challenge_data = $pow->generate_challenge($ip, intval($this->options['pow_difficulty'] ?? 4));
        $redirect_url = $this->get_current_url();
        if (wp_parse_url($redirect_url, PHP_URL_HOST) !== wp_parse_url(home_url(), PHP_URL_HOST)) {
            $redirect_url = home_url('/');
        }
        $ajax_url = admin_url('admin-ajax.php');
        $nonce = wp_create_nonce('webdecoy_pow');

        include WEBDECOY_PLUGIN_DIR . 'templates/challenge-page.php';
        exit;
    }

    /**
     * Block a request
     *
     * @param string $message
     */
    private function block_request(string $message): void
    {
        // Send no-cache headers to prevent caching of block pages
        // This ensures unblocking takes effect immediately
        nocache_headers();
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        header('Expires: Thu, 01 Jan 1970 00:00:00 GMT');

        if ($this->options['show_block_page']) {
            status_header(403);
            include WEBDECOY_PLUGIN_DIR . 'templates/block-page.php';
            exit;
        } else {
            wp_die(esc_html($message), esc_html__('Access Denied', 'webdecoy'), ['response' => 403]);
        }
    }

    /**
     * Log detection locally
     *
     * @param \WebDecoy\DetectionResult $result
     * @param string $ip
     */
    private function log_detection(\WebDecoy\DetectionResult $result, string $ip): void
    {
        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_detections';

        // Build flags array including MITRE metadata
        $flags_data = [
            'flags' => $result->getFlags(),
            'metadata' => $result->getMetadata(),
        ];

        $wpdb->insert($table, [
            'ip_address' => $ip,
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '',
            'score' => $result->getScore(),
            'threat_level' => $result->getThreatLevel(),
            'source' => 'wordpress_plugin',
            'flags' => json_encode($flags_data),
            'created_at' => gmdate('Y-m-d H:i:s'),
        ]);

        $this->flag_critical_moment($ip, $result->getThreatLevel());
    }

    /**
     * Submit detection to WebDecoy API
     *
     * @param \WebDecoy\DetectionResult $result
     * @param string $ip
     */
    private function submit_detection(\WebDecoy\DetectionResult $result, string $ip): void
    {
        if (!$this->is_premium()) {
            return;
        }

        $client = $this->get_client();
        if (!$client) {
            return;
        }

        $detection = \WebDecoy\Detection::fromArray([
            'scanner_id' => $this->get_scanner_id(),
            'ip_address' => $ip,
            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Used for logging only
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '',
            'url' => $this->get_current_url(),
            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Used for logging only
            'referer' => isset($_SERVER['HTTP_REFERER']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_REFERER'])) : null,
            'client_score' => $result->getScore(),
            'flags' => $result->getFlags(),
            'fingerprint' => $this->get_detector()->getSignalCollector()->buildFingerprint(),
            'source' => 'wordpress_plugin',
            'metadata' => $result->getMetadata(),
        ]);

        $client->submitDetection($detection);
    }

    /**
     * Whether this request carries the reserved test User-Agent
     * (prefix "WebDecoy-Test/", case-insensitive). See WebDecoy/app#677.
     */
    private function is_test_trigger_request(): bool
    {
        if (!isset($_SERVER['HTTP_USER_AGENT'])) {
            return false;
        }
        $ua = ltrim(sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])));
        return stripos($ua, 'WebDecoy-Test/') === 0;
    }

    /**
     * Record the reserved test detection and answer with an unambiguous
     * receipt (WebDecoy/app#677).
     *
     * Logs locally always, submits to the cloud when connected — the same two
     * paths a real detection takes — then responds 403 so the curl output
     * itself shows the plugin acted. Never blocks the IP, never trips rules:
     * a test must have no consequences beyond its own row.
     *
     * @param string $ip
     */
    private function handle_test_trigger(string $ip): void
    {
        global $wpdb;

        $result = new \WebDecoy\DetectionResult(100, ['test_trigger']);

        // Local log, inlined rather than via log_detection(): that path also
        // queues the critical-moment alert for CRITICAL rows, and a test must
        // not page anyone.
        $wpdb->insert($wpdb->prefix . 'webdecoy_detections', [
            'ip_address' => $ip,
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '',
            'score' => $result->getScore(),
            'threat_level' => $result->getThreatLevel(),
            'source' => 'wordpress_plugin',
            'flags' => json_encode(['flags' => $result->getFlags(), 'metadata' => ['test' => true]]),
            'created_at' => gmdate('Y-m-d H:i:s'),
        ]);

        try {
            $this->submit_detection($result, $ip);
        } catch (\Exception $e) {
            error_log('WebDecoy API error: ' . $e->getMessage());
        }

        nocache_headers();
        status_header(403);
        header('Content-Type: application/json; charset=utf-8');
        echo wp_json_encode([
            'webdecoy_test' => true,
            'message'       => 'Test detection recorded. Check your WebDecoy dashboard.',
        ]);
        exit;
    }

    /**
     * Check comment submission
     *
     * @param int $comment_post_id
     */
    public function check_comment(int $comment_post_id): void
    {
        $this->check_honeypot('comment');
    }

    /**
     * Filter comment data
     *
     * @param array $commentdata
     * @return array
     */
    public function filter_comment(array $commentdata): array
    {
        $detector = $this->get_detector();
        $result = $detector->analyze();

        if ($result->shouldBlock($this->options['min_score_to_block'])) {
            // Reachable at default sensitivity and serves a literal 403 — same gate.
            $suppression = $this->suppression_reason();
            if ($suppression === '') {
                wp_die(
                    esc_html__('Your comment has been blocked due to suspicious activity.', 'webdecoy'),
                    esc_html__('Comment Blocked', 'webdecoy'),
                    ['response' => 403, 'back_link' => true]
                );
            }
            $this->record_suppressed_action($suppression, 'Comment refused: score ' . $result->getScore());
        }

        return $commentdata;
    }

    /**
     * Detect a login attempt using a canary credential — a fake value that could
     * only have come from a decoy response we served. That's unambiguous
     * exfiltration evidence: log a high-severity detection, block the IP, and
     * reject the login.
     *
     * @param \WP_User|\WP_Error|null $user
     * @param string $username
     * @param string $password
     * @return \WP_User|\WP_Error|null
     */
    public function check_canary_login($user, string $username, string $password)
    {
        // The kill switch has to be unconditional to be a kill switch. A canary hit is
        // zero-false-positive evidence, so it is still refused in monitor mode — but
        // never when the owner has explicitly turned the plugin off in wp-config.php.
        if (defined('WEBDECOY_DISABLE') && WEBDECOY_DISABLE) {
            return $user;
        }

        if ($username === '' && $password === '') {
            return $user;
        }

        if (
            WebDecoy_Decoy_Response::is_canary_credential($username)
            || WebDecoy_Decoy_Response::is_canary_credential($password)
        ) {
            $ip = $this->get_client_ip();

            global $wpdb;
            $wpdb->insert($wpdb->prefix . 'webdecoy_detections', [
                'ip_address' => $ip,
                'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '',
                'score' => 100,
                'threat_level' => \WebDecoy\DetectionResult::THREAT_CRITICAL,
                'source' => 'wordpress_plugin',
                'flags' => wp_json_encode([
                    'flags' => ['canary_credential_use'],
                    'metadata' => ['reason' => 'Login attempt with a decoy (canary) credential'],
                ]),
                'created_at' => gmdate('Y-m-d H:i:s'),
            ]);

            // Confirmed decoy exfiltration is always CRITICAL — surface the moment.
            $this->flag_critical_moment($ip, \WebDecoy\DetectionResult::THREAT_CRITICAL);

            $this->enforce_block($ip, 'Canary credential use (decoy exfiltration)');

            return new \WP_Error(
                'webdecoy_canary',
                __('Access denied.', 'webdecoy')
            );
        }

        return $user;
    }

    /**
     * Check login attempt
     *
     * @param \WP_User|\WP_Error|null $user
     * @param string $username
     * @param string $password
     * @return \WP_User|\WP_Error|null
     */
    public function check_login($user, string $username, string $password)
    {
        // Skip if already error
        if (is_wp_error($user)) {
            return $user;
        }

        $this->check_honeypot('login');

        $detector = $this->get_detector();
        $result = $detector->analyze();

        if ($result->shouldBlock($this->options['min_score_to_block'])) {
            // Refusing a login is enforcement, and it is the one refusal a locked-out
            // owner cannot work around — so it must honour WEBDECOY_DISABLE and
            // monitor mode like every other action.
            $suppression = $this->suppression_reason();
            if ($suppression !== '') {
                $this->record_suppressed_action($suppression, 'Login refused: score ' . $result->getScore());
                return $user;
            }
            return new \WP_Error(
                'webdecoy_blocked',
                __('Login blocked due to suspicious activity.', 'webdecoy')
            );
        }

        return $user;
    }

    /**
     * Check registration attempt
     *
     * @param string $sanitized_user_login
     * @param string $user_email
     * @param \WP_Error $errors
     */
    public function check_registration(string $sanitized_user_login, string $user_email, \WP_Error $errors): void
    {
        $this->check_honeypot('register');

        $detector = $this->get_detector();
        $result = $detector->analyze();

        if ($result->shouldBlock($this->options['min_score_to_block'])) {
            $suppression = $this->suppression_reason();
            if ($suppression !== '') {
                $this->record_suppressed_action($suppression, 'Registration refused: score ' . $result->getScore());
                return;
            }
            $errors->add(
                'webdecoy_blocked',
                __('Registration blocked due to suspicious activity.', 'webdecoy')
            );
        }
    }

    /**
     * Check WooCommerce checkout
     */
    public function check_checkout(): void
    {
        if (!class_exists('WebDecoy_WooCommerce')) {
            return;
        }

        $woo = new WebDecoy_WooCommerce($this->options);
        $woo->check_checkout();
    }

    /**
     * Track successful payment
     *
     * @param int $order_id
     */
    public function track_payment(int $order_id): void
    {
        if (!class_exists('WebDecoy_WooCommerce')) {
            return;
        }

        $woo = new WebDecoy_WooCommerce($this->options);
        $woo->track_payment($order_id);
    }

    /**
     * Track checkout attempt
     *
     * @param int $order_id
     */
    public function track_checkout_attempt(int $order_id): void
    {
        if (!class_exists('WebDecoy_WooCommerce')) {
            return;
        }

        $woo = new WebDecoy_WooCommerce($this->options);
        $woo->track_attempt($order_id);
    }

    /**
     * Check honeypot field
     *
     * @param string $context
     */
    private function check_honeypot(string $context): void
    {
        $honeypot_name = 'webdecoy_hp_' . $context;

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- honeypot detection: any submitted value is treated as a bot signal, so nonce verification is not applicable
        if (isset($_POST[$honeypot_name]) && !empty($_POST[$honeypot_name])) {
            // Honeypot triggered - definitely a bot
            $ip = $this->get_client_ip();
            // Previously passed no duration at all, which meant a permanent block.
            if ($this->enforce_block($ip, 'Honeypot triggered: ' . $context)) {
                $this->block_request(__('Suspicious activity detected.', 'webdecoy'));
            }
        }
    }

    /**
     * Inject honeypot into comment form
     */
    public function inject_comment_honeypot(): void
    {
        $this->output_honeypot_field('comment');
    }

    /**
     * Inject honeypot into login form
     */
    public function inject_login_honeypot(): void
    {
        $this->output_honeypot_field('login');
    }

    /**
     * Inject honeypot into registration form
     */
    public function inject_register_honeypot(): void
    {
        $this->output_honeypot_field('register');
    }

    /**
     * Output honeypot field HTML
     *
     * @param string $context
     */
    private function output_honeypot_field(string $context): void
    {
        $name = 'webdecoy_hp_' . $context;
        echo '<div style="position:absolute;left:-9999px;top:-9999px;"><label for="' . esc_attr($name) . '">' . esc_html__('Leave empty', 'webdecoy') . '</label><input type="text" name="' . esc_attr($name) . '" id="' . esc_attr($name) . '" value="" tabindex="-1" autocomplete="off"></div>';
    }

    /**
     * Add admin menu
     */
    public function admin_menu(): void
    {
        add_menu_page(
            __('WebDecoy', 'webdecoy'),
            __('WebDecoy', 'webdecoy'),
            'manage_options',
            'webdecoy',
            [$this, 'settings_page'],
            'dashicons-shield',
            80
        );

        add_submenu_page(
            'webdecoy',
            __('Settings', 'webdecoy'),
            __('Settings', 'webdecoy'),
            'manage_options',
            'webdecoy',
            [$this, 'settings_page']
        );

        add_submenu_page(
            'webdecoy',
            __('Statistics', 'webdecoy'),
            __('Statistics', 'webdecoy'),
            'manage_options',
            'webdecoy-statistics',
            [$this, 'statistics_page']
        );

        add_submenu_page(
            'webdecoy',
            __('Blocked IPs', 'webdecoy'),
            __('Blocked IPs', 'webdecoy'),
            'manage_options',
            'webdecoy-blocked',
            [$this, 'blocked_ips_page']
        );

        add_submenu_page(
            'webdecoy',
            __('Detections', 'webdecoy'),
            __('Detections', 'webdecoy'),
            'manage_options',
            'webdecoy-detections',
            [$this, 'detections_page']
        );
    }

    /**
     * Register settings
     */
    public function register_settings(): void
    {
        register_setting('webdecoy_options', 'webdecoy_options', [
            'sanitize_callback' => [$this, 'sanitize_options'],
        ]);
    }

    /**
     * Sanitize options
     *
     * @param array $input
     * @return array
     */
    public function sanitize_options(array $input): array
    {
        $sanitized = [];

        // API Configuration - encrypt the API key for storage
        $api_key = sanitize_text_field($input['api_key'] ?? '');
        if (!empty($api_key) && !$this->is_encrypted($api_key)) {
            // Only encrypt if it's a new plaintext key
            $sanitized['api_key'] = $this->encrypt_value($api_key);
        } else {
            // Already encrypted or empty - keep as is
            $sanitized['api_key'] = $api_key;
        }

        // Publishable site key + clearance scope (not secret; stored as-is).
        $sanitized['site_key'] = sanitize_text_field($input['site_key'] ?? '');
        $sanitized['clearance_scope'] = sanitize_text_field($input['clearance_scope'] ?? '');

        // Cloud connection metadata is owned by the connect flow, not this form.
        // Carry the stored values forward so saving settings never wipes them.
        $existing = get_option('webdecoy_options', []);
        foreach (['organization_id', 'organization_name', 'plan'] as $connect_key) {
            if (is_array($existing) && isset($existing[$connect_key])) {
                $sanitized[$connect_key] = sanitize_text_field((string) $existing[$connect_key]);
            }
        }

        // Proxy / client IP resolution
        $sanitized['behind_cloudflare'] = !empty($input['behind_cloudflare']);
        $sanitized['trusted_proxies'] = $this->sanitize_trusted_proxies($input['trusted_proxies'] ?? '');

        // Detection Settings
        $sanitized['enabled'] = !empty($input['enabled']);
        $sanitized['sensitivity'] = in_array($input['sensitivity'] ?? 'medium', ['low', 'medium', 'high']) ? $input['sensitivity'] : 'medium';
        $sanitized['min_score_to_block'] = max(0, min(100, intval($input['min_score_to_block'] ?? 75)));
        $sanitized['min_threat_level'] = in_array($input['min_threat_level'] ?? 'HIGH', ['MINIMAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']) ? $input['min_threat_level'] : 'HIGH';

        // Good Bot Handling
        $sanitized['allow_search_engines'] = !empty($input['allow_search_engines']);
        $sanitized['allow_social_bots'] = !empty($input['allow_social_bots']);
        $sanitized['block_ai_crawlers'] = !empty($input['block_ai_crawlers']);
        $sanitized['custom_allowlist'] = array_filter(array_map('sanitize_text_field', explode("\n", $input['custom_allowlist'] ?? '')));

        // Blocking Settings
        // Allowlist: validate as IPs/CIDRs (reuses the trusted-proxy validator),
        // stored as an array of valid entries.
        $allowlist = $this->sanitize_trusted_proxies($input['ip_allowlist'] ?? '');
        $sanitized['ip_allowlist'] = $allowlist === '' ? [] : explode("\n", $allowlist);
        if (WebDecoy_Runtime_Config::forced_monitor_mode() !== null) {
            // The mode is forced by WEBDECOY_DEFAULT_MODE and its checkbox is
            // disabled, so the form never posts it. Carry the STORED value
            // forward rather than reading the absent field as false: otherwise
            // every settings save silently drifts the stored mode to
            // 'blocking', which detonates the day the constant is removed.
            $stored = get_option('webdecoy_options', []);
            $sanitized['monitor_mode'] = !empty(is_array($stored) ? ($stored['monitor_mode'] ?? true) : true);
        } else {
            $sanitized['monitor_mode'] = !empty($input['monitor_mode']);
        }
        $sanitized['block_action'] = in_array($input['block_action'] ?? 'block', ['block', 'challenge', 'log']) ? $input['block_action'] : 'block';
        $sanitized['block_duration'] = max(0, intval($input['block_duration'] ?? 1));
        $sanitized['show_block_page'] = !empty($input['show_block_page']);
        $sanitized['block_page_message'] = sanitize_textarea_field($input['block_page_message'] ?? '');

        // Rate Limiting
        $sanitized['rate_limit_enabled'] = !empty($input['rate_limit_enabled']);
        $sanitized['rate_limit_requests'] = max(1, intval($input['rate_limit_requests'] ?? 60));
        $sanitized['rate_limit_window'] = max(1, intval($input['rate_limit_window'] ?? 60));
        $sanitized['rate_limit_algorithm'] = in_array($input['rate_limit_algorithm'] ?? 'fixed', ['fixed', 'sliding'], true) ? $input['rate_limit_algorithm'] : 'fixed';
        $sanitized['rate_limit_key'] = in_array($input['rate_limit_key'] ?? 'ip', ['ip', 'ip_route', 'user'], true) ? $input['rate_limit_key'] : 'ip';
        $sanitized['rate_limit_dry_run'] = !empty($input['rate_limit_dry_run']);

        // Tripwires
        $sanitized['tripwire_enabled'] = !empty($input['tripwire_enabled']);
        $sanitized['tripwire_include_defaults'] = !empty($input['tripwire_include_defaults']);
        $sanitized['tripwire_paths'] = $this->sanitize_path_list($input['tripwire_paths'] ?? '');
        $sanitized['tripwire_prefixes'] = $this->sanitize_path_list($input['tripwire_prefixes'] ?? '');
        $sanitized['tripwire_patterns'] = $this->sanitize_pattern_list($input['tripwire_patterns'] ?? '');
        $sanitized['tripwire_action'] = in_array($input['tripwire_action'] ?? 'block', ['block', 'throttle'], true) ? $input['tripwire_action'] : 'block';
        $sanitized['tripwire_dry_run'] = !empty($input['tripwire_dry_run']);
        // Kept in step with block_action above, which has always accepted challenge
        // and log. The deterministic path had the harsher options and none of the
        // gentler ones, which was backwards. Refs #53.
        $sanitized['tripwire_response'] = in_array($input['tripwire_response'] ?? 'block', ['block', 'challenge', 'log', 'notfound', 'decoy', 'tarpit'], true) ? $input['tripwire_response'] : 'block';
        $sanitized['honeytoken_enabled'] = !empty($input['honeytoken_enabled']);
        $sanitized['honeytoken_rotate'] = !empty($input['honeytoken_rotate']);
        $sanitized['traps_fake_plugins'] = !empty($input['traps_fake_plugins']);
        $sanitized['traps_xmlrpc'] = !empty($input['traps_xmlrpc']);
        $sanitized['traps_author_enum'] = !empty($input['traps_author_enum']);
        $sanitized['filter_rules'] = $this->sanitize_filter_rules($input['filter_rules'] ?? []);

        // Form Protection
        $sanitized['protect_comments'] = !empty($input['protect_comments']);
        $sanitized['protect_login'] = !empty($input['protect_login']);
        $sanitized['protect_registration'] = !empty($input['protect_registration']);
        $sanitized['inject_honeypot'] = !empty($input['inject_honeypot']);

        // Client-Side Scanner
        $sanitized['scanner_enabled'] = !empty($input['scanner_enabled']);
        $sanitized['scanner_min_score'] = max(0, min(100, intval($input['scanner_min_score'] ?? 20)));
        $sanitized['scanner_on_all_pages'] = !empty($input['scanner_on_all_pages']);
        $sanitized['scanner_exclude_logged_in'] = !empty($input['scanner_exclude_logged_in']);

        // WooCommerce
        $sanitized['protect_checkout'] = !empty($input['protect_checkout']);
        $sanitized['checkout_velocity_limit'] = max(1, intval($input['checkout_velocity_limit'] ?? 5));
        $sanitized['checkout_velocity_window'] = max(60, intval($input['checkout_velocity_window'] ?? 3600));
        $sanitized['woo_honeytoken_coupons'] = !empty($input['woo_honeytoken_coupons']);

        // Proof-of-Work
        $sanitized['pow_enabled'] = !empty($input['pow_enabled']);
        $sanitized['pow_difficulty'] = max(2, min(7, intval($input['pow_difficulty'] ?? 4)));
        $sanitized['challenge_duration'] = max(5, min(60, intval($input['challenge_duration'] ?? 15)));
        $sanitized['challenge_show_credit'] = !empty($input['challenge_show_credit']);

        return $sanitized;
    }

    /**
     * Settings page
     */
    public function settings_page(): void
    {
        include WEBDECOY_PLUGIN_DIR . 'admin/partials/settings-page.php';
    }

    /**
     * Statistics page
     */
    public function statistics_page(): void
    {
        include WEBDECOY_PLUGIN_DIR . 'admin/partials/statistics-page.php';
    }

    /**
     * Blocked IPs page
     */
    public function blocked_ips_page(): void
    {
        include WEBDECOY_PLUGIN_DIR . 'admin/partials/blocked-ips-page.php';
    }

    /**
     * Detections page
     */
    public function detections_page(): void
    {
        include WEBDECOY_PLUGIN_DIR . 'admin/partials/detections-page.php';
    }

    /**
     * Add dashboard widget
     */
    public function dashboard_widget(): void
    {
        wp_add_dashboard_widget(
            'webdecoy_dashboard_widget',
            __('WebDecoy - Threat Overview', 'webdecoy'),
            [$this, 'render_dashboard_widget']
        );
    }

    /**
     * Render dashboard widget
     */
    public function render_dashboard_widget(): void
    {
        include WEBDECOY_PLUGIN_DIR . 'admin/partials/dashboard-widget.php';
    }

    /**
     * Enqueue admin scripts
     *
     * @param string $hook
     */
    public function admin_scripts(string $hook): void
    {
        if (strpos($hook, 'webdecoy') === false && $hook !== 'index.php') {
            return;
        }

        wp_enqueue_style(
            'webdecoy-admin',
            WEBDECOY_PLUGIN_URL . 'admin/css/webdecoy-admin.css',
            [],
            WEBDECOY_VERSION
        );

        wp_enqueue_script(
            'webdecoy-admin',
            WEBDECOY_PLUGIN_URL . 'admin/js/webdecoy-admin.js',
            ['jquery'],
            WEBDECOY_VERSION,
            true
        );

        wp_localize_script('webdecoy-admin', 'webdecoyAdmin', [
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('webdecoy_admin'),
            'strings' => [
                'testing' => __('Testing connection...', 'webdecoy'),
                'testSuccess' => __('Connection successful!', 'webdecoy'),
                'testFailed' => __('Connection failed:', 'webdecoy'),
                'connectionFailed' => __('Connection failed', 'webdecoy'),
                /* translators: %s: IP address to block */
                'confirmBlock' => __('Are you sure you want to block %s?', 'webdecoy'),
                'confirmUnblock' => __('Are you sure you want to unblock this IP?', 'webdecoy'),
                /* translators: %d: number of IP addresses to block */
                'confirmBulkBlock' => __('Are you sure you want to block %d IPs?', 'webdecoy'),
                'selectIPs' => __('Please select at least one IP to block.', 'webdecoy'),
                'toggleVisibility' => __('Toggle visibility', 'webdecoy'),
                'error' => __('An error occurred. Please try again.', 'webdecoy'),
            ],
        ]);

        // Load Chart.js and charts script on statistics page
        if ($hook === 'webdecoy_page_webdecoy-statistics') {
            // Chart.js is bundled locally (admin/js/vendor/) rather than loaded
            // from a CDN, so the plugin makes no external requests.
            wp_enqueue_script(
                'chartjs',
                WEBDECOY_PLUGIN_URL . 'admin/js/vendor/chart.umd.min.js',
                [],
                '4.5.1',
                true
            );

            wp_enqueue_script(
                'webdecoy-charts',
                WEBDECOY_PLUGIN_URL . 'admin/js/webdecoy-charts.js',
                ['chartjs'],
                WEBDECOY_VERSION,
                true
            );
        }
    }

    /**
     * Enqueue frontend scanner script
     */
    public function frontend_scripts(): void
    {
        if (!$this->options['scanner_enabled']) {
            return;
        }

        // Skip for logged-in users if configured
        if ($this->options['scanner_exclude_logged_in'] && is_user_logged_in()) {
            return;
        }

        wp_enqueue_script(
            'webdecoy-scanner',
            WEBDECOY_PLUGIN_URL . 'public/js/webdecoy-scanner.js',
            [],
            WEBDECOY_VERSION,
            true
        );

        wp_localize_script('webdecoy-scanner', 'webdecoyScanner', [
            'enabled' => true,
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('webdecoy_scanner'),
            'minScore' => intval($this->options['scanner_min_score']),
            'powEnabled' => !empty($this->options['pow_enabled']),
            'challengeUrl' => admin_url('admin-ajax.php'),
        ]);
    }

    /**
     * Enqueue the bundled @webdecoy/client browser script, which silently mints
     * the wd_clearance cookie for real visitors. The script auto-starts from the
     * data-site-key attribute injected in {@see add_defer_to_scanner()}.
     *
     * Served from the plugin's own origin (not a CDN) per WordPress.org
     * guidelines. Minting is idle-deferred, once per session, and does no
     * proof-of-work, so there's no page-load cost.
     */
    public function enqueue_clearance_client(): void
    {
        if (empty($this->options['site_key'])) {
            return;
        }

        // The WordPress.org build (build.sh --org) omits the bundled client, so
        // no-op cleanly when the asset isn't present rather than enqueue a 404.
        if (!file_exists(WEBDECOY_PLUGIN_DIR . 'public/js/webdecoy-clearance.js')) {
            return;
        }

        // Skip for logged-in users if the scanner is configured to exclude them,
        // keeping behavior consistent across both front-end scripts.
        if (!empty($this->options['scanner_exclude_logged_in']) && is_user_logged_in()) {
            return;
        }

        wp_enqueue_script(
            'webdecoy-clearance',
            WEBDECOY_PLUGIN_URL . 'public/js/webdecoy-clearance.js',
            [],
            WEBDECOY_VERSION,
            true
        );
    }

    /**
     * Inject JS execution verification challenge token into the page head.
     * Generates a unique token per page view, embeds it as a meta tag, and
     * reports it to the ingest service. bot-detection-pro.js reads the meta tag
     * and beacons it back. If the beacon never arrives, the visitor is a non-JS scraper.
     */
    public function inject_js_verification_token(): void
    {
        // Skip for logged-in users if scanner excludes them
        if ($this->options['scanner_exclude_logged_in'] && is_user_logged_in()) {
            return;
        }

        // Generate a unique challenge token (32 bytes hex = 64 chars)
        $token = bin2hex(random_bytes(32));

        // Output the meta tag in <head>
        echo '<meta name="wd-ct" content="' . esc_attr($token) . '">' . "\n";

        // Report page serve to ingest service (fire-and-forget)
        $api_key = $this->options['api_key'];
        if (empty($api_key)) {
            return;
        }

        $collector = new \WebDecoy\SignalCollector($this->get_trusted_proxies());
        $ip = $collector->getIP();

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $domain = isset($_SERVER['HTTP_HOST']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_HOST'])) : '';

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $path = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';

        $payload = [
            'token'      => $token,
            'domain'     => $domain,
            'path'       => $path,
            'ip'         => $ip,
            'user_agent' => $user_agent,
        ];

        wp_remote_post('https://ingest.webdecoy.com/api/v1/page-serve', [
            'timeout'  => 1,
            'blocking' => false,
            'headers'  => [
                'Content-Type'  => 'application/json',
                'Authorization' => 'Bearer ' . $api_key,
            ],
            'body' => wp_json_encode($payload),
        ]);
    }

    /**
     * AJAX: Handle client-side detection
     * Receives detection from JavaScript scanner and forwards to WebDecoy ingest
     */
    public function ajax_client_detection(): void
    {
        // Verify nonce
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Nonce verification handles sanitization
        if (!isset($_POST['nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['nonce'])), 'webdecoy_scanner')) {
            wp_send_json_error(['message' => 'Invalid nonce'], 403);
            return;
        }

        // Get visitor IP first for rate limiting
        $collector = new \WebDecoy\SignalCollector($this->get_trusted_proxies());
        $ip = $collector->getIP();

        // Rate limit detection submissions (max 10 per minute per IP)
        if ($this->is_detection_rate_limited($ip)) {
            wp_send_json_error(['message' => 'Rate limited'], 429);
            return;
        }

        // Get detection data
        $detection_json = isset($_POST['detection']) ? sanitize_text_field(wp_unslash($_POST['detection'])) : '';
        $detection = json_decode($detection_json, true);

        if (!$detection || !is_array($detection)) {
            wp_send_json_error(['message' => 'Invalid detection data'], 400);
            return;
        }

        // Log detection locally
        $this->log_client_detection($detection, $ip);

        // Check if should block based on score and action setting
        $score = intval($detection['s'] ?? 0);
        $action = $this->options['block_action'] ?? 'block';

        if ($score >= $this->options['min_score_to_block'] && $action === 'block') {
            // Only block if action is set to 'block'
            $flags = implode(', ', $detection['f'] ?? []);
            $this->enforce_block($ip, "Client detection (score: {$score}): {$flags}");
        }

        // Forward to WebDecoy ingest service if premium
        if ($this->is_premium()) {
            $this->forward_to_ingest($detection, $ip);
        }

        wp_send_json_success(['received' => true]);
    }

    /**
     * Check if detection submissions are rate limited for an IP
     * Allows max 10 detections per minute per IP to prevent flooding
     *
     * @param string $ip Client IP address
     * @return bool True if rate limited
     */
    private function is_detection_rate_limited(string $ip): bool
    {
        $transient_key = 'webdecoy_detect_' . md5($ip);
        $count = get_transient($transient_key);

        if ($count === false) {
            // First request in this window
            set_transient($transient_key, 1, 60); // 60 second window
            return false;
        }

        if ($count >= 10) {
            // Rate limit exceeded
            return true;
        }

        // Increment counter
        set_transient($transient_key, $count + 1, 60);
        return false;
    }

    /**
     * Log client-side detection to local database
     */
    private function log_client_detection(array $detection, string $ip): void
    {
        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_detections';

        // This data comes from an unauthenticated (nopriv) AJAX endpoint, so clamp
        // and bound everything before storing: keep score in 0-100 and cap the
        // free-text fields so an attacker can't bloat the table with huge rows.
        $score = max(0, min(100, intval($detection['s'] ?? 0)));

        $user_agent = (string) ($detection['fp']['userAgent'] ?? '');
        if (strlen($user_agent) > 512) {
            $user_agent = substr($user_agent, 0, 512);
        }

        $flags_json = wp_json_encode($detection['f'] ?? []);
        if (!is_string($flags_json) || strlen($flags_json) > 2048) {
            $flags_json = is_string($flags_json) ? substr($flags_json, 0, 2048) : '[]';
        }

        // Determine threat level from score
        $threat_level = 'MINIMAL';
        if ($score >= 75) {
            $threat_level = 'CRITICAL';
        } elseif ($score >= 60) {
            $threat_level = 'HIGH';
        } elseif ($score >= 40) {
            $threat_level = 'MEDIUM';
        } elseif ($score >= 20) {
            $threat_level = 'LOW';
        }

        $wpdb->insert($table, [
            'ip_address' => $ip,
            'user_agent' => $user_agent,
            'score' => $score,
            'threat_level' => $threat_level,
            'source' => 'wordpress_plugin',
            'flags' => $flags_json,
            'created_at' => gmdate('Y-m-d H:i:s'),
        ]);

        $this->flag_critical_moment($ip, $threat_level);
    }

    /**
     * Forward detection to WebDecoy ingest service
     *
     * The ingest service authenticates via the API key in the Authorization header.
     * Organization ID and Property ID are looked up from the API key automatically.
     */
    private function forward_to_ingest(array $detection, string $ip): void
    {
        $ingest_url = 'https://ingest.webdecoy.com/api/v1/detect';

        // Get API key (decrypt if needed)
        $api_key = $this->options['api_key'];
        if (!empty($api_key) && $this->is_encrypted($api_key)) {
            $api_key = $this->decrypt_value($api_key);
        }

        if (empty($api_key)) {
            error_log('WebDecoy: Cannot forward to ingest - API key not configured');
            return;
        }

        // Build payload for ingest service
        // Note: aid is deprecated - org_id comes from API key authentication
        // sid is optional - just identifies this as a WordPress plugin
        $payload = [
            'sid' => $this->get_scanner_id(),
            'v' => 1,
            's' => $detection['s'] ?? 0,
            'f' => $detection['f'] ?? [],
            'fp' => $detection['fp'] ?? [],
            'url' => $detection['url'] ?? '',
            'ref' => $detection['ref'] ?? '',
            'ts' => $detection['ts'] ?? (time() * 1000),
            'ai' => $detection['ai'] ?? '',
            'hp' => $detection['hp'] ?? '',
            'timing' => $detection['timing'] ?? null,
            // Add server-side data
            'ip' => $ip,
            'source' => 'wordpress_plugin',
            // The visitor's own fingerprint material.
            //
            // This is a server-to-server beacon, so the ingest service sees THIS
            // site's outbound request headers on it, not the visitor's. It used
            // to identify visitors from those — identical on every beacon this
            // site sends — which collapsed every visitor we ever reported into a
            // single shared "actor". Header names only, plus Accept-Language and
            // Accept-Encoding; no header values otherwise, so nothing sensitive
            // leaves the site.
            'cs' => $this->build_client_signals(),
        ];

        // Send to ingest (fire-and-forget, don't block)
        // Authentication is via API key in Authorization header
        wp_remote_post($ingest_url, [
            'timeout' => 1,
            'blocking' => false,
            'headers' => [
                'Content-Type' => 'application/json',
                'Authorization' => 'Bearer ' . $api_key,
            ],
            'body' => json_encode($payload),
        ]);
    }

    /**
     * The visitor's fingerprint material for a forwarded detection (`cs`).
     *
     * Delegates to the SDK's SignalCollector, which is the canonical
     * implementation and is shared with any other host framework. Falls back to
     * an empty array if the SDK is unavailable for any reason — the ingest
     * service treats absent client signals as "compose no network identity",
     * which is correct: no actor is better than one shared by every visitor.
     *
     * @return array
     */
    private function build_client_signals(): array
    {
        if (!class_exists('\\WebDecoy\\SignalCollector')) {
            return [];
        }

        try {
            $collector = new \WebDecoy\SignalCollector();
            return $collector->getClientSignals();
        } catch (\Throwable $e) {
            // A detection beacon is never worth breaking the page over.
            return [];
        }
    }

    /**
     * AJAX: Test API connection
     */
    public function ajax_test_connection(): void
    {
        check_ajax_referer('webdecoy_admin', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'webdecoy')]);
            return;
        }

        $api_key = sanitize_text_field(wp_unslash($_POST['api_key'] ?? ''));

        // Decrypt if encrypted
        if (!empty($api_key) && $this->is_encrypted($api_key)) {
            $api_key = $this->decrypt_value($api_key);
        }

        if (empty($api_key)) {
            // Clear cache since credentials are incomplete
            $this->clear_api_status_cache();
            $this->set_api_status_cache('inactive', __('API key is required.', 'webdecoy'));
            wp_send_json_error(['message' => __('API key is required.', 'webdecoy')]);
            return;
        }

        try {
            $client = new \WebDecoy\Client([
                'api_key' => $api_key,
            ]);

            $client->testConnection();

            // Update cache to active
            $this->set_api_status_cache('active');

            wp_send_json_success(['message' => __('Connection successful! API is active.', 'webdecoy')]);
        } catch (\Exception $e) {
            // Update cache to inactive with error message
            $this->set_api_status_cache('inactive', $e->getMessage());

            wp_send_json_error(['message' => $e->getMessage()]);
        }
    }

    /**
     * AJAX: Get stats
     */
    public function ajax_get_stats(): void
    {
        check_ajax_referer('webdecoy_admin', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'webdecoy')]);
            return;
        }

        $client = $this->get_client();
        if (!$client) {
            wp_send_json_error(['message' => __('API not configured.', 'webdecoy')]);
            return;
        }

        try {
            $stats = $client->getStats(
                gmdate('Y-m-d', strtotime('-7 days')),
                gmdate('Y-m-d')
            );
            wp_send_json_success($stats);
        } catch (\Exception $e) {
            wp_send_json_error(['message' => $e->getMessage()]);
        }
    }

    /**
     * AJAX: Block IP
     */
    public function ajax_block_ip(): void
    {
        check_ajax_referer('webdecoy_admin', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'webdecoy')]);
            return;
        }

        $ip = sanitize_text_field(wp_unslash($_POST['ip'] ?? ''));
        $reason = sanitize_text_field(wp_unslash($_POST['reason'] ?? ''));
        $duration = intval($_POST['duration'] ?? 24);

        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            wp_send_json_error(['message' => __('Invalid IP address.', 'webdecoy')]);
            return;
        }

        // force: a human typed this address, so the safety guards do not apply.
        $blocker = new WebDecoy_Blocker();
        $blocker->block($ip, $reason, $duration > 0 ? $duration : null, true);

        wp_send_json_success(['message' => __('IP blocked successfully.', 'webdecoy')]);
    }

    /**
     * AJAX: Unblock IP
     */
    public function ajax_unblock_ip(): void
    {
        check_ajax_referer('webdecoy_admin', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'webdecoy')]);
            return;
        }

        $ip = sanitize_text_field(wp_unslash($_POST['ip'] ?? ''));

        if (empty($ip)) {
            wp_send_json_error(['message' => __('Invalid IP address.', 'webdecoy')]);
            return;
        }

        $blocker = new WebDecoy_Blocker();
        $blocker->unblock($ip);

        wp_send_json_success(['message' => __('IP unblocked successfully.', 'webdecoy')]);
    }

    /**
     * AJAX: Bulk block IPs from detections page
     */
    public function ajax_bulk_block(): void
    {
        check_ajax_referer('webdecoy_admin', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'webdecoy')]);
            return;
        }

        $ips = isset($_POST['ips']) ? array_map('sanitize_text_field', wp_unslash((array) $_POST['ips'])) : [];

        if (empty($ips)) {
            wp_send_json_error(['message' => __('No IPs selected.', 'webdecoy')]);
            return;
        }

        $blocker = new WebDecoy_Blocker();
        $blocked = 0;
        $refused = 0;

        // Not forced: these addresses came from detection rows, not from a human
        // typing them, so behind an unconfigured proxy they may all be the front
        // door. The guards apply and refusals are reported back.
        foreach ($ips as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                if ($blocker->block($ip, 'Bulk block from detections page', $this->block_duration())) {
                    $blocked++;
                } else {
                    $refused++;
                }
            }
        }

        wp_send_json_success([
            'message' => $refused > 0
                ? sprintf(
                    /* translators: 1: number of IPs blocked, 2: number refused */
                    __('%1$d IPs blocked. %2$d refused as infrastructure addresses — check that your trusted proxy settings match how this site is served.', 'webdecoy'),
                    $blocked,
                    $refused
                )
                : sprintf(
                    /* translators: %d: number of IPs blocked */
                    __('%d IPs blocked.', 'webdecoy'),
                    $blocked
                ),
        ]);
    }

    /**
     * AJAX: Generate PoW challenge
     */
    public function ajax_pow_challenge(): void
    {
        check_ajax_referer('webdecoy_pow', '_wpnonce');

        // Rate limit: max 5 challenges per minute per IP
        $ip = $this->get_client_ip();
        $rate_key = 'webdecoy_pow_rate_' . md5($ip);
        $count = (int) get_transient($rate_key);

        if ($count >= 5) {
            wp_send_json_error(['message' => __('Too many requests.', 'webdecoy')], 429);
            return;
        }

        set_transient($rate_key, $count + 1, 60);

        $pow = new WebDecoy_PoW();
        $difficulty = intval($this->options['pow_difficulty'] ?? 4);
        $challenge = $pow->generate_challenge($ip, $difficulty);

        wp_send_json_success($challenge);
    }

    /**
     * AJAX: Verify PoW solution
     */
    public function ajax_pow_verify(): void
    {
        check_ajax_referer('webdecoy_pow', '_wpnonce');

        $ip = $this->get_client_ip();

        // Get challenge data
        $challenge_json = isset($_POST['challenge']) ? sanitize_text_field(wp_unslash($_POST['challenge'])) : '';
        $challenge = json_decode($challenge_json, true);

        if (!$challenge || !is_array($challenge)) {
            wp_send_json_error(['message' => __('Invalid challenge data.', 'webdecoy')]);
            return;
        }

        $nonce = isset($_POST['pow_nonce']) ? intval($_POST['pow_nonce']) : 0;
        $hash = isset($_POST['pow_hash']) ? sanitize_text_field(wp_unslash($_POST['pow_hash'])) : '';
        if (!preg_match('/^[0-9a-f]{64}$/i', $hash)) {
            wp_send_json_error(['message' => __('Invalid hash.', 'webdecoy')]);
            return;
        }

        $pow = new WebDecoy_PoW();
        $result = $pow->verify_solution($challenge, $nonce, $hash);

        if (!$result['valid']) {
            $pow->record_failure($ip);
            wp_send_json_error(['message' => $result['reason']]);
            return;
        }

        // Score behavioral signals if provided
        $behavioral_json = isset($_POST['behavioral']) ? sanitize_text_field(wp_unslash($_POST['behavioral'])) : '';
        $behavioral = json_decode($behavioral_json, true);

        if ($behavioral && is_array($behavioral)) {
            $scorer = new WebDecoy_Behavioral_Scorer();
            $score_result = $scorer->score($behavioral);

            // If behavioral score is very high (definitely bot), reject despite PoW
            if ($score_result['score'] > 0.9) {
                wp_send_json_error(['message' => __('Verification failed.', 'webdecoy')]);
                return;
            }
        }

        // Set verified cookie
        $duration = intval($this->options['challenge_duration'] ?? 15) * MINUTE_IN_SECONDS;
        $cookie_value = hash_hmac('sha256', $ip . time(), $this->get_encryption_key());

        // Store the cookie hash so we can verify it later
        set_transient('webdecoy_verified_' . md5($ip), $cookie_value, $duration);

        // Set cookie on client
        setcookie('webdecoy_verified', $cookie_value, time() + $duration, '/', '', is_ssl(), true);

        wp_send_json_success(['message' => __('Verified successfully.', 'webdecoy')]);
    }

    /**
     * Get API client
     *
     * @return \WebDecoy\Client|null
     */
    public function get_client(): ?\WebDecoy\Client
    {
        if ($this->client === null && !empty($this->options['api_key'])) {
            try {
                $this->client = new \WebDecoy\Client([
                    'api_key' => $this->options['api_key'],
                ]);
            } catch (\Exception $e) {
                error_log('WebDecoy client error: ' . $e->getMessage());
                return null;
            }
        }
        return $this->client;
    }

    /**
     * Get bot detector
     *
     * @return \WebDecoy\BotDetector
     */
    public function get_detector(): \WebDecoy\BotDetector
    {
        if ($this->detector === null) {
            $this->detector = new \WebDecoy\BotDetector([
                'sensitivity' => $this->options['sensitivity'],
                'allow_search_engines' => $this->options['allow_search_engines'],
                'allow_social_bots' => $this->options['allow_social_bots'],
                'block_ai_crawlers' => $this->options['block_ai_crawlers'],
                'custom_allowlist' => $this->options['custom_allowlist'],
                'trusted_proxies' => $this->get_trusted_proxies(),
            ]);
        }
        return $this->detector;
    }

    /**
     * Get client IP
     *
     * @return string
     */
    public function get_client_ip(): string
    {
        return $this->get_detector()->getSignalCollector()->getIP();
    }

    /**
     * Check if API is properly configured (credentials exist)
     *
     * @return bool
     */
    public function is_api_configured(): bool
    {
        return !empty($this->options['api_key']);
    }

    /**
     * Check if API status is cached as active (without making API calls)
     * Used during initialization to determine if protection hooks should be enabled.
     * This only returns true if the API key has been validated and cached as 'active'.
     *
     * @return bool
     */
    public function is_api_status_active(): bool
    {
        // First check if credentials exist
        if (!$this->is_api_configured()) {
            return false;
        }

        // Only check the cache - don't make API calls during initialization
        $cached = get_transient('webdecoy_api_status');

        return $cached === 'active';
    }

    /**
     * Check if premium (cloud) features are available
     * Used to gate cloud-only features: sync, enrichment, cross-site intelligence
     *
     * @return bool
     */
    public function is_premium(): bool
    {
        return !empty($this->options['api_key']) && $this->is_api_status_active();
    }

    /**
     * Check if API key is valid and account is active
     * Results are cached for 12 hours to avoid hitting the API on every request
     * Uses a lock to prevent thundering herd on cache miss
     *
     * @param bool $force_check Force a fresh check, bypassing cache
     * @return bool
     */
    public function is_api_active(bool $force_check = false): bool
    {
        // First check if credentials exist
        if (!$this->is_api_configured()) {
            return false;
        }

        // Check cache
        $cache_key = 'webdecoy_api_status';
        $cached = get_transient($cache_key);

        if (!$force_check && $cached !== false) {
            return $cached === 'active';
        }

        // Use a lock to prevent thundering herd on cache miss
        // If another request is already checking, return false (fail safe)
        $lock_key = 'webdecoy_api_status_lock';
        if (get_transient($lock_key)) {
            // Another process is checking - fail safe, don't spam the API
            return false;
        }

        // Set lock for 30 seconds to prevent concurrent validation requests
        set_transient($lock_key, true, 30);

        // Validate against the API
        try {
            $client = $this->get_client();
            if (!$client) {
                $this->set_api_status_cache('inactive', 'API client initialization failed');
                delete_transient($lock_key);
                return false;
            }

            $client->testConnection();

            // API is valid and active
            $this->set_api_status_cache('active');
            delete_transient($lock_key);
            return true;

        } catch (\WebDecoy\Exception\WebDecoyException $e) {
            // API returned an error
            $this->set_api_status_cache('inactive', $e->getMessage());
            delete_transient($lock_key);
            return false;
        } catch (\Exception $e) {
            // Network or other error - cache for shorter time and fail open
            // Don't cache failures for too long in case it's a temporary network issue
            set_transient($cache_key, 'error', 5 * MINUTE_IN_SECONDS);
            update_option('webdecoy_api_last_error', $e->getMessage());
            delete_transient($lock_key);

            // Fail open on network errors to not block legitimate traffic
            // but don't run scanner either
            return false;
        }
    }

    /**
     * Set API status cache
     *
     * @param string $status 'active' or 'inactive'
     * @param string|null $error_message Optional error message
     */
    private function set_api_status_cache(string $status, ?string $error_message = null): void
    {
        $cache_key = 'webdecoy_api_status';

        // Cache active status for 12 hours, inactive for 15 minutes
        $expiration = $status === 'active' ? 12 * HOUR_IN_SECONDS : 15 * MINUTE_IN_SECONDS;

        set_transient($cache_key, $status, $expiration);

        if ($error_message) {
            update_option('webdecoy_api_last_error', $error_message);
        } else {
            delete_option('webdecoy_api_last_error');
        }

        update_option('webdecoy_api_last_check', current_time('mysql'));
    }

    /**
     * Clear API status cache (useful when settings are saved)
     */
    public function clear_api_status_cache(): void
    {
        delete_transient('webdecoy_api_status');
    }

    /**
     * Get current URL
     *
     * @return string
     */
    private function get_current_url(): string
    {
        return $this->get_detector()->getSignalCollector()->getCurrentUrl();
    }

    /**
     * Get plugin options
     *
     * @return array
     */
    public function get_options(): array
    {
        return $this->options;
    }

    /**
     * Persist Cloud credentials returned by the connect exchange.
     *
     * Called by {@see WebDecoy_Cloud_Connect} after a successful token exchange.
     * The API key is encrypted at rest exactly like the manual-entry path; the
     * publishable site key and org metadata are stored alongside it.
     *
     * @param string $api_key           Plaintext secret API key.
     * @param string $site_key          Publishable site key (org id).
     * @param string $organization_id   Cloud organization id.
     * @param string $organization_name Human-readable org name.
     * @param string $plan              Plan slug (e.g. free_connected).
     */
    public function store_cloud_credentials(string $api_key, string $site_key, string $organization_id, string $organization_name, string $plan): void
    {
        $options = get_option('webdecoy_options', []);
        if (!is_array($options)) {
            $options = [];
        }

        if ($api_key !== '') {
            $options['api_key'] = $this->is_encrypted($api_key) ? $api_key : $this->encrypt_value($api_key);
        }
        $options['site_key'] = sanitize_text_field($site_key);
        $options['organization_id'] = sanitize_text_field($organization_id);
        $options['organization_name'] = sanitize_text_field($organization_name);
        $options['plan'] = sanitize_text_field($plan);

        $this->update_options_raw($options);

        // Reflect the change in the in-request cache with the API key decrypted,
        // matching load_options() so downstream getters see the plaintext key.
        $this->options = $options;
        if ($api_key !== '') {
            $this->options['api_key'] = $this->is_encrypted($api_key) ? $this->decrypt_value($api_key) : $api_key;
        }

        // The only caller is the connect flow, which reaches here immediately
        // after a successful token exchange against the API — the key is
        // known-good right now. Mark the status active instead of merely
        // clearing the cache: with only a clear, is_premium() stays false
        // until something happens to trigger a revalidation, which keeps the
        // JS verification token and violation reporting off at the exact
        // moment the user just connected and is watching. (update_options_raw
        // above already fired the option hook that clears the cache, so this
        // set is what survives.)
        $this->set_api_status_cache('active');
    }

    /**
     * Clear all Cloud credentials + org metadata locally (no remote call).
     * Used by the Disconnect action.
     */
    public function clear_cloud_credentials(): void
    {
        $options = get_option('webdecoy_options', []);
        if (!is_array($options)) {
            $options = [];
        }

        $options['api_key'] = '';
        $options['site_key'] = '';
        $options['organization_id'] = '';
        $options['organization_name'] = '';
        $options['plan'] = '';

        $this->update_options_raw($options);

        $this->options['api_key'] = '';
        $this->options['site_key'] = '';
        $this->options['organization_id'] = '';
        $this->options['organization_name'] = '';
        $this->options['plan'] = '';

        $this->clear_api_status_cache();
    }

    /**
     * Write the options option verbatim, bypassing the Settings API sanitizer.
     *
     * sanitize_options() is written for a full form POST: it rebuilds the array
     * from string form fields and would mangle the array-typed values (e.g.
     * custom_allowlist) already present in a stored, complete options array. For
     * these trusted, pre-shaped writes we detach the sanitize filter for the
     * duration of the update, then restore it if it was attached.
     *
     * @param array<string,mixed> $options Complete, pre-sanitized options array.
     */
    private function update_options_raw(array $options): void
    {
        $had_filter = remove_filter('sanitize_option_webdecoy_options', [$this, 'sanitize_options']);
        update_option('webdecoy_options', $options);
        if ($had_filter) {
            add_filter('sanitize_option_webdecoy_options', [$this, 'sanitize_options']);
        }
    }

}

/**
 * Get plugin instance
 *
 * @return WebDecoy_Plugin
 */
function webdecoy(): WebDecoy_Plugin
{
    return WebDecoy_Plugin::instance();
}

/**
 * Trusted-proxy ranges, reachable from classes that do not hold a plugin reference.
 * Used by WebDecoy_Blocker::guard() to refuse blocking infrastructure addresses.
 *
 * @return string[]
 */
function webdecoy_plugin_trusted_proxies(): array
{
    return WebDecoy_Plugin::instance()->get_trusted_proxies();
}

// Initialize plugin
webdecoy();
