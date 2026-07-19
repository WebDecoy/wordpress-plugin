<?php
/**
 * Plugin Name: WebDecoy Bot Detection
 * Plugin URI: https://webdecoy.com/wordpress
 * Description: Protect your WordPress site from bots, spam, and carding attacks with WebDecoy's advanced threat detection.
 * Version: 2.1.0
 * Requires at least: 5.6
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
define('WEBDECOY_VERSION', '2.1.0');
define('WEBDECOY_PLUGIN_FILE', __FILE__);
define('WEBDECOY_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('WEBDECOY_PLUGIN_URL', plugin_dir_url(__FILE__));
define('WEBDECOY_PLUGIN_BASENAME', plugin_basename(__FILE__));

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
            'block_action' => 'block',
            'block_duration' => 24,
            'show_block_page' => true,
            'block_page_message' => 'Access to this site has been restricted.',

            // Rate Limiting
            'rate_limit_enabled' => true,
            'rate_limit_requests' => 60,
            'rate_limit_window' => 60,

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

            // Form Protection
            'protect_comments' => true,
            'protect_login' => true,
            'protect_registration' => true,
            'inject_honeypot' => true,

            // WooCommerce
            'protect_checkout' => true,
            'checkout_velocity_limit' => 5,
            'checkout_velocity_window' => 3600,

            // Client-side Scanner
            'scanner_enabled' => true,
            'scanner_min_score' => 20,
            'scanner_on_all_pages' => true,
            'scanner_exclude_logged_in' => false,

            // Proof-of-Work
            'pow_enabled' => true,
            'pow_difficulty' => 4,
            'challenge_duration' => 15,
        ];

        $saved = get_option('webdecoy_options', []);
        $this->options = array_merge($defaults, $saved);

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

        // Self-hosted update mechanism: Only active when WEBDECOY_SELF_HOSTED constant is defined.
        // WordPress.org installs use the standard WordPress.org update system exclusively.
        // This code is inert by default and does not run on WordPress.org-distributed copies.
        if (defined('WEBDECOY_SELF_HOSTED') && WEBDECOY_SELF_HOSTED) {
            add_filter('pre_set_site_transient_update_plugins', [$this, 'check_for_updates']);
            add_filter('plugins_api', [$this, 'plugin_info'], 10, 3);
            // Verify the downloaded package's checksum before WordPress installs it.
            add_filter('upgrader_pre_download', [$this, 'verify_update_package'], 10, 3);
        }

        // Early request check (as early as possible)
        add_action('init', [$this, 'early_check'], 1);

        // Load includes
        add_action('plugins_loaded', [$this, 'load_includes']);

        // Admin hooks
        if (is_admin()) {
            add_action('admin_menu', [$this, 'admin_menu']);
            add_action('admin_init', [$this, 'register_settings']);
            add_action('wp_dashboard_setup', [$this, 'dashboard_widget']);
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

        // JS execution verification: inject challenge token meta tag and report page serve
        // Only active when scanner is enabled and API key is configured (premium)
        if ($this->options['scanner_enabled'] && !is_admin() && $this->is_premium()) {
            add_action('wp_head', [$this, 'inject_js_verification_token'], 1);
        }

        // Clear API cache when settings are saved
        add_action('update_option_webdecoy_options', [$this, 'clear_api_status_cache']);

        // Load text domain
        add_action('init', [$this, 'load_textdomain']);

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
        require_once WEBDECOY_PLUGIN_DIR . 'includes/class-webdecoy-forms.php';
        require_once WEBDECOY_PLUGIN_DIR . 'includes/class-webdecoy-rate-limiter.php';

        require_once WEBDECOY_PLUGIN_DIR . 'includes/class-webdecoy-pow.php';
        require_once WEBDECOY_PLUGIN_DIR . 'includes/class-webdecoy-behavioral-scorer.php';
        require_once WEBDECOY_PLUGIN_DIR . 'includes/class-webdecoy-violation-reporter.php';

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
     * Load text domain
     */
    public function load_textdomain(): void
    {
        load_plugin_textdomain('webdecoy', false, dirname(WEBDECOY_PLUGIN_BASENAME) . '/languages');
    }

    /**
     * Early request check
     */
    public function early_check(): void
    {
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

        if ($blocker->is_blocked($ip)) {
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

        // Check rate limit
        if ($this->options['rate_limit_enabled']) {
            $rateLimiter = new WebDecoy_Rate_Limiter();
            if ($rateLimiter->is_exceeded($ip)) {
                $this->handle_rate_limit_exceeded($ip);
                return;
            }
            $rateLimiter->increment($ip);
        }

        // Run bot detection with request path for MITRE ATT&CK path analysis
        $detector = $this->get_detector();
        $signals = $detector->getSignalCollector()->collect();

        // Add request path for path-based scoring
        $signals['request_path'] = $this->get_request_path();

        $result = $detector->analyze($signals);

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

        if (!empty($this->options['tripwire_enabled'])) {
            $rules[] = new \WebDecoy\Rules\TripwireRule([
                'paths' => is_array($this->options['tripwire_paths'] ?? null) ? $this->options['tripwire_paths'] : [],
                'prefixes' => is_array($this->options['tripwire_prefixes'] ?? null) ? $this->options['tripwire_prefixes'] : [],
                'patterns' => is_array($this->options['tripwire_patterns'] ?? null) ? $this->options['tripwire_patterns'] : [],
                'includeDefaults' => !empty($this->options['tripwire_include_defaults']),
                'action' => ($this->options['tripwire_action'] ?? 'block') === 'throttle'
                    ? \WebDecoy\Rules\RuleResult::THROTTLE
                    : \WebDecoy\Rules\RuleResult::DENY,
                'dryRun' => !empty($this->options['tripwire_dry_run']),
            ]);
        }

        if ($rules === []) {
            return null;
        }

        return new \WebDecoy\Rules\RuleEngine($rules);
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

        // Only the headers rules actually read. The Cookie header is passed raw
        // (not sanitize_text_field'd) so the wd_clearance token value survives
        // intact for forwarding.
        $headers = [];
        if (isset($_SERVER['HTTP_COOKIE'])) {
            $headers['cookie'] = (string) wp_unslash($_SERVER['HTTP_COOKIE']);
        }

        return new \WebDecoy\Rules\RuleContext(
            $ip,
            $this->get_request_path(),
            $method,
            $userAgent,
            $headers
        );
    }

    /**
     * Act on a non-ALLOW rule-engine decision: DENY blocks, THROTTLE serves 429.
     *
     * @param \WebDecoy\Rules\RuleEngineResult $result
     * @param string $ip
     */
    private function handle_rule_decision(\WebDecoy\Rules\RuleEngineResult $result, string $ip): void
    {
        if ($result->action === \WebDecoy\Rules\RuleResult::THROTTLE) {
            $retryAfter = 60;
            if (is_array($result->metadata) && isset($result->metadata['retryAfter'])) {
                $retryAfter = max(1, intval($result->metadata['retryAfter']));
            }
            nocache_headers();
            status_header(429);
            header('Retry-After: ' . $retryAfter);
            wp_die(
                esc_html__('Too many requests. Please try again later.', 'webdecoy'),
                esc_html__('Too Many Requests', 'webdecoy'),
                ['response' => 429]
            );
            return;
        }

        // DENY: record the block, then serve the block page / wp_die.
        $blocker = new WebDecoy_Blocker();
        $duration = $this->options['block_duration'] > 0 ? $this->options['block_duration'] : null;
        $reason = $result->reason ?? ('Rule enforced: ' . ($result->rule ?? 'rule'));
        $blocker->block($ip, $reason, $duration);
        $this->block_request($this->options['block_page_message']);
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
                'created_at' => current_time('mysql'),
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

            // Serve challenge page
            $this->serve_challenge_page($ip);
            return;
        }

        // Default action: block
        $blocker = new WebDecoy_Blocker();
        $duration = $this->options['block_duration'] > 0 ? $this->options['block_duration'] : null;
        $blocker->block($ip, 'Bot detection score: ' . $result->getScore(), $duration);
        $this->block_request($this->options['block_page_message']);
    }

    /**
     * Check if an IP has been verified via challenge
     *
     * @param string $ip
     * @return bool
     */
    private function is_challenge_verified(string $ip): bool
    {
        $cookie = isset($_COOKIE['webdecoy_verified']) ? sanitize_text_field($_COOKIE['webdecoy_verified']) : '';
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
        if (parse_url($redirect_url, PHP_URL_HOST) !== parse_url(home_url(), PHP_URL_HOST)) {
            $redirect_url = home_url('/');
        }
        $ajax_url = admin_url('admin-ajax.php');
        $nonce = wp_create_nonce('webdecoy_pow');

        include WEBDECOY_PLUGIN_DIR . 'templates/challenge-page.php';
        exit;
    }

    /**
     * Handle rate limit exceeded
     *
     * @param string $ip
     */
    private function handle_rate_limit_exceeded(string $ip): void
    {
        // Add rate exceeded flag to detection
        $detector = $this->get_detector();
        $result = $detector->analyze(['rate_exceeded' => true]);

        // Log rate limit exceeded
        $this->log_detection($result, $ip);

        if ($result->getScore() >= $this->options['min_score_to_block']) {
            $this->handle_blocking($result, $ip);
        } else {
            // Just block temporarily for rate limiting
            $this->block_request(__('Too many requests. Please try again later.', 'webdecoy'));
        }
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
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field($_SERVER['HTTP_USER_AGENT']) : '',
            'score' => $result->getScore(),
            'threat_level' => $result->getThreatLevel(),
            'source' => 'wordpress_plugin',
            'flags' => json_encode($flags_data),
            'created_at' => current_time('mysql'),
        ]);
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
            wp_die(
                esc_html__('Your comment has been blocked due to suspicious activity.', 'webdecoy'),
                esc_html__('Comment Blocked', 'webdecoy'),
                ['response' => 403, 'back_link' => true]
            );
        }

        return $commentdata;
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

        if (isset($_POST[$honeypot_name]) && !empty($_POST[$honeypot_name])) {
            // Honeypot triggered - definitely a bot
            $ip = $this->get_client_ip();
            $blocker = new WebDecoy_Blocker();
            $blocker->block($ip, 'Honeypot triggered: ' . $context);

            $this->block_request(__('Suspicious activity detected.', 'webdecoy'));
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
        $sanitized['block_action'] = in_array($input['block_action'] ?? 'block', ['block', 'challenge', 'log']) ? $input['block_action'] : 'block';
        $sanitized['block_duration'] = max(0, intval($input['block_duration'] ?? 24));
        $sanitized['show_block_page'] = !empty($input['show_block_page']);
        $sanitized['block_page_message'] = sanitize_textarea_field($input['block_page_message'] ?? '');

        // Rate Limiting
        $sanitized['rate_limit_enabled'] = !empty($input['rate_limit_enabled']);
        $sanitized['rate_limit_requests'] = max(1, intval($input['rate_limit_requests'] ?? 60));
        $sanitized['rate_limit_window'] = max(1, intval($input['rate_limit_window'] ?? 60));

        // Tripwires
        $sanitized['tripwire_enabled'] = !empty($input['tripwire_enabled']);
        $sanitized['tripwire_include_defaults'] = !empty($input['tripwire_include_defaults']);
        $sanitized['tripwire_paths'] = $this->sanitize_path_list($input['tripwire_paths'] ?? '');
        $sanitized['tripwire_prefixes'] = $this->sanitize_path_list($input['tripwire_prefixes'] ?? '');
        $sanitized['tripwire_patterns'] = $this->sanitize_pattern_list($input['tripwire_patterns'] ?? '');
        $sanitized['tripwire_action'] = in_array($input['tripwire_action'] ?? 'block', ['block', 'throttle'], true) ? $input['tripwire_action'] : 'block';
        $sanitized['tripwire_dry_run'] = !empty($input['tripwire_dry_run']);

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

        // Proof-of-Work
        $sanitized['pow_enabled'] = !empty($input['pow_enabled']);
        $sanitized['pow_difficulty'] = max(2, min(7, intval($input['pow_difficulty'] ?? 4)));
        $sanitized['challenge_duration'] = max(5, min(60, intval($input['challenge_duration'] ?? 15)));

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
                'confirmBlock' => __('Are you sure you want to block %s?', 'webdecoy'),
                'confirmUnblock' => __('Are you sure you want to unblock this IP?', 'webdecoy'),
                'confirmBulkBlock' => __('Are you sure you want to block %d IPs?', 'webdecoy'),
                'selectIPs' => __('Please select at least one IP to block.', 'webdecoy'),
                'toggleVisibility' => __('Toggle visibility', 'webdecoy'),
                'error' => __('An error occurred. Please try again.', 'webdecoy'),
            ],
        ]);

        // Load Chart.js and charts script on statistics page
        if ($hook === 'webdecoy_page_webdecoy-statistics') {
            wp_enqueue_script(
                'chartjs',
                'https://cdn.jsdelivr.net/npm/chart.js@4.4/dist/chart.umd.min.js',
                [],
                '4.4.0',
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
        $detection_json = isset($_POST['detection']) ? wp_unslash($_POST['detection']) : '';
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
            $blocker = new WebDecoy_Blocker();
            $duration = $this->options['block_duration'] > 0 ? $this->options['block_duration'] : null;
            $flags = implode(', ', $detection['f'] ?? []);
            $blocker->block($ip, "Client detection (score: {$score}): {$flags}", $duration);
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
            'created_at' => current_time('mysql'),
        ]);
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
     * AJAX: Test API connection
     */
    public function ajax_test_connection(): void
    {
        check_ajax_referer('webdecoy_admin', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'webdecoy')]);
            return;
        }

        $api_key = sanitize_text_field($_POST['api_key'] ?? '');

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
                date('Y-m-d', strtotime('-7 days')),
                date('Y-m-d')
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

        $ip = sanitize_text_field($_POST['ip'] ?? '');
        $reason = sanitize_text_field($_POST['reason'] ?? '');
        $duration = intval($_POST['duration'] ?? 24);

        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            wp_send_json_error(['message' => __('Invalid IP address.', 'webdecoy')]);
            return;
        }

        $blocker = new WebDecoy_Blocker();
        $blocker->block($ip, $reason, $duration > 0 ? $duration : null);

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

        $ip = sanitize_text_field($_POST['ip'] ?? '');

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

        $ips = isset($_POST['ips']) ? array_map('sanitize_text_field', (array) $_POST['ips']) : [];

        if (empty($ips)) {
            wp_send_json_error(['message' => __('No IPs selected.', 'webdecoy')]);
            return;
        }

        $blocker = new WebDecoy_Blocker();
        $blocked = 0;

        foreach ($ips as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $duration = $this->options['block_duration'] > 0 ? $this->options['block_duration'] : null;
                $blocker->block($ip, 'Bulk block from detections page', $duration);
                $blocked++;
            }
        }

        wp_send_json_success([
            'message' => sprintf(
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
        $challenge_json = isset($_POST['challenge']) ? wp_unslash($_POST['challenge']) : '';
        $challenge = json_decode($challenge_json, true);

        if (!$challenge || !is_array($challenge)) {
            wp_send_json_error(['message' => __('Invalid challenge data.', 'webdecoy')]);
            return;
        }

        $nonce = isset($_POST['pow_nonce']) ? intval($_POST['pow_nonce']) : 0;
        $hash = isset($_POST['pow_hash']) ? wp_unslash($_POST['pow_hash']) : '';
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
        $behavioral_json = isset($_POST['behavioral']) ? wp_unslash($_POST['behavioral']) : '';
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
     * Check for plugin updates from WebDecoy CDN
     *
     * @param object $transient Update transient
     * @return object Modified transient
     */
    public function check_for_updates($transient)
    {
        if (empty($transient->checked)) {
            return $transient;
        }

        // Check for cached update info
        $update_info = get_transient('webdecoy_update_info');

        if ($update_info === false) {
            // Fetch update info from WebDecoy
            $response = wp_remote_get('https://cdn.webdecoy.com/wordpress/update-info.json', [
                'timeout' => 10,
                'headers' => [
                    'Accept' => 'application/json',
                ],
            ]);

            if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
                return $transient;
            }

            $update_info = json_decode(wp_remote_retrieve_body($response), true);

            if (!$update_info || !isset($update_info['version'])) {
                return $transient;
            }

            // Cache for 12 hours
            set_transient('webdecoy_update_info', $update_info, 12 * HOUR_IN_SECONDS);
        }

        // Compare versions
        if (version_compare(WEBDECOY_VERSION, $update_info['version'], '<')) {
            // Host-pin the package URL: WordPress will download and install whatever
            // is at `package` with full privileges, so refuse any URL that is not an
            // HTTPS link on our own CDN. Without this, a tampered update-info.json
            // could point the installer at an attacker-controlled ZIP (RCE).
            $download_url = $update_info['download_url'] ?? '';
            if (!$this->is_trusted_package_url($download_url)) {
                return $transient;
            }

            $transient->response[WEBDECOY_PLUGIN_BASENAME] = (object) [
                'slug' => 'webdecoy',
                'plugin' => WEBDECOY_PLUGIN_BASENAME,
                'new_version' => $update_info['version'],
                'package' => $download_url,
                'url' => $update_info['details_url'] ?? 'https://webdecoy.com/wordpress',
                'icons' => $update_info['icons'] ?? [],
                'banners' => $update_info['banners'] ?? [],
                'tested' => $update_info['tested'] ?? '',
                'requires_php' => $update_info['requires_php'] ?? '7.4',
            ];
        }

        return $transient;
    }

    /**
     * Whether a package download URL is an HTTPS link on our own CDN host.
     * Used to prevent the self-hosted updater from installing a ZIP from any
     * other origin.
     */
    private function is_trusted_package_url(string $url): bool
    {
        if ($url === '') {
            return false;
        }
        $parts = wp_parse_url($url);
        if (empty($parts['scheme']) || empty($parts['host'])) {
            return false;
        }
        return strtolower($parts['scheme']) === 'https'
            && strtolower($parts['host']) === 'cdn.webdecoy.com';
    }

    /**
     * Verify the integrity of the self-hosted update package before installation.
     *
     * Hooked on `upgrader_pre_download`. When the package is our CDN-hosted ZIP and
     * the update metadata advertises a sha256, we download it ourselves, verify the
     * checksum, and hand WordPress the verified local file. A mismatch (or a missing
     * checksum) aborts the upgrade with a WP_Error rather than installing unverified
     * code. Returning false defers to WordPress's normal download for anything that
     * isn't our package.
     *
     * @param bool|WP_Error $reply   Short-circuit value (false to continue).
     * @param string        $package The package URL being downloaded.
     * @param object        $upgrader The upgrader instance.
     * @return bool|string|\WP_Error
     */
    public function verify_update_package($reply, $package, $upgrader)
    {
        // Only act on our own CDN packages; let WP handle everything else.
        if (!is_string($package) || !$this->is_trusted_package_url($package)) {
            return $reply;
        }

        $update_info = get_transient('webdecoy_update_info');
        $expected = is_array($update_info) ? ($update_info['sha256'] ?? '') : '';
        $expected = is_string($expected) ? strtolower(trim($expected)) : '';

        // Require a checksum to install self-hosted updates.
        if (!preg_match('/^[a-f0-9]{64}$/', $expected)) {
            return new \WP_Error(
                'webdecoy_no_checksum',
                __('WebDecoy update aborted: no valid checksum was provided for the package.', 'webdecoy')
            );
        }

        if (!function_exists('download_url')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }

        $tmp_file = download_url($package);
        if (is_wp_error($tmp_file)) {
            return $tmp_file;
        }

        $actual = hash_file('sha256', $tmp_file);
        if (!hash_equals($expected, (string) $actual)) {
            wp_delete_file($tmp_file);
            return new \WP_Error(
                'webdecoy_checksum_mismatch',
                __('WebDecoy update aborted: package checksum did not match the expected value.', 'webdecoy')
            );
        }

        // Verified: hand WordPress the local file to install.
        return $tmp_file;
    }

    /**
     * Plugin information for the update details popup
     *
     * @param false|object|array $result
     * @param string $action
     * @param object $args
     * @return false|object
     */
    public function plugin_info($result, $action, $args)
    {
        if ($action !== 'plugin_information' || !isset($args->slug) || $args->slug !== 'webdecoy') {
            return $result;
        }

        // Fetch plugin info from WebDecoy
        $response = wp_remote_get('https://cdn.webdecoy.com/wordpress/plugin-info.json', [
            'timeout' => 10,
            'headers' => [
                'Accept' => 'application/json',
            ],
        ]);

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return $result;
        }

        $info = json_decode(wp_remote_retrieve_body($response), true);

        if (!$info) {
            return $result;
        }

        return (object) [
            'name' => $info['name'] ?? 'WebDecoy Bot Detection',
            'slug' => 'webdecoy',
            'version' => $info['version'] ?? WEBDECOY_VERSION,
            'author' => $info['author'] ?? '<a href="https://webdecoy.com">WebDecoy</a>',
            'author_profile' => $info['author_profile'] ?? 'https://webdecoy.com',
            'requires' => $info['requires'] ?? '5.6',
            'tested' => $info['tested'] ?? '',
            'requires_php' => $info['requires_php'] ?? '7.4',
            'sections' => $info['sections'] ?? [
                'description' => 'Protect your WordPress site from bots, spam, and carding attacks.',
                'changelog' => $info['changelog'] ?? '',
            ],
            'download_link' => $info['download_url'] ?? '',
            'banners' => $info['banners'] ?? [],
            'icons' => $info['icons'] ?? [],
        ];
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

// Initialize plugin
webdecoy();
