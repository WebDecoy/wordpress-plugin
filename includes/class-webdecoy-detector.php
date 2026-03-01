<?php
/**
 * WebDecoy Detector
 *
 * WordPress-specific wrapper around the WebDecoy SDK's bot detection
 * functionality with additional WordPress-specific signals.
 *
 * @package WebDecoy
 */

// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared
// phpcs:disable WordPress.DB.PreparedSQLPlaceholders.LikeWildcardsInQuery

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * WebDecoy Detector Class
 */
class WebDecoy_Detector
{
    /**
     * SDK Bot Detector
     *
     * @var \WebDecoy\BotDetector
     */
    private \WebDecoy\BotDetector $detector;

    /**
     * Plugin options
     *
     * @var array
     */
    private array $options;

    /**
     * Constructor
     *
     * @param array|null $options Plugin options
     */
    public function __construct(?array $options = null)
    {
        $this->options = $options ?? get_option('webdecoy_options', []);

        $this->detector = new \WebDecoy\BotDetector([
            'sensitivity' => $this->options['sensitivity'] ?? 'medium',
            'allow_search_engines' => $this->options['allow_search_engines'] ?? true,
            'allow_social_bots' => $this->options['allow_social_bots'] ?? true,
            'block_ai_crawlers' => $this->options['block_ai_crawlers'] ?? false,
            'custom_allowlist' => $this->options['custom_allowlist'] ?? [],
        ]);
    }

    /**
     * Analyze current request
     *
     * @param array $additional_signals Additional signals to include
     * @return \WebDecoy\DetectionResult
     */
    public function analyze(array $additional_signals = []): \WebDecoy\DetectionResult
    {
        $collector = $this->detector->getSignalCollector();
        $signals = $collector->collect();

        // Add WordPress-specific signals
        $signals = array_merge($signals, $this->collect_wordpress_signals());

        // Add any additional signals passed in
        $signals = array_merge($signals, $additional_signals);

        return $this->detector->analyze($signals);
    }

    /**
     * Collect WordPress-specific signals
     *
     * @return array
     */
    private function collect_wordpress_signals(): array
    {
        $signals = [];

        // Add request path for path-based scoring (MITRE ATT&CK detection)
        $signals['request_path'] = $this->get_request_path();

        // Check if logged in user (less likely to be bot)
        $signals['is_logged_in'] = is_user_logged_in();

        // Check if admin request
        $signals['is_admin'] = is_admin();

        // Check if AJAX
        $signals['is_ajax'] = wp_doing_ajax();

        // Check if REST API request
        $signals['is_rest'] = defined('REST_REQUEST') && REST_REQUEST;

        // Check if XMLRPC request
        $signals['is_xmlrpc'] = defined('XMLRPC_REQUEST') && XMLRPC_REQUEST;

        // Check if cron request
        $signals['is_cron'] = wp_doing_cron();

        // Check for WordPress-specific cookies
        $signals['has_wp_cookies'] = $this->has_wordpress_cookies();

        // Check if accessing sensitive endpoints
        $signals['is_login_page'] = $this->is_login_page();
        $signals['is_register_page'] = $this->is_register_page();

        return $signals;
    }

    /**
     * Get the current request path
     *
     * @return string
     */
    private function get_request_path(): string
    {
        // Use REQUEST_URI which includes the full path and query string
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized with esc_url_raw below
        $request_uri = isset($_SERVER['REQUEST_URI']) ? wp_unslash($_SERVER['REQUEST_URI']) : '/';

        // Sanitize but preserve the structure for pattern matching
        return esc_url_raw($request_uri);
    }

    /**
     * Check if WordPress cookies are present
     *
     * @return bool
     */
    private function has_wordpress_cookies(): bool
    {
        foreach ($_COOKIE as $name => $value) {
            if (strpos($name, 'wordpress_') === 0 ||
                strpos($name, 'wp-') === 0 ||
                $name === 'comment_author_' ||
                $name === LOGGED_IN_COOKIE) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if on login page
     *
     * @return bool
     */
    private function is_login_page(): bool
    {
        return in_array(
            $GLOBALS['pagenow'] ?? '',
            ['wp-login.php', 'wp-register.php']
        );
    }

    /**
     * Check if on registration page
     *
     * @return bool
     */
    private function is_register_page(): bool
    {
        return ($GLOBALS['pagenow'] ?? '') === 'wp-login.php' &&
               isset($_REQUEST['action']) &&
               $_REQUEST['action'] === 'register';
    }

    /**
     * Quick bot check
     *
     * @return bool True if likely a bot
     */
    public function is_likely_bot(): bool
    {
        return $this->detector->isLikelyBot();
    }

    /**
     * Check if good bot
     *
     * @return array|null Bot info or null
     */
    public function identify_bot(): ?array
    {
        $ua = $this->detector->getSignalCollector()->getUserAgent();
        return $this->detector->identifyBot($ua);
    }

    /**
     * Get underlying SDK detector
     *
     * @return \WebDecoy\BotDetector
     */
    public function get_sdk_detector(): \WebDecoy\BotDetector
    {
        return $this->detector;
    }

    /**
     * Get signal collector
     *
     * @return \WebDecoy\SignalCollector
     */
    public function get_signal_collector(): \WebDecoy\SignalCollector
    {
        return $this->detector->getSignalCollector();
    }

    /**
     * Get good bot list
     *
     * @return \WebDecoy\GoodBotList
     */
    public function get_good_bot_list(): \WebDecoy\GoodBotList
    {
        return $this->detector->getGoodBotList();
    }

    /**
     * Log detection locally
     *
     * @param \WebDecoy\DetectionResult $result
     * @param string $ip
     */
    public function log_detection(\WebDecoy\DetectionResult $result, string $ip): void
    {
        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_detections';

        $wpdb->insert($table, [
            'ip_address' => $ip,
            'user_agent' => $this->get_signal_collector()->getUserAgent(),
            'score' => $result->getScore(),
            'threat_level' => $result->getThreatLevel(),
            'source' => 'wordpress_plugin',
            'flags' => json_encode($result->getFlags()),
            'created_at' => current_time('mysql'),
        ]);
    }

    /**
     * Get recent detections
     *
     * @param int $limit Number to retrieve
     * @return array
     */
    public function get_recent_detections(int $limit = 10): array
    {
        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_detections';

        return $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$table} ORDER BY created_at DESC LIMIT %d",
            $limit
        ), ARRAY_A) ?: [];
    }

    /**
     * Get detection stats
     *
     * @param int $days Number of days to look back
     * @return array
     */
    public function get_stats(int $days = 7): array
    {
        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_detections';
        $since = date('Y-m-d H:i:s', strtotime("-{$days} days"));

        $total = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$table} WHERE created_at > %s",
            $since
        ));

        $by_level = $wpdb->get_results($wpdb->prepare(
            "SELECT threat_level, COUNT(*) as count FROM {$table} WHERE created_at > %s GROUP BY threat_level",
            $since
        ), OBJECT_K);

        $by_day = $wpdb->get_results($wpdb->prepare(
            "SELECT DATE(created_at) as date, COUNT(*) as count FROM {$table} WHERE created_at > %s GROUP BY DATE(created_at) ORDER BY date",
            $since
        ), ARRAY_A);

        $high_risk = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$table} WHERE created_at > %s AND threat_level IN ('HIGH', 'CRITICAL')",
            $since
        ));

        return [
            'total' => (int) $total,
            'high_risk' => (int) $high_risk,
            'by_level' => $by_level,
            'by_day' => $by_day,
            'period_days' => $days,
        ];
    }

    /**
     * Get unique IPs detected
     *
     * @param int $days Number of days
     * @return int
     */
    public function get_unique_ips(int $days = 7): int
    {
        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_detections';
        $since = date('Y-m-d H:i:s', strtotime("-{$days} days"));

        return (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(DISTINCT ip_address) FROM {$table} WHERE created_at > %s",
            $since
        ));
    }
}
