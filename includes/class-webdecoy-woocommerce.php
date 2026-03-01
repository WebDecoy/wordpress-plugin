<?php
/**
 * WebDecoy WooCommerce Integration
 *
 * Provides carding attack protection for WooCommerce checkout
 * including velocity checks and card testing detection.
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
 * WebDecoy WooCommerce Class
 */
class WebDecoy_WooCommerce
{
    /**
     * Plugin options
     *
     * @var array
     */
    private array $options;

    /**
     * Blocker instance
     *
     * @var WebDecoy_Blocker
     */
    private WebDecoy_Blocker $blocker;

    /**
     * Constructor
     *
     * @param array $options Plugin options
     */
    public function __construct(array $options)
    {
        $this->options = $options;
        $this->blocker = new WebDecoy_Blocker();
    }

    /**
     * Check checkout request for suspicious activity
     */
    public function check_checkout(): void
    {
        if (!$this->options['protect_checkout']) {
            return;
        }

        $ip = $this->get_client_ip();

        // Check if already blocked
        if ($this->blocker->is_blocked($ip)) {
            wc_add_notice(
                __('Your checkout has been blocked due to suspicious activity.', 'webdecoy'),
                'error'
            );
            return;
        }

        // Check velocity
        if (!$this->check_velocity($ip)) {
            $this->blocker->block(
                $ip,
                'Checkout velocity exceeded',
                $this->options['block_duration'] > 0 ? $this->options['block_duration'] : null
            );

            wc_add_notice(
                __('Too many checkout attempts. Please try again later.', 'webdecoy'),
                'error'
            );

            $this->log_detection($ip, 'velocity_exceeded');
            return;
        }

        // Check for card testing patterns
        if ($this->detect_card_testing($ip)) {
            $this->blocker->block(
                $ip,
                'Card testing detected',
                $this->options['block_duration'] > 0 ? $this->options['block_duration'] : null
            );

            wc_add_notice(
                __('Suspicious checkout activity detected.', 'webdecoy'),
                'error'
            );

            $this->log_detection($ip, 'card_testing');
            return;
        }

        // Run bot detection
        $detector = new WebDecoy_Detector($this->options);
        $result = $detector->analyze();

        if ($result->shouldBlock($this->options['min_score_to_block'])) {
            $this->blocker->block(
                $ip,
                'Bot detected at checkout: score ' . $result->getScore(),
                $this->options['block_duration'] > 0 ? $this->options['block_duration'] : null
            );

            wc_add_notice(
                __('Your checkout has been blocked due to suspicious activity.', 'webdecoy'),
                'error'
            );

            $this->log_detection($ip, 'bot_detection', $result->getScore());
        }
    }

    /**
     * Check checkout velocity for an IP
     *
     * @param string $ip IP address
     * @return bool True if within limits
     */
    private function check_velocity(string $ip): bool
    {
        $limit = $this->options['checkout_velocity_limit'] ?? 5;
        $window = $this->options['checkout_velocity_window'] ?? 3600;

        $attempts = $this->get_recent_attempts($ip, $window);

        return count($attempts) < $limit;
    }

    /**
     * Detect card testing patterns
     *
     * @param string $ip IP address
     * @return bool True if card testing detected
     */
    private function detect_card_testing(string $ip): bool
    {
        $attempts = $this->get_recent_attempts($ip, 3600);

        if (count($attempts) < 2) {
            return false;
        }

        // Pattern 1: Multiple small amounts (< $5)
        $small_amounts = array_filter($attempts, function ($a) {
            return isset($a['amount']) && (float) $a['amount'] < 5.00;
        });

        if (count($small_amounts) >= 3) {
            return true;
        }

        // Pattern 2: Multiple declined transactions
        $declined = array_filter($attempts, function ($a) {
            return isset($a['status']) && $a['status'] === 'declined';
        });

        if (count($declined) >= 3) {
            return true;
        }

        // Pattern 3: Multiple different cards from same IP
        $card_last4s = array_unique(array_filter(array_column($attempts, 'card_last4')));

        if (count($card_last4s) >= 3) {
            return true;
        }

        // Pattern 4: Rapid succession of attempts (< 30 seconds apart)
        if (count($attempts) >= 3) {
            $timestamps = array_column($attempts, 'created_at');
            sort($timestamps);

            $rapid_count = 0;
            for ($i = 1; $i < count($timestamps); $i++) {
                $diff = strtotime($timestamps[$i]) - strtotime($timestamps[$i - 1]);
                if ($diff < 30) {
                    $rapid_count++;
                }
            }

            if ($rapid_count >= 2) {
                return true;
            }
        }

        return false;
    }

    /**
     * Track checkout attempt
     *
     * @param int $order_id Order ID
     */
    public function track_attempt(int $order_id): void
    {
        $order = wc_get_order($order_id);
        if (!$order) {
            return;
        }

        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_checkout_attempts';

        $wpdb->insert($table, [
            'ip_address' => $this->get_client_ip(),
            'order_id' => $order_id,
            'status' => 'attempt',
            'amount' => $order->get_total(),
            'card_last4' => $this->get_card_last4($order),
            'created_at' => current_time('mysql'),
        ]);
    }

    /**
     * Track successful payment
     *
     * @param int $order_id Order ID
     */
    public function track_payment(int $order_id): void
    {
        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_checkout_attempts';
        $ip = $this->get_client_ip();

        // Update most recent attempt for this IP/order to success
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is safe, built from $wpdb->prefix
        $wpdb->query($wpdb->prepare(
            "UPDATE {$table} SET status = 'success' WHERE ip_address = %s AND order_id = %d AND status = 'attempt'",
            $ip,
            $order_id
        ));
    }

    /**
     * Track failed payment
     *
     * @param int $order_id Order ID
     * @param string $reason Failure reason
     */
    public function track_failure(int $order_id, string $reason = 'failed'): void
    {
        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_checkout_attempts';
        $ip = $this->get_client_ip();

        // Determine status based on reason
        $status = 'failed';
        if (stripos($reason, 'decline') !== false ||
            stripos($reason, 'insufficient') !== false ||
            stripos($reason, 'card') !== false) {
            $status = 'declined';
        }

        // Update most recent attempt for this IP/order
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is safe, built from $wpdb->prefix
        $wpdb->query($wpdb->prepare(
            "UPDATE {$table} SET status = %s WHERE ip_address = %s AND order_id = %d AND status = 'attempt'",
            $status,
            $ip,
            $order_id
        ));
    }

    /**
     * Get recent checkout attempts for an IP
     *
     * @param string $ip IP address
     * @param int $window Time window in seconds
     * @return array
     */
    private function get_recent_attempts(string $ip, int $window): array
    {
        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_checkout_attempts';
        $since = gmdate('Y-m-d H:i:s', strtotime("-{$window} seconds"));

        return $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$table} WHERE ip_address = %s AND created_at > %s ORDER BY created_at DESC",
            $ip,
            $since
        ), ARRAY_A) ?: [];
    }

    /**
     * Get card last 4 digits from order
     *
     * @param \WC_Order $order
     * @return string|null
     */
    private function get_card_last4(\WC_Order $order): ?string
    {
        // Try to get from order meta
        $last4 = $order->get_meta('_card_last4');
        if ($last4) {
            return $last4;
        }

        // Try payment tokens
        $tokens = $order->get_payment_tokens();
        foreach ($tokens as $token_id) {
            $token = WC_Payment_Tokens::get($token_id);
            if ($token && method_exists($token, 'get_last4')) {
                return $token->get_last4();
            }
        }

        return null;
    }

    /**
     * Log detection to database and forward to WebDecoy
     *
     * @param string $ip
     * @param string $reason
     * @param int|null $score
     */
    private function log_detection(string $ip, string $reason, ?int $score = null): void
    {
        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_detections';
        $final_score = $score ?? 100;
        $source = 'woocommerce_' . $reason;

        // Log locally
        $wpdb->insert($table, [
            'ip_address' => $ip,
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field($_SERVER['HTTP_USER_AGENT']) : '',
            'score' => $final_score,
            'threat_level' => 'HIGH',
            'source' => $source,
            'created_at' => current_time('mysql'),
        ]);

        // Forward to WebDecoy ingest service
        $this->forward_to_webdecoy($ip, $source, $final_score, [$reason]);
    }

    /**
     * Forward detection to WebDecoy ingest service
     *
     * @param string $ip
     * @param string $source
     * @param int $score
     * @param array $flags
     */
    private function forward_to_webdecoy(string $ip, string $source, int $score, array $flags): void
    {
        // Check if API is configured
        if (empty($this->options['api_key']) || empty($this->options['organization_id'])) {
            return;
        }

        $ingest_url = rtrim($this->options['api_url'] ?? 'https://api.webdecoy.com', '/');
        $ingest_url = str_replace('api.webdecoy.com', 'ingest.webdecoy.com', $ingest_url);
        $ingest_url .= '/api/v1/detect';

        $collector = new \WebDecoy\SignalCollector();

        $payload = [
            'aid' => $this->options['organization_id'],
            'sid' => $this->options['scanner_id'] ?? ('wordpress-woo-' . get_site_url()),
            'v' => 1,
            's' => $score,
            'f' => $flags,
            'fp' => [
                'userAgent' => $collector->getUserAgent(),
                'ip' => $ip,
            ],
            'url' => $collector->getCurrentUrl(),
            'ref' => isset($_SERVER['HTTP_REFERER']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_REFERER'])) : '', // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
            'ts' => time() * 1000,
            'source' => $source,
            'blocked' => true,
        ];

        // Send to ingest (fire-and-forget)
        wp_remote_post($ingest_url, [
            'timeout' => 1,
            'blocking' => false,
            'headers' => [
                'Content-Type' => 'application/json',
                'Authorization' => 'Bearer ' . $this->options['api_key'],
            ],
            'body' => json_encode($payload),
        ]);
    }

    /**
     * Get client IP
     *
     * @return string
     */
    private function get_client_ip(): string
    {
        $collector = new \WebDecoy\SignalCollector();
        return $collector->getIP();
    }

    /**
     * Get client IP - public accessor for Blocks integration
     *
     * @return string
     */
    public function get_client_ip_public(): string
    {
        return $this->get_client_ip();
    }

    /**
     * Check velocity - public accessor for Blocks integration
     *
     * @param string $ip
     * @return bool
     */
    public function check_velocity_public(string $ip): bool
    {
        return $this->check_velocity($ip);
    }

    /**
     * Detect card testing - public accessor for Blocks integration
     *
     * @param string $ip
     * @return bool
     */
    public function detect_card_testing_public(string $ip): bool
    {
        return $this->detect_card_testing($ip);
    }

    /**
     * Get checkout attempt stats
     *
     * @param int $days Number of days
     * @return array
     */
    public function get_stats(int $days = 7): array
    {
        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_checkout_attempts';
        $since = gmdate('Y-m-d H:i:s', strtotime("-{$days} days"));

        $total = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$table} WHERE created_at > %s",
            $since
        ));

        $by_status = $wpdb->get_results($wpdb->prepare(
            "SELECT status, COUNT(*) as count FROM {$table} WHERE created_at > %s GROUP BY status",
            $since
        ), OBJECT_K);

        $unique_ips = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(DISTINCT ip_address) FROM {$table} WHERE created_at > %s",
            $since
        ));

        $blocked = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM (
                SELECT ip_address FROM {$table}
                WHERE created_at > %s AND status IN ('declined', 'failed')
                GROUP BY ip_address HAVING COUNT(*) >= 3
            ) AS suspicious_ips",
            $since
        ));

        return [
            'total_attempts' => (int) $total,
            'by_status' => $by_status,
            'unique_ips' => (int) $unique_ips,
            'blocked_ips' => (int) $blocked,
            'period_days' => $days,
        ];
    }

    /**
     * Get suspicious IPs from checkout attempts
     *
     * @param int $threshold Number of failed attempts to be considered suspicious
     * @return array
     */
    public function get_suspicious_ips(int $threshold = 3): array
    {
        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_checkout_attempts';
        $since = gmdate('Y-m-d H:i:s', strtotime('-24 hours'));

        return $wpdb->get_results($wpdb->prepare(
            "SELECT ip_address, COUNT(*) as attempts,
                    SUM(CASE WHEN status = 'declined' THEN 1 ELSE 0 END) as declined,
                    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
                    COUNT(DISTINCT card_last4) as unique_cards
             FROM {$table}
             WHERE created_at > %s
             GROUP BY ip_address
             HAVING declined >= %d OR failed >= %d OR unique_cards >= 3
             ORDER BY attempts DESC",
            $since,
            $threshold,
            $threshold
        ), ARRAY_A) ?: [];
    }
}

// Hook into WooCommerce payment completion - track success
add_action('woocommerce_payment_complete', function ($order_id) {
    $options = get_option('webdecoy_options', []);
    if (empty($options['protect_checkout'])) {
        return;
    }

    $woo = new WebDecoy_WooCommerce($options);
    $woo->track_payment($order_id);
});

// Hook into payment failure notifications
add_action('woocommerce_order_status_failed', function ($order_id) {
    $options = get_option('webdecoy_options', []);
    if (empty($options['protect_checkout'])) {
        return;
    }

    $woo = new WebDecoy_WooCommerce($options);
    $woo->track_failure($order_id);
});

/**
 * WooCommerce Blocks Checkout Integration
 *
 * Extends WooCommerce Store API to validate checkout requests
 * from the block-based Cart and Checkout blocks.
 */
add_action('woocommerce_blocks_loaded', function () {
    if (!class_exists('Automattic\WooCommerce\StoreApi\Schemas\V1\CheckoutSchema')) {
        return;
    }

    // Hook into Store API checkout validation
    add_action(
        'woocommerce_store_api_checkout_update_order_from_request',
        function ($order, $request) {
            $options = get_option('webdecoy_options', []);
            if (empty($options['protect_checkout'])) {
                return;
            }

            $woo = new WebDecoy_WooCommerce($options);
            $ip = $woo->get_client_ip_public();

            // Check if already blocked
            $blocker = new WebDecoy_Blocker();
            if ($blocker->is_blocked($ip)) {
                throw new \Automattic\WooCommerce\StoreApi\Exceptions\RouteException(
                    'webdecoy_blocked',
                    __('Your checkout has been blocked due to suspicious activity.', 'webdecoy'),
                    403
                );
            }

            // Check velocity
            if (!$woo->check_velocity_public($ip)) {
                $blocker->block(
                    $ip,
                    'Checkout velocity exceeded (Blocks)',
                    $options['block_duration'] > 0 ? $options['block_duration'] : null
                );

                throw new \Automattic\WooCommerce\StoreApi\Exceptions\RouteException(
                    'webdecoy_velocity',
                    __('Too many checkout attempts. Please try again later.', 'webdecoy'),
                    429
                );
            }

            // Check for card testing patterns
            if ($woo->detect_card_testing_public($ip)) {
                $blocker->block(
                    $ip,
                    'Card testing detected (Blocks)',
                    $options['block_duration'] > 0 ? $options['block_duration'] : null
                );

                throw new \Automattic\WooCommerce\StoreApi\Exceptions\RouteException(
                    'webdecoy_carding',
                    __('Suspicious checkout activity detected.', 'webdecoy'),
                    403
                );
            }
        },
        10,
        2
    );

    // Track checkout attempt after order is processed
    add_action(
        'woocommerce_store_api_checkout_order_processed',
        function ($order) {
            $options = get_option('webdecoy_options', []);
            if (empty($options['protect_checkout'])) {
                return;
            }

            $woo = new WebDecoy_WooCommerce($options);
            $woo->track_attempt($order->get_id());
        },
        10,
        1
    );
});
