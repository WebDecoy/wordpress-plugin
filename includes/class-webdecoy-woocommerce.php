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

        // Monitor mode, WEBDECOY_DISABLE and an unconfigured proxy all mean "watch,
        // don't act". That has to hold on the checkout path too — an error notice in
        // woocommerce_checkout_process aborts the order, so an ungated refusal here
        // means a store takes no money while the admin banner says nothing is blocked,
        // and none of the three off switches help. Detection and logging stay
        // unconditional; only the notice is withheld.
        //
        // The checkout path also never writes a sitewide IP block: behind an
        // unconfigured proxy every shopper shares one address, so one false positive
        // would 403 the whole store on every page. Refusing this order is already the
        // proportionate response. Refs #52, #56.
        $suppressed = $this->suppressed();

        // Check if already blocked
        if ($this->blocker->is_blocked($ip) && !$suppressed) {
            wc_add_notice(
                __('Your checkout has been blocked due to suspicious activity.', 'webdecoy'),
                'error'
            );
            return;
        }

        // Check velocity
        if (!$this->check_velocity($ip)) {
            $this->log_detection($ip, 'velocity_exceeded');
            if (!$suppressed) {
                wc_add_notice(
                    __('Too many checkout attempts. Please try again later.', 'webdecoy'),
                    'error'
                );
            }
            return;
        }

        // Check for card testing patterns
        if ($this->detect_card_testing($ip)) {
            $this->log_detection($ip, 'card_testing');
            if (!$suppressed) {
                wc_add_notice(
                    __('Suspicious checkout activity detected.', 'webdecoy'),
                    'error'
                );
            }
            return;
        }

        // Run bot detection
        $detector = new WebDecoy_Detector($this->options);
        $result = $detector->analyze();

        if ($result->shouldBlock($this->options['min_score_to_block'])) {
            $this->log_detection($ip, 'bot_detection', $result->getScore());
            if (!$suppressed) {
                wc_add_notice(
                    __('Your checkout has been blocked due to suspicious activity.', 'webdecoy'),
                    'error'
                );
            }
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

        // A completed order is not a failed checkout attempt. Counting successes
        // here throttled legitimate repeat buyers. Refs #52.
        $attempts = $this->get_recent_attempts($ip, $window, false);

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
        // Successful orders are not evidence of card testing. track_payment() only
        // flips a row's status to 'success' and never removes it, so without this
        // filter three completed sub-$5 orders from one address in an hour — the
        // normal profile for digital downloads, donations, tips and add-ons — read
        // as an attack. Refs WebDecoy/wordpress-plugin#52.
        $attempts = $this->get_recent_attempts($ip, 3600, false);

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
    private function get_recent_attempts(string $ip, int $window, bool $include_successful = true): array
    {
        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_checkout_attempts';
        $since = gmdate('Y-m-d H:i:s', strtotime("-{$window} seconds"));

        if ($include_successful) {
            return $wpdb->get_results($wpdb->prepare(
                "SELECT * FROM {$table} WHERE ip_address = %s AND created_at > %s ORDER BY created_at DESC",
                $ip,
                $since
            ), ARRAY_A) ?: [];
        }

        return $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$table} WHERE ip_address = %s AND created_at > %s AND status <> 'success' ORDER BY created_at DESC",
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
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '',
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
     * True when the plugin is in a watch-only state — monitor mode, WEBDECOY_DISABLE,
     * or an unconfigured reverse proxy. Public so the Store API closure can consult it.
     *
     * Fails CLOSED to "not suppressed" only if the main plugin class is unavailable,
     * which cannot happen while this class is loaded by it.
     */
    public function suppressed(): bool
    {
        if (defined('WEBDECOY_DISABLE') && WEBDECOY_DISABLE) {
            return true;
        }
        if (function_exists('webdecoy')) {
            return webdecoy()->enforcement_suppressed();
        }
        return !empty($this->options['monitor_mode']);
    }

    /**
     * Record a detection - public accessor for the Store API / Blocks integration,
     * which refuses the order via RouteException and must still leave a record.
     *
     * @param string $ip
     * @param string $reason
     * @param int|null $score
     */
    public function log_detection_public(string $ip, string $reason, ?int $score = null): void
    {
        $this->log_detection($ip, $reason, $score);
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

    /**
     * The honeytoken coupon code for this site — a fake promo code planted where
     * coupon-scraping bots look but no human ever sees. Deterministic from a
     * per-site secret; optionally rotates daily. Applying it is, by
     * construction, an automated action.
     */
    public function honeytoken_coupon(bool $rotate = false): string
    {
        $secret = get_option('webdecoy_coupon_secret', '');
        if (!is_string($secret) || $secret === '') {
            $secret = bin2hex(random_bytes(16));
            add_option('webdecoy_coupon_secret', $secret, '', 'yes');
        }
        $label = $rotate ? ('day:' . gmdate('Y-m-d')) : 'stable';
        return 'WD' . strtoupper(substr(hash_hmac('sha256', $label, $secret), 0, 8));
    }

    /**
     * Hidden markup exposing the honeytoken coupon to page scrapers only. Placed
     * in an HTML comment plus an offscreen, aria-hidden node so it never appears
     * to a human or in the accessibility tree.
     */
    public function render_coupon_bait(): void
    {
        if (empty($this->options['woo_honeytoken_coupons'])) {
            return;
        }
        $code = $this->honeytoken_coupon(!empty($this->options['honeytoken_rotate']));
        echo "\n<!-- promo code: " . esc_html($code) . " -->\n";
        echo '<div aria-hidden="true" style="position:absolute;left:-9999px;top:auto;width:1px;height:1px;overflow:hidden">'
            . '<span class="wd-promo" data-coupon="' . esc_attr($code) . '">' . esc_html($code) . '</span></div>' . "\n";
    }

    /**
     * Coupon-load filter: if the code being applied is our honeytoken, record a
     * detection (and optionally block), then report it invalid. Runs for both
     * classic checkout and the Store API / Blocks, since both load coupons via
     * WC_Coupon → this filter. Real coupons are untouched.
     *
     * @param mixed  $data   Coupon data (false when no matching coupon post).
     * @param string $code   The coupon code being looked up.
     * @return mixed
     */
    public function catch_coupon($data, string $code)
    {
        if (empty($this->options['woo_honeytoken_coupons'])) {
            return $data;
        }

        $canary = $this->honeytoken_coupon(!empty($this->options['honeytoken_rotate']));
        // Also honor the previous day's code during rotation grace.
        $prev = null;
        if (!empty($this->options['honeytoken_rotate'])) {
            $secret = get_option('webdecoy_coupon_secret', '');
            if (is_string($secret) && $secret !== '') {
                $prev = 'WD' . strtoupper(substr(hash_hmac('sha256', 'day:' . gmdate('Y-m-d', time() - DAY_IN_SECONDS), $secret), 0, 8));
            }
        }

        $normalized = strtoupper(trim($code));
        if ($normalized === $canary || ($prev !== null && $normalized === $prev)) {
            $ip = $this->get_client_ip();
            $this->log_detection($ip, 'honeytoken_coupon', 100);

            // This is a real write to the sitewide block table, so it passes the same
            // gate as every other enforcement action — it was firing in monitor mode
            // under a banner reading "nothing is blocked" (#56). Rejecting the coupon
            // is not enforcement: the code does not exist, and answering as though it
            // does not is the deception working.
            if (($this->options['block_action'] ?? 'block') === 'block' && !$this->suppressed()) {
                $duration = (int) ($this->options['block_duration'] ?? 1);
                $this->blocker->block(
                    $ip,
                    'Honeytoken coupon applied',
                    $duration > 0 ? $duration : null
                );
            }

            return false; // reject as a non-existent coupon
        }

        return $data;
    }
}

// Honeytoken coupons: plant a hidden fake code and catch anyone who applies it.
add_action('woocommerce_before_cart', function () {
    $options = get_option('webdecoy_options', []);
    if (empty($options['protect_checkout']) || empty($options['woo_honeytoken_coupons'])) {
        return;
    }
    (new WebDecoy_WooCommerce($options))->render_coupon_bait();
});
add_action('woocommerce_before_checkout_form', function () {
    $options = get_option('webdecoy_options', []);
    if (empty($options['protect_checkout']) || empty($options['woo_honeytoken_coupons'])) {
        return;
    }
    (new WebDecoy_WooCommerce($options))->render_coupon_bait();
});
add_filter('woocommerce_get_shop_coupon_data', function ($data, $code) {
    $options = get_option('webdecoy_options', []);
    if (empty($options['protect_checkout']) || empty($options['woo_honeytoken_coupons'])) {
        return $data;
    }
    return (new WebDecoy_WooCommerce($options))->catch_coupon($data, (string) $code);
}, 10, 2);

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

            // Suppressed states apply here exactly as on the classic path (#56).
            $suppressed = $woo->suppressed();

            // Check if already blocked
            $blocker = new WebDecoy_Blocker();
            if ($blocker->is_blocked($ip) && !$suppressed) {
                throw new \Automattic\WooCommerce\StoreApi\Exceptions\RouteException(
                    'webdecoy_blocked',
                    esc_html(__('Your checkout has been blocked due to suspicious activity.', 'webdecoy')),
                    403
                );
            }

            // As on the classic checkout path, refusing the order IS the response.
            // The RouteException below already stops it with a 429/403. Writing a
            // sitewide IP block from here would, behind an unconfigured proxy where
            // every shopper shares one address, 403 the whole store on every page
            // from a single checkout false positive.
            // Refs WebDecoy/wordpress-plugin#52.

            // Check velocity
            if (!$woo->check_velocity_public($ip)) {
                $woo->log_detection_public($ip, 'velocity_exceeded');
                if ($suppressed) {
                    return;
                }
                throw new \Automattic\WooCommerce\StoreApi\Exceptions\RouteException(
                    'webdecoy_velocity',
                    esc_html(__('Too many checkout attempts. Please try again later.', 'webdecoy')),
                    429
                );
            }

            // Check for card testing patterns
            if ($woo->detect_card_testing_public($ip)) {
                $woo->log_detection_public($ip, 'card_testing');
                if ($suppressed) {
                    return;
                }
                throw new \Automattic\WooCommerce\StoreApi\Exceptions\RouteException(
                    'webdecoy_carding',
                    esc_html(__('Suspicious checkout activity detected.', 'webdecoy')),
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
