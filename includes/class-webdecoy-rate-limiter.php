<?php
/**
 * WebDecoy Rate Limiter
 *
 * Implements per-IP rate limiting to prevent abuse
 * and detect automated requests.
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
 * WebDecoy Rate Limiter Class
 */
class WebDecoy_Rate_Limiter
{
    /**
     * Default requests per window
     */
    private const DEFAULT_LIMIT = 60;

    /**
     * Default window in seconds
     */
    private const DEFAULT_WINDOW = 60;

    /**
     * Max requests per window
     *
     * @var int
     */
    private int $limit;

    /**
     * Time window in seconds
     *
     * @var int
     */
    private int $window;

    /**
     * Constructor
     *
     * @param int|null $limit Requests per window
     * @param int|null $window Time window in seconds
     */
    public function __construct(?int $limit = null, ?int $window = null)
    {
        $options = get_option('webdecoy_options', []);

        $this->limit = $limit ?? ($options['rate_limit_requests'] ?? self::DEFAULT_LIMIT);
        $this->window = $window ?? ($options['rate_limit_window'] ?? self::DEFAULT_WINDOW);
    }

    /**
     * Check if rate limit is exceeded for an IP
     *
     * @param string $ip IP address
     * @return bool True if exceeded
     */
    public function is_exceeded(string $ip): bool
    {
        $count = $this->get_count($ip);
        return $count >= $this->limit;
    }

    /**
     * Increment request count for an IP
     *
     * @param string $ip IP address
     * @return int New count
     */
    public function increment(string $ip): int
    {
        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_rate_limits';
        $now = current_time('mysql');
        $window_start = date('Y-m-d H:i:s', strtotime("-{$this->window} seconds"));

        // Check for existing record in current window
        $existing = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$table} WHERE ip_address = %s AND window_start > %s",
            $ip,
            $window_start
        ), ARRAY_A);

        if ($existing) {
            // Increment existing count
            $new_count = (int) $existing['request_count'] + 1;
            $wpdb->update(
                $table,
                ['request_count' => $new_count],
                ['ip_address' => $ip]
            );
            return $new_count;
        } else {
            // Delete old record if exists and create new
            $wpdb->delete($table, ['ip_address' => $ip]);
            $wpdb->insert($table, [
                'ip_address' => $ip,
                'request_count' => 1,
                'window_start' => $now,
            ]);
            return 1;
        }
    }

    /**
     * Get current request count for an IP
     *
     * @param string $ip IP address
     * @return int Current count
     */
    public function get_count(string $ip): int
    {
        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_rate_limits';
        $window_start = date('Y-m-d H:i:s', strtotime("-{$this->window} seconds"));

        $count = $wpdb->get_var($wpdb->prepare(
            "SELECT request_count FROM {$table} WHERE ip_address = %s AND window_start > %s",
            $ip,
            $window_start
        ));

        return (int) ($count ?? 0);
    }

    /**
     * Get remaining requests for an IP
     *
     * @param string $ip IP address
     * @return int Remaining requests
     */
    public function get_remaining(string $ip): int
    {
        $count = $this->get_count($ip);
        return max(0, $this->limit - $count);
    }

    /**
     * Get time until window resets for an IP
     *
     * @param string $ip IP address
     * @return int Seconds until reset, 0 if no active window
     */
    public function get_reset_time(string $ip): int
    {
        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_rate_limits';
        $window_start_threshold = date('Y-m-d H:i:s', strtotime("-{$this->window} seconds"));

        $window_start = $wpdb->get_var($wpdb->prepare(
            "SELECT window_start FROM {$table} WHERE ip_address = %s AND window_start > %s",
            $ip,
            $window_start_threshold
        ));

        if (!$window_start) {
            return 0;
        }

        $reset_time = strtotime($window_start) + $this->window;
        $remaining = $reset_time - time();

        return max(0, $remaining);
    }

    /**
     * Reset rate limit for an IP
     *
     * @param string $ip IP address
     * @return bool Success
     */
    public function reset(string $ip): bool
    {
        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_rate_limits';

        return $wpdb->delete($table, ['ip_address' => $ip]) !== false;
    }

    /**
     * Clean up old rate limit records
     *
     * @return int Number of rows deleted
     */
    public function cleanup(): int
    {
        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_rate_limits';
        $threshold = date('Y-m-d H:i:s', strtotime('-1 hour'));

        return $wpdb->query($wpdb->prepare(
            "DELETE FROM {$table} WHERE window_start < %s",
            $threshold
        ));
    }

    /**
     * Get rate limit headers
     *
     * @param string $ip IP address
     * @return array Headers to send
     */
    public function get_headers(string $ip): array
    {
        return [
            'X-RateLimit-Limit' => $this->limit,
            'X-RateLimit-Remaining' => $this->get_remaining($ip),
            'X-RateLimit-Reset' => time() + $this->get_reset_time($ip),
        ];
    }

    /**
     * Send rate limit headers
     *
     * @param string $ip IP address
     */
    public function send_headers(string $ip): void
    {
        if (headers_sent()) {
            return;
        }

        foreach ($this->get_headers($ip) as $name => $value) {
            header("{$name}: {$value}");
        }
    }

    /**
     * Get configured limit
     *
     * @return int
     */
    public function get_limit(): int
    {
        return $this->limit;
    }

    /**
     * Get configured window
     *
     * @return int
     */
    public function get_window(): int
    {
        return $this->window;
    }

    /**
     * Set limit
     *
     * @param int $limit
     * @return self
     */
    public function set_limit(int $limit): self
    {
        $this->limit = max(1, $limit);
        return $this;
    }

    /**
     * Set window
     *
     * @param int $window
     * @return self
     */
    public function set_window(int $window): self
    {
        $this->window = max(1, $window);
        return $this;
    }

    /**
     * Get stats
     *
     * @return array Statistics
     */
    public function get_stats(): array
    {
        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_rate_limits';
        $window_start = date('Y-m-d H:i:s', strtotime("-{$this->window} seconds"));

        $active_ips = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(DISTINCT ip_address) FROM {$table} WHERE window_start > %s",
            $window_start
        ));

        $total_requests = $wpdb->get_var($wpdb->prepare(
            "SELECT SUM(request_count) FROM {$table} WHERE window_start > %s",
            $window_start
        ));

        $exceeded = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$table} WHERE window_start > %s AND request_count >= %d",
            $window_start,
            $this->limit
        ));

        return [
            'active_ips' => (int) $active_ips,
            'total_requests' => (int) $total_requests,
            'exceeded_count' => (int) $exceeded,
            'limit' => $this->limit,
            'window' => $this->window,
        ];
    }
}
