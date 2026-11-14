<?php
/**
 * Request outcomes recorded by this plugin, independently of detection rows.
 * Only UTC hour, outcome and count are stored; no visitor identifiers.
 *
 * @package WebDecoy
 */
if (!defined('ABSPATH')) {
    exit;
}

class WebDecoy_Request_Counts
{
    public const SINCE_DB_VERSION = '2.11.1';
    public const RETENTION_DAYS = 30;
    private const PRIORITIES = ['withheld' => 1, 'challenged' => 2, 'throttled' => 3, 'blocked' => 4];
    private static string $pending = '';
    private static bool $registered = false;
    private static bool $flushed = false;
    private static ?int $blog_id = null;

    /** Mark an actual enforcement path; repeated marks still produce one row increment. */
    public static function mark(string $outcome): void
    {
        if (PHP_SAPI === 'cli' || self::$flushed || (defined('WEBDECOY_DISABLE') && WEBDECOY_DISABLE)) {
            return;
        }
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
        if (self::is_setup_test($ua)) {
            return;
        }
        $chosen = self::choose(self::$pending, $outcome);
        if ($chosen !== self::$pending) {
            self::$blog_id = get_current_blog_id();
        }
        self::$pending = $chosen;
        if (self::$pending !== '' && !self::$registered) {
            self::$registered = true;
            register_shutdown_function([self::class, 'flush']);
        }
    }

    /** Stronger enforcement supersedes a withheld/challenge decision in one request. */
    public static function choose(string $previous, string $next): string
    {
        if (!isset(self::PRIORITIES[$next])) {
            return $previous;
        }
        return (self::PRIORITIES[$next] > (self::PRIORITIES[$previous] ?? 0)) ? $next : $previous;
    }

    public static function is_setup_test(string $user_agent): bool
    {
        return stripos(ltrim($user_agent), 'WebDecoy-Test/') === 0;
    }

    /** A marked response must actually finish with the matching HTTP status. */
    public static function matches_response(string $outcome, int $status): bool
    {
        if ($outcome === 'blocked' || $outcome === 'challenged') {
            return $status === 403;
        }
        if ($outcome === 'throttled') {
            return $status === 429;
        }
        // A withheld decision is not a denial, whatever later code returns.
        return $outcome === 'withheld';
    }

    public static function table(): string
    {
        global $wpdb;
        return esc_sql($wpdb->prefix . 'webdecoy_request_counts');
    }

    /** Final response accounting cannot interfere with the protection response. */
    public static function flush(): void
    {
        if (self::$flushed) {
            return;
        }
        self::$flushed = true;
        if (!self::matches_response(self::$pending, (int) http_response_code())) {
            return;
        }
        $switched = false;
        $previous_errors = null;
        try {
            global $wpdb;
            $previous_errors = $wpdb->suppress_errors(true);
            // A later switch_to_blog must not attribute this request to another site.
            if (self::$blog_id !== null && get_current_blog_id() !== self::$blog_id) {
                switch_to_blog(self::$blog_id);
                $switched = true;
            }
            if (!self::ready()) {
                return;
            }
            $table = self::table();
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- trusted table prefix; outcome is a closed enum
            $wpdb->query($wpdb->prepare(
                "INSERT INTO {$table} (bucket, outcome, hits) VALUES (%s, %s, 1) ON DUPLICATE KEY UPDATE hits = hits + 1",
                gmdate('Y-m-d H:00:00'),
                self::$pending
            ));
        } catch (\Throwable $error) {
            // Observability must never turn a completed denial into an error page.
            unset($error);
        } finally {
            if ($switched) {
                try {
                    restore_current_blog();
                } catch (\Throwable $error) {
                    unset($error);
                }
            }
            if ($previous_errors !== null) {
                try {
                    $wpdb->suppress_errors($previous_errors);
                } catch (\Throwable $error) {
                    unset($error);
                }
            }
        }
    }

    /** UTC calendar days, including today. No rolling/calendar window mismatch. */
    public static function window(int $days, ?int $now = null): array
    {
        $now = $now ?? time();
        $days = max(1, min(self::RETENTION_DAYS, $days));
        return [
            'from' => gmdate('Y-m-d 00:00:00', $now - ($days - 1) * 86400),
            'until' => gmdate('Y-m-d 00:00:00', $now + 86400),
        ];
    }

    public static function summarize(array $rows): array
    {
        $totals = ['blocked' => 0, 'throttled' => 0, 'challenged' => 0, 'withheld' => 0];
        foreach ($rows as $row) {
            $outcome = (string) ($row['outcome'] ?? '');
            if (isset($totals[$outcome]) && is_numeric($row['hits'] ?? null)) {
                $totals[$outcome] += max(0, (int) $row['hits']);
            }
        }
        return $totals;
    }

    /** Saved findings and request outcomes use exactly the same date boundaries. */
    public static function summary(int $days): array
    {
        $window = self::window($days);
        $result = array_merge(self::summarize([]), $window, [
            'available' => false,
            'detections' => 0,
            'started_at' => (int) get_option('webdecoy_request_counts_started_at', 0),
        ]);
        if (!self::ready()) {
            return $result;
        }
        global $wpdb;
        $table = self::table();
        $detections = esc_sql($wpdb->prefix . 'webdecoy_detections');
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- trusted table prefix
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT outcome, SUM(hits) AS hits FROM {$table} WHERE bucket >= %s AND bucket < %s GROUP BY outcome",
            $window['from'], $window['until']
        ), ARRAY_A);
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- trusted table prefix
        $count = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$detections} WHERE created_at >= %s AND created_at < %s",
            $window['from'], $window['until']
        ));
        if (!is_array($rows) || $count === null) {
            return $result;
        }
        return array_merge($result, self::summarize($rows), ['available' => true, 'detections' => (int) $count]);
    }

    public static function prune(): void
    {
        if (!self::ready()) {
            return;
        }
        global $wpdb;
        $table = self::table();
        $window = self::window(self::RETENTION_DAYS);
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- trusted table prefix
        $wpdb->query($wpdb->prepare("DELETE FROM {$table} WHERE bucket < %s", $window['from']));
    }

    private static function ready(): bool
    {
        return version_compare((string) get_option('webdecoy_db_version', '0'), self::SINCE_DB_VERSION, '>=')
            && (int) get_option('webdecoy_request_counts_started_at', 0) > 0;
    }
}
