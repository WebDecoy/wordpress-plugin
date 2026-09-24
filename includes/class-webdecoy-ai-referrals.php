<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Counts page visits that AI products (ChatGPT, Claude, Perplexity, Gemini,
 * Copilot and others) send to this site, for WebDecoy's AI Traffic page.
 *
 * Aggregate counts only: an AI platform, a landing path and a number. Nothing
 * about a visitor (IP, user agent, cookie, query string, full referrer) is
 * stored or sent. Only a browser loading a page counts: a GET whose fetch
 * metadata says it is a document navigation. Pages served from a full-page
 * cache never reach PHP and are not counted, so the figure is a floor.
 *
 * Counts accumulate in one small table and are sent every fifteen minutes when
 * the site is connected to WebDecoy Cloud. Each send claims the open counts
 * under a batch id; a failed send keeps that id and is retried with it, and
 * WebDecoy counts a batch id once.
 */
class WebDecoy_AI_Referrals
{
    public const CRON_HOOK = 'webdecoy_flush_ai_referrals';
    private const ENDPOINT = 'https://in.webdecoy.com/api/v1/sdk/ai-referrals';
    private const MAX_PATH = 500;
    /** Rows sent per batch; the endpoint takes up to 500. */
    private const BATCH_SIZE = 500;
    /** Distinct platform and path pairs kept before new ones are dropped. */
    private const MAX_ROWS = 5000;

    public static function table(): string
    {
        global $wpdb;
        return $wpdb->prefix . 'webdecoy_ai_referrals';
    }

    /**
     * Whether counting runs: connected to WebDecoy Cloud, and not turned off
     * with the webdecoy_count_ai_referrals filter.
     */
    public static function enabled(string $apiKey): bool
    {
        return $apiKey !== '' && (bool) apply_filters('webdecoy_count_ai_referrals', true);
    }

    /** Wire the counter and its flush, scheduling the flush if it is not. */
    public static function register(string $apiKey): void
    {
        if (!self::enabled($apiKey)) {
            return;
        }
        add_action('template_redirect', [self::class, 'observe'], 1);
        add_action(self::CRON_HOOK, static function () use ($apiKey): void {
            self::flush($apiKey);
        });
        if (function_exists('wp_next_scheduled') && !wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_event(time() + 900, 'fifteen_minutes', self::CRON_HOOK);
        }
    }

    /** Count the current request if it is a page visit an AI product sent. */
    public static function observe(): void
    {
        // phpcs:disable WordPress.Security.ValidatedSanitizedInput -- compared and classified, never stored or echoed
        $method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? ''));
        $mode = (string) ($_SERVER['HTTP_SEC_FETCH_MODE'] ?? '');
        $dest = (string) ($_SERVER['HTTP_SEC_FETCH_DEST'] ?? '');
        $referer = wp_unslash((string) ($_SERVER['HTTP_REFERER'] ?? ''));
        $uri = (string) ($_SERVER['REQUEST_URI'] ?? '/');
        // phpcs:enable
        $platform = self::classifyRequest($method, $mode, $dest, $referer, $uri);
        if ($platform === '') {
            return;
        }
        self::increment($platform, self::landingPath($uri));
    }

    /**
     * The AI platform a request came from, or '' when it is not a page visit
     * an AI product sent. Pure, for tests.
     */
    public static function classifyRequest(string $method, string $mode, string $dest, string $referer, string $uri): string
    {
        if ($method !== 'GET' || $mode !== 'navigate' || ($dest !== '' && $dest !== 'document')) {
            return '';
        }
        return \WebDecoy\LlmReferral::classify($referer, 'https://site.invalid' . $uri);
    }

    /** The path of a request URI, cut to the width WebDecoy stores. */
    public static function landingPath(string $uri): string
    {
        $path = (string) (parse_url($uri, PHP_URL_PATH) ?: '/');
        if ($path === '' || $path[0] !== '/') {
            $path = '/' . $path;
        }
        if (strlen($path) > self::MAX_PATH) {
            $path = substr($path, 0, self::MAX_PATH);
        }
        return mb_check_encoding($path, 'UTF-8') ? $path : '/';
    }

    private static function increment(string $platform, string $path): void
    {
        global $wpdb;
        $table = self::table();
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix
        $rows = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$table}");
        $key = sha1($platform . "\n" . $path);
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $exists = (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$table} WHERE ref_key = %s AND batch_id = ''", $key));
        if ($rows >= self::MAX_ROWS && $exists === 0) {
            return; // Bounded: a new pair is dropped rather than growing the table.
        }
        // phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix
        $wpdb->query($wpdb->prepare(
            "INSERT INTO {$table} (ref_key, batch_id, platform, landing_path, referrals) VALUES (%s, '', %s, %s, 1)
             ON DUPLICATE KEY UPDATE referrals = referrals + 1",
            $key,
            $platform,
            $path
        ));
        // phpcs:enable
    }

    /**
     * Send counted referrals. A batch that failed before is resent under its
     * own id first; otherwise the open counts are claimed under a new one.
     */
    public static function flush(string $apiKey): void
    {
        if ($apiKey === '' || !function_exists('wp_remote_post')) {
            return;
        }
        global $wpdb;
        $table = self::table();
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $batch = (string) $wpdb->get_var("SELECT batch_id FROM {$table} WHERE batch_id <> '' LIMIT 1");
        if ($batch === '') {
            $batch = wp_generate_uuid4();
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $claimed = (int) $wpdb->query($wpdb->prepare("UPDATE {$table} SET batch_id = %s WHERE batch_id = '' LIMIT %d", $batch, self::BATCH_SIZE));
            if ($claimed === 0) {
                return;
            }
        }
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $rows = $wpdb->get_results($wpdb->prepare("SELECT platform, landing_path, referrals FROM {$table} WHERE batch_id = %s", $batch));
        $referrals = [];
        foreach ((array) $rows as $row) {
            $referrals[] = [
                'platform' => (string) $row->platform,
                'path' => (string) $row->landing_path,
                'count' => (int) $row->referrals,
            ];
        }
        if ($referrals === [] || self::send($apiKey, $batch, $referrals)) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery
            $wpdb->delete($table, ['batch_id' => $batch]);
        }
    }

    /**
     * True when the batch needs no retry: accepted, or refused for a reason a
     * retry cannot fix (a 4xx, such as a key not scoped to one site).
     *
     * @param array<int, array{platform: string, path: string, count: int}> $referrals
     */
    private static function send(string $apiKey, string $batch, array $referrals): bool
    {
        $response = wp_remote_post(self::ENDPOINT, [
            'timeout' => 5,
            'headers' => [
                'Content-Type' => 'application/json',
                'Authorization' => 'Bearer ' . $apiKey,
            ],
            'body' => wp_json_encode(['report_id' => $batch, 'source' => 'wordpress', 'referrals' => $referrals]),
        ]);
        if (is_wp_error($response)) {
            return false;
        }
        $code = (int) wp_remote_retrieve_response_code($response);
        return $code >= 200 && $code < 500;
    }
}
