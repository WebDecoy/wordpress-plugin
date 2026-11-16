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
 * Every install keeps its own daily counts (platform, landing path, number)
 * for {@see self::LOCAL_RETENTION_DAYS} days, shown on the dashboard widget and
 * the Statistics page with no account. When the site is also connected to
 * WebDecoy Cloud, counts accumulate in a second small table and are sent every
 * fifteen minutes. Each send claims the open counts under a batch id; a failed
 * send keeps that id and is retried with it, and WebDecoy counts a batch id
 * once.
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

    /** The schema version that created the local daily table. Recording waits for it. */
    public const SINCE_DB_VERSION = '2.13.0';
    /** Days of local daily counts kept. */
    public const LOCAL_RETENTION_DAYS = 30;
    /**
     * Distinct landing paths kept per day. Past it a referral still counts for
     * its platform, under an empty path, so platform totals stay exact.
     */
    private const MAX_PATHS_PER_DAY = 1000;

    /** True once register() has turned counting on. */
    private static bool $counting = false;
    /** True when counts are also queued for WebDecoy Cloud. */
    private static bool $cloud = false;

    /**
     * The ai_referrals table name, prefixed and escaped for interpolation.
     */
    public static function table(): string
    {
        global $wpdb;
        return esc_sql($wpdb->prefix . 'webdecoy_ai_referrals');
    }

    /** The local daily counts table name, prefixed and escaped for interpolation. */
    public static function days_table(): string
    {
        global $wpdb;
        return esc_sql($wpdb->prefix . 'webdecoy_ai_referral_days');
    }

    /**
     * Whether counting runs at all: on unless turned off with the
     * webdecoy_count_ai_referrals filter. Needs no account.
     */
    public static function enabled(): bool
    {
        return (bool) apply_filters('webdecoy_count_ai_referrals', true);
    }

    /**
     * Wire the counter. Counts are always kept locally; with an API key they
     * are also sent to WebDecoy Cloud, and the flush is scheduled.
     */
    public static function register(string $apiKey): void
    {
        self::$counting = false;
        self::$cloud = false;
        if (!self::enabled()) {
            return;
        }
        self::$counting = true;
        add_action('template_redirect', [self::class, 'observe'], 1);
        self::$cloud = $apiKey !== '';
        if (!self::$cloud) {
            return;
        }
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
        if (!self::$counting) {
            return;
        }
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
        $path = self::landingPath($uri);
        self::recordDay($platform, $path);
        if (self::$cloud) {
            self::increment($platform, $path);
        }
    }

    /** The UTC day a timestamp counts against. Pure, for tests. */
    public static function day(int $timestamp): string
    {
        return gmdate('Y-m-d', $timestamp);
    }

    /**
     * Count one referral in the local daily table, bounded to
     * {@see self::MAX_PATHS_PER_DAY} landing paths a day.
     */
    private static function recordDay(string $platform, string $path): void
    {
        if (!self::localReady()) {
            return;
        }
        global $wpdb;
        $table = self::days_table();
        $day = self::day(time());
        // phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix
        $known = (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$table} WHERE day = %s AND platform = %s AND path_key = %s",
            $day,
            $platform,
            sha1($path)
        ));
        if ($known === 0) {
            $paths = (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$table} WHERE day = %s", $day));
            if ($paths >= self::MAX_PATHS_PER_DAY) {
                $path = '';
            }
        }
        $wpdb->query($wpdb->prepare(
            "INSERT INTO {$table} (day, platform, path_key, landing_path, referrals) VALUES (%s, %s, %s, %s, 1)
             ON DUPLICATE KEY UPDATE referrals = referrals + 1",
            $day,
            $platform,
            sha1($path),
            $path
        ));
        // phpcs:enable
    }

    /**
     * Referrals over the last N days (today included), for the dashboard
     * widget and the Statistics page.
     *
     * @return array{total:int,platforms:list<array{platform:string,referrals:int}>,pages:list<array{path:string,referrals:int}>}
     */
    public static function summary(int $days): array
    {
        if (!self::localReady()) {
            return self::summarize([]);
        }
        global $wpdb;
        $table = self::days_table();
        // phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT platform, landing_path, SUM(referrals) AS referrals FROM {$table} WHERE day >= %s GROUP BY platform, landing_path",
            self::day(time() - (max(1, $days) - 1) * DAY_IN_SECONDS)
        ), ARRAY_A);
        // phpcs:enable
        return self::summarize(is_array($rows) ? $rows : []);
    }

    /**
     * Fold daily rows into a total, per-platform counts and per-page counts,
     * busiest first. Rows past the daily path bound have an empty path: they
     * count for their platform but name no page. Pure, for tests.
     *
     * @param list<array{platform:string,landing_path:string,referrals:int|string}> $rows
     * @return array{total:int,platforms:list<array{platform:string,referrals:int}>,pages:list<array{path:string,referrals:int}>}
     */
    public static function summarize(array $rows): array
    {
        $total = 0;
        $platforms = [];
        $pages = [];
        foreach ($rows as $row) {
            $platform = (string) ($row['platform'] ?? '');
            $path = (string) ($row['landing_path'] ?? '');
            $n = (int) ($row['referrals'] ?? 0);
            if ($platform === '' || $n <= 0) {
                continue;
            }
            $total += $n;
            $platforms[$platform] = ($platforms[$platform] ?? 0) + $n;
            if ($path !== '') {
                $pages[$path] = ($pages[$path] ?? 0) + $n;
            }
        }
        $byCount = static function (array $counts, string $key): array {
            $list = [];
            foreach ($counts as $name => $n) {
                $list[] = [$key => (string) $name, 'referrals' => $n];
            }
            usort($list, static function (array $a, array $b) use ($key): int {
                return $b['referrals'] <=> $a['referrals'] ?: strcmp($a[$key], $b[$key]);
            });
            return $list;
        };
        return ['total' => $total, 'platforms' => $byCount($platforms, 'platform'), 'pages' => $byCount($pages, 'path')];
    }

    /** Delete local daily counts older than the retention window. */
    public static function prune(): void
    {
        if (!self::localReady()) {
            return;
        }
        global $wpdb;
        $table = self::days_table();
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix
        $wpdb->query($wpdb->prepare("DELETE FROM {$table} WHERE day < %s", self::day(time() - self::LOCAL_RETENTION_DAYS * DAY_IN_SECONDS)));
    }

    /** Whether the local daily table exists yet (the schema upgrade has run). */
    private static function localReady(): bool
    {
        return version_compare((string) get_option('webdecoy_db_version', '0'), self::SINCE_DB_VERSION, '>=');
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

    /**
     * Record one referral for a platform/landing-path pair, bounded to
     * {@see self::MAX_ROWS} distinct pairs.
     *
     * @param string $platform Referring AI platform
     * @param string $path Landing path the referral counted against
     */
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
        // While WebDecoy is refusing work, leave the counts where they are
        // (WebDecoy/app#1245); they are sent under the same id afterwards.
        if (class_exists('WebDecoy_Detection_Sender') && WebDecoy_Detection_Sender::backing_off()) {
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
     * retry cannot fix (a 4xx, such as a key not scoped to one site). A 429 is
     * "not now", not "never": the batch is kept and resent under its id, which
     * ingest deduplicates (WebDecoy/app#1245).
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
            self::note_refusal();
            return false;
        }
        $code = (int) wp_remote_retrieve_response_code($response);
        if ($code === 429 || $code >= 500) {
            self::note_refusal();
            return false;
        }
        return $code >= 200 && $code < 500;
    }

    /** Pause cloud calls after an unavailable answer (WebDecoy/app#1245). */
    private static function note_refusal(): void
    {
        if (class_exists('WebDecoy_Detection_Sender')) {
            WebDecoy_Detection_Sender::note_refusal();
        }
    }
}
