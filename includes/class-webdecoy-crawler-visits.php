<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Counts visits from known crawlers, AI agents and bot tools, so a site can
 * see which bots read it without connecting to anything.
 *
 * Counters only: one row per hour, agent and verification state, holding a
 * number. No IP address, User-Agent, path or anything else about a request is
 * stored, and a request that does not name a known agent is not counted at
 * all, so human visitors leave no trace here.
 *
 * Identity comes from the shared agent registry (the same table the WebDecoy
 * dashboard and edge sensor use). Verification is read from the bot detector's
 * own result, never worked out a second time:
 *
 *   verified  the source address passed reverse and forward DNS for that bot
 *   failed    the address did not belong to the bot it claimed to be
 *   claimed   identified by User-Agent alone (no verification exists for that
 *             agent, or it was not run)
 *
 * When the site sits behind a proxy the plugin has not been told about, every
 * request carries the proxy's address and a failed check means nothing, so it
 * is counted as claimed instead.
 *
 * Pages served from a full-page cache never reach PHP and are not counted, so
 * every figure is a minimum.
 */
class WebDecoy_Crawler_Visits
{
    /** The schema version that created the table. Recording waits for it. */
    public const SINCE_DB_VERSION = '2.11.0';

    public const VERIFIED = 'verified';
    public const CLAIMED = 'claimed';
    public const FAILED = 'failed';

    /** Days of hourly counters kept. */
    public const RETENTION_DAYS = 30;

    private const AI_CATEGORIES = ['training_crawler', 'ai_search_crawler', 'ai_agent', 'ai_assistant'];
    private const SEARCH_CATEGORIES = ['search_crawler'];

    /**
     * The counters table name, prefixed and escaped for interpolation.
     */
    public static function table(): string
    {
        global $wpdb;
        return esc_sql($wpdb->prefix . 'webdecoy_crawler_visits');
    }

    /**
     * Which agent a request is and how sure we are, or null when it names no
     * known agent. Pure, for tests.
     *
     * @param string       $userAgent     The request's User-Agent
     * @param list<string> $flags         Flags on the bot detector's result
     * @param bool         $ipUnreliable  True when the client address is a proxy's
     * @return array{agent_id:string,verification:string}|null
     */
    public static function classify(string $userAgent, array $flags, bool $ipUnreliable): ?array
    {
        $agent = \WebDecoy\AgentRegistry::match($userAgent);
        if ($agent === null) {
            return null;
        }

        $verification = self::CLAIMED;
        if (in_array('verified_good_bot', $flags, true)) {
            $verification = self::VERIFIED;
        } elseif (in_array('bot_verification_failed', $flags, true) && !$ipUnreliable) {
            $verification = self::FAILED;
        }

        return ['agent_id' => $agent['id'], 'verification' => $verification];
    }

    /**
     * Count the current request when it names a known agent.
     *
     * @param string       $userAgent
     * @param list<string> $flags
     * @param bool         $ipUnreliable
     */
    public static function observe(string $userAgent, array $flags, bool $ipUnreliable): void
    {
        if (!self::ready()) {
            return;
        }
        $hit = self::classify($userAgent, $flags, $ipUnreliable);
        if ($hit === null) {
            return;
        }

        global $wpdb;
        $table = self::table();
        // phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix
        $wpdb->query($wpdb->prepare(
            "INSERT INTO {$table} (bucket, agent_id, verification, hits) VALUES (%s, %s, %s, 1)
             ON DUPLICATE KEY UPDATE hits = hits + 1",
            self::bucket(time()),
            $hit['agent_id'],
            $hit['verification']
        ));
        // phpcs:enable
    }

    /**
     * The hour a timestamp counts against, in UTC like every timestamp the
     * plugin stores. Pure, for tests.
     */
    public static function bucket(int $timestamp): string
    {
        return gmdate('Y-m-d H:00:00', $timestamp);
    }

    /**
     * Summary of the last N hours, for the dashboard widget and the
     * Statistics page.
     *
     * @return array{total:int,verified:int,claimed:int,failed:int,groups:array{ai:int,search:int,other:int},agents:list<array<string,mixed>>}
     */
    public static function summary(int $hours): array
    {
        if (!self::ready()) {
            return self::summarize([]);
        }
        global $wpdb;
        $table = self::table();
        // phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT agent_id, verification, SUM(hits) AS hits FROM {$table} WHERE bucket >= %s GROUP BY agent_id, verification",
            self::bucket(time() - (max(1, $hours) - 1) * 3600)
        ), ARRAY_A);
        // phpcs:enable
        return self::summarize(is_array($rows) ? $rows : []);
    }

    /**
     * Fold counter rows into totals, per-group counts and a per-agent list
     * (busiest first). Pure, for tests.
     *
     * @param list<array{agent_id:string,verification:string,hits:int|string}> $rows
     * @return array{total:int,verified:int,claimed:int,failed:int,groups:array{ai:int,search:int,other:int},agents:list<array<string,mixed>>}
     */
    public static function summarize(array $rows): array
    {
        $out = [
            'total' => 0,
            self::VERIFIED => 0,
            self::CLAIMED => 0,
            self::FAILED => 0,
            'groups' => ['ai' => 0, 'search' => 0, 'other' => 0],
            'agents' => [],
        ];
        $agents = [];

        foreach ($rows as $row) {
            $id = (string) ($row['agent_id'] ?? '');
            $state = (string) ($row['verification'] ?? '');
            $hits = (int) ($row['hits'] ?? 0);
            if ($id === '' || $hits <= 0 || !in_array($state, [self::VERIFIED, self::CLAIMED, self::FAILED], true)) {
                continue;
            }

            if (!isset($agents[$id])) {
                $known = \WebDecoy\AgentRegistry::find($id);
                $category = $known !== null ? (string) $known['category'] : '';
                $agents[$id] = [
                    'id' => $id,
                    'name' => $known !== null ? (string) $known['name'] : $id,
                    'organization' => $known !== null ? (string) $known['organization'] : '',
                    'category' => $category,
                    'group' => self::group($category),
                    'hits' => 0,
                    self::VERIFIED => 0,
                    self::CLAIMED => 0,
                    self::FAILED => 0,
                ];
            }

            $agents[$id]['hits'] += $hits;
            $agents[$id][$state] += $hits;
            $out['total'] += $hits;
            $out[$state] += $hits;
            $out['groups'][$agents[$id]['group']] += $hits;
        }

        $list = array_values($agents);
        usort($list, static function (array $a, array $b): int {
            return $b['hits'] <=> $a['hits'] ?: strcmp($a['name'], $b['name']);
        });
        $out['agents'] = $list;

        return $out;
    }

    /**
     * The widget's grouping of a registry category: ai, search or other.
     * Pure, for tests.
     */
    public static function group(string $category): string
    {
        if (in_array($category, self::AI_CATEGORIES, true)) {
            return 'ai';
        }
        if (in_array($category, self::SEARCH_CATEGORIES, true)) {
            return 'search';
        }
        return 'other';
    }

    /**
     * A plain-language name for a registry category. Pure, for tests.
     */
    public static function category_label(string $category): string
    {
        $labels = [
            'training_crawler' => __('AI training crawler', 'webdecoy'),
            'ai_search_crawler' => __('AI search crawler', 'webdecoy'),
            'ai_agent' => __('AI agent', 'webdecoy'),
            'ai_assistant' => __('AI assistant', 'webdecoy'),
            'search_crawler' => __('Search engine', 'webdecoy'),
            'seo_crawler' => __('SEO tool', 'webdecoy'),
            'security_scanner' => __('Security scanner', 'webdecoy'),
            'generic_scraper' => __('Scraper or HTTP library', 'webdecoy'),
            'commercial_scraper' => __('Commercial scraper', 'webdecoy'),
            'headless_browser' => __('Headless browser', 'webdecoy'),
            'fetcher' => __('Fetcher or HTTP client', 'webdecoy'),
            'monitoring' => __('Uptime monitor', 'webdecoy'),
            'feed_reader' => __('Feed reader', 'webdecoy'),
            'archiver' => __('Archiver', 'webdecoy'),
        ];
        return $labels[$category] ?? __('Other bot', 'webdecoy');
    }

    /**
     * Delete counters older than the retention window. Runs on the hourly
     * cleanup cron.
     */
    public static function prune(): void
    {
        if (!self::ready()) {
            return;
        }
        global $wpdb;
        $table = self::table();
        // phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix
        $wpdb->query($wpdb->prepare(
            "DELETE FROM {$table} WHERE bucket < %s",
            self::bucket(time() - self::RETENTION_DAYS * DAY_IN_SECONDS)
        ));
        // phpcs:enable
    }

    /**
     * True once the table exists: the activator or the schema upgrade on the
     * next admin page load creates it. Until then nothing is counted, rather
     * than a front-end request writing to a missing table.
     */
    private static function ready(): bool
    {
        return version_compare((string) get_option('webdecoy_db_version', '0'), self::SINCE_DB_VERSION, '>=');
    }
}
