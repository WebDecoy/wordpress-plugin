<?php
/**
 * Read-only local analytics for the dashboard. No request recording changes.
 *
 * @package WebDecoy
 */
if (!defined('ABSPATH')) {
    exit;
}

class WebDecoy_Traffic_Report
{
    /** Bound dashboard work and make the URL selector predictable. */
    public static function days($value): int
    {
        return (string) $value === '30' ? 30 : 7;
    }

    /** Read hourly crawler and daily referral counters over one UTC window. */
    public static function read(int $days): array
    {
        $days = self::days($days);
        $now = time();
        $start = gmdate('Y-m-d', $now - ($days - 1) * DAY_IN_SECONDS);
        $key = 'traffic_report_' . $days . '_' . $start;
        $cached = wp_cache_get($key, 'webdecoy_analytics');
        if (is_array($cached)) {
            return $cached;
        }
        global $wpdb;
        $version = (string) get_option('webdecoy_db_version', '0');
        $crawler_rows = [];
        $referral_rows = [];
        $crawler_ready = version_compare($version, WebDecoy_Crawler_Visits::SINCE_DB_VERSION, '>=');
        $referral_ready = version_compare($version, WebDecoy_AI_Referrals::SINCE_DB_VERSION, '>=');
        // phpcs:disable WordPress.DB.DirectDatabaseQuery -- Admin-only aggregates cached for 60 seconds below.
        if ($crawler_ready) {
            $table = esc_sql(WebDecoy_Crawler_Visits::table());
            $crawler_rows = $wpdb->get_results($wpdb->prepare(
                "SELECT DATE(bucket) AS day, agent_id, verification, SUM(hits) AS hits FROM {$table} WHERE bucket >= %s GROUP BY DATE(bucket), agent_id, verification", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Escaped plugin-owned table name.
                $start . ' 00:00:00'
            ), ARRAY_A);
            $crawler_ready = is_array($crawler_rows);
        }
        if ($referral_ready) {
            $table = esc_sql(WebDecoy_AI_Referrals::days_table());
            $referral_rows = $wpdb->get_results($wpdb->prepare(
                "SELECT day, platform, landing_path, SUM(referrals) AS referrals FROM {$table} WHERE day >= %s GROUP BY day, platform, landing_path", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Escaped plugin-owned table name.
                $start
            ), ARRAY_A);
            $referral_ready = is_array($referral_rows);
        }
        // phpcs:enable
        $report = self::project(is_array($crawler_rows) ? $crawler_rows : [], is_array($referral_rows) ? $referral_rows : [], $days, $now);
        $report['crawler_ready'] = $crawler_ready;
        $report['referral_ready'] = $referral_ready;
        wp_cache_set($key, $report, 'webdecoy_analytics', 60);
        return $report;
    }

    /**
     * Project the same rows into cards, tables and zero-filled daily series.
     * Invalid/out-of-window rows never inflate a card independently of its chart.
     */
    public static function project(array $crawler_rows, array $referral_rows, int $days, int $now): array
    {
        $days = self::days($days);
        $series = ['ai' => [], 'search' => [], 'other' => [], 'referrals' => []];
        foreach ($series as &$daily) {
            for ($i = $days - 1; $i >= 0; $i--) {
                $daily[gmdate('Y-m-d', $now - $i * 86400)] = 0;
            }
        }
        unset($daily);
        $crawlers = [];
        foreach ($crawler_rows as $row) {
            $day = (string) ($row['day'] ?? '');
            if (!isset($series['ai'][$day])) {
                continue;
            }
            $one = WebDecoy_Crawler_Visits::summarize([$row]);
            if ($one['total'] <= 0) {
                continue;
            }
            foreach (['ai', 'search', 'other'] as $group) {
                $series[$group][$day] += $one['groups'][$group];
            }
            $crawlers[] = $row;
        }
        $referrals = [];
        foreach ($referral_rows as $row) {
            $day = (string) ($row['day'] ?? '');
            if (!isset($series['referrals'][$day])) {
                continue;
            }
            $one = WebDecoy_AI_Referrals::summarize([$row]);
            if ($one['total'] <= 0) {
                continue;
            }
            $series['referrals'][$day] += $one['total'];
            $referrals[] = $row;
        }
        return [
            'days' => $days,
            'labels' => array_keys($series['ai']),
            'series' => array_map('array_values', $series),
            'crawlers' => WebDecoy_Crawler_Visits::summarize($crawlers),
            'referrals' => WebDecoy_AI_Referrals::summarize($referrals),
        ];
    }
}
