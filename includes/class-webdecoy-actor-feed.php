<?php
/**
 * WebDecoy Actor Feed
 *
 * Pre-emptive network blocking. When this site is connected to WebDecoy Cloud
 * AND entitled to the actor feed (Pro+), an hourly cron pulls the shared
 * "known attacker" IP feed and mirrors it into the existing blocked-IPs table
 * with a rolling 48h expiry — so those attackers are denied before they ever
 * reach the site.
 *
 * Zero external calls unless connected AND entitled. The cron is only scheduled
 * while both hold ({@see self::maybe_reconcile_schedule()}), and the handler
 * re-checks both and unschedules itself before it ever touches the network
 * ({@see self::sync()}). A `403 upgrade_required` from the feed also unschedules
 * quietly.
 *
 * Coexistence with the user's own blocks — hard invariants enforced here:
 *  - network rows carry `created_by = 'webdecoy-network'`. Rows created by
 *    anyone else (a human admin, 'system', rate-limiter) are NEVER updated or
 *    deleted by this class.
 *  - an IP present in the user's ip_allowlist is NEVER inserted (exact match and
 *    CIDR range, via {@see WebDecoy_Blocker::is_allowlisted()}).
 *  - at most {@see self::MAX_NETWORK_ROWS} network rows are kept; the oldest
 *    (least-recently-seen) are evicted first.
 *
 * @package WebDecoy
 */

// The table name is interpolated from $wpdb->prefix (a trusted value) into
// otherwise-prepared statements, exactly as WebDecoy_Blocker does.
// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared
// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery
// phpcs:disable WordPress.DB.DirectDatabaseQuery.NoCaching

// Prevent direct access.
if (!defined('ABSPATH')) {
    exit;
}

/**
 * WebDecoy Actor Feed controller.
 */
class WebDecoy_Actor_Feed
{
    /** Hourly cron hook that pulls the feed and refreshes network blocks. */
    public const CRON_HOOK = 'webdecoy_sync_actor_feed';

    /** Shared actor feed endpoint (Bearer API key; same auth as entitlements). */
    private const FEED_ENDPOINT = 'https://ingest.webdecoy.com/api/v1/sdk/actor-feed';

    /** Option persisting the delta cursor (`since`) between syncs. */
    private const CURSOR_OPTION = 'webdecoy_actor_feed_cursor';

    /** Advisory intel store. Read for scoring; never consulted to block. */
    private const INTEL_OPTION = 'webdecoy_actor_feed_intel';

    /** created_by marker for rows this class owns. */
    public const CREATED_BY = 'webdecoy-network';

    /** Entitlement feature key that gates the whole mechanism. */
    private const FEATURE = 'actor_feed';

    /** Rolling block lifetime (hours). Refreshed every sync for live feed IPs. */
    private const EXPIRY_HOURS = 48;

    /** Hard cap on the number of network-owned rows. */
    private const MAX_NETWORK_ROWS = 2000;

    /** Safety cap on pagination follows per sync. */
    private const MAX_PAGES = 25;

    /** Seconds per hour — literal to keep the class loadable without WordPress. */
    private const HOUR = 3600;

    /** @var WebDecoy_Blocker|null Lazily created for allowlist checks. */
    private $blocker = null;

    /**
     * Wire up the cron. The handler is registered unconditionally (wp-cron can
     * fire on any front-end request); the schedule itself is reconciled against
     * the current connection + entitlement state on each admin load.
     */
    public function register(): void
    {
        add_action(self::CRON_HOOK, [$this, 'sync']);

        if (is_admin()) {
            add_action('admin_init', [$this, 'maybe_reconcile_schedule']);
        }
    }

    /**
     * Schedule the hourly sync when connected + entitled; unschedule otherwise.
     * Cheap: reads two options, no HTTP. Keeps the schedule tracking entitlement
     * changes (including a downgrade or disconnect) on the next admin page load.
     */
    public function maybe_reconcile_schedule(): void
    {
        if (self::is_enabled()) {
            if (!wp_next_scheduled(self::CRON_HOOK)) {
                // Stagger the first run slightly so activation/connect returns fast.
                wp_schedule_event(time() + 60, 'hourly', self::CRON_HOOK);
            }
        } else {
            self::unschedule();
        }
    }

    /**
     * Whether the feed mechanism may run: connected AND entitled to actor_feed.
     */
    public static function is_enabled(): bool
    {
        if (!class_exists('WebDecoy_Cloud_Connect') || !WebDecoy_Cloud_Connect::is_connected()) {
            return false;
        }
        $entitlements = WebDecoy_Cloud_Connect::get_entitlements();
        return !empty($entitlements['features'][self::FEATURE]);
    }

    /**
     * Remove any scheduled sync (idempotent).
     */
    public static function unschedule(): void
    {
        wp_clear_scheduled_hook(self::CRON_HOOK);
    }

    /**
     * Cron handler: pull the feed (following pagination) and reconcile the
     * network-owned blocked rows. Self-guards so it makes no request unless the
     * site is both connected and entitled.
     */
    public function sync(): void
    {
        if (!self::is_enabled()) {
            self::unschedule();
            return;
        }

        $api_key = $this->api_key();
        if ($api_key === '') {
            self::unschedule();
            return;
        }

        $cursor = (int) get_option(self::CURSOR_OPTION, 0);
        $latest_cursor = $cursor;

        $ip_map = [];   // ip => ['actor_id' => string, 'last_seen' => int]
        $pages = 0;

        do {
            $requested = $latest_cursor;
            $result = $this->fetch_page($api_key, $requested);

            if ($result['status'] === 'upgrade') {
                // Entitlement revoked server-side (403 upgrade_required). Stop
                // quietly and stop scheduling; the next entitlements sync will
                // confirm the downgrade locally.
                self::unschedule();
                return;
            }
            if ($result['status'] !== 'ok') {
                // Transient error — keep the cursor and retry next hour. Any rows
                // already present keep protecting until their 48h expiry lapses.
                return;
            }

            $normalized = self::normalize_feed_page($result['body']);
            $ip_map = self::merge_actor_ips($ip_map, $normalized['actors']);

            $advanced = $normalized['next_since'] > $requested;
            if ($advanced) {
                $latest_cursor = $normalized['next_since'];
            }
            $pages++;

            $continue = self::should_continue(
                $normalized['complete'],
                $advanced,
                $pages,
                self::MAX_PAGES,
                count($ip_map),
                self::MAX_NETWORK_ROWS
            );
        } while ($continue);

        // Exclude the user's allowlist + invalid IPs (pure pass).
        $insertable = self::exclude_allowlisted($ip_map, $this->allowlist());

        // The feed is INTELLIGENCE, not enforcement. It used to write these
        // addresses straight into wp_webdecoy_blocked_ips. Measured against
        // production that was net-negative: only 2 of 4,866 addresses were ever
        // seen at more than one site (0.04%), 93% of hostile addresses are gone
        // within the hour, 82% of feed entries were already stale by a week, and
        // none were still active. Blocking an address the attacker abandoned days
        // ago does not stop the attacker — it blocks whoever holds it now, which on
        // a residential range is a real person.
        //
        // The data is kept and surfaced (actor intel, scoring input, rate-limit
        // trigger) where being wrong costs a delay rather than a lockout.
        // Refs WebDecoy/app#476.
        $this->record_intel($insertable);
        // The feed no longer owns rows in the block table, so there is nothing left
        // to cap there. Any rows it wrote before this version are removed once, on
        // upgrade, by purge_feed_blocks().
        self::purge_feed_blocks();

        update_option(self::CURSOR_OPTION, $latest_cursor, false);
    }

    /**
     * Fetch one feed page. Returns a status envelope so the caller can tell a
     * transient failure ('retry') from an entitlement revocation ('upgrade').
     *
     * @return array{status:string,body:array<string,mixed>}
     */
    private function fetch_page(string $api_key, int $since): array
    {
        if (!function_exists('wp_remote_get')) {
            return ['status' => 'retry', 'body' => []];
        }

        $url = self::FEED_ENDPOINT . '?since=' . rawurlencode((string) $since);

        $response = wp_remote_get($url, [
            'timeout' => 8,
            'headers' => [
                'Accept'        => 'application/json',
                'Authorization' => 'Bearer ' . $api_key,
            ],
        ]);

        if (is_wp_error($response)) {
            return ['status' => 'retry', 'body' => []];
        }

        $code = (int) wp_remote_retrieve_response_code($response);
        $body = json_decode((string) wp_remote_retrieve_body($response), true);
        $body = is_array($body) ? $body : [];

        if ($code === 403) {
            return ['status' => 'upgrade', 'body' => $body];
        }
        if ($code < 200 || $code >= 300) {
            return ['status' => 'retry', 'body' => []];
        }

        return ['status' => 'ok', 'body' => $body];
    }

    /**
     * Store the feed as advisory intelligence. Nothing here blocks a request.
     *
     * Replaces apply_blocks(), which wrote these addresses into the live block
     * table. See the call site for why that was removed (WebDecoy/app#476).
     *
     * @param array<string,array{actor_id:string,last_seen:int}> $ip_map
     */
    private function record_intel(array $ip_map): void
    {
        if ($ip_map === []) {
            update_option(self::INTEL_OPTION, [], false);
            return;
        }

        $intel = [];
        foreach ($ip_map as $ip => $meta) {
            $intel[(string) $ip] = [
                'actor_id'  => (string) $meta['actor_id'],
                'last_seen' => (int) $meta['last_seen'],
            ];
            if (count($intel) >= self::MAX_NETWORK_ROWS) {
                break;
            }
        }

        update_option(self::INTEL_OPTION, $intel, false);
    }

    /**
     * Advisory lookup: has this address been seen attacking another site recently?
     *
     * Callers must treat a hit as a scoring input or a reason to rate-limit, never
     * as grounds to block — see WebDecoy/app#476 for the measurement.
     *
     * @return array{actor_id:string,last_seen:int}|null
     */
    public function intel_for(string $ip): ?array
    {
        $intel = get_option(self::INTEL_OPTION, []);
        if (!is_array($intel) || !isset($intel[$ip]) || !is_array($intel[$ip])) {
            return null;
        }
        return [
            'actor_id'  => (string) ($intel[$ip]['actor_id'] ?? ''),
            'last_seen' => (int) ($intel[$ip]['last_seen'] ?? 0),
        ];
    }

    /**
     * Remove every row this feed previously wrote into the live block table.
     * Runs once on upgrade so existing installs stop enforcing on stale addresses.
     */
    public static function purge_feed_blocks(): int
    {
        global $wpdb;
        $table = $wpdb->prefix . 'webdecoy_blocked_ips';
        $rows = $wpdb->get_col($wpdb->prepare(
            "SELECT ip_address FROM {$table} WHERE created_by = %s",
            self::CREATED_BY
        ));
        $deleted = (int) $wpdb->query($wpdb->prepare(
            "DELETE FROM {$table} WHERE created_by = %s",
            self::CREATED_BY
        ));
        foreach ((array) $rows as $ip) {
            wp_cache_delete('webdecoy_blocked_' . $ip, 'webdecoy');
        }
        return $deleted;
    }

    /**
     * Trim network-owned rows back to the cap, evicting the oldest first.
     *
     * blocked_at proxies last_seen: it is refreshed to "now" for every IP still
     * present in the feed each sync, so the smallest blocked_at is the row that
     * has gone longest without appearing in the feed — the right one to drop.
     */
    private function enforce_cap(): void
    {
        global $wpdb;
        $table = $wpdb->prefix . 'webdecoy_blocked_ips';

        $count = (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$table} WHERE created_by = %s",
            self::CREATED_BY
        ));
        if ($count <= self::MAX_NETWORK_ROWS) {
            return;
        }

        $excess = $count - self::MAX_NETWORK_ROWS;
        $ids = $wpdb->get_col($wpdb->prepare(
            "SELECT id FROM {$table} WHERE created_by = %s ORDER BY blocked_at ASC, id ASC LIMIT %d",
            self::CREATED_BY,
            $excess
        ));

        if (!$ids) {
            return;
        }

        $placeholders = implode(',', array_fill(0, count($ids), '%d'));
        $wpdb->query($wpdb->prepare(
            "DELETE FROM {$table} WHERE id IN ({$placeholders})",
            $ids
        ));
    }

    /**
     * Decrypted API key from the plugin's in-request options.
     */
    private function api_key(): string
    {
        if (!function_exists('webdecoy')) {
            return '';
        }
        $options = webdecoy()->get_options();
        return isset($options['api_key']) ? (string) $options['api_key'] : '';
    }

    /**
     * The user's IP allowlist (raw list; CIDR handled by the blocker).
     *
     * @return array<int,string>
     */
    private function allowlist(): array
    {
        $options = get_option('webdecoy_options', []);
        if (!is_array($options)) {
            return [];
        }
        $allow = isset($options['ip_allowlist']) ? $options['ip_allowlist'] : [];
        return is_array($allow) ? $allow : [];
    }

    private function blocker(): WebDecoy_Blocker
    {
        if ($this->blocker === null) {
            $this->blocker = new WebDecoy_Blocker();
        }
        return $this->blocker;
    }

    // ---------------------------------------------------------------------
    // Pure helpers (no WordPress calls) — unit-tested in tests/ActorFeedTest.php.
    // ---------------------------------------------------------------------

    /**
     * Normalize one raw feed response into typed actors + pagination signals.
     * Drops malformed actors (missing id or no usable IPs).
     *
     * @param array<string,mixed> $body
     * @return array{actors:array<int,array{id:string,ips:array<int,string>,last_seen:int}>,next_since:int,complete:bool}
     */
    public static function normalize_feed_page(array $body): array
    {
        $actors_out = [];
        $actors_in = isset($body['actors']) && is_array($body['actors']) ? $body['actors'] : [];

        foreach ($actors_in as $actor) {
            if (!is_array($actor)) {
                continue;
            }
            $id = isset($actor['id']) ? (string) $actor['id'] : '';
            $last_seen = isset($actor['last_seen']) ? (int) $actor['last_seen'] : 0;

            $ips_in = isset($actor['ips']) && is_array($actor['ips']) ? $actor['ips'] : [];
            $ips = [];
            foreach ($ips_in as $ip) {
                if (!is_string($ip)) {
                    continue;
                }
                $ip = trim($ip);
                if ($ip !== '') {
                    $ips[] = $ip;
                }
            }

            if ($id === '' || $ips === []) {
                continue;
            }
            $actors_out[] = ['id' => $id, 'ips' => $ips, 'last_seen' => $last_seen];
        }

        return [
            'actors'     => $actors_out,
            'next_since' => isset($body['next_since']) ? (int) $body['next_since'] : 0,
            'complete'   => !empty($body['complete']),
        ];
    }

    /**
     * Merge a page's actors into an ip => {actor_id,last_seen} accumulator,
     * keeping the most-recent last_seen when an IP appears more than once.
     *
     * @param array<string,array{actor_id:string,last_seen:int}> $accumulated
     * @param array<int,array{id:string,ips:array<int,string>,last_seen:int}> $actors
     * @return array<string,array{actor_id:string,last_seen:int}>
     */
    public static function merge_actor_ips(array $accumulated, array $actors): array
    {
        foreach ($actors as $actor) {
            $id = isset($actor['id']) ? (string) $actor['id'] : '';
            $last_seen = isset($actor['last_seen']) ? (int) $actor['last_seen'] : 0;
            $ips = isset($actor['ips']) && is_array($actor['ips']) ? $actor['ips'] : [];

            foreach ($ips as $ip) {
                $ip = (string) $ip;
                if ($ip === '') {
                    continue;
                }
                if (!isset($accumulated[$ip]) || $last_seen > $accumulated[$ip]['last_seen']) {
                    $accumulated[$ip] = ['actor_id' => $id, 'last_seen' => $last_seen];
                }
            }
        }
        return $accumulated;
    }

    /**
     * Drop invalid IPs and any exact allowlist match. (CIDR allowlist ranges are
     * enforced separately at insert time via the blocker.)
     *
     * @param array<string,array{actor_id:string,last_seen:int}> $ip_map
     * @param array<int,string> $allowlist
     * @return array<string,array{actor_id:string,last_seen:int}>
     */
    public static function exclude_allowlisted(array $ip_map, array $allowlist): array
    {
        $out = [];
        foreach ($ip_map as $ip => $meta) {
            $ip = (string) $ip;
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                continue;
            }
            if (in_array($ip, $allowlist, true)) {
                continue;
            }
            $out[$ip] = $meta;
        }
        return $out;
    }

    /**
     * Given ip => sort-key (last_seen / blocked_at epoch) and a cap, return the
     * IPs to evict (oldest sort-key first) to bring the set within the cap.
     *
     * @param array<string,int> $rows
     * @return array<int,string>
     */
    public static function select_evictions(array $rows, int $cap): array
    {
        if ($cap < 0) {
            $cap = 0;
        }
        if (count($rows) <= $cap) {
            return [];
        }
        asort($rows); // ascending: oldest first
        $excess = count($rows) - $cap;
        return array_slice(array_keys($rows), 0, $excess);
    }

    /**
     * Pagination decision. Continue only while the feed is incomplete, the
     * cursor actually advanced (guards against a stuck cursor), and neither the
     * page nor row safety cap is hit.
     */
    public static function should_continue(
        bool $complete,
        bool $advanced,
        int $pages,
        int $max_pages,
        int $collected,
        int $max_rows
    ): bool {
        if ($complete) {
            return false;
        }
        if (!$advanced) {
            return false;
        }
        if ($pages >= $max_pages) {
            return false;
        }
        if ($collected >= $max_rows) {
            return false;
        }
        return true;
    }
}
