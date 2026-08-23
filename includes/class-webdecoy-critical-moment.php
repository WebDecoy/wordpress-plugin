<?php
/**
 * WebDecoy Post-CRITICAL Moment
 *
 * When a CRITICAL detection is recorded (a decoy/canary credential is replayed —
 * unambiguous exfiltration), we queue a single, dismissible admin notice that
 * turns the raw event into an upgrade moment. Throttled to at most one every
 * seven days.
 *
 * Zero external calls at queue time: queueing happens on the front-end request
 * that recorded the detection and only writes local state. The intel lookup that
 * personalises the connected copy is deferred to the admin render — a connected,
 * entitled context — and unconnected sites never look anything up at all (they
 * show static "Connect" copy).
 *
 * State:
 *  - option `webdecoy_critical_moment_last`  — epoch of the last queued moment
 *    (drives the 7-day throttle via {@see self::should_queue()}).
 *  - transient `webdecoy_critical_moment`     — the pending one-shot notice
 *    (the queued IP), consumed on first admin render.
 *
 * @package WebDecoy
 */

// Prevent direct access.
if (!defined('ABSPATH')) {
    exit;
}

/**
 * WebDecoy Post-CRITICAL Moment controller.
 */
class WebDecoy_Critical_Moment
{
    /** Pending one-shot notice (holds the queued IP). */
    private const NOTICE_TRANSIENT = 'webdecoy_critical_moment';

    /** Epoch of the last queued moment (throttle anchor). */
    public const LAST_OPTION = 'webdecoy_critical_moment_last';

    /** Throttle window: 7 days (literal to keep the class loadable sans WordPress). */
    private const THROTTLE_WINDOW = 604800;

    /** Pending-notice lifetime: 7 days, so it survives until an admin logs in. */
    private const NOTICE_TTL = 604800;

    /**
     * Register the admin render. Queueing is driven directly from the detection
     * insert sites via {@see self::maybe_queue()}, so no front-end hook is
     * needed here.
     */
    public function register(): void
    {
        if (is_admin() && !WebDecoy_Runtime_Config::hide_admin_ui()) {
            add_action('admin_notices', [$this, 'render']);
        }
    }

    /**
     * Queue a moment for a CRITICAL detection's IP, subject to the throttle.
     * Makes no external request — only local option/transient writes.
     */
    public function maybe_queue(string $ip): void
    {
        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return;
        }

        $last = (int) get_option(self::LAST_OPTION, 0);
        if (!self::should_queue($last, time(), self::THROTTLE_WINDOW)) {
            return;
        }

        set_transient(self::NOTICE_TRANSIENT, ['ip' => $ip, 'at' => time()], self::NOTICE_TTL);
        update_option(self::LAST_OPTION, time(), false);
    }

    /**
     * Render (and consume) any pending moment. One-shot + dismissible.
     */
    public function render(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        $pending = get_transient(self::NOTICE_TRANSIENT);
        if (!is_array($pending) || empty($pending['ip']) || !is_string($pending['ip'])) {
            return;
        }

        $ip = $pending['ip'];
        // Consume immediately so it shows exactly once.
        delete_transient(self::NOTICE_TRANSIENT);

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return;
        }

        $notice = $this->build_notice($ip);
        if ($notice['message'] === '') {
            return;
        }

        $class = ($notice['type'] === 'success') ? 'notice-success' : 'notice-warning';
        ?>
        <div class="notice <?php echo esc_attr($class); ?> is-dismissible webdecoy-critical-moment">
            <p>
                <strong><?php esc_html_e('WebDecoy:', 'webdecoy'); ?></strong>
                <?php echo esc_html($notice['message']); ?>
            </p>
            <?php if ($notice['cta_url'] !== '' && $notice['cta_label'] !== '') : ?>
                <p>
                    <a href="<?php echo esc_url($notice['cta_url']); ?>" class="button button-primary">
                        <?php echo esc_html($notice['cta_label']); ?>
                    </a>
                </p>
            <?php endif; ?>
        </div>
        <?php
    }

    /**
     * Build the notice copy + CTA for the queued IP. This is the only place that
     * may perform an intel lookup, and only when connected.
     *
     * @return array{message:string,cta_label:string,cta_url:string,type:string}
     */
    private function build_notice(string $ip): array
    {
        $connected = class_exists('WebDecoy_Cloud_Connect') && WebDecoy_Cloud_Connect::is_connected();

        $known = false;
        $has_actor_feed = false;
        $days = 0;
        $org_id = '';

        if ($connected) {
            $entitlements = WebDecoy_Cloud_Connect::get_entitlements();
            $has_actor_feed = !empty($entitlements['features']['actor_feed']);

            $options = function_exists('webdecoy') ? webdecoy()->get_options() : [];
            $org_id = isset($options['organization_id']) ? (string) $options['organization_id'] : '';
            $api_key = isset($options['api_key']) ? (string) $options['api_key'] : '';

            // Prefer the locally synced feed: the hourly actor-feed sync already holds
            // this data, so consulting it costs an option read instead of a blocking
            // HTTP round trip on a page render. This is also the consumer the feed was
            // missing — before this it wrote an option nothing ever read (#62).
            if ($has_actor_feed && class_exists('WebDecoy_Actor_Feed')) {
                $local = (new WebDecoy_Actor_Feed())->intel_for($ip);
                if ($local !== null && $local['last_seen'] > 0) {
                    $known = true;
                    $days = self::days_since($local['last_seen'], time());
                }
            }

            // Fall back to the live lookup only when the local feed had nothing —
            // either the org has no feed entitlement or the actor is newer than the
            // last sync.
            if (!$known && $api_key !== '' && class_exists('WebDecoy_Actor_Intel')) {
                $intel = new WebDecoy_Actor_Intel($api_key);
                $map = $intel->lookup([$ip]);
                $entry = isset($map[$ip]) && is_array($map[$ip]) ? $map[$ip] : null;
                if ($entry !== null && !empty($entry['known'])) {
                    $known = true;
                    $days = self::days_since((int) $entry['first_seen'], time());
                }
            }
        }

        switch (self::variant($connected, $known, $has_actor_feed)) {
            case 'connected_upgrade':
                $n = max(1, $days);
                return [
                    'message'   => sprintf(
                        /* translators: %d: number of days since first seen on the network */
                        // Must not claim Pro would have BLOCKED this. Since 2.3.2 the
                        // cross-site feed is advisory and writes nothing to the block
                        // list, on any plan — see #476. Sell the history, not a block
                        // that does not happen.
                        _n(
                            'This attacker was first seen on the WebDecoy network %d day ago — Pro shows you the full cross-site history for this actor.',
                            'This attacker was first seen on the WebDecoy network %d days ago — Pro shows you the full cross-site history for this actor.',
                            $n,
                            'webdecoy'
                        ),
                        $n
                    ),
                    'cta_label' => __('Upgrade to Pro', 'webdecoy'),
                    'cta_url'   => class_exists('WebDecoy_Cloud_Connect')
                        ? WebDecoy_Cloud_Connect::wp_upgrade_url('wp_pro', $org_id)
                        : '',
                    'type'      => 'warning',
                ];

            case 'connected_covered':
                // Was "already blocked network-wide" with a success chip pointing at
                // the blocked-IPs page. Since 2.3.2 the feed blocks nothing and that
                // page is empty of feed entries, so the claim was false and the link
                // went nowhere useful. Recognition is real; the block was not. #62.
                return [
                    'message'   => __('This attacker is already known across the WebDecoy network — the same actor has been seen attacking other sites.', 'webdecoy'),
                    'cta_label' => __('View detections', 'webdecoy'),
                    'cta_url'   => admin_url('admin.php?page=webdecoy-detections'),
                    'type'      => 'warning',
                ];

            case 'connected_unknown':
                return [
                    'message'   => __('A CRITICAL deception trap was just tripped on your site. Review the detection for the full picture.', 'webdecoy'),
                    'cta_label' => __('View detections', 'webdecoy'),
                    'cta_url'   => admin_url('admin.php?page=webdecoy-detections'),
                    'type'      => 'warning',
                ];

            case 'unconnected':
            default:
                return [
                    // Was "and to block threats like it automatically". Connecting does
                    // not block anything: the cross-site feed is advisory on every plan
                    // and writes nothing to the block list (#476). The unconnected pitch
                    // was the last place in this file still promising it, three variants
                    // below a comment forbidding exactly that claim.
                    'message'   => __('A CRITICAL deception trap was just tripped. Connect to WebDecoy Cloud to see whether this attacker is already known across the network, and what it has been doing to other sites.', 'webdecoy'),
                    'cta_label' => __('Connect to WebDecoy Cloud', 'webdecoy'),
                    'cta_url'   => admin_url('admin.php?page=webdecoy&tab=cloud'),
                    'type'      => 'warning',
                ];
        }
    }

    // ---------------------------------------------------------------------
    // Pure helpers (no WordPress calls) — unit-tested in tests/CriticalMomentTest.php.
    // ---------------------------------------------------------------------

    /**
     * Throttle decision: allow a new moment only when none has fired, or the
     * window has fully elapsed since the last one.
     */
    public static function should_queue(int $last_fired_at, int $now, int $window): bool
    {
        if ($last_fired_at <= 0) {
            return true;
        }
        return ($now - $last_fired_at) >= $window;
    }

    /**
     * Whole days between a first-seen epoch and now. Clamped to 0 for missing or
     * future timestamps.
     */
    public static function days_since(int $first_seen, int $now): int
    {
        if ($first_seen <= 0 || $now <= $first_seen) {
            return 0;
        }
        return (int) floor(($now - $first_seen) / 86400);
    }

    /**
     * Select the copy variant from the connection + intel + entitlement state.
     */
    public static function variant(bool $connected, bool $known, bool $has_actor_feed): string
    {
        if (!$connected) {
            return 'unconnected';
        }
        if (!$known) {
            return 'connected_unknown';
        }
        if ($has_actor_feed) {
            return 'connected_covered';
        }
        return 'connected_upgrade';
    }
}
