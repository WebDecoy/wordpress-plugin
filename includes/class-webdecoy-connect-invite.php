<?php
/**
 * WebDecoy connect invite
 *
 * One dismissible notice that offers WebDecoy Cloud after the plugin is
 * activated. Until now Connect lived on the Settings page's Cloud tab, and
 * no site ever found it. The notice says what the plugin is already doing
 * on this site, using this week's counts when there are any, then offers
 * Connect with the same nonce-protected form the Cloud tab uses.
 *
 * Shown to administrators on the WordPress dashboard, the Plugins screen and
 * WebDecoy's own pages, only while the site is not connected. "Not now"
 * snoozes for 14 days; "Don't show again" ends it. Makes no external request:
 * the plugin leaves the site only when the admin clicks Connect.
 *
 * State: option `webdecoy_connect_invite` — '' (pending), 'never', or
 * 'later:<epoch>' (snoozed until then).
 *
 * @package WebDecoy
 */

// Prevent direct access.
if (!defined('ABSPATH')) {
    exit;
}

/**
 * WebDecoy connect invite controller.
 */
class WebDecoy_Connect_Invite
{
    public const STATE_OPTION = 'webdecoy_connect_invite';

    /** "Not now" snoozes for 14 days (literal to keep the class loadable sans WordPress). */
    public const SNOOZE = 1209600;

    /** Where the Connect click came from, sent to the app so it can count invite connects. */
    public const SOURCE = 'invite';

    private const ACTION = 'webdecoy_connect_invite';

    /** Set once this request has rendered the invite, so the review ask can stand aside. */
    private static bool $rendered = false;

    public function register(): void
    {
        if (!is_admin() || WebDecoy_Runtime_Config::hide_admin_ui()) {
            return;
        }
        // Ahead of the review ask (priority 10), which checks rendered().
        add_action('admin_notices', [$this, 'render'], 5);
        add_action('admin_post_' . self::ACTION, [$this, 'handle']);
    }

    /** Whether the invite was shown on this page view. */
    public static function rendered(): bool
    {
        return self::$rendered;
    }

    public function render(): void
    {
        if (!current_user_can('manage_options') || !self::on_relevant_screen()) {
            return;
        }
        $connected = class_exists('WebDecoy_Cloud_Connect') && WebDecoy_Cloud_Connect::is_connected();
        if (!self::is_due($connected, (string) get_option(self::STATE_OPTION, ''), time())) {
            return;
        }
        self::$rendered = true;

        $visits = class_exists('WebDecoy_Crawler_Visits') ? WebDecoy_Crawler_Visits::summary(168) : ['total' => 0, 'groups' => ['ai' => 0]];
        $total = (int) ($visits['total'] ?? 0);
        $ai = (int) ($visits['groups']['ai'] ?? 0);

        $link = static function (string $choice): string {
            return wp_nonce_url(
                admin_url('admin-post.php?action=' . self::ACTION . '&choice=' . $choice),
                self::ACTION
            );
        };
        ?>
        <div class="notice notice-info webdecoy-connect-invite">
            <p>
                <strong><?php esc_html_e('WebDecoy:', 'webdecoy'); ?></strong>
                <?php echo esc_html(self::message($total, $ai)); ?>
            </p>
            <p><?php echo esc_html(self::offer()); ?></p>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="webdecoy_cloud_connect" />
                <input type="hidden" name="source" value="<?php echo esc_attr(self::SOURCE); ?>" />
                <?php wp_nonce_field('webdecoy_cloud_connect'); ?>
                <p>
                    <label>
                        <input type="checkbox" name="digest" value="1" />
                        <?php esc_html_e('Send me a monthly security report', 'webdecoy'); ?>
                    </label>
                </p>
                <p>
                    <button type="submit" class="button button-primary">
                        <?php esc_html_e('Connect free', 'webdecoy'); ?>
                    </button>
                    <a href="<?php echo esc_url($link('later')); ?>" class="button">
                        <?php esc_html_e('Not now', 'webdecoy'); ?>
                    </a>
                    <a href="<?php echo esc_url($link('never')); ?>">
                        <?php esc_html_e("Don't show again", 'webdecoy'); ?>
                    </a>
                </p>
            </form>
        </div>
        <?php
    }

    /** Record "Not now" or "Don't show again" and return to the page. */
    public function handle(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to do that.', 'webdecoy'), 403);
        }
        check_admin_referer(self::ACTION);

        $choice = isset($_GET['choice']) ? sanitize_key(wp_unslash($_GET['choice'])) : '';
        update_option(self::STATE_OPTION, self::state_for($choice, time()), false);

        wp_safe_redirect(wp_get_referer() ?: admin_url());
        exit;
    }

    private static function on_relevant_screen(): bool
    {
        if (!function_exists('get_current_screen')) {
            return false;
        }
        $screen = get_current_screen();
        if ($screen === null) {
            return false;
        }
        $id = (string) $screen->id;
        return $id === 'dashboard' || $id === 'plugins' || strpos($id, 'webdecoy') !== false;
    }

    // ---------------------------------------------------------------------
    // Pure helpers (no WordPress calls) — unit-tested in tests/ConnectInviteTest.php.
    // ---------------------------------------------------------------------

    /** Whether to show the invite: not connected, not dismissed, not snoozed past now. */
    public static function is_due(bool $connected, string $state, int $now): bool
    {
        if ($connected) {
            return false;
        }
        if ($state === '') {
            return true;
        }
        if (strpos($state, 'later:') === 0) {
            return $now >= (int) substr($state, 6);
        }
        return false;
    }

    /** The stored state for a choice. Anything unrecognised snoozes rather than silencing it for good. */
    public static function state_for(string $choice, int $now): string
    {
        return $choice === 'never' ? 'never' : 'later:' . ($now + self::SNOOZE);
    }

    /** What the plugin is doing on this site, from this week's counts. */
    public static function message(int $total, int $ai): string
    {
        if ($total <= 0) {
            return __('WebDecoy is now counting bot and AI crawler visits on this site. Everything it shows works without an account.', 'webdecoy');
        }
        if ($ai > 0) {
            return sprintf(
                /* translators: 1: bot visits counted in 7 days, 2: of which AI crawlers and agents */
                __('In the last 7 days WebDecoy counted %1$s bot visits on this site, %2$s of them from AI crawlers and agents. Everything it shows works without an account.', 'webdecoy'),
                number_format($total),
                number_format($ai)
            );
        }
        return sprintf(
            /* translators: %s: bot visits counted in 7 days */
            __('In the last 7 days WebDecoy counted %s bot visits on this site. Everything it shows works without an account.', 'webdecoy'),
            number_format($total)
        );
    }

    /** Why connect, in what a free connected site actually gets. */
    public static function offer(): string
    {
        return __('Connect free to see each bot\'s history beside your detections and this site in the WebDecoy dashboard, with an optional monthly report. Nothing leaves your site until you click Connect.', 'webdecoy');
    }
}
