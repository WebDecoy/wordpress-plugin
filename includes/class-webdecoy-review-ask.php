<?php
/**
 * WebDecoy review ask
 *
 * One dismissible request for a wordpress.org review, shown to administrators
 * only after the plugin has had a week on the site and has something to show
 * for it: bot visits counted in the last seven days. The copy names that
 * number, so the ask is about what the site owner has seen, not about us.
 *
 * Never shown on a site that has counted nothing, never more than once per
 * snooze, and gone for good after "Leave a review" or "Don't ask again".
 * Makes no external request; the review link is an ordinary link the admin
 * chooses to follow.
 *
 * State:
 *  - option `webdecoy_review_first_seen` — epoch of the first admin page view
 *    after this version, the start of the one-week wait.
 *  - option `webdecoy_review_ask` — '' (pending), 'done', 'never', or
 *    'later:<epoch>' (snoozed until then).
 *
 * @package WebDecoy
 */

// Prevent direct access.
if (!defined('ABSPATH')) {
    exit;
}

/**
 * WebDecoy review ask controller.
 */
class WebDecoy_Review_Ask
{
    public const FIRST_SEEN_OPTION = 'webdecoy_review_first_seen';
    public const STATE_OPTION = 'webdecoy_review_ask';

    /** Wait before the first ask: 7 days (literal to keep the class loadable sans WordPress). */
    public const WAIT = 604800;

    /** "Maybe later" snoozes for 30 days. */
    public const SNOOZE = 2592000;

    public const REVIEW_URL = 'https://wordpress.org/support/plugin/webdecoy/reviews/#new-post';

    private const ACTION = 'webdecoy_review_ask';

    public function register(): void
    {
        if (!is_admin() || WebDecoy_Runtime_Config::hide_admin_ui()) {
            return;
        }
        add_action('admin_notices', [$this, 'render']);
        add_action('admin_post_' . self::ACTION, [$this, 'handle']);
    }

    /**
     * Render the ask on the WordPress dashboard and WebDecoy's own pages, when due.
     */
    public function render(): void
    {
        if (!current_user_can('manage_options') || !self::on_relevant_screen()) {
            return;
        }

        $now = time();
        $first_seen = (int) get_option(self::FIRST_SEEN_OPTION, 0);
        if ($first_seen <= 0) {
            update_option(self::FIRST_SEEN_OPTION, $now, false);
            return;
        }

        $visits = class_exists('WebDecoy_Crawler_Visits') ? WebDecoy_Crawler_Visits::summary(168) : ['total' => 0, 'groups' => ['ai' => 0]];
        $total = (int) ($visits['total'] ?? 0);
        $ai = (int) ($visits['groups']['ai'] ?? 0);

        if (!self::is_due($first_seen, $now, (string) get_option(self::STATE_OPTION, ''), $total)) {
            return;
        }

        $link = static function (string $choice): string {
            return wp_nonce_url(
                admin_url('admin-post.php?action=' . self::ACTION . '&choice=' . $choice),
                self::ACTION
            );
        };
        ?>
        <div class="notice notice-info webdecoy-review-ask">
            <p>
                <strong><?php esc_html_e('WebDecoy:', 'webdecoy'); ?></strong>
                <?php echo esc_html(self::message($total, $ai)); ?>
            </p>
            <p>
                <a href="<?php echo esc_url($link('done')); ?>" class="button button-primary" target="_blank" rel="noopener">
                    <?php esc_html_e('Leave a review', 'webdecoy'); ?>
                </a>
                <a href="<?php echo esc_url($link('later')); ?>" class="button">
                    <?php esc_html_e('Maybe later', 'webdecoy'); ?>
                </a>
                <a href="<?php echo esc_url($link('never')); ?>">
                    <?php esc_html_e("Don't ask again", 'webdecoy'); ?>
                </a>
            </p>
        </div>
        <?php
    }

    /**
     * Record the admin's choice. "Leave a review" continues to wordpress.org;
     * the other two return to the page they came from.
     */
    public function handle(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to do that.', 'webdecoy'), 403);
        }
        check_admin_referer(self::ACTION);

        $choice = isset($_GET['choice']) ? sanitize_key(wp_unslash($_GET['choice'])) : '';
        update_option(self::STATE_OPTION, self::state_for($choice, time()), false);

        if ($choice === 'done') {
            // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- fixed wordpress.org URL
            wp_redirect(self::REVIEW_URL);
            exit;
        }
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
        return $screen->id === 'dashboard' || strpos((string) $screen->id, 'webdecoy') !== false;
    }

    // ---------------------------------------------------------------------
    // Pure helpers (no WordPress calls) — unit-tested in tests/ReviewAskTest.php.
    // ---------------------------------------------------------------------

    /**
     * Whether the ask is due: a week since first seen, bots counted this week,
     * and the admin has neither answered nor snoozed past now.
     */
    public static function is_due(int $first_seen, int $now, string $state, int $bot_visits): bool
    {
        if ($first_seen <= 0 || ($now - $first_seen) < self::WAIT || $bot_visits <= 0) {
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

    /**
     * The stored state for a choice. Anything unrecognised snoozes rather
     * than silencing the ask for good.
     */
    public static function state_for(string $choice, int $now): string
    {
        switch ($choice) {
            case 'done':
                return 'done';
            case 'never':
                return 'never';
            default:
                return 'later:' . ($now + self::SNOOZE);
        }
    }

    /**
     * The ask, built on what the plugin counted this week.
     */
    public static function message(int $total, int $ai): string
    {
        if ($ai > 0) {
            return sprintf(
                /* translators: 1: bot visits counted in 7 days, 2: of which AI crawlers and agents */
                __('In the last 7 days WebDecoy counted %1$s bot visits on this site, %2$s of them from AI crawlers and agents. If that was useful to see, a short review on WordPress.org helps other site owners find it.', 'webdecoy'),
                number_format($total),
                number_format($ai)
            );
        }
        return sprintf(
            /* translators: %s: bot visits counted in 7 days */
            __('In the last 7 days WebDecoy counted %s bot visits on this site. If that was useful to see, a short review on WordPress.org helps other site owners find it.', 'webdecoy'),
            number_format($total)
        );
    }
}
