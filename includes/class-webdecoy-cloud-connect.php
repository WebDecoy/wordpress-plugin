<?php
/**
 * WebDecoy Cloud Connect
 *
 * Owns the one-click "Connect to WebDecoy Cloud" flow and the entitlements
 * sync. The connect flow is strictly user-initiated: the plugin makes NO
 * external HTTP request until the admin clicks "Connect". After a successful
 * connect the entitlements endpoint is polled twice daily to keep the local
 * feature switchboard current, failing open to the free tier on any error.
 *
 * Connect handshake (authoritative contract, see WebDecoy/wordpress-plugin#40):
 *
 *  1. Admin clicks Connect. We mint a 64-hex nonce, stash it in a 15-minute
 *     transient, and redirect the browser to the app connect page carrying the
 *     nonce, site details, digest-consent bit, and a return URL.
 *  2. The app (Auth0 session) provisions/reuses an org + property, mints a
 *     one-time connect token bound to site_url + nonce, and redirects the
 *     browser back to our return URL with `wd_connect_token` appended.
 *  3. We exchange that token server-side for the API key, publishable site key,
 *     and org metadata, then persist them locally. The token is single-use.
 *  4. Entitlements are fetched with the API key (same auth scheme as the
 *     violation reporter) and cached locally.
 *
 * @package WebDecoy
 */

// Prevent direct access.
if (!defined('ABSPATH')) {
    exit;
}

/**
 * WebDecoy Cloud Connect controller.
 */
class WebDecoy_Cloud_Connect
{
    /** User-facing app page that walks the admin through approving the connect. */
    private const CONNECT_URL = 'https://app.webdecoy.com/connect/wordpress';

    /** Server-to-server exchange: one-time connect token -> credentials. */
    private const EXCHANGE_ENDPOINT = 'https://api.webdecoy.com/api/v1/connect/wordpress/exchange';

    /**
     * Entitlements endpoint. Authenticated with the API key exactly like
     * {@see WebDecoy_Violation_Reporter} authenticates the violations batch:
     * an `Authorization: Bearer <api_key>` header against the ingest service.
     */
    private const ENTITLEMENTS_ENDPOINT = 'https://ingest.webdecoy.com/api/v1/sdk/entitlements';

    /** Where the generic "Upgrade" link points once connected. */
    private const BILLING_URL = 'https://app.webdecoy.com/billing';

    /** WordPress-channel checkout entry point (contract §4). */
    private const WP_BILLING_URL = 'https://app.webdecoy.com/billing/wordpress';

    /** Valid WordPress plan slugs the checkout accepts. */
    private const WP_PLANS = ['wp_pro', 'wp_woo', 'wp_agency'];

    /** Transient holding the pending connect nonce (site-scoped, one flow at a time). */
    private const NONCE_TRANSIENT = 'webdecoy_connect_nonce';

    /** Connect nonce lifetime: 15 minutes (literal to avoid a WP-constant load dependency). */
    private const NONCE_TTL = 900;

    /** Option caching the last entitlements response (+ a fetched_at timestamp). */
    private const ENTITLEMENTS_OPTION = 'webdecoy_entitlements';

    /** Transient carrying a one-shot admin notice across the post-connect redirect. */
    private const NOTICE_TRANSIENT = 'webdecoy_connect_notice';

    /** Entitlements older than 12 hours are treated as stale (still served). */
    private const ENTITLEMENTS_STALE_AFTER = 43200;

    /** Twice-daily cron hook that refreshes entitlements. */
    public const CRON_HOOK = 'webdecoy_sync_entitlements';

    /** Feature flags the entitlements contract defines. All default to false (fail open to free). */
    private const FEATURE_KEYS = ['actor_feed', 'enrichment', 'alerts', 'edge_push', 'decoy_packs', 'woo_intel'];

    /**
     * Wire up the flow. The cron handler is always registered (wp-cron can fire
     * on any front-end request); the interactive handlers only in wp-admin.
     */
    public function register(): void
    {
        add_action(self::CRON_HOOK, [$this, 'sync_entitlements']);

        if (!is_admin()) {
            return;
        }

        add_action('admin_post_webdecoy_cloud_connect', [$this, 'handle_connect']);
        add_action('admin_post_webdecoy_cloud_disconnect', [$this, 'handle_disconnect']);
        add_action('admin_init', [$this, 'maybe_handle_return']);
        add_action('admin_notices', [$this, 'render_notices']);
    }

    /**
     * Step 1: mint the nonce and redirect the browser to the app connect page.
     * This is the FIRST point at which the plugin ever leaves the site, and only
     * because the admin clicked "Connect".
     */
    public function handle_connect(): void
    {
        check_admin_referer('webdecoy_cloud_connect');

        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to connect this site.', 'webdecoy'));
        }

        // 64 hex chars of CSPRNG output; also the app<->exchange binding value.
        $nonce = bin2hex(random_bytes(32));
        set_transient(self::NONCE_TRANSIENT, $nonce, self::NONCE_TTL);

        // Consent checkbox: a boolean presence check (the value is never used).
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- boolean presence only; nonce already verified above
        $digest = !empty($_POST['digest']) ? '1' : '0';

        // Build the query with http_build_query so every value is encoded
        // exactly once (WP's add_query_arg does not encode appended args).
        $query = http_build_query([
            'site_url'   => home_url(),
            'site_name'  => get_bloginfo('name'),
            'nonce'      => $nonce,
            'digest'     => $digest,
            'return_url' => admin_url('admin.php?page=webdecoy&tab=cloud&wd_connect=1'),
        ]);
        $url = self::CONNECT_URL . '?' . $query;

        // Intentional off-site redirect to the user-chosen Cloud host; not a
        // same-origin navigation, so wp_safe_redirect() is not applicable.
        // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
        wp_redirect(esc_url_raw($url));
        exit;
    }

    /**
     * Step 3: on the settings-page return, exchange the one-time token for
     * credentials and persist them. Authenticity rests on three checks: the
     * caller must hold manage_options, our one-time transient nonce must still
     * exist (proving this browser started the flow), and the exchange token is
     * server-validated as single-use and bound to site_url + nonce.
     */
    public function maybe_handle_return(): void
    {
        // Routing only; no state changes here. The state-changing exchange below
        // is gated by capability + the one-time server-stored transient nonce.
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $page = isset($_GET['page']) ? sanitize_key(wp_unslash($_GET['page'])) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if ($page !== 'webdecoy' || !isset($_GET['wd_connect'])) {
            return;
        }

        if (!current_user_can('manage_options')) {
            return;
        }

        // Explicit denial from the app: surface it, change nothing.
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $error = isset($_GET['wd_connect_error']) ? sanitize_key(wp_unslash($_GET['wd_connect_error'])) : '';
        if ($error !== '') {
            $this->set_notice('error', __('Connection was cancelled. No changes were made.', 'webdecoy'));
            $this->redirect_clean();
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $raw_token = isset($_GET['wd_connect_token']) ? sanitize_text_field(wp_unslash($_GET['wd_connect_token'])) : '';
        // Further reduce to a strict URL-token charset before use.
        $token = self::sanitize_connect_token($raw_token);
        if ($token === '') {
            // No token and no error — likely a stale/bookmarked return URL. Do nothing.
            return;
        }

        $nonce = get_transient(self::NONCE_TRANSIENT);
        if (!is_string($nonce) || !self::is_hex($nonce, 64)) {
            $this->set_notice('error', __('Your connect session expired before it completed. Please click Connect again.', 'webdecoy'));
            $this->redirect_clean();
        }

        $result = $this->exchange_token($token, $nonce);

        if ($result === null) {
            // exchange_token() has already recorded the specific failure notice.
            $this->redirect_clean();
        }

        // Persist credentials + org metadata (API key encrypted at rest by the
        // main plugin, mirroring the manual-entry path).
        webdecoy()->store_cloud_credentials(
            (string) ($result['api_key'] ?? ''),
            (string) ($result['site_key'] ?? ''),
            (string) ($result['organization_id'] ?? ''),
            (string) ($result['organization_name'] ?? ''),
            (string) ($result['plan'] ?? 'free_connected')
        );

        // Single-use: burn the nonce so the token can't be replayed.
        delete_transient(self::NONCE_TRANSIENT);

        // Pull entitlements immediately, then keep them fresh twice daily.
        $this->sync_entitlements();
        $this->schedule_sync();

        $org = (string) ($result['organization_name'] ?? '');
        $this->set_notice(
            'success',
            $org !== ''
                /* translators: %s: organization name */
                ? sprintf(__('Connected to WebDecoy Cloud (%s). Cloud features are now active.', 'webdecoy'), $org)
                : __('Connected to WebDecoy Cloud. Cloud features are now active.', 'webdecoy')
        );
        $this->redirect_clean();
    }

    /**
     * Disconnect: clear credentials, org metadata, and cached entitlements
     * locally. No remote call is made (P0 contract).
     */
    public function handle_disconnect(): void
    {
        check_admin_referer('webdecoy_cloud_disconnect');

        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to disconnect this site.', 'webdecoy'));
        }

        webdecoy()->clear_cloud_credentials();
        delete_option(self::ENTITLEMENTS_OPTION);
        delete_transient(self::NONCE_TRANSIENT);
        wp_clear_scheduled_hook(self::CRON_HOOK);

        $this->set_notice('success', __('Disconnected from WebDecoy Cloud. Local protection remains active.', 'webdecoy'));
        $this->redirect_clean();
    }

    /**
     * POST the one-time token to the exchange endpoint. Returns the decoded
     * credentials array on success, or null (with a notice already set) on any
     * failure.
     *
     * @return array<string,mixed>|null
     */
    private function exchange_token(string $token, string $nonce): ?array
    {
        $response = wp_remote_post(self::EXCHANGE_ENDPOINT, [
            'timeout' => 10,
            'headers' => [
                'Content-Type' => 'application/json',
                'Accept'       => 'application/json',
            ],
            'body' => wp_json_encode([
                'connect_token' => $token,
                'site_url'      => home_url(),
                'nonce'         => $nonce,
            ]),
        ]);

        if (is_wp_error($response)) {
            $this->set_notice('error', __('Could not reach WebDecoy Cloud to complete the connection. Please try again.', 'webdecoy'));
            return null;
        }

        $code = (int) wp_remote_retrieve_response_code($response);
        $body = json_decode((string) wp_remote_retrieve_body($response), true);
        $body = is_array($body) ? $body : [];

        if ($code < 200 || $code >= 300) {
            $reason = isset($body['error']) && is_string($body['error']) && $body['error'] !== ''
                ? $body['error']
                : __('the connection token was invalid or expired', 'webdecoy');
            $this->set_notice(
                'error',
                /* translators: %s: reason the connection failed */
                sprintf(__('WebDecoy Cloud declined the connection: %s. Please click Connect again.', 'webdecoy'), $reason)
            );
            return null;
        }

        if (empty($body['api_key'])) {
            $this->set_notice('error', __('WebDecoy Cloud returned an incomplete response. Please try again.', 'webdecoy'));
            return null;
        }

        return $body;
    }

    /**
     * Fetch entitlements with the stored API key and cache the normalized
     * response. On any error the existing cache is left untouched and the
     * accessor continues to fail open to free. Runs after connect and twice
     * daily via {@see self::CRON_HOOK}.
     */
    public function sync_entitlements(): void
    {
        if (!function_exists('wp_remote_get')) {
            return;
        }

        $options = webdecoy()->get_options();
        $api_key = isset($options['api_key']) ? (string) $options['api_key'] : '';
        if ($api_key === '') {
            return;
        }

        // Same auth scheme as WebDecoy_Violation_Reporter::send(): the API key
        // as a Bearer token in the Authorization header.
        $response = wp_remote_get(self::ENTITLEMENTS_ENDPOINT, [
            'timeout' => 5,
            'headers' => [
                'Accept'        => 'application/json',
                'Authorization' => 'Bearer ' . $api_key,
            ],
        ]);

        if (is_wp_error($response)) {
            return;
        }
        $code = (int) wp_remote_retrieve_response_code($response);
        if ($code < 200 || $code >= 300) {
            return;
        }

        $body = json_decode((string) wp_remote_retrieve_body($response), true);
        if (!is_array($body)) {
            return;
        }

        $body['fetched_at'] = time();
        update_option(self::ENTITLEMENTS_OPTION, self::normalize_entitlements($body, time()), false);
    }

    /**
     * Ensure the twice-daily entitlements refresh is scheduled.
     */
    private function schedule_sync(): void
    {
        if (!wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_event(time(), 'twicedaily', self::CRON_HOOK);
        }
    }

    /**
     * Normalized entitlements accessor. Always returns a complete, typed shape;
     * a missing/invalid cache fails open to the free tier (all features false).
     *
     * @return array{plan:string,channel:string,features:array<string,bool>,digest:array{enabled:bool},fetched_at:int,stale:bool}
     */
    public static function get_entitlements(): array
    {
        $cached = get_option(self::ENTITLEMENTS_OPTION, []);
        return self::normalize_entitlements(is_array($cached) ? $cached : [], time());
    }

    /**
     * Whether this site is connected to WebDecoy Cloud (an API key is stored).
     */
    public static function is_connected(): bool
    {
        $options = get_option('webdecoy_options', []);
        return is_array($options) && !empty($options['api_key']);
    }

    /**
     * The URL the generic "Upgrade" link points to.
     */
    public static function billing_url(): string
    {
        return self::BILLING_URL;
    }

    /**
     * The WordPress-channel checkout URL for a given plan (contract §4):
     * `.../billing/wordpress?organization_id={id}&plan={wp_pro|wp_woo|wp_agency}`.
     *
     * The org id defaults to the stored one when not supplied. An unrecognized
     * plan falls back to `wp_pro`.
     */
    public static function wp_upgrade_url(string $plan = 'wp_pro', string $organization_id = ''): string
    {
        if (!in_array($plan, self::WP_PLANS, true)) {
            $plan = 'wp_pro';
        }

        if ($organization_id === '') {
            $options = get_option('webdecoy_options', []);
            if (is_array($options) && isset($options['organization_id'])) {
                $organization_id = (string) $options['organization_id'];
            }
        }

        // http_build_query encodes each value exactly once (add_query_arg does not).
        $query = http_build_query([
            'organization_id' => $organization_id,
            'plan'            => $plan,
        ]);

        return self::WP_BILLING_URL . '?' . $query;
    }

    // ---------------------------------------------------------------------
    // Pure helpers (no WordPress calls) — unit-tested in tests/CloudConnectTest.php.
    // ---------------------------------------------------------------------

    /**
     * Normalize a raw entitlements payload into the canonical shape. Pure: the
     * caller supplies "now" so staleness is deterministic and testable.
     *
     * @param array<string,mixed> $raw
     * @return array{plan:string,channel:string,features:array<string,bool>,digest:array{enabled:bool},fetched_at:int,stale:bool}
     */
    public static function normalize_entitlements(array $raw, int $now): array
    {
        $features_in = isset($raw['features']) && is_array($raw['features']) ? $raw['features'] : [];
        $features = [];
        foreach (self::FEATURE_KEYS as $key) {
            $features[$key] = !empty($features_in[$key]);
        }

        $plan = isset($raw['plan']) && is_string($raw['plan']) && $raw['plan'] !== '' ? $raw['plan'] : 'free';
        $channel = isset($raw['channel']) && is_string($raw['channel']) ? $raw['channel'] : '';

        $digest_in = isset($raw['digest']) && is_array($raw['digest']) ? $raw['digest'] : [];
        $digest_enabled = !empty($digest_in['enabled']);

        $fetched_at = isset($raw['fetched_at']) ? (int) $raw['fetched_at'] : 0;
        $age = $fetched_at > 0 ? ($now - $fetched_at) : PHP_INT_MAX;
        $stale = $age > self::ENTITLEMENTS_STALE_AFTER;

        return [
            'plan'       => $plan,
            'channel'    => $channel,
            'features'   => $features,
            'digest'     => ['enabled' => $digest_enabled],
            'fetched_at' => $fetched_at,
            'stale'      => $stale,
        ];
    }

    /**
     * Constant-form hex check. `$length` of 0 means "any non-empty length".
     */
    public static function is_hex(string $value, int $length = 0): bool
    {
        if ($value === '') {
            return false;
        }
        if ($length > 0 && strlen($value) !== $length) {
            return false;
        }
        return ctype_xdigit($value) === true;
    }

    /**
     * Reduce an inbound connect token to safe, URL-token characters and cap its
     * length. Returns '' when nothing usable survives.
     */
    public static function sanitize_connect_token(string $raw): string
    {
        $token = preg_replace('/[^A-Za-z0-9._\-]/', '', $raw);
        if (!is_string($token)) {
            return '';
        }
        return substr($token, 0, 256);
    }

    /**
     * Human-readable label for a plan slug (e.g. free_connected -> "Free Connected").
     */
    public static function plan_label(string $plan): string
    {
        if ($plan === '' ) {
            return 'Connected';
        }
        if ($plan === 'free_connected') {
            return 'Free Connected';
        }
        return ucwords(str_replace(['_', '-'], ' ', $plan));
    }

    // ---------------------------------------------------------------------
    // Admin notices (one-shot, carried across the redirect via a transient).
    // ---------------------------------------------------------------------

    /**
     * Store a one-shot admin notice.
     */
    private function set_notice(string $type, string $message): void
    {
        set_transient(self::NOTICE_TRANSIENT, ['type' => $type, 'message' => $message], MINUTE_IN_SECONDS);
    }

    /**
     * Render (and consume) any pending connect notice.
     */
    public function render_notices(): void
    {
        $notice = get_transient(self::NOTICE_TRANSIENT);
        if (!is_array($notice) || empty($notice['message'])) {
            return;
        }
        delete_transient(self::NOTICE_TRANSIENT);

        $class = ($notice['type'] ?? 'success') === 'error' ? 'notice-error' : 'notice-success';
        printf(
            '<div class="notice %s is-dismissible"><p><strong>%s</strong> %s</p></div>',
            esc_attr($class),
            esc_html__('WebDecoy Cloud:', 'webdecoy'),
            esc_html((string) $notice['message'])
        );
    }

    /**
     * Redirect back to the clean Cloud tab (stripping the one-time token from
     * the address bar) and stop. Never returns.
     */
    private function redirect_clean(): void
    {
        wp_safe_redirect(admin_url('admin.php?page=webdecoy&tab=cloud'));
        exit;
    }
}
