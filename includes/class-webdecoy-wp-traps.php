<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

/**
 * WordPress-native tripwires (beyond @webdecoy/node parity).
 *
 * Traps that require knowing WordPress internals — the recon patterns every
 * WP scanner (wpscan-style) runs — which the framework-agnostic Node SDK can't
 * express. Each turns a probe into a deterministic detection, and where useful
 * feeds the attacker a canary they'll incriminate themselves with later:
 *
 *  - Fake vulnerable-plugin paths: known scanner-hammered plugin slugs, armed
 *    as tripwire prefixes ONLY when that plugin is not actually installed — so
 *    a real installed plugin's routes are never shadowed.
 *  - XML-RPC probing (opt-in, off by default since legit clients use it).
 *  - Author enumeration (?author=N and the REST users endpoint): instead of
 *    leaking real usernames, records the probe and hands back a canary username.
 *    A later login attempt with that canary is caught as exfiltration
 *    (see WebDecoy_Decoy_Response::is_canary_credential()).
 *
 * Path-based traps are returned as tripwire prefixes/paths and flow through the
 * normal engine (DENY + violation + clearance + optional decoy). The query- and
 * REST-based traps hook WP directly and record a synthetic tripwire violation
 * via the callback supplied to register().
 */
class WebDecoy_WP_Traps
{
    /**
     * Well-known, historically-targeted plugin slugs that scanners probe for.
     * Armed only when the slug is NOT installed here.
     *
     * @var string[]
     */
    private const KNOWN_VULN_SLUGS = [
        'wp-file-manager',
        'revslider',
        'wp-gdpr-compliance',
        'duplicator',
        'wp-fastest-cache',
        'wp-symposium',
        'wp-mobile-detector',
        'simple-fields',
        'work-the-flow-file-upload',
        'wp-support-plus-responsive-ticket-system',
    ];

    /** @var callable|null Called with a WebDecoy\Rules\ViolationEvent-like record. */
    private $recorder;

    /**
     * @param callable|null $recorder function(string $rule, string $path, int|string $confidence): void
     *                                Records + reports a synthetic tripwire hit.
     */
    public function __construct(?callable $recorder = null)
    {
        $this->recorder = $recorder;
    }

    /**
     * Tripwire path prefixes for fake vulnerable-plugin routes — only for
     * plugins that are NOT installed, so a genuinely installed plugin's paths
     * are never trapped.
     *
     * @return string[]
     */
    public static function plugin_path_prefixes(): array
    {
        $prefixes = [];
        $plugin_dir = defined('WP_PLUGIN_DIR') ? WP_PLUGIN_DIR : (defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR . '/plugins' : '');

        foreach (self::KNOWN_VULN_SLUGS as $slug) {
            if ($plugin_dir !== '' && is_dir($plugin_dir . '/' . $slug)) {
                continue; // real plugin present — never trap it
            }
            $prefixes[] = '/wp-content/plugins/' . $slug . '/';
        }

        return $prefixes;
    }

    /**
     * Register the query/REST-based traps (author enumeration). Path-based traps
     * are handled by the engine via plugin_path_prefixes(); this covers the ones
     * the engine can't express.
     */
    public function register(bool $author_enum): void
    {
        if ($author_enum) {
            // Catch ?author=N enumeration before WP resolves and leaks the real
            // username via canonical redirect.
            add_action('template_redirect', [$this, 'guard_author_enum'], 0);
            // Return canary users from the unauthenticated REST users endpoint.
            add_filter('rest_request_after_callbacks', [$this, 'guard_rest_users'], 10, 3);
        }
    }

    /**
     * Detect ?author=N enumeration by an unauthenticated visitor and respond
     * with a fake author page exposing a canary username instead of the real
     * one. Records the probe.
     */
    public function guard_author_enum(): void
    {
        if (is_user_logged_in()) {
            return;
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (!isset($_GET['author'])) {
            return;
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $author = sanitize_text_field(wp_unslash($_GET['author']));
        if (!ctype_digit((string) $author)) {
            return; // /?author=slug is not numeric enumeration
        }

        $this->record('tripwire', '/?author=' . $author);

        $canary = WebDecoy_Decoy_Response::canaries()['author_user'] ?? 'editor';

        nocache_headers();
        status_header(200);
        header('Content-Type: text/html; charset=UTF-8');
        echo '<!DOCTYPE html><html><head><title>Author</title><meta name="robots" content="noindex"></head><body>';
        echo '<h1>Posts by ' . esc_html($canary) . '</h1><p>No posts found.</p>';
        echo '</body></html>';
        exit;
    }

    /**
     * For an unauthenticated GET of the REST users collection, replace the
     * response with a canary user so enumeration harvests a trap identity, and
     * record the probe. Authenticated requests (block editor, etc.) are
     * untouched.
     *
     * @param \WP_REST_Response|\WP_HTTP_Response|\WP_Error $response
     * @param array                                         $handler
     * @param \WP_REST_Request                              $request
     * @return mixed
     */
    public function guard_rest_users($response, $handler, $request)
    {
        if (is_user_logged_in()) {
            return $response;
        }
        if (!($request instanceof \WP_REST_Request)) {
            return $response;
        }
        $route = (string) $request->get_route();
        if (strpos($route, '/wp/v2/users') !== 0) {
            return $response;
        }
        if (strtoupper($request->get_method()) !== 'GET') {
            return $response;
        }

        $this->record('tripwire', $route);

        $canary = WebDecoy_Decoy_Response::canaries()['author_user'] ?? 'editor';
        $fake = [[
            'id' => 1,
            'name' => $canary,
            'slug' => $canary,
        ]];

        return new \WP_REST_Response($fake, 200);
    }

    /**
     * Record a synthetic tripwire hit through the supplied recorder.
     */
    private function record(string $rule, string $path): void
    {
        if (is_callable($this->recorder)) {
            call_user_func($this->recorder, $rule, $path);
        }
    }
}
