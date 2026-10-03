<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

/**
 * IP enrichment client — fetches VPN/proxy/Tor, geo, ASN, and abuse-score data
 * for an IP from the ingest service, for use by `ip.*` filter-rule fields.
 *
 * PHP port of @webdecoy/node's IPEnrichmentClient. Differences forced by the
 * per-request PHP model:
 *  - Cache is a WordPress transient (1h TTL) instead of an in-process Map, so it
 *    survives across requests. No in-flight dedupe is needed (each request is a
 *    single process).
 *  - Fetch is lazy at the call site: the caller only enriches when a configured
 *    filter rule actually references an `ip.*` field.
 *
 * Cloud feature: requires an API key. Fails open — any error (no key, timeout,
 * bad response) returns null, and an `ip.*` field then resolves to undefined
 * (its comparisons evaluate false), matching node.
 */
class WebDecoy_IP_Enrichment
{
    private const ENDPOINT_BASE = 'https://in.webdecoy.com/api/v1/sdk/ip/';

    /** Cache TTL — 1 hour, matching node's ttlMs default. */
    private const TTL = HOUR_IN_SECONDS;

    /** @var string */
    private $apiKey;

    /** @var int Request timeout in seconds (filterable). */
    private $timeout;

    /**
     * Constructor
     *
     * @param string $apiKey WebDecoy Cloud API key
     */
    public function __construct(string $apiKey)
    {
        $this->apiKey = $apiKey;
        $this->timeout = (int) apply_filters('webdecoy_enrichment_timeout', 2);
    }

    /**
     * Get enrichment data for an IP. Returns the node-shaped nested array
     * (security/location/network/reputation/categories) or null on any failure.
     *
     * @return array<string,mixed>|null
     */
    public function enrich(string $ip): ?array
    {
        if ($this->apiKey === '' || $ip === '') {
            return null;
        }

        // Entitlement gate (P1 contract §3): enrichment is a paid Cloud feature.
        // When we positively know the org isn't entitled (a synced entitlements
        // cache with features.enrichment false), fail silently to no-enrichment —
        // no remote call is made, and ip.* fields resolve to undefined just as
        // they do without a key. A never-synced cache (fetched_at 0, e.g. a
        // manual-key install) falls through and lets the server make the call
        // (it 403s wordpress-channel orgs that lack enrichment).
        if (class_exists('WebDecoy_Cloud_Connect')) {
            $entitlements = WebDecoy_Cloud_Connect::get_entitlements();
            $fetched_at = isset($entitlements['fetched_at']) ? (int) $entitlements['fetched_at'] : 0;
            if ($fetched_at > 0 && empty($entitlements['features']['enrichment'])) {
                return null;
            }
        }

        $cacheKey = 'webdecoy_enrich_' . md5($ip);
        $cached = get_transient($cacheKey);
        if (is_array($cached)) {
            return $cached;
        }
        // Cache negative results briefly too, so a bad IP doesn't refetch every
        // request. Stored as the string 'none'.
        if ($cached === 'none') {
            return null;
        }

        // While ingest is refusing work, skip the call instead of making this
        // page wait out the timeout for every new IP (WebDecoy/app#1245).
        if (class_exists('WebDecoy_Detection_Sender') && WebDecoy_Detection_Sender::backing_off()) {
            return null;
        }

        $data = $this->fetch($ip);

        if ($data === null) {
            set_transient($cacheKey, 'none', MINUTE_IN_SECONDS * 5);
            return null;
        }

        set_transient($cacheKey, $data, self::TTL);
        return $data;
    }

    /**
     * @return array<string,mixed>|null
     */
    private function fetch(string $ip): ?array
    {
        if (!function_exists('wp_remote_get')) {
            return null;
        }

        $url = self::ENDPOINT_BASE . rawurlencode($ip) . '/enrichment';

        $response = wp_remote_get($url, [
            'timeout' => $this->timeout,
            'headers' => [
                'Authorization' => 'Bearer ' . $this->apiKey,
                'Accept' => 'application/json',
            ],
        ]);

        if (is_wp_error($response)) {
            self::note_refusal();
            return null;
        }
        $code = (int) wp_remote_retrieve_response_code($response);
        if ($code === 429 || $code >= 500) {
            self::note_refusal();
        }
        if ($code !== 200) {
            return null;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (!is_array($data) || !isset($data['security'])) {
            return null;
        }

        return $data;
    }

    /** Pause cloud calls after an unavailable answer (WebDecoy/app#1245). */
    private static function note_refusal(): void
    {
        if (class_exists('WebDecoy_Detection_Sender')) {
            WebDecoy_Detection_Sender::note_refusal();
        }
    }
}
