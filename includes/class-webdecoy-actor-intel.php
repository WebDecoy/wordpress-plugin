<?php
/**
 * WebDecoy Actor Intel
 *
 * Batched cross-network intelligence lookups for the Detections admin list and
 * the post-CRITICAL moment. One POST per render resolves the unique IPs on the
 * page (<= 50) that aren't already cached; each IP's normalized result is cached
 * in a transient for one hour.
 *
 * Requires a Cloud connection (any connected plan). Free-connected orgs receive
 * a redacted teaser (known / count / first-seen / last-seen only); Pro+ receive
 * full fields (tor / vpn / abuse score / actor). The server decides the tier and
 * sets `redacted`; this client trusts that flag and never surfaces fields the
 * server withheld.
 *
 * Fails silently to "no intel" on any error (no key, timeout, non-200, bad
 * shape): the caller renders an em-dash, never a broken table. A successful
 * response that simply doesn't mention an IP is cached as a negative so the page
 * doesn't refetch it every load.
 *
 * @package WebDecoy
 */

// Prevent direct access.
if (!defined('ABSPATH')) {
    exit;
}

/**
 * WebDecoy Actor Intel client.
 */
class WebDecoy_Actor_Intel
{
    /** Batched intel endpoint (Bearer API key). */
    private const ENDPOINT = 'https://ingest.webdecoy.com/api/v1/sdk/detections/intel';

    /** Per-IP transient cache prefix. */
    private const CACHE_PREFIX = 'webdecoy_intel_';

    /** Cache TTL — 1 hour (literal to keep the class loadable without WordPress). */
    private const TTL = 3600;

    /** Contract cap: at most 50 IPs per request. */
    public const MAX_IPS = 50;

    /** Request timeout (seconds). */
    private const TIMEOUT = 5;

    /** @var string Plaintext API key. */
    private $apiKey;

    public function __construct(string $apiKey)
    {
        $this->apiKey = $apiKey;
    }

    /**
     * Resolve intel for a set of IPs. Returns ip => normalized-intel-array for
     * every input IP that resolved (cached or freshly fetched); IPs that failed
     * to resolve are simply absent from the map (caller shows an em-dash).
     *
     * At most one batched request is made per call, covering only the uncached,
     * valid, unique IPs (capped at 50).
     *
     * @param array<int,string> $ips
     * @return array<string,array<string,mixed>>
     */
    public function lookup(array $ips): array
    {
        $ips = self::unique_ips($ips, self::MAX_IPS);
        if ($ips === [] || $this->apiKey === '') {
            return [];
        }

        $out = [];
        $need = [];

        foreach ($ips as $ip) {
            $cached = get_transient(self::CACHE_PREFIX . md5($ip));
            if (is_array($cached)) {
                $out[$ip] = $cached;
            } elseif ($cached === 'none') {
                // Known-negative: resolved, but not present in the network.
                continue;
            } else {
                $need[] = $ip;
            }
        }

        if ($need !== []) {
            $fetched = $this->fetch($need);
            if ($fetched !== null) {
                foreach ($need as $ip) {
                    if (isset($fetched[$ip]) && is_array($fetched[$ip])) {
                        $normalized = self::normalize_result($fetched[$ip]);
                        set_transient(self::CACHE_PREFIX . md5($ip), $normalized, self::TTL);
                        $out[$ip] = $normalized;
                    } else {
                        // Successful response that omitted this IP — cache the
                        // negative so we don't re-ask for an hour.
                        set_transient(self::CACHE_PREFIX . md5($ip), 'none', self::TTL);
                    }
                }
            }
            // On outright failure ($fetched === null) we cache nothing: the IPs
            // stay unresolved and simply render as em-dashes this page load.
        }

        return $out;
    }

    /**
     * POST the batch and return the raw `results` map, or null on any failure.
     *
     * @param array<int,string> $ips
     * @return array<string,mixed>|null
     */
    private function fetch(array $ips): ?array
    {
        if (!function_exists('wp_remote_post')) {
            return null;
        }

        $response = wp_remote_post(self::ENDPOINT, [
            'timeout' => self::TIMEOUT,
            'headers' => [
                'Content-Type'  => 'application/json',
                'Accept'        => 'application/json',
                'Authorization' => 'Bearer ' . $this->apiKey,
            ],
            'body' => wp_json_encode(['ips' => array_values($ips)]),
        ]);

        if (is_wp_error($response)) {
            return null;
        }
        if ((int) wp_remote_retrieve_response_code($response) !== 200) {
            return null;
        }

        $body = json_decode((string) wp_remote_retrieve_body($response), true);
        if (!is_array($body) || !isset($body['results']) || !is_array($body['results'])) {
            return null;
        }

        return $body['results'];
    }

    // ---------------------------------------------------------------------
    // Pure helpers (no WordPress calls) — unit-tested in tests/ActorIntelTest.php.
    // ---------------------------------------------------------------------

    /**
     * Normalize one IP's raw intel entry into a complete, typed shape. Honors
     * the server's `redacted` flag: when redacted, the enriched fields
     * (tor/vpn/abuse_score/actor) are forced null regardless of what the payload
     * contains, so a free-connected teaser can never leak Pro-only intel.
     *
     * @param array<string,mixed> $raw
     * @return array{known:bool,network_detections:int,first_seen:int,last_seen:int,redacted:bool,tor:?bool,vpn:?bool,abuse_score:?int,actor:?array{id:string,sites:int}}
     */
    public static function normalize_result(array $raw): array
    {
        $redacted = !empty($raw['redacted']);

        $result = [
            'known'              => !empty($raw['known']),
            'network_detections' => isset($raw['network_detections']) ? max(0, (int) $raw['network_detections']) : 0,
            'first_seen'         => isset($raw['first_seen']) ? (int) $raw['first_seen'] : 0,
            'last_seen'          => isset($raw['last_seen']) ? (int) $raw['last_seen'] : 0,
            'redacted'           => $redacted,
            'tor'                => null,
            'vpn'                => null,
            'abuse_score'        => null,
            'actor'              => null,
        ];

        if (!$redacted) {
            if (array_key_exists('tor', $raw)) {
                $result['tor'] = (bool) $raw['tor'];
            }
            if (array_key_exists('vpn', $raw)) {
                $result['vpn'] = (bool) $raw['vpn'];
            }
            if (isset($raw['abuse_score'])) {
                $result['abuse_score'] = max(0, min(100, (int) $raw['abuse_score']));
            }
            if (isset($raw['actor']) && is_array($raw['actor'])) {
                $result['actor'] = [
                    'id'    => isset($raw['actor']['id']) ? (string) $raw['actor']['id'] : '',
                    'sites' => isset($raw['actor']['sites']) ? max(0, (int) $raw['actor']['sites']) : 0,
                ];
            }
        }

        return $result;
    }

    /**
     * Dedupe, validate, and cap a list of IPs for a batch request.
     *
     * @param array<int,mixed> $ips
     * @return array<int,string>
     */
    public static function unique_ips(array $ips, int $max): array
    {
        if ($max < 0) {
            $max = 0;
        }
        $seen = [];
        foreach ($ips as $ip) {
            if (count($seen) >= $max) {
                break;
            }
            $ip = is_string($ip) ? trim($ip) : '';
            if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
                continue;
            }
            $seen[$ip] = true;
        }
        return array_keys($seen);
    }
}
