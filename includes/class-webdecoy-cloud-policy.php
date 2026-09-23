<?php
/**
 * The site's enforcement policy from WebDecoy Cloud, fetched and cached.
 *
 * Until now every policy this plugin applied was a local option. A site
 * protected by WebDecoy Cloud and this plugin had two policies that could
 * disagree, and the per-path crawler refusals an owner sets in the dashboard
 * never reached WordPress at all. This reads the same public, cacheable
 * config the edge sensor reads, keyed by this site's organization and
 * hostname, so the dashboard, the edge and this plugin resolve one policy.
 *
 * Precedence, stated once:
 *  - The cloud policy governs per-path crawler refusals. It can only refuse;
 *    it never grants a crawler access this plugin would otherwise deny.
 *  - The local "Block AI crawlers" setting is unchanged and site-wide; it can
 *    only add refusals.
 *  - The custom allowlist exempts a bot from the local setting, not from a
 *    cloud path refusal. Remove the refusal in the dashboard instead.
 *  - This plugin's monitor mode still gates every block. A cloud refusal on a
 *    site in monitor mode is counted, not applied.
 *
 * @package WebDecoy
 */

if (!defined('ABSPATH')) {
    exit;
}

class WebDecoy_Cloud_Policy
{
    /** The public config endpoint the edge sensor reads (nothing in it is secret). */
    private const CONFIG_ENDPOINT = 'https://in.webdecoy.com/api/v1/clearance/config';

    /** Where the last good fetch is kept: the config body plus fetched_at. */
    public const OPTION = 'webdecoy_cloud_policy';

    /**
     * How old a cached policy may be before it is not applied. The cron runs
     * twice daily; two days covers a missed run and a host whose cron is
     * sluggish, without letting a policy the owner changed last week keep
     * refusing after they turned it off.
     */
    public const MAX_AGE = 2 * DAY_IN_SECONDS;

    /**
     * Wire the refresh onto the entitlements cron: same cadence, same
     * lifecycle (scheduled on connect, cleared on disconnect).
     */
    public function register(): void
    {
        add_action(WebDecoy_Cloud_Connect::CRON_HOOK, [$this, 'sync']);
    }

    /**
     * Fetch the policy for this site and cache it. On any failure the cached
     * copy is left as it is; get_policy() decides whether it is still usable.
     */
    public function sync(): void
    {
        if (!function_exists('wp_remote_get')) {
            return;
        }
        $organization_id = self::organization_id();
        if ($organization_id === '') {
            return;
        }
        $host = (string) wp_parse_url(home_url(), PHP_URL_HOST);
        $url = add_query_arg(
            ['aid' => $organization_id, 'host' => $host],
            self::CONFIG_ENDPOINT
        );
        $response = wp_remote_get($url, [
            'timeout' => 5,
            'headers' => ['Accept' => 'application/json'],
        ]);
        if (is_wp_error($response)) {
            return;
        }
        $code = (int) wp_remote_retrieve_response_code($response);
        if ($code < 200 || $code >= 300) {
            return;
        }
        $body = json_decode((string) wp_remote_retrieve_body($response), true);
        if (!is_array($body) || !isset($body['mode'])) {
            return;
        }
        update_option(self::OPTION, ['config' => self::relevant($body), 'fetched_at' => time()], false);
    }

    /**
     * Keep only what this plugin reads. The config also carries public keys,
     * credential ids and the deny-list, which the edge needs and this plugin
     * does not; storing them here would be a second copy of things that
     * change without us.
     *
     * @param array<string,mixed> $body
     * @return array<string,mixed>
     */
    private static function relevant(array $body): array
    {
        $keep = ['scope', 'mode', 'routes', 'route_min_trust', 'monitor_routes', 'route_exceptions', 'route_refusals', 'generated_at'];
        $out = [];
        foreach ($keep as $k) {
            if (array_key_exists($k, $body)) {
                $out[$k] = $body[$k];
            }
        }
        return $out;
    }

    /**
     * The policy to apply on this request, or null when there is none to
     * trust: not connected, never fetched, or fetched too long ago.
     *
     * @return array<string,mixed>|null
     */
    public static function get_policy(): ?array
    {
        $cached = get_option(self::OPTION, null);
        if (!is_array($cached) || !is_array($cached['config'] ?? null)) {
            return null;
        }
        $age = time() - (int) ($cached['fetched_at'] ?? 0);
        if ($age > self::MAX_AGE) {
            return null;
        }
        return $cached['config'];
    }

    /**
     * What the settings page says about the cloud policy: whether one is
     * applied, how old it is, and what it refuses.
     *
     * @return array{state:string,fetched_at:int,mode:string,refusing:int,watching:int}
     */
    public static function describe(): array
    {
        $cached = get_option(self::OPTION, null);
        $config = is_array($cached) && is_array($cached['config'] ?? null) ? $cached['config'] : null;
        $fetched_at = is_array($cached) ? (int) ($cached['fetched_at'] ?? 0) : 0;
        if (self::organization_id() === '') {
            $state = 'not_connected';
        } elseif ($config === null) {
            $state = 'not_fetched';
        } elseif (time() - $fetched_at > self::MAX_AGE) {
            $state = 'stale';
        } else {
            $state = 'applied';
        }
        $refusing = 0;
        $watching = 0;
        foreach ((array) ($config['route_refusals'] ?? []) as $r) {
            if (!is_array($r) || empty($r['refuse_behaviors'])) {
                continue;
            }
            if (($r['mode'] ?? '') === 'monitor') {
                $watching++;
            } else {
                $refusing++;
            }
        }
        return [
            'state' => $state,
            'fetched_at' => $fetched_at,
            'mode' => (string) ($config['mode'] ?? ''),
            'refusing' => $refusing,
            'watching' => $watching,
        ];
    }

    /** Drop the cached policy, on disconnect. */
    public static function clear(): void
    {
        delete_option(self::OPTION);
    }

    private static function organization_id(): string
    {
        $options = get_option('webdecoy_options', []);
        return is_array($options) ? (string) ($options['organization_id'] ?? '') : '';
    }
}
