<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Page caches and crawler counts.
 *
 * Crawler visits are counted in PHP (WebDecoy_Crawler_Visits::observe() from
 * early_check()). A full-page cache answers before PHP runs, so on a cached
 * site most crawler page views are never counted. robots.txt, sitemaps and
 * llms.txt are not page-cached, so those fetches still are.
 *
 * This class answers two questions:
 *
 *   detect()   is a page cache in front of WordPress, which one, and can we
 *              ask it to let crawlers through. Admin-side only: constants,
 *              class checks and already-loaded options, nothing per request.
 *
 *   reconcile() make each supported cache plugin's "do not serve cached pages
 *              to these User-Agents" setting match the owner's opt-in. We
 *              record exactly what we add, add nothing the owner already has,
 *              and on opt-out remove only our own entries.
 *
 * The User-Agent tokens come from the shared agent registry, filtered to the
 * categories the dashboard reports as AI and search crawlers. There is no
 * second, hand-maintained list.
 *
 * Supported, each through the plugin's own API (confirmed from its source):
 *
 *   W3 Total Cache   pgcache.reject.ua, saved through Util_Admin::config_save()
 *                    so W3TC rewrites its own rules. Checked on cache reads too.
 *   LiteSpeed Cache  cache-exc_useragents, saved through the litespeed_save_conf
 *                    action, which rewrites its .htaccess rule.
 *   WP Rocket        the rocket_cache_reject_ua filter, then WP Rocket's own
 *                    flush_rocket_htaccess() and rocket_generate_config_file().
 *   WP Super Cache   its rejected-UA list only stops new pages being cached:
 *                    existing cached files are still served to those agents.
 *                    So we register a WP Super Cache plugin file (the
 *                    wpsc_add_plugin action) that turns caching off for the
 *                    request on cache_init, when a crawler token matches. That
 *                    runs only when WP Super Cache serves from PHP; in its
 *                    mod_rewrite mode Apache serves the file first, so that
 *                    mode is reported as not supported.
 */
class WebDecoy_Page_Cache
{
    /** The owner's opt-in (bool). Off by default. */
    public const OPTION = 'webdecoy_cached_crawler_counts';

    /** What we added to each cache plugin, so opt-out removes only that. */
    public const STATE_OPTION = 'webdecoy_cache_bypass_state';

    /** Settings API group for the opt-in form. */
    public const SETTINGS_GROUP = 'webdecoy_page_cache';

    /** LiteSpeed Cache's "Do Not Cache User Agents" option id. */
    private const LITESPEED_UA_KEY = 'cache-exc_useragents';

    /**
     * A token is used only if it reads as a bot name, so an ordinary browser
     * User-Agent never matches by accident (e.g. "copilot" or "siri" alone).
     */
    private const DISTINCTIVE = '/(bot|spider|crawl|-user|search|agent|fetch|inspectiontool|-ai\b|-extended|-web\b)/';

    /** Characters every supported cache plugin's list format takes unescaped. */
    private const SAFE_TOKEN = '/^[a-z0-9][a-z0-9._-]{3,63}$/';

    /** @var list<string>|null */
    private static $tokens = null;

    /**
     * Hook up the opt-in setting and keep cache plugins in step with it.
     */
    public static function register(): void
    {
        // WP Rocket reads this filter whenever it rebuilds its config, which
        // can happen on any request, so it is registered wherever WP Rocket is.
        if (defined('WP_ROCKET_VERSION') && get_option(self::OPTION)) {
            add_filter('rocket_cache_reject_ua', [self::class, 'rocket_reject_ua']);
        }

        if (!is_admin()) {
            return;
        }
        add_action('admin_init', [self::class, 'register_setting']);
        add_action('admin_init', [self::class, 'reconcile'], 20);
        add_action('add_option_' . self::OPTION, [self::class, 'reconcile']);
        add_action('update_option_' . self::OPTION, [self::class, 'reconcile']);
    }

    /**
     * The opt-in, through the Settings API: options.php checks the nonce and
     * manage_options before anything is saved.
     */
    public static function register_setting(): void
    {
        register_setting(self::SETTINGS_GROUP, self::OPTION, [
            'type' => 'boolean',
            'default' => false,
            'sanitize_callback' => [self::class, 'sanitize'],
        ]);
    }

    /**
     * @param mixed $value
     */
    public static function sanitize($value): bool
    {
        return !empty($value);
    }

    /**
     * Is a page cache in front of WordPress, and which one.
     *
     * A host cache wins over a plugin: when the host answers first, letting
     * crawlers through a plugin's cache changes nothing.
     *
     * @return array{kind:string,name:string,key:string,bypass_supported:bool}
     */
    public static function detect(): array
    {
        $host = self::detect_host();
        if ($host !== null) {
            return ['kind' => 'host', 'name' => $host, 'key' => '', 'bypass_supported' => false];
        }

        if (defined('WP_ROCKET_VERSION')) {
            return self::plugin('WP Rocket', 'wp_rocket', true);
        }
        if (defined('W3TC') && self::w3tc_page_cache_enabled()) {
            return self::plugin('W3 Total Cache', 'w3tc', true);
        }
        // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Read LiteSpeed Cache configuration through its published filter.
        if (defined('LSCWP_V') && function_exists('apply_filters') && apply_filters('litespeed_conf', 'cache')) {
            return self::plugin('LiteSpeed Cache', 'litespeed', true);
        }
        if (defined('WPCACHEHOME') && !empty($GLOBALS['cache_enabled'])) {
            return self::plugin('WP Super Cache', 'wp_super_cache', self::wpsc_supported());
        }
        if (class_exists('WpFastestCache', false)) {
            return self::plugin('WP Fastest Cache', '', false);
        }
        if (class_exists('Cache_Enabler', false)) {
            return self::plugin('Cache Enabler', '', false);
        }
        if (defined('SiteGround_Optimizer\VERSION') && get_option('siteground_optimizer_file_caching')) {
            return self::plugin('SiteGround Optimizer file cache', '', false);
        }
        if (defined('WP_CACHE') && WP_CACHE && defined('WP_CONTENT_DIR') && file_exists(WP_CONTENT_DIR . '/advanced-cache.php')) {
            return self::plugin('', '', false);
        }

        return ['kind' => 'none', 'name' => '', 'key' => '', 'bypass_supported' => false];
    }

    /**
     * @return array{kind:string,name:string,key:string,bypass_supported:bool}
     */
    private static function plugin(string $name, string $key, bool $supported): array
    {
        return ['kind' => 'plugin', 'name' => $name, 'key' => $key, 'bypass_supported' => $supported];
    }

    /**
     * A managed host or edge that serves cached pages before WordPress runs.
     */
    private static function detect_host(): ?string
    {
        if (defined('WPE_APIKEY') || class_exists('WpeCommon', false)) {
            return 'WP Engine';
        }
        if (defined('KINSTAMU_VERSION') || !empty($_SERVER['KINSTA_CACHE_ZONE'])) {
            return 'Kinsta';
        }
        if (defined('PANTHEON_ENVIRONMENT') || !empty($_ENV['PANTHEON_ENVIRONMENT'])) {
            return 'Pantheon';
        }
        if (defined('IS_PRESSABLE') && IS_PRESSABLE) {
            return 'Pressable';
        }
        if ((defined('IS_ATOMIC') && IS_ATOMIC) || defined('WPCOMSH_VERSION')) {
            return 'WordPress.com';
        }
        if (defined('SiteGround_Optimizer\VERSION') && (int) get_option('siteground_optimizer_enable_cache', 0) === 1) {
            return 'SiteGround';
        }
        if (defined('CLOUDFLARE_PLUGIN_DIR')) {
            $apo = get_option('automatic_platform_optimization');
            if (is_array($apo) && isset($apo['value']) && $apo['value'] !== false && $apo['value'] !== 'off') {
                return 'Cloudflare APO';
            }
        }
        return null;
    }

    private static function w3tc_page_cache_enabled(): bool
    {
        if (!class_exists('\W3TC\Dispatcher')) {
            return false;
        }
        try {
            return (bool) \W3TC\Dispatcher::config()->get_boolean('pgcache.enabled');
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * WP Super Cache can be asked only when it serves pages from PHP and can
     * load our file by a path relative to ABSPATH.
     */
    private static function wpsc_supported(): bool
    {
        return empty($GLOBALS['wp_cache_mod_rewrite'])
            && self::wpsc_entry() !== ''
            && has_action('wpsc_add_plugin') !== false;
    }

    /**
     * The User-Agent tokens of the crawlers the dashboard reports as AI and
     * search, in registry order, each a distinctive lower-case substring, with
     * any token already covered by a shorter one dropped. Pure given $agents.
     *
     * @param list<array<string,mixed>>|null $agents Registry agents; the bundled registry when null
     * @return list<string>
     */
    public static function crawler_tokens(?array $agents = null): array
    {
        if ($agents === null && self::$tokens !== null) {
            return self::$tokens;
        }
        $source = $agents ?? \WebDecoy\AgentRegistry::all();
        $candidates = [];
        foreach ($source as $agent) {
            // The dashboard's own grouping decides what counts as AI or search.
            if (WebDecoy_Crawler_Visits::group((string) ($agent['category'] ?? '')) === 'other') {
                continue;
            }
            foreach ((array) ($agent['patterns'] ?? []) as $pattern) {
                $pattern = strtolower((string) $pattern);
                if (preg_match(self::SAFE_TOKEN, $pattern) === 1 && preg_match(self::DISTINCTIVE, $pattern) === 1) {
                    $candidates[$pattern] = true;
                }
            }
        }

        $tokens = [];
        $all = array_keys($candidates);
        foreach ($all as $token) {
            foreach ($all as $other) {
                if ($other !== $token && strpos($token, $other) !== false) {
                    continue 2;
                }
            }
            $tokens[] = $token;
        }

        if ($agents === null) {
            self::$tokens = $tokens;
        }
        return $tokens;
    }

    /**
     * Does a User-Agent contain any of the tokens (case-insensitive). Pure.
     *
     * @param list<string> $tokens
     */
    public static function ua_matches(string $userAgent, array $tokens): bool
    {
        if ($userAgent === '') {
            return false;
        }
        $ua = strtolower($userAgent);
        foreach ($tokens as $token) {
            if ($token !== '' && strpos($ua, $token) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * Bring a cache plugin's list in step with what we want in it. Pure.
     *
     * Entries we added before and no longer want are removed (exact match);
     * wanted entries are added unless the list already has them in any case,
     * in which case they stay the owner's and are never recorded as ours.
     *
     * @param list<string> $current   The plugin's list as it is now
     * @param list<string> $ours      What we recorded adding last time
     * @param list<string> $wanted    What we want there now (empty to opt out)
     * @return array{list:list<string>,ours:list<string>}
     */
    public static function sync_list(array $current, array $ours, array $wanted): array
    {
        $list = [];
        foreach ($current as $entry) {
            $entry = (string) $entry;
            if (in_array($entry, $ours, true) && !in_array($entry, $wanted, true)) {
                continue;
            }
            $list[] = $entry;
        }

        $present = array_map('strtolower', $list);
        $kept = [];
        foreach ($wanted as $entry) {
            if (in_array($entry, $ours, true) && in_array($entry, $list, true)) {
                $kept[] = $entry;
                continue;
            }
            if (in_array(strtolower($entry), $present, true)) {
                continue;
            }
            $list[] = $entry;
            $present[] = strtolower($entry);
            $kept[] = $entry;
        }

        return ['list' => $list, 'ours' => $kept];
    }

    /**
     * WP Rocket's reject list is a regex: anchored and case-insensitive in its
     * .htaccess rule, unanchored and case-sensitive in its PHP check. A
     * leading ".*" and an inline (?i:) flag mean the same thing in both. Pure.
     *
     * @param list<string> $tokens
     * @return list<string>
     */
    public static function rocket_patterns(array $tokens): array
    {
        return array_map(static function (string $token): string {
            return '.*(?i:' . preg_quote($token, '#') . ')';
        }, $tokens);
    }

    /**
     * rocket_cache_reject_ua: append our patterns, leave the owner's alone.
     *
     * @param mixed $ua
     * @return array<int,string>
     */
    public static function rocket_reject_ua($ua): array
    {
        $ua = is_array($ua) ? $ua : [];
        $present = array_map('strtolower', array_map('strval', $ua));
        foreach (self::rocket_patterns(self::crawler_tokens()) as $pattern) {
            if (!in_array(strtolower($pattern), $present, true)) {
                $ua[] = $pattern;
            }
        }
        return $ua;
    }

    /**
     * Make every installed, supported cache plugin match the opt-in. Safe to
     * call on any admin request: it writes only when something differs.
     */
    public static function reconcile(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }
        self::apply((bool) get_option(self::OPTION));
    }

    /**
     * Remove everything we added, whatever the setting says. For deactivation.
     */
    public static function remove_all(): void
    {
        self::apply(false);
    }

    /**
     * Bring every installed, supported cache plugin in step with $on.
     *
     * Each adapter reads the plugin's list, sync_list() works out the new one,
     * and it is written back only when something differs. What we added is
     * recorded per plugin; a failed write records nothing.
     *
     * @param array<string,array{available:callable,wanted:callable,read:callable,write:callable}>|null $adapters
     *        The real cache plugins when null; tests pass in-memory ones.
     */
    public static function apply(bool $on, ?array $adapters = null): void
    {
        $state = get_option(self::STATE_OPTION, []);
        $state = is_array($state) ? $state : [];
        $before = $state;
        $tokens = $on ? self::crawler_tokens() : [];

        foreach ($adapters ?? self::adapters() as $key => $adapter) {
            if (!$adapter['available']()) {
                continue;
            }
            $ours = isset($state[$key]) && is_array($state[$key]) ? array_values($state[$key]) : [];
            $wanted = $adapter['wanted']($tokens);
            $current = $adapter['read']($ours);
            $result = self::sync_list($current, $ours, $wanted);
            if ($result['list'] !== $current && !$adapter['write']($result['list'], $current)) {
                continue;
            }
            if ($result['ours'] === []) {
                unset($state[$key]);
            } else {
                $state[$key] = $result['ours'];
            }
        }

        if ($state !== $before) {
            if ($state === []) {
                delete_option(self::STATE_OPTION);
            } else {
                update_option(self::STATE_OPTION, $state, false);
            }
        }
    }

    /**
     * One entry per supported cache plugin, each through that plugin's own
     * API. read() is given what we recorded as ours, for a cache with no list
     * of its own to read (WP Rocket's is a filter, so our record is the list).
     *
     * Public so tests can swap the I/O and keep each plugin's own mapping.
     *
     * @return array<string,array{available:callable,wanted:callable,read:callable,write:callable}>
     */
    public static function adapters(): array
    {
        $same = static function (array $tokens): array {
            return $tokens;
        };

        return [
            'w3tc' => [
                'available' => static function (): bool {
                    return defined('W3TC') && class_exists('\W3TC\Dispatcher') && class_exists('\W3TC\Util_Admin');
                },
                'wanted' => $same,
                'read' => static function (): array {
                    return self::w3tc_read();
                },
                'write' => static function (array $list): bool {
                    return self::w3tc_write($list);
                },
            ],
            'litespeed' => [
                'available' => static function (): bool {
                    return defined('LSCWP_V') && has_action('litespeed_save_conf') !== false;
                },
                'wanted' => $same,
                'read' => static function (): array {
                    // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Read LiteSpeed Cache configuration through its published filter.
                    $list = apply_filters('litespeed_conf', self::LITESPEED_UA_KEY);
                    return is_array($list) ? array_values(array_map('strval', $list)) : [];
                },
                'write' => static function (array $list): bool {
                    // LiteSpeed's public API: saves the option and rewrites
                    // its .htaccess "no cache" rule for these agents.
                    // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Invoke LiteSpeed Cache's settings action.
                    do_action('litespeed_save_conf', [self::LITESPEED_UA_KEY => $list]);
                    return true;
                },
            ],
            'wp_super_cache' => [
                'available' => static function (): bool {
                    return defined('WPCACHEHOME') && has_action('wpsc_add_plugin') !== false && self::wpsc_entry() !== '';
                },
                'wanted' => static function (array $tokens): array {
                    return $tokens === [] ? [] : [self::wpsc_entry()];
                },
                'read' => static function (): array {
                    $plugins = $GLOBALS['wpsc_plugins'] ?? [];
                    return is_array($plugins) ? array_values(array_map('strval', $plugins)) : [];
                },
                'write' => static function (array $list, array $old): bool {
                    // WP Super Cache's own add and remove for plugin files it loads.
                    foreach (array_diff($old, $list) as $file) {
                        // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Invoke WP Super Cache's own cache-plugin registration action.
                        do_action('wpsc_delete_plugin', $file);
                    }
                    foreach (array_diff($list, $old) as $file) {
                        // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Invoke WP Super Cache's own cache-plugin registration action.
                        do_action('wpsc_add_plugin', $file);
                    }
                    return true;
                },
            ],
            'wp_rocket' => [
                'available' => static function (): bool {
                    return defined('WP_ROCKET_VERSION') && function_exists('rocket_generate_config_file');
                },
                'wanted' => static function (array $tokens): array {
                    return $tokens === [] ? [] : [md5(implode('|', self::rocket_patterns($tokens)))];
                },
                'read' => static function (array $ours): array {
                    return $ours;
                },
                'write' => static function (array $list): bool {
                    remove_filter('rocket_cache_reject_ua', [self::class, 'rocket_reject_ua']);
                    if ($list !== []) {
                        add_filter('rocket_cache_reject_ua', [self::class, 'rocket_reject_ua']);
                    }
                    // What WP Rocket itself runs when a reject list changes.
                    if (function_exists('flush_rocket_htaccess')) {
                        flush_rocket_htaccess();
                    }
                    rocket_generate_config_file();
                    return true;
                },
            ],
        ];
    }

    /**
     * @return list<string>
     */
    private static function w3tc_read(): array
    {
        try {
            return array_values(array_map('strval', (array) \W3TC\Dispatcher::config()->get_array('pgcache.reject.ua')));
        } catch (\Throwable $e) {
            return [];
        }
    }

    /**
     * Saved the way W3TC's own settings screen saves, so it regenerates its
     * rewrite rules and page-cache config itself.
     *
     * @param list<string> $list
     */
    private static function w3tc_write(array $list): bool
    {
        try {
            $current = \W3TC\Dispatcher::config();
            $new = new \W3TC\Config();
            $new->set('pgcache.reject.ua', $list);
            \W3TC\Util_Admin::config_save($current, $new);
        } catch (\Throwable $e) {
            return false;
        }
        try {
            // What W3TC runs on its own admin pages: rewrites .htaccess and
            // nginx.conf rules (Disk: Enhanced) for the new list now.
            \W3TC\Dispatcher::component('Root_Environment')->fix_in_wpadmin($new);
        } catch (\Throwable $e) {
            unset($e); // W3TC retries on its next admin page and reports there.
        }
        return true;
    }

    /**
     * Our WP Super Cache plugin file, relative to ABSPATH the way WP Super
     * Cache stores and loads it. Empty when the plugin lives outside ABSPATH.
     */
    public static function wpsc_entry(): string
    {
        $file = WEBDECOY_PLUGIN_DIR . 'includes/wpsc-crawler-bypass.php';
        if (strpos($file, ABSPATH) !== 0) {
            return '';
        }
        return substr($file, strlen(ABSPATH));
    }
}
