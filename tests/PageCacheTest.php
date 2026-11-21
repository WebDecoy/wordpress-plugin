<?php

declare(strict_types=1);

/**
 * Page caches and crawler counts: which crawler tokens are used, detection,
 * and the add/remove round trip for each supported cache plugin, with the
 * owner's own entries surviving both directions.
 *
 * Run: php tests/run.php
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/');
}
if (!defined('WEBDECOY_PLUGIN_DIR')) {
    define('WEBDECOY_PLUGIN_DIR', ABSPATH . 'wp-content/plugins/webdecoy/');
}
if (!isset($GLOBALS['__wd_opts'])) {
    $GLOBALS['__wd_opts'] = [];
}
// Option and hook stubs, guarded so they never replace a real WordPress and
// shaped like the other tests' stubs (options live in $GLOBALS['__wd_opts']).
if (!function_exists('get_option')) {
    function get_option($k, $d = false)
    {
        return $GLOBALS['__wd_opts'][$k] ?? $d;
    }
}
if (!function_exists('update_option')) {
    function update_option($k, $v, $autoload = null)
    {
        unset($autoload);
        $GLOBALS['__wd_opts'][$k] = $v;
        return true;
    }
}
if (!function_exists('delete_option')) {
    function delete_option($k)
    {
        unset($GLOBALS['__wd_opts'][$k]);
        return true;
    }
}
if (!function_exists('apply_filters')) {
    function apply_filters($hook, $value) { return $value; } // phpcs:ignore
}
// do_action/has_action dispatch to handlers a test registers in
// $GLOBALS['__wd_pc_handlers'], and record every call.
if (!function_exists('do_action')) {
    function do_action($hook, ...$args)
    {
        $GLOBALS['__wd_pc_actions'][] = [$hook, $args];
        if (isset($GLOBALS['__wd_pc_handlers'][$hook])) {
            ($GLOBALS['__wd_pc_handlers'][$hook])(...$args);
        }
    }
}
if (!function_exists('has_action')) {
    function has_action($hook, $cb = false)
    {
        unset($cb);
        return isset($GLOBALS['__wd_pc_handlers'][$hook]) ? 10 : false;
    }
}

require_once __DIR__ . '/stubs/w3tc-fake.php';
require_once dirname(__DIR__) . '/sdk/src/AgentRegistry.php';
require_once dirname(__DIR__) . '/includes/class-webdecoy-crawler-visits.php';
require_once dirname(__DIR__) . '/includes/class-webdecoy-page-cache.php';

$t = ['TestRunner', 'test'];
$same = ['TestRunner', 'assertSame'];
$true = ['TestRunner', 'assertTrue'];

/** Registry agents in the generated file's shape. */
function page_cache_fixture(): array
{
    $agent = function (string $category, array $patterns) {
        return ['id' => $patterns[0], 'category' => $category, 'patterns' => $patterns];
    };
    return [
        $agent('training_crawler', ['gptbot']),
        $agent('training_crawler', ['hunyuan/']),           // unsafe character
        $agent('ai_assistant', ['copilot']),                // not distinctive
        $agent('ai_assistant', ['chatgpt-user']),
        $agent('search_crawler', ['applebot']),
        $agent('training_crawler', ['applebot-extended']),  // covered by applebot
        $agent('seo_crawler', ['ahrefsbot']),               // reported as "other"
        $agent('search_crawler', ['googlebot']),
    ];
}

const PAGE_CACHE_BROWSERS = [
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0',
    'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36',
];
const PAGE_CACHE_GPTBOT = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)';

/**
 * A real adapter with its I/O swapped for an in-memory list.
 *
 * @param array<int,string> $list
 */
function page_cache_memory_adapter(string $key, array &$list): array
{
    $adapter = WebDecoy_Page_Cache::adapters()[$key];
    $adapter['available'] = static function (): bool {
        return true;
    };
    $adapter['read'] = static function () use (&$list): array {
        return $list;
    };
    $adapter['write'] = static function (array $new) use (&$list): bool {
        $list = $new;
        return true;
    };
    return $adapter;
}

function page_cache_reset(): void
{
    unset($GLOBALS['__wd_opts'][WebDecoy_Page_Cache::STATE_OPTION]);
    $GLOBALS['__wd_pc_actions'] = [];
    $GLOBALS['__wd_pc_handlers'] = [];
}

echo "\nPage cache: crawler tokens\n";

$t('tokens are distinctive AI and search agent names, registry order, covered ones dropped', function () use ($same) {
    $same(['gptbot', 'chatgpt-user', 'applebot', 'googlebot'], WebDecoy_Page_Cache::crawler_tokens(page_cache_fixture()));
});

$t('every bundled token names an agent the dashboard reports as AI or search', function () use ($true) {
    $tokens = WebDecoy_Page_Cache::crawler_tokens();
    $true(count($tokens) > 20 && count($tokens) < 150, 'a reasonable list, got ' . count($tokens));
    foreach (['gptbot', 'claudebot', 'perplexitybot', 'chatgpt-user', 'googlebot', 'bingbot'] as $expected) {
        $true(in_array($expected, $tokens, true), "missing {$expected}");
    }
    foreach ($tokens as $token) {
        $agent = \WebDecoy\AgentRegistry::match('Mozilla/5.0 (compatible; ' . $token . '/1.0)');
        $true($agent !== null, "{$token} matches no agent");
        $true(WebDecoy_Crawler_Visits::group($agent['category']) !== 'other', "{$token} is not AI or search");
    }
});

$t('no token matches an ordinary browser', function () use ($true) {
    $tokens = WebDecoy_Page_Cache::crawler_tokens();
    foreach (PAGE_CACHE_BROWSERS as $ua) {
        $true(!WebDecoy_Page_Cache::ua_matches($ua, $tokens), $ua);
    }
    $true(WebDecoy_Page_Cache::ua_matches(PAGE_CACHE_GPTBOT, $tokens), 'GPTBot should match');
    $true(!WebDecoy_Page_Cache::ua_matches('', $tokens), 'empty UA');
});

echo "\nPage cache: list sync\n";

$t('adds what is missing and records only that', function () use ($same) {
    $r = WebDecoy_Page_Cache::sync_list(['MyMonitor'], [], ['gptbot', 'claudebot']);
    $same(['MyMonitor', 'gptbot', 'claudebot'], $r['list']);
    $same(['gptbot', 'claudebot'], $r['ours']);
});

$t('an entry the owner already has, in any case, stays theirs', function () use ($same) {
    $r = WebDecoy_Page_Cache::sync_list(['GPTBot'], [], ['gptbot', 'claudebot']);
    $same(['GPTBot', 'claudebot'], $r['list']);
    $same(['claudebot'], $r['ours']);
    $off = WebDecoy_Page_Cache::sync_list($r['list'], $r['ours'], []);
    $same(['GPTBot'], $off['list']);
    $same([], $off['ours']);
});

$t('a registry change drops our stale entry and adds the new one, owner untouched', function () use ($same) {
    $r = WebDecoy_Page_Cache::sync_list(['a-owner', 'gptbot', 'oldbot'], ['gptbot', 'oldbot'], ['gptbot', 'newbot']);
    $same(['a-owner', 'gptbot', 'newbot'], $r['list']);
    $same(['gptbot', 'newbot'], $r['ours']);
});

echo "\nPage cache: WP Rocket patterns\n";

$t('patterns match in WP Rocket\'s PHP check and in its anchored .htaccess rule', function () use ($true) {
    $patterns = WebDecoy_Page_Cache::rocket_patterns(['gptbot', 'chatgpt-user']);
    $joined = implode('|', $patterns);
    // PHP side (Buffer\Tests::can_process_user_agent): '#' . list . '#', no flags.
    $true(preg_match('#' . $joined . '#', PAGE_CACHE_GPTBOT) === 1, 'php check');
    // .htaccess side: RewriteCond %{HTTP_USER_AGENT} !^(list).* [NC]
    $true(preg_match('#^(' . $joined . ').*#i', PAGE_CACHE_GPTBOT) === 1, 'htaccess rule');
    foreach (PAGE_CACHE_BROWSERS as $ua) {
        $true(preg_match('#' . $joined . '#', $ua) === 0, $ua);
    }
});

$t('the filter appends ours and keeps the owner\'s and WP Rocket\'s defaults', function () use ($same, $true) {
    $owner = ['MyMonitor', 'facebookexternalhit', 'WhatsApp'];
    $out = WebDecoy_Page_Cache::rocket_reject_ua($owner);
    $same($owner, array_slice($out, 0, 3));
    $true(in_array('.*(?i:gptbot)', $out, true), 'gptbot pattern added');
    $same($out, WebDecoy_Page_Cache::rocket_reject_ua($out), 'idempotent');
});

echo "\nPage cache: round trips\n";

$t('W3 Total Cache: on adds to pgcache.reject.ua through config_save, off removes only ours', function () use ($same, $true) {
    page_cache_reset();
    if (!defined('W3TC')) {
        define('W3TC', true);
    }
    \W3TC\Config::$stored = ['pgcache.enabled' => true, 'pgcache.reject.ua' => ['MyMonitor', 'GPTBot']];
    $w3tc = ['w3tc' => WebDecoy_Page_Cache::adapters()['w3tc']];

    WebDecoy_Page_Cache::apply(true, $w3tc);
    $list = \W3TC\Config::$stored['pgcache.reject.ua'];
    $same(['MyMonitor', 'GPTBot'], array_slice($list, 0, 2));
    $true(in_array('claudebot', $list, true), 'claudebot added');
    $true(!in_array('gptbot', $list, true), 'owner already rejects GPTBot');
    $true(\W3TC\Root_Environment::$fixes > 0, 'rules rewritten');
    $saves = \W3TC\Util_Admin::$saves;

    WebDecoy_Page_Cache::apply(true, $w3tc);
    $same($saves, \W3TC\Util_Admin::$saves, 'no write when already in step');

    WebDecoy_Page_Cache::apply(false, $w3tc);
    $same(['MyMonitor', 'GPTBot'], \W3TC\Config::$stored['pgcache.reject.ua']);
    $same(false, get_option(WebDecoy_Page_Cache::STATE_OPTION), 'state cleared');
});

$t('W3 Total Cache: a failed save records nothing', function () use ($same) {
    page_cache_reset();
    \W3TC\Config::$stored = ['pgcache.reject.ua' => []];
    \W3TC\Util_Admin::$fail = true;
    WebDecoy_Page_Cache::apply(true, ['w3tc' => WebDecoy_Page_Cache::adapters()['w3tc']]);
    \W3TC\Util_Admin::$fail = false;
    $same([], \W3TC\Config::$stored['pgcache.reject.ua']);
    $same(false, get_option(WebDecoy_Page_Cache::STATE_OPTION));
});

$t('LiteSpeed Cache: saves through litespeed_save_conf, owner entries survive', function () use ($same, $true) {
    page_cache_reset();
    $list = ['MyMonitor'];
    $adapter = WebDecoy_Page_Cache::adapters()['litespeed'];
    $adapter['available'] = static function (): bool {
        return true;
    };
    $adapter['read'] = static function () use (&$list): array {
        return $list;
    };
    // Keep the real write so the call into LiteSpeed's API is what is checked.
    $GLOBALS['__wd_pc_handlers']['litespeed_save_conf'] = static function (array $matrix) use (&$list): void {
        $list = $matrix['cache-exc_useragents'];
    };

    WebDecoy_Page_Cache::apply(true, ['litespeed' => $adapter]);
    $same('MyMonitor', $list[0]);
    $true(in_array('perplexitybot', $list, true), 'perplexitybot added');

    WebDecoy_Page_Cache::apply(false, ['litespeed' => $adapter]);
    $same(['MyMonitor'], $list);
});

$t('WP Super Cache: registers our phase-1 file with wpsc_add_plugin, removes it with wpsc_delete_plugin', function () use ($same) {
    page_cache_reset();
    $GLOBALS['wpsc_plugins'] = ['wp-content/owner-wpsc-plugin.php'];
    $GLOBALS['__wd_pc_handlers']['wpsc_add_plugin'] = static function (string $file): void {
        $GLOBALS['wpsc_plugins'][] = $file;
    };
    $GLOBALS['__wd_pc_handlers']['wpsc_delete_plugin'] = static function (string $file): void {
        $GLOBALS['wpsc_plugins'] = array_values(array_diff($GLOBALS['wpsc_plugins'], [$file]));
    };
    $adapter = WebDecoy_Page_Cache::adapters()['wp_super_cache'];
    $adapter['available'] = static function (): bool {
        return true;
    };

    WebDecoy_Page_Cache::apply(true, ['wp_super_cache' => $adapter]);
    $same(['wp-content/owner-wpsc-plugin.php', 'wp-content/plugins/webdecoy/includes/wpsc-crawler-bypass.php'], $GLOBALS['wpsc_plugins']);

    WebDecoy_Page_Cache::apply(true, ['wp_super_cache' => $adapter]);
    $same(1, count(array_filter($GLOBALS['__wd_pc_actions'], static function ($a) {
        return $a[0] === 'wpsc_add_plugin';
    })), 'added once');

    WebDecoy_Page_Cache::apply(false, ['wp_super_cache' => $adapter]);
    $same(['wp-content/owner-wpsc-plugin.php'], $GLOBALS['wpsc_plugins']);
    unset($GLOBALS['wpsc_plugins']);
});

$t('WP Super Cache: our phase-1 file is relative to ABSPATH, as WP Super Cache loads it', function () use ($same, $true) {
    $same('wp-content/plugins/webdecoy/includes/wpsc-crawler-bypass.php', WebDecoy_Page_Cache::wpsc_entry());
    $true(file_exists(dirname(__DIR__) . '/includes/wpsc-crawler-bypass.php'), 'file ships with the plugin');
});

$t('WP Rocket: regenerates once on, once off, and records nothing when off', function () use ($same) {
    page_cache_reset();
    $writes = [];
    $adapter = WebDecoy_Page_Cache::adapters()['wp_rocket'];
    $adapter['available'] = static function (): bool {
        return true;
    };
    $adapter['write'] = static function (array $list) use (&$writes): bool {
        $writes[] = $list;
        return true;
    };

    WebDecoy_Page_Cache::apply(true, ['wp_rocket' => $adapter]);
    WebDecoy_Page_Cache::apply(true, ['wp_rocket' => $adapter]);
    $same(1, count($writes), 'one regeneration while on');
    $same(1, count($writes[0]));

    WebDecoy_Page_Cache::apply(false, ['wp_rocket' => $adapter]);
    $same(2, count($writes));
    $same([], $writes[1]);
    $same(false, get_option(WebDecoy_Page_Cache::STATE_OPTION));
});

$t('several plugins at once: state is kept per plugin', function () use ($same) {
    page_cache_reset();
    $a = ['OwnerA'];
    $b = [];
    $adapters = [
        'w3tc' => page_cache_memory_adapter('w3tc', $a),
        'litespeed' => page_cache_memory_adapter('litespeed', $b),
    ];
    WebDecoy_Page_Cache::apply(true, $adapters);
    $state = get_option(WebDecoy_Page_Cache::STATE_OPTION);
    $same(['w3tc', 'litespeed'], array_keys($state));
    $same(count(WebDecoy_Page_Cache::crawler_tokens()), count($state['litespeed']));
    WebDecoy_Page_Cache::apply(false, $adapters);
    $same(['OwnerA'], $a);
    $same([], $b);
});

echo "\nPage cache: detection\n";

$t('W3 Total Cache with page cache on is a plugin cache we can bypass', function () use ($same) {
    \W3TC\Config::$stored = ['pgcache.enabled' => true];
    $same(
        ['kind' => 'plugin', 'name' => 'W3 Total Cache', 'key' => 'w3tc', 'bypass_supported' => true],
        WebDecoy_Page_Cache::detect()
    );
});

$t('W3 Total Cache with page cache off is no page cache', function () use ($same) {
    \W3TC\Config::$stored = ['pgcache.enabled' => false];
    $same('none', WebDecoy_Page_Cache::detect()['kind']);
});

// Last: constants cannot be undefined.
$t('a host cache wins over a plugin, and cannot be bypassed', function () use ($same) {
    \W3TC\Config::$stored = ['pgcache.enabled' => true];
    define('KINSTAMU_VERSION', '2.0');
    $same(
        ['kind' => 'host', 'name' => 'Kinsta', 'key' => '', 'bypass_supported' => false],
        WebDecoy_Page_Cache::detect()
    );
});
