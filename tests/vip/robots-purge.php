<?php
declare(strict_types=1);
define('ABSPATH', '/tmp/');
require dirname(__DIR__) . '/bootstrap.php';
require dirname(__DIR__, 2) . '/sdk/src/AgentRegistry.php';
require dirname(__DIR__, 2) . '/includes/class-webdecoy-robots-txt.php';
$GLOBALS['wd_purges'] = [];
$GLOBALS['wd_legacy_purges'] = [];
function wpcom_vip_purge_edge_cache_for_url($url) { $GLOBALS['wd_legacy_purges'][] = $url; }
if (($argv[1] ?? '') === 'modern') {
    function wpvip_purge_edge_cache_for_url($url) { $GLOBALS['wd_purges'][] = $url; }
}
function home_url($path) { return 'https://site.invalid' . $path; }
$categories = array_keys(WebDecoy_Robots_Txt::choices());
$category = $categories[0];
$chosen = ['robots_disallow_categories' => [$category]];
TestRunner::test('VIP purges only robots.txt when policy is enabled, changed or removed', function () use ($chosen) {
    WebDecoy_Robots_Txt::settings_updated([], $chosen);
    WebDecoy_Robots_Txt::settings_updated($chosen, $chosen + ['other_setting' => true]);
    WebDecoy_Robots_Txt::settings_updated($chosen, []);
    $all = array_merge($GLOBALS['wd_purges'], $GLOBALS['wd_legacy_purges']);
    TestRunner::assertSame(['https://site.invalid/robots.txt', 'https://site.invalid/robots.txt'], $all);
    if (function_exists('wpvip_purge_edge_cache_for_url')) {
        TestRunner::assertSame([], $GLOBALS['wd_legacy_purges'], 'modern function takes precedence');
    }
});
exit(TestRunner::summary());
