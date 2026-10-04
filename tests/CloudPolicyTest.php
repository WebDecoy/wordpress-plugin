<?php

declare(strict_types=1);

/**
 * Per-path crawler refusals from WebDecoy Cloud, applied in the plugin (#995).
 *
 * The policy the dashboard shows is the policy this plugin applies: same
 * config body the edge reads, same route resolution. These tests pin what
 * that means for a request: refused on a covered path in Enforce, counted on
 * a watched path or a monitoring site, untouched off-path, and never widened
 * by the custom allowlist.
 *
 * Run: php tests/run.php
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/');
}
if (!function_exists('get_transient')) {
    function get_transient($key) { return false; }
}
if (!function_exists('set_transient')) {
    function set_transient($key, $value, $ttl = 0) { return true; }
}
foreach (['DetectionResult', 'AgentRegistry', 'GoodBotList', 'RouteResolution', 'SignalCollector', 'MitreMapping', 'BotDetector'] as $class) {
    $file = dirname(__DIR__) . '/sdk/src/' . $class . '.php';
    if (is_file($file)) {
        require_once $file;
    }
}

$t = ['TestRunner', 'test'];
$same = ['TestRunner', 'assertSame'];
$true = ['TestRunner', 'assertTrue'];

function cloud_policy_analyze(string $userAgent, string $uri, array $options): \WebDecoy\DetectionResult
{
    $_SERVER = [
        'HTTP_USER_AGENT' => $userAgent,
        'REMOTE_ADDR' => '203.0.113.9',
        'REQUEST_URI' => $uri,
        'REQUEST_METHOD' => 'GET',
        'HTTP_ACCEPT' => '*/*',
    ];
    // Like the WordPress wrapper: collected signals plus the request path.
    $detector = new \WebDecoy\BotDetector($options);
    $signals = $detector->getSignalCollector()->collect();
    $signals['request_path'] = $uri;
    return $detector->analyze($signals);
}

function cloud_policy_config(string $mode = 'enforce'): array
{
    return [
        'scope' => ['basis' => 'host'],
        'mode' => $mode,
        'routes' => ['/premium/*'],
        'route_min_trust' => [],
        'monitor_routes' => [['pattern' => '/blog/*', 'min_trust' => '', 'except' => []]],
        'route_exceptions' => [['pattern' => '/premium/*', 'except' => ['/premium/free/*']]],
        'route_refusals' => [
            ['pattern' => '/premium/*', 'mode' => '', 'refuse_behaviors' => ['training']],
            ['pattern' => '/blog/*', 'mode' => 'monitor', 'refuse_behaviors' => ['training']],
        ],
    ];
}

const CLOUD_GPTBOT = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)';
const CLOUD_CHATGPT_USER = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot';
const CLOUD_GOOGLEBOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

echo "\nCloud policy: per-path crawler refusals\n";

$t('a training crawler is refused on a path that refuses training, whatever the local setting', function () use ($true, $same) {
    $result = cloud_policy_analyze(CLOUD_GPTBOT, '/premium/article?utm=x', ['cloud_policy' => cloud_policy_config(), 'block_ai_crawlers' => false]);
    $true($result->shouldBlock(100), 'served despite the cloud refusal');
    $same(false, $result->isGoodBot());
    $true(in_array('crawler_refused', $result->getFlags(), true), 'the reason must be visible in the log');
    $meta = $result->getMetadata();
    $same('cloud_policy', $meta['denied_by'] ?? null);
    $same('/premium/*', $meta['cloud_policy']['pattern'] ?? null);
    $same('training', $meta['cloud_policy']['behavior'] ?? null);
    $same('claimed', $meta['cloud_policy']['assurance'] ?? null);
});

$t('the same crawler passes off-path and on an excepted path', function () use ($same) {
    foreach (['/about', '/premium/free/sample'] as $uri) {
        $result = cloud_policy_analyze(CLOUD_GPTBOT, $uri, ['cloud_policy' => cloud_policy_config()]);
        $same(true, $result->isGoodBot(), $uri);
        $same(false, in_array('crawler_refused', $result->getFlags(), true), $uri);
    }
});

$t('a crawler of another kind passes on the refusing path', function () use ($same) {
    foreach ([CLOUD_GOOGLEBOT, CLOUD_CHATGPT_USER] as $ua) {
        $result = cloud_policy_analyze($ua, '/premium/article', ['cloud_policy' => cloud_policy_config(), 'verify_bot_ips' => false]);
        $same(true, $result->isGoodBot(), $ua);
    }
});

$t('a watched path counts the refusal and lets the crawler through', function () use ($same, $true) {
    $result = cloud_policy_analyze(CLOUD_GPTBOT, '/blog/post', ['cloud_policy' => cloud_policy_config()]);
    $same(true, $result->isGoodBot());
    $true(in_array('crawler_would_be_refused', $result->getFlags(), true));
    $same('monitor', $result->getMetadata()['cloud_policy']['mode'] ?? null);
});

$t('a monitoring site counts every refusal instead of applying it', function () use ($same, $true) {
    $result = cloud_policy_analyze(CLOUD_GPTBOT, '/premium/article', ['cloud_policy' => cloud_policy_config('monitor')]);
    $same(true, $result->isGoodBot());
    $true(in_array('crawler_would_be_refused', $result->getFlags(), true));
    $same('/premium/*', $result->getMetadata()['cloud_policy']['pattern'] ?? null);
});

$t('the custom allowlist does not open a path the cloud policy refuses', function () use ($true) {
    $result = cloud_policy_analyze(CLOUD_GPTBOT, '/premium/article', ['cloud_policy' => cloud_policy_config(), 'custom_allowlist' => ['GPTBot']]);
    $true($result->shouldBlock(100), 'a local exemption granted access the owner refused in the cloud');
});

$t('the local setting still refuses first, site-wide', function () use ($true) {
    $result = cloud_policy_analyze(CLOUD_GPTBOT, '/about', ['cloud_policy' => cloud_policy_config(), 'block_ai_crawlers' => true]);
    $true(in_array('ai_crawler_blocked', $result->getFlags(), true));
});

$t('no policy, no effect', function () use ($same) {
    $result = cloud_policy_analyze(CLOUD_GPTBOT, '/premium/article', ['cloud_policy' => null]);
    $same(true, $result->isGoodBot());
});
