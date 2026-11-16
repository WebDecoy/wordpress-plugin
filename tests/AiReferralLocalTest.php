<?php

declare(strict_types=1);

/**
 * AI referral counts are kept locally on every install, with no account, and
 * queued for WebDecoy Cloud only when connected.
 *
 * Run: php tests/run.php
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/');
}
if (!defined('DAY_IN_SECONDS')) {
    define('DAY_IN_SECONDS', 86400);
}
if (!isset($GLOBALS['__wd_opts'])) {
    $GLOBALS['__wd_opts'] = [];
}
if (!function_exists('get_option')) {
    function get_option($k, $d = false)
    {
        return $GLOBALS['__wd_opts'][$k] ?? $d;
    }
}
if (!function_exists('apply_filters')) {
    function apply_filters($hook, $value) { return $value; } // phpcs:ignore
}
if (!function_exists('add_action')) {
    function add_action($hook, $cb, $priority = 10, $args = 1) { return true; } // phpcs:ignore
}
if (!function_exists('wp_next_scheduled')) {
    function wp_next_scheduled($hook) { return 1; } // phpcs:ignore
}
if (!function_exists('esc_sql')) {
    function esc_sql($s) { return $s; } // phpcs:ignore
}
if (!function_exists('wp_unslash')) {
    function wp_unslash($s) { return $s; } // phpcs:ignore
}
require_once dirname(__DIR__) . '/sdk/src/LlmReferral.php';
require_once dirname(__DIR__) . '/includes/class-webdecoy-ai-referrals.php';

/** Records which table each INSERT went to. */
final class WdFakeReferralDb
{
    public $prefix = 'wp_';
    /** @var list<string> */
    public $inserts = [];

    public function prepare($sql, ...$args) { return vsprintf(str_replace(['%d', '%s'], ['%d', "'%s'"], $sql), $args); }
    public function get_var($sql) { return 0; }
    public function query($sql)
    {
        if (preg_match('/INSERT INTO (\S+)/', $sql, $m)) {
            $this->inserts[] = $m[1];
        }
        return true;
    }
}

$t = ['TestRunner', 'test'];
$same = ['TestRunner', 'assertSame'];

/** Observe one ChatGPT page visit with a given API key; return the tables written. */
function wd_observe_referral(string $apiKey, string $dbVersion): array
{
    $db = new WdFakeReferralDb();
    $GLOBALS['wpdb'] = $db;
    $GLOBALS['__wd_opts']['webdecoy_db_version'] = $dbVersion;
    $_SERVER['REQUEST_METHOD'] = 'GET';
    $_SERVER['HTTP_SEC_FETCH_MODE'] = 'navigate';
    $_SERVER['HTTP_SEC_FETCH_DEST'] = 'document';
    $_SERVER['HTTP_REFERER'] = 'https://chatgpt.com/c/1';
    $_SERVER['REQUEST_URI'] = '/pricing?x=1';
    WebDecoy_AI_Referrals::register($apiKey);
    WebDecoy_AI_Referrals::observe();
    unset($_SERVER['HTTP_SEC_FETCH_MODE'], $_SERVER['HTTP_SEC_FETCH_DEST'], $_SERVER['HTTP_REFERER']);
    return $db->inserts;
}

$t('an AI referral is counted locally with no account, and not queued for the cloud', function () use ($same) {
    $same(wd_observe_referral('', '2.13.0'), ['wp_webdecoy_ai_referral_days']);
});

$t('a connected site counts locally and queues for the cloud', function () use ($same) {
    $same(wd_observe_referral('key', '2.13.0'), ['wp_webdecoy_ai_referral_days', 'wp_webdecoy_ai_referrals']);
});

$t('local counting waits for the table to exist', function () use ($same) {
    $same(wd_observe_referral('', '2.11.1'), []);
});

$t('the summary totals by platform and page, busiest first', function () use ($same) {
    $s = WebDecoy_AI_Referrals::summarize([
        ['platform' => 'Perplexity', 'landing_path' => '/blog/a', 'referrals' => '2'],
        ['platform' => 'ChatGPT', 'landing_path' => '/pricing', 'referrals' => '5'],
        ['platform' => 'ChatGPT', 'landing_path' => '/blog/a', 'referrals' => 1],
        // Past the daily path bound: counts for the platform, names no page.
        ['platform' => 'ChatGPT', 'landing_path' => '', 'referrals' => 3],
        ['platform' => '', 'landing_path' => '/x', 'referrals' => 9],
        ['platform' => 'Claude', 'landing_path' => '/x', 'referrals' => 0],
    ]);
    $same($s['total'], 11);
    $same($s['platforms'], [
        ['platform' => 'ChatGPT', 'referrals' => 9],
        ['platform' => 'Perplexity', 'referrals' => 2],
    ]);
    $same($s['pages'], [
        ['path' => '/pricing', 'referrals' => 5],
        ['path' => '/blog/a', 'referrals' => 3],
    ]);
});

$t('the summary of nothing is empty', function () use ($same) {
    $same(WebDecoy_AI_Referrals::summarize([]), ['total' => 0, 'platforms' => [], 'pages' => []]);
});
