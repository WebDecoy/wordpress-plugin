<?php

declare(strict_types=1);

/**
 * IP enrichment pauses with detection sends while ingest is refusing work
 * (WebDecoy/app#1245). Named to load after HoneytokenTest, whose get_option
 * stub WebDecoy_Cloud_Connect needs.
 *
 * Run: php tests/run.php
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/');
}
require_once dirname(__DIR__) . '/includes/class-webdecoy-detection-sender.php';

$t = ['TestRunner', 'test'];
$same = ['TestRunner', 'assertSame'];
$true = ['TestRunner', 'assertTrue'];

// IP enrichment shares the backoff: during an outage a page must not wait out
// the enrichment timeout for every new IP.
if (!function_exists('apply_filters')) {
    function apply_filters($hook, $value) { return $value; }
}
if (!defined('MINUTE_IN_SECONDS')) {
    define('MINUTE_IN_SECONDS', 60);
}
if (!defined('HOUR_IN_SECONDS')) {
    define('HOUR_IN_SECONDS', 3600);
}
if (!function_exists('wp_remote_get')) {
    $GLOBALS['wd_test_remote'] = ['calls' => 0, 'code' => 503];
    function wp_remote_get($url, $args = []) { $GLOBALS['wd_test_remote']['calls']++; return ['code' => $GLOBALS['wd_test_remote']['code']]; }
    function is_wp_error($thing) { return false; }
    function wp_remote_retrieve_response_code($response) { return $response['code']; }
    function wp_remote_retrieve_body($response) { return ''; }
}
require_once dirname(__DIR__) . '/includes/class-webdecoy-ip-enrichment.php';

$t('IP enrichment makes no call while ingest is refusing, and a 503 starts the pause', function () use ($same, $true) {
    WebDecoy_Detection_Sender::reset();
    $GLOBALS['wd_test_remote'] = ['calls' => 0, 'code' => 503];
    $enricher = new WebDecoy_IP_Enrichment('key');
    $enricher->enrich('198.51.100.7');
    $same(1, $GLOBALS['wd_test_remote']['calls'], 'first call is made');
    $true(WebDecoy_Detection_Sender::backing_off(), 'a 503 pauses cloud calls');
    $enricher->enrich('198.51.100.8');
    $enricher->enrich('198.51.100.9');
    $same(1, $GLOBALS['wd_test_remote']['calls'], 'no further calls while paused');
    WebDecoy_Detection_Sender::reset();
});
