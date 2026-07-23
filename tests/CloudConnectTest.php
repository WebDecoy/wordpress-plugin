<?php

declare(strict_types=1);

/**
 * Tests for the pure, WordPress-free helpers in WebDecoy_Cloud_Connect:
 * entitlements normalization (fail-open + staleness), connect-token/nonce
 * validation, and plan labelling. These are the parts of the connect flow that
 * can be exercised without a WordPress runtime.
 *
 * Run: php tests/run.php
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/');
}
require_once dirname(__DIR__) . '/includes/class-webdecoy-cloud-connect.php';

$t = ['TestRunner', 'test'];
$same = ['TestRunner', 'assertSame'];
$true = ['TestRunner', 'assertTrue'];

echo "\nCloud Connect: entitlements normalization\n";

$t('empty payload fails open to free (all features false, stale)', function () use ($same, $true) {
    $e = WebDecoy_Cloud_Connect::normalize_entitlements([], 1000000);
    $same('free', $e['plan'], 'plan defaults to free');
    $same('', $e['channel'], 'channel defaults empty');
    $same(false, $e['digest']['enabled'], 'digest defaults off');
    $same(0, $e['fetched_at'], 'no timestamp -> 0');
    $true($e['stale'] === true, 'never-fetched is stale');
    foreach (['actor_feed', 'enrichment', 'alerts', 'edge_push', 'decoy_packs', 'woo_intel'] as $key) {
        $same(false, $e['features'][$key], "feature {$key} defaults false");
    }
});

$t('a full payload is normalized to typed values', function () use ($same, $true) {
    $now = 2000000;
    $raw = [
        'plan' => 'free_connected',
        'channel' => 'wordpress',
        'features' => [
            'actor_feed' => true,
            'enrichment' => 1,        // truthy non-bool -> true
            'alerts' => false,
            'edge_push' => 0,          // falsy -> false
            // decoy_packs + woo_intel omitted -> default false
        ],
        'digest' => ['enabled' => true],
        'fetched_at' => $now - 100,   // fresh
    ];
    $e = WebDecoy_Cloud_Connect::normalize_entitlements($raw, $now);
    $same('free_connected', $e['plan']);
    $same('wordpress', $e['channel']);
    $same(true, $e['features']['actor_feed']);
    $same(true, $e['features']['enrichment'], 'truthy coerced to bool true');
    $same(false, $e['features']['alerts']);
    $same(false, $e['features']['edge_push'], 'falsy coerced to bool false');
    $same(false, $e['features']['decoy_packs'], 'omitted feature is false');
    $same(false, $e['features']['woo_intel'], 'omitted feature is false');
    $same(true, $e['digest']['enabled']);
    $same($now - 100, $e['fetched_at']);
    $true($e['stale'] === false, 'recent fetch is not stale');
});

$t('staleness flips at the 12h boundary', function () use ($true) {
    $now = 1000000;
    // 11h old -> fresh; 13h old -> stale (threshold is 12h = 43200s).
    $fresh = WebDecoy_Cloud_Connect::normalize_entitlements(['fetched_at' => $now - (11 * 3600)], $now);
    $stale = WebDecoy_Cloud_Connect::normalize_entitlements(['fetched_at' => $now - (13 * 3600)], $now);
    $true($fresh['stale'] === false, '11h old is fresh');
    $true($stale['stale'] === true, '13h old is stale');
});

$t('garbage feature/digest shapes never fatal, always typed', function () use ($same) {
    $e = WebDecoy_Cloud_Connect::normalize_entitlements([
        'plan' => 123,             // non-string -> default free
        'features' => 'nope',      // non-array -> all false
        'digest' => 'nope',        // non-array -> off
    ], 500);
    $same('free', $e['plan'], 'non-string plan falls back to free');
    $same(false, $e['features']['actor_feed']);
    $same(false, $e['digest']['enabled']);
});

echo "\nCloud Connect: token & nonce validation\n";

$t('is_hex validates a 64-char connect nonce', function () use ($true) {
    $good = str_repeat('a1b2', 16); // 64 hex chars
    $true(WebDecoy_Cloud_Connect::is_hex($good, 64) === true, '64 hex chars pass');
    $true(WebDecoy_Cloud_Connect::is_hex($good, 32) === false, 'wrong length fails');
    $true(WebDecoy_Cloud_Connect::is_hex('zzzz', 4) === false, 'non-hex fails');
    $true(WebDecoy_Cloud_Connect::is_hex('', 64) === false, 'empty fails');
    $true(WebDecoy_Cloud_Connect::is_hex('deadbeef') === true, 'any-length hex passes with no length arg');
});

$t('sanitize_connect_token strips unsafe chars and caps length', function () use ($same, $true) {
    $same('abcXYZ-9._', WebDecoy_Cloud_Connect::sanitize_connect_token('abcXYZ-9._'), 'url-safe token preserved');
    $same('abcscriptdef', WebDecoy_Cloud_Connect::sanitize_connect_token('abc<script>def'), 'angle brackets stripped, alnum kept');
    $same('a1b2c3', WebDecoy_Cloud_Connect::sanitize_connect_token("a1b2\nc3 "), 'newlines and spaces stripped');
    $same('', WebDecoy_Cloud_Connect::sanitize_connect_token('   '), 'whitespace-only -> empty');
    $long = str_repeat('a', 500);
    $true(strlen(WebDecoy_Cloud_Connect::sanitize_connect_token($long)) === 256, 'capped at 256');
});

echo "\nCloud Connect: plan labels\n";

$t('plan_label humanizes slugs', function () use ($same) {
    $same('Free Connected', WebDecoy_Cloud_Connect::plan_label('free_connected'));
    $same('Pro', WebDecoy_Cloud_Connect::plan_label('pro'));
    $same('Team Annual', WebDecoy_Cloud_Connect::plan_label('team_annual'));
    $same('Connected', WebDecoy_Cloud_Connect::plan_label(''), 'empty slug -> generic label');
});
