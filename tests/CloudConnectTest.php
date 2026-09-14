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

echo "\nCloud Connect: what the success notice claims\n";

// Storing credentials is not evidence that this site is covered. The notice
// said "Cloud features are now active" the instant the keys landed, which
// asserts coverage before anything from the site has been received (#994).
$t('the connected notice does not claim the site is covered', function () use ($same, $true) {
    foreach (['', 'Acme Ltd'] as $org) {
        $msg = WebDecoy_Cloud_Connect::connected_notice_message($org);

        $true(
            stripos($msg, 'first report') !== false,
            'says a report is still to come'
        );
        foreach (['now active', 'are active', 'is protected', 'is now protected'] as $claim) {
            $true(
                stripos($msg, $claim) === false,
                "does not claim coverage with \"{$claim}\""
            );
        }
    }
});

$t('the connected notice names the organization when the server named one', function () use ($same, $true) {
    $true(
        strpos(WebDecoy_Cloud_Connect::connected_notice_message('Acme Ltd'), 'Acme Ltd') !== false,
        'the organization is named'
    );
    $true(
        strpos(WebDecoy_Cloud_Connect::connected_notice_message(''), '()') === false,
        'no empty parentheses when the server named none'
    );
});

echo "\nCloud Connect: where the first-report link goes\n";

// The exchange scopes the setup page to the property the site became
// (app#994). The unscoped page shows whichever site the app last had
// selected, which on an account with several sites is the wrong one.
$t('the first-report link is the server\'s property-scoped setup page', function () use ($same) {
    $scoped = 'https://app.webdecoy.com/onboarding/setup?property=6aa166fa-763a-4b1c-b037-076befb7b53c';
    $same($scoped, WebDecoy_Cloud_Connect::setup_url_from(['setup_url' => $scoped]));
});

$t('without a server URL the link is the unscoped setup page', function () use ($same) {
    $same('https://app.webdecoy.com/onboarding/setup', WebDecoy_Cloud_Connect::setup_url_from([]));
    $same('https://app.webdecoy.com/onboarding/setup', WebDecoy_Cloud_Connect::setup_url_from(['setup_url' => '   ']));
    $same('https://app.webdecoy.com/onboarding/setup', WebDecoy_Cloud_Connect::setup_url_from(['setup_url' => 42]));
});

$t('a server URL anywhere but the app\'s own setup page is not followed', function () use ($same) {
    foreach ([
        'https://evil.example.com/onboarding/setup?property=x',
        'http://app.webdecoy.com/onboarding/setup?property=x',
        'https://app.webdecoy.com/billing?property=x',
        'https://app.webdecoy.com:8443/onboarding/setup',
        'https://user:pw@app.webdecoy.com/onboarding/setup',
        'javascript:alert(1)',
    ] as $bad) {
        $same('https://app.webdecoy.com/onboarding/setup', WebDecoy_Cloud_Connect::setup_url_from(['setup_url' => $bad]), $bad);
    }
});
