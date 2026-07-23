<?php

declare(strict_types=1);

/**
 * Tests for the pure, WordPress-free helpers in WebDecoy_Actor_Intel:
 * per-IP response normalization (including the free-connected redaction
 * guarantee) and the unique/validated/capped IP batching.
 *
 * Run: php tests/run.php
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/');
}
require_once dirname(__DIR__) . '/includes/class-webdecoy-actor-intel.php';

$t = ['TestRunner', 'test'];
$same = ['TestRunner', 'assertSame'];
$true = ['TestRunner', 'assertTrue'];
$null = ['TestRunner', 'assertNull'];

echo "\nActor Intel: response normalization\n";

$t('a full (Pro) result exposes all fields, typed', function () use ($same, $true) {
    $r = WebDecoy_Actor_Intel::normalize_result([
        'known'              => 1,           // truthy -> true
        'network_detections' => '42',        // numeric string -> int
        'first_seen'         => 1600000000,
        'last_seen'          => 1600100000,
        'redacted'           => false,
        'tor'                => 1,
        'vpn'                => 0,
        'abuse_score'        => 250,         // clamped to 100
        'actor'              => ['id' => 'act_7', 'sites' => '9'],
    ]);

    $same(true, $r['known']);
    $same(42, $r['network_detections']);
    $same(1600000000, $r['first_seen']);
    $same(1600100000, $r['last_seen']);
    $same(false, $r['redacted']);
    $same(true, $r['tor'], 'truthy tor coerced to bool');
    $same(false, $r['vpn'], 'falsy vpn coerced to bool');
    $same(100, $r['abuse_score'], 'abuse score clamped to 0..100');
    $true(is_array($r['actor']), 'actor present');
    $same('act_7', $r['actor']['id']);
    $same(9, $r['actor']['sites']);
});

$t('a redacted (free-connected) result withholds every enriched field', function () use ($same, $null) {
    $r = WebDecoy_Actor_Intel::normalize_result([
        'known'              => true,
        'network_detections' => 5,
        'first_seen'         => 1600000000,
        'last_seen'          => 1600100000,
        'redacted'           => true,
        // Even if the server leaks these, the client must NOT surface them:
        'tor'                => true,
        'vpn'                => true,
        'abuse_score'        => 88,
        'actor'              => ['id' => 'act_x', 'sites' => 3],
    ]);

    $same(true, $r['known'], 'teaser still exposes known');
    $same(5, $r['network_detections'], 'teaser still exposes the count');
    $same(1600000000, $r['first_seen']);
    $same(true, $r['redacted']);
    $null($r['tor'], 'tor withheld when redacted');
    $null($r['vpn'], 'vpn withheld when redacted');
    $null($r['abuse_score'], 'abuse score withheld when redacted');
    $null($r['actor'], 'actor withheld when redacted');
});

$t('a sparse result fills sane defaults and never fatals', function () use ($same, $null) {
    $r = WebDecoy_Actor_Intel::normalize_result([]);
    $same(false, $r['known']);
    $same(0, $r['network_detections']);
    $same(0, $r['first_seen']);
    $same(0, $r['last_seen']);
    $same(false, $r['redacted']);
    $null($r['tor']);
    $null($r['vpn']);
    $null($r['abuse_score']);
    $null($r['actor']);
});

$t('negative counts are floored at zero', function () use ($same) {
    $r = WebDecoy_Actor_Intel::normalize_result(['network_detections' => -3, 'abuse_score' => -10]);
    $same(0, $r['network_detections']);
    $same(0, $r['abuse_score']);
});

echo "\nActor Intel: IP batching\n";

$t('unique_ips dedupes, drops invalids, and caps the batch', function () use ($same) {
    $out = WebDecoy_Actor_Intel::unique_ips(
        ['1.1.1.1', '1.1.1.1', ' 2.2.2.2 ', 'nope', '', 3, '2001:db8::5'],
        50
    );
    $same(['1.1.1.1', '2.2.2.2', '2001:db8::5'], $out, 'deduped, trimmed, invalids removed');
});

$t('unique_ips honors the max cap', function () use ($same) {
    $out = WebDecoy_Actor_Intel::unique_ips(['1.1.1.1', '2.2.2.2', '3.3.3.3'], 2);
    $same(['1.1.1.1', '2.2.2.2'], $out, 'stops at the cap');
    $same([], WebDecoy_Actor_Intel::unique_ips(['1.1.1.1'], 0), 'cap of 0 yields nothing');
});
