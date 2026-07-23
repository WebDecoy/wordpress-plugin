<?php

declare(strict_types=1);

/**
 * Tests for the pure, WordPress-free helpers in WebDecoy_Actor_Feed:
 * feed-page normalization, cross-page IP merge, allowlist exclusion, the
 * network-row cap/eviction ordering, and the pagination-continue decision.
 *
 * Run: php tests/run.php
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/');
}
require_once dirname(__DIR__) . '/includes/class-webdecoy-actor-feed.php';

$t = ['TestRunner', 'test'];
$same = ['TestRunner', 'assertSame'];
$true = ['TestRunner', 'assertTrue'];

echo "\nActor Feed: feed-page normalization\n";

$t('normalizes actors and pagination signals; drops malformed actors', function () use ($same, $true) {
    $page = WebDecoy_Actor_Feed::normalize_feed_page([
        'actors' => [
            ['id' => 'a1', 'ips' => ['1.1.1.1', '2.2.2.2'], 'last_seen' => 100],
            ['id' => '', 'ips' => ['3.3.3.3']],            // no id -> dropped
            ['id' => 'a3', 'ips' => []],                    // no ips -> dropped
            ['id' => 'a4', 'ips' => ['4.4.4.4', 5, ' ', '6.6.6.6']], // non-string/blank ip filtered
            'garbage',                                       // non-array -> skipped
        ],
        'next_since' => 555,
        'complete'   => false,
    ]);

    $same(2, count($page['actors']), 'only well-formed actors survive');
    $same('a1', $page['actors'][0]['id']);
    $same(['1.1.1.1', '2.2.2.2'], $page['actors'][0]['ips']);
    $same(['4.4.4.4', '6.6.6.6'], $page['actors'][1]['ips'], 'non-string and blank ips removed');
    $same(555, $page['next_since']);
    $true($page['complete'] === false, 'complete is a strict bool');
});

$t('missing pagination fields default safely', function () use ($same, $true) {
    $page = WebDecoy_Actor_Feed::normalize_feed_page([]);
    $same([], $page['actors']);
    $same(0, $page['next_since'], 'absent next_since -> 0');
    $true($page['complete'] === false, 'absent complete -> false');
});

echo "\nActor Feed: cross-page IP merge\n";

$t('merges ips across actors, keeping the most-recent last_seen', function () use ($same) {
    $acc = WebDecoy_Actor_Feed::merge_actor_ips([], [
        ['id' => 'a1', 'ips' => ['1.1.1.1'], 'last_seen' => 100],
        ['id' => 'a2', 'ips' => ['2.2.2.2'], 'last_seen' => 200],
    ]);
    // Second page: 1.1.1.1 reappears with a newer last_seen under a different actor.
    $acc = WebDecoy_Actor_Feed::merge_actor_ips($acc, [
        ['id' => 'a9', 'ips' => ['1.1.1.1'], 'last_seen' => 500],
    ]);

    $same(2, count($acc), 'ip set is deduped');
    $same('a9', $acc['1.1.1.1']['actor_id'], 'newer last_seen wins the actor attribution');
    $same(500, $acc['1.1.1.1']['last_seen']);
    $same(200, $acc['2.2.2.2']['last_seen']);
});

$t('an older repeat does not overwrite a newer record', function () use ($same) {
    $acc = WebDecoy_Actor_Feed::merge_actor_ips([], [
        ['id' => 'new', 'ips' => ['9.9.9.9'], 'last_seen' => 900],
    ]);
    $acc = WebDecoy_Actor_Feed::merge_actor_ips($acc, [
        ['id' => 'old', 'ips' => ['9.9.9.9'], 'last_seen' => 100],
    ]);
    $same('new', $acc['9.9.9.9']['actor_id'], 'stale duplicate is ignored');
    $same(900, $acc['9.9.9.9']['last_seen']);
});

echo "\nActor Feed: allowlist exclusion\n";

$t('never emits an allowlisted or invalid IP', function () use ($same, $true) {
    $map = [
        '1.1.1.1'   => ['actor_id' => 'a', 'last_seen' => 1],
        '2.2.2.2'   => ['actor_id' => 'b', 'last_seen' => 2], // allowlisted
        'not-an-ip' => ['actor_id' => 'c', 'last_seen' => 3], // invalid
        '2001:db8::1' => ['actor_id' => 'd', 'last_seen' => 4],
    ];
    $out = WebDecoy_Actor_Feed::exclude_allowlisted($map, ['2.2.2.2']);

    $true(isset($out['1.1.1.1']), 'non-allowlisted ipv4 kept');
    $true(isset($out['2001:db8::1']), 'valid ipv6 kept');
    $true(!isset($out['2.2.2.2']), 'exact allowlist match excluded');
    $true(!isset($out['not-an-ip']), 'invalid ip excluded');
    $same(2, count($out));
});

echo "\nActor Feed: cap / eviction ordering\n";

$t('no eviction while at or under the cap', function () use ($same) {
    $rows = ['1.1.1.1' => 100, '2.2.2.2' => 200];
    $same([], WebDecoy_Actor_Feed::select_evictions($rows, 2), 'exactly at cap keeps everything');
    $same([], WebDecoy_Actor_Feed::select_evictions($rows, 5), 'under cap keeps everything');
});

$t('evicts the oldest-seen rows first, exactly the overage', function () use ($same) {
    $rows = [
        'newest' => 500,
        'oldest' => 100,
        'middle' => 300,
    ];
    // Cap of 1 -> must drop the two oldest, keeping only "newest".
    $evict = WebDecoy_Actor_Feed::select_evictions($rows, 1);
    $same(['oldest', 'middle'], $evict, 'ascending last_seen order, count == overage');
});

echo "\nActor Feed: pagination continue decision\n";

$t('stops on complete, stalled cursor, or a cap; else continues', function () use ($true) {
    // complete -> stop even if a cursor was returned.
    $true(WebDecoy_Actor_Feed::should_continue(true, true, 1, 25, 10, 2000) === false, 'complete stops');
    // cursor did not advance -> stop (guards against an infinite loop).
    $true(WebDecoy_Actor_Feed::should_continue(false, false, 1, 25, 10, 2000) === false, 'stalled cursor stops');
    // page cap reached -> stop.
    $true(WebDecoy_Actor_Feed::should_continue(false, true, 25, 25, 10, 2000) === false, 'page cap stops');
    // row cap reached -> stop.
    $true(WebDecoy_Actor_Feed::should_continue(false, true, 1, 25, 2000, 2000) === false, 'row cap stops');
    // otherwise keep paginating.
    $true(WebDecoy_Actor_Feed::should_continue(false, true, 1, 25, 10, 2000) === true, 'incomplete + advanced continues');
});
