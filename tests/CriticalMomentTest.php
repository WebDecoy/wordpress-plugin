<?php

declare(strict_types=1);

/**
 * Tests for the pure, WordPress-free helpers in WebDecoy_Critical_Moment:
 * the 7-day throttle decision, the first-seen "N days" computation, and the
 * copy-variant selection from connection / intel / entitlement state.
 *
 * Run: php tests/run.php
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/');
}
require_once dirname(__DIR__) . '/includes/class-webdecoy-critical-moment.php';

$t = ['TestRunner', 'test'];
$same = ['TestRunner', 'assertSame'];
$true = ['TestRunner', 'assertTrue'];

$week = 604800;

echo "\nCritical Moment: throttle\n";

$t('a never-fired moment is always allowed', function () use ($true, $week) {
    $true(WebDecoy_Critical_Moment::should_queue(0, 1000000, $week) === true, 'no prior moment -> allow');
    $true(WebDecoy_Critical_Moment::should_queue(-1, 1000000, $week) === true, 'sentinel <= 0 -> allow');
});

$t('throttle blocks within the window and reopens at the boundary', function () use ($true, $week) {
    $now = 10000000;
    $true(WebDecoy_Critical_Moment::should_queue($now - 1, $now, $week) === false, '1s later still blocked');
    $true(WebDecoy_Critical_Moment::should_queue($now - ($week - 1), $now, $week) === false, 'just inside window blocked');
    $true(WebDecoy_Critical_Moment::should_queue($now - $week, $now, $week) === true, 'exactly at window reopens');
    $true(WebDecoy_Critical_Moment::should_queue($now - ($week + 1), $now, $week) === true, 'past window allowed');
});

echo "\nCritical Moment: days since first seen\n";

$t('days_since floors whole days and clamps to zero', function () use ($same) {
    $now = 1000000000;
    $same(0, WebDecoy_Critical_Moment::days_since(0, $now), 'no first_seen -> 0');
    $same(0, WebDecoy_Critical_Moment::days_since($now + 5000, $now), 'future first_seen -> 0');
    $same(0, WebDecoy_Critical_Moment::days_since($now - 3600, $now), 'under a day -> 0');
    $same(1, WebDecoy_Critical_Moment::days_since($now - 86400, $now), 'exactly one day');
    $same(3, WebDecoy_Critical_Moment::days_since($now - (3 * 86400 + 100), $now), 'floors partial days');
});

echo "\nCritical Moment: copy variant\n";

$t('variant reflects connection, intel, and entitlement', function () use ($same) {
    $same('unconnected', WebDecoy_Critical_Moment::variant(false, false, false), 'not connected');
    $same('unconnected', WebDecoy_Critical_Moment::variant(false, true, true), 'connection is the gate');
    $same('connected_unknown', WebDecoy_Critical_Moment::variant(true, false, false), 'connected but IP unknown');
    $same('connected_upgrade', WebDecoy_Critical_Moment::variant(true, true, false), 'known + no feed -> upgrade pitch');
    $same('connected_covered', WebDecoy_Critical_Moment::variant(true, true, true), 'known + feed -> confirmation copy');
});
