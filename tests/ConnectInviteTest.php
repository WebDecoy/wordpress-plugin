<?php

declare(strict_types=1);

/**
 * Tests for the pure helpers in WebDecoy_Connect_Invite: when the invite
 * shows, what each choice stores, and the copy built on the week's counts.
 *
 * Run: php tests/run.php
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/');
}
require_once dirname(__DIR__) . '/includes/class-webdecoy-connect-invite.php';
require_once dirname(__DIR__) . '/includes/class-webdecoy-cloud-connect.php';

$t = ['TestRunner', 'test'];
$true = ['TestRunner', 'assertTrue'];
$same = ['TestRunner', 'assertSame'];

$now = 20000000;

echo "\nConnect invite: when it shows\n";

$t('shows on a site that is not connected and has not answered', function () use ($true, $now) {
    $true(WebDecoy_Connect_Invite::is_due(false, '', $now) === true, 'pending, not connected -> shown');
});

$t('never on a connected site, whatever the state', function () use ($true, $now) {
    $true(WebDecoy_Connect_Invite::is_due(true, '', $now) === false, 'connected -> hidden');
    $true(WebDecoy_Connect_Invite::is_due(true, 'later:1', $now) === false, 'connected after a snooze -> hidden');
});

$t("don't show again ends it; a snooze holds until it ends", function () use ($true, $now) {
    $true(WebDecoy_Connect_Invite::is_due(false, 'never', $now) === false, 'never -> hidden');
    $true(WebDecoy_Connect_Invite::is_due(false, 'later:' . ($now + 1), $now) === false, 'inside the snooze -> hidden');
    $true(WebDecoy_Connect_Invite::is_due(false, 'later:' . $now, $now) === true, 'snooze over -> shown');
});

echo "\nConnect invite: choices\n";

$t('not now snoozes 14 days; anything unrecognised snoozes too', function () use ($same, $now) {
    $same('later:' . ($now + WebDecoy_Connect_Invite::SNOOZE), WebDecoy_Connect_Invite::state_for('later', $now));
    $same('later:' . ($now + WebDecoy_Connect_Invite::SNOOZE), WebDecoy_Connect_Invite::state_for('bogus', $now));
    $same('never', WebDecoy_Connect_Invite::state_for('never', $now));
});

$t('the connect source is an allowlisted label', function () use ($same) {
    $same('invite', WebDecoy_Cloud_Connect::connect_source('invite'));
    $same('settings', WebDecoy_Cloud_Connect::connect_source(''));
    $same('settings', WebDecoy_Cloud_Connect::connect_source('<script>'));
});

echo "\nConnect invite: copy\n";

$t('names the week\'s counts when there are any', function () use ($true) {
    $msg = WebDecoy_Connect_Invite::message(1234, 56);
    $true(strpos($msg, '1,234 bot visits') !== false && strpos($msg, '56 of them') !== false, 'totals and AI share');
    $true(strpos(WebDecoy_Connect_Invite::message(7, 0), '7 bot visits') !== false, 'totals without AI');
    $true(strpos(WebDecoy_Connect_Invite::message(0, 0), 'now counting') !== false, 'nothing counted yet');
});

$t('promises nothing leaves the site before Connect', function () use ($true) {
    $true(strpos(WebDecoy_Connect_Invite::offer(), 'Nothing leaves your site until you click Connect') !== false, 'privacy line');
});
