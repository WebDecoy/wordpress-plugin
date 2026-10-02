<?php

declare(strict_types=1);

/**
 * Detections are sent after the response, never in the page path
 * (WebDecoy/app#1245).
 *
 * When ingest was slow or down, an inline send with a 10 second timeout (plus a
 * 10 second key lookup) stalled every flagged page view for up to 20 seconds,
 * before the block decision ran. These tests pin the deferral, the backoff that
 * stops an outage costing one failed attempt per page view, and, by reading the
 * plugin source, that no send path goes around the sender.
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

$t('a detection is queued during the request, not sent', function () use ($same) {
    WebDecoy_Detection_Sender::reset();
    $sent = 0;
    WebDecoy_Detection_Sender::defer(function () use (&$sent) { $sent++; });
    $same(0, $sent, 'nothing is sent while the request is being handled');
    $same(1, WebDecoy_Detection_Sender::queued());
    WebDecoy_Detection_Sender::send_queued();
    $same(1, $sent, 'sent at shutdown');
    $same(0, WebDecoy_Detection_Sender::queued());
});

$t('a refusal pauses sending for every later request', function () use ($same, $true) {
    WebDecoy_Detection_Sender::reset();
    $calls = 0;
    WebDecoy_Detection_Sender::defer(function () use (&$calls) { $calls++; throw new \Exception('shed', 503); });
    WebDecoy_Detection_Sender::defer(function () use (&$calls) { $calls++; });
    WebDecoy_Detection_Sender::send_queued();
    $same(1, $calls, 'stops at the first refusal');
    $true(WebDecoy_Detection_Sender::backing_off());
    // The next request queues nothing while backing off.
    WebDecoy_Detection_Sender::defer(function () use (&$calls) { $calls++; });
    $same(0, WebDecoy_Detection_Sender::queued());
});

$t('429, 5xx and no answer are refusals; other 4xx are not', function () use ($true) {
    $true(WebDecoy_Detection_Sender::is_refusal(new \Exception('', 429)));
    $true(WebDecoy_Detection_Sender::is_refusal(new \Exception('', 503)));
    $true(WebDecoy_Detection_Sender::is_refusal(new \Exception('timeout', 0)));
    $true(!WebDecoy_Detection_Sender::is_refusal(new \Exception('', 400)));
    $true(!WebDecoy_Detection_Sender::is_refusal(new \Exception('', 401)));
});

$t('a bad request does not pause sending', function () use ($true) {
    WebDecoy_Detection_Sender::reset();
    WebDecoy_Detection_Sender::defer(function () { throw new \Exception('bad payload', 400); });
    WebDecoy_Detection_Sender::send_queued();
    $true(!WebDecoy_Detection_Sender::backing_off());
});

$t('one request queues at most five sends', function () use ($same) {
    WebDecoy_Detection_Sender::reset();
    for ($i = 0; $i < 20; $i++) {
        WebDecoy_Detection_Sender::defer(function () {});
    }
    $same(5, WebDecoy_Detection_Sender::queued());
    WebDecoy_Detection_Sender::reset();
});

$t('every detection send in the plugin goes through the deferred sender', function () use ($same, $true) {
    $src = (string) file_get_contents(dirname(__DIR__) . '/webdecoy.php');
    $same(1, substr_count($src, '->submitDetection('), 'exactly one send site');
    $send = strpos($src, '->submitDetection(');
    $defer = strrpos(substr($src, 0, (int) $send), 'WebDecoy_Detection_Sender::defer(');
    $true($defer !== false && $send - $defer < 400, 'the send site is inside a WebDecoy_Detection_Sender::defer closure');
    // The detection client never falls back to a per-request key lookup when
    // the organization id is known, and never waits 10 seconds.
    $true(strpos($src, "'timeout' => 3,") !== false, 'detection client uses a short timeout');
    $true(strpos($src, "'organization_id' => \$org !== '' ? \$org : null,") !== false, 'detection client is given the organization id');
});

