<?php

declare(strict_types=1);

/** Pure outcome selection, response validation and UTC accounting boundaries. */
if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/');
}
require_once dirname(__DIR__) . '/includes/class-webdecoy-request-counts.php';

$t = ['TestRunner', 'test'];
$same = ['TestRunner', 'assertSame'];
$true = ['TestRunner', 'assertTrue'];

$t('repeated decisions keep one strongest request outcome', function () use ($same) {
    $outcome = '';
    foreach (['withheld', 'withheld', 'challenged', 'throttled', 'blocked', 'blocked', 'withheld'] as $decision) {
        $outcome = WebDecoy_Request_Counts::choose($outcome, $decision);
    }
    $same('blocked', $outcome);
    $same('withheld', WebDecoy_Request_Counts::choose('withheld', 'unknown'));
    $same('', WebDecoy_Request_Counts::choose('', 'unknown'));
});

$t('only the matching final HTTP denial counts as a block or throttle', function () use ($same) {
    foreach ([200, 301, 404, 429, 500] as $status) {
        $same(false, WebDecoy_Request_Counts::matches_response('blocked', $status));
        $same(false, WebDecoy_Request_Counts::matches_response('challenged', $status));
    }
    $same(true, WebDecoy_Request_Counts::matches_response('blocked', 403));
    $same(true, WebDecoy_Request_Counts::matches_response('challenged', 403));
    $same(true, WebDecoy_Request_Counts::matches_response('throttled', 429));
    $same(false, WebDecoy_Request_Counts::matches_response('throttled', 403));
    $same(false, WebDecoy_Request_Counts::matches_response('', 403));
    $same(false, WebDecoy_Request_Counts::matches_response('unknown', 403));
});

$t('withheld enforcement is an observation, never an actual denial', function () use ($same) {
    foreach ([200, 302, 403, 429] as $status) {
        $same(true, WebDecoy_Request_Counts::matches_response('withheld', $status));
    }
    $totals = WebDecoy_Request_Counts::summarize([['outcome' => 'withheld', 'hits' => 9]]);
    $same(9, $totals['withheld']);
    $same(0, $totals['blocked']);
    $same(0, $totals['throttled']);
});

$t('setup user agents are excluded without excluding ordinary bots', function () use ($same) {
    $same(true, WebDecoy_Request_Counts::is_setup_test(' WebDecoy-Test/1.0 Playground'));
    $same(true, WebDecoy_Request_Counts::is_setup_test('webdecoy-test/1.0'));
    $same(false, WebDecoy_Request_Counts::is_setup_test('python-requests/2.32.3'));
    $same(false, WebDecoy_Request_Counts::is_setup_test('Mozilla/5.0 WebDecoy-Test/1.0'));
});

$t('calendar windows cross month and leap-day boundaries in UTC', function () use ($same) {
    $now = gmmktime(23, 59, 59, 3, 1, 2024);
    $same(['from' => '2024-03-01 00:00:00', 'until' => '2024-03-02 00:00:00'], WebDecoy_Request_Counts::window(1, $now));
    $same(['from' => '2024-02-24 00:00:00', 'until' => '2024-03-02 00:00:00'], WebDecoy_Request_Counts::window(7, $now));
    $same(['from' => '2024-02-01 00:00:00', 'until' => '2024-03-02 00:00:00'], WebDecoy_Request_Counts::window(30, $now));
    $same(WebDecoy_Request_Counts::window(1, $now), WebDecoy_Request_Counts::window(0, $now));
    $same(WebDecoy_Request_Counts::window(30, $now), WebDecoy_Request_Counts::window(900, $now));
});

$t('stored outcome rows reconcile independently and ignore unknown dimensions', function () use ($same) {
    $rows = [
        ['outcome' => 'blocked', 'hits' => '12'],
        ['outcome' => 'blocked', 'hits' => 5],
        ['outcome' => 'challenged', 'hits' => 3],
        ['outcome' => 'throttled', 'hits' => 4],
        ['outcome' => 'withheld', 'hits' => 9],
        ['outcome' => 'unknown', 'hits' => 1000],
        ['outcome' => 'blocked', 'hits' => -5],
        ['outcome' => 'blocked', 'hits' => 'bad'],
    ];
    $totals = WebDecoy_Request_Counts::summarize($rows);
    $same(['blocked' => 17, 'throttled' => 4, 'challenged' => 3, 'withheld' => 9], $totals);
    $same(33, array_sum($totals));
});
