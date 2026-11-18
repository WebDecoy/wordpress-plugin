<?php
/** Dashboard chart/card reconciliation at UTC boundaries. */
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/class-webdecoy-crawler-visits.php';
require_once dirname(__DIR__) . '/includes/class-webdecoy-ai-referrals.php';
require_once dirname(__DIR__) . '/includes/class-webdecoy-traffic-report.php';

TestRunner::test('traffic report clamps ranges and fills exactly seven UTC dates', function () {
    $r = WebDecoy_Traffic_Report::project([], [], 99, strtotime('2026-11-18 00:01:00 UTC'));
    TestRunner::assertSame(7, $r['days']);
    TestRunner::assertSame('2026-11-12', $r['labels'][0]);
    TestRunner::assertSame('2026-11-18', $r['labels'][6]);
    TestRunner::assertSame(array_fill(0, 7, 0), $r['series']['ai']);
    TestRunner::assertSame(0, $r['crawlers']['total']);
});

TestRunner::test('traffic cards and charts use the same valid in-window rows', function () {
    $r = WebDecoy_Traffic_Report::project([
        ['day' => '2026-11-12', 'agent_id' => 'gptbot', 'verification' => 'claimed', 'hits' => '4'],
        ['day' => '2026-11-18', 'agent_id' => 'googlebot', 'verification' => 'verified', 'hits' => 3],
        ['day' => '2026-11-18', 'agent_id' => 'retired-agent', 'verification' => 'claimed', 'hits' => 2],
        ['day' => '2026-11-11', 'agent_id' => 'gptbot', 'verification' => 'claimed', 'hits' => 90],
        ['day' => '2026-11-18', 'agent_id' => 'gptbot', 'verification' => 'invalid', 'hits' => 80],
        ['day' => '2026-11-19', 'agent_id' => 'gptbot', 'verification' => 'claimed', 'hits' => 70],
    ], [
        ['day' => '2026-11-18', 'platform' => 'ChatGPT', 'landing_path' => '/', 'referrals' => '5'],
        ['day' => '2026-11-18', 'platform' => 'ChatGPT', 'landing_path' => '', 'referrals' => 1],
        ['day' => '2026-11-11', 'platform' => 'Claude', 'landing_path' => '/', 'referrals' => 50],
    ], 7, strtotime('2026-11-18 00:01:00 UTC'));
    TestRunner::assertSame(['ai' => 4, 'search' => 3, 'other' => 2], $r['crawlers']['groups']);
    TestRunner::assertSame(9, $r['crawlers']['total']);
    foreach ($r['crawlers']['groups'] as $group => $n) {
        TestRunner::assertSame($n, array_sum($r['series'][$group]));
    }
    TestRunner::assertSame(6, $r['referrals']['total']);
    TestRunner::assertSame(6, array_sum($r['series']['referrals']));
    TestRunner::assertSame(5, $r['referrals']['pages'][0]['referrals']);
});

TestRunner::test('thirty-day report includes the UTC first day and rejects older rows', function () {
    $r = WebDecoy_Traffic_Report::project([
        ['day' => '2026-10-20', 'agent_id' => 'gptbot', 'verification' => 'claimed', 'hits' => 2],
        ['day' => '2026-10-19', 'agent_id' => 'gptbot', 'verification' => 'claimed', 'hits' => 9],
    ], [], 30, strtotime('2026-11-18 23:59:00 UTC'));
    TestRunner::assertSame(30, count($r['labels']));
    TestRunner::assertSame(2, $r['crawlers']['total']);
    TestRunner::assertSame(2, $r['series']['ai'][0]);
});
