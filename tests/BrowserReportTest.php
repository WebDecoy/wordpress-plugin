<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/');
}
require_once dirname(__DIR__) . '/includes/class-webdecoy-browser-report.php';

TestRunner::test('the AJAX relay builds a separate browser report from aggregate observations', function () {
    $report = WebDecoy_Browser_Report::build([
        's' => 92,
        'f' => ['behavior_robotic_mouse_movement', 'behavior_robotic_scrolling', 'behavior_clicks_without_mouse_movement'],
        'fp' => ['maxTouchPoints' => 0, 'language' => 'en-US', 'userAgent' => 'browser-claim'],
        'behavior' => [
            'mouseMovements' => 40, 'straightLineRatio' => 0.8, 'scrollEvents' => 8, 'clicks' => 2,
            'keyPresses' => 0, 'timeOnPage' => 6000, 'timeToFirstInteraction' => 123,
        ],
    ], 'GPTBot/1.0');

    TestRunner::assertSame('wordpress_browser', $report['source']);
    TestRunner::assertSame(92, $report['s']);
    TestRunner::assertSame('GPTBot/1.0', $report['ua']);
    TestRunner::assertSame(['behavior_clicks_without_mouse_movement', 'behavior_robotic_mouse_movement', 'behavior_robotic_scrolling'], $report['f']);
    TestRunner::assertSame([
        'timeOnPage' => 6000, 'timeToFirstInteraction' => 123, 'mouseMovements' => 40, 'straightLineRatio' => 0.8,
        'clicks' => 2, 'scrollEvents' => 8, 'keyPresses' => 0, 'maxTouchPoints' => 0,
    ], $report['behavior']);
    TestRunner::assertSame(['maxTouchPoints' => 0, 'language' => 'en-US', 'userAgent' => 'GPTBot/1.0'], $report['fp']);
});

TestRunner::test('browser reports omit field contents, URL query data, and unsupported values', function () {
    $report = WebDecoy_Browser_Report::build([
        's' => 999,
        'f' => ['tripwire', 'PRIVATE_FIXTURE', ['PRIVATE_FIXTURE']],
        'ai' => 'PRIVATE_FIXTURE',
        'hp' => 'PRIVATE_FIXTURE',
        'url' => 'https://test:PRIVATE_FIXTURE@example.test:8443/products?field=PRIVATE_FIXTURE#PRIVATE_FIXTURE',
        'ref' => 'javascript:PRIVATE_FIXTURE',
        'fp' => ['webrtcIP' => 'PRIVATE_FIXTURE', 'arbitrary' => 'PRIVATE_FIXTURE'],
        'behavior' => [
            'mouseMovements' => '47', 'clicks' => [], 'scrollEvents' => 51, 'straightLineRatio' => -0.1,
            'keyPresses' => 0, 'timeToFirstInteraction' => null, 'form' => ['value' => 'PRIVATE_FIXTURE'],
        ],
    ], '');

    TestRunner::assertSame(100, $report['s']);
    TestRunner::assertSame('https://example.test:8443/products', $report['url']);
    TestRunner::assertSame('', $report['ref']);
    TestRunner::assertSame('filled', $report['hp']);
    TestRunner::assertSame([], $report['f']);
    TestRunner::assertSame(['keyPresses' => 0], $report['behavior']);
    TestRunner::assertTrue(!isset($report['fp']) && !isset($report['ai']));
    TestRunner::assertTrue(strpos(json_encode($report), 'PRIVATE_FIXTURE') === false);
});

TestRunner::test('cached AJAX payloads can report without behavior or fingerprint objects', function () {
    $report = WebDecoy_Browser_Report::build(['s' => 50, 'f' => ['webdriver']], '');
    TestRunner::assertSame(['webdriver'], $report['f']);
    TestRunner::assertTrue(!array_key_exists('behavior', $report));
    TestRunner::assertTrue(!array_key_exists('fp', $report));
});
