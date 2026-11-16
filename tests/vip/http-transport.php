<?php
// Isolated process: exercise VIP-present and ordinary WP runtimes separately.
declare(strict_types=1);
define('ABSPATH', '/tmp/');
require dirname(__DIR__) . '/bootstrap.php';
class WP_Error { public $code; public function __construct($code, $message) { $this->code = $code; } }
function wp_remote_get($url, $args) { $GLOBALS['wd_http_call'] = [$url, $args]; return $GLOBALS['wd_http_result']; }
function wp_remote_post($url, $args) { $GLOBALS['wd_http_call'] = [$url, $args]; return $GLOBALS['wd_http_result']; }
$vip = ($argv[1] ?? '') === 'vip';
if ($vip) {
    function vip_safe_wp_remote_get($url, $fallback, $threshold, $timeout, $retry, $args) {
        $GLOBALS['wd_http_vip_call'] = [$url, $fallback, $threshold, $timeout, $retry, $args];
        return $GLOBALS['wd_http_result'] ?? $fallback;
    }
}
require dirname(__DIR__, 2) . '/includes/class-webdecoy-http.php';
$headers = ['Authorization' => 'Bearer test-key', 'Accept' => 'application/json'];
$args = ['headers' => $headers, 'timeout' => 10];
$GLOBALS['wd_http_result'] = ['response' => ['code' => 403], 'body' => '{"error":"forbidden"}'];
TestRunner::test('HTTP preserves non-success responses and authorization', function () use ($args, $vip, $headers) {
    TestRunner::assertSame($GLOBALS['wd_http_result'], WebDecoy_HTTP::get('https://service.invalid/feed', $args));
    if ($vip) {
        $call = $GLOBALS['wd_http_vip_call'];
        TestRunner::assertSame('https://service.invalid/feed', $call[0]);
        TestRunner::assertTrue($call[1] instanceof WP_Error);
        TestRunner::assertSame(3, $call[2]);
        TestRunner::assertSame(3.0, $call[3]);
        TestRunner::assertSame(20, $call[4]);
        TestRunner::assertSame($headers, $call[5]['headers']);
        TestRunner::assertSame(3.0, $call[5]['timeout']);
        TestRunner::assertTrue(!isset($GLOBALS['wd_http_call']), 'VIP must not use the ordinary GET fallback');
    } else {
        TestRunner::assertSame(['https://service.invalid/feed', $args], $GLOBALS['wd_http_call']);
    }
});
TestRunner::test('transport failures stay WP_Error, never success-shaped cached data', function () use ($args, $vip) {
    $GLOBALS['wd_http_result'] = $vip ? null : new WP_Error('timeout', 'Timeout');
    TestRunner::assertTrue(WebDecoy_HTTP::get('https://service.invalid/feed', $args) instanceof WP_Error);
});
TestRunner::test('POST preserves one-time exchange body without replay or GET circuit breaking', function () use ($args, $vip) {
    $GLOBALS['wd_http_result'] = ['response' => ['code' => 200]];
    $post = $args + ['body' => '{"connect_token":"one-time"}'];
    TestRunner::assertSame($GLOBALS['wd_http_result'], WebDecoy_HTTP::post('https://service.invalid/exchange', $post));
    $expected = $post;
    if ($vip) { $expected['timeout'] = 3.0; }
    TestRunner::assertSame(['https://service.invalid/exchange', $expected], $GLOBALS['wd_http_call']);
});
if ($vip) {
    foreach ([0 => 0.1, 1 => 1.0, 2 => 2.0, 30 => 3.0, 'bad' => 3.0] as $input => $expected) {
        TestRunner::test('VIP bounds timeout ' . $input, function () use ($input, $expected) {
            WebDecoy_HTTP::get('https://service.invalid/feed', ['timeout' => $input]);
            TestRunner::assertSame($expected, $GLOBALS['wd_http_vip_call'][3]);
        });
    }
}
exit(TestRunner::summary());
