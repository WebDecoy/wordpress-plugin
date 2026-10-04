<?php

declare(strict_types=1);

/**
 * BotDetector resolves a missing client IP the way SignalCollector does (#85).
 *
 * The address analyze() settles on is the one a good bot is verified against.
 * It used to come from a private resolver that took CF-Connecting-IP or the
 * leftmost X-Forwarded-For from anyone, so a client could pick the address its
 * claimed Googlebot was checked against. These tests watch that address through
 * a GoodBotList spy, so no reverse DNS runs.
 *
 * Run: php tests/run.php
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/');
}
if (!function_exists('get_transient')) {
    function get_transient($key) { return false; }
}
if (!function_exists('set_transient')) {
    function set_transient($key, $value, $ttl = 0) { return true; }
}
if (!isset($GLOBALS['__wd_opts'])) {
    $GLOBALS['__wd_opts'] = [];
}
if (!function_exists('get_option')) {
    function get_option($k, $d = false)
    {
        return $GLOBALS['__wd_opts'][$k] ?? $d;
    }
}
foreach (['DetectionResult', 'AgentRegistry', 'GoodBotList', 'RouteResolution', 'SignalCollector', 'MitreMapping', 'BotDetector'] as $class) {
    $file = dirname(__DIR__) . '/sdk/src/' . $class . '.php';
    if (is_file($file)) {
        require_once $file;
    }
}
require_once dirname(__DIR__) . '/includes/class-webdecoy-detector.php';

/** Records the IP a bot is verified against instead of resolving DNS. */
class BotDetectorIpSpy extends \WebDecoy\GoodBotList
{
    /** @var string|null */
    public $verifiedIp = null;

    public function verifyBotIP(string $userAgent, string $ip): array
    {
        $this->verifiedIp = $ip;
        return ['verified' => false, 'hostname' => null, 'reason' => 'spy'];
    }
}

const BOT_DETECTOR_IP_GOOGLEBOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

/**
 * The IP analyze() verified a Googlebot request against.
 *
 * @param array<string, string> $server  Request $_SERVER
 * @param string[]              $proxies Trusted proxies
 * @param array|null            $signals Signals passed to analyze(), or null to collect
 */
function bot_detector_verified_ip(array $server, array $proxies, ?array $signals = null): ?string
{
    $saved = $_SERVER;
    $_SERVER = $server + ['HTTP_USER_AGENT' => BOT_DETECTOR_IP_GOOGLEBOT, 'REQUEST_URI' => '/'];
    try {
        $detector = new \WebDecoy\BotDetector(['trusted_proxies' => $proxies]);
        $spy = new BotDetectorIpSpy();
        $prop = new ReflectionProperty(\WebDecoy\BotDetector::class, 'goodBotList');
        if (PHP_VERSION_ID < 80100) {
            $prop->setAccessible(true);
        }
        $prop->setValue($detector, $spy);
        $detector->analyze($signals);
        return $spy->verifiedIp;
    } finally {
        $_SERVER = $saved;
    }
}

/** Signals without ip_address, as a caller that collected its own would pass. */
function bot_detector_signals_without_ip(): array
{
    return ['user_agent' => BOT_DETECTOR_IP_GOOGLEBOT, 'request_path' => '/'];
}

$spoofed = [
    'REMOTE_ADDR' => '203.0.113.5',
    'HTTP_CF_CONNECTING_IP' => '192.0.2.66',
    'HTTP_X_FORWARDED_FOR' => '192.0.2.77, 198.51.100.1',
    'HTTP_X_REAL_IP' => '192.0.2.88',
];

TestRunner::test('with no trusted proxy, forwarding headers cannot choose the verified IP', function () use ($spoofed) {
    TestRunner::assertSame('203.0.113.5', bot_detector_verified_ip($spoofed, []), 'collected signals');
    TestRunner::assertSame('203.0.113.5', bot_detector_verified_ip($spoofed, [], bot_detector_signals_without_ip()), 'missing ip_address');
});

TestRunner::test('a client that is not a trusted proxy cannot spoof past one configured elsewhere', function () use ($spoofed) {
    TestRunner::assertSame('203.0.113.5', bot_detector_verified_ip($spoofed, ['10.0.0.0/8'], bot_detector_signals_without_ip()));
});

TestRunner::test('behind a trusted proxy the X-Forwarded-For chain is read right to left', function () {
    $server = ['REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_FOR' => '192.0.2.77, 198.51.100.7, 10.0.0.9'];
    TestRunner::assertSame('198.51.100.7', bot_detector_verified_ip($server, ['10.0.0.0/8'], bot_detector_signals_without_ip()));
});

TestRunner::test('IPv6 chains resolve the same way', function () {
    $server = ['REMOTE_ADDR' => '2001:db8:ffff::1', 'HTTP_X_FORWARDED_FOR' => '2001:db8::bad, 2001:db8:1::7, 2001:db8:ffff::2'];
    TestRunner::assertSame('2001:db8:1::7', bot_detector_verified_ip($server, ['2001:db8:ffff::/48'], bot_detector_signals_without_ip()), 'trusted IPv6 proxy');
    $direct = ['REMOTE_ADDR' => '2001:db8:2::5', 'HTTP_X_FORWARDED_FOR' => '2001:db8::bad'];
    TestRunner::assertSame('2001:db8:2::5', bot_detector_verified_ip($direct, [], bot_detector_signals_without_ip()), 'untrusted IPv6 peer');
});

TestRunner::test('a valid supplied ip_address is kept, an invalid one is resolved', function () use ($spoofed) {
    $signals = bot_detector_signals_without_ip();
    TestRunner::assertSame('198.51.100.9', bot_detector_verified_ip($spoofed, [], $signals + ['ip_address' => '198.51.100.9']));
    TestRunner::assertSame('203.0.113.5', bot_detector_verified_ip($spoofed, [], $signals + ['ip_address' => 'not-an-ip']));
});

TestRunner::test('BotDetector and SignalCollector resolve the same request identically', function () {
    $cases = [
        [['REMOTE_ADDR' => '203.0.113.5', 'HTTP_X_FORWARDED_FOR' => '192.0.2.77'], []],
        [['REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_FOR' => '192.0.2.77, 198.51.100.7'], ['10.0.0.0/8']],
        [['REMOTE_ADDR' => '10.0.0.5', 'HTTP_CF_CONNECTING_IP' => '198.51.100.8'], ['10.0.0.0/8']],
        [['REMOTE_ADDR' => '2001:db8:ffff::1', 'HTTP_X_FORWARDED_FOR' => '2001:db8:1::7'], ['2001:db8:ffff::/48']],
    ];
    foreach ($cases as [$server, $proxies]) {
        $saved = $_SERVER;
        $_SERVER = $server;
        $expected = (new \WebDecoy\SignalCollector($proxies))->getIP();
        $_SERVER = $saved;
        TestRunner::assertSame($expected, bot_detector_verified_ip($server, $proxies, bot_detector_signals_without_ip()), $server['REMOTE_ADDR']);
    }
});

TestRunner::test('the WordPress detector wrapper uses the configured trusted proxies', function () {
    $GLOBALS['wd_bot_detector_ip_proxies'] = ['10.0.0.0/8'];
    if (!function_exists('webdecoy_plugin_trusted_proxies')) {
        function webdecoy_plugin_trusted_proxies(): array
        {
            return $GLOBALS['wd_bot_detector_ip_proxies'] ?? [];
        }
    }
    $saved = $_SERVER;
    $_SERVER = ['REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_FOR' => '198.51.100.7'];
    try {
        $wrapper = new WebDecoy_Detector([]);
        $prop = new ReflectionProperty(WebDecoy_Detector::class, 'detector');
        if (PHP_VERSION_ID < 80100) {
            $prop->setAccessible(true);
        }
        TestRunner::assertSame('198.51.100.7', $prop->getValue($wrapper)->getSignalCollector()->getIP());
    } finally {
        $_SERVER = $saved;
        unset($GLOBALS['wd_bot_detector_ip_proxies']);
    }
});
