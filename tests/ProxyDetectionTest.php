<?php

declare(strict_types=1);

/**
 * The admin-side "behind an unconfigured proxy" detection must not fire on hosts
 * that already resolve REMOTE_ADDR to the visitor and merely pass the forwarding
 * headers along (WordPress.com, nginx real_ip, mod_remoteip).
 *
 * Run: php tests/run.php
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/');
}
if (!function_exists('sanitize_text_field')) {
    function sanitize_text_field($s) // phpcs:ignore
    {
        return trim((string) $s);
    }
}
if (!function_exists('wp_unslash')) {
    function wp_unslash($s) // phpcs:ignore
    {
        return $s;
    }
}
require_once dirname(__DIR__) . '/includes/class-webdecoy-blocker.php';

echo "\nProxy detection: unresolved forwarding headers\n";

TestRunner::test('flags only forwarding headers the host has not resolved', function () {
    $saved = $_SERVER;
    $cases = [
        'no headers' => [['REMOTE_ADDR' => '203.0.113.5'], ''],
        'host resolved XFF' => [['REMOTE_ADDR' => '203.0.113.5', 'HTTP_X_FORWARDED_FOR' => '203.0.113.5'], ''],
        'host resolved XFF chain' => [['REMOTE_ADDR' => '203.0.113.5', 'HTTP_X_FORWARDED_FOR' => '198.51.100.1, 203.0.113.5'], ''],
        'host resolved CF' => [['REMOTE_ADDR' => '2001:db8::1', 'HTTP_CF_CONNECTING_IP' => '2001:DB8:0::1'], ''],
        'host resolved Forwarded' => [['REMOTE_ADDR' => '2001:db8::1', 'HTTP_FORWARDED' => 'for="[2001:db8::1]:4711";proto=https'], ''],
        'host resolved v4:port' => [['REMOTE_ADDR' => '203.0.113.5', 'HTTP_FORWARDED' => 'for=203.0.113.5:443'], ''],
        'unresolved XFF' => [['REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => '203.0.113.5'], 'X-Forwarded-For'],
        'unresolved CF' => [['REMOTE_ADDR' => '172.70.1.1', 'HTTP_CF_CONNECTING_IP' => '203.0.113.5', 'HTTP_X_FORWARDED_FOR' => '203.0.113.5'], 'CF-Connecting-IP'],
        'garbage header' => [['REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => 'unknown'], 'X-Forwarded-For'],
    ];
    try {
        foreach ($cases as $name => [$server, $expected]) {
            $_SERVER = $server;
            TestRunner::assertSame($expected, WebDecoy_Blocker::unresolved_forwarding_header(), $name);
        }
    } finally {
        $_SERVER = $saved;
    }
});
