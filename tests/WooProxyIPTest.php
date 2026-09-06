<?php

declare(strict_types=1);

require_once __DIR__ . '/WooOrderStatusTest.php';
require_once dirname(__DIR__) . '/sdk/src/SignalCollector.php';

function webdecoy()
{
    return $GLOBALS['wd_woo_proxy_plugin'];
}

TestRunner::test('WooCommerce shares the configured client IP resolver', function () {
    $saved = $_SERVER;
    $GLOBALS['wd_woo_proxy_plugin'] = new class {
        public array $proxies = ['10.0.0.0/8'];
        public function get_client_ip(): string
        {
            return (new \WebDecoy\SignalCollector($this->proxies))->getIP();
        }
    };
    $woo = (new ReflectionClass(WebDecoy_WooCommerce::class))->newInstanceWithoutConstructor();
    try {
        foreach (['203.0.113.11', '203.0.113.12'] as $shopper) {
            $_SERVER = ['REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_FOR' => $shopper];
            TestRunner::assertSame($shopper, $woo->get_client_ip_public(), 'shoppers must not share the proxy bucket');
        }
        $GLOBALS['wd_woo_proxy_plugin']->proxies = [];
        TestRunner::assertSame('10.0.0.5', $woo->get_client_ip_public(), 'untrusted headers stay untrusted');
        $GLOBALS['wd_woo_proxy_plugin']->proxies = ['10.0.0.0/8'];
        $_SERVER = ['REMOTE_ADDR' => '203.0.113.21', 'HTTP_X_FORWARDED_FOR' => '192.0.2.99'];
        TestRunner::assertSame('203.0.113.21', $woo->get_client_ip_public(), 'direct requests cannot spoof their IP');
    } finally {
        $_SERVER = $saved;
        unset($GLOBALS['wd_woo_proxy_plugin']);
    }
});

TestRunner::test('checkout cannot reintroduce an unconfigured IP collector', function () {
    $source = file_get_contents(dirname(__DIR__) . '/includes/class-webdecoy-woocommerce.php');
    preg_match('/private function get_client_ip\(\): string\s*\{([^}]+)\}/', $source, $match);
    TestRunner::assertTrue(isset($match[1]), 'client IP method must exist');
    TestRunner::assertTrue(strpos($match[1], 'SignalCollector') === false, 'delegate instead of constructing an IP collector');
    TestRunner::assertTrue(strpos($match[1], 'webdecoy()->get_client_ip()') !== false, 'use the configured resolver');
});
