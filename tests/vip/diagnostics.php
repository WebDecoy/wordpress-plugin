<?php
declare(strict_types=1);
define('ABSPATH', '/tmp/');
define('WP_DEBUG', ($argv[1] ?? '') === 'debug');
define('WP_DEBUG_LOG', true);
require dirname(__DIR__) . '/bootstrap.php';
require dirname(__DIR__, 2) . '/includes/class-webdecoy-diagnostics.php';
$log = tempnam(sys_get_temp_dir(), 'wd-diagnostics-');
ini_set('error_log', $log);
try {
    WebDecoy_Diagnostics::report('api_error');
    WebDecoy_Diagnostics::report('secret-token-123');
    $logged = file_get_contents($log);
    TestRunner::test('operational log requires debug and never accepts arbitrary sensitive data', function () use ($logged) {
        TestRunner::assertTrue(strpos($logged, 'secret-token-123') === false);
        TestRunner::assertSame(WP_DEBUG, strpos($logged, 'WebDecoy: api_error') !== false);
    });
} finally { unlink($log); }
exit(TestRunner::summary());
