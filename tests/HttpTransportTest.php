<?php
/** Run transport stubs in separate processes so other WP emulation stays intact. */
foreach (['vip', 'wordpress'] as $wd_transport_runtime) {
    TestRunner::test('HTTP transport: ' . $wd_transport_runtime, function () use ($wd_transport_runtime) {
        $output = [];
        $status = 0;
        exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/vip/http-transport.php') . ' ' . escapeshellarg($wd_transport_runtime) . ' 2>&1', $output, $status);
        TestRunner::assertSame(0, $status, implode("\n", $output));
    });
}
