<?php
foreach ([['robots-purge.php', 'modern'], ['robots-purge.php', 'legacy'], ['analytics-cache.php'], ['diagnostics.php', 'debug'], ['diagnostics.php', 'production']] as $wd_vip_fixture) {
    TestRunner::test('VIP regression: ' . implode(' ', $wd_vip_fixture), function () use ($wd_vip_fixture) {
        $command = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/vip/' . array_shift($wd_vip_fixture));
        foreach ($wd_vip_fixture as $argument) { $command .= ' ' . escapeshellarg($argument); }
        $output = []; $status = 0;
        exec($command . ' 2>&1', $output, $status);
        TestRunner::assertSame(0, $status, implode("\n", $output));
    });
}
