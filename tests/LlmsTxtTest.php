<?php

declare(strict_types=1);

/**
 * llms.txt generator.
 *
 * The behaviour tests run in their own process (tests/llms/llms-txt.php):
 * they stand in for get_posts(), transients and post meta, and those stubs
 * must not meet the other tests' versions of the same functions.
 *
 * The guards below read source: there is one place that builds the llms.txt
 * body and one physical-file check, and they stay that way.
 *
 * Run: php tests/run.php
 */

echo "\nllms.txt generator\n";

TestRunner::test('llms.txt behaviour (separate process)', function () {
    $output = [];
    $status = 0;
    exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/llms/llms-txt.php') . ' 2>&1', $output, $status);
    foreach ($output as $line) {
        if ($line !== '' && strpos($line, ' passed, ') === false) {
            echo '  ' . $line . "\n";
        }
    }
    TestRunner::assertSame(0, $status, implode("\n", $output));
});

/**
 * Every plugin PHP file outside tests, vendor and the generator itself.
 *
 * @return array<string,string> relative path => source
 */
function llms_guard_sources(): array
{
    $root = dirname(__DIR__);
    $files = array_merge(
        [$root . '/webdecoy.php', $root . '/uninstall.php'],
        glob($root . '/includes/*.php') ?: [],
        glob($root . '/admin/partials/*.php') ?: [],
        glob($root . '/public/*.php') ?: [],
        glob($root . '/templates/*.php') ?: []
    );
    $out = [];
    foreach ($files as $file) {
        $relative = substr($file, strlen($root) + 1);
        if ($relative !== 'includes/class-webdecoy-llms-txt.php') {
            $out[$relative] = (string) file_get_contents($file);
        }
    }
    return $out;
}

TestRunner::test('guard: only WebDecoy_Llms_Txt::body() produces llms.txt text', function () {
    foreach (llms_guard_sources() as $file => $source) {
        TestRunner::assertTrue(strpos($source, 'WebDecoy_Llms_Txt::build(') === false, $file . ' builds llms.txt itself; read WebDecoy_Llms_Txt::body()');
        TestRunner::assertTrue(preg_match('/llms(-full)?\\.txt[^\\n]*(add_rewrite_rule|header\\()|(add_rewrite_rule|header\\()[^\\n]*llms/', $source) !== 1, $file . ' routes or answers llms.txt outside the generator');
    }
    $generator = (string) file_get_contents(dirname(__DIR__) . '/includes/class-webdecoy-llms-txt.php');
    TestRunner::assertSame(1, substr_count($generator, 'self::build('), 'body() is the only caller of build()');
    TestRunner::assertTrue(strpos($generator, 'add_rewrite_rule') === false, 'no rewrite rule: nothing for an owner to flush');
});

TestRunner::test('guard: the settings preview and the response read the same body()', function () {
    $settings = (string) file_get_contents(dirname(__DIR__) . '/admin/partials/settings-page.php');
    TestRunner::assertTrue(strpos($settings, 'WebDecoy_Llms_Txt::body()') !== false, 'the preview must show body()');
    $generator = (string) file_get_contents(dirname(__DIR__) . '/includes/class-webdecoy-llms-txt.php');
    TestRunner::assertTrue(strpos($generator, 'self::send(self::body())') !== false, 'the response must send body()');
});

TestRunner::test('guard: one physical-file check, shared with robots.txt', function () {
    $generator = (string) file_get_contents(dirname(__DIR__) . '/includes/class-webdecoy-llms-txt.php');
    TestRunner::assertTrue(strpos($generator, 'is_file(') === false && strpos($generator, 'file_exists(') === false, 'the generator must ask WebDecoy_Robots_Txt::physical_file()');
    TestRunner::assertTrue(strpos($generator, 'WebDecoy_Robots_Txt::physical_file($roots, self::FILE)') !== false);
});
