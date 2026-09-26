<?php

declare(strict_types=1);

/**
 * The plugin constructor runs when webdecoy.php is included, before
 * plugins_loaded. The classes load_includes() requires do not exist yet at that
 * point, so the code the constructor runs may name them only as callbacks
 * (Foo::class, or inside a method hooked for later), never call them.
 *
 * 2.10.0 called WebDecoy_AI_Referrals::register() from init_hooks() and failed
 * with "Class not found" on every request.
 *
 * Run: php tests/run.php
 */

$t = ['TestRunner', 'test'];
$true = ['TestRunner', 'assertTrue'];

/** Body of a WebDecoy_Plugin method, from its signature to its closing brace. */
function webdecoy_boot_method_body(string $src, string $name): string
{
    if (preg_match('/function\s+' . $name . '\s*\([^)]*\)[^{]*\{/', $src, $m, PREG_OFFSET_CAPTURE) !== 1) {
        throw new \RuntimeException("method {$name} not found in webdecoy.php");
    }
    $i = $m[0][1] + strlen($m[0][0]);
    for ($depth = 1, $n = strlen($src); $i < $n && $depth > 0; $i++) {
        $depth += $src[$i] === '{' ? 1 : ($src[$i] === '}' ? -1 : 0);
    }
    return substr($src, $m[0][1], $i - $m[0][1]);
}

$t('construction never uses a class load_includes() loads later', function () use ($true) {
    $root = dirname(__DIR__);
    $src = (string) file_get_contents($root . '/webdecoy.php');

    // Classes declared by the files load_includes() requires.
    $deferred = [];
    preg_match_all("/'(includes\\/[a-z0-9-]+\\.php)'/", webdecoy_boot_method_body($src, 'load_includes'), $files);
    foreach ($files[1] as $file) {
        if (preg_match('/^\s*(?:final\s+)?class\s+(\w+)/m', (string) file_get_contents($root . '/' . $file), $c) === 1) {
            $deferred[] = $c[1];
        }
    }
    $true(in_array('WebDecoy_AI_Referrals', $deferred, true), 'load_includes() class list was not parsed');

    foreach (['__construct', 'load_options', 'init_hooks'] as $method) {
        $body = webdecoy_boot_method_body($src, $method);
        foreach ($deferred as $class) {
            $uses = preg_match('/\bnew\s+' . $class . '\b|\b' . $class . '::(?!class\b)/', $body) === 1;
            $true(!$uses, "{$method}() uses {$class}, which is not loaded until plugins_loaded");
        }
    }
});
