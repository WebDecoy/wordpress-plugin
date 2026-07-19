<?php

declare(strict_types=1);

/**
 * Tests for WebDecoy_Honeytoken (F4 hidden-link injection).
 *
 * Self-contained: defines the handful of WordPress functions the class touches
 * (guarded so they don't collide with other tests or a real WP runtime), then
 * exercises token derivation, the hidden-link markup, rotation, and that a
 * honeytoken path actually trips a tripwire. Run: php tests/run.php
 */

use WebDecoy\Rules\RuleContext;
use WebDecoy\Rules\RuleEngine;
use WebDecoy\Rules\RuleResult;
use WebDecoy\Rules\TripwireRule;

if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/');
}
if (!defined('DAY_IN_SECONDS')) {
    define('DAY_IN_SECONDS', 86400);
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
if (!function_exists('add_option')) {
    function add_option($k, $v, $a = '', $b = 'yes')
    {
        $GLOBALS['__wd_opts'][$k] = $v;
        return true;
    }
}
if (!function_exists('esc_attr')) {
    function esc_attr($s)
    {
        return htmlspecialchars((string) $s, ENT_QUOTES);
    }
}

require_once dirname(__DIR__) . '/includes/class-webdecoy-honeytoken.php';

$t = ['TestRunner', 'test'];
$eq = ['TestRunner', 'assertSame'];
$true = ['TestRunner', 'assertTrue'];

echo "\nWebDecoy_Honeytoken\n";

$t('derives a stable /__wd/{12-hex} path from the per-site secret', function () use ($eq, $true) {
    $h = new WebDecoy_Honeytoken(false);
    $p = $h->primary_path();
    $true(strpos($p, '/__wd/') === 0, 'under /__wd/');
    $eq(strlen('/__wd/') + 12, strlen($p), '12-hex token');
    $eq($p, $h->primary_path(), 'deterministic across calls');
    $eq($p, (new WebDecoy_Honeytoken(false))->primary_path(), 'stable across instances (same secret)');
});

$t('stable mode arms exactly the advertised path', function () use ($eq) {
    $h = new WebDecoy_Honeytoken(false);
    $paths = $h->active_paths();
    $eq(1, count($paths));
    $eq($h->primary_path(), $paths[0]);
});

$t('persists an unguessable secret to options', function () use ($true) {
    (new WebDecoy_Honeytoken(false))->primary_path();
    $secret = $GLOBALS['__wd_opts']['webdecoy_honeytoken_secret'] ?? '';
    $true(is_string($secret) && strlen($secret) >= 16, 'secret stored');
});

$t('hidden link matches the node hiding technique', function () use ($true) {
    $h = new WebDecoy_Honeytoken(false);
    $link = $h->render_link();
    $true(strpos($link, 'href="' . $h->primary_path() . '"') !== false, 'href = primary path');
    $true(strpos($link, 'aria-hidden="true"') !== false, 'aria-hidden');
    $true(strpos($link, 'tabindex="-1"') !== false, 'tabindex -1');
    $true(strpos($link, 'rel="nofollow noindex"') !== false, 'nofollow noindex');
    $true(strpos($link, 'position:absolute;left:-9999px') !== false, 'offscreen');
});

$t('rotation arms today + yesterday and differs from stable', function () use ($eq, $true) {
    $r = new WebDecoy_Honeytoken(true);
    $paths = $r->active_paths();
    $eq(2, count($paths), 'today + yesterday grace window');
    $true(in_array($r->primary_path(), $paths, true), 'today is armed');
    $true($r->primary_path() !== (new WebDecoy_Honeytoken(false))->primary_path(), 'rotating != stable');
});

$t('a honeytoken path trips a tripwire; normal pages pass', function () use ($eq) {
    $h = new WebDecoy_Honeytoken(false);
    $engine = new RuleEngine([new TripwireRule(['paths' => $h->active_paths(), 'includeDefaults' => false])]);
    $hit = $engine->evaluate(new RuleContext('9.9.9.9', $h->primary_path(), 'GET', 'scrapy', [], 1700000000000));
    $eq(RuleResult::DENY, $hit->action);
    $eq('tripwire', $hit->rule);
    $miss = $engine->evaluate(new RuleContext('9.9.9.9', '/', 'GET', 'human', [], 1700000000000));
    $eq(RuleResult::ALLOW, $miss->action);
});
