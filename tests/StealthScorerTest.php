<?php

declare(strict_types=1);

/**
 * Tests for the stealth (F1) scoring added to WebDecoy_Behavioral_Scorer.
 *
 * Verifies the strong/weak curve mirrors @webdecoy/node's, that stealth is a
 * decisive max()-override (not diluted by the weighted model), and — critically
 * — that it is false-positive-safe: no lies, or a single weak (privacy-extension)
 * patch, must never push a legitimate visitor toward a block.
 *
 * Run: php tests/run.php
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/');
}
require_once dirname(__DIR__) . '/includes/class-webdecoy-behavioral-scorer.php';

$t = ['TestRunner', 'test'];
$true = ['TestRunner', 'assertTrue'];

function stealth_score(array $lies): float
{
    $scorer = new WebDecoy_Behavioral_Scorer();
    $res = $scorer->score(['lies' => $lies]);
    return $res['category_scores']['stealth'];
}

function final_score(array $signals): float
{
    $scorer = new WebDecoy_Behavioral_Scorer();
    $res = $scorer->score($signals);
    return $res['score'];
}

echo "\nStealth (F1) scoring\n";

$t('no lie data -> stealth 0, no false positive', function () use ($true) {
    $true(stealth_score([]) === 0.0, 'empty lies = 0');
    // A session with no behavioral data at all must not be pushed up by stealth.
    $true(final_score([]) < 0.5, 'empty session stays low');
});

$t('one strong tell is decisive (>= 0.7)', function () use ($true) {
    $s = stealth_score(['strong' => ['Function.prototype.toString'], 'weak' => []]);
    $true($s >= 0.7 && $s <= 0.75, 'single strong ~0.7 (got ' . $s . ')');
});

$t('additional strong tells increase the score toward the cap', function () use ($true) {
    $two = stealth_score(['strong' => ['a', 'b'], 'weak' => []]);
    $three = stealth_score(['strong' => ['a', 'b', 'c'], 'weak' => []]);
    $true($two > 0.8 && $two <= 0.85, 'two strong ~0.82');
    $true($three > $two, 'monotonic increase');
    $true(stealth_score(['strong' => array_fill(0, 10, 'x'), 'weak' => []]) <= 0.97, 'capped at 0.97');
});

$t('one strong tell overrides a low behavioral score (max, not diluted)', function () use ($true) {
    // Even with otherwise-human-looking (empty) behavior, a strong lie decides.
    $final = final_score(['lies' => ['strong' => ['navigator.webdriver getter'], 'weak' => []]]);
    $true($final >= 0.7, 'strong lie makes the final score decisive (got ' . $final . ')');
});

$t('FALSE-POSITIVE SAFETY: a single weak patch is never decisive', function () use ($true) {
    $s = stealth_score(['strong' => [], 'weak' => ['HTMLCanvasElement.toDataURL']]);
    $true($s === 0.0, 'one weak tell (e.g. a canvas-blocker extension) scores 0');
    $final = final_score(['lies' => ['strong' => [], 'weak' => ['HTMLCanvasElement.toDataURL']]]);
    $true($final < 0.5, 'a privacy-extension user is never blocked by stealth alone');
});

$t('multiple weak patches are suspicious but still not decisive', function () use ($true) {
    $s = stealth_score(['strong' => [], 'weak' => ['a', 'b', 'c']]);
    $true($s > 0.0 && $s < 0.6, 'multiple weak tells score modestly (<0.6), never auto-block (got ' . $s . ')');
});
