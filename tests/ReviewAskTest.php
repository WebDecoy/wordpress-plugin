<?php

declare(strict_types=1);

/**
 * Tests for the pure helpers in WebDecoy_Review_Ask: when the review ask is
 * due, what each choice stores, and the copy built on the week's counts.
 *
 * Run: php tests/run.php
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/');
}
require_once dirname(__DIR__) . '/includes/class-webdecoy-review-ask.php';

$t = ['TestRunner', 'test'];
$true = ['TestRunner', 'assertTrue'];
$same = ['TestRunner', 'assertSame'];

$now = 20000000;
$week = WebDecoy_Review_Ask::WAIT;

echo "\nReview ask: when it is due\n";

$t('not before a week on the site, and never without a first-seen time', function () use ($true, $now, $week) {
    $true(WebDecoy_Review_Ask::is_due(0, $now, '', 50) === false, 'no first-seen -> not due');
    $true(WebDecoy_Review_Ask::is_due($now - $week + 1, $now, '', 50) === false, 'just under a week -> not due');
    $true(WebDecoy_Review_Ask::is_due($now - $week, $now, '', 50) === true, 'a week with bots counted -> due');
});

$t('never on a site that counted nothing this week', function () use ($true, $now, $week) {
    $true(WebDecoy_Review_Ask::is_due($now - 2 * $week, $now, '', 0) === false, 'zero visits -> not due');
});

$t('an answer silences it; a snooze holds until it ends', function () use ($true, $now, $week) {
    $first = $now - 2 * $week;
    $true(WebDecoy_Review_Ask::is_due($first, $now, 'done', 50) === false, 'reviewed -> never again');
    $true(WebDecoy_Review_Ask::is_due($first, $now, 'never', 50) === false, "don't ask again -> never again");
    $true(WebDecoy_Review_Ask::is_due($first, $now, 'later:' . ($now + 1), 50) === false, 'inside the snooze -> not due');
    $true(WebDecoy_Review_Ask::is_due($first, $now, 'later:' . $now, 50) === true, 'snooze ended -> due');
});

echo "\nReview ask: choices\n";

$t('each choice stores its state, and anything else snoozes', function () use ($same, $now) {
    $same('done', WebDecoy_Review_Ask::state_for('done', $now));
    $same('never', WebDecoy_Review_Ask::state_for('never', $now));
    $same('later:' . ($now + WebDecoy_Review_Ask::SNOOZE), WebDecoy_Review_Ask::state_for('later', $now));
    $same('later:' . ($now + WebDecoy_Review_Ask::SNOOZE), WebDecoy_Review_Ask::state_for('bogus', $now));
});

echo "\nReview ask: copy\n";

$t('names the week\'s count, and the AI share when there is one', function () use ($true) {
    $with = WebDecoy_Review_Ask::message(1234, 56);
    $true(strpos($with, '1,234 bot visits') !== false && strpos($with, '56 of them from AI') !== false, $with);
    $without = WebDecoy_Review_Ask::message(12, 0);
    $true(strpos($without, '12 bot visits') !== false && strpos($without, 'AI') === false, $without);
    $true(strpos($with . $without, '—') === false, 'no em-dashes in customer copy');
});
