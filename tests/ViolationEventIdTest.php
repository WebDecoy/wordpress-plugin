<?php

declare(strict_types=1);

/**
 * Violation event ids (WebDecoy/app#1945).
 *
 * A batch can reach ingest and be saved while its response is lost; the drain
 * then retries it. Ingest stores each event id once per organization, so the
 * retry is harmless only if the resent row carries the id it was given when
 * it was spooled.
 *
 * Run: php tests/run.php
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/');
}
require_once dirname(__DIR__) . '/includes/class-webdecoy-violation-reporter.php';

$t = ['TestRunner', 'test'];
$same = ['TestRunner', 'assertSame'];
$true = ['TestRunner', 'assertTrue'];

echo "\nViolation event ids\n";

$t('a spooled event gets the id it was given', function () use ($same) {
    $payload = WebDecoy_Violation_Reporter::with_event_id(['rule' => 'tripwire'], '0b7d3f3e-5c1a-4c39-9a51-6f2f6a4b8e11');
    $same('0b7d3f3e-5c1a-4c39-9a51-6f2f6a4b8e11', $payload['eventId']);
    $same('tripwire', $payload['rule']);
});

$t('an id already on the payload is never replaced', function () use ($same) {
    $payload = WebDecoy_Violation_Reporter::with_event_id(['eventId' => 'first'], 'second');
    $same('first', $payload['eventId']);
});

$t('the id survives the trip through the spool unchanged', function () use ($same) {
    $stored = json_encode(WebDecoy_Violation_Reporter::with_event_id(['rule' => 'rate_limit'], 'abc'));
    $resent = json_decode($stored, true);
    $same('abc', $resent['eventId'], 'a retry resends the stored payload, id included');
});

$t('report() stamps the id at spool time, not at send time', function () use ($true) {
    $src = (string) file_get_contents(dirname(__DIR__) . '/includes/class-webdecoy-violation-reporter.php');
    $true(
        (bool) preg_match('/\'payload\'\s*=>\s*wp_json_encode\(self::with_event_id\(\$event->toApiPayload\(\),\s*wp_generate_uuid4\(\)\)\)/', $src),
        'the spool insert must carry a generated eventId'
    );
    $true(substr_count($src, 'wp_generate_uuid4(') === 1, 'ids are generated in one place only');
});
