<?php

declare(strict_types=1);

/**
 * Tests for SignalCollector::getClientSignals — the visitor fingerprint material
 * forwarded on a server-side detection (the `cs` payload field).
 *
 * This exists because of a real failure. The plugin beacons detections over its
 * own HTTP connection, so the ingest service sees THIS SITE's request headers on
 * the beacon rather than the visitor's, and it was composing the visitor's
 * network identity from those. They are identical on every beacon a site sends,
 * so every visitor a site ever reported collapsed into one shared "actor" — in
 * production one such identity reached 500+ addresses and 88 unrelated user
 * agents before anyone noticed.
 *
 * Two properties matter and are both pinned below: the material must actually
 * distinguish visitors, and it must carry no header VALUES beyond the two the
 * server's fingerprint reads. A plugin that shipped its visitors' cookies to us
 * would be a far worse bug than the one it fixes.
 *
 * Run: php tests/run.php
 */

require_once dirname(__DIR__) . '/sdk/src/SignalCollector.php';

$t = ['TestRunner', 'test'];
$same = ['TestRunner', 'assertSame'];
$true = ['TestRunner', 'assertTrue'];

/** Collect signals for a given $_SERVER, restoring it afterwards. */
function wd_signals_for(array $server): array
{
    $saved = $_SERVER;
    $_SERVER = $server;
    try {
        return (new \WebDecoy\SignalCollector())->getClientSignals();
    } finally {
        $_SERVER = $saved;
    }
}

echo "\nClient signals: what is forwarded\n";

$t('header names are lowercased and sorted', function () use ($same) {
    $cs = wd_signals_for([
        'HTTP_USER_AGENT' => 'Mozilla/5.0 (compatible; Googlebot/2.1)',
        'HTTP_ACCEPT' => '*/*',
        'HTTP_FROM' => 'googlebot(at)googlebot.com',
    ]);
    $same(['accept', 'from', 'user-agent'], $cs['hn'], 'names normalized and ordered');
});

$t('the two values the network identity reads are sent', function () use ($same) {
    $cs = wd_signals_for([
        'HTTP_ACCEPT_LANGUAGE' => 'en-US,en;q=0.9',
        'HTTP_ACCEPT_ENCODING' => 'gzip, br',
    ]);
    $same('en-US,en;q=0.9', $cs['al'], 'accept-language value');
    $same('gzip, br', $cs['ae'], 'accept-encoding value');
});

$t('absent values are empty strings, not missing keys', function () use ($same) {
    $cs = wd_signals_for(['HTTP_USER_AGENT' => 'curl/8.4.0']);
    $same('', $cs['al'], 'accept-language absent');
    $same('', $cs['ae'], 'accept-encoding absent');
});

echo "\nClient signals: what is NOT forwarded\n";

$t('no header values leave the site beyond those two', function () use ($true) {
    $cs = wd_signals_for([
        'HTTP_USER_AGENT' => 'Mozilla/5.0',
        'HTTP_COOKIE' => 'wordpress_logged_in_abc=admin|SECRET-SESSION-TOKEN',
        'HTTP_AUTHORIZATION' => 'Bearer SK-LIVE-PRIVATE',
        'HTTP_X_WP_NONCE' => 'PRIVATE-NONCE',
    ]);
    // Serialize the whole payload so this catches a value smuggled in under any
    // key, not only the ones this test thought to look at.
    $wire = json_encode($cs);
    $true(strpos($wire, 'SECRET-SESSION-TOKEN') === false, 'cookie value not forwarded');
    $true(strpos($wire, 'SK-LIVE-PRIVATE') === false, 'authorization value not forwarded');
    $true(strpos($wire, 'PRIVATE-NONCE') === false, 'nonce value not forwarded');
});

$t('sensitive header NAMES are kept — the name set is the entropy', function () use ($true) {
    $cs = wd_signals_for([
        'HTTP_USER_AGENT' => 'Mozilla/5.0',
        'HTTP_COOKIE' => 'a=b',
        'HTTP_AUTHORIZATION' => 'Bearer x',
    ]);
    $true(in_array('cookie', $cs['hn'], true), 'cookie name retained');
    $true(in_array('authorization', $cs['hn'], true), 'authorization name retained');
});

$t('proxy and CDN header names are excluded', function () use ($same) {
    // Constant for every request through that infrastructure, so they carry no
    // information — but including them would make the same visitor fingerprint
    // differently here than at the edge, splitting one actor in two.
    $cs = wd_signals_for([
        'HTTP_USER_AGENT' => 'curl/8.4.0',
        'HTTP_CF_CONNECTING_IP' => '66.249.66.1',
        'HTTP_CF_RAY' => '8f2a-IAD',
        'HTTP_X_FORWARDED_FOR' => '66.249.66.1',
        'HTTP_X_FORWARDED_PROTO' => 'https',
        'HTTP_TRUE_CLIENT_IP' => '66.249.66.1',
        'HTTP_CDN_LOOP' => 'cloudflare',
        'HTTP_X_VERCEL_ID' => 'iad1',
        'REMOTE_ADDR' => '10.0.0.1',
    ]);
    $same(['user-agent'], $cs['hn'], 'only the visitor\'s own header names remain');
});

echo "\nClient signals: does it actually distinguish visitors\n";

$t('two different clients produce different material', function () use ($true) {
    $googlebot = wd_signals_for([
        'HTTP_USER_AGENT' => 'Mozilla/5.0 (compatible; Googlebot/2.1)',
        'HTTP_ACCEPT' => '*/*',
        'HTTP_FROM' => 'googlebot(at)googlebot.com',
        'HTTP_ACCEPT_ENCODING' => 'gzip, deflate, br',
    ]);
    $amazonbot = wd_signals_for([
        'HTTP_USER_AGENT' => 'Mozilla/5.0 (compatible; Amazonbot/0.1)',
        'HTTP_ACCEPT' => '*/*',
        'HTTP_ACCEPT_LANGUAGE' => 'en-US,en;q=0.5',
        'HTTP_ACCEPT_ENCODING' => 'gzip',
    ]);
    $true($googlebot !== $amazonbot, 'distinct clients must not share fingerprint material');
});

$t('the same client is stable across requests', function () use ($same) {
    $server = [
        'HTTP_USER_AGENT' => 'Mozilla/5.0 (compatible; Googlebot/2.1)',
        'HTTP_ACCEPT' => '*/*',
        'HTTP_ACCEPT_ENCODING' => 'gzip',
    ];
    $same(wd_signals_for($server), wd_signals_for($server), 'identical requests fingerprint alike');
});

echo "\nClient signals: the wire contract\n";

$t('keys match what the ingest service reads', function () use ($same, $true) {
    // Matched by name across a repository boundary — the Go side decodes `hn`,
    // `al` and `ae`, so a rename here is silent data loss, not a build error.
    $cs = wd_signals_for(['HTTP_USER_AGENT' => 'curl/8.4.0']);
    $keys = array_keys($cs);
    sort($keys);
    $same(['ae', 'al', 'hn'], $keys, 'wire keys are hn/al/ae');
    $true(is_array($cs['hn']), 'hn is a list');
});
