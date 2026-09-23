<?php

declare(strict_types=1);

/**
 * The protected-path rule is one rule (#995).
 *
 * WebDecoy/app pkg/models/testdata/route_resolution_vectors.json is replayed
 * by Go, the Cloudflare Worker, the Lambda and now this plugin. A vector that
 * fails here means the plugin would refuse a crawler on a path the dashboard
 * says it does not, or the reverse. Copy the file verbatim when it changes.
 *
 * Run: php tests/run.php
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/');
}
require_once dirname(__DIR__) . '/sdk/src/RouteResolution.php';

$t = ['TestRunner', 'test'];
$same = ['TestRunner', 'assertSame'];

$vectors = json_decode((string) file_get_contents(__DIR__ . '/vectors/route_resolution_vectors.json'), true);
if (!is_array($vectors) || empty($vectors['cases'])) {
    throw new \RuntimeException('no route resolution vectors');
}

foreach ($vectors['cases'] as $case) {
    $t('route resolution: ' . $case['name'], function () use ($case, $same) {
        $got = \WebDecoy\RouteResolution::resolve(
            (string) $case['path'],
            (array) $case['rules'],
            (string) ($case['site_mode'] ?? 'enforce')
        );
        $want = $case['want'];
        // Compare field by field so a failure names what drifted.
        foreach (['covering', 'deciding_mode', 'attributed', 'required_trust', 'requirement_source', 'excepted_by', 'refused_behaviors'] as $field) {
            $same($got[$field], $want[$field], $field);
        }
        $same(count($got['previews']), count($want['previews']), 'preview count');
        foreach ($want['previews'] as $i => $p) {
            $same($got['previews'][$i]['pattern'], $p['pattern'], "preview $i pattern");
            $same($got['previews'][$i]['required_trust'], $p['required_trust'], "preview $i required_trust");
            $same($got['previews'][$i]['refused_behaviors'] ?? null, $p['refused_behaviors'] ?? null, "preview $i refused_behaviors");
        }
    });
}

$t('rules are read from a validator config as the Worker reads them', function () use ($same) {
    $config = [
        'routes' => ['/premium/*', '/login'],
        'route_min_trust' => [['pattern' => '/login', 'min_trust' => 'human-likely']],
        'route_exceptions' => [['pattern' => '/premium/*', 'except' => ['/premium/free/*']]],
        'monitor_routes' => [['pattern' => '/blog/*', 'min_trust' => '', 'except' => []]],
        'route_refusals' => [
            ['pattern' => '/premium/*', 'mode' => '', 'refuse_behaviors' => ['training']],
            ['pattern' => '/blog/*', 'mode' => 'monitor', 'refuse_behaviors' => ['training', 'search']],
            ['pattern' => '/ghost/*', 'mode' => '', 'refuse_behaviors' => ['training']],
        ],
    ];
    $rules = \WebDecoy\RouteResolution::rulesFromConfig($config);
    $r = \WebDecoy\RouteResolution::resolve('/premium/a', $rules, 'enforce');
    $same($r['refused_behaviors'], ['training']);
    $same($r['deciding_mode'], 'enforce');
    $same(\WebDecoy\RouteResolution::resolve('/premium/free/x', $rules, 'enforce')['excepted_by'], '/premium/*');
    // A watched path refuses nothing, in either site mode.
    $b = \WebDecoy\RouteResolution::resolve('/blog/x', $rules, 'enforce');
    $same($b['deciding_mode'], 'monitor');
    $same($b['refused_behaviors'], ['search', 'training']);
    // A refusal whose pattern is not a served route is ignored, as the Worker ignores it.
    $same(\WebDecoy\RouteResolution::resolve('/ghost/x', $rules, 'enforce')['covering'], []);
});
