<?php

declare(strict_types=1);

/**
 * The Detections list explains a decoy hit with the same words the WordPress
 * digest email uses (WebDecoy/app#443): the sentence table and the golden
 * vectors are generated from WebDecoy/app's pkg/hitexplain.
 *
 * Run: php tests/run.php
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/');
}
require_once dirname(__DIR__) . '/sdk/src/HitExplanation.php';

use WebDecoy\HitExplanation;
use WebDecoy\Rules\RuleContext;
use WebDecoy\Rules\TripwireRule;

$t = ['TestRunner', 'test'];
// Actual first, expected second, so each line reads as "this is that".
$same = static function ($actual, $expected, string $msg = ''): void {
    TestRunner::assertSame($expected, $actual, $msg);
};

$t('every hit explanation vector matches Go', function () use ($same) {
    $path = dirname(__DIR__) . '/sdk/src/registry/hit-explanation-vectors.generated.json';
    $vectors = json_decode((string) file_get_contents($path), true);
    if (!is_array($vectors) || count($vectors) < 20) {
        throw new \RuntimeException('no hit explanation vectors');
    }
    foreach ($vectors as $v) {
        $h = $v['hit'];
        $label = json_encode($h);
        $same(HitExplanation::classify($h['source'], $h['trap_kind'], $h['path']), $v['kind'], 'kind ' . $label);
        $same(HitExplanation::explain($h['source'], $h['trap_kind'], $h['path']), $v['explanation'], 'sentence ' . $label);
    }
});

$t('invalid UTF-8 in a path counts as not recorded', function () use ($same) {
    $same(HitExplanation::safePath("/bad\xff\xfe"), '');
    $same(
        HitExplanation::explain('sdk_tripwire', 'trap_path', "/bad\xff\xfe"),
        'A visitor requested a path set up as a trap on your site. The path was not recorded.'
    );
});

$t('a local tripwire row is explained from its stored flags', function () use ($same) {
    $row = json_encode([
        'flags' => ['tripwire_rule'],
        'metadata' => ['rule' => 'tripwire', 'path' => '/__wd/3f9a2c71b0de', 'trap_kind' => 'hidden_link', 'dry_run' => true],
    ]);
    $same(
        HitExplanation::forLocalFlags($row),
        'A visitor requested /__wd/3f9a2c71b0de, the address of a hidden link on your pages. People can\'t see or click that link.'
    );

    // A row written before the kind was recorded still gets an honest sentence.
    $old = json_encode(['flags' => ['tripwire_rule'], 'metadata' => ['rule' => 'tripwire', 'path' => '/.env']]);
    $same(HitExplanation::forLocalFlags($old), 'A visitor requested /.env, a path set up as a trap on your site.');

    // Not decoy hits: the decoy-served follow-up row, test triggers, heuristic
    // scoring rows, and junk.
    $same(HitExplanation::forLocalFlags(json_encode(['flags' => ['decoy_served'], 'metadata' => ['rule' => 'tripwire', 'decoy_path' => '/.env']])), '');
    $same(HitExplanation::forLocalFlags(json_encode(['flags' => ['test_trigger'], 'metadata' => ['test' => true]])), '');
    $same(HitExplanation::forLocalFlags(json_encode(['headless_browser', 'no_cookies'])), '');
    $same(HitExplanation::forLocalFlags(json_encode(['f' => ['admin_probing']])), '');
    $same(HitExplanation::forLocalFlags(null), '');
    $same(HitExplanation::forLocalFlags('{not json'), '');
});

$t('a tripwire hit records which trap it was', function () use ($same) {
    $hit = static function (TripwireRule $rule, string $path) {
        $result = $rule->evaluate(new RuleContext('203.0.113.9', $path, 'GET'));
        return $result->metadata['trap_kind'] ?? null;
    };
    $defaults = new TripwireRule(['paths' => ['/my-secret-admin']]);
    $same($hit($defaults, '/.env'), 'probe_path');
    $same($hit($defaults, '/.env?x=1'), 'probe_path');
    $same($hit($defaults, '/my-secret-admin'), 'trap_path');

    $honeytoken = new TripwireRule(['paths' => ['/__wd/abc'], 'includeDefaults' => false, 'trapKind' => 'hidden_link']);
    $same($hit($honeytoken, '/__wd/abc'), 'hidden_link');

    $plugins = new TripwireRule(['prefixes' => ['/wp-content/plugins/revslider/'], 'includeDefaults' => false, 'trapKind' => 'fake_plugin']);
    $same($hit($plugins, '/wp-content/plugins/revslider/x.php'), 'fake_plugin');

    // A kind the shared table does not know cannot pick a sentence.
    $bogus = new TripwireRule(['paths' => ['/x'], 'includeDefaults' => false, 'trapKind' => 'decoy_url']);
    $same(HitExplanation::classify('sdk_tripwire', (string) $hit($bogus, '/x'), '/x'), 'trap_path');
});

$t('every trap kind the plugin records is one the shared table knows', function () use ($same) {
    $known = HitExplanation::table()['trap_kinds'];
    $root = dirname(__DIR__);
    $sources = [
        $root . '/webdecoy.php',
        $root . '/includes/class-webdecoy-wp-traps.php',
        $root . '/sdk/src/Rules/TripwireRule.php',
    ];
    $found = 0;
    foreach ($sources as $file) {
        $src = (string) file_get_contents($file);
        preg_match_all("/'trapKind'\\s*=>\\s*'([a-z_]+)'|->record\\('tripwire',[^,]+,\\s*'([a-z_]+)'\\)|TRAP_KIND_[A-Z_]+\\s*=\\s*'([a-z_]+)'/", $src, $m);
        foreach (array_merge($m[1], $m[2], $m[3]) as $kind) {
            if ($kind === '') {
                continue;
            }
            $found++;
            $same(in_array($kind, $known, true), true, basename($file) . ' records unknown trap kind ' . $kind);
        }
    }
    $same($found >= 6, true, 'expected the plugin to record at least six trap kinds, found ' . $found);
});
