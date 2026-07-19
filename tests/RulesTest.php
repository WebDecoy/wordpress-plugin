<?php

declare(strict_types=1);

/**
 * Parity tests for the PHP rule engine + tripwire rule.
 *
 * These mirror @webdecoy/node's rule-engine.test.ts and tripwire-rule.test.ts
 * so an expression means the same thing in both SDKs. Run: php tests/run.php
 */

use WebDecoy\Rules\RuleContext;
use WebDecoy\Rules\RuleEngine;
use WebDecoy\Rules\RuleInterface;
use WebDecoy\Rules\RuleResult;
use WebDecoy\Rules\TripwireRule;

/** A stub rule that always returns a fixed result (mirrors node's fixedRule). */
final class FixedRule implements RuleInterface
{
    /** @var RuleResult */
    private $result;

    public function __construct(RuleResult $result)
    {
        $this->result = $result;
    }

    public function getName(): string
    {
        return $this->result->rule;
    }

    public function evaluate(RuleContext $context): RuleResult
    {
        return $this->result;
    }
}

function ctx_cookie(?string $cookie = null): RuleContext
{
    return new RuleContext(
        '203.0.113.5',
        '/wp-admin.php',
        'GET',
        '',
        $cookie !== null ? ['cookie' => $cookie] : [],
        1700000000000
    );
}

function ctx_path(string $path): RuleContext
{
    return new RuleContext('203.0.113.10', $path, 'GET', '', [], 1700000000000);
}

$t = ['TestRunner', 'test'];
$eq = ['TestRunner', 'assertSame'];
$true = ['TestRunner', 'assertTrue'];
$null = ['TestRunner', 'assertNull'];
$match = ['TestRunner', 'assertMatches'];

echo "RuleEngine clearance forwarding (#136)\n";

$t('attaches the wd_clearance token to a tripwire violation', function () use ($eq) {
    $engine = new RuleEngine([new FixedRule(new RuleResult(RuleResult::DENY, 'tripwire', 'honeypot path'))]);
    $res = $engine->evaluate(ctx_cookie('foo=1; wd_clearance=TOK123; bar=2'));
    $eq('tripwire', $res->violations[0]->rule);
    $eq('TOK123', $res->violations[0]->clearance);
});

$t('does NOT attach clearance to non-tripwire rules', function () use ($eq, $null) {
    $engine = new RuleEngine([new FixedRule(new RuleResult(RuleResult::DENY, 'filter', 'ip.tor'))]);
    $res = $engine->evaluate(ctx_cookie('wd_clearance=TOK123'));
    $eq('filter', $res->violations[0]->rule);
    $null($res->violations[0]->clearance);
});

$t('leaves clearance null for a tripwire when there is no cookie', function () use ($null) {
    $engine = new RuleEngine([new FixedRule(new RuleResult(RuleResult::DENY, 'tripwire', 'honeypot path'))]);
    $res = $engine->evaluate(ctx_cookie());
    $null($res->violations[0]->clearance);
});

$t('leaves clearance null when the cookie has no wd_clearance', function () use ($null) {
    $engine = new RuleEngine([new FixedRule(new RuleResult(RuleResult::DENY, 'tripwire', 'honeypot path'))]);
    $res = $engine->evaluate(ctx_cookie('session=abc; theme=dark'));
    $null($res->violations[0]->clearance);
});

echo "\nRuleEngine ordering & dry-run semantics\n";

$t('first non-dry-run DENY wins; dry-run records but does not decide', function () use ($eq, $true) {
    $engine = new RuleEngine([
        new FixedRule(new RuleResult(RuleResult::DENY, 'dry', 'logged', ['dryRun' => true])),
        new FixedRule(new RuleResult(RuleResult::DENY, 'real', 'blocked')),
    ]);
    $res = $engine->evaluate(ctx_path('/x'));
    $eq('real', $res->rule, 'deciding rule');
    $eq(2, count($res->violations), 'both violations recorded');
    $true($res->violations[0]->dryRun, 'first violation marked dry-run');
});

$t('all-ALLOW yields ALLOW with no violations', function () use ($eq, $true) {
    $engine = new RuleEngine([new FixedRule(RuleResult::allow('noop'))]);
    $res = $engine->evaluate(ctx_path('/'));
    $true($res->isAllowed(), 'engine allows');
    $eq(0, count($res->violations));
});

$t('THROTTLE metadata (retryAfter) is preserved on the result', function () use ($eq) {
    $engine = new RuleEngine([new FixedRule(new RuleResult(RuleResult::THROTTLE, 'ratelimit', 'slow down', ['retryAfter' => 30]))]);
    $res = $engine->evaluate(ctx_path('/'));
    $eq(RuleResult::THROTTLE, $res->action);
    $eq(30, $res->metadata['retryAfter']);
});

echo "\nTripwireRule\n";

$t('DENYs built-in scanner-bait paths', function () use ($eq, $true) {
    $rule = new TripwireRule();
    foreach (['/.env', '/.git/config', '/wp-config.php'] as $p) {
        $eq(RuleResult::DENY, $rule->evaluate(ctx_path($p))->action, $p);
    }
    $true(count(TripwireRule::DEFAULT_TRIPWIRE_PATHS) > 5);
});

$t('ALLOWs normal application paths', function () use ($eq) {
    $rule = new TripwireRule();
    foreach (['/', '/products', '/api/users', '/about'] as $p) {
        $eq(RuleResult::ALLOW, $rule->evaluate(ctx_path($p))->action, $p);
    }
});

$t('DENYs a registered honeytoken path and reports confidence 100', function () use ($eq, $match) {
    $rule = new TripwireRule(['paths' => ['/__wd/abc123']]);
    $res = $rule->evaluate(ctx_path('/__wd/abc123'));
    $eq(RuleResult::DENY, $res->action);
    $eq(100, $res->metadata['confidence']);
    $match('/Tripwire hit/', $res->reason);
});

$t('strips query string and fragment before matching', function () use ($eq) {
    $rule = new TripwireRule();
    $eq(RuleResult::DENY, $rule->evaluate(ctx_path('/.env?foo=bar'))->action);
    $eq(RuleResult::DENY, $rule->evaluate(ctx_path('/.git/config#x'))->action);
});

$t('respects includeDefaults: false', function () use ($eq) {
    $rule = new TripwireRule(['paths' => ['/trap'], 'includeDefaults' => false]);
    $eq(RuleResult::ALLOW, $rule->evaluate(ctx_path('/.env'))->action);
    $eq(RuleResult::DENY, $rule->evaluate(ctx_path('/trap'))->action);
});

$t('supports prefixes and patterns', function () use ($eq) {
    $rule = new TripwireRule([
        'prefixes' => ['/.git/'],
        'patterns' => ['/admin-backup'],
        'includeDefaults' => false,
    ]);
    $eq(RuleResult::DENY, $rule->evaluate(ctx_path('/.git/anything/deep'))->action);
    $eq(RuleResult::DENY, $rule->evaluate(ctx_path('/admin-backup.zip'))->action);
    $eq(RuleResult::ALLOW, $rule->evaluate(ctx_path('/git-guide'))->action);
});

$t('dryRun logs but does not block', function () use ($eq, $true, $match) {
    $rule = new TripwireRule(['dryRun' => true]);
    $res = $rule->evaluate(ctx_path('/.env'));
    $eq(RuleResult::ALLOW, $res->action);
    $true($res->metadata['dryRun']);
    $match('/Tripwire hit/', $res->reason);
});

$t('invalid regex pattern fails open (no match, no throw)', function () use ($eq) {
    // An unbalanced group would throw if not guarded.
    $rule = new TripwireRule(['patterns' => ['('], 'includeDefaults' => false]);
    $eq(RuleResult::ALLOW, $rule->evaluate(ctx_path('/anything'))->action);
});

echo "\ntripwire through the RuleEngine\n";

$t('a honeytoken hit produces a DENY + a recorded violation', function () use ($eq, $true) {
    $engine = new RuleEngine([new TripwireRule(['paths' => ['/__wd/deadbeef'], 'includeDefaults' => false])]);

    $allow = $engine->evaluate(ctx_path('/products'));
    $eq(RuleResult::ALLOW, $allow->action);
    $eq(0, count($allow->violations));

    $deny = $engine->evaluate(ctx_path('/__wd/deadbeef'));
    $eq(RuleResult::DENY, $deny->action);
    $eq('tripwire', $deny->rule);
    $true(count($deny->violations) > 0);
});

echo "\nViolationEvent wire format\n";

$t('toApiPayload matches the ingest ViolationEventRequest shape', function () use ($eq, $true) {
    $engine = new RuleEngine([new TripwireRule(['includeDefaults' => true])]);
    $res = $engine->evaluate(ctx_cookie('wd_clearance=ABC') );
    // ctx_cookie path is /wp-admin.php which is not a default tripwire; craft one:
    $ctx = new RuleContext('9.9.9.9', '/.env', 'GET', 'curl/8', ['cookie' => 'wd_clearance=ABC'], 1700000000000);
    $res = $engine->evaluate($ctx);
    $payload = $res->violations[0]->toApiPayload();
    $eq('tripwire', $payload['rule']);
    $eq('DENY', $payload['action']);
    $eq('9.9.9.9', $payload['ip']);
    $eq('/.env', $payload['path']);
    $eq('ABC', $payload['clearance']);
    $eq(false, $payload['dryRun']);
    $eq('2023-11-14T22:13:20.000Z', $payload['timestamp'], 'ISO ms timestamp');
    $true(isset($payload['metadata']['confidence']));
});
