<?php

declare(strict_types=1);

/**
 * Parity tests for the filter expression language (tokenizer → parser →
 * evaluator → FilterRule). Verifies the PHP port matches @webdecoy/node's
 * JavaScript semantics — especially the places PHP would naturally diverge:
 * numeric `===` (1 === 1.0), number-vs-string equality, JS truthiness, and
 * fail-open on undefined operands.
 *
 * Run: php tests/run.php
 */

use WebDecoy\Rules\RuleContext;
use WebDecoy\Rules\RuleResult;
use WebDecoy\Rules\FilterRule;
use WebDecoy\Rules\Filter\Parser;
use WebDecoy\Rules\Filter\Evaluator;
use WebDecoy\Rules\Filter\FilterSyntaxException;

/** Enrichment fixture matching the ingest /enrichment shape. */
function enrichment(): array
{
    return [
        'security' => ['vpn' => true, 'proxy' => false, 'tor' => false, 'relay' => false, 'hosting' => true],
        'location' => ['country' => 'CN', 'country_name' => 'China', 'city' => 'Beijing', 'timezone' => 'Asia/Shanghai'],
        'network' => ['asn' => 4808, 'asn_org' => 'China Unicom'],
        'reputation' => ['abuse_score' => 75, 'total_reports' => 12, 'is_high_risk' => true],
        'categories' => ['scanner'],
    ];
}

function ctx_enriched(string $path = '/wp-login.php', string $method = 'GET', array $headers = []): RuleContext
{
    return new RuleContext('203.0.113.9', $path, $method, 'curl/8', $headers, 1700000000000, enrichment());
}

/** Evaluate an expression to its JS-truthy boolean result. */
function evalExpr(string $expr, RuleContext $ctx): bool
{
    $ast = (new Parser($expr))->parse();
    return Evaluator::isTruthy(Evaluator::evaluate($ast, $ctx));
}

$t = ['TestRunner', 'test'];
$true = ['TestRunner', 'assertTrue'];
$eq = ['TestRunner', 'assertSame'];

echo "\nFilter expression language\n";

// Booleans + or/and
$t('ip.* boolean fields resolve from enrichment.security', function () use ($true) {
    $c = ctx_enriched();
    $true(evalExpr('ip.vpn', $c), 'ip.vpn true');
    $true(!evalExpr('ip.proxy', $c), 'ip.proxy false');
    $true(evalExpr('ip.vpn or ip.tor', $c), 'or');
    $true(!evalExpr('ip.tor or ip.proxy', $c), 'or both false');
    $true(!evalExpr('ip.vpn and ip.tor', $c), 'and one false');
    $true(evalExpr('ip.vpn and ip.hosting', $c), 'and both true');
});

$t('not and parentheses', function () use ($true) {
    $c = ctx_enriched();
    $true(evalExpr('not ip.proxy', $c), 'not false = true');
    $true(!evalExpr('not ip.vpn', $c), 'not true = false');
    $true(!evalExpr('(ip.tor or ip.proxy) and ip.hosting', $c), 'parens group the or');
    $true(evalExpr('(ip.vpn or ip.tor) and ip.hosting', $c), 'parens true');
});

$t('precedence: and binds tighter than or', function () use ($true) {
    $c = ctx_enriched();
    // ip.vpn or (ip.tor and ip.proxy) = true or false = true
    $true(evalExpr('ip.vpn or ip.tor and ip.proxy', $c), 'and before or');
});

// String equality + arrays + in/not in
$t('string equality and array membership', function () use ($true) {
    $c = ctx_enriched();
    $true(evalExpr('ip.country == "CN"', $c), 'eq string');
    $true(!evalExpr('ip.country == "US"', $c), 'neq string');
    $true(evalExpr('ip.country != "US"', $c), '!=');
    $true(evalExpr('ip.country in ["CN","RU"]', $c), 'in');
    $true(!evalExpr('ip.country in ["US","GB"]', $c), 'in false');
    $true(evalExpr('ip.country not in ["US","GB"]', $c), 'not in');
});

// Numeric comparisons + the int/float === parity trap
$t('numeric comparisons and JS-style numeric equality', function () use ($true) {
    $c = ctx_enriched();
    $true(evalExpr('ip.abuse_score > 50', $c), '> ');
    $true(!evalExpr('ip.abuse_score > 90', $c), '> false');
    $true(evalExpr('ip.abuse_score >= 75', $c), '>=');
    $true(evalExpr('ip.abuse_score <= 75', $c), '<=');
    $true(!evalExpr('ip.abuse_score < 75', $c), '<');
    // enrichment asn is int 4808; literal is float 4808 — JS === treats them equal
    $true(evalExpr('ip.asn == 4808', $c), 'int field == float literal (JS numeric ===)');
    // number vs string are never equal in JS
    $true(!evalExpr('ip.asn == "4808"', $c), 'number != string (JS strict types)');
});

// req.* fields + header() + matches
$t('req fields, header() call, and matches', function () use ($true) {
    $c = ctx_enriched('/wp-login.php', 'POST', ['x-requested-with' => 'XMLHttpRequest']);
    $true(evalExpr('req.method == "POST"', $c), 'req.method');
    $true(evalExpr('req.path matches "^/wp-login"', $c), 'matches regex');
    $true(!evalExpr('req.path matches "^/admin"', $c), 'matches no');
    $true(evalExpr('req.header("X-Requested-With") == "XMLHttpRequest"', $c), 'header() case-insensitive');
    $true(!evalExpr('req.path matches "("', $c), 'invalid regex fails open (false, no throw)');
});

// Fail-open when enrichment absent
$t('undefined operands fail open (false), never error', function () use ($true) {
    $bare = new RuleContext('203.0.113.9', '/', 'GET', 'x', [], 1700000000000, null);
    $true(!evalExpr('ip.vpn', $bare), 'ip.* with no enrichment = falsy');
    $true(!evalExpr('ip.abuse_score > 50', $bare), 'comparison with undefined = false');
    $true(!evalExpr('ip.vpn and ip.tor', $bare), 'and with undefined = false');
    $true(!evalExpr('req.header("x-missing") == "y"', $bare), 'missing header = undefined = false');
});

echo "\nFilterRule\n";

$t('parses at construction and fires with configured action', function () use ($eq) {
    $rule = new FilterRule(['expression' => 'ip.abuse_score > 50', 'action' => RuleResult::DENY]);
    $eq(RuleResult::DENY, $rule->evaluate(ctx_enriched())->action);
    $eq(RuleResult::ALLOW, $rule->evaluate(new RuleContext('1.1.1.1', '/', 'GET', 'x', [], 1700000000000, null))->action);
});

$t('dry-run fires as ALLOW but still reports a match reason', function () use ($eq, $true) {
    $rule = new FilterRule(['expression' => 'ip.vpn', 'dryRun' => true]);
    $res = $rule->evaluate(ctx_enriched());
    $eq(RuleResult::ALLOW, $res->action);
    $true(strpos((string) $res->reason, 'Filter matched') === 0, 'reason set');
});

$t('THROTTLE action honored', function () use ($eq) {
    $rule = new FilterRule(['expression' => 'ip.hosting', 'action' => RuleResult::THROTTLE]);
    $eq(RuleResult::THROTTLE, $rule->evaluate(ctx_enriched())->action);
});

$t('needsEnrichment detects ip.* references', function () use ($true) {
    $true((new FilterRule(['expression' => 'ip.tor']))->needsEnrichment(), 'ip.* needs enrichment');
    $true(!(new FilterRule(['expression' => 'req.method == "POST"']))->needsEnrichment(), 'req-only does not');
});

$t('malformed expression throws at construction (fail fast)', function () use ($true) {
    $threw = false;
    try {
        new FilterRule(['expression' => 'ip.vpn ==']);
    } catch (FilterSyntaxException $e) {
        $threw = true;
    }
    $true($threw, 'incomplete expression rejected');
});
