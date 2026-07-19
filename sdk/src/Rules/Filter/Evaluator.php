<?php

declare(strict_types=1);

namespace WebDecoy\Rules\Filter;

use WebDecoy\Rules\RuleContext;

/**
 * Filter expression evaluator — walks an AST against a {@see RuleContext}.
 * Faithful PHP port of @webdecoy/node's filter/evaluator.ts.
 *
 * PHP's `===` and truthiness differ from JavaScript's, so equality, ordering,
 * membership, and boolean short-circuiting are reimplemented to match JS
 * semantics exactly — otherwise an expression could mean different things in the
 * two SDKs. The `null` value here is JS `undefined` (an unresolved property):
 * any comparison touching it is false, and `and`/`or` treat it as absent.
 */
final class Evaluator
{
    private const MAX_REGEX_LENGTH = 500;

    /**
     * @param array<string,mixed> $node
     * @return mixed boolean|float|string|array|null (null == JS undefined)
     */
    public static function evaluate(array $node, RuleContext $context)
    {
        switch ($node['kind']) {
            case 'bool':
            case 'number':
            case 'string':
                return $node['value'];

            case 'array':
                return array_map(static function ($el) use ($context) {
                    return self::evaluate($el, $context);
                }, $node['elements']);

            case 'property':
                return self::resolveProperty($node['path'], $context);

            case 'call':
                return self::resolveCall($node['object'], $node['method'], $node['args'], $context);

            case 'unary':
                return self::evaluateUnary($node['op'], $node['operand'], $context);

            case 'binary':
                return self::evaluateBinary($node['op'], $node['left'], $node['right'], $context);
        }

        return null;
    }

    /**
     * JS-truthiness: only null/false/0/0.0/""/NaN are falsy. Notably "0" and []
     * are TRUTHY (unlike PHP), matching the JS engine.
     *
     * @param mixed $v
     */
    private static function truthy($v): bool
    {
        if ($v === null || $v === false) {
            return false;
        }
        if ($v === true) {
            return true;
        }
        if (is_int($v) || is_float($v)) {
            return $v != 0;
        }
        if (is_string($v)) {
            return $v !== '';
        }
        return true; // arrays/objects are truthy in JS
    }

    /**
     * JS strict-equality (===): numbers compare by value (1 === 1.0), everything
     * else must match type and value; a number and a string are never equal.
     *
     * @param mixed $l
     * @param mixed $r
     */
    private static function jsStrictEq($l, $r): bool
    {
        $ln = is_int($l) || is_float($l);
        $rn = is_int($r) || is_float($r);
        if ($ln && $rn) {
            return (float) $l === (float) $r;
        }
        if ($ln !== $rn) {
            return false; // one numeric, one not → different JS types
        }
        return $l === $r;
    }

    /**
     * @param string[] $path
     * @return mixed
     */
    private static function resolveProperty(array $path, RuleContext $context)
    {
        $namespace = $path[0];
        $prop = implode('.', array_slice($path, 1));

        if ($namespace === 'ip') {
            $e = $context->enrichment;
            if (!is_array($e)) {
                return null;
            }

            switch ($prop) {
                case 'vpn':
                    return $e['security']['vpn'] ?? null;
                case 'proxy':
                    return $e['security']['proxy'] ?? null;
                case 'tor':
                    return $e['security']['tor'] ?? null;
                case 'relay':
                    return $e['security']['relay'] ?? null;
                case 'hosting':
                    return $e['security']['hosting'] ?? null;
                case 'country':
                    return $e['location']['country'] ?? null;
                case 'country_name':
                    return $e['location']['country_name'] ?? null;
                case 'city':
                    return $e['location']['city'] ?? null;
                case 'timezone':
                    return $e['location']['timezone'] ?? null;
                case 'asn':
                    return $e['network']['asn'] ?? null;
                case 'asn_org':
                    return $e['network']['asn_org'] ?? null;
                case 'abuse_score':
                    return $e['reputation']['abuse_score'] ?? null;
                case 'total_reports':
                    return $e['reputation']['total_reports'] ?? null;
                case 'is_high_risk':
                    return $e['reputation']['is_high_risk'] ?? null;
                default:
                    return null;
            }
        }

        if ($namespace === 'req') {
            switch ($prop) {
                case 'path':
                    return $context->path;
                case 'method':
                    return $context->method;
                case 'ip':
                    return $context->ip;
                case 'user_agent':
                    return $context->userAgent;
                default:
                    return null;
            }
        }

        return null;
    }

    /**
     * @param string[]                     $object
     * @param array<int,array<string,mixed>> $args
     * @return mixed
     */
    private static function resolveCall(array $object, string $method, array $args, RuleContext $context)
    {
        $namespace = $object[0] ?? '';

        if ($namespace === 'req' && $method === 'header') {
            if (count($args) !== 1) {
                return null;
            }
            $headerName = self::evaluate($args[0], $context);
            if (!is_string($headerName)) {
                return null;
            }
            return $context->header($headerName); // null when absent
        }

        return null;
    }

    /**
     * @param array<string,mixed> $operand
     * @return mixed
     */
    private static function evaluateUnary(string $op, array $operand, RuleContext $context)
    {
        $val = self::evaluate($operand, $context);
        if ($op === 'not') {
            if ($val === null) {
                return false;
            }
            return !self::truthy($val);
        }
        return null;
    }

    /**
     * @param array<string,mixed> $left
     * @param array<string,mixed> $right
     * @return mixed
     */
    private static function evaluateBinary(string $op, array $left, array $right, RuleContext $context)
    {
        // Short-circuit boolean operators (mirrors node exactly: 'and' bails only
        // on undefined or literal false, not on other falsy values).
        if ($op === 'and') {
            $l = self::evaluate($left, $context);
            if ($l === null || $l === false) {
                return false;
            }
            $r = self::evaluate($right, $context);
            if ($r === null) {
                return false;
            }
            return self::truthy($r);
        }

        if ($op === 'or') {
            $l = self::evaluate($left, $context);
            if ($l !== null && self::truthy($l)) {
                return true;
            }
            $r = self::evaluate($right, $context);
            if ($r === null) {
                return false;
            }
            return self::truthy($r);
        }

        $l = self::evaluate($left, $context);
        $r = self::evaluate($right, $context);

        // Any comparison touching undefined (null) is false — fail-open.
        if ($l === null || $r === null) {
            return false;
        }

        switch ($op) {
            case '==':
                return self::jsStrictEq($l, $r);
            case '!=':
                return !self::jsStrictEq($l, $r);
            case '>':
                return self::isNum($l) && self::isNum($r) && $l > $r;
            case '>=':
                return self::isNum($l) && self::isNum($r) && $l >= $r;
            case '<':
                return self::isNum($l) && self::isNum($r) && $l < $r;
            case '<=':
                return self::isNum($l) && self::isNum($r) && $l <= $r;

            case 'in':
                if (!is_array($r)) {
                    return false;
                }
                return self::includes($r, $l);

            case 'not in':
                if (!is_array($r)) {
                    return false;
                }
                return !self::includes($r, $l);

            case 'matches':
                if (!is_string($l) || !is_string($r)) {
                    return false;
                }
                if (strlen($r) > self::MAX_REGEX_LENGTH) {
                    return false;
                }
                $delimited = '#' . str_replace('#', '\\#', $r) . '#';
                // phpcs:ignore
                $res = @preg_match($delimited, $l);
                return $res === 1;

            default:
                return false;
        }
    }

    /**
     * @param mixed $v
     */
    private static function isNum($v): bool
    {
        return is_int($v) || is_float($v);
    }

    /**
     * Array membership with JS includes() (SameValueZero) semantics.
     *
     * @param array<int,mixed> $haystack
     * @param mixed            $needle
     */
    private static function includes(array $haystack, $needle): bool
    {
        foreach ($haystack as $el) {
            if (self::jsStrictEq($needle, $el)) {
                return true;
            }
        }
        return false;
    }

    /**
     * JS-truthiness of a top-level filter result (used by FilterRule to decide
     * whether the rule triggers).
     *
     * @param mixed $v
     */
    public static function isTruthy($v): bool
    {
        return self::truthy($v);
    }
}
