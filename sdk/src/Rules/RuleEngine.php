<?php

declare(strict_types=1);

namespace WebDecoy\Rules;

/**
 * Rule Engine — evaluates rules in order; first non-dry-run DENY/THROTTLE wins.
 *
 * A faithful PHP port of @webdecoy/node's rule engine
 * (packages/webdecoy/src/rules/rule-engine.ts). Semantics that MUST match:
 *
 *  - Rules evaluate in the order given.
 *  - Every non-ALLOW result records a {@see ViolationEvent}, including dry-run.
 *  - The first non-ALLOW result that is NOT dry-run decides the outcome.
 *  - A dry-run rule records its violation but does not decide (it "logs").
 *  - The wd_clearance token is attached ONLY to tripwire violations, so only the
 *    deception signal drives the durable device-fingerprint deny-list.
 */
class RuleEngine
{
    /** @var RuleInterface[] */
    private $rules;

    /**
     * @param RuleInterface[] $rules
     */
    public function __construct(array $rules)
    {
        $this->rules = $rules;
    }

    /**
     * Pull the wd_clearance token from a request's Cookie header, if present.
     * Mirrors node's extractClearance().
     */
    private static function extractClearance(RuleContext $context): ?string
    {
        $cookie = $context->header('cookie');
        if ($cookie === null || $cookie === '') {
            return null;
        }
        foreach (explode(';', $cookie) as $part) {
            $eq = strpos($part, '=');
            if ($eq === false) {
                continue;
            }
            if (trim(substr($part, 0, $eq)) === 'wd_clearance') {
                $value = trim(substr($part, $eq + 1));
                return $value !== '' ? $value : null;
            }
        }
        return null;
    }

    /**
     * Evaluate all rules against the request context.
     */
    public function evaluate(RuleContext $context): RuleEngineResult
    {
        $violations = [];
        $deciding = null;

        $iso = self::isoTimestamp($context->timestamp);

        foreach ($this->rules as $rule) {
            $result = $rule->evaluate($context);

            if ($result->action !== RuleResult::ALLOW) {
                $isDryRun = $result->isDryRun();

                // Tripwire hits (a real user can't reach a honeypot path) carry
                // the actor's wd_clearance token so the backend can deny its
                // device fingerprint — the deception signal driving enforcement.
                $clearance = $result->rule === 'tripwire'
                    ? self::extractClearance($context)
                    : null;

                $violations[] = new ViolationEvent(
                    $result->rule,
                    $result->action,
                    $context->ip,
                    $context->path,
                    $context->method,
                    $context->userAgent !== '' ? $context->userAgent : null,
                    $result->reason,
                    $clearance,
                    $result->metadata !== [] ? $result->metadata : null,
                    $isDryRun,
                    $iso
                );

                // First non-ALLOW, non-dry-run result decides the outcome.
                if ($deciding === null && !$isDryRun) {
                    $deciding = $result;
                }
            }
        }

        if ($deciding !== null) {
            return new RuleEngineResult(
                $deciding->action,
                $deciding->rule,
                $deciding->reason,
                $deciding->metadata !== [] ? $deciding->metadata : null,
                $violations
            );
        }

        return new RuleEngineResult(RuleResult::ALLOW, null, null, null, $violations);
    }

    /**
     * Convert a millisecond Unix timestamp to an ISO-8601 UTC string with
     * milliseconds (e.g. 2026-07-19T18:30:00.000Z) to match node's
     * `new Date(ts).toISOString()`.
     */
    private static function isoTimestamp(int $millis): string
    {
        $seconds = intdiv($millis, 1000);
        $ms = $millis % 1000;
        return gmdate('Y-m-d\TH:i:s', $seconds) . sprintf('.%03dZ', $ms);
    }
}
