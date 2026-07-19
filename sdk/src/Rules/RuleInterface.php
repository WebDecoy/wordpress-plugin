<?php

declare(strict_types=1);

namespace WebDecoy\Rules;

/**
 * A rule evaluated by the {@see RuleEngine}.
 *
 * Mirrors the `Rule` interface in @webdecoy/node so tripwire, filter, and
 * rate-limit rules share one evaluation path.
 */
interface RuleInterface
{
    /**
     * Stable rule name. The engine keys clearance-forwarding off the literal
     * name "tripwire" (see {@see RuleEngine::evaluate()}), so tripwire rules
     * MUST return exactly that.
     */
    public function getName(): string;

    /**
     * Evaluate this rule against the request context.
     */
    public function evaluate(RuleContext $context): RuleResult;
}
