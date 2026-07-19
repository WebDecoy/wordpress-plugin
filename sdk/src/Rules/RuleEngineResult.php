<?php

declare(strict_types=1);

namespace WebDecoy\Rules;

/**
 * Aggregate outcome of a full {@see RuleEngine::evaluate()} pass.
 */
class RuleEngineResult
{
    /** @var string Deciding action: ALLOW, DENY, or THROTTLE. */
    public $action;

    /** @var string|null Name of the deciding rule (null when ALLOW). */
    public $rule;

    /** @var string|null Reason from the deciding rule. */
    public $reason;

    /** @var array<string,mixed>|null Metadata from the deciding rule. */
    public $metadata;

    /**
     * Every non-ALLOW result recorded this pass — including dry-run hits — for
     * reporting. Distinct from the single deciding result above.
     *
     * @var ViolationEvent[]
     */
    public $violations;

    /**
     * @param ViolationEvent[]        $violations
     * @param array<string,mixed>|null $metadata
     */
    public function __construct(
        string $action,
        ?string $rule = null,
        ?string $reason = null,
        ?array $metadata = null,
        array $violations = []
    ) {
        $this->action = $action;
        $this->rule = $rule;
        $this->reason = $reason;
        $this->metadata = $metadata;
        $this->violations = $violations;
    }

    public function isAllowed(): bool
    {
        return $this->action === RuleResult::ALLOW;
    }
}
