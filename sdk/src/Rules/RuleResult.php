<?php

declare(strict_types=1);

namespace WebDecoy\Rules;

/**
 * The outcome of evaluating a single rule against a {@see RuleContext}.
 *
 * Actions match @webdecoy/node exactly: ALLOW, DENY, THROTTLE. "Log-only" is
 * expressed via a dry-run rule, which returns ALLOW but still records a
 * violation (see {@see RuleEngine}).
 */
class RuleResult
{
    public const ALLOW = 'ALLOW';
    public const DENY = 'DENY';
    public const THROTTLE = 'THROTTLE';

    /** @var string One of the action constants. */
    public $action;

    /** @var string Name of the rule that produced this result. */
    public $rule;

    /** @var string|null Human-readable reason (present on non-ALLOW results). */
    public $reason;

    /**
     * @var array<string,mixed> Rule-specific metadata (e.g. confidence,
     *                          retryAfter, dryRun).
     */
    public $metadata;

    /**
     * @param array<string,mixed> $metadata
     */
    public function __construct(string $action, string $rule, ?string $reason = null, array $metadata = [])
    {
        $this->action = $action;
        $this->rule = $rule;
        $this->reason = $reason;
        $this->metadata = $metadata;
    }

    public static function allow(string $rule): self
    {
        return new self(self::ALLOW, $rule);
    }

    public function isAllow(): bool
    {
        return $this->action === self::ALLOW;
    }

    public function isDryRun(): bool
    {
        return !empty($this->metadata['dryRun']);
    }
}
